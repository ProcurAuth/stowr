//! The routes `GET /api/multiparts` and `POST /api/multiparts/abort`.

use std::sync::Arc;

use http::Method;
use serde::{Deserialize, Deserializer, Serialize};

use super::MultipartAbortResult;
use super::multiparts::{
    DEFAULT_LIST_SIZE, MAXIMUM_ABORT_DAYS, MAXIMUM_ABORT_ITEMS, MAXIMUM_LIST_SIZE, MINIMUM_ABORT_AGE,
    MultipartAbortItem, MultipartListResponse, PARTS_PAGE_SIZE, abort_job_request, abort_selected_multiparts,
    collect_multipart_uploads, decode_multipart_cursor, describe_multipart_uploads, encode_multipart_cursor,
    invalid_multipart_request, multipart_unsupported, valid_multipart_upload_id,
};
use super::target::Targets;
use crate::access::{authorize, authorize_read};
use crate::common::BoxFuture;
use crate::common::app::App;
use crate::common::config::{PERMISSION_READ, PERMISSION_WRITE};
use crate::common::error::{Error, Result};
use crate::common::http::{Req, Response, api_error, decode_json, json, method_not_allowed};
use crate::common::misc::clean_relative_key;
use crate::common::time::Timestamp;
use crate::jobs::{JobState, job_type};

/// A value that is `null` in the JSON text has the default value, as a missing member has.
fn null_as_default<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// The body of `POST /api/multiparts/abort`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AbortRequest {
    #[serde(default, deserialize_with = "null_as_default")]
    instance: String,
    /// The uploads of "Abort selected". The request gives these or `olderThanDays`, not both.
    #[serde(default, deserialize_with = "null_as_default")]
    uploads: Vec<MultipartAbortItem>,
    /// The job aborts each dated upload under `prefix` that is older than this number of days.
    #[serde(default, rename = "olderThanDays", deserialize_with = "null_as_default")]
    older_than_days: i64,
    #[serde(default, deserialize_with = "null_as_default")]
    prefix: String,
}

/// The job `abort_multiparts` as the client sees it. The other members of a job are not in the form of this type of
/// job.
#[derive(Clone, Debug, Serialize)]
pub(super) struct PublicAbortJob {
    id: String,
    #[serde(rename = "type")]
    job_type: String,
    instance: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    prefix: String,
    status: String,
    processed: i64,
    #[serde(rename = "storageRequests", skip_serializing_if = "is_zero")]
    storage_requests: i64,
    #[serde(rename = "storageBytes", skip_serializing_if = "is_zero")]
    storage_bytes: i64,
    #[serde(rename = "lastKey", skip_serializing_if = "String::is_empty")]
    last_key: String,
    #[serde(rename = "olderThanDays", skip_serializing_if = "is_zero_u32")]
    older_than_days: u32,
    #[serde(rename = "multipartAbort", skip_serializing_if = "Option::is_none")]
    multipart_abort: Option<MultipartAbortResult>,
    #[serde(skip_serializing_if = "String::is_empty")]
    error: String,
    #[serde(rename = "createdAt")]
    created_at: Timestamp,
    #[serde(rename = "updatedAt")]
    updated_at: Timestamp,
    #[serde(rename = "startedAt", skip_serializing_if = "Option::is_none")]
    started_at: Option<Timestamp>,
    #[serde(rename = "endedAt", skip_serializing_if = "Option::is_none")]
    ended_at: Option<Timestamp>,
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}

fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}

impl From<&JobState> for PublicAbortJob {
    fn from(job: &JobState) -> Self {
        Self {
            id: job.id.clone(),
            job_type: job.job_type.clone(),
            instance: job.instance.clone(),
            prefix: job.prefix.clone(),
            status: job.status.clone(),
            processed: job.processed,
            storage_requests: job.storage_requests,
            storage_bytes: job.storage_bytes,
            last_key: job.last_key.clone(),
            older_than_days: job
                .multipart_abort
                .as_ref()
                .map_or(0, |request| request.older_than_days),
            multipart_abort: job.multipart_result.clone(),
            error: job.error.clone(),
            created_at: job.created_at,
            updated_at: job.updated_at,
            started_at: job.started_at,
            ended_at: job.ended_at,
        }
    }
}

/// The handler of `GET /api/multiparts`: the incomplete uploads under a prefix.
pub fn handle_multiparts(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        match list_route(app, req).await {
            Ok(response) => response,
            Err(error) => api_error(&error),
        }
    })
}

/// The handler of `POST /api/multiparts/abort`: abort the uploads of the request (200 with the result of each), or
/// start the job that aborts the uploads older than a number of days (202 with the job).
pub fn handle_multipart_abort(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        match abort_route(app, req).await {
            Ok(response) => response,
            Err(error) => api_error(&error),
        }
    })
}

async fn list_route(app: Arc<App>, req: Req) -> Result<Response> {
    if req.method != Method::GET {
        return Ok(method_not_allowed(&["GET"]));
    }
    let prefix = clean_relative_key(req.query.get("prefix"));
    let instance = app.instance_of("", req.query.get("instance"))?.clone();
    instance.require_permission(PERMISSION_READ)?;
    authorize_read(&app, &req.ctx, &instance, &prefix).await?;
    let target = app
        .target(&instance.cfg.id)
        .ok_or_else(|| Error::internal("the instance has no target"))?;
    if !target.multipart_available() {
        return Err(multipart_unsupported());
    }
    let mut limit = DEFAULT_LIST_SIZE;
    let raw = req.query.get("max");
    if !raw.is_empty() {
        limit = match raw.parse::<i64>() {
            Ok(value) if (1..=MAXIMUM_LIST_SIZE as i64).contains(&value) => value as usize,
            _ => {
                return Err(invalid_multipart_request(format!(
                    "max must be an integer from 1 to {MAXIMUM_LIST_SIZE}, got {raw:?}"
                )));
            }
        };
    }
    let cursor = decode_multipart_cursor(req.query.get("token"))?;
    let collected = collect_multipart_uploads(&*target, &req.ctx, &prefix, cursor, limit).await?;
    let active = app.uploads.active_provider_uploads(&instance.cfg.id);
    let uploads = describe_multipart_uploads(&req.ctx, &target, collected.uploads, collected.relatives, &active).await;
    Ok(json(
        200,
        &MultipartListResponse {
            instance: instance.cfg.id.clone(),
            prefix,
            uploads,
            next_token: encode_multipart_cursor(&collected.next),
            now: Timestamp::now().rfc3339(),
            minimum_abort_age_hours: MINIMUM_ABORT_AGE.as_secs() / 3600,
            parts_page_size: PARTS_PAGE_SIZE,
        },
    ))
}

async fn abort_route(app: Arc<App>, req: Req) -> Result<Response> {
    if req.method != Method::POST {
        return Ok(method_not_allowed(&["POST"]));
    }
    let Req { query, body, ctx, .. } = req;
    let mut request: AbortRequest = decode_json(body).await?;
    let instance = app.instance_of(&request.instance, query.get("instance"))?.clone();
    let has_uploads = !request.uploads.is_empty();
    if has_uploads && request.older_than_days != 0 {
        return Err(invalid_multipart_request("give uploads or olderThanDays, not both"));
    }
    if !has_uploads && request.older_than_days == 0 {
        return Err(invalid_multipart_request("give the uploads to abort, or olderThanDays"));
    }
    if request.uploads.len() > MAXIMUM_ABORT_ITEMS {
        return Err(invalid_multipart_request(format!(
            "give at most {MAXIMUM_ABORT_ITEMS} uploads in one request, got {}",
            request.uploads.len()
        )));
    }
    if request.older_than_days != 0 && !(1..=MAXIMUM_ABORT_DAYS).contains(&request.older_than_days) {
        return Err(invalid_multipart_request(format!(
            "olderThanDays must be an integer from 1 to {MAXIMUM_ABORT_DAYS}, got {}",
            request.older_than_days
        )));
    }
    if has_uploads && !request.prefix.is_empty() {
        return Err(invalid_multipart_request("prefix goes with olderThanDays only"));
    }
    for item in &mut request.uploads {
        item.key = clean_relative_key(&item.key);
        if item.key.is_empty() || !valid_multipart_upload_id(&item.upload_id) {
            return Err(invalid_multipart_request(
                "each upload needs a key and the upload id that the list gave",
            ));
        }
    }
    for permission in [PERMISSION_READ, PERMISSION_WRITE] {
        instance.require_permission(permission)?;
    }
    let target = app
        .target(&instance.cfg.id)
        .ok_or_else(|| Error::internal("the instance has no target"))?;
    target.require_multipart_list()?;
    if has_uploads {
        let keys: Vec<String> = request.uploads.iter().map(|item| item.key.clone()).collect();
        authorize(&app, &ctx, app.access.abort_uploads_operation(&instance, &keys)).await?;
        let response = abort_selected_multiparts(&app.uploads, &*target, &ctx, &request.uploads).await;
        return Ok(json(200, &response));
    }
    let prefix = clean_relative_key(&request.prefix);
    authorize(&app, &ctx, app.access.write_prefix_operation(&instance, &prefix)).await?;
    let job = app.jobs.create(JobState {
        job_type: job_type::ABORT_MULTIPARTS.to_owned(),
        instance: instance.cfg.id.clone(),
        prefix,
        multipart_abort: Some(abort_job_request(request.older_than_days, Timestamp::now())),
        multipart_result: Some(MultipartAbortResult::default()),
        ..JobState::default()
    })?;
    Ok(json(202, &PublicAbortJob::from(&job)))
}
