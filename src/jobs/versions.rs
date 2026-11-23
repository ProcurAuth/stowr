// SPDX-License-Identifier: MIT OR Apache-2.0
//! The version routes (docs/ARCHITECTURE.md, "Version capability and version access"): the versions of one key,
//! the count of the versions of visible keys, the restore of a version and the delete of one version for ever.
//!
//! Each route answers `501 versioning_unavailable` for a bucket whose start probe found no versions.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use http::Method;
use serde::{Deserialize, Serialize};

use super::integrity::nullable;
use super::seam;
use crate::access::ACTION_DELETE;
use crate::common::BoxFuture;
use crate::common::app::App;
use crate::common::config::{PERMISSION_DELETE, PERMISSION_READ, PERMISSION_WRITE};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Req, Response, api_error, decode_json, json, method_not_allowed, no_content};
use crate::common::misc::clean_relative_key;
use crate::common::query::Query;
use crate::common::storage::StoredObjectVersion;
use crate::instance::Instance;

/// The page size of `/api/versions` without a valid `max`.
const DEFAULT_VERSION_PAGE: u32 = 250;
/// The most versions of one page of `/api/versions`.
const MAX_VERSION_PAGE: i64 = 1000;
/// The most keys of one request of `/api/version-counts`.
const MAX_COUNTED_KEYS: usize = 100;

fn versioning_unavailable() -> Error {
    Error::api(
        501,
        "versioning_unavailable",
        "object versioning is not available for this storage bucket",
    )
}

fn answer(result: Result<Response>) -> Response {
    result.unwrap_or_else(|error| api_error(&error))
}

/// One page of the versions of a key. An empty page has `versions: null`, as the providers give it.
#[derive(Serialize)]
struct VersionsAnswer<'a> {
    instance: &'a str,
    key: &'a str,
    #[serde(rename = "nextPageToken")]
    next_page_token: &'a str,
    versions: Option<&'a [StoredObjectVersion]>,
}

/// The handler of `/api/versions`: the versions of one key (`GET`), or the delete of one version for ever
/// (`DELETE`).
pub fn handle_versions(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        let Req { method, query, ctx, .. } = req;
        answer(versions_route(&app, &method, &query, &ctx).await)
    })
}

async fn versions_route(app: &App, method: &Method, query: &Query, ctx: &OpCtx) -> Result<Response> {
    let instance = app.instance_of("", query.get("instance"))?.clone();
    if !instance.versioning_available() {
        return Err(versioning_unavailable());
    }
    let key = clean_relative_key(query.get("key"));
    if key.is_empty() {
        return Err(Error::api(400, "invalid_key", "object key is required"));
    }
    if *method == Method::GET {
        instance.require_permission(PERMISSION_READ)?;
        crate::access::authorize_read(app, ctx, &instance, &key).await?;
        let maximum = match query.get("max").trim().parse::<i64>() {
            Ok(value) if (1..=MAX_VERSION_PAGE).contains(&value) => value as u32,
            _ => DEFAULT_VERSION_PAGE,
        };
        let page = instance
            .list_versions(ctx, &instance.full_key(&key), query.get("pageToken"), maximum)
            .await?;
        return Ok(json(
            200,
            &VersionsAnswer {
                instance: &instance.cfg.id,
                key: &key,
                next_page_token: &page.next_page_token,
                versions: (!page.versions.is_empty()).then_some(page.versions.as_slice()),
            },
        ));
    }
    if *method == Method::DELETE {
        instance.require_permission(PERMISSION_DELETE)?;
        crate::access::authorize_use(app, ctx, ACTION_DELETE, &instance, &key).await?;
        instance
            .delete_version(ctx, &instance.full_key(&key), query.get("version").trim())
            .await?;
        return Ok(no_content());
    }
    Ok(method_not_allowed(&["GET", "DELETE"]))
}

/// The body of `POST /api/version-counts`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct VersionCountsRequest {
    #[serde(deserialize_with = "nullable")]
    instance: String,
    #[serde(deserialize_with = "nullable")]
    keys: Vec<String>,
}

/// The count of the versions of one key, without the delete markers.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct VersionCount {
    /// The versions.
    pub count: usize,
    /// The id of the current version.
    #[serde(rename = "currentVersion", skip_serializing_if = "String::is_empty")]
    pub current_version: String,
}

#[derive(Serialize)]
struct VersionCountsAnswer<'a> {
    counts: BTreeMap<String, VersionCount>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    errors: BTreeMap<String, String>,
    instance: &'a str,
}

/// The handler of `POST /api/version-counts`: the count of the versions of 1 to 100 keys. A key whose count fails
/// goes in `errors` with a public message.
pub fn handle_version_counts(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        if req.method != Method::POST {
            return method_not_allowed(&["POST"]);
        }
        answer(version_counts_route(&app, req).await)
    })
}

async fn version_counts_route(app: &App, req: Req) -> Result<Response> {
    let Req { body, ctx, query, .. } = req;
    let request: VersionCountsRequest = decode_json(body).await?;
    let instance = app.instance_of(&request.instance, query.get("instance"))?.clone();
    if !instance.versioning_available() {
        return Err(versioning_unavailable());
    }
    instance.require_permission(PERMISSION_READ)?;
    if request.keys.is_empty() || request.keys.len() > MAX_COUNTED_KEYS {
        return Err(Error::api(
            400,
            "invalid_keys",
            "between 1 and 100 object keys are required",
        ));
    }
    let mut keys = Vec::with_capacity(request.keys.len());
    let mut seen = BTreeSet::new();
    for raw in &request.keys {
        let key = clean_relative_key(raw);
        if key.is_empty() || !seen.insert(key.clone()) {
            continue;
        }
        keys.push(key);
    }
    // The first key is the use. The other keys are the other permissions.
    seam::authorize_read_many(app, &ctx, &instance, &keys).await?;
    let mut counts = BTreeMap::new();
    let mut errors = BTreeMap::new();
    for key in keys {
        match count_object_versions(&ctx, &instance, &instance.full_key(&key)).await {
            Ok(count) => {
                counts.insert(key, count);
            }
            Err(error) => {
                errors.insert(key, error.public_message());
            }
        }
    }
    Ok(json(
        200,
        &VersionCountsAnswer {
            counts,
            errors,
            instance: &instance.cfg.id,
        },
    ))
}

/// Count the versions of one key, page after page. A page token that comes back stops the count with an error.
async fn count_object_versions(ctx: &OpCtx, instance: &Instance, full_key: &str) -> Result<VersionCount> {
    let mut result = VersionCount::default();
    let mut page_token = String::new();
    let mut seen_tokens = BTreeSet::new();
    loop {
        let page = instance.list_versions(ctx, full_key, &page_token, 1000).await?;
        for version in &page.versions {
            if version.delete_marker {
                continue;
            }
            result.count += 1;
            if version.is_current {
                result.current_version.clone_from(&version.version);
            }
        }
        if page.next_page_token.is_empty() {
            return Ok(result);
        }
        if page.next_page_token == page_token {
            return Err(Error::internal("provider returned the same version page token twice"));
        }
        if !seen_tokens.insert(page.next_page_token.clone()) {
            return Err(Error::internal("provider returned a repeated version page token"));
        }
        page_token = page.next_page_token;
    }
}

/// The body of `POST /api/versions/restore`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct RestoreRequest {
    #[serde(deserialize_with = "nullable")]
    instance: String,
    #[serde(deserialize_with = "nullable")]
    key: String,
    #[serde(deserialize_with = "nullable")]
    version: String,
}

#[derive(Serialize)]
struct RestoreAnswer<'a> {
    key: &'a str,
    restored: bool,
    version: &'a str,
}

/// The handler of `POST /api/versions/restore`: copy one version onto its key.
pub fn handle_version_restore(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        if req.method != Method::POST {
            return method_not_allowed(&["POST"]);
        }
        answer(restore_route(&app, req).await)
    })
}

async fn restore_route(app: &App, req: Req) -> Result<Response> {
    let Req { body, ctx, query, .. } = req;
    let request: RestoreRequest = decode_json(body).await?;
    let instance = app.instance_of(&request.instance, query.get("instance"))?.clone();
    if !instance.versioning_available() {
        return Err(versioning_unavailable());
    }
    for permission in [PERMISSION_READ, PERMISSION_WRITE] {
        instance.require_permission(permission)?;
    }
    let key = clean_relative_key(&request.key);
    if key.is_empty() || request.version.trim().is_empty() {
        return Err(Error::api(400, "invalid_version", "key and version are required"));
    }
    crate::access::authorize(app, &ctx, seam::restore_operation(app, &instance, &key)).await?;
    instance
        .restore_version(&ctx, &instance.full_key(&key), &request.version)
        .await?;
    Ok(json(
        200,
        &RestoreAnswer {
            key: &key,
            restored: true,
            version: &request.version,
        },
    ))
}
