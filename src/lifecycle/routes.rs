// SPDX-License-Identifier: MIT OR Apache-2.0
//! The routes `/api/tags`, `/api/tags/bulk` and `/api/lifecycle`.

use std::sync::Arc;

use http::Method;
use serde::Deserialize;

use super::editor::{LifecycleResponse, lifecycle_deletes};
use super::rules::{EditRule, invalid_lifecycle};
use super::tags::{MAX_OBJECT_TAGS, TagsResponse, apply_tag_change, tag_job, validate_tags};
use super::{Tag, TagChange, nullable};
use crate::access::{self, ACTION_READ, ACTION_WRITE, Operation};
use crate::common::BoxFuture;
use crate::common::app::App;
use crate::common::config::{PERMISSION_DELETE, PERMISSION_READ, PERMISSION_WRITE};
use crate::common::error::{Error, Result};
use crate::common::http::{Req, Response, api_error, decode_json, json, method_not_allowed};
use crate::common::misc::{clean_relative_key, normalize_prefix};
use crate::instance::Instance;

fn answer(result: Result<Response>) -> Response {
    result.unwrap_or_else(|error| api_error(&error))
}

fn invalid_tags(message: &str) -> Error {
    Error::api(400, "invalid_tags", message)
}

fn invalid_key() -> Error {
    Error::api(400, "invalid_key", "object key is required")
}

// --- /api/tags ---------------------------------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct TagsRequest {
    #[serde(default, deserialize_with = "nullable")]
    instance: String,
    #[serde(default, deserialize_with = "nullable")]
    key: String,
    #[serde(default, deserialize_with = "nullable")]
    version: String,
    #[serde(default, deserialize_with = "nullable")]
    tags: Vec<Tag>,
}

/// The handler of `/api/tags`: read (`GET`) or replace (`PUT`) the tags of an object.
pub fn handle_tags(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move { answer(tags_route(app, req).await) })
}

async fn tags_route(app: Arc<App>, req: Req) -> Result<Response> {
    if req.method == Method::GET {
        let key = clean_relative_key(req.query.get("key"));
        let instance = app.instance_of("", req.query.get("instance"))?.clone();
        instance.require_permission(PERMISSION_READ)?;
        if key.is_empty() {
            return Err(invalid_key());
        }
        access::authorize_read(&app, &req.ctx, &instance, &key).await?;
        let version = req.query.get("version").trim().to_owned();
        let tags = instance.get_tags(&req.ctx, &instance.full_key(&key), &version).await?;
        return Ok(json(
            200,
            &TagsResponse {
                instance: instance.cfg.id.clone(),
                key,
                version,
                tags,
                max_tags: MAX_OBJECT_TAGS,
            },
        ));
    }
    if req.method == Method::PUT {
        let Req { body, ctx, query, .. } = req;
        let request: TagsRequest = decode_json(body).await?;
        let key = clean_relative_key(&request.key);
        let instance = app.instance_of(&request.instance, query.get("instance"))?.clone();
        instance.require_permission(PERMISSION_WRITE)?;
        if key.is_empty() {
            return Err(invalid_key());
        }
        validate_tags(&request.tags)?;
        access::authorize_use(&app, &ctx, ACTION_WRITE, &instance, &key).await?;
        let tags = apply_tag_change(
            &[],
            &TagChange {
                add: request.tags,
                remove: Vec::new(),
            },
        );
        let version = request.version.trim().to_owned();
        instance
            .put_tags(&ctx, &instance.full_key(&key), &version, &tags)
            .await?;
        return Ok(json(
            200,
            &TagsResponse {
                instance: instance.cfg.id.clone(),
                key,
                version,
                tags,
                max_tags: MAX_OBJECT_TAGS,
            },
        ));
    }
    Ok(method_not_allowed(&["GET", "PUT"]))
}

// --- /api/tags/bulk ----------------------------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TagsBulkRequest {
    #[serde(default, deserialize_with = "nullable")]
    instance: String,
    #[serde(default, deserialize_with = "nullable")]
    prefix: String,
    #[serde(default, deserialize_with = "nullable")]
    add: Vec<Tag>,
    #[serde(default, deserialize_with = "nullable")]
    remove: Vec<String>,
}

/// The checks of a request of `/api/tags/bulk` before the access policy: the prefix, the permissions of the instance
/// and the change. Gives the prefix and the change of the job.
pub(super) fn bulk_change(instance: &Instance, request: &TagsBulkRequest) -> Result<(String, TagChange)> {
    let mut prefix = clean_relative_key(&request.prefix);
    if !prefix.is_empty() {
        prefix = normalize_prefix(&prefix);
    }
    for permission in [PERMISSION_READ, PERMISSION_WRITE] {
        instance.require_permission(permission)?;
    }
    if request.add.is_empty() && request.remove.is_empty() {
        return Err(invalid_tags("give at least one tag to add or one key to remove"));
    }
    validate_tags(&request.add)?;
    if request.remove.iter().any(String::is_empty) {
        return Err(invalid_tags("a key to remove cannot be empty"));
    }
    Ok((
        prefix,
        TagChange {
            add: request.add.clone(),
            remove: request.remove.clone(),
        },
    ))
}

/// The handler of `/api/tags/bulk`: start the job that changes the tags of each object under a prefix.
pub fn handle_tags_bulk(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move { answer(tags_bulk_route(app, req).await) })
}

async fn tags_bulk_route(app: Arc<App>, req: Req) -> Result<Response> {
    if req.method != Method::POST {
        return Ok(method_not_allowed(&["POST"]));
    }
    let Req { body, ctx, query, .. } = req;
    let request: TagsBulkRequest = decode_json(body).await?;
    let instance = app.instance_of(&request.instance, query.get("instance"))?.clone();
    let (prefix, change) = bulk_change(&instance, &request)?;
    access::authorize(&app, &ctx, app.access.write_prefix_operation(&instance, &prefix)).await?;
    let job = app.jobs.create(tag_job(&instance.cfg.id, &prefix, change))?;
    Ok(crate::jobs::job_answer(202, &job))
}

// --- /api/lifecycle ----------------------------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleRequest {
    #[serde(default, deserialize_with = "nullable")]
    instance: String,
    #[serde(default, deserialize_with = "nullable")]
    hash: String,
    #[serde(default, deserialize_with = "nullable")]
    rules: Vec<EditRule>,
}

/// The handler of `/api/lifecycle`: the rules of the bucket with the state of the editor (`GET`), or the save of the
/// rules of the editor (`PUT`).
pub fn handle_lifecycle(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move { answer(lifecycle_route(app, req).await) })
}

async fn lifecycle_route(app: Arc<App>, req: Req) -> Result<Response> {
    if req.method == Method::PUT {
        return lifecycle_save(app, req).await;
    }
    if req.method != Method::GET {
        return Ok(method_not_allowed(&["GET", "PUT"]));
    }
    let instance = app.instance_of("", req.query.get("instance"))?.clone();
    instance.require_permission(PERMISSION_READ)?;
    access::authorize(
        &app,
        &req.ctx,
        Operation {
            use_ask: access::object_ask(&app, ACTION_READ, &instance, ""),
            ..Operation::default()
        },
    )
    .await?;
    let state = instance.read_lifecycle_state(&req.ctx).await?;
    Ok(json(
        200,
        &LifecycleResponse {
            instance: instance.cfg.id.clone(),
            rules: state.rules,
            editor: Some(state.editor),
            warnings: Vec::new(),
        },
    ))
}

fn valid_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

async fn lifecycle_save(app: Arc<App>, req: Req) -> Result<Response> {
    let Req { body, ctx, query, .. } = req;
    let mut request: LifecycleRequest = decode_json(body).await?;
    let instance = app.instance_of(&request.instance, query.get("instance"))?.clone();
    for permission in [PERMISSION_READ, PERMISSION_WRITE] {
        instance.require_permission(permission)?;
    }
    if !valid_hash(&request.hash) {
        return Err(invalid_lifecycle("hash must be the hash that GET /api/lifecycle gave"));
    }
    for rule in &mut request.rules {
        rule.prefix = clean_relative_key(&rule.prefix);
    }
    instance.lifecycle_writer()?;
    // The access check needs the rules that the save removes: a first read gives them. The save reads again.
    let current = instance.read_lifecycle_state(&ctx).await?;
    if lifecycle_deletes(&current, &request.rules) {
        instance.require_permission(PERMISSION_DELETE)?;
    }
    access::authorize(&app, &ctx, app.access.lifecycle_operation(&instance)).await?;
    let (state, warnings) = instance.save_lifecycle(&ctx, &request.hash, &request.rules).await?;
    let mut response = LifecycleResponse {
        instance: instance.cfg.id.clone(),
        rules: state.rules,
        editor: Some(state.editor),
        warnings,
    };
    if response.editor.as_ref().is_some_and(|editor| editor.hash.is_empty()) {
        // The read back failed: the answer has no state, and the page reads the rules again.
        response.rules = Vec::new();
        response.editor = None;
    }
    Ok(json(200, &response))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_prefix_has_one_slash_at_its_end_and_none_at_its_start() {
        assert_eq!(normalize_prefix("/a//"), "a/");
        assert_eq!(normalize_prefix("a/b"), "a/b/");
        assert_eq!(normalize_prefix("///"), "");
        assert_eq!(normalize_prefix(""), "");
    }

    #[test]
    fn a_hash_has_64_lower_case_hexadecimal_characters() {
        assert!(valid_hash(&"a1".repeat(32)));
        assert!(!valid_hash(&"A1".repeat(32)));
        assert!(!valid_hash("abc"));
    }
}
