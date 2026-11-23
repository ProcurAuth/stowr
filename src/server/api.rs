//! The routes of the instances, of the build, of the permissions, of the listing, of Insights, of the copy, the
//! rename and the delete of objects and prefixes, and of the health check.

use std::sync::Arc;
use std::time::Duration;

use http::header::{CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, HeaderValue};
use http::{HeaderMap, Method};
use serde::{Deserialize, Serialize};

use super::paths::normalize_prefix;
use super::seams;
use super::{RequestHead, split};
use crate::access::{ACTION_DELETE, ACTION_READ, ACTION_WRITE, Operation, object_ask};
use crate::common::BoxFuture;
use crate::common::app::App;
use crate::common::config::{PERMISSION_DELETE, PERMISSION_READ, PERMISSION_WRITE, RuntimePolicy};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Req, Response, answer, api_error, decode_json, empty, json, method_not_allowed};
use crate::common::misc::clean_relative_key;
use crate::common::storage::{ListOptions, ListPage, ObjectInfo};
use crate::common::time::Timestamp;
use crate::instance::Instance;
use crate::instance::ceiling::{Ceilings, check_object_ceiling};
use crate::jobs::{JobState, job_type};

/// The page size of a provider listing.
pub const PROVIDER_LIST_PAGE_SIZE: u32 = 1000;
/// How long `/api/stats` waits for a job before it answers 202.
pub const STATS_INLINE_WAIT: Duration = Duration::from_millis(100);

fn api_result(result: Result<Response>) -> Response {
    result.unwrap_or_else(|error| api_error(&error))
}

/// The handler of `/api/instances`.
pub fn handle_instances(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        if req.method != Method::GET {
            return method_not_allowed(&["GET"]);
        }
        api_result(instances(&app, &split(req).0))
    })
}

/// The public limits of the process in `/api/instances`, in the order of their names.
#[derive(Serialize)]
struct PublicRuntime {
    #[serde(rename = "forceReadOnly")]
    force_read_only: bool,
    #[serde(rename = "fullObjectFallback")]
    full_object_fallback: bool,
    #[serde(rename = "maxArchiveEntries")]
    max_archive_entries: u32,
    #[serde(rename = "maxRangeCacheBytes")]
    max_range_cache_bytes: i64,
    #[serde(rename = "maxStorageBytes")]
    max_storage_bytes: i64,
    #[serde(rename = "maxStorageRequests")]
    max_storage_requests: i64,
    #[serde(rename = "sessionTTLSeconds")]
    session_ttl_seconds: u32,
}

fn public_runtime(policy: &RuntimePolicy) -> PublicRuntime {
    PublicRuntime {
        force_read_only: policy.force_read_only(),
        full_object_fallback: policy.allow_full_object_fallback,
        max_archive_entries: policy.max_archive_entries,
        max_range_cache_bytes: policy.max_range_cache_bytes,
        max_storage_bytes: policy.max_storage_bytes_per_request,
        max_storage_requests: policy.max_storage_requests_per_request,
        session_ttl_seconds: policy.session_ttl_seconds,
    }
}

#[derive(Serialize)]
struct InstancesAnswer {
    build: crate::config::build_info::BuildInfo,
    default: String,
    instances: Vec<crate::instance::InstanceInfo>,
    runtime: PublicRuntime,
}

fn instances(app: &App, req: &RequestHead) -> Result<Response> {
    let (instances, default) = seams::visible_instances(app, &req.ctx)?;
    Ok(json(
        200,
        &InstancesAnswer {
            build: crate::config::build_info::current(),
            default,
            instances,
            runtime: public_runtime(&app.config.runtime),
        },
    ))
}

/// The handler of `/api/build`.
pub fn handle_build(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        let _ = app;
        if req.method != Method::GET && req.method != Method::HEAD {
            return method_not_allowed(&["GET", "HEAD"]);
        }
        let mut response = json(200, &crate::config::build_info::current());
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    })
}

/// The handler of `POST /api/permissions/refresh`.
pub fn handle_permission_refresh(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        if req.method != Method::POST {
            return method_not_allowed(&["POST"]);
        }
        api_result(permission_refresh(&app, &split(req).0).await)
    })
}

#[derive(Serialize)]
struct RefreshAnswer {
    capabilities: crate::common::storage::Capabilities,
    instance: String,
}

async fn permission_refresh(app: &App, req: &RequestHead) -> Result<Response> {
    let instance = app.instance_of("", req.query.get("instance"))?;
    crate::access::authorize(
        app,
        &req.ctx,
        Operation {
            use_ask: object_ask(app, ACTION_READ, instance, ""),
            ..Operation::default()
        },
    )
    .await?;
    let ctx = req.ctx.with_timeout(Duration::from_secs(15));
    let capabilities = instance.refresh_capabilities(&ctx).await;
    Ok(json(
        200,
        &RefreshAnswer {
            capabilities,
            instance: instance.cfg.id.clone(),
        },
    ))
}

/// One entry of a listing: a folder (`prefix`) or an object (`content`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ListItem {
    /// `prefix` or `content`.
    #[serde(rename = "type")]
    pub item_type: &'static str,
    /// The name: the last part of the key, with `/` at the end for a folder.
    pub name: String,
    /// The relative prefix of a folder.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub prefix: String,
    /// The relative key of an object.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub key: String,
    /// The size of an object.
    #[serde(skip_serializing_if = "is_zero")]
    pub size: i64,
    /// The last change of an object.
    #[serde(rename = "lastModified", skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<Timestamp>,
    /// The ETag of an object.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub etag: String,
    /// The media type of an object, when the listing gives it.
    #[serde(rename = "contentType", skip_serializing_if = "String::is_empty")]
    pub content_type: String,
    /// True for an entry of a volume that the server does not read.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub unreadable: bool,
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}

/// The answer of `/api/list`.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ListAnswer {
    /// The instance.
    pub instance: String,
    /// The relative prefix.
    pub prefix: String,
    /// `/` or empty.
    pub delimiter: String,
    /// The folders, then the objects.
    pub items: Vec<ListItem>,
    /// The token of the next page.
    #[serde(rename = "nextContinuationToken", skip_serializing_if = "String::is_empty")]
    pub next_continuation_token: String,
    /// True when the provider has more pages.
    #[serde(rename = "isTruncated")]
    pub is_truncated: bool,
    /// True when the scan read each page.
    #[serde(rename = "scanComplete")]
    pub scan_complete: bool,
    /// True when the interface can sort the whole folder.
    #[serde(rename = "sortAvailable")]
    pub sort_available: bool,
    /// The decisions at the node, in mode `authzen`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access: Option<seams::ListAccess>,
}

/// Read pages of a listing: at most `max_pages` pages (0: no limit). Gives the pages and true when the scan read the
/// last page.
pub async fn scan_list_pages(
    ctx: &OpCtx,
    instance: &Instance,
    mut options: ListOptions,
    max_pages: u32,
) -> Result<(ListPage, bool)> {
    let mut aggregated = ListPage::default();
    let mut page_token = options.page_token.clone();
    let mut page_number: u32 = 0;
    loop {
        options.max_results = PROVIDER_LIST_PAGE_SIZE;
        options.page_token = page_token.clone();
        let page = instance.list(ctx, &options).await?;
        aggregated.objects.extend(page.objects);
        aggregated.prefixes.extend(page.prefixes);
        let next = page.next_page_token;
        if next.is_empty() {
            aggregated.next_page_token = String::new();
            return Ok((aggregated, true));
        }
        if next == page_token {
            return Err(Error::internal("provider returned the same continuation token twice"));
        }
        aggregated.next_page_token = next.clone();
        if max_pages > 0 && page_number + 1 >= max_pages {
            return Ok((aggregated, false));
        }
        page_token = next;
        page_number += 1;
    }
}

/// Sort the entries of a listing: the folders first, then the names without case. Equal names keep their order.
pub fn sort_list_items(items: &mut [ListItem]) {
    let mut rows: Vec<(String, ListItem)> = items
        .iter()
        .map(|item| (item.name.to_lowercase(), item.clone()))
        .collect();
    rows.sort_by(|left, right| {
        let left_folder = left.1.item_type == "prefix";
        let right_folder = right.1.item_type == "prefix";
        right_folder.cmp(&left_folder).then_with(|| left.0.cmp(&right.0))
    });
    for (slot, (_, item)) in items.iter_mut().zip(rows) {
        *slot = item;
    }
}

/// The prefixes of the `exclude` parameters: comma-separated, cleaned, empty parts removed.
pub fn parse_excludes(values: &[&str]) -> Vec<String> {
    values
        .iter()
        .flat_map(|value| value.split(','))
        .map(|part| clean_relative_key(part.trim()))
        .filter(|part| !part.is_empty())
        .collect()
}

fn is_excluded(relative: &str, excludes: &[String]) -> bool {
    excludes.iter().any(|exclude| relative.starts_with(exclude.as_str()))
}

fn last_part(text: &str) -> &str {
    text.rfind('/').map_or(text, |index| &text[index + 1..])
}

/// The zero time of a provider: it means "no time".
fn known_time(time: Option<Timestamp>) -> Option<Timestamp> {
    time.filter(|time| !(time.secs == -62_135_596_800 && time.nanos == 0))
}

/// The handler of `/api/list`.
pub fn handle_list(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        if req.method != Method::GET && req.method != Method::HEAD {
            return method_not_allowed(&["GET", "HEAD"]);
        }
        api_result(list(&app, &split(req).0).await)
    })
}

async fn list(app: &App, req: &RequestHead) -> Result<Response> {
    let instance = app.instance_of("", req.query.get("instance"))?;
    let prefix = clean_relative_key(req.query.get("prefix"));
    instance.require_permission(PERMISSION_READ)?;
    let display = seams::list_display(app, &req.ctx, instance, &prefix)?;
    let delimiter = if req.query.has("delimiter") {
        req.query.get("delimiter").to_owned()
    } else {
        "/".to_owned()
    };
    if !delimiter.is_empty() && delimiter != "/" {
        return Err(Error::api(400, "invalid_delimiter", "delimiter must be empty or /"));
    }
    let page_token = req.query.get("continuationToken").to_owned();
    let (page, scan_complete) = scan_list_pages(
        &req.ctx,
        instance,
        ListOptions {
            prefix: instance.full_key(&prefix),
            delimiter: delimiter.clone(),
            page_token: page_token.clone(),
            ..ListOptions::default()
        },
        instance.cfg.max_scan_pages,
    )
    .await?;
    let excludes = parse_excludes(&req.query.values("exclude"));
    let mut items = Vec::with_capacity(page.prefixes.len() + page.objects.len());
    let mut seen = std::collections::HashSet::new();
    for full_prefix in &page.prefixes {
        let Some(relative) = instance.relative_key(full_prefix) else {
            continue;
        };
        if relative.is_empty() || is_excluded(&relative, &excludes) {
            continue;
        }
        let relative = normalize_prefix(&relative);
        let name = last_part(relative.trim_end_matches('/')).to_owned();
        if !seen.insert(format!("p:{relative}")) {
            continue;
        }
        items.push(ListItem {
            item_type: "prefix",
            name: format!("{name}/"),
            prefix: relative,
            ..ListItem::default()
        });
    }
    for object in &page.objects {
        let Some(relative) = instance.relative_key(&object.key) else {
            continue;
        };
        if relative.is_empty() || is_excluded(&relative, &excludes) {
            continue;
        }
        if relative.ends_with('/') && object.size == 0 {
            continue;
        }
        if !seen.insert(format!("o:{relative}")) {
            continue;
        }
        items.push(object_item(&relative, object));
    }
    sort_list_items(&mut items);
    if display.navigation {
        items = seams::navigation_items(app, &req.ctx, instance, items)?;
    }
    let answer_body = ListAnswer {
        instance: instance.cfg.id.clone(),
        prefix,
        delimiter,
        items,
        is_truncated: !page.next_page_token.is_empty(),
        next_continuation_token: page.next_page_token,
        scan_complete,
        sort_available: page_token.is_empty() && scan_complete,
        access: display.access,
    };
    if req.method == Method::HEAD {
        return Ok(answer(200, HeaderMap::new(), empty()));
    }
    Ok(json(200, &answer_body))
}

fn object_item(relative: &str, object: &ObjectInfo) -> ListItem {
    ListItem {
        item_type: "content",
        name: last_part(relative).to_owned(),
        key: relative.to_owned(),
        size: object.size,
        last_modified: known_time(object.last_modified),
        etag: object.etag.clone(),
        content_type: object.content_type.clone(),
        unreadable: object.unreadable,
        ..ListItem::default()
    }
}

/// The handler of `/api/stats`.
pub fn handle_stats(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        if req.method != Method::GET {
            return method_not_allowed(&["GET"]);
        }
        api_result(stats(&app, &split(req).0).await)
    })
}

async fn stats(app: &App, req: &RequestHead) -> Result<Response> {
    let instance = app.instance_of("", req.query.get("instance"))?;
    let prefix = normalize_prefix(&clean_relative_key(req.query.get("prefix")));
    instance.require_permission(PERMISSION_READ)?;
    crate::access::authorize_read(app, &req.ctx, instance, &prefix).await?;
    let job = match seams::reusable_stats_job(app, &instance.cfg.id, &prefix) {
        Some(job) => job,
        None => app.jobs.create(JobState {
            job_type: job_type::STATS_PREFIX.to_owned(),
            instance: instance.cfg.id.clone(),
            prefix,
            ..JobState::default()
        })?,
    };
    if job.status == "completed" && job.stats.is_some() {
        return Ok(seams::job_answer(200, &job));
    }
    if let Some(finished) = app.jobs.wait_for_terminal(&job.id, STATS_INLINE_WAIT).await {
        return Ok(seams::job_answer(200, &finished));
    }
    Ok(seams::job_answer(202, &job))
}

/// The body of a copy or a rename.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ObjectOperationRequest {
    /// The instance.
    pub instance: String,
    /// The source key or prefix.
    pub src: String,
    /// The target key or prefix.
    pub dst: String,
    /// True for a prefix.
    #[serde(rename = "isPrefix")]
    pub is_prefix: bool,
}

/// The body of a delete of a prefix.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct DeletePrefixRequest {
    /// The instance.
    pub instance: String,
    /// The prefix.
    pub prefix: String,
}

/// Clean the source and the target of a copy or a move of a prefix.
pub fn validate_prefix_operation(source: &str, target: &str) -> Result<(String, String)> {
    let source = normalize_prefix(&clean_relative_key(source));
    let target = normalize_prefix(&clean_relative_key(target));
    if source.is_empty() || target.is_empty() {
        return Err(Error::api(400, "invalid_path", "src and dst are required"));
    }
    if source == target {
        return Err(Error::api(400, "same_path", "src and dst must be different"));
    }
    if target.starts_with(&source) {
        return Err(Error::api(
            400,
            "recursive_destination",
            "destination cannot be inside source prefix",
        ));
    }
    if source.starts_with(&target) {
        return Err(Error::api(
            400,
            "overlapping_prefixes",
            "destination cannot contain source prefix because object paths would overlap",
        ));
    }
    Ok((source, target))
}

/// Clean the source and the target of a copy or a move of one object. It makes no storage call.
pub fn clean_object_pair(source: &str, target: &str) -> Result<(String, String)> {
    let (source, target) = (clean_relative_key(source), clean_relative_key(target));
    if source.is_empty() || target.is_empty() {
        return Err(Error::api(400, "invalid_path", "src and dst are required"));
    }
    if source == target {
        return Err(Error::api(400, "same_path", "src and dst must be different"));
    }
    Ok((source, target))
}

/// The permissions of a copy: read the source, then write the target (the use).
pub fn copy_operation(app: &App, instance: &Instance, source: &str, target: &str) -> Operation {
    Operation {
        others: vec![object_ask(app, ACTION_READ, instance, source)],
        use_ask: object_ask(app, ACTION_WRITE, instance, target),
        continuation: false,
    }
}

/// The permissions of a move: read the source and write the target, then delete the source (the use).
pub fn move_operation(app: &App, instance: &Instance, source: &str, target: &str) -> Operation {
    Operation {
        others: vec![
            object_ask(app, ACTION_READ, instance, source),
            object_ask(app, ACTION_WRITE, instance, target),
        ],
        use_ask: object_ask(app, ACTION_DELETE, instance, source),
        continuation: false,
    }
}

/// The permissions of the delete of a prefix: read it, then delete it (the use).
pub fn delete_prefix_operation(app: &App, instance: &Instance, prefix: &str) -> Operation {
    Operation {
        others: vec![object_ask(app, ACTION_READ, instance, prefix)],
        use_ask: object_ask(app, ACTION_DELETE, instance, prefix),
        continuation: false,
    }
}

/// The ceilings that a job keeps: a copy of the ceilings of the request, or `None` in mode `open`.
fn job_ceilings(ctx: &OpCtx) -> Option<Arc<Ceilings>> {
    ctx.ceilings.as_ref().map(|ceilings| Arc::new(ceilings.snapshot()))
}

/// Check the ceilings of read and of write for the size of an object that the operation copies.
pub fn check_copy_ceilings(ctx: &OpCtx, size: i64) -> Result<()> {
    check_object_ceiling(ctx, ACTION_READ, size)?;
    check_object_ceiling(ctx, ACTION_WRITE, size)
}

/// The error of a move whose copy is made and whose source stays.
pub fn source_deletion_error(error: Error) -> Error {
    if crate::bucket::is_object_locked(&error) {
        return Error::api(
            409,
            "object_locked",
            format!("The copy is made, but the source stays. {error}"),
        );
    }
    error
}

/// Start a job for the copy or the move of one object from the threshold of the copy in parts up. Gives `None` for a
/// smaller object, for a back end that copies each size in one request, and for a move that one rename makes.
pub async fn start_large_copy(
    app: &App,
    ctx: &OpCtx,
    instance: &Instance,
    source: &str,
    target: &str,
    move_object: bool,
) -> Result<Option<JobState>> {
    if instance.backend.multipart_copier().is_none() {
        return Ok(None);
    }
    if move_object && instance.moves_objects() {
        return Ok(None);
    }
    let (source, target) = (clean_relative_key(source), clean_relative_key(target));
    if source.is_empty() || target.is_empty() || source == target {
        return Ok(None);
    }
    // The copy names no version: the HEAD reads the current version, as the copy does.
    let head = instance
        .head(&ctx.with_version(None), &instance.full_key(&source))
        .await?;
    let length = head
        .headers
        .get(CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .trim()
        .to_owned();
    let Ok(size) = length.parse::<i64>() else {
        return Ok(None);
    };
    check_copy_ceilings(ctx, size)?;
    if !instance.copies_in_parts(size) {
        return Ok(None);
    }
    let kind = if move_object {
        job_type::MOVE_OBJECT
    } else {
        job_type::COPY_OBJECT
    };
    let job = app.jobs.create(JobState {
        job_type: kind.to_owned(),
        instance: instance.cfg.id.clone(),
        source,
        target,
        total_bytes: size,
        ceilings: job_ceilings(ctx),
        ..JobState::default()
    })?;
    Ok(Some(job))
}

/// Each object under a prefix, page after page: the object and its relative key.
pub async fn for_each_object(
    ctx: &OpCtx,
    instance: &Instance,
    prefix: &str,
    mut visit: impl FnMut(&ObjectInfo, &str) -> Result<()>,
) -> Result<()> {
    let mut page_token = String::new();
    loop {
        let page = instance
            .list(
                ctx,
                &ListOptions {
                    prefix: instance.full_key(prefix),
                    max_results: 1000,
                    page_token: page_token.clone(),
                    ..ListOptions::default()
                },
            )
            .await?;
        for object in &page.objects {
            let Some(relative) = instance.relative_key(&object.key) else {
                continue;
            };
            visit(object, &relative)?;
        }
        if page.next_page_token.is_empty() {
            return Ok(());
        }
        if page.next_page_token == page_token {
            return Err(Error::internal("provider returned the same continuation token twice"));
        }
        page_token = page.next_page_token;
    }
}

/// Copy or move one object or each object of a prefix. Gives the number of objects.
pub async fn copy_or_move(
    ctx: &OpCtx,
    instance: &Instance,
    source: &str,
    target: &str,
    is_prefix: bool,
    move_object: bool,
) -> Result<usize> {
    let mut source = clean_relative_key(source);
    let mut target = clean_relative_key(target);
    if is_prefix {
        source = normalize_prefix(&source);
        target = normalize_prefix(&target);
    }
    if source.is_empty() || target.is_empty() {
        return Err(Error::api(400, "invalid_path", "src and dst are required"));
    }
    if source == target {
        return Err(Error::api(400, "same_path", "src and dst must be different"));
    }
    if is_prefix && target.starts_with(&source) {
        return Err(Error::api(
            400,
            "recursive_destination",
            "destination cannot be inside source prefix",
        ));
    }
    if is_prefix && source.starts_with(&target) {
        return Err(Error::api(
            400,
            "overlapping_prefixes",
            "destination cannot contain source prefix because object paths would overlap",
        ));
    }
    if !is_prefix {
        if move_object && instance.moves_objects() {
            instance
                .move_object(ctx, &instance.full_key(&source), &instance.full_key(&target))
                .await?;
            return Ok(1);
        }
        instance
            .copy(ctx, &instance.full_key(&source), &instance.full_key(&target))
            .await?;
        if move_object {
            instance
                .delete(ctx, &instance.full_key(&source))
                .await
                .map_err(source_deletion_error)?;
        }
        return Ok(1);
    }
    let mut keys = Vec::new();
    let mut sizes = Vec::new();
    for_each_object(ctx, instance, &source, |object, relative| {
        keys.push(relative.to_owned());
        sizes.push(object.size);
        Ok(())
    })
    .await?;
    if keys.is_empty() {
        return Err(Error::api(404, "empty_prefix", "source prefix contains no objects"));
    }
    // Each size is known now: the check of each ceiling comes before the first effect.
    for size in &sizes {
        check_copy_ceilings(ctx, *size)?;
    }
    let mut copied = 0;
    if move_object && instance.moves_objects() {
        for key in &keys {
            let destination = format!("{target}{}", key.strip_prefix(source.as_str()).unwrap_or(key));
            instance
                .move_object(ctx, &instance.full_key(key), &instance.full_key(&destination))
                .await?;
            copied += 1;
        }
        instance.remove_empty_folders(ctx, &instance.full_key(&source)).await?;
        return Ok(copied);
    }
    for (key, size) in keys.iter().zip(&sizes) {
        let destination = format!("{target}{}", key.strip_prefix(source.as_str()).unwrap_or(key));
        instance
            .copy_sized(
                ctx,
                &instance.full_key(key),
                &instance.full_key(&destination),
                *size,
                None,
            )
            .await?;
        copied += 1;
    }
    if move_object {
        let full_keys: Vec<String> = keys.iter().map(|key| instance.full_key(key)).collect();
        let locked = instance.delete_many(ctx, &full_keys).await?;
        if let Some(first) = locked.first() {
            let first = instance.relative_key(first).unwrap_or_default();
            return Err(Error::api(
                409,
                "object_locked",
                format!(
                    "All copies are made, but {} source(s) stay: Object Lock keeps them (the first is {first:?}).",
                    locked.len()
                ),
            ));
        }
    }
    Ok(copied)
}

#[derive(Serialize)]
struct CopiedAnswer {
    copied: usize,
}

#[derive(Serialize)]
struct MovedAnswer {
    moved: usize,
}

/// The handler of `POST /api/copy`.
pub fn handle_copy(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        if req.method != Method::POST {
            return method_not_allowed(&["POST"]);
        }
        api_result(copy_or_rename(&app, req, false).await)
    })
}

/// The handler of `POST /api/rename`.
pub fn handle_rename(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        if req.method != Method::POST {
            return method_not_allowed(&["POST"]);
        }
        api_result(copy_or_rename(&app, req, true).await)
    })
}

async fn copy_or_rename(app: &App, req: Req, move_object: bool) -> Result<Response> {
    let Req { body, query, ctx, .. } = req;
    let request: ObjectOperationRequest = decode_json(body).await?;
    let instance = app.instance_of(&request.instance, query.get("instance"))?;
    let permissions: &[&str] = if move_object {
        &[PERMISSION_READ, PERMISSION_WRITE, PERMISSION_DELETE]
    } else {
        &[PERMISSION_READ, PERMISSION_WRITE]
    };
    for permission in permissions {
        instance.require_permission(permission)?;
    }
    let operation = |source: &str, target: &str| {
        if move_object {
            move_operation(app, instance, source, target)
        } else {
            copy_operation(app, instance, source, target)
        }
    };
    if request.is_prefix {
        let (source, target) = validate_prefix_operation(&request.src, &request.dst)?;
        crate::access::authorize(app, &ctx, operation(&source, &target)).await?;
        let kind = if move_object {
            job_type::MOVE_PREFIX
        } else {
            job_type::COPY_PREFIX
        };
        let job = app.jobs.create(JobState {
            job_type: kind.to_owned(),
            instance: instance.cfg.id.clone(),
            source,
            target,
            ceilings: job_ceilings(&ctx),
            ..JobState::default()
        })?;
        return Ok(seams::job_answer(202, &job));
    }
    let (source, target) = clean_object_pair(&request.src, &request.dst)?;
    crate::access::authorize(app, &ctx, operation(&source, &target)).await?;
    if let Some(job) = start_large_copy(app, &ctx, instance, &source, &target, move_object).await? {
        return Ok(seams::job_answer(202, &job));
    }
    let count = copy_or_move(&ctx, instance, &source, &target, false, move_object).await?;
    if move_object {
        return Ok(json(200, &MovedAnswer { moved: count }));
    }
    Ok(json(200, &CopiedAnswer { copied: count }))
}

/// The handler of `POST /api/delete-prefix`.
pub fn handle_delete_prefix(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        if req.method != Method::POST {
            return method_not_allowed(&["POST"]);
        }
        api_result(delete_prefix(&app, req).await)
    })
}

async fn delete_prefix(app: &App, req: Req) -> Result<Response> {
    let Req { body, query, ctx, .. } = req;
    let request: DeletePrefixRequest = decode_json(body).await?;
    let instance = app.instance_of(&request.instance, query.get("instance"))?;
    let prefix = normalize_prefix(&clean_relative_key(&request.prefix));
    for permission in [PERMISSION_READ, PERMISSION_DELETE] {
        instance.require_permission(permission)?;
    }
    if prefix.is_empty() {
        return Err(Error::api(
            400,
            "invalid_prefix",
            "refusing to delete the whole bucket; prefix is required",
        ));
    }
    crate::access::authorize(app, &ctx, delete_prefix_operation(app, instance, &prefix)).await?;
    let job = app.jobs.create(JobState {
        job_type: job_type::DELETE_PREFIX.to_owned(),
        instance: instance.cfg.id.clone(),
        prefix,
        ..JobState::default()
    })?;
    Ok(seams::job_answer(202, &job))
}

#[derive(Serialize)]
struct HealthAnswer {
    instances: usize,
    status: &'static str,
}

/// The handler of `/healthz`.
pub fn handle_health(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        if req.method != Method::GET && req.method != Method::HEAD {
            return method_not_allowed(&["GET", "HEAD"]);
        }
        if req.method == Method::HEAD {
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            return answer(200, headers, empty());
        }
        json(
            200,
            &HealthAnswer {
                instances: app.instances.len(),
                status: "ok",
            },
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(item_type: &'static str, name: &str) -> ListItem {
        ListItem {
            item_type,
            name: name.to_owned(),
            ..ListItem::default()
        }
    }

    #[test]
    fn listing_puts_folders_first_and_ignores_case() {
        let mut items = vec![
            item("content", "b.txt"),
            item("prefix", "Zeta/"),
            item("content", "A.txt"),
            item("prefix", "alpha/"),
            item("content", "a.txt"),
        ];
        sort_list_items(&mut items);
        let names: Vec<&str> = items.iter().map(|item| item.name.as_str()).collect();
        // Stable for names that differ only by case: "A.txt" was listed before "a.txt".
        assert_eq!(names, vec!["alpha/", "Zeta/", "A.txt", "a.txt", "b.txt"]);
    }

    #[test]
    fn excludes_are_cleaned_prefixes() {
        assert_eq!(parse_excludes(&["a/, /b ,", "c"]), vec!["a/", "b", "c"]);
        assert!(is_excluded("a/x", &parse_excludes(&["a/"])));
    }

    #[test]
    fn prefix_operations_refuse_overlaps() {
        assert!(
            validate_prefix_operation("folder/", "folder/copy/")
                .unwrap_err()
                .has_code("recursive_destination")
        );
        assert!(
            validate_prefix_operation("folder/nested/", "folder/")
                .unwrap_err()
                .has_code("overlapping_prefixes")
        );
        assert!(validate_prefix_operation("a", "a/").unwrap_err().has_code("same_path"));
        assert_eq!(
            validate_prefix_operation("/a", "b").unwrap(),
            ("a/".to_owned(), "b/".to_owned())
        );
        assert!(clean_object_pair("", "b").unwrap_err().has_code("invalid_path"));
    }
}
