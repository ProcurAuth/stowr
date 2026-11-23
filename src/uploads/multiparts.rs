//! The incomplete multipart uploads of a bucket: the list, the abort of chosen uploads and the job that aborts the
//! old ones (docs/ARCHITECTURE.md, "Cleanup of incomplete multipart uploads").
//!
//! The age of an upload comes from its `Initiated` date. SeaweedFS sends no such date: the age is unknown, and the
//! abort by age never aborts such an upload. An abort by age never aborts an upload younger than 24 hours. No abort
//! touches an upload that the upload manager of this process uses. Only the S3 back end has the list: the GCS back
//! end answers `501`.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use super::session::nanos_between;
use super::target::UploadTarget;
use super::{
    MultipartAbortJob, MultipartAbortResult, MultipartCursor, MultipartPartsSummary, MultipartUpload,
    MultipartUploadLister, MultipartUploadPage, UploadManager,
};
use crate::common::config::{PERMISSION_READ, PERMISSION_WRITE, PROVIDER_VOLUME};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::json;
use crate::common::time::Timestamp;
use crate::instance::Instance;
use crate::instance::gate::{self, Slot};
use crate::jobs::{JobRun, JobState};

/// The number of uploads in one answer of the list, when the request gives no number.
pub const DEFAULT_LIST_SIZE: usize = 100;
/// The largest number of uploads in one answer of the list.
pub const MAXIMUM_LIST_SIZE: usize = 500;
/// The limit of provider pages that one answer of the list reads.
pub const LIST_PAGES: usize = 10;
/// The `max-uploads` of each provider page that the abort job reads.
pub const SCAN_PAGE_SIZE: usize = 1000;
/// The `max-parts` of the one `ListParts` request for each listed upload. An upload with more parts shows "at least"
/// this count and the size of these parts.
pub const PARTS_PAGE_SIZE: u32 = 1000;
/// The number of `ListParts` requests of one answer at the same time.
pub const PARTS_WORKERS: usize = 4;
/// The limit of uploads in one request of "Abort selected".
pub const MAXIMUM_ABORT_ITEMS: usize = 1000;
/// The largest age in days that the abort by age accepts.
pub const MAXIMUM_ABORT_DAYS: i64 = 36500;
/// The youngest upload that the abort by age can abort: 24 hours.
pub const MINIMUM_ABORT_AGE: Duration = Duration::from_secs(24 * 60 * 60);
/// The reason of the skip of an upload that this process sends now.
pub const ACTIVE_UPLOAD_REASON: &str = "this Stowr process sends this upload now";

/// The time that the start probe waits for the provider.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// `501 multipart_unsupported`.
pub fn multipart_unsupported() -> Error {
    Error::api(
        501,
        "multipart_unsupported",
        "this storage provider does not let Stowr list the incomplete multipart uploads",
    )
}

/// `400 invalid_multipart_request`.
pub fn invalid_multipart_request(message: impl Into<String>) -> Error {
    Error::api(400, "invalid_multipart_request", message)
}

/// True for a provider that does not know a request: it answers 501 or 405.
pub fn provider_refused_feature(error: &Error) -> bool {
    error.as_upstream().is_some_and(|upstream| {
        upstream.status == 501
            || upstream.status == 405
            || upstream.code == "NotImplemented"
            || upstream.code == "MethodNotAllowed"
    })
}

/// True for the 404 of an upload that the provider does not know.
pub fn is_no_such_upload(error: &Error) -> bool {
    error
        .as_upstream()
        .is_some_and(|upstream| upstream.status == 404 || upstream.code == "NoSuchUpload")
}

/// The form of the cursor in the page token: the markers and the position, with short names. An empty value is not in
/// the text.
#[derive(Deserialize)]
struct RawCursor {
    #[serde(default, rename = "k")]
    key_marker: String,
    #[serde(default, rename = "u")]
    upload_id_marker: String,
    #[serde(default, rename = "i")]
    skip: i64,
}

/// The page token of a cursor. An empty cursor gives an empty text.
pub fn encode_multipart_cursor(cursor: &MultipartCursor) -> String {
    if *cursor == MultipartCursor::default() {
        return String::new();
    }
    json::to_vec(cursor)
        .map(|data| URL_SAFE_NO_PAD.encode(data))
        .unwrap_or_default()
}

/// The cursor of a page token. A token that is not valid gives `400 invalid_page_token`.
pub fn decode_multipart_cursor(token: &str) -> Result<MultipartCursor> {
    if token.is_empty() {
        return Ok(MultipartCursor::default());
    }
    let invalid = || {
        Error::api(
            400,
            "invalid_page_token",
            "the page token of the incomplete uploads is not valid: open the list again",
        )
    };
    let data = URL_SAFE_NO_PAD.decode(token).map_err(|_| invalid())?;
    if data.len() > 4096 {
        return Err(invalid());
    }
    if data == b"null" {
        return Ok(MultipartCursor::default());
    }
    let raw: RawCursor = serde_json::from_slice(&data).map_err(|_| invalid())?;
    if raw.skip < 0 {
        return Err(invalid());
    }
    Ok(MultipartCursor {
        key_marker: raw.key_marker,
        upload_id_marker: raw.upload_id_marker,
        skip: u32::try_from(raw.skip).unwrap_or(u32::MAX),
    })
}

// --- Storage instance ------------------------------------------------------------------------------------------------

/// Count one provider call and take the slots of the gates.
async fn begin_request(instance: &Instance, ctx: &OpCtx) -> Result<Slot> {
    if let Some(budget) = &ctx.budget {
        budget.consume_request()?;
    }
    gate::acquire(ctx, &[&instance.global_gate, &instance.gate]).await
}

/// Learn the `read` permission from the result of a provider call, as each call of the instance does.
fn observe_read<T>(instance: &Instance, result: &Result<T>) {
    if !instance.cfg.allows(PERMISSION_READ) {
        return;
    }
    let next = match result {
        Ok(_) => crate::common::storage::CapabilityState {
            state: crate::common::storage::CapabilityStateName::Allowed,
            allowed: true,
            verified: true,
            source: "observed".to_owned(),
            reason: "a real provider operation succeeded during this process".to_owned(),
            expires: None,
        },
        Err(error) => match error.as_upstream() {
            Some(upstream) if upstream.status == 401 || upstream.status == 403 => {
                crate::common::storage::CapabilityState {
                    state: crate::common::storage::CapabilityStateName::Denied,
                    allowed: false,
                    verified: true,
                    source: "provider".to_owned(),
                    reason: "the storage provider denied a real operation during this process".to_owned(),
                    // One object's 403 is not a verdict for the instance: it shows for a short time and is never
                    // enforced.
                    expires: Some(Timestamp::now().plus_secs(60)),
                }
            }
            _ => return,
        },
    };
    if let Ok(mut caps) = instance.caps.lock()
        && caps.read.source != "runtime"
        && caps.read.source != "configuration"
    {
        caps.read = next;
        caps.checked_at = Some(Timestamp::now());
    }
}

impl Instance {
    /// True when the instance can list its incomplete uploads. Until the probe has run, the answer is yes for a back
    /// end that has the list.
    pub fn multipart_uploads_available(&self) -> bool {
        self.backend.multipart_lister().is_some() && !self.multiparts.off.load(Ordering::SeqCst)
    }

    /// The list of the incomplete uploads of the back end, or `501 multipart_unsupported`.
    pub fn multipart_lister(&self) -> Result<&dyn MultipartUploadLister> {
        match self.backend.multipart_lister() {
            Some(lister) if !self.multiparts.off.load(Ordering::SeqCst) => Ok(lister),
            _ => Err(multipart_unsupported()),
        }
    }

    /// Ask for one incomplete upload. A provider without the list answers 501 or 405. Any other failure (denied,
    /// timeout) leaves the answer at yes. An instance without the read permission is not probed. A volume lists its
    /// temporary files, and the probe would read its tree at start.
    pub async fn probe_multipart_uploads(&self, ctx: &OpCtx) {
        let Some(lister) = self.backend.multipart_lister() else {
            return;
        };
        if !self.permitted(PERMISSION_READ) || self.cfg.provider == PROVIDER_VOLUME {
            return;
        }
        let ctx = ctx.with_timeout(PROBE_TIMEOUT);
        let outcome =
            tokio::time::timeout(PROBE_TIMEOUT, lister.list_uploads(&ctx, &MultipartCursor::default(), 1)).await;
        if let Ok(Err(error)) = outcome
            && provider_refused_feature(&error)
        {
            self.multiparts.off.store(true, Ordering::SeqCst);
        }
    }

    /// Read one page of the provider. A provider that refuses the request turns the list off.
    pub async fn list_multipart_uploads(
        &self,
        ctx: &OpCtx,
        cursor: &MultipartCursor,
        maximum: u32,
    ) -> Result<MultipartUploadPage> {
        let lister = self.multipart_lister()?;
        let _slot = begin_request(self, ctx).await?;
        let markers = MultipartCursor {
            key_marker: cursor.key_marker.clone(),
            upload_id_marker: cursor.upload_id_marker.clone(),
            skip: 0,
        };
        let result = lister.list_uploads(ctx, &markers, maximum).await;
        if let Err(error) = &result
            && provider_refused_feature(error)
        {
            self.multiparts.off.store(true, Ordering::SeqCst);
            return Err(multipart_unsupported());
        }
        observe_read(self, &result);
        result
    }

    /// Read the first page of the parts of one upload.
    pub async fn multipart_upload_parts(
        &self,
        ctx: &OpCtx,
        key: &str,
        upload_id: &str,
    ) -> Result<MultipartPartsSummary> {
        let lister = self.multipart_lister()?;
        let _slot = begin_request(self, ctx).await?;
        let result = lister.upload_parts(ctx, key, upload_id, PARTS_PAGE_SIZE).await;
        observe_read(self, &result);
        result
    }
}

// --- List ------------------------------------------------------------------------------------------------------------

/// Read the page of the cursor and check that the provider moves its markers forward.
pub async fn next_multipart_page(
    target: &dyn UploadTarget,
    ctx: &OpCtx,
    cursor: &MultipartCursor,
    maximum: u32,
) -> Result<MultipartUploadPage> {
    let page = target.list_multipart_uploads(ctx, cursor, maximum).await?;
    if let Some(next) = &page.next
        && (*next == MultipartCursor::default()
            || (next.key_marker == cursor.key_marker && next.upload_id_marker == cursor.upload_id_marker))
    {
        return Err(Error::api(
            502,
            "provider_paging",
            "the storage provider sent the same page of incomplete uploads again: Stowr stops the list",
        ));
    }
    Ok(page)
}

/// The key of an upload relative to the root prefix of the instance, and `None` for an upload outside the root prefix
/// or outside `prefix`.
pub fn multipart_relative_key(target: &dyn UploadTarget, upload: &MultipartUpload, prefix: &str) -> Option<String> {
    let relative = target.relative_key(&upload.key)?;
    if relative.is_empty() || !relative.starts_with(prefix) {
        return None;
    }
    Some(relative)
}

/// The uploads of one answer of the list: the uploads, the relative key of each one, and the cursor of the next
/// answer (an empty cursor at the end of the list).
pub struct CollectedUploads {
    /// The uploads with the full key of the provider.
    pub uploads: Vec<MultipartUpload>,
    /// The key of each upload relative to the root prefix.
    pub relatives: Vec<String>,
    /// The cursor of the next answer.
    pub next: MultipartCursor,
}

/// Collect up to `limit` uploads under `prefix` from the cursor. The function reads at most [`LIST_PAGES`] pages of
/// the provider.
pub async fn collect_multipart_uploads(
    target: &dyn UploadTarget,
    ctx: &OpCtx,
    prefix: &str,
    mut cursor: MultipartCursor,
    limit: usize,
) -> Result<CollectedUploads> {
    let mut uploads = Vec::with_capacity(limit);
    let mut relatives = Vec::with_capacity(limit);
    for _ in 0..LIST_PAGES {
        let wanted = (limit - uploads.len() + cursor.skip as usize).min(SCAN_PAGE_SIZE);
        let page = next_multipart_page(target, ctx, &cursor, u32::try_from(wanted).unwrap_or(u32::MAX)).await?;
        for (index, upload) in page.uploads.iter().enumerate().skip(cursor.skip as usize) {
            if uploads.len() == limit {
                // The provider sends more than the request asks: the next answer starts at this position.
                return Ok(CollectedUploads {
                    uploads,
                    relatives,
                    next: MultipartCursor {
                        key_marker: cursor.key_marker.clone(),
                        upload_id_marker: cursor.upload_id_marker.clone(),
                        skip: u32::try_from(index).unwrap_or(u32::MAX),
                    },
                });
            }
            if let Some(relative) = multipart_relative_key(target, upload, prefix) {
                uploads.push(upload.clone());
                relatives.push(relative);
            }
        }
        let Some(next) = page.next else {
            return Ok(CollectedUploads {
                uploads,
                relatives,
                next: MultipartCursor::default(),
            });
        };
        cursor = next;
        if uploads.len() == limit {
            return Ok(CollectedUploads {
                uploads,
                relatives,
                next: cursor,
            });
        }
    }
    Ok(CollectedUploads {
        uploads,
        relatives,
        next: cursor,
    })
}

/// One incomplete upload in the answer of the list.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct MultipartUploadJson {
    /// The key relative to the root prefix.
    pub key: String,
    /// The upload id.
    #[serde(rename = "uploadId")]
    pub upload_id: String,
    /// The start (RFC 3339, in seconds), when the provider gives it.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub initiated: String,
    /// The parts of the first page of the parts.
    pub parts: u32,
    /// The bytes of the parts of the first page.
    pub bytes: i64,
    /// True when the upload has more parts than the page.
    #[serde(rename = "partsAtLeast", skip_serializing_if = "std::ops::Not::not")]
    pub parts_at_least: bool,
    /// True when the provider does not give the parts.
    #[serde(rename = "partsUnknown", skip_serializing_if = "std::ops::Not::not")]
    pub parts_unknown: bool,
    /// True when this process sends the upload now. No abort touches it.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub active: bool,
}

/// The answer of `GET /api/multiparts`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct MultipartListResponse {
    /// The instance.
    pub instance: String,
    /// The prefix.
    pub prefix: String,
    /// The uploads.
    pub uploads: Vec<MultipartUploadJson>,
    /// The page token of the next answer.
    #[serde(rename = "nextToken", skip_serializing_if = "String::is_empty")]
    pub next_token: String,
    /// The time of the server: the page gives the age of each upload from it.
    pub now: String,
    /// The youngest upload that the abort by age can abort, in hours.
    #[serde(rename = "minimumAbortAgeHours")]
    pub minimum_abort_age_hours: u64,
    /// The `max-parts` of the list of the parts.
    #[serde(rename = "partsPageSize")]
    pub parts_page_size: u32,
}

/// Read the first page of the parts of each upload, [`PARTS_WORKERS`] at a time. An upload that the provider no
/// longer knows (completed or aborted since the list) is left out.
pub async fn describe_multipart_uploads(
    ctx: &OpCtx,
    target: &Arc<dyn UploadTarget>,
    uploads: Vec<MultipartUpload>,
    relatives: Vec<String>,
    active: &BTreeSet<String>,
) -> Vec<MultipartUploadJson> {
    struct Work {
        uploads: Vec<MultipartUpload>,
        relatives: Vec<String>,
        active: Vec<bool>,
        next: AtomicUsize,
        results: Mutex<Vec<Option<MultipartUploadJson>>>,
    }
    let count = uploads.len();
    let work = Arc::new(Work {
        active: uploads
            .iter()
            .map(|upload| active.contains(&upload.upload_id))
            .collect(),
        uploads,
        relatives,
        next: AtomicUsize::new(0),
        results: Mutex::new(vec![None; count]),
    });
    let mut workers = tokio::task::JoinSet::new();
    for _ in 0..PARTS_WORKERS.min(count) {
        let work = work.clone();
        let target = target.clone();
        let ctx = ctx.clone();
        workers.spawn(async move {
            loop {
                let index = work.next.fetch_add(1, Ordering::SeqCst);
                if index >= work.uploads.len() {
                    return;
                }
                let upload = &work.uploads[index];
                let mut item = MultipartUploadJson {
                    key: work.relatives[index].clone(),
                    upload_id: upload.upload_id.clone(),
                    active: work.active[index],
                    initiated: upload
                        .initiated
                        .map(|initiated| initiated.utc().rfc3339())
                        .unwrap_or_default(),
                    ..MultipartUploadJson::default()
                };
                match target
                    .multipart_upload_parts(&ctx, &upload.key, &upload.upload_id)
                    .await
                {
                    Err(error) if is_no_such_upload(&error) => continue,
                    Err(_) => item.parts_unknown = true,
                    Ok(summary) => {
                        item.parts = summary.parts;
                        item.bytes = summary.bytes;
                        item.parts_at_least = summary.at_least;
                        item.parts_unknown = summary.unknown;
                    }
                }
                if let Ok(mut results) = work.results.lock() {
                    results[index] = Some(item);
                }
            }
        });
    }
    while workers.join_next().await.is_some() {}
    work.results
        .lock()
        .map(|results| results.iter().flatten().cloned().collect())
        .unwrap_or_default()
}

// --- Abort -----------------------------------------------------------------------------------------------------------

/// One upload in a request of "Abort selected".
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MultipartAbortItem {
    /// The key relative to the root prefix.
    #[serde(default)]
    pub key: String,
    /// The upload id that the list gave.
    #[serde(default, rename = "uploadId")]
    pub upload_id: String,
}

/// One upload that an abort does not abort.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct MultipartAbortFailure {
    /// The key.
    pub key: String,
    /// The upload id.
    #[serde(rename = "uploadId")]
    pub upload_id: String,
    /// The reason.
    pub reason: String,
}

/// The answer of "Abort selected".
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct MultipartAbortResponse {
    /// The uploads that the provider no longer has.
    pub aborted: Vec<MultipartAbortItem>,
    /// The uploads that the request keeps.
    pub skipped: Vec<MultipartAbortFailure>,
    /// The uploads that the provider refuses to abort.
    pub failed: Vec<MultipartAbortFailure>,
}

/// An upload id that the list can give: 1 to 1024 characters 0x20 to 0x7E, with no space at the start or the end.
pub fn valid_multipart_upload_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 1024 && printable_ascii(id)
}

fn printable_ascii(text: &str) -> bool {
    text == text.trim() && text.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

/// Abort each listed upload, at any age. The function skips an upload that this process sends now. An upload that the
/// provider no longer knows counts as aborted.
pub async fn abort_selected_multiparts(
    manager: &UploadManager,
    target: &dyn UploadTarget,
    ctx: &OpCtx,
    items: &[MultipartAbortItem],
) -> MultipartAbortResponse {
    let mut response = MultipartAbortResponse::default();
    let active = manager.active_provider_uploads(target.id());
    for item in items {
        if active.contains(&item.upload_id) {
            response.skipped.push(MultipartAbortFailure {
                key: item.key.clone(),
                upload_id: item.upload_id.clone(),
                reason: ACTIVE_UPLOAD_REASON.to_owned(),
            });
            continue;
        }
        match target
            .abort_multipart(ctx, &target.full_key(&item.key), &item.upload_id)
            .await
        {
            Ok(()) => response.aborted.push(item.clone()),
            Err(error) => response.failed.push(MultipartAbortFailure {
                key: item.key.clone(),
                upload_id: item.upload_id.clone(),
                reason: error.public_message(),
            }),
        }
    }
    response
}

/// What the abort job needs from the job that runs it: the control of the person and the save of the progress.
pub trait JobProgress: Sync {
    /// `Err(Error::Interrupted)` when a person paused or canceled the job.
    fn check_control(&self) -> Result<()>;
    /// Save the progress of the job.
    fn save(&self, job: &JobState) -> Result<()>;
}

impl JobProgress for JobRun {
    fn check_control(&self) -> Result<()> {
        JobRun::check_control(self)
    }

    fn save(&self, job: &JobState) -> Result<()> {
        JobRun::save(self, job)
    }
}

/// Run the job `abort_multiparts`: read the whole list of the provider and abort each upload under the prefix of the
/// job that started before the cutoff of the job. An upload without a date, an upload younger than 24 hours and an
/// upload that this process sends stay. A job that runs again reads the list again from the start: the aborted uploads
/// are gone, and the counts of the skipped uploads start again from zero.
pub async fn run_abort_multiparts(
    manager: &UploadManager,
    target: &dyn UploadTarget,
    ctx: &OpCtx,
    progress: &dyn JobProgress,
    job: &mut JobState,
) -> Result<()> {
    let Some(request) = job
        .multipart_abort
        .clone()
        .filter(|request| request.older_than_days >= 1)
    else {
        return Err(invalid_multipart_request("the job has no age"));
    };
    let result = job.multipart_result.get_or_insert_with(MultipartAbortResult::default);
    result.skipped_undated = 0;
    result.skipped_recent = 0;
    result.skipped_active = 0;
    result.failed = 0;
    job.processed = 0;
    let minimum_age = i128::try_from(MINIMUM_ABORT_AGE.as_nanos()).unwrap_or(i128::MAX);
    let mut cursor = MultipartCursor::default();
    loop {
        progress.check_control()?;
        let page = next_multipart_page(target, ctx, &cursor, SCAN_PAGE_SIZE as u32).await?;
        let active = manager.active_provider_uploads(target.id());
        for upload in &page.uploads {
            let Some(relative) = multipart_relative_key(target, upload, &job.prefix) else {
                continue;
            };
            progress.check_control()?;
            job.processed += 1;
            let now = Timestamp::now();
            let result = job.multipart_result.get_or_insert_with(MultipartAbortResult::default);
            match upload.initiated {
                None => result.skipped_undated += 1,
                Some(initiated)
                    if request.cutoff.is_none_or(|cutoff| initiated > cutoff)
                        || nanos_between(now, initiated) < minimum_age =>
                {
                    result.skipped_recent += 1;
                }
                Some(_) if active.contains(&upload.upload_id) => result.skipped_active += 1,
                Some(_) => match target.abort_multipart(ctx, &upload.key, &upload.upload_id).await {
                    Err(error) => {
                        if ctx.check().is_err() {
                            return Err(error);
                        }
                        result.failed += 1;
                    }
                    Ok(()) => {
                        result.aborted += 1;
                        job.last_key = relative;
                    }
                },
            }
            job.updated_at = now;
        }
        progress.save(job)?;
        progress.check_control()?;
        match page.next {
            None => return Ok(()),
            Some(next) => cursor = next,
        }
    }
}

/// The request of the job `abort_multiparts` with its cutoff: the time of the request minus the age.
pub fn abort_job_request(older_than_days: i64, now: Timestamp) -> MultipartAbortJob {
    MultipartAbortJob {
        older_than_days: u32::try_from(older_than_days).unwrap_or(0),
        cutoff: Some(now.plus_secs(-older_than_days.saturating_mul(24 * 60 * 60))),
    }
}

/// The permissions that the job needs, as the route checks them.
pub fn require_job_permissions(target: &dyn UploadTarget) -> Result<()> {
    for permission in [PERMISSION_READ, PERMISSION_WRITE] {
        target.require_permission(permission)?;
    }
    Ok(())
}
