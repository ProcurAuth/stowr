// SPDX-License-Identifier: MIT OR Apache-2.0
//! The uploads: the resumable upload sessions in memory, the sealed resume token `stowr1`, the SHA-256 checksums of
//! the parts, and the incomplete multipart uploads (docs/ARCHITECTURE.md, "Upload resume protocol", "Upload
//! checksums", "Cleanup of incomplete multipart uploads").
//!
//! This module owns `/api/uploads`, `/api/uploads/resume`, `/api/multiparts`, `/api/multiparts/abort`, the
//! job `abort_multiparts`, and the S3 list of the incomplete uploads (`impl MultipartUploadLister for S3Backend`).
//!
//! The upload manager and the incomplete-upload functions work with an [`UploadTarget`]: one storage instance with its
//! key and its permissions. The routes get the target of an instance from the application.

mod checksum;
mod handlers;
mod limit;
mod manager;
mod multipart_routes;
mod multiparts;
mod s3_list;
mod session;
mod target;
mod token;

#[cfg(test)]
mod checksum_tests;
#[cfg(test)]
mod handlers_tests;
#[cfg(test)]
mod manager_tests;
#[cfg(test)]
mod multiparts_tests;
#[cfg(test)]
mod session_tests;
#[cfg(test)]
pub(crate) mod test_fakes;
#[cfg(test)]
mod token_tests;

use std::sync::atomic::AtomicBool;

use serde::{Deserialize, Serialize};

use crate::common::BoxFuture;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Route, RouteAccess, route};
use crate::common::time::Timestamp;

pub use checksum::{
    CHECKSUM_HEADER, UPLOAD_CHECKSUM_SHA256, checksum_confirmed, composite_checksum, parse_checksum_header,
    same_composite_checksum, sha256_base64, verify_upload_checksum, with_checksum_transfer, with_upload_tags,
};
pub use handlers::{RESUME_TOKEN_HEADER, handle_uploads};
pub use limit::limit_body;
pub use manager::{
    ChunkInput, CreateUploadRequest, UPLOAD_IDLE_TTL, UPLOAD_REAP_ABORT_LIMIT, UPLOAD_REAP_INTERVAL, UploadManager,
    volume_session_upload_id,
};
pub use multipart_routes::{handle_multipart_abort, handle_multiparts};
pub use multiparts::{
    ACTIVE_UPLOAD_REASON, JobProgress, MINIMUM_ABORT_AGE, MultipartAbortFailure, MultipartAbortItem,
    MultipartAbortResponse, MultipartListResponse, MultipartUploadJson, abort_job_request, abort_selected_multiparts,
    collect_multipart_uploads, decode_multipart_cursor, describe_multipart_uploads, encode_multipart_cursor,
    invalid_multipart_request, is_no_such_upload, multipart_unsupported, next_multipart_page, provider_refused_feature,
    run_abort_multiparts, valid_multipart_upload_id,
};
pub use session::{
    MAX_IN_MEMORY_UPLOAD_SESSIONS, PublicUpload, STATUS_CANCELED, STATUS_COMPLETED, STATUS_UPLOADING, UploadPartState,
    UploadSession, parse_content_range, upload_chunk_size,
};
pub use target::{AccessCheck, InstanceTarget, NoCheck, Targets, UploadTarget};
pub use token::{
    RESUME_TOKEN_VERSION, ResumeDescriptor, derive_cipher_key, open_resume_token, seal_descriptor, upload_id_from_token,
};

/// The position in the list of the incomplete uploads of a provider. The page token holds it with the short names
/// `k`, `u` and `i`; a value that is empty or 0 is not in the text.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct MultipartCursor {
    /// `key-marker`.
    #[serde(rename = "k", skip_serializing_if = "String::is_empty")]
    pub key_marker: String,
    /// `upload-id-marker`.
    #[serde(rename = "u", skip_serializing_if = "String::is_empty")]
    pub upload_id_marker: String,
    /// The position in the page.
    #[serde(rename = "i", skip_serializing_if = "is_zero")]
    pub skip: u32,
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

/// One incomplete upload.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MultipartUpload {
    /// The full key.
    pub key: String,
    /// The upload id.
    pub upload_id: String,
    /// The start, when the provider gives it.
    pub initiated: Option<Timestamp>,
}

/// One page of the incomplete uploads.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MultipartUploadPage {
    /// The uploads.
    pub uploads: Vec<MultipartUpload>,
    /// The cursor of the next page, or `None` on the last page.
    pub next: Option<MultipartCursor>,
}

/// The parts of one incomplete upload: the count and the bytes of the first page of parts.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MultipartPartsSummary {
    /// The parts.
    pub parts: u32,
    /// The bytes.
    pub bytes: i64,
    /// True when the upload has more parts than the page.
    pub at_least: bool,
    /// True when the provider gives no parts.
    pub unknown: bool,
}

/// The list of the incomplete uploads of a back end.
pub trait MultipartUploadLister: Send + Sync {
    /// One page of the incomplete uploads.
    fn list_uploads<'a>(
        &'a self,
        ctx: &'a OpCtx,
        cursor: &'a MultipartCursor,
        maximum: u32,
    ) -> BoxFuture<'a, Result<MultipartUploadPage>>;
    /// The parts of one upload, at most `maximum`.
    fn upload_parts<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        upload_id: &'a str,
        maximum: u32,
    ) -> BoxFuture<'a, Result<MultipartPartsSummary>>;
}

/// The removal of one incomplete upload of a volume (its temporary file).
pub trait IncompleteUploadRemover: Send + Sync {
    /// Remove the upload.
    fn remove_incomplete_upload<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        upload_id: &'a str,
    ) -> BoxFuture<'a, Result<()>>;
}

/// The state of the list of the incomplete uploads of an instance.
#[derive(Debug, Default)]
pub struct MultipartsState {
    /// Set when the provider refuses the list.
    pub off: AtomicBool,
}

/// The request of the job `abort_multiparts`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MultipartAbortJob {
    /// The age in days.
    pub older_than_days: u32,
    /// The cutoff: the time of the request minus the age. The job aborts the uploads that start before it.
    pub cutoff: Option<Timestamp>,
}

/// The counts of the job `abort_multiparts`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MultipartAbortResult {
    /// The aborted uploads.
    pub aborted: u64,
    /// The uploads without a start date.
    pub skipped_undated: u64,
    /// The uploads younger than the cutoff or than 24 hours.
    pub skipped_recent: u64,
    /// The uploads that this process sends now.
    pub skipped_active: u64,
    /// The failures.
    pub failed: u64,
}

/// Run the job `abort_multiparts`.
pub async fn run_abort_multiparts_job(run: &crate::jobs::JobRun, job: &mut crate::jobs::JobState) -> Result<()> {
    let instance = run.app.instance(&job.instance)?.clone();
    let Some(target) = <crate::common::app::App as Targets>::target(&run.app, &instance.cfg.id) else {
        return Err(Error::api(404, "unknown_instance", "storage instance was not found"));
    };
    multiparts::require_job_permissions(&*target)?;
    run_abort_multiparts(&run.app.uploads, &*target, &run.ctx, run, job).await
}

/// The routes of this module.
pub fn routes() -> Vec<Route> {
    vec![
        route("/api/multiparts", RouteAccess::HandlerAsks, handle_multiparts),
        route(
            "/api/multiparts/abort",
            RouteAccess::HandlerAsks,
            handle_multipart_abort,
        ),
        route("/api/uploads/resume", RouteAccess::HandlerAsks, handle_uploads),
        route("/api/uploads", RouteAccess::HandlerAsks, handle_uploads),
    ]
}
