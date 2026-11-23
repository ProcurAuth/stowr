//! The background jobs in memory, the Insights statistics, the per-object integrity, the technical inspection and
//! the version routes (docs/ARCHITECTURE.md, "Background jobs", "Insights treemap normalization", "Version
//! capability and version access"; docs/PREVIEWS.md, "Per-object integrity", "Technical inspection").
//!
//! The manager admits four active or queued jobs at most, runs two at the same time, keeps `job_history_limit`
//! finished jobs, and cancels a job that stays paused for 30 minutes. The runners of the jobs of the other work
//! packages are functions of those packages: `crate::archive::run_extraction`, `crate::archive::run_entry_integrity`,
//! `crate::lifecycle::run_tag_job`, `crate::uploads::run_abort_multiparts_job`.

use std::sync::{Arc, Weak};
use std::time::Duration;

use serde::Serialize;

use crate::common::app::App;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Route, RouteAccess, route};
use crate::common::time::Timestamp;
use crate::instance::ceiling::Ceilings;

/// The types of the jobs.
pub mod job_type {
    /// The copy of a prefix.
    pub const COPY_PREFIX: &str = "copy_prefix";
    /// The move of a prefix.
    pub const MOVE_PREFIX: &str = "move_prefix";
    /// The copy of one object in parts.
    pub const COPY_OBJECT: &str = "copy_object";
    /// The move of one object in parts.
    pub const MOVE_OBJECT: &str = "move_object";
    /// The delete of a prefix.
    pub const DELETE_PREFIX: &str = "delete_prefix";
    /// The Insights statistics of a prefix.
    pub const STATS_PREFIX: &str = "stats_prefix";
    /// The integrity of one object.
    pub const INTEGRITY: &str = "integrity";
    /// The extraction of archive entries.
    pub const EXTRACT_ARCHIVE: &str = "extract_archive";
    /// The integrity of archive entries.
    pub const ARCHIVE_ENTRY_INTEGRITY: &str = "archive_entry_integrity";
    /// The change of the tags under a prefix.
    pub const TAG_PREFIX: &str = "tag_prefix";
    /// The abort of the incomplete uploads older than a number of days.
    pub const ABORT_MULTIPARTS: &str = "abort_multiparts";
}

/// The Insights statistics of a prefix (the work package `jobs` gives the members).
#[derive(Clone, Debug, Default, Serialize)]
pub struct StatsResponse {
    /// The instance.
    pub instance: String,
    /// The prefix.
    pub prefix: String,
}

/// The request of an integrity job.
#[derive(Clone, Debug, Default, Serialize)]
pub struct IntegrityRequest {
    /// The relative key.
    pub key: String,
    /// The version.
    pub version: String,
}

/// The result of an integrity job.
#[derive(Clone, Debug, Default, Serialize)]
pub struct IntegrityResult {}

/// A job in the memory of the process.
#[derive(Clone, Debug, Default)]
pub struct JobState {
    /// The id (`job_...`).
    pub id: String,
    /// The type (see [`job_type`]).
    pub job_type: String,
    /// The instance.
    pub instance: String,
    /// The instance of the target of an extraction.
    pub target_instance: String,
    /// The source.
    pub source: String,
    /// The version.
    pub version: String,
    /// The target.
    pub target: String,
    /// The selected entries of an archive.
    pub entries: Vec<String>,
    /// The prefix.
    pub prefix: String,
    /// `queued`, `running`, `paused`, `completed`, `failed` or `canceled`.
    pub status: String,
    /// The processed objects.
    pub processed: i64,
    /// The provider calls.
    pub storage_requests: i64,
    /// The provider bytes.
    pub storage_bytes: i64,
    /// The bytes of the copied objects.
    pub copied_bytes: i64,
    /// The copied parts of the object in progress.
    pub copying_bytes: i64,
    /// The size of the source of a copy of one object.
    pub total_bytes: i64,
    /// The last key that the job finished.
    pub last_key: String,
    /// The Insights statistics.
    pub stats: Option<Box<StatsResponse>>,
    /// The request of an integrity job.
    pub integrity_request: Option<IntegrityRequest>,
    /// The result of an integrity job.
    pub integrity: Option<IntegrityResult>,
    /// The result of an extraction.
    pub archive_extract: Option<crate::archive::ArchiveExtractResult>,
    /// The request of an archive entry integrity job.
    pub archive_entry_integrity_request: Option<crate::archive::ArchiveEntryIntegrityRequest>,
    /// The result of an archive entry integrity job.
    pub archive_entry_integrity: Option<crate::archive::ArchiveEntryIntegrityResult>,
    /// The change of a tag job.
    pub tag_change: Option<crate::lifecycle::TagChange>,
    /// The request of an abort job.
    pub multipart_abort: Option<crate::uploads::MultipartAbortJob>,
    /// The counts of an abort job.
    pub multipart_result: Option<crate::uploads::MultipartAbortResult>,
    /// The keys that an active Object Lock kept.
    pub locked: i64,
    /// The first 20 locked keys.
    pub locked_keys: Vec<String>,
    /// The refusal for a ceiling that stopped the job.
    pub refusal: Option<Error>,
    /// The ceilings of the request that made the job.
    pub ceilings: Option<Arc<Ceilings>>,
    /// The public error.
    pub error: String,
    /// The creation.
    pub created_at: Timestamp,
    /// The last change.
    pub updated_at: Timestamp,
    /// The start.
    pub started_at: Option<Timestamp>,
    /// The end.
    pub ended_at: Option<Timestamp>,
}

/// The handle of a running job: the application, the context of its storage calls and its id.
pub struct JobRun {
    /// The application.
    pub app: Arc<App>,
    /// The context: the budget, the unbounded gate wait, the ceilings of the job, the cancellation.
    pub ctx: OpCtx,
    /// The id of the job.
    pub id: String,
}

impl JobRun {
    /// Save the progress of the job.
    pub fn save(&self, job: &JobState) -> Result<()> {
        let _ = job;
        Err(Error::not_served("the progress of a job"))
    }

    /// `Err(Error::Interrupted)` when a person paused or canceled the job.
    pub fn check_control(&self) -> Result<()> {
        self.ctx.check()
    }
}

/// The jobs of the process.
#[derive(Debug, Default)]
pub struct JobManager {
    app: Weak<App>,
    history_limit: u32,
}

impl JobManager {
    /// A manager with its workers and its reaper.
    pub fn new(app: Weak<App>, history_limit: u32) -> Self {
        Self { app, history_limit }
    }

    /// Create and queue a job. `429 job_limit_reached` with four active or queued jobs.
    pub fn create(&self, job: JobState) -> Result<JobState> {
        let _ = (job, &self.app, self.history_limit);
        Err(Error::not_served("the background jobs"))
    }

    /// A copy of a job.
    pub fn get(&self, id: &str) -> Option<JobState> {
        let _ = id;
        None
    }

    /// Wait until the job ends, at most `maximum`.
    pub async fn wait_for_terminal(&self, id: &str, maximum: Duration) -> Option<JobState> {
        let _ = (id, maximum);
        None
    }

    /// Stop the workers and the reaper.
    pub fn close(&self) {}
}

crate::stub_handler!(handle_jobs, "the route /api/jobs/");
crate::stub_handler!(handle_versions, "the route /api/versions");
crate::stub_handler!(handle_version_counts, "the route /api/version-counts");
crate::stub_handler!(handle_version_restore, "the route /api/versions/restore");
crate::stub_handler!(handle_integrity, "the route /api/integrity");
crate::stub_handler!(handle_inspect, "the route /api/inspect");

/// The handler of `/api/jobs` without an id: always 404.
pub fn handle_job_collection(
    app: Arc<App>,
    req: crate::common::http::Req,
) -> crate::common::BoxFuture<'static, crate::common::http::Response> {
    Box::pin(async move {
        let _ = (app, req);
        crate::common::http::not_found()
    })
}

/// The routes of this work package.
pub fn routes() -> Vec<Route> {
    vec![
        route("/api/jobs", RouteAccess::TokenOnly, handle_job_collection),
        route("/api/jobs/", RouteAccess::HandlerAsks, handle_jobs),
        route("/api/versions", RouteAccess::HandlerAsks, handle_versions),
        route("/api/version-counts", RouteAccess::HandlerAsks, handle_version_counts),
        route(
            "/api/versions/restore",
            RouteAccess::HandlerAsks,
            handle_version_restore,
        ),
        route("/api/integrity", RouteAccess::HandlerAsks, handle_integrity),
        route("/api/inspect", RouteAccess::HandlerAsks, handle_inspect),
    ]
}
