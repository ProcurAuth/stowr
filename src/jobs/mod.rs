//! The background jobs in memory, the Insights statistics, the per-object integrity, the technical inspection and
//! the version routes (docs/ARCHITECTURE.md, "Background jobs", "Insights treemap normalization", "Version
//! capability and version access"; docs/PREVIEWS.md, "Per-object integrity", "Technical inspection").
//!
//! The manager admits four active or queued jobs at most, runs two at the same time, keeps `job_history_limit`
//! finished jobs, and cancels a job that stays paused for 30 minutes. The runners of the jobs of the other work
//! packages are functions of those packages: `crate::archive::run_extraction`, `crate::archive::run_entry_integrity`,
//! `crate::lifecycle::run_tag_job`, `crate::uploads::run_abort_multiparts_job`. A runner that walks the objects of a
//! prefix can use the shared walk of this folder: [`ObjectWalk`] and [`run_object_walk`].
//!
//! A route gives a job to the client with [`job_answer`] (or [`JobState::public`]): the public form of a job.

mod digest;
mod inspect;
mod integrity;
mod manager;
mod public;
mod routes;
mod seam;
mod sniff;
mod stats;
mod versions;
mod walk;

#[cfg(test)]
mod access_tests;
#[cfg(test)]
mod analysis_tests;
#[cfg(test)]
mod manager_tests;
#[cfg(test)]
mod stats_tests;
#[cfg(test)]
mod testing;
#[cfg(test)]
mod walk_tests;

use std::sync::Arc;

use crate::common::app::App;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Route, RouteAccess, route};
use crate::common::time::Timestamp;
use crate::instance::ceiling::Ceilings;

pub use inspect::{InspectProbe, InspectResources, InspectResponse, handle_inspect};
pub use integrity::{
    ANALYSIS_INLINE_WAIT, IntegrityEntry, IntegrityRequest, IntegrityResult, analysis_job_answer, checksum_matches,
    compute_object_integrity, handle_integrity,
};
pub use manager::{
    JobManager, MAX_ACTIVE_JOBS, PAUSED_JOB_TTL, STATS_INLINE_WAIT, STATS_RESULT_REUSE_TTL, terminal_status,
};
pub use public::{PublicJob, job_answer};
pub use routes::{handle_job_collection, handle_jobs, handle_stats};
pub use stats::{
    Aggregate, DEFAULT_MAX_STATS_FOLDERS, MAX_STATS_FOLDER_DEPTH, MAX_STATS_LARGEST_ENTRIES, MAX_STATS_RECENT_ENTRIES,
    STATS_LAYOUT_VERSION, StatsEntry, StatsResponse, StatsTreemapNode, add_largest_stats_entry, add_recent_stats_entry,
    add_stats_folder_aggregates, build_stats_treemap, new_stats_response, stats_treemap_threshold,
};
pub use versions::{handle_version_counts, handle_version_restore, handle_versions};
pub use walk::{ObjectStep, ObjectWalk, WALK_PAGE_SIZE, WalkHost, run_object_walk};

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

/// The states of a job.
pub mod job_status {
    /// The job waits for a worker.
    pub const QUEUED: &str = "queued";
    /// A worker runs the job.
    pub const RUNNING: &str = "running";
    /// A person paused the job. It keeps its place in the four active jobs.
    pub const PAUSED: &str = "paused";
    /// The job ended without an error.
    pub const COMPLETED: &str = "completed";
    /// The job ended with an error.
    pub const FAILED: &str = "failed";
    /// A person canceled the job, or the job stayed paused too long.
    pub const CANCELED: &str = "canceled";
}

/// The most keys that a job keeps in `locked_keys`.
pub const MAX_LOCKED_KEYS: usize = 20;

/// A job in the memory of the process.
///
/// In a copy job, `copied_bytes` counts the bytes of the copied objects, and `copying_bytes` counts the copied parts
/// of the object in progress: a pause or an error drops them. `total_bytes` is the size of the source of a
/// `copy_object` or a `move_object` job.
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
    /// `queued`, `running`, `paused`, `completed`, `failed` or `canceled` (see [`job_status`]).
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
    /// The refusal for a ceiling that stopped the job. A route that waits for the job gives it as it is.
    pub refusal: Option<Error>,
    /// The ceilings of the request that made the job. The job applies them in its own context.
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

impl JobState {
    /// Count a key that Object Lock kept, and keep the first [`MAX_LOCKED_KEYS`] keys to show them.
    pub fn add_locked(&mut self, key: &str) {
        self.locked += 1;
        if self.locked_keys.len() < MAX_LOCKED_KEYS {
            self.locked_keys.push(key.to_owned());
        }
    }

    /// The public form of the job, as the routes give it.
    pub fn public(&self) -> PublicJob {
        public::public_job(self)
    }
}

/// The handle of a running job: the application, the context of its storage calls and its id.
pub struct JobRun {
    /// The application.
    pub app: Arc<App>,
    /// The context: the budget, the unbounded gate wait, the ceilings of the job, the cancellation. A pause, a
    /// cancel and the stop of the manager cancel it.
    pub ctx: OpCtx,
    /// The id of the job.
    pub id: String,
}

impl JobRun {
    /// Save the progress of the job: the manager keeps a copy of it.
    pub fn save(&self, job: &JobState) -> Result<()> {
        self.app.jobs.put(job.clone())
    }

    /// `Err(Error::Interrupted)` when a person paused or canceled the job, `Err(Error::Canceled)` when the manager
    /// stops or the job is gone.
    pub fn check_control(&self) -> Result<()> {
        self.app.jobs.control_state(&self.id)
    }

    /// The reason why a long loop of the job must stop: the control of the job, else the cancellation of its
    /// context.
    pub fn interrupted(&self) -> Result<()> {
        if let Err(error) = self.ctx.check() {
            self.check_control()?;
            return Err(error);
        }
        self.check_control()
    }

    /// The job as the manager has it now.
    pub fn latest(&self) -> Option<JobState> {
        self.app.jobs.get(&self.id)
    }

    /// Take the status and the end of the job that the manager has now. A resume can change `paused` to `queued`
    /// before the worker sees the pause. The worker already runs the job, so the status becomes `running`.
    pub fn refresh_status(&self, job: &mut JobState) {
        if let Some((status, ended_at)) = self.app.jobs.status_of(&self.id) {
            job.status = if status == job_status::QUEUED {
                job_status::RUNNING.to_owned()
            } else {
                status
            };
            job.ended_at = ended_at;
        }
    }

    /// `Err(Error::Interrupted)` when the status of the job is `paused` or `canceled`.
    pub fn stop_on_control_status(job: &JobState) -> Result<()> {
        match job.status.as_str() {
            job_status::PAUSED => Err(Error::Interrupted(crate::common::error::Interrupt::Paused)),
            job_status::CANCELED => Err(Error::Interrupted(crate::common::error::Interrupt::Canceled)),
            _ => Ok(()),
        }
    }
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
