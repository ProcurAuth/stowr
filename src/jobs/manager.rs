//! The job manager: the jobs in the memory of the process, two workers, the reaper of the paused jobs, the controls
//! (pause, resume, cancel), the history and the reuse of a recent Insights job.
//!
//! The jobs live only in the memory of the process: a restart loses them. The manager admits four active or queued
//! jobs at most, so that a burst of large scans cannot use up the memory of a small server. A paused job keeps its
//! place; only the holder of its id can resume or cancel it, and the reaper cancels it after 30 minutes.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use tokio::sync::mpsc;

use super::stats::{build_stats_treemap, new_stats_response};
use super::walk::{run_copy_prefix, run_delete_prefix, run_object_copy, run_stats};
use super::{JobRun, JobState, job_status, job_type};
use crate::access::{ACTION_READ, ACTION_WRITE};
use crate::common::app::App;
use crate::common::config::{PERMISSION_DELETE, PERMISSION_READ, PERMISSION_WRITE};
use crate::common::ctx::{GateMode, OpCtx};
use crate::common::error::{Error, Interrupt, Result};
use crate::common::misc::{CancelToken, new_state_id};
use crate::common::time::Timestamp;
use crate::instance::budget::Budget;
use crate::instance::ceiling::{CeilingMap, Ceilings, ceiling_error_of, check_listed_sizes, with_access_ceilings};

/// The most active or queued jobs (a paused job counts).
pub const MAX_ACTIVE_JOBS: usize = 4;
/// The jobs that run at the same time.
const WORKER_COUNT: usize = 2;
/// The places of the queue of the workers.
const QUEUE_SIZE: usize = 8;
/// The time after which the reaper cancels a paused job.
pub const PAUSED_JOB_TTL: Duration = Duration::from_secs(30 * 60);
/// The interval of the reaper.
const REAP_INTERVAL: Duration = Duration::from_secs(60);
/// How long `/api/stats` waits for a job before it answers 202.
pub const STATS_INLINE_WAIT: Duration = Duration::from_millis(100);
/// How long a completed Insights job of the same prefix serves the next requests.
pub const STATS_RESULT_REUSE_TTL: Duration = Duration::from_secs(30);
/// The interval of the poll of a job that a route waits for.
const WAIT_POLL: Duration = Duration::from_millis(5);

/// True for the end states: `completed`, `failed` and `canceled`.
pub fn terminal_status(status: &str) -> bool {
    matches!(
        status,
        job_status::COMPLETED | job_status::FAILED | job_status::CANCELED
    )
}

/// The lock of a mutex of the manager, also after a panic of another thread: the state of the manager stays valid
/// because each change under a lock is one step.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// The time between two times, in nanoseconds (negative when `later` is before `earlier`).
fn nanos_between(earlier: Timestamp, later: Timestamp) -> i128 {
    (i128::from(later.secs) - i128::from(earlier.secs)) * 1_000_000_000 + i128::from(later.nanos)
        - i128::from(earlier.nanos)
}

fn job_limit_reached() -> Error {
    Error::api(
        429,
        "job_limit_reached",
        format!("the server is already running or queuing {MAX_ACTIVE_JOBS} background jobs"),
    )
}

/// The state that the manager shares with its workers.
struct Shared {
    jobs: Mutex<HashMap<String, JobState>>,
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    active: Mutex<HashMap<String, CancelToken>>,
    sender: mpsc::Sender<String>,
    receiver: Arc<tokio::sync::Mutex<mpsc::Receiver<String>>>,
    shutdown: CancelToken,
    started: AtomicBool,
}

/// The jobs of the process.
pub struct JobManager {
    app: Weak<App>,
    history_limit: u32,
    shared: Arc<Shared>,
}

impl std::fmt::Debug for JobManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JobManager")
            .field("history_limit", &self.history_limit)
            .finish_non_exhaustive()
    }
}

impl Default for JobManager {
    /// A manager without an application: it keeps jobs, and runs none.
    fn default() -> Self {
        Self::new(Weak::new(), 0)
    }
}

impl Drop for JobManager {
    fn drop(&mut self) {
        self.close();
    }
}

impl JobManager {
    /// A manager with its workers and its reaper. The workers start in the runtime of the caller, or at the first
    /// job when the caller has no runtime. A history limit of 0 keeps each finished job.
    pub fn new(app: Weak<App>, history_limit: u32) -> Self {
        let (sender, receiver) = mpsc::channel(QUEUE_SIZE);
        let manager = Self {
            app,
            history_limit,
            shared: Arc::new(Shared {
                jobs: Mutex::new(HashMap::new()),
                locks: Mutex::new(HashMap::new()),
                active: Mutex::new(HashMap::new()),
                sender,
                receiver: Arc::new(tokio::sync::Mutex::new(receiver)),
                shutdown: CancelToken::new(),
                started: AtomicBool::new(false),
            }),
        };
        manager.ensure_workers();
        manager
    }

    /// Start the workers and the reaper one time, when a runtime is there.
    fn ensure_workers(&self) {
        if self.shared.started.load(Ordering::SeqCst) || self.shared.shutdown.is_canceled() {
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        if self.shared.started.swap(true, Ordering::SeqCst) {
            return;
        }
        for _ in 0..WORKER_COUNT {
            handle.spawn(worker(
                self.app.clone(),
                self.shared.receiver.clone(),
                self.shared.shutdown.clone(),
            ));
        }
        handle.spawn(reaper(self.app.clone(), self.shared.shutdown.clone()));
    }

    /// Stop the workers and the reaper. A running job stops and goes back to the queue state.
    pub fn close(&self) {
        self.shared.shutdown.cancel();
        for token in lock(&self.shared.active).values() {
            token.cancel();
        }
    }

    /// A copy of a job.
    pub fn get(&self, id: &str) -> Option<JobState> {
        lock(&self.shared.jobs).get(id).cloned()
    }

    /// The status and the end of a job, without a copy of the whole job.
    pub fn status_of(&self, id: &str) -> Option<(String, Option<Timestamp>)> {
        lock(&self.shared.jobs)
            .get(id)
            .map(|job| (job.status.clone(), job.ended_at))
    }

    /// Keep a copy of a job: it replaces the job with the same id.
    pub fn put(&self, job: JobState) -> Result<()> {
        lock(&self.shared.jobs).insert(job.id.clone(), job);
        Ok(())
    }

    fn job_lock(&self, id: &str) -> Arc<tokio::sync::Mutex<()>> {
        lock(&self.shared.locks).entry(id.to_owned()).or_default().clone()
    }

    fn active_count(jobs: &HashMap<String, JobState>, exclude: &str) -> usize {
        jobs.iter()
            .filter(|(id, job)| id.as_str() != exclude && !terminal_status(&job.status))
            .count()
    }

    /// Create and queue a job. `429 job_limit_reached` with four active or queued jobs. The job gets its id, the
    /// status `queued` and its times. An Insights job gets new statistics.
    pub fn create(&self, mut job: JobState) -> Result<JobState> {
        let Some(app) = self.app.upgrade() else {
            return Err(Error::internal("job manager is not initialized"));
        };
        if !app.instances.iter().any(|instance| instance.cfg.id == job.instance) {
            return Err(Error::api(404, "unknown_instance", "storage instance was not found"));
        }
        self.prune_history();
        let now = Timestamp::now();
        job.id = new_state_id("job")?;
        job.status = job_status::QUEUED.to_owned();
        job.created_at = now;
        job.updated_at = now;
        job.error.clear();
        if job.job_type == job_type::STATS_PREFIX && job.stats.is_none() {
            job.stats = Some(Box::new(new_stats_response(
                &job.instance,
                &job.prefix,
                app.config.runtime.max_stats_folders,
            )));
        }
        {
            let mut jobs = lock(&self.shared.jobs);
            if Self::active_count(&jobs, "") >= MAX_ACTIVE_JOBS {
                return Err(job_limit_reached());
            }
            jobs.insert(job.id.clone(), job.clone());
        }
        self.enqueue(job.id.clone());
        Ok(job)
    }

    /// Give a job id to the workers. A full queue gives it later.
    fn enqueue(&self, id: String) {
        self.ensure_workers();
        match self.shared.sender.try_send(id) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(id)) => {
                if let Ok(handle) = tokio::runtime::Handle::try_current() {
                    let sender = self.shared.sender.clone();
                    let shutdown = self.shared.shutdown.clone();
                    handle.spawn(async move {
                        tokio::select! {
                            _ = sender.send(id) => {}
                            () = shutdown.canceled() => {}
                        }
                    });
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
    }

    /// Remove the oldest finished jobs over the history limit. The active jobs always stay.
    pub fn prune_history(&self) {
        if self.history_limit == 0 {
            return;
        }
        let removed: Vec<String> = {
            let mut jobs = lock(&self.shared.jobs);
            let mut terminal: Vec<(Timestamp, String)> = jobs
                .values()
                .filter(|job| terminal_status(&job.status))
                .map(|job| (job.updated_at, job.id.clone()))
                .collect();
            if terminal.len() <= self.history_limit as usize {
                return;
            }
            terminal.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| right.1.cmp(&left.1)));
            let removed: Vec<String> = terminal
                .split_off(self.history_limit as usize)
                .into_iter()
                .map(|(_, id)| id)
                .collect();
            for id in &removed {
                jobs.remove(id);
            }
            removed
        };
        let mut locks = lock(&self.shared.locks);
        for id in removed {
            locks.remove(&id);
        }
    }

    /// Cancel each job that a person paused more than 30 minutes before `now`, so that it leaves its place. Gives
    /// the number of canceled jobs.
    pub fn reap_expired_paused(&self, now: Timestamp) -> usize {
        let ttl = i128::from(PAUSED_JOB_TTL.as_secs()) * 1_000_000_000;
        let expired: Vec<String> = {
            let mut jobs = lock(&self.shared.jobs);
            let mut expired = Vec::new();
            for (id, job) in jobs.iter_mut() {
                if job.status != job_status::PAUSED || nanos_between(job.updated_at, now) <= ttl {
                    continue;
                }
                job.status = job_status::CANCELED.to_owned();
                job.error.clear();
                job.updated_at = now;
                job.ended_at = Some(now);
                expired.push(id.clone());
            }
            expired
        };
        for id in &expired {
            self.cancel_active(id);
        }
        if !expired.is_empty() {
            self.prune_history();
        }
        expired.len()
    }

    fn cancel_active(&self, id: &str) {
        if let Some(token) = lock(&self.shared.active).get(id) {
            token.cancel();
        }
    }

    /// A recent Insights job of an instance and a prefix: a completed one of the last 30 seconds, else the newest
    /// queued or running one.
    pub fn reusable_stats_job(&self, instance: &str, prefix: &str) -> Option<JobState> {
        self.reusable_stats_job_at(instance, prefix, Timestamp::now())
    }

    /// [`JobManager::reusable_stats_job`] at a given time.
    pub fn reusable_stats_job_at(&self, instance: &str, prefix: &str, now: Timestamp) -> Option<JobState> {
        let ttl = i128::from(STATS_RESULT_REUSE_TTL.as_secs()) * 1_000_000_000;
        let jobs = lock(&self.shared.jobs);
        let mut active: Option<&JobState> = None;
        let mut completed: Option<&JobState> = None;
        for candidate in jobs.values() {
            if candidate.job_type != job_type::STATS_PREFIX
                || candidate.instance != instance
                || candidate.prefix != prefix
            {
                continue;
            }
            match candidate.status.as_str() {
                job_status::QUEUED | job_status::RUNNING => {
                    if active.is_none_or(|current| candidate.updated_at > current.updated_at) {
                        active = Some(candidate);
                    }
                }
                job_status::COMPLETED => {
                    let fresh = candidate.ended_at.is_some_and(|ended| nanos_between(ended, now) <= ttl);
                    if candidate.stats.is_none() || !fresh {
                        continue;
                    }
                    if completed.is_none_or(|current| candidate.updated_at > current.updated_at) {
                        completed = Some(candidate);
                    }
                }
                _ => {}
            }
        }
        completed.or(active).cloned()
    }

    /// Wait until the job ends or pauses, at most `maximum`. `None` when the time is over or the job is gone. With no
    /// time, gives the job only when it ended.
    pub async fn wait_for_terminal(&self, id: &str, maximum: Duration) -> Option<JobState> {
        if maximum.is_zero() {
            return self.get(id).filter(|job| terminal_status(&job.status));
        }
        let deadline = tokio::time::Instant::now() + maximum;
        loop {
            let job = self.get(id)?;
            if terminal_status(&job.status) || job.status == job_status::PAUSED {
                return Some(job);
            }
            let now = tokio::time::Instant::now();
            if now >= deadline {
                return None;
            }
            tokio::time::sleep_until((now + WAIT_POLL).min(deadline)).await;
            if tokio::time::Instant::now() >= deadline {
                let job = self.get(id)?;
                if terminal_status(&job.status) || job.status == job_status::PAUSED {
                    return Some(job);
                }
                return None;
            }
        }
    }

    /// The control of a running job: `Err(Error::Interrupted)` after a pause or a cancel, `Err(Error::Canceled)` when
    /// the job is gone or the manager stops. It reads the status only.
    pub fn control_state(&self, id: &str) -> Result<()> {
        let status = lock(&self.shared.jobs).get(id).map(|job| job.status.clone());
        match status.as_deref() {
            None => Err(Error::Interrupted(Interrupt::Canceled)),
            Some(job_status::PAUSED) => Err(Error::Interrupted(Interrupt::Paused)),
            Some(job_status::CANCELED) => Err(Error::Interrupted(Interrupt::Canceled)),
            Some(_) if self.shared.shutdown.is_canceled() => Err(Error::Canceled),
            Some(_) => Ok(()),
        }
    }

    /// Give the job the lower value of each ceiling of its own ceilings and of the ceilings given (a resume after
    /// new answers of the PDP).
    pub fn lower_ceilings(&self, id: &str, ceilings: &CeilingMap) {
        if ceilings.is_empty() {
            return;
        }
        let mut jobs = lock(&self.shared.jobs);
        if let Some(job) = jobs.get_mut(id) {
            let merged = Ceilings::default();
            if let Some(current) = &job.ceilings {
                merged.lower_all(&current.values());
            }
            merged.lower_all(ceilings);
            job.ceilings = Some(Arc::new(merged));
        }
    }

    /// Change only the copied parts of the object in progress of a job. The loop of the job keeps the other fields.
    pub fn set_copying_bytes(&self, id: &str, bytes: i64) {
        let mut jobs = lock(&self.shared.jobs);
        if let Some(job) = jobs.get_mut(id)
            && !terminal_status(&job.status)
        {
            job.copying_bytes = bytes;
            job.updated_at = Timestamp::now();
        }
    }

    /// Pause, resume or cancel a job. A pause needs a queued or running job; a resume needs a paused or failed job
    /// and a free place; a cancel of a completed or canceled job changes nothing.
    pub fn change_status(&self, id: &str, action: &str) -> Result<JobState> {
        let now = Timestamp::now();
        let job = {
            let mut jobs = lock(&self.shared.jobs);
            let Some(stored) = jobs.get(id) else {
                return Err(super::seam::unknown_job());
            };
            let mut job = stored.clone();
            match action {
                "pause" => {
                    if job.status != job_status::QUEUED && job.status != job_status::RUNNING {
                        return Err(Error::api(
                            409,
                            "job_not_active",
                            "only queued or running jobs can be paused",
                        ));
                    }
                    job.status = job_status::PAUSED.to_owned();
                }
                "resume" => {
                    if job.status != job_status::PAUSED && job.status != job_status::FAILED {
                        return Err(Error::api(
                            409,
                            "job_not_resumable",
                            "only paused or failed jobs can be resumed",
                        ));
                    }
                    if Self::active_count(&jobs, &job.id) >= MAX_ACTIVE_JOBS {
                        return Err(job_limit_reached());
                    }
                    job.status = job_status::QUEUED.to_owned();
                    job.error.clear();
                    job.ended_at = None;
                }
                "cancel" => {
                    if job.status == job_status::COMPLETED || job.status == job_status::CANCELED {
                        return Ok(job);
                    }
                    job.status = job_status::CANCELED.to_owned();
                    job.error.clear();
                    job.ended_at = Some(now);
                }
                _ => return Err(Error::api(400, "invalid_job_action", "unknown job action")),
            }
            job.updated_at = now;
            jobs.insert(id.to_owned(), job.clone());
            job
        };
        if action == "pause" || action == "cancel" {
            self.cancel_active(id);
        }
        if action == "cancel" {
            self.prune_history();
        }
        if action == "resume" {
            self.enqueue(job.id.clone());
        }
        Ok(job)
    }

    /// Run one queued job. The lock of the job makes two entries of one id in the queue run one after the other.
    /// The controls do not take it, so a pause or a cancel acts during a provider request.
    async fn run(&self, app: &Arc<App>, id: &str) {
        let execution = self.job_lock(id);
        let _running = execution.lock().await;
        let Some(mut job) = self.get(id) else {
            return;
        };
        if job.status != job_status::QUEUED {
            return;
        }
        let now = Timestamp::now();
        job.status = job_status::RUNNING.to_owned();
        job.error.clear();
        job.updated_at = now;
        job.started_at.get_or_insert(now);
        let _ = self.put(job.clone());

        let policy = &app.config.runtime;
        let budget = Arc::new(if reads_whole_objects(&job.job_type) {
            Budget::for_background(policy)
        } else {
            Budget::for_request(policy)
        });
        let token = CancelToken::new();
        lock(&self.shared.active).insert(id.to_owned(), token.clone());
        if self.shared.shutdown.is_canceled() {
            token.cancel();
        }
        // A background job queues for the storage slots: it does not fail after the short wait of a request.
        let base = OpCtx {
            budget: Some(budget.clone()),
            gate: GateMode::Unbounded,
            cancel: token,
            ..OpCtx::default()
        };
        let ceilings = job
            .ceilings
            .as_ref()
            .map(|ceilings| ceilings.values())
            .unwrap_or_default();
        let run = JobRun {
            app: app.clone(),
            ctx: with_access_ceilings(&base, &ceilings),
            id: id.to_owned(),
        };
        let (mut job, result) = execute_contained(run, job).await;

        let usage = budget.usage();
        job.storage_requests = usage.storage_requests;
        job.storage_bytes = usage.storage_bytes;
        if let Some(latest) = self.get(id) {
            job = latest;
        }
        let finish = self.finish(job, result);
        lock(&self.shared.active).remove(id);
        if finish {
            self.prune_history();
        }
    }

    /// Keep the end of a run. Gives true when the job reached an end state.
    fn finish(&self, mut job: JobState, result: Result<()>) -> bool {
        if matches!(result, Err(Error::Interrupted(Interrupt::Paused))) || job.status == job_status::PAUSED {
            return false;
        }
        if matches!(result, Err(Error::Interrupted(Interrupt::Canceled))) || job.status == job_status::CANCELED {
            return false;
        }
        if matches!(result, Err(Error::Canceled)) && self.shared.shutdown.is_canceled() {
            // The process stops: the job waits in the queue state.
            job.status = job_status::QUEUED.to_owned();
            job.error.clear();
            job.updated_at = Timestamp::now();
            job.ended_at = None;
            let _ = self.put(job);
            return false;
        }
        let end = Timestamp::now();
        job.updated_at = end;
        job.ended_at = Some(end);
        match result {
            Err(error) => {
                job.status = job_status::FAILED.to_owned();
                job.error = error.public_message();
                if let Some(refusal) = ceiling_error_of(&error) {
                    job.refusal = Some(Error::Api(Box::new(refusal.clone())));
                }
            }
            Ok(()) => {
                job.status = job_status::COMPLETED.to_owned();
                job.error.clear();
                if let (Some(stats), Some(started)) = (job.stats.as_deref_mut(), job.started_at) {
                    stats.took_ms = i64::try_from(nanos_between(started, end) / 1_000_000).unwrap_or(i64::MAX);
                    let (threshold, treemap) = build_stats_treemap(stats);
                    stats.treemap_threshold_bytes = threshold;
                    stats.treemap = Some(treemap);
                }
            }
        }
        let _ = self.put(job);
        true
    }
}

/// True for the jobs that read complete objects: they use the background budget.
fn reads_whole_objects(kind: &str) -> bool {
    matches!(
        kind,
        job_type::INTEGRITY
            | job_type::EXTRACT_ARCHIVE
            | job_type::ARCHIVE_ENTRY_INTEGRITY
            | job_type::COPY_OBJECT
            | job_type::MOVE_OBJECT
            | job_type::ABORT_MULTIPARTS
    )
}

/// Run a job in its own task: a panic of the job does not stop the worker or the process. The job is then failed.
async fn execute_contained(run: JobRun, job: JobState) -> (JobState, Result<()>) {
    let before = job.clone();
    let task = tokio::spawn(async move {
        let mut job = job;
        let result = execute(&run, &mut job).await;
        (job, result)
    });
    match task.await {
        Ok(outcome) => outcome,
        Err(error) if error.is_panic() => {
            let panic = error.into_panic();
            let text = panic
                .downcast_ref::<&str>()
                .map(|text| (*text).to_owned())
                .or_else(|| panic.downcast_ref::<String>().cloned())
                .unwrap_or_default();
            crate::log!("job {} ({}) panicked: {}", before.id, before.job_type, text);
            (
                before,
                Err(Error::api(500, "job_panicked", "the job failed unexpectedly")),
            )
        }
        Err(_) => (before, Err(Error::Canceled)),
    }
}

/// Run the work of a job of each type.
async fn execute(run: &JobRun, job: &mut JobState) -> Result<()> {
    let instance = run.app.instance(&job.instance)?.clone();
    let require = |permissions: &[&str]| -> Result<()> {
        for permission in permissions {
            instance.require_permission(permission)?;
        }
        Ok(())
    };
    match job.job_type.as_str() {
        job_type::COPY_PREFIX | job_type::MOVE_PREFIX => {
            let moves = job.job_type == job_type::MOVE_PREFIX;
            if moves {
                require(&[PERMISSION_READ, PERMISSION_WRITE, PERMISSION_DELETE])?;
            } else {
                require(&[PERMISSION_READ, PERMISSION_WRITE])?;
            }
            // The ceilings of read and write: the check of each listed size comes before the first copy.
            if job.last_key.is_empty() {
                check_listed_sizes(&run.ctx, &instance, &job.source, &[ACTION_READ, ACTION_WRITE]).await?;
            }
            run_copy_prefix(run, &instance, job, moves).await?;
            if moves {
                // A volume keeps the folders of the moved files: the move removes the folders that it emptied.
                instance
                    .remove_empty_folders(&run.ctx, &instance.full_key(&job.source))
                    .await?;
            }
            Ok(())
        }
        job_type::COPY_OBJECT | job_type::MOVE_OBJECT => {
            if job.job_type == job_type::MOVE_OBJECT {
                require(&[PERMISSION_READ, PERMISSION_WRITE, PERMISSION_DELETE])?;
            } else {
                require(&[PERMISSION_READ, PERMISSION_WRITE])?;
            }
            run_object_copy(run, &instance, job).await
        }
        job_type::DELETE_PREFIX => {
            require(&[PERMISSION_READ, PERMISSION_DELETE])?;
            run_delete_prefix(run, &instance, job).await?;
            // A volume keeps the folders of the deleted files: the delete of a folder removes them.
            instance
                .remove_empty_folders(&run.ctx, &instance.full_key(&job.prefix))
                .await
        }
        job_type::TAG_PREFIX => {
            require(&[PERMISSION_READ, PERMISSION_WRITE])?;
            crate::lifecycle::run_tag_job(run, job).await
        }
        job_type::ABORT_MULTIPARTS => {
            require(&[PERMISSION_READ, PERMISSION_WRITE])?;
            crate::uploads::run_abort_multiparts_job(run, job).await
        }
        job_type::STATS_PREFIX => {
            require(&[PERMISSION_READ])?;
            run_stats(run, &instance, job).await
        }
        job_type::INTEGRITY => {
            require(&[PERMISSION_READ])?;
            super::integrity::run_integrity(run, job).await
        }
        job_type::EXTRACT_ARCHIVE => crate::archive::run_extraction(run, job).await,
        job_type::ARCHIVE_ENTRY_INTEGRITY => crate::archive::run_entry_integrity(run, job).await,
        other => Err(Error::internal(format!("unknown job type {other:?}"))),
    }
}

/// A worker: it takes the next job id of the queue and runs the job, until the manager stops.
async fn worker(app: Weak<App>, receiver: Arc<tokio::sync::Mutex<mpsc::Receiver<String>>>, shutdown: CancelToken) {
    loop {
        let id = {
            let mut queue = tokio::select! {
                () = shutdown.canceled() => return,
                queue = receiver.lock() => queue,
            };
            tokio::select! {
                () = shutdown.canceled() => return,
                id = queue.recv() => match id {
                    Some(id) => id,
                    None => return,
                },
            }
        };
        let Some(app) = app.upgrade() else {
            return;
        };
        app.jobs.run(&app, &id).await;
    }
}

/// The reaper: each minute, it cancels the jobs that stayed paused too long.
async fn reaper(app: Weak<App>, shutdown: CancelToken) {
    let mut interval = tokio::time::interval_at(tokio::time::Instant::now() + REAP_INTERVAL, REAP_INTERVAL);
    loop {
        tokio::select! {
            () = shutdown.canceled() => return,
            _ = interval.tick() => {
                let Some(app) = app.upgrade() else {
                    return;
                };
                app.jobs.reap_expired_paused(Timestamp::now());
            }
        }
    }
}
