// SPDX-License-Identifier: MIT OR Apache-2.0
//! The walk of the objects of a prefix for a job, and the jobs that walk a prefix: the copy, the move, the delete and
//! the Insights statistics. The copy and the move of one object in parts are here too.
//!
//! A walk lists the objects in key order after the last key that the job finished, one page of 1000 keys at a time.
//! After a pause, a failure or a stop of the process, the job goes on after its last key. [`run_object_walk`] gives
//! the rules of the checkpoints: a job saves its progress after each object (the statistics after 100 objects or
//! one second), and stops at once after a pause or a cancel.

use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Instant;

use super::stats::{init_largest_heap, init_recent_heap, new_stats_response, record_object};
use super::{JobRun, JobState, STATS_LAYOUT_VERSION, job_type};
use crate::bucket::is_object_locked;
use crate::common::BoxFuture;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::storage::{CopyProgress, ListOptions, ObjectInfo};
use crate::common::time::Timestamp;
use crate::instance::Instance;
use crate::instance::ops::MAX_DELETE_BATCH;

/// The keys of one page of a walk.
pub const WALK_PAGE_SIZE: u32 = 1000;

/// The objects under a relative prefix, after a relative key, in key order.
#[derive(Debug)]
pub struct ObjectWalk {
    prefix: String,
    last_key: String,
    page: std::vec::IntoIter<ObjectInfo>,
    listed: bool,
    progressed: bool,
    last_page: bool,
}

impl ObjectWalk {
    /// A walk of the objects whose relative key starts with `prefix` and comes after `last_key` (empty: from the
    /// start).
    pub fn new(prefix: &str, last_key: &str) -> Self {
        Self {
            prefix: prefix.to_owned(),
            last_key: last_key.to_owned(),
            page: Vec::new().into_iter(),
            listed: false,
            progressed: false,
            last_page: false,
        }
    }

    /// The relative key of the last object that the walk gave.
    pub fn last_key(&self) -> &str {
        &self.last_key
    }

    /// The next object and its relative key, or `None` at the end. A page that gives no new object ends the walk:
    /// a provider that ignores the start key cannot make a loop.
    pub async fn next(&mut self, ctx: &OpCtx, instance: &Instance) -> Result<Option<(ObjectInfo, String)>> {
        loop {
            for object in self.page.by_ref() {
                let Some(relative) = instance.relative_key(&object.key) else {
                    continue;
                };
                if relative.is_empty()
                    || !relative.starts_with(&self.prefix)
                    || (!self.last_key.is_empty() && relative <= self.last_key)
                {
                    continue;
                }
                self.last_key.clone_from(&relative);
                self.progressed = true;
                return Ok(Some((object, relative)));
            }
            if self.listed && (!self.progressed || self.last_page) {
                return Ok(None);
            }
            let options = ListOptions {
                prefix: instance.full_key(&self.prefix),
                max_results: WALK_PAGE_SIZE,
                start_after: if self.last_key.is_empty() {
                    String::new()
                } else {
                    instance.full_key(&self.last_key)
                },
                ..ListOptions::default()
            };
            let mut page = instance.list(ctx, &options).await?;
            page.objects.sort_by(|left, right| left.key.cmp(&right.key));
            self.last_page = page.next_page_token.is_empty() && page.objects.len() < WALK_PAGE_SIZE as usize;
            self.listed = true;
            self.progressed = false;
            self.page = page.objects.into_iter();
        }
    }
}

/// The work of a job on one object of its walk.
pub trait ObjectStep: Send {
    /// Do the work on one object. `relative` is its relative key.
    fn apply<'a>(
        &'a mut self,
        job: &'a mut JobState,
        object: &'a ObjectInfo,
        relative: &'a str,
    ) -> BoxFuture<'a, Result<()>>;
}

/// What the walk of a job needs from the job that runs it. A [`JobRun`] gives each function; a test can give a fake.
pub trait WalkHost: Sync {
    /// The context of the storage calls of the job.
    fn ctx(&self) -> &OpCtx;
    /// `Err(Error::Interrupted)` when a person paused or canceled the job.
    fn check_control(&self) -> Result<()>;
    /// Take the status and the end of the job that the manager has now.
    fn refresh_status(&self, job: &mut JobState);
    /// Save the progress of the job.
    fn save(&self, job: &JobState) -> Result<()>;
}

impl WalkHost for JobRun {
    fn ctx(&self) -> &OpCtx {
        &self.ctx
    }

    fn check_control(&self) -> Result<()> {
        JobRun::check_control(self)
    }

    fn refresh_status(&self, job: &mut JobState) {
        JobRun::refresh_status(self, job);
    }

    fn save(&self, job: &JobState) -> Result<()> {
        JobRun::save(self, job)
    }
}

fn empty_prefix() -> Error {
    Error::api(404, "empty_prefix", "source prefix contains no objects")
}

/// Walk the objects under the prefix of a job (its `prefix`, else its `source`) after its `last_key`, and apply the
/// step to each one. After each object the job counts it, takes the status that the manager has, and saves its
/// progress: each object for each job type, and after 100 objects or one second for the statistics. A pause or a
/// cancel stops the walk at once with `Err(Error::Interrupted)`. A job other than the statistics that finds no
/// object fails with `404 empty_prefix`.
pub async fn run_object_walk(
    host: &dyn WalkHost,
    instance: &Instance,
    job: &mut JobState,
    step: &mut (dyn ObjectStep + '_),
) -> Result<()> {
    let prefix = if job.prefix.is_empty() {
        job.source.clone()
    } else {
        job.prefix.clone()
    };
    let stats = job.job_type == job_type::STATS_PREFIX;
    let mut processed_this_run = 0i64;
    let mut last_checkpoint = Instant::now();
    let mut walk = ObjectWalk::new(&prefix, &job.last_key);
    while let Some((object, relative)) = walk.next(host.ctx(), instance).await? {
        host.check_control()?;
        step.apply(job, &object, &relative).await?;
        job.processed += 1;
        processed_this_run += 1;
        job.last_key = relative;
        job.updated_at = Timestamp::now();
        host.refresh_status(job);
        let control = JobRun::stop_on_control_status(job);
        let checkpoint = !stats
            || processed_this_run % 100 == 0
            || last_checkpoint.elapsed() >= std::time::Duration::from_secs(1)
            || control.is_err();
        if checkpoint {
            host.save(job)?;
            last_checkpoint = Instant::now();
        }
        control?;
    }
    if stats && processed_this_run > 0 {
        host.save(job)?;
    }
    if job.processed == 0 && processed_this_run == 0 && !stats {
        return Err(empty_prefix());
    }
    Ok(())
}

/// Copy one object of a copy job and add its size to the copied bytes of the job. During a copy in parts, the job of
/// the manager shows the copied parts, so a poll of the job sees the progress.
async fn copy_counted(
    run: &JobRun,
    job: &mut JobState,
    instance: &Instance,
    source: &str,
    destination: &str,
    size: i64,
) -> Result<()> {
    job.copying_bytes = 0;
    let copying = Arc::new(AtomicI64::new(0));
    let app = run.app.clone();
    let id = run.id.clone();
    let progress: CopyProgress = Arc::new(move |part: i64| {
        let total = copying.fetch_add(part, Ordering::SeqCst) + part;
        app.jobs.set_copying_bytes(&id, total);
    });
    let result = instance
        .copy_sized(
            &run.ctx,
            &instance.full_key(source),
            &instance.full_key(destination),
            size,
            Some(progress),
        )
        .await;
    if let Err(error) = result {
        run.app.jobs.set_copying_bytes(&run.id, 0);
        return Err(error);
    }
    job.copied_bytes += size;
    Ok(())
}

/// The error of a move whose copy is made and whose source stays.
pub(super) fn source_deletion_error(error: Error) -> Error {
    if is_object_locked(&error) {
        return Error::api(
            409,
            "object_locked",
            format!("The copy is made, but the source stays. {error}"),
        );
    }
    error
}

/// The step of a copy or a move of a prefix.
struct CopyStep<'r> {
    run: &'r JobRun,
    instance: &'r Instance,
    remove_source: bool,
}

impl ObjectStep for CopyStep<'_> {
    fn apply<'a>(
        &'a mut self,
        job: &'a mut JobState,
        object: &'a ObjectInfo,
        relative: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let suffix = relative.strip_prefix(job.source.as_str()).unwrap_or(relative);
            let destination = format!("{}{suffix}", job.target);
            let instance = self.instance;
            if self.remove_source && instance.moves_objects() {
                // A volume moves each file with one rename.
                instance
                    .move_object(
                        &self.run.ctx,
                        &instance.full_key(relative),
                        &instance.full_key(&destination),
                    )
                    .await?;
                job.copied_bytes += object.size;
                return Ok(());
            }
            copy_counted(self.run, job, instance, relative, &destination, object.size).await?;
            if self.remove_source
                && let Err(error) = instance.delete(&self.run.ctx, &instance.full_key(relative)).await
            {
                // A source that Object Lock keeps stays: the job counts it and goes on.
                if !is_object_locked(&error) {
                    return Err(error);
                }
                job.add_locked(relative);
            }
            Ok(())
        })
    }
}

/// The step of the Insights statistics.
struct StatsStep;

impl ObjectStep for StatsStep {
    fn apply<'a>(
        &'a mut self,
        job: &'a mut JobState,
        object: &'a ObjectInfo,
        relative: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let kind = crate::server::detect_kind(relative, &object.content_type);
            let prefix = job.prefix.clone();
            if let Some(stats) = job.stats.as_deref_mut() {
                record_object(stats, &prefix, relative, object, kind);
            }
            Ok(())
        })
    }
}

/// Run a copy (`remove_source` false) or a move of a prefix.
pub(super) async fn run_copy_prefix(
    run: &JobRun,
    instance: &Instance,
    job: &mut JobState,
    remove_source: bool,
) -> Result<()> {
    let mut step = CopyStep {
        run,
        instance,
        remove_source,
    };
    run_object_walk(run, instance, job, &mut step).await
}

/// Run the Insights statistics of a prefix. Statistics of an older layout start again from the first key.
pub(super) async fn run_stats(run: &JobRun, instance: &Instance, job: &mut JobState) -> Result<()> {
    if job
        .stats
        .as_ref()
        .is_none_or(|stats| stats.layout_version != STATS_LAYOUT_VERSION)
    {
        job.processed = 0;
        job.last_key.clear();
        job.stats = Some(Box::new(new_stats_response(
            &job.instance,
            &job.prefix,
            run.app.config.runtime.max_stats_folders,
        )));
        run.save(job)?;
    }
    if let Some(stats) = job.stats.as_deref_mut() {
        init_largest_heap(&mut stats.largest);
        init_recent_heap(&mut stats.recent);
    }
    run_object_walk(run, instance, job, &mut StatsStep).await
}

/// Delete the keys of a batch with one request when the back end can, count the deleted keys and the locked keys,
/// and save the progress. The job counts a batch only after the provider deleted it.
async fn flush_delete_batch(
    run: &JobRun,
    instance: &Instance,
    job: &mut JobState,
    batch: &mut Vec<String>,
    processed_this_run: &mut i64,
) -> Result<()> {
    let Some(last) = batch.last().cloned() else {
        return Ok(());
    };
    let keys: Vec<String> = batch.iter().map(|relative| instance.full_key(relative)).collect();
    let locked = instance.delete_many(&run.ctx, &keys).await?;
    // A key that Object Lock keeps stays in the bucket: the job counts it as locked, not as deleted.
    for full in &locked {
        job.add_locked(&instance.relative_key(full).unwrap_or_default());
    }
    job.processed += (batch.len() - locked.len()) as i64;
    *processed_this_run += batch.len() as i64;
    job.last_key = last;
    batch.clear();
    job.updated_at = Timestamp::now();
    run.refresh_status(job);
    run.save(job)?;
    JobRun::stop_on_control_status(job)
}

/// Delete the objects of a prefix in batches: one request for each listing page, up to 1000 keys. A pause or a stop
/// between two batches goes on after the last deleted key.
pub(super) async fn run_delete_prefix(run: &JobRun, instance: &Instance, job: &mut JobState) -> Result<()> {
    let mut batch: Vec<String> = Vec::with_capacity(MAX_DELETE_BATCH);
    let mut processed_this_run = 0i64;
    let mut walk = ObjectWalk::new(&job.prefix, &job.last_key);
    while let Some((_, relative)) = walk.next(&run.ctx, instance).await? {
        run.check_control()?;
        batch.push(relative);
        if batch.len() >= MAX_DELETE_BATCH {
            flush_delete_batch(run, instance, job, &mut batch, &mut processed_this_run).await?;
        }
    }
    flush_delete_batch(run, instance, job, &mut batch, &mut processed_this_run).await?;
    if job.processed == 0 && job.locked == 0 && processed_this_run == 0 {
        return Err(empty_prefix());
    }
    Ok(())
}

/// Copy or move one large object in parts. A pause or a cancel aborts the copy in parts; a resume starts it again
/// from the first part.
pub(super) async fn run_object_copy(run: &JobRun, instance: &Instance, job: &mut JobState) -> Result<()> {
    run.check_control()?;
    job.copied_bytes = 0;
    let (source, target, total) = (job.source.clone(), job.target.clone(), job.total_bytes);
    copy_counted(run, job, instance, &source, &target, total).await?;
    if job.job_type == job_type::MOVE_OBJECT {
        instance
            .delete(&run.ctx, &instance.full_key(&source))
            .await
            .map_err(source_deletion_error)?;
    }
    job.processed = 1;
    job.last_key = source;
    job.updated_at = Timestamp::now();
    run.refresh_status(job);
    run.save(job)
}
