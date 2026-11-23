// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tests of the walk of a prefix and of the copy of large objects in parts.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;

use super::testing::{rig_over, wait_for_status};
use super::*;
use crate::common::BoxFuture;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::storage::{Backend, ListPage, MultipartCopier, MultipartCopyOptions, ObjectInfo};
use crate::testkit::{MemoryBackend, MemoryLayer, read_write_backend};

/// A back end that copies an object in parts of `part_size` bytes, as the S3 engine does. A copy can wait after its
/// first part until the test gives a permit.
struct PartsCopier {
    memory: MemoryBackend,
    part_size: usize,
    parts: AtomicUsize,
    completed: AtomicUsize,
    copy_objects: AtomicUsize,
    hold: Option<tokio::sync::Semaphore>,
}

impl PartsCopier {
    fn new(objects: &[(&str, Vec<u8>)], part_size: usize, hold: bool) -> Self {
        let memory = MemoryBackend::new();
        for (key, data) in objects {
            memory.insert(key, data.clone(), "application/octet-stream");
        }
        Self {
            memory,
            part_size,
            parts: AtomicUsize::new(0),
            completed: AtomicUsize::new(0),
            copy_objects: AtomicUsize::new(0),
            hold: hold.then(|| tokio::sync::Semaphore::new(0)),
        }
    }
}

impl MemoryLayer for PartsCopier {
    fn memory(&self) -> &MemoryBackend {
        &self.memory
    }

    fn copy<'a>(&'a self, ctx: &'a OpCtx, source: &'a str, destination: &'a str) -> BoxFuture<'a, Result<()>> {
        self.copy_objects.fetch_add(1, Ordering::SeqCst);
        self.memory.copy(ctx, source, destination)
    }

    fn multipart_copier(&self) -> Option<&dyn MultipartCopier> {
        Some(self)
    }
}

impl MultipartCopier for PartsCopier {
    fn copy_multipart<'a>(
        &'a self,
        ctx: &'a OpCtx,
        source: &'a str,
        destination: &'a str,
        options: MultipartCopyOptions,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let object = self
                .memory
                .object(source)
                .ok_or_else(|| Error::upstream(404, "NoSuchKey", ""))?;
            for (index, chunk) in object.data.chunks(self.part_size).enumerate() {
                if let Some(gate) = &options.gate {
                    let _slot = gate(ctx.clone()).await?;
                }
                if index == 1
                    && let Some(hold) = &self.hold
                {
                    let permit = ctx
                        .run(async { hold.acquire().await.map_err(|_| Error::Canceled) })
                        .await?;
                    permit.forget();
                }
                ctx.check()?;
                self.parts.fetch_add(1, Ordering::SeqCst);
                if let Some(progress) = &options.progress {
                    progress(chunk.len() as i64);
                }
            }
            self.memory
                .insert(destination, Bytes::clone(&object.data), &object.content_type);
            self.completed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
    }
}

fn app_over(backend: Arc<PartsCopier>) -> Arc<crate::common::app::App> {
    let app = rig_over(backend);
    app.instance("rw").unwrap().set_multipart_copy_threshold(16);
    app
}

fn object_job(kind: &str, source: &str, target: &str, size: i64) -> JobState {
    JobState {
        job_type: kind.to_owned(),
        instance: "rw".to_owned(),
        source: source.to_owned(),
        target: target.to_owned(),
        total_bytes: size,
        ..JobState::default()
    }
}

#[tokio::test]
async fn the_copy_of_a_large_object_runs_as_a_job_with_its_bytes() {
    let data = b"0123456789".repeat(10);
    let backend = Arc::new(PartsCopier::new(&[("tenant/big.bin", data.clone())], 40, false));
    let app = app_over(backend.clone());
    let job = app
        .jobs
        .create(object_job(job_type::COPY_OBJECT, "big.bin", "copy/big.bin", 100))
        .unwrap();
    assert_eq!(job.public().total_bytes, 100);
    let done = wait_for_status(&app, &job.id, job_status::COMPLETED).await.public();
    assert_eq!((done.processed, done.copied_bytes), (1, 100));
    assert_eq!(done.last_key, "big.bin");
    assert_eq!(
        &backend.memory.object("tenant/copy/big.bin").unwrap().data[..],
        &data[..]
    );
    assert_eq!(backend.parts.load(Ordering::SeqCst), 3);
    assert_eq!(backend.copy_objects.load(Ordering::SeqCst), 0);
    assert!(backend.memory.contains("tenant/big.bin"), "the copy removed the source");
}

#[tokio::test]
async fn the_rename_of_a_large_object_moves_it_in_a_job() {
    let backend = Arc::new(PartsCopier::new(&[("tenant/big.bin", vec![b'x'; 100])], 40, false));
    let app = app_over(backend.clone());
    let job = app
        .jobs
        .create(object_job(job_type::MOVE_OBJECT, "big.bin", "moved.bin", 100))
        .unwrap();
    wait_for_status(&app, &job.id, job_status::COMPLETED).await;
    assert!(!backend.memory.contains("tenant/big.bin"), "the source is still there");
    assert_eq!(backend.memory.object("tenant/moved.bin").unwrap().data.len(), 100);
    assert_eq!(backend.completed.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn the_copy_of_a_prefix_counts_the_copied_bytes() {
    let backend = Arc::new(PartsCopier::new(
        &[
            ("tenant/dir/big.bin", vec![b'b'; 40]),
            ("tenant/dir/small.txt", b"tiny".to_vec()),
        ],
        16,
        false,
    ));
    let app = app_over(backend.clone());
    let job = app
        .jobs
        .create(JobState {
            source: "dir/".to_owned(),
            target: "out/".to_owned(),
            ..object_job(job_type::COPY_PREFIX, "", "", 0)
        })
        .unwrap();
    let done = wait_for_status(&app, &job.id, job_status::COMPLETED).await.public();
    assert_eq!((done.processed, done.copied_bytes, done.total_bytes), (2, 44, 0));
    assert_eq!(backend.completed.load(Ordering::SeqCst), 1);
    assert_eq!(backend.copy_objects.load(Ordering::SeqCst), 1);
    assert_eq!(backend.memory.object("tenant/out/small.txt").unwrap().data, "tiny");
}

#[tokio::test]
async fn a_pause_drops_the_copied_parts_and_a_resume_copies_from_the_first_part() {
    let backend = Arc::new(PartsCopier::new(&[("tenant/big.bin", vec![b'y'; 100])], 40, true));
    let app = app_over(backend.clone());
    let job = app
        .jobs
        .create(object_job(job_type::COPY_OBJECT, "big.bin", "copy.bin", 100))
        .unwrap();
    // The copy waits after its first part: a poll of the job shows the copied part.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while app.jobs.get(&job.id).unwrap().public().copied_bytes != 40 {
        assert!(tokio::time::Instant::now() < deadline, "the copied part did not show");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(app.jobs.get(&job.id).unwrap().status, job_status::RUNNING);
    let paused = app.jobs.change_status(&job.id, "pause").unwrap();
    assert_eq!(paused.status, job_status::PAUSED);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while app.jobs.get(&job.id).unwrap().public().copied_bytes != 0 {
        assert!(tokio::time::Instant::now() < deadline, "the pause kept the copied part");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(!backend.memory.contains("tenant/copy.bin"));
    backend.hold.as_ref().unwrap().add_permits(1);
    app.jobs.change_status(&job.id, "resume").unwrap();
    let done = wait_for_status(&app, &job.id, job_status::COMPLETED).await.public();
    assert_eq!(done.copied_bytes, 100);
    assert_eq!(backend.parts.load(Ordering::SeqCst), 1 + 3);
    assert_eq!(backend.memory.object("tenant/copy.bin").unwrap().data.len(), 100);
}

#[tokio::test]
async fn a_walk_gives_the_objects_of_the_prefix_in_key_order_after_the_last_key() {
    let backend = read_write_backend();
    backend.insert("tenant/folder/a.txt", "a", "text/plain");
    backend.insert("tenant/folderish.txt", "x", "text/plain");
    let instance = super::testing::read_write_over(backend.clone());
    let ctx = OpCtx::default();
    let mut walk = ObjectWalk::new("folder/", "");
    let mut keys = Vec::new();
    while let Some((object, relative)) = walk.next(&ctx, &instance).await.unwrap() {
        assert_eq!(object.key, format!("tenant/{relative}"));
        keys.push(relative);
    }
    assert_eq!(
        keys,
        vec!["folder/a.txt", "folder/direct.txt", "folder/nested/deep.txt"]
    );
    assert_eq!(walk.last_key(), "folder/nested/deep.txt");
    let mut after = ObjectWalk::new("folder/", "folder/a.txt");
    let (_, first) = after.next(&ctx, &instance).await.unwrap().unwrap();
    assert_eq!(first, "folder/direct.txt");
    assert_eq!(backend.state().last.start_after, "tenant/folder/a.txt");
    assert_eq!(backend.state().last.max_results, WALK_PAGE_SIZE);
}

#[tokio::test]
async fn a_provider_that_ignores_the_start_key_cannot_make_a_loop() {
    let backend = Arc::new(MemoryBackend::new());
    let objects: Vec<ObjectInfo> = (0..WALK_PAGE_SIZE)
        .map(|index| ObjectInfo {
            key: format!("tenant/p/{index:05}"),
            size: 1,
            ..ObjectInfo::default()
        })
        .collect();
    backend.state().list_pages = vec![ListPage {
        objects,
        next_page_token: "page-0".to_owned(),
        ..ListPage::default()
    }];
    let instance = super::testing::read_write_over(backend.clone());
    let ctx = OpCtx::default();
    let mut walk = ObjectWalk::new("p/", "");
    let mut count = 0;
    while walk.next(&ctx, &instance).await.unwrap().is_some() {
        count += 1;
    }
    assert_eq!(count, WALK_PAGE_SIZE as usize);
    assert_eq!(backend.state().list_calls, 2);
}

/// A step that fails on one key.
struct FailOn(&'static str);

impl ObjectStep for FailOn {
    fn apply<'a>(
        &'a mut self,
        _job: &'a mut JobState,
        _object: &'a ObjectInfo,
        relative: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if relative == self.0 {
                return Err(Error::api(409, "stop_here", "stop"));
            }
            Ok(())
        })
    }
}

#[tokio::test]
async fn the_shared_walk_saves_each_object_and_stops_at_an_error() {
    let backend = read_write_backend();
    let app = rig_over(backend.clone());
    let instance = app.instance("rw").unwrap().clone();
    let mut job = JobState {
        id: "job_walk".to_owned(),
        job_type: job_type::TAG_PREFIX.to_owned(),
        instance: "rw".to_owned(),
        prefix: "folder/".to_owned(),
        status: job_status::RUNNING.to_owned(),
        ..JobState::default()
    };
    app.jobs.put(job.clone()).unwrap();
    let run = JobRun {
        app: app.clone(),
        ctx: OpCtx::default(),
        id: job.id.clone(),
    };
    let error = run_object_walk(&run, &instance, &mut job, &mut FailOn("folder/nested/deep.txt"))
        .await
        .unwrap_err();
    assert!(error.has_code("stop_here"));
    let saved = app.jobs.get("job_walk").unwrap();
    assert_eq!((saved.processed, saved.last_key.as_str()), (1, "folder/direct.txt"));
    // The run goes on after the last saved key.
    let mut resumed = saved.clone();
    run_object_walk(&run, &instance, &mut resumed, &mut FailOn("none"))
        .await
        .unwrap();
    assert_eq!(
        (resumed.processed, resumed.last_key.as_str()),
        (2, "folder/nested/deep.txt")
    );
    // A pause stops the walk at the next object.
    let mut paused = JobState {
        processed: 0,
        last_key: String::new(),
        ..saved
    };
    app.jobs.change_status("job_walk", "pause").unwrap();
    let error = run_object_walk(&run, &instance, &mut paused, &mut FailOn("none"))
        .await
        .unwrap_err();
    assert_eq!(error, Error::Interrupted(crate::common::error::Interrupt::Paused));
    // A walk of an empty prefix fails, except for the statistics.
    let mut empty = JobState {
        id: "job_empty".to_owned(),
        job_type: job_type::TAG_PREFIX.to_owned(),
        prefix: "nothing/".to_owned(),
        status: job_status::RUNNING.to_owned(),
        ..JobState::default()
    };
    app.jobs.put(empty.clone()).unwrap();
    let run = JobRun {
        app: app.clone(),
        ctx: OpCtx::default(),
        id: "job_empty".to_owned(),
    };
    let error = run_object_walk(&run, &instance, &mut empty, &mut FailOn("none"))
        .await
        .unwrap_err();
    assert!(error.has_code("empty_prefix"));
}

/// A host that records the progress of each save and never stops the walk.
#[derive(Default)]
struct RecordingHost {
    ctx: OpCtx,
    saves: std::sync::Mutex<Vec<i64>>,
}

impl WalkHost for RecordingHost {
    fn ctx(&self) -> &OpCtx {
        &self.ctx
    }

    fn check_control(&self) -> Result<()> {
        Ok(())
    }

    fn refresh_status(&self, _job: &mut JobState) {}

    fn save(&self, job: &JobState) -> Result<()> {
        self.saves.lock().unwrap().push(job.processed);
        Ok(())
    }
}

#[tokio::test]
async fn the_statistics_save_less_often_than_the_other_walks() {
    let backend = read_write_backend();
    backend.insert("tenant/folder/a.txt", "a", "text/plain");
    let instance = super::testing::read_write_over(backend);
    for (kind, saves) in [(job_type::TAG_PREFIX, vec![1, 2, 3]), (job_type::STATS_PREFIX, vec![3])] {
        let host = RecordingHost::default();
        let mut job = JobState {
            job_type: kind.to_owned(),
            prefix: "folder/".to_owned(),
            status: job_status::RUNNING.to_owned(),
            ..JobState::default()
        };
        run_object_walk(&host, &instance, &mut job, &mut FailOn("none"))
            .await
            .unwrap();
        assert_eq!(*host.saves.lock().unwrap(), saves, "{kind}");
        assert_eq!(job.last_key, "folder/nested/deep.txt");
    }
}
