//! The tests of the job manager: the jobs of a prefix, the limits, the history, the controls, the reaper, the panic
//! of a job, the ceilings of a job and the routes `/api/jobs/` and `/api/stats`.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::testing::{Called, call, rig, rig_over, wait_for_status};
use super::*;
use crate::access::{ACTION_READ, ACTION_WRITE, AccessRequest};
use crate::common::BoxFuture;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::storage::{Backend, BatchDeleter, ListOptions, ListPage, Mover};
use crate::common::time::Timestamp;
use crate::instance::ceiling::{CeilingMap, MAX_OBJECT_SIZE};
use crate::testkit::{MemoryBackend, MemoryLayer};

fn job_of(kind: &str, instance: &str) -> JobState {
    JobState {
        job_type: kind.to_owned(),
        instance: instance.to_owned(),
        ..JobState::default()
    }
}

fn stored(id: &str, status: &str, updated_at: Timestamp) -> JobState {
    JobState {
        id: id.to_owned(),
        job_type: job_type::STATS_PREFIX.to_owned(),
        instance: "rw".to_owned(),
        status: status.to_owned(),
        created_at: updated_at,
        updated_at,
        ..JobState::default()
    }
}

fn ceilings(action: &str, value: i64) -> CeilingMap {
    let mut map = CeilingMap::new();
    map.entry(action.to_owned())
        .or_default()
        .insert(MAX_OBJECT_SIZE.to_owned(), value);
    map
}

#[tokio::test]
async fn a_recursive_copy_runs_as_a_job_in_memory() {
    let rig = rig();
    let created = rig
        .app
        .jobs
        .create(JobState {
            source: "folder/".to_owned(),
            target: "copied/".to_owned(),
            ..job_of(job_type::COPY_PREFIX, "rw")
        })
        .unwrap();
    assert_eq!(created.status, job_status::QUEUED);
    let done = wait_for_status(&rig.app, &created.id, job_status::COMPLETED).await;
    assert_eq!(done.processed, 2);
    assert_eq!(done.public().copied_bytes, 10);
    assert_eq!(
        &rig.backend.object("tenant/copied/direct.txt").unwrap().data[..],
        b"direct"
    );
    assert_eq!(
        &rig.backend.object("tenant/copied/nested/deep.txt").unwrap().data[..],
        b"deep"
    );
    assert!(rig.backend.contains("tenant/folder/direct.txt"));
}

#[tokio::test]
async fn a_move_of_a_prefix_removes_the_sources() {
    let rig = rig();
    let created = rig
        .app
        .jobs
        .create(JobState {
            source: "folder/".to_owned(),
            target: "moved/".to_owned(),
            ..job_of(job_type::MOVE_PREFIX, "rw")
        })
        .unwrap();
    let done = wait_for_status(&rig.app, &created.id, job_status::COMPLETED).await;
    assert_eq!(done.processed, 2);
    assert!(!rig.backend.contains("tenant/folder/direct.txt"));
    assert!(rig.backend.contains("tenant/moved/nested/deep.txt"));
}

#[tokio::test]
async fn the_folder_statistics_keep_bounded_distributions_and_the_largest_objects() {
    let rig = rig();
    let now = Timestamp::now();
    rig.backend
        .insert_modified("tenant/folder/photo.jpg", vec![b'j'; 80], "image/jpeg", now);
    rig.backend.insert_modified(
        "tenant/folder/archive.bin",
        vec![b'b'; 20],
        "application/octet-stream",
        now,
    );
    rig.backend.insert_modified(
        "tenant/folder/nested/more/item.bin",
        vec![b'm'; 10],
        "application/octet-stream",
        now,
    );
    let created = rig
        .app
        .jobs
        .create(JobState {
            prefix: "folder/".to_owned(),
            ..job_of(job_type::STATS_PREFIX, "rw")
        })
        .unwrap();
    let done = wait_for_status(&rig.app, &created.id, job_status::COMPLETED).await;
    let stats = done.stats.as_ref().expect("the statistics");
    assert_eq!((stats.count, stats.total_bytes), (5, 120));
    // The distribution by kind follows the kind of each object.
    let photo_kind = crate::server::detect_kind("folder/photo.jpg", "image/jpeg");
    let objects = [
        ("folder/photo.jpg", "image/jpeg", 80),
        ("folder/archive.bin", "application/octet-stream", 20),
        ("folder/nested/more/item.bin", "application/octet-stream", 10),
        ("folder/direct.txt", "text/plain", 6),
        ("folder/nested/deep.txt", "text/plain", 4),
    ];
    let mut expected = Aggregate::default();
    for (key, mime, size) in objects {
        if crate::server::detect_kind(key, mime) == photo_kind {
            expected.count += 1;
            expected.bytes += size;
        }
    }
    assert_eq!(stats.by_type[photo_kind], expected);
    assert_eq!(stats.by_folder["nested/"], Aggregate { count: 2, bytes: 14 });
    assert_eq!(stats.by_folder["nested/more/"], Aggregate { count: 1, bytes: 10 });
    let public = done.public();
    let largest = &public.stats.as_ref().unwrap().largest;
    assert_eq!(largest.len(), 5);
    assert_eq!(largest[0].path, "folder/photo.jpg");
    assert!(public.stats.as_ref().unwrap().recent.len() <= MAX_STATS_RECENT_ENTRIES);
    // The treemap and the time of the scan come at the end of the job.
    let treemap = stats.treemap.as_ref().expect("the treemap");
    assert_eq!((treemap.bytes, treemap.count), (120, 5));
    assert_eq!(stats.treemap_threshold_bytes, 2);
    assert!(stats.newest.is_some() && stats.oldest.is_some());
}

#[tokio::test]
async fn the_job_collection_route_is_not_exposed() {
    let rig = rig();
    let collection = call(&rig.app, "GET", "/api/jobs", None).await;
    assert_eq!(collection.status, 404);
    assert_eq!(collection.text, "404 page not found\n");
    let subtree = call(&rig.app, "GET", "/api/jobs/", None).await;
    assert_eq!(subtree.status, 404);
    assert_eq!(subtree.json()["error"]["code"], "unknown_job");
}

#[tokio::test]
async fn jobs_do_not_survive_a_new_manager() {
    let rig = rig();
    let now = Timestamp::now();
    rig.app
        .jobs
        .put(stored("job-memory-only", job_status::COMPLETED, now))
        .unwrap();
    assert!(rig.app.jobs.get("job-memory-only").is_some());
    rig.app.jobs.close();
    let other = rig_over(Arc::new(MemoryBackend::new()));
    assert!(other.jobs.get("job-memory-only").is_none());
    let fresh = JobManager::new(std::sync::Weak::new(), 10);
    assert!(fresh.get("job-memory-only").is_none());
}

#[test]
fn the_manager_prunes_only_the_old_finished_jobs() {
    let manager = JobManager::new(std::sync::Weak::new(), 2);
    let base = Timestamp::parse_rfc3339("2026-07-24T12:00:00Z").unwrap();
    manager
        .put(stored("completed-old", job_status::COMPLETED, base))
        .unwrap();
    manager
        .put(stored("failed-middle", job_status::FAILED, base.plus_secs(60)))
        .unwrap();
    manager
        .put(stored("completed-new", job_status::COMPLETED, base.plus_secs(120)))
        .unwrap();
    manager
        .put(stored("running-kept", job_status::RUNNING, base.plus_secs(180)))
        .unwrap();
    manager.prune_history();
    for id in ["failed-middle", "completed-new", "running-kept"] {
        assert!(manager.get(id).is_some(), "{id} must stay");
    }
    assert!(manager.get("completed-old").is_none());
}

#[tokio::test]
async fn insights_answer_inline_and_reuse_a_fresh_completed_result() {
    let rig = rig();
    rig.backend.state().list_calls = 0;
    let first = call(&rig.app, "GET", "/api/stats?instance=rw&prefix=folder%2F", None).await;
    assert_eq!(first.status, 200, "{}", first.text);
    let first = first.json();
    assert_eq!(first["status"], job_status::COMPLETED);
    assert!(first["stats"].is_object());
    let calls = rig.backend.state().list_calls;
    let second = call(&rig.app, "GET", "/api/stats?instance=rw&prefix=folder%2F", None).await;
    assert_eq!(second.status, 200, "{}", second.text);
    let second = second.json();
    assert_eq!(second["status"], job_status::COMPLETED);
    assert_eq!(second["id"], first["id"]);
    assert_eq!(
        rig.backend.state().list_calls,
        calls,
        "a fresh result made another listing"
    );
}

#[tokio::test]
async fn insights_go_to_the_background_after_the_inline_wait() {
    let rig = rig();
    rig.backend.state().list_delay = Duration::from_millis(200);
    let started = std::time::Instant::now();
    let answer = call(&rig.app, "GET", "/api/stats?instance=rw&prefix=folder%2F", None).await;
    let elapsed = started.elapsed();
    assert_eq!(answer.status, 202, "{}", answer.text);
    assert!(
        elapsed >= Duration::from_millis(80) && elapsed <= Duration::from_millis(180),
        "inline wait = {elapsed:?}, want about 100 ms"
    );
    let id = answer.json()["id"].as_str().unwrap().to_owned();
    let done = wait_for_status(&rig.app, &id, job_status::COMPLETED).await;
    assert!(done.stats.is_some());
}

#[tokio::test]
async fn the_stats_route_checks_the_method_the_instance_and_the_permission() {
    let rig = rig();
    assert_eq!(call(&rig.app, "POST", "/api/stats?instance=rw", None).await.status, 405);
    let unknown = call(&rig.app, "GET", "/api/stats?instance=none", None).await;
    assert_eq!(unknown.status, 404);
    assert_eq!(unknown.json()["error"]["code"], "unknown_instance");
}

async fn fill_active(app: &crate::common::app::App, status: &str) {
    let now = Timestamp::now();
    for index in 0..MAX_ACTIVE_JOBS {
        app.jobs.put(stored(&format!("active-{index}"), status, now)).unwrap();
    }
}

#[tokio::test]
async fn the_manager_bounds_the_active_jobs_with_paused_jobs() {
    let rig = rig();
    fill_active(&rig.app, job_status::PAUSED).await;
    let error = rig
        .app
        .jobs
        .create(JobState {
            prefix: "folder/".to_owned(),
            ..job_of(job_type::STATS_PREFIX, "rw")
        })
        .unwrap_err();
    assert_eq!(error.status(), 429);
    assert_eq!(error.code(), "job_limit_reached");
    assert_eq!(
        error.public_message(),
        "the server is already running or queuing 4 background jobs"
    );
}

#[tokio::test]
async fn the_job_limit_refuses_more_work() {
    let rig = rig();
    fill_active(&rig.app, job_status::RUNNING).await;
    let error = rig.app.jobs.create(job_of(job_type::STATS_PREFIX, "rw")).unwrap_err();
    assert_eq!((error.status(), error.code().as_str()), (429, "job_limit_reached"));
}

#[tokio::test]
async fn a_job_of_an_unknown_instance_is_refused() {
    let rig = rig();
    let error = rig.app.jobs.create(job_of(job_type::STATS_PREFIX, "none")).unwrap_err();
    assert_eq!((error.status(), error.code().as_str()), (404, "unknown_instance"));
    let lone = JobManager::default();
    assert!(lone.create(job_of(job_type::STATS_PREFIX, "rw")).is_err());
}

/// A back end whose listing panics while the switch is on.
struct PanicList {
    memory: MemoryBackend,
    panics: AtomicBool,
}

impl MemoryLayer for PanicList {
    fn memory(&self) -> &MemoryBackend {
        &self.memory
    }

    fn list<'a>(&'a self, ctx: &'a OpCtx, options: &'a ListOptions) -> BoxFuture<'a, Result<ListPage>> {
        if self.panics.load(Ordering::SeqCst) {
            panic!("backend exploded");
        }
        self.memory.list(ctx, options)
    }
}

#[tokio::test]
async fn a_panic_of_a_job_fails_the_job_and_keeps_the_worker() {
    let backend = Arc::new(PanicList {
        memory: MemoryBackend::with_objects(&[("tenant/folder/a.txt", "a")]),
        panics: AtomicBool::new(true),
    });
    let app = rig_over(backend.clone());
    let job = app
        .jobs
        .create(JobState {
            prefix: "folder/".to_owned(),
            ..job_of(job_type::DELETE_PREFIX, "rw")
        })
        .unwrap();
    let failed = wait_for_status(&app, &job.id, job_status::FAILED).await;
    assert!(!failed.error.is_empty());
    assert!(!failed.error.contains("exploded"), "{}", failed.error);
    assert_eq!(failed.error, "the job failed unexpectedly");
    // The worker is alive and runs the next jobs.
    backend.panics.store(false, Ordering::SeqCst);
    let next = app
        .jobs
        .create(JobState {
            prefix: "folder/".to_owned(),
            ..job_of(job_type::STATS_PREFIX, "rw")
        })
        .unwrap();
    wait_for_status(&app, &next.id, job_status::COMPLETED).await;
}

#[tokio::test]
async fn expired_paused_jobs_are_canceled_and_free_their_place() {
    let rig = rig();
    let now = Timestamp::now();
    fill_active(&rig.app, job_status::PAUSED).await;
    let half = PAUSED_JOB_TTL.as_secs() as i64 / 2;
    assert_eq!(rig.app.jobs.reap_expired_paused(now.plus_secs(half)), 0);
    let after = PAUSED_JOB_TTL.as_secs() as i64 + 60;
    assert_eq!(rig.app.jobs.reap_expired_paused(now.plus_secs(after)), MAX_ACTIVE_JOBS);
    let reaped = rig.app.jobs.get("active-0").unwrap();
    assert_eq!(reaped.status, job_status::CANCELED);
    assert!(reaped.ended_at.is_some());
    let job = rig
        .app
        .jobs
        .create(JobState {
            prefix: "folder/".to_owned(),
            ..job_of(job_type::STATS_PREFIX, "rw")
        })
        .expect("the place is free");
    wait_for_status(&rig.app, &job.id, job_status::COMPLETED).await;
}

/// A back end with a batch delete that records each batch.
struct Batches {
    memory: MemoryBackend,
    batches: Mutex<Vec<usize>>,
    singles: AtomicUsize,
}

impl MemoryLayer for Batches {
    fn memory(&self) -> &MemoryBackend {
        &self.memory
    }

    fn delete<'a>(&'a self, ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<()>> {
        self.singles.fetch_add(1, Ordering::SeqCst);
        self.memory.delete(ctx, key)
    }

    fn batch_deleter(&self) -> Option<&dyn BatchDeleter> {
        Some(self)
    }
}

impl BatchDeleter for Batches {
    fn delete_many<'a>(&'a self, _ctx: &'a OpCtx, keys: &'a [String]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.batches.lock().unwrap().push(keys.len());
            let mut objects = self.memory.objects();
            for key in keys {
                objects.remove(key);
            }
            Ok(())
        })
    }
}

#[tokio::test]
async fn the_delete_of_a_prefix_goes_in_batches_and_counts_each_object() {
    let memory = MemoryBackend::new();
    for index in 0..2300 {
        memory.insert(&format!("tenant/bulk/{index:05}.txt"), "x", "text/plain");
    }
    memory.insert("tenant/keep/one.txt", "x", "text/plain");
    let backend = Arc::new(Batches {
        memory,
        batches: Mutex::new(Vec::new()),
        singles: AtomicUsize::new(0),
    });
    let app = rig_over(backend.clone());
    let job = app
        .jobs
        .create(JobState {
            prefix: "bulk/".to_owned(),
            ..job_of(job_type::DELETE_PREFIX, "rw")
        })
        .unwrap();
    let done = wait_for_status(&app, &job.id, job_status::COMPLETED).await;
    assert_eq!(done.processed, 2300);
    assert_eq!(*backend.batches.lock().unwrap(), vec![1000, 1000, 300]);
    assert_eq!(backend.singles.load(Ordering::SeqCst), 0);
    assert!(backend.memory.keys().iter().all(|key| !key.starts_with("tenant/bulk/")));
    assert!(backend.memory.contains("tenant/keep/one.txt"));
}

#[tokio::test]
async fn the_delete_of_an_empty_prefix_fails() {
    let rig = rig();
    let job = rig
        .app
        .jobs
        .create(JobState {
            prefix: "nothing/".to_owned(),
            ..job_of(job_type::DELETE_PREFIX, "rw")
        })
        .unwrap();
    let failed = wait_for_status(&rig.app, &job.id, job_status::FAILED).await;
    assert!(failed.error.contains("no objects"), "{}", failed.error);
}

/// A back end that refuses the delete of the locked keys with `409 object_locked`.
struct Locks {
    memory: MemoryBackend,
    locked: Vec<String>,
    deletes: Mutex<Vec<String>>,
}

impl MemoryLayer for Locks {
    fn memory(&self) -> &MemoryBackend {
        &self.memory
    }

    fn delete<'a>(&'a self, ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if self.locked.iter().any(|locked| locked == key) {
                return Err(Error::api(409, "object_locked", format!("Object Lock keeps {key:?}.")));
            }
            self.deletes.lock().unwrap().push(key.to_owned());
            self.memory.delete(ctx, key).await
        })
    }
}

#[tokio::test]
async fn the_delete_of_a_prefix_counts_the_locked_keys() {
    let memory = MemoryBackend::new();
    for name in ["a", "b", "c", "d"] {
        memory.insert(&format!("tenant/logs/{name}.txt"), name, "text/plain");
    }
    let backend = Arc::new(Locks {
        memory,
        locked: vec!["tenant/logs/b.txt".to_owned(), "tenant/logs/d.txt".to_owned()],
        deletes: Mutex::new(Vec::new()),
    });
    let app = rig_over(backend.clone());
    let job = app
        .jobs
        .create(JobState {
            prefix: "logs/".to_owned(),
            ..job_of(job_type::DELETE_PREFIX, "rw")
        })
        .unwrap();
    let done = wait_for_status(&app, &job.id, job_status::COMPLETED).await.public();
    assert_eq!(done.processed, 2);
    assert_eq!(done.locked, 2);
    assert_eq!(done.locked_keys, vec!["logs/b.txt", "logs/d.txt"]);
    assert!(done.error.is_empty());
    assert_eq!(
        *backend.deletes.lock().unwrap(),
        vec!["tenant/logs/a.txt", "tenant/logs/c.txt"]
    );
}

#[tokio::test]
async fn the_move_of_a_prefix_keeps_a_locked_source_and_counts_it() {
    let memory = MemoryBackend::with_objects(&[("tenant/in/a.txt", "a"), ("tenant/in/b.txt", "b")]);
    let backend = Arc::new(Locks {
        memory,
        locked: vec!["tenant/in/a.txt".to_owned()],
        deletes: Mutex::new(Vec::new()),
    });
    let app = rig_over(backend.clone());
    let job = app
        .jobs
        .create(JobState {
            source: "in/".to_owned(),
            target: "out/".to_owned(),
            ..job_of(job_type::MOVE_PREFIX, "rw")
        })
        .unwrap();
    let done = wait_for_status(&app, &job.id, job_status::COMPLETED).await.public();
    assert_eq!(done.locked, 1);
    assert_eq!(done.locked_keys, vec!["in/a.txt"]);
    assert!(backend.memory.contains("tenant/in/a.txt"));
    assert!(backend.memory.contains("tenant/out/a.txt"));
    assert!(!backend.memory.contains("tenant/in/b.txt"));
    // The move of one object whose source stays: the copy is made, and the error says why.
    let object = app
        .jobs
        .create(JobState {
            source: "in/a.txt".to_owned(),
            target: "single.txt".to_owned(),
            total_bytes: 1,
            ..job_of(job_type::MOVE_OBJECT, "rw")
        })
        .unwrap();
    let failed = wait_for_status(&app, &object.id, job_status::FAILED).await;
    assert!(
        failed
            .error
            .starts_with("The copy is made, but the source stays. Object Lock keeps"),
        "{}",
        failed.error
    );
    assert!(backend.memory.contains("tenant/single.txt"));
}

/// A back end that moves an object with one rename and removes the empty folders, as a volume does.
struct Renames {
    memory: MemoryBackend,
    removed: Mutex<Vec<String>>,
}

impl MemoryLayer for Renames {
    fn memory(&self) -> &MemoryBackend {
        &self.memory
    }

    fn mover(&self) -> Option<&dyn Mover> {
        Some(self)
    }

    fn folder_remover(&self) -> Option<&dyn crate::common::storage::FolderRemover> {
        Some(self)
    }
}

impl Mover for Renames {
    fn move_object<'a>(&'a self, _ctx: &'a OpCtx, source: &'a str, destination: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let object = self
                .memory
                .object(source)
                .ok_or_else(|| Error::upstream(404, "NotFound", ""))?;
            self.memory.objects().remove(source);
            self.memory.insert(destination, object.data, &object.content_type);
            Ok(())
        })
    }
}

impl crate::common::storage::FolderRemover for Renames {
    fn remove_empty_folders<'a>(&'a self, _ctx: &'a OpCtx, prefix: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.removed.lock().unwrap().push(prefix.to_owned());
            Ok(())
        })
    }
}

#[tokio::test]
async fn the_move_of_a_prefix_on_a_volume_renames_each_file_and_removes_the_folders() {
    let backend = Arc::new(Renames {
        memory: MemoryBackend::with_objects(&[("tenant/src/a.txt", "aa"), ("tenant/src/sub/b.txt", "b")]),
        removed: Mutex::new(Vec::new()),
    });
    let app = rig_over(backend.clone());
    let job = app
        .jobs
        .create(JobState {
            source: "src/".to_owned(),
            target: "dst/".to_owned(),
            ..job_of(job_type::MOVE_PREFIX, "rw")
        })
        .unwrap();
    let done = wait_for_status(&app, &job.id, job_status::COMPLETED).await;
    assert_eq!((done.processed, done.copied_bytes), (2, 3));
    assert_eq!(backend.memory.keys(), vec!["tenant/dst/a.txt", "tenant/dst/sub/b.txt"]);
    assert_eq!(*backend.removed.lock().unwrap(), vec!["tenant/src/"]);
}

#[tokio::test]
async fn a_job_with_its_own_ceilings_refuses_a_prefix_before_a_copy() {
    let rig = rig();
    rig.backend.insert("tenant/folder/set/a.txt", "abc", "text/plain");
    rig.backend
        .insert("tenant/folder/set/z.txt", "x".repeat(30), "text/plain");
    let job = rig
        .app
        .jobs
        .create(JobState {
            source: "folder/set/".to_owned(),
            target: "copied/".to_owned(),
            ceilings: Some(Arc::new(Ceilings::from_map(&ceilings(ACTION_WRITE, 10)))),
            ..job_of(job_type::COPY_PREFIX, "rw")
        })
        .unwrap();
    let failed = wait_for_status(&rig.app, &job.id, job_status::FAILED).await;
    assert!(failed.error.contains("action object.write"), "{}", failed.error);
    assert!(failed.refusal.is_some());
    assert!(rig.backend.keys().iter().all(|key| !key.starts_with("tenant/copied/")));
}

#[tokio::test]
async fn a_resume_keeps_the_lower_value_of_each_ceiling() {
    let rig = rig();
    let job = rig
        .app
        .jobs
        .create(JobState {
            prefix: "folder/".to_owned(),
            ceilings: Some(Arc::new(Ceilings::from_map(&ceilings(ACTION_READ, 50)))),
            ..job_of(job_type::STATS_PREFIX, "rw")
        })
        .unwrap();
    let mut lower = ceilings(ACTION_READ, 20);
    lower.extend(ceilings(ACTION_WRITE, 9));
    rig.app.jobs.lower_ceilings(&job.id, &lower);
    rig.app.jobs.lower_ceilings(&job.id, &ceilings(ACTION_READ, 60));
    let kept = rig.app.jobs.get(&job.id).unwrap().ceilings.unwrap();
    assert_eq!(kept.get(ACTION_READ, MAX_OBJECT_SIZE), Some(20));
    assert_eq!(kept.get(ACTION_WRITE, MAX_OBJECT_SIZE), Some(9));
}

#[tokio::test]
async fn the_integrity_route_gives_the_refusal_of_a_ceiling_of_its_request() {
    let rig = rig();
    rig.backend
        .insert("tenant/folder/twelve.txt", "hello world!", "text/plain");
    let request = AccessRequest {
        subject: "user-1".to_owned(),
        ..AccessRequest::default()
    };
    request.ceilings.lower(ACTION_READ, MAX_OBJECT_SIZE, 10);
    let ctx = OpCtx {
        access: Some(Arc::new(request)),
        ..super::testing::request_ctx(&rig.app)
    };
    let body = serde_json::json!({"instance": "rw", "key": "folder/twelve.txt"});
    let refused = super::testing::call_with(
        handle_integrity,
        &rig.app,
        "POST",
        "/api/integrity",
        Some(body.clone()),
        ctx,
    )
    .await;
    assert_eq!(refused.status, 403, "{}", refused.text);
    assert_eq!(refused.json()["error"]["code"], "ceiling_exceeded");
    assert_eq!(refused.json()["error"]["action"], ACTION_READ);
    assert_eq!(refused.json()["error"]["limit"], 10);
    let request = AccessRequest::default();
    request.ceilings.lower(ACTION_READ, MAX_OBJECT_SIZE, 20);
    let ctx = OpCtx {
        access: Some(Arc::new(request)),
        ..super::testing::request_ctx(&rig.app)
    };
    let allowed =
        super::testing::call_with(handle_integrity, &rig.app, "POST", "/api/integrity", Some(body), ctx).await;
    assert!(allowed.status == 200 || allowed.status == 202, "{}", allowed.text);
}

async fn slow_stats_job(rig: &super::testing::Rig) -> JobState {
    rig.backend.state().list_delay = Duration::from_millis(300);
    rig.app
        .jobs
        .create(JobState {
            prefix: "folder/".to_owned(),
            ..job_of(job_type::STATS_PREFIX, "rw")
        })
        .unwrap()
}

fn code(called: &Called) -> String {
    called.json()["error"]["code"].as_str().unwrap_or("").to_owned()
}

#[tokio::test]
async fn a_person_pauses_resumes_and_cancels_a_job() {
    let rig = rig();
    let job = slow_stats_job(&rig).await;
    let path = format!("/api/jobs/{}", job.id);

    let read = call(&rig.app, "GET", &path, None).await;
    assert_eq!(read.status, 200);
    assert_eq!(read.json()["id"], job.id.as_str());

    let paused = call(&rig.app, "POST", &format!("{path}/pause"), None).await;
    assert_eq!(paused.status, 200, "{}", paused.text);
    assert_eq!(paused.json()["status"], job_status::PAUSED);
    // A pause of a paused job is refused.
    let again = call(&rig.app, "POST", &format!("{path}/pause"), None).await;
    assert_eq!((again.status, code(&again).as_str()), (409, "job_not_active"));
    // The worker stops at its next control and leaves the job paused.
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(rig.app.jobs.get(&job.id).unwrap().status, job_status::PAUSED);

    rig.backend.state().list_delay = Duration::ZERO;
    let resumed = call(&rig.app, "POST", &format!("{path}/resume"), None).await;
    assert_eq!(resumed.status, 200, "{}", resumed.text);
    assert_eq!(resumed.json()["status"], job_status::QUEUED);
    wait_for_status(&rig.app, &job.id, job_status::COMPLETED).await;
    let resume_done = call(&rig.app, "POST", &format!("{path}/resume"), None).await;
    assert_eq!(
        (resume_done.status, code(&resume_done).as_str()),
        (409, "job_not_resumable")
    );

    // A cancel of a completed job changes nothing.
    let canceled = call(&rig.app, "POST", &format!("{path}/cancel"), None).await;
    assert_eq!(canceled.status, 200);
    assert_eq!(canceled.json()["status"], job_status::COMPLETED);

    let other = slow_stats_job(&rig).await;
    let canceled = call(&rig.app, "POST", &format!("/api/jobs/{}/cancel", other.id), None).await;
    assert_eq!(canceled.json()["status"], job_status::CANCELED);
    assert!(canceled.json()["endedAt"].is_string());
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(rig.app.jobs.get(&other.id).unwrap().status, job_status::CANCELED);
}

#[tokio::test]
async fn the_job_routes_check_the_method_the_id_and_the_action() {
    let rig = rig();
    let job = slow_stats_job(&rig).await;
    let path = format!("/api/jobs/{}", job.id);
    let post = call(&rig.app, "POST", &path, None).await;
    assert_eq!(post.status, 405);
    assert_eq!(post.headers.get("allow").unwrap(), "GET");
    let get_action = call(&rig.app, "GET", &format!("{path}/pause"), None).await;
    assert_eq!(get_action.status, 405);
    assert_eq!(get_action.headers.get("allow").unwrap(), "POST");
    let deep = call(&rig.app, "POST", &format!("{path}/pause/now"), None).await;
    assert_eq!(deep.status, 405);
    let unknown_action = call(&rig.app, "POST", &format!("{path}/stop"), None).await;
    assert_eq!(
        (unknown_action.status, code(&unknown_action).as_str()),
        (400, "invalid_job_action")
    );
    let unknown = call(&rig.app, "GET", "/api/jobs/job_nothing", None).await;
    assert_eq!((unknown.status, code(&unknown).as_str()), (404, "unknown_job"));
    assert_eq!(unknown.json()["error"]["message"], "job was not found");
    let unknown_control = call(&rig.app, "POST", "/api/jobs/job_nothing/stop", None).await;
    assert_eq!(unknown_control.status, 404);
    rig.app.jobs.change_status(&job.id, "cancel").unwrap();
}

#[tokio::test]
async fn a_resume_needs_a_free_place() {
    let rig = rig();
    let now = Timestamp::now();
    rig.app.jobs.put(stored("failed-one", job_status::FAILED, now)).unwrap();
    fill_active(&rig.app, job_status::PAUSED).await;
    let error = rig.app.jobs.change_status("failed-one", "resume").unwrap_err();
    assert_eq!(error.code(), "job_limit_reached");
    // A paused job that resumes keeps its own place.
    let resumed = rig.app.jobs.change_status("active-0", "resume").unwrap();
    assert_eq!(resumed.status, job_status::QUEUED);
    assert!(resumed.ended_at.is_none());
    let error = rig.app.jobs.change_status("active-1", "restart").unwrap_err();
    assert_eq!(error.code(), "invalid_job_action");
}

#[tokio::test]
async fn a_completed_insights_job_serves_again_for_thirty_seconds() {
    let rig = rig();
    let now = Timestamp::now();
    let mut done = stored("done", job_status::COMPLETED, now);
    done.prefix = "p/".to_owned();
    done.stats = Some(Box::new(new_stats_response("rw", "p/", 0)));
    done.ended_at = Some(now);
    rig.app.jobs.put(done).unwrap();
    let mut running = stored("running", job_status::RUNNING, now.plus_secs(5));
    running.prefix = "p/".to_owned();
    rig.app.jobs.put(running).unwrap();
    assert_eq!(
        rig.app
            .jobs
            .reusable_stats_job_at("rw", "p/", now.plus_secs(30))
            .unwrap()
            .id,
        "done"
    );
    assert_eq!(
        rig.app
            .jobs
            .reusable_stats_job_at("rw", "p/", now.plus_secs(31))
            .unwrap()
            .id,
        "running"
    );
    assert!(rig.app.jobs.reusable_stats_job_at("rw", "q/", now).is_none());
}

#[tokio::test]
async fn a_wait_ends_at_the_end_of_a_job_or_after_its_time() {
    let rig = rig();
    let job = slow_stats_job(&rig).await;
    assert!(
        rig.app
            .jobs
            .wait_for_terminal(&job.id, Duration::from_millis(20))
            .await
            .is_none()
    );
    assert!(rig.app.jobs.wait_for_terminal(&job.id, Duration::ZERO).await.is_none());
    let done = rig
        .app
        .jobs
        .wait_for_terminal(&job.id, Duration::from_secs(5))
        .await
        .unwrap();
    assert_eq!(done.status, job_status::COMPLETED);
    assert!(rig.app.jobs.wait_for_terminal(&job.id, Duration::ZERO).await.is_some());
    assert!(
        rig.app
            .jobs
            .wait_for_terminal("job_none", Duration::from_millis(10))
            .await
            .is_none()
    );
}
