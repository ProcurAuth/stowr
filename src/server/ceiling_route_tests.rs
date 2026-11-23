//! The route tests of the ceiling `max_object_size`, of the display questions of a listing and of the options route
//! in mode `authzen`. Each request goes through the whole dispatch with the fake guard. A test reads the answer, the
//! objects of the back end, the jobs and the questions of the fake.
//!
//! The answers of [`ceilings`] say true to each question. They give the ceiling of `object.read`, of
//! `object.write`, or of both, and one unit to a usage question.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use serde_json::{Map, Value, json};

use super::testing::{TestRequest, TestResponse, app_with_access};
use crate::access::actions::ActionDocument;
use crate::access::fake::{FakePdp, FakeQuestion};
use crate::access::test_support::{
    BUCKET, FOLDER, SERVICE, SUBJECT, authzen_config, bucket, ctx_of, instance_over, memory,
};
use crate::access::{ACTION_DELETE, ACTION_READ, ACTION_WRITE, AccessLayer, Operation};
use crate::archive::zip::writer::{EntryHeader, ZipWriter};
use crate::common::app::App;
use crate::common::config::{RuntimePolicy, VolumeConfig};
use crate::common::ctx::OpCtx;
use crate::instance::Instance;
use crate::instance::ceiling::{Ceilings, MAX_OBJECT_SIZE, ceiling_applies, ceiling_of};
use crate::instance::gate::Gate;
use crate::jobs::{JobState, job_type};
use crate::testkit::MemoryBackend;

/// The token that the fake guard accepts.
const TOKEN: &str = "good-token";
/// The value of [`ceilings`] that gives no ceiling.
const NONE: i64 = -1;
/// The longest wait for the end of a job.
const JOB_WAIT: Duration = Duration::from_secs(20);

/// The application of a test, its fake guard and the memory back end of the instance `rw`.
struct Env {
    app: Arc<App>,
    fake: Arc<FakePdp>,
    rw: Arc<MemoryBackend>,
}

/// The application: `readonly` (read only), `rw` (root prefix `tenant/`, three objects) and the extra instances. The
/// configuration names the extra volume blocks.
fn env_with(extra: Vec<Arc<Instance>>, volumes: Vec<VolumeConfig>) -> Env {
    let readonly = bucket("readonly", "Read only", Some(&["read"]));
    let mut rw = bucket("rw", "Read write", None);
    rw.root_prefix = "tenant/".to_owned();
    let mut config = authzen_config(SERVICE, vec![readonly.clone(), rw.clone()], volumes);
    config.job_history_limit = 10;
    let fake = Arc::new(FakePdp::new());
    fake.accept_token(TOKEN, SUBJECT, "");
    let access = AccessLayer::with_guard(&config, fake.clone()).unwrap();
    let rw_backend = memory(&[
        ("tenant/folder/direct.txt", "direct"),
        ("tenant/folder/nested/deep.txt", "deep"),
        ("tenant/a/x.txt", "a"),
    ]);
    let mut instances = vec![
        instance_over(readonly, memory(&[("ro.txt", "ro")])),
        instance_over(rw, rw_backend.clone()),
    ];
    instances.extend(extra);
    Env {
        app: app_with_access(config, instances, access),
        fake,
        rw: rw_backend,
    }
}

fn env() -> Env {
    env_with(Vec::new(), Vec::new())
}

/// An answer function: true to each question, the ceiling of `object.read` and of `object.write` ([`NONE`] for no
/// ceiling), and one unit for a usage question.
fn ceilings(read: i64, write: i64) -> impl Fn(&FakeQuestion) -> Value + Send + Sync + 'static {
    move |question: &FakeQuestion| {
        let mut context = Map::new();
        if question.usage {
            context.insert("usage".to_owned(), json!({"units": 1}));
        }
        let limit = if question.action == ACTION_READ {
            read
        } else if question.action == ACTION_WRITE {
            write
        } else {
            NONE
        };
        if limit != NONE {
            let mut limits = Map::new();
            limits.insert(MAX_OBJECT_SIZE.to_owned(), json!(limit));
            context.insert("limits".to_owned(), Value::Object(limits));
        }
        json!({"decision": true, "context": Value::Object(context)})
    }
}

async fn send(env: &Env, method: &str, target: &str) -> TestResponse {
    TestRequest::new(method, target)
        .header("x-identity-token", TOKEN)
        .send(&env.app)
        .await
}

async fn send_with(env: &Env, method: &str, target: &str, headers: &[(&str, &str)]) -> TestResponse {
    let mut request = TestRequest::new(method, target).header("x-identity-token", TOKEN);
    for (name, value) in headers {
        request = request.header(name, value);
    }
    request.send(&env.app).await
}

async fn send_json(env: &Env, method: &str, target: &str, body: &str) -> TestResponse {
    TestRequest::new(method, target)
        .header("x-identity-token", TOKEN)
        .header("content-type", "application/json")
        .body(body.to_owned())
        .send(&env.app)
        .await
}

async fn send_body(env: &Env, method: &str, target: &str, body: &str) -> TestResponse {
    TestRequest::new(method, target)
        .header("x-identity-token", TOKEN)
        .body(body.to_owned())
        .send(&env.app)
        .await
}

/// Put an object below the root prefix of `rw`.
fn seed(env: &Env, key: &str, data: impl Into<Bytes>) {
    env.rw
        .insert(&format!("tenant/{key}"), data, "application/octet-stream");
}

/// Put an object of `size` bytes `x` below the root prefix of `rw`.
fn seed_size(env: &Env, key: &str, size: usize) {
    seed(env, key, vec![b'x'; size]);
}

/// True when `rw` has the object.
fn has(env: &Env, key: &str) -> bool {
    env.rw.contains(&format!("tenant/{key}"))
}

/// The number of objects of `rw` below a relative prefix.
fn count_under(env: &Env, prefix: &str) -> usize {
    let full = format!("tenant/{prefix}");
    env.rw.keys().iter().filter(|key| key.starts_with(&full)).count()
}

/// Check the `403 ceiling_exceeded` answer of a JSON route: the action, the ceiling and the limit.
fn assert_ceiling(answer: &TestResponse, action: &str, limit: i64) {
    assert_eq!(answer.status, 403, "{}", answer.text());
    let body = answer.json();
    let error = &body["error"];
    assert_eq!(error["code"], "ceiling_exceeded", "{}", answer.text());
    assert_eq!(error["action"], action, "{}", answer.text());
    assert_eq!(error["ceiling"], MAX_OBJECT_SIZE, "{}", answer.text());
    assert_eq!(error["limit"], limit, "{}", answer.text());
}

/// The job that an answer gives, when it ends.
async fn ended_job(env: &Env, answer: &TestResponse) -> JobState {
    assert!(
        answer.status == 202 || answer.status == 200,
        "job request: {} {}",
        answer.status,
        answer.text()
    );
    let id = answer.json()["id"].as_str().unwrap().to_owned();
    env.app.jobs.wait_for_terminal(&id, JOB_WAIT).await.unwrap()
}

/// The ceiling of a job for an action.
fn job_ceiling(job: &JobState, action: &str) -> Option<i64> {
    job.ceilings
        .as_ref()
        .and_then(|ceilings| ceilings.get(action, MAX_OBJECT_SIZE))
}

/// The bytes of a ZIP archive with these entries.
fn zip_of(entries: &[(&str, Vec<u8>)]) -> Bytes {
    let mut writer = ZipWriter::new();
    for (name, content) in entries {
        writer
            .create(&EntryHeader {
                name: (*name).to_owned(),
                ..EntryHeader::default()
            })
            .unwrap();
        writer.write(Bytes::from(content.clone())).unwrap();
    }
    writer.finish().unwrap();
    let mut out = Vec::new();
    for chunk in writer.take_output() {
        out.extend_from_slice(&chunk);
    }
    Bytes::from(out)
}

static FOLDER_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A new empty folder of a test. The folder goes away when the value is dropped.
struct TestFolder {
    path: PathBuf,
}

impl TestFolder {
    fn new() -> Self {
        let path = std::env::temp_dir().join("stowr-ceiling-route-tests").join(format!(
            "t-{}-{}",
            std::process::id(),
            FOLDER_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self {
            path: std::fs::canonicalize(&path).unwrap(),
        }
    }
}

impl Drop for TestFolder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn write_file(root: &Path, relative: &str, content: &str) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(path, content).unwrap();
}

/// The block and the instance of the volume `vol` on a folder.
fn volume_instance(root: &Path) -> (VolumeConfig, Arc<Instance>) {
    let cfg = VolumeConfig {
        id: "vol".to_owned(),
        name: "vol".to_owned(),
        path: root.to_path_buf(),
        ..VolumeConfig::default()
    };
    let instance = crate::volume::new_volume_instance(&cfg, Arc::new(RuntimePolicy::default()), Gate::new(4)).unwrap();
    (cfg, Arc::new(instance))
}

// --- The read ceiling --------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_read_ceiling_of_one_mebibyte_lets_a_small_object_go() {
    let env = env();
    seed(&env, "reports/a.txt", "hello world!");
    env.fake.set_answer(ceilings(1 << 20, NONE));
    let answer = send(&env, "GET", "/s3?instance=rw&key=reports%2Fa.txt").await;
    assert!(
        (200..300).contains(&answer.status),
        "{} {}",
        answer.status,
        answer.text()
    );
    assert_eq!(answer.text(), "hello world!");
}

#[tokio::test]
async fn a_json_route_refuses_an_object_over_the_read_ceiling_with_the_members_of_the_ceiling() {
    let env = env();
    seed_size(&env, "folder/big.json", 40);
    env.fake.set_answer(ceilings(10, NONE));
    let answer = send(&env, "GET", "/api/json/raw?instance=rw&key=folder%2Fbig.json").await;
    assert_ceiling(&answer, ACTION_READ, 10);
}

#[tokio::test]
async fn a_range_of_an_object_over_the_read_ceiling_gives_no_data() {
    let env = env();
    seed_size(&env, "folder/big.bin", 100);
    env.fake.set_answer(ceilings(10, NONE));
    // The ceiling applies to the whole object, not to the range.
    let range = [("range", "bytes=0-4")];
    let answer = send_with(&env, "GET", "/s3?instance=rw&key=folder%2Fbig.bin&preview=1", &range).await;
    assert_eq!(answer.status, 403, "{}", answer.text());
    assert!(answer.body.len() <= 200, "{}", answer.text());
    assert!(!answer.text().contains("xxxxx"), "{}", answer.text());

    // A preview route of the API reads ranges through the range reader.
    env.rw.insert(
        "tenant/folder/big.zip",
        zip_of(&[("a.txt", vec![b'a'; 100])]),
        "application/zip",
    );
    let answer = send(&env, "GET", "/api/archive-preview?instance=rw&key=folder%2Fbig.zip").await;
    assert_ceiling(&answer, ACTION_READ, 10);
    assert_eq!(env.rw.bytes_read(), 0, "the service read bytes before the refusal");

    env.fake.set_answer(ceilings(1 << 20, NONE));
    let answer = send_with(&env, "GET", "/s3?instance=rw&key=folder%2Fbig.bin&preview=1", &range).await;
    assert_eq!(answer.status, 206, "{}", answer.text());
    assert_eq!(answer.text(), "xxxxx");
}

// --- The write ceiling -------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_gateway_refuses_a_put_over_the_write_ceiling_or_of_an_unknown_size() {
    let env = env();
    env.fake.set_answer(ceilings(NONE, 10));
    let answer = send_body(&env, "PUT", "/s3?instance=rw&key=other%2Fnew.txt", &"y".repeat(20)).await;
    assert_eq!(answer.status, 403, "{}", answer.text());
    assert!(!has(&env, "other/new.txt"));

    // A body of an unknown size has no check that can pass: the ceiling refuses it.
    let chunked = [("transfer-encoding", "chunked")];
    let answer = send_with(&env, "PUT", "/s3?instance=rw&key=other%2Fchunked.txt", &chunked).await;
    assert_eq!(answer.status, 403, "{}", answer.text());
    assert!(!has(&env, "other/chunked.txt"));

    // A size equal to the ceiling passes.
    let answer = send_body(&env, "PUT", "/s3?instance=rw&key=other%2Ffits.txt", "0123456789").await;
    assert_eq!(answer.status, 204, "{}", answer.text());
    assert!(has(&env, "other/fits.txt"));
}

// --- The copy and the move ---------------------------------------------------------------------------------------

#[tokio::test]
async fn a_copy_checks_the_read_and_the_write_ceilings_before_the_copy() {
    let env = env();
    seed(&env, "folder/twelve.txt", "hello world!");
    let body = r#"{"instance":"rw","src":"folder/twelve.txt","dst":"other/copy.txt"}"#;

    // The source is over the read ceiling. The ceiling of the target is high.
    env.fake.set_answer(ceilings(10, 1000));
    assert_ceiling(&send_json(&env, "POST", "/api/copy", body).await, ACTION_READ, 10);
    assert!(!has(&env, "other/copy.txt"));

    // The read ceiling is high. The ceiling of the target is low.
    env.fake.set_answer(ceilings(1000, 10));
    assert_ceiling(&send_json(&env, "POST", "/api/copy", body).await, ACTION_WRITE, 10);
    assert!(!has(&env, "other/copy.txt"));

    env.fake.set_answer(ceilings(1000, 1000));
    let answer = send_json(&env, "POST", "/api/copy", body).await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert!(has(&env, "other/copy.txt"));
}

#[tokio::test]
async fn a_rename_checks_the_ceilings_of_its_copy_and_keeps_the_source() {
    let env = env();
    seed(&env, "folder/twelve.txt", "hello world!");
    env.fake.set_answer(ceilings(1000, 10));
    let answer = send_json(
        &env,
        "POST",
        "/api/rename",
        r#"{"instance":"rw","src":"folder/twelve.txt","dst":"other/moved.txt"}"#,
    )
    .await;
    assert_ceiling(&answer, ACTION_WRITE, 10);
    assert!(has(&env, "folder/twelve.txt"));
    assert!(!has(&env, "other/moved.txt"));
}

#[tokio::test]
async fn a_prefix_copy_copies_nothing_when_one_object_is_over_a_ceiling() {
    let env = env();
    seed_size(&env, "folder/set/a.txt", 3);
    seed_size(&env, "folder/set/b.txt", 5);
    seed_size(&env, "folder/set/z.txt", 30);
    let body = r#"{"instance":"rw","src":"folder/set/","dst":"copied/","isPrefix":true}"#;
    env.fake.set_answer(ceilings(10, 10));
    let job = ended_job(&env, &send_json(&env, "POST", "/api/copy", body).await).await;
    assert_eq!(job.status, "failed", "{job:?}");
    assert!(job.error.contains(MAX_OBJECT_SIZE), "{}", job.error);
    assert_eq!(count_under(&env, "copied/"), 0, "a copy ran before the refusal");
    // The job keeps the ceilings of its request.
    assert_eq!(job_ceiling(&job, ACTION_READ), Some(10));
    assert_eq!(job_ceiling(&job, ACTION_WRITE), Some(10));

    // The same prefix with high ceilings copies each object.
    env.fake.set_answer(ceilings(100, 100));
    let job = ended_job(&env, &send_json(&env, "POST", "/api/copy", body).await).await;
    assert_eq!(job.status, "completed", "{job:?}");
    assert_eq!(count_under(&env, "copied/"), 3);
}

#[tokio::test]
async fn a_prefix_move_moves_nothing_when_one_object_is_over_the_read_ceiling() {
    let env = env();
    seed_size(&env, "folder/set/a.txt", 3);
    seed_size(&env, "folder/set/z.txt", 30);
    env.fake.set_answer(ceilings(10, NONE));
    let answer = send_json(
        &env,
        "POST",
        "/api/rename",
        r#"{"instance":"rw","src":"folder/set/","dst":"moved/","isPrefix":true}"#,
    )
    .await;
    let job = ended_job(&env, &answer).await;
    assert_eq!(job.status, "failed", "{job:?}");
    assert_eq!(count_under(&env, "moved/"), 0, "a part of the prefix moved");
    assert!(has(&env, "folder/set/a.txt"));
}

#[tokio::test]
async fn the_copy_of_a_prefix_checks_each_size_before_the_first_copy() {
    let env = env();
    seed_size(&env, "folder/set/a.txt", 3);
    seed_size(&env, "folder/set/z.txt", 30);
    let ctx = ctx_of(SUBJECT, "rid-prefix");
    if let Some(request) = &ctx.access {
        request.ceilings.lower(ACTION_READ, MAX_OBJECT_SIZE, 10);
    }
    let instance = env.app.instance("rw").unwrap().clone();
    let error = super::api::copy_or_move(&ctx, &instance, "folder/set/", "copied/", true, false)
        .await
        .unwrap_err();
    assert!(error.has_code("ceiling_exceeded"), "{error:?}");
    assert_eq!(count_under(&env, "copied/"), 0, "a copy ran");
}

#[tokio::test]
async fn a_large_copy_is_refused_before_its_job_and_its_job_keeps_the_ceilings() {
    let folder = TestFolder::new();
    let root = folder.path.join("volume");
    write_file(&root, "big.bin", &"0123456789abcdef".repeat(256));
    let (cfg, volume) = volume_instance(&root);
    // A copy of 1024 bytes or more goes in parts: a job makes it.
    volume.set_multipart_copy_threshold(1024);
    let env = env_with(vec![volume], vec![cfg]);
    let body = r#"{"instance":"vol","src":"big.bin","dst":"copy/big.bin"}"#;

    env.fake.set_answer(ceilings(NONE, 1000));
    assert_ceiling(&send_json(&env, "POST", "/api/copy", body).await, ACTION_WRITE, 1000);
    assert!(!root.join("copy/big.bin").exists(), "the copy ran");

    env.fake.set_answer(ceilings(1 << 20, 1 << 20));
    let answer = send_json(&env, "POST", "/api/copy", body).await;
    assert_eq!(answer.status, 202, "{}", answer.text());
    let job = ended_job(&env, &answer).await;
    assert_eq!(job.status, "completed", "{job:?}");
    assert_eq!(job.job_type, job_type::COPY_OBJECT);
    assert_eq!(job_ceiling(&job, ACTION_WRITE), Some(1 << 20));
    assert_eq!(job_ceiling(&job, ACTION_READ), Some(1 << 20));
    assert!(root.join("copy/big.bin").exists());
}

// --- The uploads and the extraction ------------------------------------------------------------------------------

#[tokio::test]
async fn an_upload_checks_the_write_ceiling_at_its_creation_and_at_each_chunk() {
    let env = env();
    env.fake.set_answer(ceilings(NONE, 10));
    let answer = send_json(
        &env,
        "POST",
        "/api/uploads",
        r#"{"instance":"rw","key":"other/up.bin","size":20}"#,
    )
    .await;
    assert_ceiling(&answer, ACTION_WRITE, 10);
    assert!(env.rw.state().multipart.is_empty(), "a multipart upload started");

    // An upload of 3 bytes fits. A chunk gets the answer of its own continuation.
    let created = send_json(
        &env,
        "POST",
        "/api/uploads",
        r#"{"instance":"rw","key":"other/up.bin","size":3}"#,
    )
    .await;
    assert_eq!(created.status, 201, "{}", created.text());
    let token = created.json()["resumeToken"].as_str().unwrap().to_owned();
    let chunk = || {
        TestRequest::new("PUT", "/api/uploads")
            .header("x-identity-token", TOKEN)
            .header("x-stowr-resume-token", &token)
            .header("content-range", "bytes 0-2/3")
            .body("abc")
            .send(&env.app)
    };
    env.fake.set_answer(ceilings(NONE, 2));
    assert_ceiling(&chunk().await, ACTION_WRITE, 2);
    let stored: usize = env.rw.state().multipart.values().map(|upload| upload.parts.len()).sum();
    assert_eq!(stored, 0, "a part was stored");

    env.fake.set_answer(ceilings(NONE, 3));
    let answer = chunk().await;
    assert_eq!(answer.status, 200, "{}", answer.text());
}

#[tokio::test]
async fn an_extraction_job_checks_the_members_against_the_ceilings_before_the_first_write() {
    let env = env();
    env.rw.insert(
        "tenant/folder/a.zip",
        zip_of(&[("a.txt", b"tiny".to_vec()), ("z.txt", vec![b'z'; 40])]),
        "application/zip",
    );
    let body = r#"{"instance":"rw","key":"folder/a.zip","target":"extracted/","entries":["a.txt","z.txt"]}"#;

    env.fake.set_answer(ceilings(NONE, 10));
    let job = ended_job(&env, &send_json(&env, "POST", "/api/archive-extract", body).await).await;
    assert_eq!(job.status, "failed", "{job:?}");
    assert!(job.error.contains(MAX_OBJECT_SIZE), "{}", job.error);
    assert_eq!(
        count_under(&env, "extracted/"),
        0,
        "a member was written before the refusal"
    );

    // The archive is an object that the extraction reads: the read ceiling applies to it.
    env.fake.set_answer(ceilings(10, NONE));
    let job = ended_job(&env, &send_json(&env, "POST", "/api/archive-extract", body).await).await;
    assert_eq!(job.status, "failed", "{job:?}");
    assert!(job.error.contains(MAX_OBJECT_SIZE), "{}", job.error);
    assert_eq!(count_under(&env, "extracted/"), 0);

    env.fake.set_answer(ceilings(1 << 20, 100));
    let job = ended_job(&env, &send_json(&env, "POST", "/api/archive-extract", body).await).await;
    assert_eq!(job.status, "completed", "{job:?}");
    assert_eq!(count_under(&env, "extracted/"), 2);
}

// --- The jobs and the request ------------------------------------------------------------------------------------

#[tokio::test]
async fn an_integrity_job_applies_the_ceiling_of_its_request_without_a_new_question() {
    let env = env();
    seed(&env, "folder/twelve.txt", "hello world!");
    let body = r#"{"instance":"rw","key":"folder/twelve.txt"}"#;
    // The job reads the bytes. The job carries the ceiling of the request: the PDP gets no question for the job.
    env.fake.set_answer(ceilings(10, NONE));
    assert_ceiling(&send_json(&env, "POST", "/api/integrity", body).await, ACTION_READ, 10);
    assert_eq!(env.fake.questions().len(), 1, "{:?}", env.fake.questions());
    // The job of the refusal stays in the manager: it failed with the ceiling of its request.
    let jobs = env.app.jobs.all();
    assert_eq!(jobs.len(), 1, "{jobs:?}");
    let refused = &jobs[0];
    assert_eq!(refused.job_type, job_type::INTEGRITY);
    assert_eq!(refused.status, "failed", "{refused:?}");
    assert!(refused.error.contains("max_object_size"), "{}", refused.error);
    assert_eq!(job_ceiling(refused, ACTION_READ), Some(10));

    env.fake.set_answer(ceilings(20, NONE));
    let answer = send_json(&env, "POST", "/api/integrity", body).await;
    assert!(
        answer.status == 200 || answer.status == 202,
        "{} {}",
        answer.status,
        answer.text()
    );
}

#[tokio::test]
async fn a_job_with_its_own_ceilings_refuses_a_prefix_without_a_question_to_the_pdp() {
    let env = env();
    seed_size(&env, "folder/set/a.txt", 3);
    seed_size(&env, "folder/set/z.txt", 30);
    let own = Ceilings::default();
    own.lower(ACTION_WRITE, MAX_OBJECT_SIZE, 10);
    let job = env
        .app
        .jobs
        .create(JobState {
            job_type: job_type::COPY_PREFIX.to_owned(),
            instance: "rw".to_owned(),
            source: "folder/set/".to_owned(),
            target: "copied/".to_owned(),
            ceilings: Some(Arc::new(own)),
            ..JobState::default()
        })
        .unwrap();
    let failed = env.app.jobs.wait_for_terminal(&job.id, JOB_WAIT).await.unwrap();
    assert_eq!(failed.status, "failed", "{failed:?}");
    assert!(failed.error.contains("action object.write"), "{}", failed.error);
    assert_eq!(count_under(&env, "copied/"), 0);
    assert_eq!(env.fake.requests(), 0);
}

#[tokio::test]
async fn each_authorize_of_a_request_keeps_the_lower_ceiling() {
    let env = crate::access::test_support::Env::new();
    env.fake.set_answer(|question: &FakeQuestion| {
        let size = if question.path.ends_with("folder:b") { 5 } else { 50 };
        json!({"decision": true, "context": {"limits": {"max_object_size": size}}})
    });
    let ctx = env.ctx("rid-lower");
    let read = |relative: &str| Operation {
        use_ask: env.ask(ACTION_READ, relative),
        ..Operation::default()
    };
    env.layer.authorize(&ctx, read("a/x")).await.unwrap();
    assert_eq!(ceiling_of(&ctx, ACTION_READ), Some(50));
    env.layer.authorize(&ctx, read("b/y")).await.unwrap();
    assert_eq!(ceiling_of(&ctx, ACTION_READ), Some(5));
    assert_eq!(ceiling_of(&ctx, ACTION_WRITE), None);
}

#[tokio::test]
async fn the_open_mode_checks_no_ceiling_and_makes_no_head_request() {
    let (app, _, rw) = super::testing::memory_app();
    rw.insert("tenant/folder/big.bin", vec![b'x'; 5000], "application/octet-stream");
    let answer = super::testing::get(&app, "/s3?instance=rw&key=folder%2Fbig.bin").await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert_eq!(answer.body.len(), 5000);
    let answer = TestRequest::new("POST", "/api/copy")
        .header("content-type", "application/json")
        .body(r#"{"instance":"rw","src":"folder/big.bin","dst":"other/big.bin"}"#)
        .send(&app)
        .await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert_eq!(
        rw.state().head_count,
        0,
        "the open mode made a HEAD request for a check"
    );
    assert!(!ceiling_applies(&OpCtx::default(), &[ACTION_READ, ACTION_WRITE]));
}

// --- The ceilings of the action document -------------------------------------------------------------------------

/// The checks of the ceilings, by action and ceiling name.
const CEILING_CHECKS: [&str; 2] = ["object.read/max_object_size", "object.write/max_object_size"];

/// Run the check of one ceiling of the action document.
async fn run_ceiling_check(key: &str) {
    let env = env();
    match key {
        "object.read/max_object_size" => {
            seed(&env, "folder/twelve.txt", "hello world!");
            env.fake.set_answer(ceilings(10, NONE));
            let answer = send(&env, "GET", "/s3?instance=rw&key=folder%2Ftwelve.txt").await;
            assert_eq!(answer.status, 403, "{key}: {}", answer.text());
        }
        "object.write/max_object_size" => {
            env.fake.set_answer(ceilings(NONE, 10));
            let answer = send_body(&env, "PUT", "/s3?instance=rw&key=other%2Fnew.txt", &"y".repeat(20)).await;
            assert_eq!(answer.status, 403, "{key}: {}", answer.text());
            assert!(!has(&env, "other/new.txt"), "{key}");
        }
        other => panic!("no check exists for the ceiling {other}"),
    }
}

#[tokio::test]
async fn each_ceiling_of_the_action_document_has_a_check() {
    let env = env();
    let document = ActionDocument::build(&env.app.config).unwrap();
    let body: Value = serde_json::from_slice(document.json()).unwrap();
    let kinds: BTreeMap<String, String> = body["limits"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|limit| {
            (
                limit["name"].as_str().unwrap_or("").to_owned(),
                limit["kind"].as_str().unwrap_or("").to_owned(),
            )
        })
        .collect();
    let mut listed = Vec::new();
    for action in body["actions"].as_array().cloned().unwrap_or_default() {
        let name = action["name"].as_str().unwrap_or("").to_owned();
        for limit in action["limits"].as_array().cloned().unwrap_or_default() {
            let limit = limit.as_str().unwrap_or("").to_owned();
            if kinds.get(&limit).map(String::as_str) == Some("ceiling") {
                listed.push(format!("{name}/{limit}"));
            }
        }
    }
    assert!(!listed.is_empty(), "the document lists no ceiling");
    for key in &listed {
        assert!(
            CEILING_CHECKS.contains(&key.as_str()),
            "the document lists the ceiling {key} and this file has no check for it"
        );
        run_ceiling_check(key).await;
    }
    // The table has no check for a ceiling that the document does not list.
    for key in CEILING_CHECKS {
        let (action, name) = key.split_once('/').unwrap();
        assert!(
            document.lists_ceiling(action, name),
            "the table has the check {key} and the document does not list it"
        );
    }
}

// --- The display questions of a listing --------------------------------------------------------------------------

#[tokio::test]
async fn a_readable_folder_gives_the_access_member_and_the_whole_listing() {
    let env = env();
    env.fake
        .set_answer(|question: &FakeQuestion| json!({"decision": question.action != ACTION_DELETE}));
    let answer = send(&env, "GET", "/api/list?instance=rw&prefix=folder%2F").await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    let body = answer.json();
    assert_eq!(body["access"], json!({"read": true, "write": true, "delete": false}));
    let items: Vec<String> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| {
            format!(
                "{}:{}",
                item["type"].as_str().unwrap_or(""),
                item["name"].as_str().unwrap_or("")
            )
        })
        .collect();
    assert_eq!(items, vec!["prefix:nested/", "content:direct.txt"]);
    // The three display questions go in three requests, one after the other (docs/ACCESS.md).
    let questions = env.fake.questions();
    assert_eq!(questions.len(), 3, "{questions:?}");
    assert_eq!(env.fake.requests(), 3);
    for (question, action) in questions.iter().zip([ACTION_READ, ACTION_WRITE, ACTION_DELETE]) {
        assert_eq!(question.action, action, "{question:?}");
        assert_eq!(question.path, FOLDER, "{question:?}");
        assert_eq!(question.match_mode, "node", "{question:?}");
        assert!(!question.usage, "{question:?}");
    }
}

#[tokio::test]
async fn a_navigation_listing_shows_the_readable_folders_and_answers_head() {
    let env = env();
    seed(&env, "root.txt", "root");
    env.fake.set_answer(|question: &FakeQuestion| {
        let decision = match (question.action.as_str(), question.match_mode.as_str()) {
            (ACTION_READ, "subtree") => question.path == FOLDER,
            (ACTION_WRITE, "node") => true,
            _ => false,
        };
        json!({"decision": decision})
    });
    let answer = send(&env, "GET", "/api/list?instance=rw").await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    let body = answer.json();
    let items = body["items"].as_array().unwrap();
    assert_eq!(items.len(), 1, "{}", answer.text());
    assert_eq!(items[0]["type"], "prefix");
    assert_eq!(items[0]["prefix"], "folder/");
    assert_eq!(body["access"], json!({"read": false, "write": true, "delete": false}));
    // Three questions on the node of the bucket, then one subtree question for each folder item.
    let questions = env.fake.questions();
    assert_eq!(questions.len(), 5, "{questions:?}");
    for question in &questions[..3] {
        assert_eq!(question.path, BUCKET, "{question:?}");
        assert_eq!(question.match_mode, "node", "{question:?}");
    }
    let mut subtree: Vec<String> = questions[3..]
        .iter()
        .map(|question| {
            assert_eq!(question.action, ACTION_READ, "{question:?}");
            assert_eq!(question.match_mode, "subtree", "{question:?}");
            assert!(!question.usage, "{question:?}");
            question.path.clone()
        })
        .collect();
    subtree.sort();
    assert_eq!(subtree, vec![format!("{BUCKET}/folder:a"), FOLDER.to_owned()]);
    // Three requests for the questions of the node, then one batch for the folder items.
    assert_eq!(env.fake.requests(), 4);

    // HEAD gives the same status.
    let answer = send(&env, "HEAD", "/api/list?instance=rw").await;
    assert_eq!(answer.status, 200);
}

// --- The options route over a volume -----------------------------------------------------------------------------

#[tokio::test]
async fn the_options_of_a_volume_continue_after_the_cursor() {
    let folder = TestFolder::new();
    let root = folder.path.join("volume");
    let outside = folder.path.join("outside");
    write_file(&outside, "secret.txt", "secret");
    write_file(&root, "a-b/x.txt", "x");
    write_file(&root, "a/b.txt", "0123456789");
    write_file(&root, "a0", "zero");
    write_file(&root, ".hidden", "hidden");
    write_file(&root, ".stowr-tmp-0123456789abcdef0123456789abcdef-upload.bin", "part");
    std::fs::create_dir_all(root.join("empty")).unwrap();
    std::os::unix::fs::symlink("a", root.join("link-in")).unwrap();
    std::os::unix::fs::symlink("a0", root.join("link-file")).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("link-out")).unwrap();
    std::os::unix::fs::symlink("missing", root.join("link-dangling")).unwrap();
    let (cfg, volume) = volume_instance(&root);
    let env = env_with(vec![volume], vec![cfg]);

    let mut ids = Vec::new();
    let mut cursor: Option<String> = None;
    for _ in 0..10 {
        let mut target = "/.well-known/procurauth/resources?type=folder&parent=bucket%3Avol&limit=1".to_owned();
        if let Some(cursor) = &cursor {
            target.push_str(&format!("&after={cursor}"));
        }
        let answer = send(&env, "GET", &target).await;
        assert_eq!(answer.status, 200, "{target}: {}", answer.text());
        let body = answer.json();
        for item in body["items"].as_array().unwrap() {
            ids.push(item["id"].as_str().unwrap().to_owned());
        }
        match body["next"].as_str() {
            Some(next) => cursor = Some(next.to_owned()),
            None => break,
        }
    }
    assert_eq!(ids, vec!["a-b", "a", "empty", "link-in"]);
}
