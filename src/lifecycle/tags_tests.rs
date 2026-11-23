//! The tests of the object tags.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use http::HeaderMap;
use serde_json::json;

use super::fakes::{
    FakeS3, TagMode, TaggingMemory, WireBackend, application, call, instance, instance_config, with_versions,
};
use super::tags::{tag_job, walk_tag_job};
use super::{MAX_OBJECT_TAGS, Tag, TagChange, apply_tag_change, encode_tagging, parse_tagging_header, same_tags};
use super::{upload_tagging_header, validate_tags, with_upload_tags};
use crate::common::config::{PERMISSION_READ, PERMISSION_WRITE};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::storage::Backend;
use crate::instance::Instance;
use crate::jobs::JobState;
use crate::jobs::WalkHost;

fn tag(key: &str, value: &str) -> Tag {
    Tag::new(key, value)
}

#[test]
fn validate_tags_accepts_and_refuses_the_cases_of_s3() {
    let long_key = "k".repeat(129);
    let many: Vec<Tag> = (0..=MAX_OBJECT_TAGS)
        .map(|index| tag(&format!("k{index}"), "v"))
        .collect();
    let cases: Vec<(&str, Vec<Tag>, bool)> = vec![
        ("none", vec![], true),
        ("simple", vec![tag("team", "data"), tag("retention", "30d")], true),
        ("allowed symbols", vec![tag("a+b-c=d.e_f:g/h@i", "x y")], true),
        ("empty value", vec![tag("flag", "")], true),
        ("unicode", vec![tag("équipe", "données")], true),
        ("empty key", vec![tag("", "v")], false),
        ("long key", vec![tag(&long_key, "v")], false),
        ("long value", vec![tag("k", &"v".repeat(257))], false),
        ("aws prefix", vec![tag("aws:cloudformation", "v")], false),
        ("AWS prefix", vec![tag("AWS:x", "v")], false),
        ("bad character", vec![tag("k", "a&b")], false),
        ("bad key char", vec![tag("k?", "v")], false),
        ("duplicate key", vec![tag("k", "1"), tag("k", "2")], false),
        ("eleven tags", many.clone(), false),
        ("ten tags", many[..MAX_OBJECT_TAGS].to_vec(), true),
        ("digits of other scripts", vec![tag("k", "\u{0663}\u{0e53}")], true),
        ("superscript digit", vec![tag("k", "\u{00b2}")], false),
    ];
    for (name, tags, ok) in cases {
        let result = validate_tags(&tags);
        assert_eq!(result.is_ok(), ok, "{name}: {result:?}");
        if let Err(error) = result {
            assert_eq!(error.status(), 400, "{name}");
            assert_eq!(error.code(), "invalid_tags", "{name}");
        }
    }
}

#[test]
fn the_messages_of_the_tag_checks_name_the_tag() {
    let message = |tags: &[Tag]| validate_tags(tags).unwrap_err().as_api().unwrap().message.clone();
    assert_eq!(
        message(&[tag("aws:x", "1")]),
        "the tag key \"aws:x\" starts with the reserved prefix aws:"
    );
    assert_eq!(
        message(&[tag("k", "1"), tag("k", "2")]),
        "the tag key \"k\" is twice in the request"
    );
    assert_eq!(message(&[tag("", "1")]), "a tag key has 1 to 128 characters, got 0");
}

#[test]
fn a_tag_change_adds_removes_and_sorts_without_changing_its_input() {
    let current = vec![tag("a", "1"), tag("b", "2"), tag("c", "3")];
    let change = TagChange {
        add: vec![tag("b", "20"), tag("d", "4")],
        remove: vec!["a".to_owned(), "missing".to_owned()],
    };
    let got = apply_tag_change(&current, &change);
    assert!(
        same_tags(&got, &[tag("b", "20"), tag("c", "3"), tag("d", "4")]),
        "tags = {got:?}"
    );
    assert_eq!(current.len(), 3);
    assert_eq!(current[1].value, "2");
    // A key that is removed and added in one change stays: the addition wins.
    let both = TagChange {
        add: vec![tag("a", "9")],
        remove: vec!["a".to_owned()],
    };
    assert_eq!(apply_tag_change(&current, &both)[0], tag("a", "9"));
}

fn headers_with(value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("x-amz-tagging", value.parse().unwrap());
    headers
}

#[test]
fn the_header_x_amz_tagging_gives_sorted_valid_tags() {
    let tags = parse_tagging_header(&headers_with("team=data&retention=30d")).unwrap();
    assert!(
        same_tags(&tags, &[tag("retention", "30d"), tag("team", "data")]),
        "tags = {tags:?}"
    );
    assert!(parse_tagging_header(&HeaderMap::new()).unwrap().is_empty());
    assert!(parse_tagging_header(&headers_with("aws:x=1")).is_err());
    let error = parse_tagging_header(&headers_with("%zz=1")).unwrap_err();
    assert_eq!(error.code(), "invalid_tags");
    assert_eq!(
        error.as_api().unwrap().message,
        "X-Amz-Tagging must be a query string such as a=b&c=d"
    );
    assert!(parse_tagging_header(&headers_with("a=1;b=2")).is_err());
    // The values of one key join in order.
    let joined = parse_tagging_header(&headers_with("a=x&a=y")).unwrap();
    assert_eq!(joined, vec![tag("a", "xy")]);
}

#[test]
fn the_tags_of_an_upload_travel_in_the_context_as_a_sorted_query() {
    let ctx = OpCtx::default();
    assert!(upload_tagging_header(&ctx).is_none());
    assert!(upload_tagging_header(&with_upload_tags(&ctx, &[])).is_none());
    let tagged = with_upload_tags(&ctx, &[tag("b", "2"), tag("a", "1")]);
    assert_eq!(upload_tagging_header(&tagged).as_deref(), Some("a=1&b=2"));
    assert_eq!(encode_tagging(&[tag("k y", "a&b")]), "k+y=a%26b");
    assert_eq!(encode_tagging(&[tag("k", "1"), tag("k", "2")]), "k=2");
}

// --- The routes ----------------------------------------------------------------------------------------------------

struct Rig {
    app: Arc<crate::common::app::App>,
    backend: Arc<TaggingMemory>,
}

fn rig_with(configure: impl FnOnce(&mut TaggingMemory)) -> Rig {
    let mut backend = TaggingMemory::new(&[("tenant/folder/direct.txt", "x"), ("readonly.txt", "x")]);
    configure(&mut backend);
    let backend = Arc::new(backend);
    let rw = instance(instance_config("rw", "tenant/", None), backend.clone());
    let readonly = instance(
        instance_config("readonly", "", Some(&[PERMISSION_READ])),
        backend.clone(),
    );
    Rig {
        app: application(vec![rw, readonly]),
        backend,
    }
}

fn rig() -> Rig {
    rig_with(|_| {})
}

#[tokio::test]
async fn the_tags_route_reads_and_replaces_the_tags_of_an_object() {
    let rig = rig();
    rig.backend.set_tags("tenant/folder/direct.txt", &[tag("team", "data")]);
    let got = call(&rig.app, "GET", "/api/tags?instance=rw&key=folder/direct.txt", None).await;
    assert_eq!(got.status, 200, "{}", got.text);
    let body = got.json();
    assert_eq!(body["maxTags"], 10);
    assert_eq!(body["instance"], "rw");
    assert_eq!(body["key"], "folder/direct.txt");
    assert_eq!(body["tags"], json!([{"key": "team", "value": "data"}]));
    assert!(body.get("version").is_none());

    let put = call(
        &rig.app,
        "PUT",
        "/api/tags",
        Some(json!({"instance": "rw", "key": "folder/direct.txt", "tags": [{"key": "z", "value": "1"}, {"key": "a", "value": "2"}]})),
    )
    .await;
    assert_eq!(put.status, 200, "{}", put.text);
    assert_eq!(
        rig.backend.tags_of("tenant/folder/direct.txt"),
        vec![tag("a", "2"), tag("z", "1")]
    );
    // An empty list removes the tags.
    let clear = call(
        &rig.app,
        "PUT",
        "/api/tags",
        Some(json!({"instance": "rw", "key": "folder/direct.txt", "tags": []})),
    )
    .await;
    assert_eq!(clear.status, 200, "{}", clear.text);
    assert!(rig.backend.tags_of("tenant/folder/direct.txt").is_empty());
}

#[tokio::test]
async fn the_tags_route_refuses_what_s3_refuses() {
    let rig = rig();
    let cases = [
        (
            "reserved prefix",
            json!({"instance": "rw", "key": "folder/direct.txt", "tags": [{"key": "aws:x", "value": "1"}]}),
        ),
        (
            "bad character",
            json!({"instance": "rw", "key": "folder/direct.txt", "tags": [{"key": "k", "value": "a&b"}]}),
        ),
        (
            "no key",
            json!({"instance": "rw", "key": "", "tags": [{"key": "k", "value": "v"}]}),
        ),
    ];
    for (name, body) in cases {
        let got = call(&rig.app, "PUT", "/api/tags", Some(body)).await;
        assert_eq!(got.status, 400, "{name}: {}", got.text);
    }
    assert_eq!(
        rig.backend.puts.load(Ordering::SeqCst),
        0,
        "a refused request reached the provider"
    );
    let missing = call(&rig.app, "GET", "/api/tags?instance=rw&key=missing.txt", None).await;
    assert_eq!(missing.status, 404, "{}", missing.text);
    // The instance "readonly" has no write permission.
    let denied = call(
        &rig.app,
        "PUT",
        "/api/tags",
        Some(json!({"instance": "readonly", "key": "readonly.txt", "tags": [{"key": "k", "value": "v"}]})),
    )
    .await;
    assert_eq!(denied.status, 403, "{}", denied.text);
    assert_eq!(call(&rig.app, "DELETE", "/api/tags", None).await.status, 405);
    let unknown = call(
        &rig.app,
        "PUT",
        "/api/tags",
        Some(json!({"instance": "rw", "key": "k", "other": 1})),
    )
    .await;
    assert_eq!(unknown.status, 400);
    assert_eq!(unknown.code(), "invalid_json");
    let no_key = call(&rig.app, "GET", "/api/tags?instance=rw", None).await;
    assert_eq!(no_key.code(), "invalid_key");
    let no_instance = call(&rig.app, "GET", "/api/tags?instance=nope&key=a", None).await;
    assert_eq!(no_instance.status, 404);
}

#[tokio::test]
async fn a_provider_without_tags_answers_501_for_tags_and_lifecycle() {
    let wire = FakeS3::new("", "");
    let mut backend = WireBackend::new(wire);
    backend.tags = false;
    backend.rules = false;
    let app = application(vec![instance(
        instance_config("rw", "tenant/", None),
        Arc::new(backend),
    )]);
    let got = call(&app, "GET", "/api/tags?instance=rw&key=folder/direct.txt", None).await;
    assert_eq!(got.status, 501, "{}", got.text);
    assert_eq!(got.code(), "tagging_unsupported");
    let put = call(
        &app,
        "PUT",
        "/api/tags",
        Some(json!({"instance": "rw", "key": "folder/direct.txt", "tags": [{"key": "k", "value": "v"}]})),
    )
    .await;
    assert_eq!(put.status, 501, "{}", put.text);
    let lifecycle = call(&app, "GET", "/api/lifecycle?instance=rw", None).await;
    assert_eq!(lifecycle.status, 501, "{}", lifecycle.text);
    assert_eq!(lifecycle.code(), "lifecycle_unsupported");
}

#[tokio::test]
async fn a_501_of_the_provider_becomes_tagging_unsupported() {
    let rig = rig_with(|backend| backend.mode = TagMode::NotImplemented);
    let got = call(&rig.app, "GET", "/api/tags?instance=rw&key=folder/direct.txt", None).await;
    assert_eq!(got.status, 501, "{}", got.text);
    assert_eq!(got.code(), "tagging_unsupported");
}

#[tokio::test]
async fn the_bulk_request_is_validated_before_a_job_starts() {
    let rig = rig();
    let cases = [
        ("no change", json!({"instance": "rw", "prefix": "data/"}), 400),
        (
            "bad tag",
            json!({"instance": "rw", "prefix": "data/", "add": [{"key": "aws:x", "value": "1"}]}),
            400,
        ),
        (
            "empty remove",
            json!({"instance": "rw", "prefix": "data/", "remove": [""]}),
            400,
        ),
        (
            "read only",
            json!({"instance": "readonly", "prefix": "data/", "add": [{"key": "k", "value": "v"}]}),
            403,
        ),
    ];
    for (name, body, status) in cases {
        let got = call(&rig.app, "POST", "/api/tags/bulk", Some(body)).await;
        assert_eq!(got.status, status, "{name}: {}", got.text);
    }
    assert_eq!(call(&rig.app, "GET", "/api/tags/bulk", None).await.status, 405);
}

#[tokio::test]
async fn the_bulk_request_gives_a_job_with_a_normal_prefix() {
    let rig = rig();
    let rw = rig.app.instance("rw").unwrap().clone();
    let request =
        json!({"instance": "rw", "prefix": "/data", "add": [{"key": "team", "value": "data"}], "remove": ["old"]});
    let parsed: super::routes::TagsBulkRequest = serde_json::from_value(request).unwrap();
    let (prefix, change) = super::routes::bulk_change(&rw, &parsed).unwrap();
    assert_eq!(prefix, "data/");
    let job = tag_job("rw", &prefix, change.clone());
    assert_eq!(job.job_type, "tag_prefix");
    assert_eq!(job.prefix, "data/");
    assert_eq!(job.tag_change, Some(change));
}

// --- The job -------------------------------------------------------------------------------------------------------

/// A job manager of a test: it keeps the saved states and can pause the job after some saves.
#[derive(Default)]
struct TestHost {
    ctx: OpCtx,
    saved: std::sync::Mutex<Vec<JobState>>,
    pause_after: Option<usize>,
}

impl WalkHost for TestHost {
    fn ctx(&self) -> &OpCtx {
        &self.ctx
    }

    fn check_control(&self) -> Result<()> {
        Ok(())
    }

    fn refresh_status(&self, job: &mut JobState) {
        let saved = self.saved.lock().unwrap();
        let status = match self.pause_after {
            Some(count) if saved.len() >= count => "paused",
            _ => "running",
        };
        job.status = status.to_owned();
        job.ended_at = None;
    }

    fn save(&self, job: &JobState) -> Result<()> {
        self.saved.lock().unwrap().push(job.clone());
        Ok(())
    }
}

fn running_job(prefix: &str, change: TagChange) -> JobState {
    JobState {
        status: "running".to_owned(),
        ..tag_job("rw", prefix, change)
    }
}

async fn run_job(rig: &Rig, host: &TestHost, job: &mut JobState) -> Result<()> {
    let rw: Arc<Instance> = rig.app.instance("rw").unwrap().clone();
    walk_tag_job(host, &rw, job).await
}

#[tokio::test]
async fn the_tag_job_changes_the_tags_under_a_prefix_and_skips_objects_that_already_match() {
    let rig = rig_with(|backend| {
        for index in 0..5 {
            backend
                .memory
                .objects
                .lock()
                .unwrap()
                .insert(format!("tenant/data/f{index}.txt"), Default::default());
        }
        backend
            .memory
            .objects
            .lock()
            .unwrap()
            .insert("tenant/other/keep.txt".to_owned(), Default::default());
    });
    rig.backend
        .set_tags("tenant/data/f0.txt", &[tag("old", "1"), tag("team", "data")]);
    rig.backend.set_tags("tenant/data/f1.txt", &[tag("team", "data")]);
    let change = TagChange {
        add: vec![tag("team", "data")],
        remove: vec!["old".to_owned()],
    };
    let host = TestHost::default();
    let mut job = running_job("data/", change);
    run_job(&rig, &host, &mut job).await.unwrap();
    assert_eq!(job.processed, 5);
    assert_eq!(job.last_key, "data/f4.txt");
    for index in 0..5 {
        let key = format!("tenant/data/f{index}.txt");
        assert_eq!(rig.backend.tags_of(&key), vec![tag("team", "data")], "{key}");
    }
    assert!(
        rig.backend.tags_of("tenant/other/keep.txt").is_empty(),
        "an object outside the prefix changed"
    );
    // f1 already had the result: 5 objects, 1 without change, 4 writes.
    assert_eq!(rig.backend.puts.load(Ordering::SeqCst), 4);
    assert_eq!(host.saved.lock().unwrap().len(), 5, "one save for each object");
}

#[tokio::test]
async fn the_tag_job_fails_when_an_object_would_have_more_than_ten_tags() {
    let rig = rig_with(|backend| {
        backend
            .memory
            .objects
            .lock()
            .unwrap()
            .insert("tenant/full/f.txt".to_owned(), Default::default());
    });
    let full: Vec<Tag> = (0..MAX_OBJECT_TAGS)
        .map(|index| tag(&format!("k{index}"), "v"))
        .collect();
    rig.backend.set_tags("tenant/full/f.txt", &full);
    let mut job = running_job(
        "full/",
        TagChange {
            add: vec![tag("extra", "1")],
            remove: vec![],
        },
    );
    let error = run_job(&rig, &TestHost::default(), &mut job).await.unwrap_err();
    let message = error.as_api().unwrap().message.clone();
    assert!(message.contains("full/f.txt"), "message = {message}");
    assert!(message.contains("at most 10 tags"), "message = {message}");
    assert_eq!(error.code(), "invalid_tags");
}

#[tokio::test]
async fn the_tag_job_without_objects_fails_with_an_empty_prefix_and_stops_when_paused() {
    let rig = rig_with(|backend| {
        for index in 0..3 {
            backend
                .memory
                .objects
                .lock()
                .unwrap()
                .insert(format!("tenant/p/f{index}.txt"), Default::default());
        }
    });
    let change = TagChange {
        add: vec![tag("k", "1")],
        remove: vec![],
    };
    let mut empty = running_job("nothing/", change.clone());
    let error = run_job(&rig, &TestHost::default(), &mut empty).await.unwrap_err();
    assert_eq!(error.code(), "empty_prefix");
    assert_eq!(error.status(), 404);
    // A pause after the second object stops the job with the key of the last finished object.
    let host = TestHost {
        pause_after: Some(1),
        ..TestHost::default()
    };
    let mut job = running_job("p/", change.clone());
    let error = run_job(&rig, &host, &mut job).await.unwrap_err();
    assert!(
        matches!(error, Error::Interrupted(crate::common::error::Interrupt::Paused)),
        "{error:?}"
    );
    assert_eq!(job.processed, 2);
    // A resumed job goes on after the last key and never writes twice.
    let mut resumed = running_job("p/", change);
    resumed.last_key = job.last_key.clone();
    resumed.processed = job.processed;
    run_job(&rig, &TestHost::default(), &mut resumed).await.unwrap();
    assert_eq!(resumed.processed, 3);
    assert_eq!(rig.backend.puts.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn the_tag_job_needs_a_change_and_the_read_and_write_permissions() {
    let rig = rig();
    let mut without = running_job("data/", TagChange::default());
    without.tag_change = None;
    let error = run_job(&rig, &TestHost::default(), &mut without).await.unwrap_err();
    assert_eq!(error.code(), "invalid_tags");
    let readonly: Arc<Instance> = rig.app.instance("readonly").unwrap().clone();
    let mut job = running_job("", TagChange::default());
    let error = walk_tag_job(&TestHost::default(), &readonly, &mut job)
        .await
        .unwrap_err();
    assert_eq!(error.code(), "permission_denied");
    assert!(readonly.require_permission(PERMISSION_WRITE).is_err());
}

// --- The versions ------------------------------------------------------------------------------------------------

#[tokio::test]
async fn tag_requests_name_the_version_of_the_object_in_a_bucket_with_versioning() {
    let rig = rig_with(|backend| backend.version_id = Some("null".to_owned()));
    with_versions(rig.app.instance("rw").unwrap());
    let got = call(&rig.app, "GET", "/api/tags?instance=rw&key=folder/direct.txt", None).await;
    assert_eq!(got.status, 200, "{}", got.text);
    let put = call(
        &rig.app,
        "PUT",
        "/api/tags",
        Some(json!({"instance": "rw", "key": "folder/direct.txt", "tags": [{"key": "a", "value": "1"}]})),
    )
    .await;
    assert_eq!(put.status, 200, "{}", put.text);
    assert_eq!(*rig.backend.seen.lock().unwrap(), vec!["get:null", "put:null"]);
    assert_eq!(rig.backend.heads.load(Ordering::SeqCst), 2);
    // A version that the request names is used as it is, with no HEAD request.
    rig.backend.seen.lock().unwrap().clear();
    rig.backend.heads.store(0, Ordering::SeqCst);
    let named = call(
        &rig.app,
        "GET",
        "/api/tags?instance=rw&key=folder/direct.txt&version=abc",
        None,
    )
    .await;
    assert_eq!(named.status, 200, "{}", named.text);
    assert_eq!(named.json()["version"], "abc");
    assert_eq!(*rig.backend.seen.lock().unwrap(), vec!["get:abc"]);
    assert_eq!(rig.backend.heads.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn tag_requests_ask_no_version_in_a_bucket_without_versioning() {
    let rig = rig_with(|backend| backend.version_id = Some("ignored".to_owned()));
    let got = call(&rig.app, "GET", "/api/tags?instance=rw&key=folder/direct.txt", None).await;
    assert_eq!(got.status, 200, "{}", got.text);
    assert_eq!(*rig.backend.seen.lock().unwrap(), vec!["get:"]);
    assert_eq!(rig.backend.heads.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn the_tag_job_reads_the_version_of_each_object_once() {
    let rig = rig_with(|backend| {
        backend.version_id = Some("v1".to_owned());
        for index in 0..3 {
            backend
                .memory
                .objects
                .lock()
                .unwrap()
                .insert(format!("tenant/v/f{index}.txt"), Default::default());
        }
    });
    with_versions(rig.app.instance("rw").unwrap());
    let mut job = running_job(
        "v/",
        TagChange {
            add: vec![tag("k", "1")],
            remove: vec![],
        },
    );
    run_job(&rig, &TestHost::default(), &mut job).await.unwrap();
    assert_eq!(rig.backend.heads.load(Ordering::SeqCst), 3);
    let seen = rig.backend.seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 6, "requests = {seen:?}");
    assert!(
        seen.iter().all(|request| request.ends_with(":v1")),
        "requests = {seen:?}"
    );
}

// --- The probe -----------------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_probe_marks_an_instance_without_tags_and_refuses_the_tags_of_an_upload() {
    let rig = rig();
    let rw = rig.app.instance("rw").unwrap().clone();
    rw.probe_tags(&OpCtx::default()).await;
    assert!(rw.tags_available(), "a provider that answers no such key keeps tags");
    assert!(rw.require_tags(&[tag("team", "data")]).is_ok());

    let refusing = rig_with(|backend| backend.mode = TagMode::NotImplemented);
    let refusing_rw = refusing.app.instance("rw").unwrap().clone();
    refusing_rw.probe_tags(&OpCtx::default()).await;
    assert!(!refusing_rw.tags_available(), "a provider that answers 501 has no tags");
    let error = refusing_rw.require_tags(&[tag("team", "data")]).unwrap_err();
    assert_eq!(error.status(), 501);
    assert_eq!(error.code(), "tagging_unsupported");
    assert!(error.public_message().contains("object tags"));
    // An upload with no tags still works.
    assert!(refusing_rw.require_tags(&[]).is_ok());
    // The tag functions stop at once, without a request to the provider.
    refusing.backend.seen.lock().unwrap().clear();
    let error = refusing_rw
        .get_tags(&OpCtx::default(), "tenant/folder/direct.txt", "")
        .await
        .unwrap_err();
    assert_eq!(error.code(), "tagging_unsupported");
    assert!(refusing.backend.seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn the_probe_keeps_the_tags_when_it_is_denied() {
    let rig = rig_with(|backend| backend.mode = TagMode::Denied);
    let rw = rig.app.instance("rw").unwrap().clone();
    rw.probe_tags(&OpCtx::default()).await;
    assert!(
        rw.tags_available(),
        "a denied probe does not prove that tags are missing"
    );
}

#[tokio::test]
async fn a_back_end_without_tag_functions_has_no_tags() {
    let plain = instance(
        instance_config("plain", "", None),
        Arc::new(crate::testkit::MemoryBackend::default()),
    );
    plain.probe_tags(&OpCtx::default()).await;
    assert!(!plain.tags_available());
    assert_eq!(
        plain.require_tags(&[tag("a", "1")]).unwrap_err().code(),
        "tagging_unsupported"
    );
}

#[tokio::test]
async fn a_provider_denial_of_a_tag_read_is_kept_in_the_permissions() {
    let rig = rig_with(|backend| backend.mode = TagMode::Denied);
    let rw = rig.app.instance("rw").unwrap().clone();
    let error = rw
        .get_tags(&OpCtx::default(), "tenant/folder/direct.txt", "")
        .await
        .unwrap_err();
    assert_eq!(error.status(), 403);
    let capability = rw.capability(PERMISSION_READ);
    assert!(!capability.allowed);
    assert_eq!(capability.source, "provider");
    assert!(capability.expires.is_some());
}

// --- The S3 requests -----------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_s3_requests_read_and_write_the_tags_with_the_version_and_a_checksum() {
    let wire = FakeS3::new("", "");
    wire.with(|state| {
        state
            .tags
            .insert("k".to_owned(), vec![tag("team", "data"), tag("a", "1")]);
    });
    let backend = WireBackend::new(wire.clone());
    let ctx = OpCtx::default();
    let tagger = backend.tagger().unwrap();
    let tags = tagger.get_tags(&ctx, "k", "v1").await.unwrap();
    assert_eq!(tags, vec![tag("a", "1"), tag("team", "data")], "the tags are sorted");
    tagger.put_tags(&ctx, "k", "v1", &[tag("a", "x&y")]).await.unwrap();
    let (query, body) = wire.with(|state| state.tag_puts[0].clone());
    assert!(body.contains("<Key>a</Key><Value>x&amp;y</Value>"), "body = {body}");
    assert!(query.contains("versionId=v1"), "query = {query}");
    assert!(body.starts_with("<Tagging><TagSet><Tag>"), "body = {body}");
    tagger.put_tags(&ctx, "k", "", &[]).await.unwrap();
    assert_eq!(wire.with(|state| state.tag_deletes.clone()), vec!["k"]);
    assert!(wire.with(|state| state.problems.clone()).is_empty());
}

#[test]
fn an_answer_of_tags_that_is_not_xml_is_a_fault() {
    assert!(super::s3::parse_tagging(b"").is_err());
    assert!(super::s3::parse_tagging(b"<Tagging><TagSet>").is_err());
    let none = super::s3::parse_tagging(b"<Tagging><TagSet/></Tagging>").unwrap();
    assert!(none.is_empty());
}

#[test]
fn the_tagger_accessor_of_a_test_back_end_follows_its_flag() {
    let mut backend = WireBackend::new(FakeS3::new("", ""));
    assert!(backend.tagger().is_some());
    backend.tags = false;
    assert!(backend.tagger().is_none());
}
