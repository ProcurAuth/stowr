//! The tests of the incomplete multipart uploads: the paging of three providers, the list with the dates and the parts,
//! the abort of chosen uploads, the abort job, the probe and the S3 documents.

use std::sync::Arc;

use base64::Engine as _;
use http::Method;
use serde_json::{Value, json};

use super::multiparts::{
    MAXIMUM_ABORT_DAYS, MAXIMUM_ABORT_ITEMS, PARTS_PAGE_SIZE, abort_job_request, abort_selected_multiparts,
    decode_multipart_cursor, encode_multipart_cursor, multipart_unsupported, run_abort_multiparts,
};
use super::s3_list::{list_parts_query, list_uploads_query, parse_list_parts, parse_list_uploads};
use super::session::{STATUS_UPLOADING, UploadSession};
use super::test_fakes::{
    FakeLister, FakeTarget, FakeUpload, ListBackend, ListStyle, Recorder, call, request, test_app, test_instance,
};
use super::{
    ACTIVE_UPLOAD_REASON, MultipartAbortItem, MultipartAbortResult, MultipartCursor, UploadManager,
    handle_multipart_abort, handle_multiparts,
};
use crate::common::config::PERMISSION_WRITE;
use crate::common::ctx::OpCtx;
use crate::common::error::Error;
use crate::common::time::Timestamp;
use crate::jobs::{JobState, job_type};

fn hours_ago(hours: i64) -> Option<Timestamp> {
    Some(Timestamp::now().plus_secs(-hours * 3600))
}

fn days_ago(days: i64) -> Option<Timestamp> {
    hours_ago(days * 24)
}

/// Three uploads of one key, uploads of other keys, and uploads outside the root prefix `tenant/`.
fn same_key_uploads(initiated: Option<Timestamp>) -> Vec<FakeUpload> {
    [
        ("tenant/a.bin", "id-3"),
        ("tenant/a.bin", "id-1"),
        ("tenant/a.bin", "id-2"),
        ("tenant/logs/b.log", "id-0"),
        ("tenant/logs/c.log", "id-9"),
        ("other/x.bin", "id-4"),
        ("tenantx/y.bin", "id-5"),
    ]
    .into_iter()
    .map(|(key, id)| FakeUpload::new(key, id, initiated))
    .collect()
}

async fn get_list(app: &Arc<crate::common::app::App>, query: &str) -> (u16, Value) {
    let (status, _, body) = call(
        handle_multiparts,
        app,
        request(Method::GET, &format!("/api/multiparts?{query}"), "", &[]),
    )
    .await;
    (status, serde_json::from_str(&body).unwrap_or(Value::String(body)))
}

/// Read every answer of the list from the first token to the end.
async fn walk(app: &Arc<crate::common::app::App>, prefix: &str, size: usize) -> Vec<String> {
    let mut names = Vec::new();
    let mut token = String::new();
    for answers in 0.. {
        assert!(answers <= 50, "the list does not end");
        let (status, body) = get_list(app, &format!("instance=rw&prefix={prefix}&max={size}&token={token}")).await;
        assert_eq!(status, 200, "{body}");
        for upload in body["uploads"].as_array().unwrap() {
            names.push(format!(
                "{}#{}",
                upload["key"].as_str().unwrap(),
                upload["uploadId"].as_str().unwrap()
            ));
        }
        token = body["nextToken"].as_str().unwrap_or("").to_owned();
        if token.is_empty() {
            break;
        }
    }
    names.sort();
    names
}

#[tokio::test]
async fn the_list_follows_the_markers_of_each_provider() {
    let want = [
        "a.bin#id-1",
        "a.bin#id-2",
        "a.bin#id-3",
        "logs/b.log#id-0",
        "logs/c.log#id-9",
    ];
    for style in [ListStyle::Aws, ListStyle::SeaweedFs, ListStyle::MinIo] {
        for size in [1, 2, 3, 100] {
            let lister = Arc::new(FakeLister::with_uploads(style, same_key_uploads(days_ago(2))));
            let app = test_app(Some(lister));
            assert_eq!(walk(&app, "", size).await, want, "{style:?}/{size}");
            // The prefix of the request is a filter of Stowr: the provider gets no prefix.
            assert_eq!(
                walk(&app, "logs/", size).await,
                ["logs/b.log#id-0", "logs/c.log#id-9"],
                "{style:?}/{size} under logs/"
            );
        }
    }
}

#[tokio::test]
async fn the_list_gives_the_date_and_the_first_page_of_the_parts() {
    let initiated = Timestamp::parse_rfc3339("2026-10-01T08:30:00Z");
    let lister = Arc::new(FakeLister::with_uploads(
        ListStyle::Aws,
        vec![
            FakeUpload::new("tenant/few.bin", "u1", initiated).with_parts(vec![5 << 20, 1000]),
            FakeUpload::new("tenant/many.bin", "u2", initiated).with_parts(vec![10; PARTS_PAGE_SIZE as usize + 5]),
            FakeUpload::new("tenant/none.bin", "u3", None),
            // An upload that a person completes between the list and the parts is left out.
            FakeUpload::new("tenant/gone.bin", "u4", initiated),
        ],
    ));
    lister.set_gone("u4");
    let app = test_app(Some(lister));
    let (status, body) = get_list(&app, "instance=rw").await;
    assert_eq!(status, 200);
    let uploads = body["uploads"].as_array().unwrap();
    assert_eq!(uploads.len(), 3, "{body}");
    assert!(body.get("nextToken").is_none());
    assert_eq!(body["minimumAbortAgeHours"], 24);
    assert_eq!(body["partsPageSize"], PARTS_PAGE_SIZE);
    assert_eq!(body["instance"], "rw");
    assert_eq!(body["prefix"], "");
    assert!(Timestamp::parse_rfc3339(body["now"].as_str().unwrap()).is_some());
    let by_key = |key: &str| uploads.iter().find(|upload| upload["key"] == key).unwrap().clone();
    let few = by_key("few.bin");
    assert_eq!(few["parts"], 2);
    assert_eq!(few["bytes"], (5 << 20) + 1000);
    assert!(few.get("partsAtLeast").is_none());
    assert_eq!(few["initiated"], "2026-10-01T08:30:00Z");
    let many = by_key("many.bin");
    assert_eq!(many["parts"], PARTS_PAGE_SIZE);
    assert_eq!(many["bytes"], 10 * i64::from(PARTS_PAGE_SIZE));
    assert_eq!(many["partsAtLeast"], true);
    let none = by_key("none.bin");
    assert_eq!(none["parts"], 0);
    assert!(none.get("initiated").is_none() && none.get("partsUnknown").is_none());
}

#[tokio::test]
async fn an_upload_with_a_failing_list_of_parts_shows_unknown_parts() {
    let lister = Arc::new(FakeLister::with_uploads(
        ListStyle::Aws,
        vec![FakeUpload::new("tenant/a.bin", "u1", days_ago(2))],
    ));
    let app = test_app(Some(lister.clone()));
    let target = app.instances[1].clone();
    assert!(target.multipart_uploads_available());
    lister.set_failing_parts();
    let (status, body) = get_list(&app, "instance=rw").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["uploads"][0]["partsUnknown"], true);
}

#[tokio::test]
async fn the_list_stops_when_the_provider_does_not_move_its_markers() {
    let lister = Arc::new(FakeLister::with_uploads(
        ListStyle::Aws,
        same_key_uploads(Some(Timestamp::now())),
    ));
    lister.set_stuck();
    let app = test_app(Some(lister));
    // The provider sends the markers of the request again: Stowr stops with an error, not a loop.
    let (status, body) = get_list(&app, "instance=rw&max=1").await;
    assert_eq!(status, 502, "{body}");
    assert_eq!(body["error"]["code"], "provider_paging");
}

#[tokio::test]
async fn the_list_validates_its_parameters() {
    let app = test_app(Some(Arc::new(FakeLister::new(ListStyle::Aws))));
    for query in [
        "instance=rw&max=0",
        "instance=rw&max=501",
        "instance=rw&max=x",
        "instance=rw&token=%21%21",
    ] {
        let (status, body) = get_list(&app, query).await;
        assert_eq!(status, 400, "{query}: {body}");
    }
    let (status, body) = get_list(&app, "instance=rw&max=0").await;
    assert_eq!(status, 400);
    assert_eq!(body["error"]["code"], "invalid_multipart_request");
    assert_eq!(
        body["error"]["message"],
        r#"max must be an integer from 1 to 500, got "0""#
    );
    let (status, body) = get_list(&app, "instance=rw&token=%21%21").await;
    assert_eq!(status, 400);
    assert_eq!(body["error"]["code"], "invalid_page_token");
    let (status, headers, _) = call(
        handle_multiparts,
        &app,
        request(Method::POST, "/api/multiparts?instance=rw", "", &[]),
    )
    .await;
    assert_eq!(status, 405);
    assert_eq!(headers["allow"], "GET");
    let (status, body) = get_list(&app, "instance=unknown").await;
    assert_eq!(status, 404, "{body}");
    assert_eq!(body["error"]["code"], "unknown_instance");
}

#[tokio::test]
async fn the_list_needs_the_read_permission_and_a_provider_with_the_list() {
    let app = test_app(Some(Arc::new(FakeLister::new(ListStyle::Aws))));
    // The instance `readonly` has the read permission and a back end without the list.
    let (status, body) = get_list(&app, "instance=readonly").await;
    assert_eq!(status, 501, "{body}");
    assert_eq!(body["error"]["code"], "multipart_unsupported");
    assert_eq!(
        body["error"]["message"],
        "this storage provider does not let Stowr list the incomplete multipart uploads"
    );
}

#[tokio::test]
async fn the_list_shows_an_upload_that_this_process_sends_as_active() {
    let lister = Arc::new(FakeLister::with_uploads(
        ListStyle::SeaweedFs,
        vec![
            FakeUpload::new("tenant/new.bin", "n1", Some(Timestamp::now())),
            FakeUpload::new("tenant/undated.bin", "d1", None),
            FakeUpload::new("tenant/sent.bin", "s1", None),
        ],
    ));
    let app = test_app(Some(lister));
    // The upload manager of this process sends s1 now.
    app.uploads
        .put(UploadSession {
            id: "upload-1".to_owned(),
            instance: "rw".to_owned(),
            key: "sent.bin".to_owned(),
            provider: "s3".to_owned(),
            status: STATUS_UPLOADING.to_owned(),
            provider_upload_id: "s1".to_owned(),
            ..UploadSession::default()
        })
        .unwrap();
    let (status, body) = get_list(&app, "instance=rw").await;
    assert_eq!(status, 200);
    let uploads = body["uploads"].as_array().unwrap();
    assert_eq!(uploads.len(), 3);
    for upload in uploads {
        assert_eq!(
            upload.get("active").is_some_and(|active| active == true),
            upload["uploadId"] == "s1",
            "{upload}"
        );
    }
}

fn item(key: &str, id: &str) -> MultipartAbortItem {
    MultipartAbortItem {
        key: key.to_owned(),
        upload_id: id.to_owned(),
    }
}

#[tokio::test]
async fn abort_selected_aborts_at_any_age_but_not_an_active_upload() {
    let lister = Arc::new(FakeLister::with_uploads(
        ListStyle::SeaweedFs,
        vec![
            FakeUpload::new("tenant/new.bin", "n1", Some(Timestamp::now())),
            FakeUpload::new("tenant/undated.bin", "d1", None),
            FakeUpload::new("tenant/sent.bin", "s1", None),
        ],
    ));
    let target = FakeTarget::new("rw", "s3", "tenant/").with_lister(lister.clone());
    let manager = UploadManager::new();
    manager
        .put(UploadSession {
            id: "upload-1".to_owned(),
            instance: "rw".to_owned(),
            key: "sent.bin".to_owned(),
            provider: "s3".to_owned(),
            status: STATUS_UPLOADING.to_owned(),
            provider_upload_id: "s1".to_owned(),
            ..UploadSession::default()
        })
        .unwrap();
    let response = abort_selected_multiparts(
        &manager,
        &target,
        &OpCtx::default(),
        &[
            item("new.bin", "n1"),
            item("undated.bin", "d1"),
            item("sent.bin", "s1"),
            item("gone.bin", "g1"),
        ],
    )
    .await;
    // An upload that the provider no longer knows counts as aborted: it is gone.
    assert_eq!(response.aborted.len(), 3);
    assert_eq!(response.skipped.len(), 1);
    assert_eq!(response.skipped[0].upload_id, "s1");
    assert_eq!(response.skipped[0].reason, ACTIVE_UPLOAD_REASON);
    assert!(response.failed.is_empty());
    assert_eq!(lister.aborted().join(" "), "tenant/new.bin#n1 tenant/undated.bin#d1");
    let text = serde_json::to_string(&response).unwrap();
    assert!(
        text.starts_with(r#"{"aborted":[{"key":"new.bin","uploadId":"n1"}"#),
        "{text}"
    );
}

#[tokio::test]
async fn abort_selected_shows_a_refusal_of_the_provider_as_failed() {
    let target = FakeTarget::new("rw", "s3", "tenant/");
    target.fail_abort_with(Error::upstream(403, "AccessDenied", "secret text of the provider"));
    let response =
        abort_selected_multiparts(&UploadManager::new(), &target, &OpCtx::default(), &[item("a", "1")]).await;
    assert!(response.aborted.is_empty() && response.skipped.is_empty());
    assert_eq!(response.failed.len(), 1);
    assert_eq!(
        response.failed[0].reason,
        "the storage provider returned HTTP 403 (AccessDenied)"
    );
}

async fn post_abort(app: &Arc<crate::common::app::App>, body: &Value) -> (u16, Value) {
    let (status, _, text) = call(
        handle_multipart_abort,
        app,
        request(Method::POST, "/api/multiparts/abort", &body.to_string(), &[]),
    )
    .await;
    (status, serde_json::from_str(&text).unwrap_or(Value::String(text)))
}

#[tokio::test]
async fn abort_validates_the_request() {
    let lister = Arc::new(FakeLister::with_uploads(
        ListStyle::Aws,
        vec![FakeUpload::new("tenant/a", "a1", None)],
    ));
    let app = test_app(Some(lister.clone()));
    let too_many: Vec<Value> = (0..=MAXIMUM_ABORT_ITEMS)
        .map(|_| json!({"key": "a", "uploadId": "a1"}))
        .collect();
    let cases = [
        ("nothing", json!({"instance": "rw"})),
        (
            "both forms",
            json!({"instance": "rw", "uploads": [{"key": "a", "uploadId": "a1"}], "olderThanDays": 3}),
        ),
        ("zero days", json!({"instance": "rw", "olderThanDays": 0})),
        ("negative days", json!({"instance": "rw", "olderThanDays": -2})),
        (
            "too many days",
            json!({"instance": "rw", "olderThanDays": MAXIMUM_ABORT_DAYS + 1}),
        ),
        ("no upload id", json!({"instance": "rw", "uploads": [{"key": "a"}]})),
        ("no key", json!({"instance": "rw", "uploads": [{"uploadId": "a1"}]})),
        (
            "prefix with list",
            json!({"instance": "rw", "uploads": [{"key": "a", "uploadId": "a1"}], "prefix": "x/"}),
        ),
        ("too many uploads", json!({"instance": "rw", "uploads": too_many})),
        (
            "unknown field",
            json!({"instance": "rw", "olderThanDays": 3, "force": true}),
        ),
        (
            "control in the upload id",
            json!({"instance": "rw", "uploads": [{"key": "a", "uploadId": "a\n1"}]}),
        ),
        (
            "space around the upload id",
            json!({"instance": "rw", "uploads": [{"key": "a", "uploadId": " a1"}]}),
        ),
        (
            "unknown member of an upload",
            json!({"instance": "rw", "uploads": [{"key": "a", "uploadId": "a1", "x": 1}]}),
        ),
    ];
    for (name, body) in cases {
        let (status, answer) = post_abort(&app, &body).await;
        assert_eq!(status, 400, "{name}: {answer}");
    }
    // The instance `readonly` has no write permission.
    let (status, answer) = post_abort(&app, &json!({"instance": "readonly", "olderThanDays": 3})).await;
    assert_eq!(status, 403, "{answer}");
    assert_eq!(answer["error"]["code"], "permission_denied");
    assert!(lister.aborted().is_empty());
}

#[tokio::test]
async fn abort_gives_the_documented_messages() {
    let app = test_app(Some(Arc::new(FakeLister::new(ListStyle::Aws))));
    let message =
        |status_and_answer: (u16, Value)| status_and_answer.1["error"]["message"].as_str().unwrap().to_owned();
    assert_eq!(
        message(post_abort(&app, &json!({"instance": "rw"})).await),
        "give the uploads to abort, or olderThanDays"
    );
    assert_eq!(
        message(post_abort(&app, &json!({"instance": "rw", "olderThanDays": 36501})).await),
        "olderThanDays must be an integer from 1 to 36500, got 36501"
    );
    assert_eq!(
        message(post_abort(&app, &json!({"instance": "rw", "uploads": [{"key": "a"}]})).await),
        "each upload needs a key and the upload id that the list gave"
    );
    assert_eq!(
        message(
            post_abort(
                &app,
                &json!({"instance": "rw", "uploads": [{"key": "a", "uploadId": "1"}], "olderThanDays": 1})
            )
            .await
        ),
        "give uploads or olderThanDays, not both"
    );
    let (status, _, _) = call(
        handle_multipart_abort,
        &app,
        request(Method::GET, "/api/multiparts/abort", "", &[]),
    )
    .await;
    assert_eq!(status, 405);
}

fn abort_job(days: i64, prefix: &str) -> JobState {
    JobState {
        id: "job_1".to_owned(),
        job_type: job_type::ABORT_MULTIPARTS.to_owned(),
        instance: "rw".to_owned(),
        prefix: prefix.to_owned(),
        multipart_abort: Some(abort_job_request(days, Timestamp::now())),
        multipart_result: Some(MultipartAbortResult::default()),
        ..JobState::default()
    }
}

#[tokio::test]
async fn the_abort_job_aborts_only_the_dated_uploads_older_than_the_age() {
    let lister = Arc::new(FakeLister::with_uploads(
        ListStyle::Aws,
        vec![
            FakeUpload::new("tenant/logs/old.log", "o1", days_ago(10)),
            FakeUpload::new("tenant/logs/old.log", "o2", days_ago(8)),
            FakeUpload::new("tenant/logs/three-days.log", "t1", days_ago(3)),
            FakeUpload::new("tenant/logs/young.log", "y1", hours_ago(2)),
            FakeUpload::new("tenant/logs/undated.log", "u1", None),
            FakeUpload::new("tenant/logs/sent.log", "s1", days_ago(30)),
            FakeUpload::new("tenant/data/old.bin", "x1", days_ago(30)),
            FakeUpload::new("other/logs/old.log", "z1", days_ago(30)),
        ],
    ));
    let target = FakeTarget::new("rw", "s3", "tenant/").with_lister(lister.clone());
    let manager = UploadManager::new();
    manager
        .put(UploadSession {
            id: "upload-1".to_owned(),
            instance: "rw".to_owned(),
            key: "logs/sent.log".to_owned(),
            provider: "s3".to_owned(),
            status: STATUS_UPLOADING.to_owned(),
            provider_upload_id: "s1".to_owned(),
            ..UploadSession::default()
        })
        .unwrap();
    let progress = Recorder::default();
    let mut job = abort_job(5, "logs/");
    run_abort_multiparts(&manager, &target, &OpCtx::default(), &progress, &mut job)
        .await
        .unwrap();
    assert_eq!(
        lister.aborted().join(" "),
        "tenant/logs/old.log#o1 tenant/logs/old.log#o2"
    );
    assert_eq!(
        job.multipart_result,
        Some(MultipartAbortResult {
            aborted: 2,
            skipped_undated: 1,
            skipped_recent: 2,
            skipped_active: 1,
            failed: 0,
        })
    );
    assert_eq!(
        job.multipart_abort.as_ref().map(|request| request.older_than_days),
        Some(5)
    );
    assert_eq!(job.processed, 6);
    assert!(job.last_key.starts_with("logs/old.log"));
    assert_eq!(progress.saves.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn the_abort_job_never_aborts_an_upload_younger_than_a_day() {
    let lister = Arc::new(FakeLister::with_uploads(
        ListStyle::Aws,
        vec![
            FakeUpload::new("tenant/a.bin", "a1", hours_ago(23)),
            FakeUpload::new("tenant/b.bin", "b1", hours_ago(25)),
        ],
    ));
    let target = FakeTarget::new("rw", "s3", "tenant/").with_lister(lister.clone());
    // A job whose cutoff is in the future (a wrong clock, or a bug) still keeps the uploads of the last 24 hours.
    let mut job = abort_job(1, "");
    job.multipart_abort = Some(super::MultipartAbortJob {
        older_than_days: 1,
        cutoff: Some(Timestamp::now().plus_secs(3600)),
    });
    run_abort_multiparts(
        &UploadManager::new(),
        &target,
        &OpCtx::default(),
        &Recorder::default(),
        &mut job,
    )
    .await
    .unwrap();
    assert_eq!(lister.aborted().join(" "), "tenant/b.bin#b1");
    let result = job.multipart_result.unwrap();
    assert_eq!((result.skipped_recent, result.aborted), (1, 1));
}

#[tokio::test]
async fn the_abort_job_on_a_provider_without_dates_aborts_nothing() {
    let lister = Arc::new(FakeLister::with_uploads(
        ListStyle::SeaweedFs,
        same_key_uploads(days_ago(90)),
    ));
    let target = FakeTarget::new("rw", "s3", "tenant/").with_lister(lister.clone());
    let mut job = abort_job(1, "");
    run_abort_multiparts(
        &UploadManager::new(),
        &target,
        &OpCtx::default(),
        &Recorder::default(),
        &mut job,
    )
    .await
    .unwrap();
    assert!(lister.aborted().is_empty());
    let result = job.multipart_result.unwrap();
    assert_eq!((result.skipped_undated, result.aborted), (5, 0));
}

#[tokio::test]
async fn the_abort_job_reads_each_page_of_the_provider_and_saves_after_each_page() {
    let uploads: Vec<FakeUpload> = (0..1500)
        .map(|index| FakeUpload::new(&format!("tenant/k{index:05}"), &format!("id-{index}"), days_ago(3)))
        .collect();
    let lister = Arc::new(FakeLister::with_uploads(ListStyle::Aws, uploads));
    let target = FakeTarget::new("rw", "s3", "tenant/").with_lister(lister.clone());
    let progress = Recorder::default();
    let mut job = abort_job(2, "");
    run_abort_multiparts(&UploadManager::new(), &target, &OpCtx::default(), &progress, &mut job)
        .await
        .unwrap();
    assert_eq!(lister.aborted().len(), 1500);
    assert_eq!(job.processed, 1500);
    assert_eq!(progress.saves.lock().unwrap().clone(), vec![(1000, 1000), (1500, 1500)]);
}

#[tokio::test]
async fn a_job_that_runs_again_counts_the_skipped_uploads_again_from_zero() {
    let lister = Arc::new(FakeLister::with_uploads(
        ListStyle::Aws,
        vec![FakeUpload::new("tenant/a.bin", "a1", None)],
    ));
    let target = FakeTarget::new("rw", "s3", "tenant/").with_lister(lister);
    let mut job = abort_job(1, "");
    for _ in 0..2 {
        run_abort_multiparts(
            &UploadManager::new(),
            &target,
            &OpCtx::default(),
            &Recorder::default(),
            &mut job,
        )
        .await
        .unwrap();
    }
    assert_eq!(job.multipart_result.unwrap().skipped_undated, 1);
    assert_eq!(job.processed, 1);
}

#[tokio::test]
async fn a_job_without_an_age_is_refused() {
    let target = FakeTarget::new("rw", "s3", "tenant/");
    for request in [None, Some(super::MultipartAbortJob::default())] {
        let mut job = abort_job(1, "");
        job.multipart_abort = request;
        let error = run_abort_multiparts(
            &UploadManager::new(),
            &target,
            &OpCtx::default(),
            &Recorder::default(),
            &mut job,
        )
        .await
        .unwrap_err();
        assert_eq!(error.code(), "invalid_multipart_request");
        assert_eq!(error.public_message(), "the job has no age");
    }
}

#[test]
fn the_cutoff_of_a_job_is_the_time_of_the_request_minus_the_age() {
    let now = Timestamp::parse_rfc3339("2026-11-23T12:00:00Z").unwrap();
    let request = abort_job_request(5, now);
    assert_eq!(request.older_than_days, 5);
    assert_eq!(request.cutoff.unwrap().rfc3339(), "2026-11-18T12:00:00Z");
}

#[tokio::test]
async fn the_probe_hides_the_feature_of_a_provider_without_the_list() {
    let lister = Arc::new(FakeLister::new(ListStyle::Aws));
    let app = test_app(Some(lister.clone()));
    let instance = app.instances[1].clone();
    instance.probe_multipart_uploads(&OpCtx::default()).await;
    assert!(
        instance.multipart_uploads_available(),
        "a provider with the list lost it"
    );
    lister.refuse_with(501);
    instance.probe_multipart_uploads(&OpCtx::default()).await;
    assert!(
        !instance.multipart_uploads_available(),
        "a provider that answers 501 keeps the list"
    );
    let (status, body) = get_list(&app, "instance=rw").await;
    assert_eq!(status, 501, "{body}");
    assert_eq!(body["error"]["code"], "multipart_unsupported");
    let (status, answer) = post_abort(&app, &json!({"instance": "rw", "olderThanDays": 2})).await;
    assert_eq!(status, 501, "{answer}");
    assert_eq!(answer["error"]["code"], "multipart_unsupported");
    // A back end without the list, as the GCS back end and the memory back end, shows no list.
    let memory = test_app(None);
    assert!(!memory.instances[1].multipart_uploads_available());
    assert_eq!(multipart_unsupported().status(), 501);
}

#[tokio::test]
async fn a_probe_that_fails_for_another_reason_keeps_the_list() {
    let lister = Arc::new(FakeLister::new(ListStyle::Aws));
    let app = test_app(Some(lister.clone()));
    let instance = app.instances[1].clone();
    lister.refuse_with(403);
    instance.probe_multipart_uploads(&OpCtx::default()).await;
    assert!(instance.multipart_uploads_available());
}

#[tokio::test]
async fn an_instance_without_the_read_permission_is_not_probed() {
    let lister = Arc::new(FakeLister::new(ListStyle::Aws));
    lister.refuse_with(501);
    let instance = test_instance(
        "wo",
        ListBackend {
            lister: Some(lister.clone()),
        },
        "",
        &[PERMISSION_WRITE],
    );
    instance.probe_multipart_uploads(&OpCtx::default()).await;
    assert!(instance.multipart_uploads_available());
}

#[test]
fn the_page_token_holds_the_markers_and_the_position_with_short_names() {
    assert_eq!(encode_multipart_cursor(&MultipartCursor::default()), "");
    let cursor = MultipartCursor {
        key_marker: "dir/a b".to_owned(),
        upload_id_marker: "id<1>".to_owned(),
        skip: 3,
    };
    let token = encode_multipart_cursor(&cursor);
    let text = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&token).unwrap();
    assert_eq!(
        String::from_utf8(text).unwrap(),
        r#"{"k":"dir/a b","u":"id\u003c1\u003e","i":3}"#
    );
    assert_eq!(decode_multipart_cursor(&token).unwrap(), cursor);
    let only_skip = MultipartCursor {
        skip: 7,
        ..MultipartCursor::default()
    };
    assert_eq!(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encode_multipart_cursor(&only_skip))
            .unwrap(),
        br#"{"i":7}"#
    );
    assert_eq!(decode_multipart_cursor("").unwrap(), MultipartCursor::default());
}

#[test]
fn a_page_token_that_is_not_valid_is_refused() {
    let encode = |text: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(text);
    let long = encode(&format!(r#"{{"k":"{}"}}"#, "x".repeat(5000)));
    for bad in [
        "!!".to_owned(),
        encode("not json"),
        encode(r#"{"i":-1}"#),
        encode(r#"{"k":1}"#),
        encode(r#"[1]"#),
        encode(r#"{"k":"a"} x"#),
        long,
    ] {
        let error = decode_multipart_cursor(&bad).unwrap_err();
        assert_eq!(
            (error.status(), error.code().as_str()),
            (400, "invalid_page_token"),
            "{bad}"
        );
    }
    assert_eq!(
        decode_multipart_cursor(&encode("null")).unwrap(),
        MultipartCursor::default()
    );
    assert_eq!(
        decode_multipart_cursor(&encode(r#"{"x":1}"#)).unwrap(),
        MultipartCursor::default()
    );
}

// --- The documents of S3 ---------------------------------------------------------------------------------------------

#[test]
fn the_request_of_the_list_never_has_a_prefix_and_has_the_markers_in_the_order_of_their_names() {
    assert_eq!(
        list_uploads_query(&MultipartCursor::default(), 0),
        vec![("uploads".to_owned(), String::new())]
    );
    let cursor = MultipartCursor {
        key_marker: "k".to_owned(),
        upload_id_marker: "u".to_owned(),
        skip: 4,
    };
    assert_eq!(
        list_uploads_query(&cursor, 1000),
        vec![
            ("key-marker".to_owned(), "k".to_owned()),
            ("max-uploads".to_owned(), "1000".to_owned()),
            ("upload-id-marker".to_owned(), "u".to_owned()),
            ("uploads".to_owned(), String::new()),
        ]
    );
    assert_eq!(
        list_parts_query("up 1", 1000),
        vec![
            ("max-parts".to_owned(), "1000".to_owned()),
            ("uploadId".to_owned(), "up 1".to_owned()),
        ]
    );
}

#[test]
fn the_answer_of_aws_has_both_markers_and_the_dates() {
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListMultipartUploadsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Bucket>b</Bucket>
  <KeyMarker></KeyMarker>
  <UploadIdMarker></UploadIdMarker>
  <NextKeyMarker>tenant/b&amp;c.bin</NextKeyMarker>
  <NextUploadIdMarker>id-2</NextUploadIdMarker>
  <MaxUploads>2</MaxUploads>
  <IsTruncated>true</IsTruncated>
  <Upload>
    <Key>tenant/a &lt;1&gt;.bin</Key>
    <UploadId>id-1</UploadId>
    <Initiator><ID>x</ID></Initiator>
    <StorageClass>STANDARD</StorageClass>
    <Initiated>2026-10-01T08:30:00.000Z</Initiated>
  </Upload>
  <Upload>
    <UploadId>id-2</UploadId>
    <Key>tenant/b&amp;c.bin</Key>
    <Initiated>2026-10-02T10:00:00+02:00</Initiated>
  </Upload>
</ListMultipartUploadsResult>"#;
    let page = parse_list_uploads(xml.as_bytes()).unwrap();
    assert_eq!(page.uploads.len(), 2);
    assert_eq!(page.uploads[0].key, "tenant/a <1>.bin");
    assert_eq!(page.uploads[0].upload_id, "id-1");
    assert_eq!(page.uploads[0].initiated.unwrap().rfc3339(), "2026-10-01T08:30:00Z");
    assert_eq!(page.uploads[1].key, "tenant/b&c.bin");
    assert_eq!(page.uploads[1].upload_id, "id-2");
    assert_eq!(page.uploads[1].initiated.unwrap().rfc3339(), "2026-10-02T08:00:00Z");
    assert_eq!(
        page.next,
        Some(MultipartCursor {
            key_marker: "tenant/b&c.bin".to_owned(),
            upload_id_marker: "id-2".to_owned(),
            skip: 0,
        })
    );
}

#[test]
fn the_answer_of_seaweedfs_has_one_marker_and_no_date() {
    let xml = "<ListMultipartUploadsResult><IsTruncated>true</IsTruncated><NextUploadIdMarker>u9</NextUploadIdMarker><Upload><Key>k</Key><UploadId>u9</UploadId></Upload></ListMultipartUploadsResult>";
    let page = parse_list_uploads(xml.as_bytes()).unwrap();
    assert_eq!(page.uploads[0].initiated, None);
    assert_eq!(
        page.next,
        Some(MultipartCursor {
            upload_id_marker: "u9".to_owned(),
            ..MultipartCursor::default()
        })
    );
}

#[test]
fn the_last_page_has_no_next_cursor_and_an_empty_answer_has_no_upload() {
    let last = "<ListMultipartUploadsResult><IsTruncated>false</IsTruncated><NextKeyMarker>ignored</NextKeyMarker></ListMultipartUploadsResult>";
    assert_eq!(
        parse_list_uploads(last.as_bytes()).unwrap(),
        super::MultipartUploadPage::default()
    );
    let none = "<ListMultipartUploadsResult/>";
    assert_eq!(
        parse_list_uploads(none.as_bytes()).unwrap(),
        super::MultipartUploadPage::default()
    );
    let flag = "<ListMultipartUploadsResult><IsTruncated>1</IsTruncated></ListMultipartUploadsResult>";
    assert!(parse_list_uploads(flag.as_bytes()).unwrap().next.is_some());
}

#[test]
fn an_answer_that_is_not_complete_or_not_valid_is_an_error() {
    for bad in [
        "<ListMultipartUploadsResult><Upload><Key>k</Key>",
        "<ListMultipartUploadsResult><IsTruncated>maybe</IsTruncated></ListMultipartUploadsResult>",
        "<ListMultipartUploadsResult><Upload><Key>&unknown;</Key></Upload></ListMultipartUploadsResult>",
        "<a></b>",
        "",
    ] {
        let error = parse_list_uploads(bad.as_bytes()).unwrap_err();
        assert!(
            error.to_string().starts_with("decode s3 multipart uploads response: "),
            "{bad:?}: {error}"
        );
    }
    assert!(parse_list_uploads(&[0xff, 0xfe]).is_err());
}

#[test]
fn the_parts_of_an_upload_are_counted_and_summed() {
    let xml = r#"<ListPartsResult><IsTruncated>true</IsTruncated>
<Part><PartNumber>1</PartNumber><ETag>"e1"</ETag><Size>5242880</Size></Part>
<Part><PartNumber>2</PartNumber><Size>1000</Size></Part>
<Part><PartNumber>3</PartNumber><Size></Size></Part>
<Part/>
</ListPartsResult>"#;
    assert_eq!(parse_list_parts(xml.as_bytes()).unwrap(), (4, 5_243_880, true));
    assert_eq!(parse_list_parts(b"<ListPartsResult/>").unwrap(), (0, 0, false));
    assert!(parse_list_parts(b"<ListPartsResult><Part><Size>x</Size></Part></ListPartsResult>").is_err());
}

#[test]
fn the_job_that_the_abort_route_gives_has_the_form_of_a_job() {
    let created = Timestamp::parse_rfc3339("2026-11-23T12:00:00Z").unwrap();
    let mut job = abort_job(5, "logs/");
    job.status = "queued".to_owned();
    job.created_at = created;
    job.updated_at = created;
    let text = String::from_utf8(crate::common::json::to_vec(&job.public()).unwrap()).unwrap();
    assert_eq!(
        text,
        r#"{"id":"job_1","type":"abort_multiparts","instance":"rw","prefix":"logs/","status":"queued","processed":0,"olderThanDays":5,"multipartAbort":{"aborted":0,"skippedUndated":0,"skippedRecent":0,"skippedActive":0,"failed":0},"createdAt":"2026-11-23T12:00:00Z","updatedAt":"2026-11-23T12:00:00Z"}"#
    );
}
