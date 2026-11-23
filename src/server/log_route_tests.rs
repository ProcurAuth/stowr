// SPDX-License-Identifier: MIT OR Apache-2.0
//! The log lines of the access policy in mode `authzen`: the request log with the subject, the refusal of a token,
//! the refusal of a route without a rule, the ceilings that a server cannot apply, a budget as a limit, the refusal of
//! a ceiling and the line of the options route. Each test keeps the log lines of its thread.

use std::sync::Arc;

use http::{HeaderMap, Method};
use serde_json::json;

use super::testing::{TestRequest, TestResponse, app_with_access};
use crate::access::AccessLayer;
use crate::access::fake::FakePdp;
use crate::access::test_support::{SERVICE, SUBJECT, authzen_config, bucket, instance_over, memory};
use crate::common::app::App;
use crate::common::config::LogMode;
use crate::common::http::RouteAccess;
use crate::common::misc::log_capture;

const TOKEN: &str = "good-token";

/// The application of the tests: `rw` (root prefix `tenant/`) with three folders, and the fake guard that accepts
/// [`TOKEN`] and answers true to each question.
fn authzen_app(log_mode: LogMode) -> (Arc<App>, Arc<FakePdp>) {
    let mut rw = bucket("rw", "Read write", None);
    rw.root_prefix = "tenant/".to_owned();
    let mut config = authzen_config(SERVICE, vec![rw.clone()], Vec::new());
    config.runtime.log_mode = log_mode;
    let fake = Arc::new(FakePdp::new());
    fake.accept_token(TOKEN, SUBJECT, "");
    let access = AccessLayer::with_guard(&config, fake.clone()).unwrap();
    let instances = vec![instance_over(
        rw,
        memory(&[
            ("tenant/one/a.txt", "a"),
            ("tenant/two/b.txt", "b"),
            ("tenant/secret/c.txt", "c"),
            ("tenant/twelve.txt", "hello world!"),
        ]),
    )];
    (app_with_access(config, instances, access), fake)
}

/// Send a request with the token and a request id.
async fn send(app: &Arc<App>, target: &str, request_id: &str) -> TestResponse {
    TestRequest::get(target)
        .header("x-identity-token", TOKEN)
        .header("x-request-id", request_id)
        .send(app)
        .await
}

/// The log lines of a block of async work on this thread.
async fn logged<T>(work: impl Future<Output = T>) -> (T, String) {
    log_capture::start();
    let value = work.await;
    (value, log_capture::take().concat())
}

#[tokio::test]
async fn the_request_log_has_the_subject_and_a_refusal_of_the_token_has_none() {
    let (app, _) = authzen_app(LogMode::Anonymous);
    let ((with_token, without_token), text) = logged(async {
        let with_token = send(&app, "/api/build", "req-log-1").await;
        let without_token = TestRequest::get("/api/build").send(&app).await;
        (with_token, without_token)
    })
    .await;
    assert_eq!(with_token.status, 200, "{}", with_token.text());
    assert_eq!(without_token.status, 401);
    assert!(text.contains(r#"subject="user-1" request_id=req-log-1"#), "{text}");
    assert!(text.contains("access.unauthenticated request_id="), "{text}");
    assert!(text.contains("reason=missing"), "{text}");
    for line in text.lines() {
        assert!(
            !(line.contains("access.unauthenticated") && line.contains("subject=")),
            "a refusal line has a subject: {line}"
        );
    }
}

#[tokio::test]
async fn a_route_without_a_rule_writes_the_line_of_the_missing_rule() {
    let (app, fake) = authzen_app(LogMode::Anonymous);
    let ctx = crate::access::test_support::ctx_of(SUBJECT, "rid-rule");
    let (result, text) = logged(app.access.guard_route(
        &ctx,
        RouteAccess::Denied,
        &Method::GET,
        "/api/unruled",
        &HeaderMap::new(),
    ))
    .await;
    assert_eq!(result.unwrap_err().status(), 403);
    assert!(text.contains("access.no_rule request_id="), "{text}");
    assert_eq!(fake.requests(), 0);
}

#[tokio::test]
async fn the_ceilings_that_the_server_cannot_apply_write_their_lines() {
    let (app, fake) = authzen_app(LogMode::Anonymous);
    let target = "/s3?instance=rw&key=twelve.txt";
    // A ceiling that the action does not list: the server cannot apply it, so it refuses.
    fake.set_answer(|_| json!({"decision": true, "context": {"limits": {"max_rows": 5}}}));
    let (answer, text) = logged(send(&app, target, "rid-c")).await;
    assert_eq!(answer.status, 403, "{}", answer.text());
    assert!(
        text.contains(r#"access.ceiling_unenforceable request_id=rid-c action=object.read ceiling="max_rows""#),
        "{text}"
    );
    // A budget is not a ceiling: the answer is not valid.
    fake.set_answer(|_| json!({"decision": true, "context": {"limits": {"writes": 1}}}));
    let (answer, text) = logged(send(&app, target, "rid-b")).await;
    assert_eq!(answer.status, 503, "{}", answer.text());
    assert!(text.contains("access.pdp_invalid_answer request_id=rid-b"), "{text}");
}

#[tokio::test]
async fn the_refusal_of_a_ceiling_writes_the_action_the_limit_and_the_size() {
    let (app, fake) = authzen_app(LogMode::Anonymous);
    fake.set_answer(|_| json!({"decision": true, "context": {"limits": {"max_object_size": 10}}}));
    let (answer, text) = logged(send(&app, "/s3?instance=rw&key=twelve.txt", "rid-get")).await;
    assert_eq!(answer.status, 403, "{}", answer.text());
    assert!(!answer.text().contains("hello"));
    assert!(
        text.contains(
            "access.ceiling_refused request_id=rid-get action=object.read ceiling=max_object_size limit=10 size=12"
        ),
        "{text}"
    );
}

#[tokio::test]
async fn the_line_of_the_options_route_has_the_counts_and_hides_the_folder_ids_in_mode_anonymous() {
    let (app, _) = authzen_app(LogMode::Anonymous);
    let (answer, text) = logged(send(
        &app,
        "/.well-known/procurauth/resources?type=folder&parent=bucket%3Arw",
        "req-1",
    ))
    .await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert!(
        text.contains(
            r#"access.options request_id=req-1 subject="user-1" type=folder parent="bucket:rw" items=3 questions=3"#
        ),
        "{text}"
    );
    let subfolder = "/.well-known/procurauth/resources?type=subfolder&parent=bucket%3Arw%2Ffolder%3Asecret";
    let (_, text) = logged(send(&app, subfolder, "req-2")).await;
    assert!(!text.contains("secret"), "{text}");
    assert!(text.contains(r#"parent="bucket:rw/folder:-""#), "{text}");
    let (detailed, _) = authzen_app(LogMode::Detailed);
    let (_, text) = logged(send(&detailed, subfolder, "req-3")).await;
    assert!(text.contains(r#"parent="bucket:rw/folder:secret""#), "{text}");
}
