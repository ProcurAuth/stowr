//! The tests of the routes `/api/uploads` and `/api/uploads/resume`: the answers that come before a call to the storage.

use std::sync::Arc;

use http::Method;
use serde_json::Value;

use super::handle_uploads;
use super::test_fakes::test_cipher_key;
use super::test_fakes::{call, request, test_app};
use super::token::{RESUME_TOKEN_LIFETIME_SECONDS, ResumeDescriptor, seal_descriptor};
use crate::common::app::App;
use crate::common::time::Timestamp;

async fn send(
    app: &Arc<App>,
    method: Method,
    target: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> (u16, Value, String) {
    let (status, _, text) = call(handle_uploads, app, request(method, target, body, headers)).await;
    (status, serde_json::from_str(&text).unwrap_or(Value::Null), text)
}

fn code_of(answer: &Value) -> &str {
    answer["error"]["code"].as_str().unwrap_or("")
}

fn token_for(instance: &str, provider: &str) -> String {
    let issued = Timestamp::now().secs - 10;
    seal_descriptor(
        &test_cipher_key(),
        instance,
        &ResumeDescriptor {
            instance: instance.to_owned(),
            key: "k.bin".to_owned(),
            provider: provider.to_owned(),
            total_size: 10,
            chunk_size: 5 << 20,
            provider_upload_id: "u".to_owned(),
            issued_at: issued,
            expires_at: issued + RESUME_TOKEN_LIFETIME_SECONDS,
            ..ResumeDescriptor::default()
        },
    )
    .unwrap()
}

#[tokio::test]
async fn a_request_without_a_token_is_refused() {
    let app = test_app(None);
    for method in [Method::GET, Method::PUT, Method::DELETE] {
        let (status, answer, _) = send(&app, method.clone(), "/api/uploads", "", &[]).await;
        assert_eq!(status, 400, "{method}");
        assert_eq!(code_of(&answer), "resume_token_required");
        assert_eq!(answer["error"]["message"], "upload resume token is required");
    }
    let (status, answer, _) = send(
        &app,
        Method::GET,
        "/api/uploads",
        "",
        &[("X-Stowr-Resume-Token", "   ")],
    )
    .await;
    assert_eq!((status, code_of(&answer)), (400, "resume_token_required"));
}

#[tokio::test]
async fn a_token_that_is_not_valid_is_refused_on_each_route() {
    let app = test_app(None);
    let headers = [("X-Stowr-Resume-Token", "stowr1.cnc.AAAA")];
    for method in [Method::GET, Method::PUT, Method::DELETE] {
        let (status, answer, _) = send(&app, method.clone(), "/api/uploads", "", &headers).await;
        assert_eq!((status, code_of(&answer)), (400, "invalid_resume_token"), "{method}");
    }
    let (status, answer, _) = send(
        &app,
        Method::POST,
        "/api/uploads/resume",
        r#"{"resumeToken":"nope"}"#,
        &[],
    )
    .await;
    assert_eq!((status, code_of(&answer)), (400, "invalid_resume_token"));
    let (status, answer, _) = send(&app, Method::POST, "/api/uploads/resume", "{}", &[]).await;
    assert_eq!((status, code_of(&answer)), (400, "invalid_resume_token"));
    let (status, answer, _) = send(
        &app,
        Method::POST,
        "/api/uploads/resume",
        r#"{"resumeToken":null}"#,
        &[],
    )
    .await;
    assert_eq!((status, code_of(&answer)), (400, "invalid_resume_token"));
}

#[tokio::test]
async fn a_token_for_an_unknown_instance_or_for_another_provider_is_refused() {
    let app = test_app(None);
    let unknown = token_for("nope", "s3");
    let (status, answer, _) = send(
        &app,
        Method::GET,
        "/api/uploads",
        "",
        &[("X-Stowr-Resume-Token", &unknown)],
    )
    .await;
    assert_eq!((status, code_of(&answer)), (404, "unknown_instance"));
    // The key of the token is the key of the credentials `test-auth`. The instances of the application have no such
    // credentials in this test, so their key differs: the token cannot be verified.
    let known = token_for("rw", "s3");
    let (status, answer, _) = send(
        &app,
        Method::GET,
        "/api/uploads",
        "",
        &[("X-Stowr-Resume-Token", &known)],
    )
    .await;
    assert_eq!((status, code_of(&answer)), (400, "invalid_resume_token"));
}

#[tokio::test]
async fn the_methods_and_the_paths_of_the_routes_are_checked() {
    let app = test_app(None);
    let (status, _, _) = send(&app, Method::PATCH, "/api/uploads", "", &[]).await;
    assert_eq!(status, 405);
    let response = call(handle_uploads, &app, request(Method::PATCH, "/api/uploads", "", &[])).await;
    assert_eq!(response.1["allow"], "GET, POST, PUT, DELETE");
    let response = call(
        handle_uploads,
        &app,
        request(Method::GET, "/api/uploads/resume", "", &[]),
    )
    .await;
    assert_eq!((response.0, response.1["allow"].to_str().unwrap()), (405, "POST"));
    let response = call(
        handle_uploads,
        &app,
        request(Method::GET, "/api/uploads/other", "", &[]),
    )
    .await;
    assert_eq!(response.0, 404);
    assert_eq!(response.2, "404 page not found\n");
}

#[tokio::test]
async fn a_create_request_is_validated_in_a_fixed_order() {
    let app = test_app(None);
    let cases = [
        ("not json", 400, "invalid_json"),
        (r#"{"instance":"rw","key":"a","size":1} {}"#, 400, "invalid_json"),
        (r#"{"instance":"rw","key":"a","size":1,"other":1}"#, 400, "invalid_json"),
        (r#"{"instance":"rw","key":"a","size":"1"}"#, 400, "invalid_json"),
        (r#"{"instance":"nope","key":"a","size":1}"#, 404, "unknown_instance"),
        (r#"{"key":"a","size":1}"#, 404, "unknown_instance"),
        (
            r#"{"instance":"readonly","key":"a","size":1}"#,
            403,
            "permission_denied",
        ),
        (r#"{"instance":"rw","key":"","size":1}"#, 400, "invalid_key"),
        (r#"{"instance":"rw","key":"a","size":-5}"#, 400, "invalid_size"),
        (
            r#"{"instance":"rw","key":"a","size":1,"checksum":"crc32"}"#,
            400,
            "invalid_checksum",
        ),
        (
            r#"{"instance":"rw","key":"a","size":1,"tags":[{"key":"a","value":"b","x":1}]}"#,
            400,
            "invalid_json",
        ),
        (
            r#"{"instance":"rw","key":"a","size":1,"tags":[{"key":"","value":"b"}]}"#,
            400,
            "invalid_tags",
        ),
    ];
    for (body, status, code) in cases {
        let (got, answer, text) = send(&app, Method::POST, "/api/uploads", body, &[]).await;
        assert_eq!((got, code_of(&answer)), (status, code), "{body}: {text}");
    }
}

#[tokio::test]
async fn the_instance_of_a_create_request_can_come_from_the_query() {
    let app = test_app(None);
    let (status, answer, _) = send(
        &app,
        Method::POST,
        "/api/uploads?instance=readonly",
        r#"{"key":"a","size":1}"#,
        &[],
    )
    .await;
    assert_eq!((status, code_of(&answer)), (403, "permission_denied"));
}

#[tokio::test]
async fn an_error_answer_is_json_without_cache() {
    let app = test_app(None);
    let (status, headers, text) = call(handle_uploads, &app, request(Method::GET, "/api/uploads", "", &[])).await;
    assert_eq!(status, 400);
    assert_eq!(headers["content-type"], "application/json; charset=utf-8");
    assert_eq!(headers["cache-control"], "no-store");
    assert_eq!(
        text,
        "{\"error\":{\"code\":\"resume_token_required\",\"message\":\"upload resume token is required\"}}\n"
    );
}
