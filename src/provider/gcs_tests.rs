// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tests of the GCS back end against a local test server.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use http::header::HeaderValue;
use http::{HeaderMap, Method};

use super::gcs::resumable_next_offset;
use super::test_server::{Problems, TestResponse, TestServer};
use super::testing::anonymous_gcs;
use crate::common::ctx::OpCtx;
use crate::common::http::{full, read_limited};
use crate::common::storage::{Backend, ConditionalWriter, ListOptions, ResumableApi, VersionStore};

fn header(pairs: &[(&'static str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
        headers.insert(*name, HeaderValue::from_str(value).unwrap());
    }
    headers
}

#[tokio::test]
async fn a_provider_copy_follows_the_continuation_token() {
    let problems = Arc::new(Problems::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let (seen, counter) = (problems.clone(), calls.clone());
    let server = TestServer::start(move |request| {
        let call = counter.fetch_add(1, Ordering::SeqCst) + 1;
        if request.method != Method::POST {
            seen.report(format!("method = {}", request.method));
        }
        if !request.raw_path.contains("/rewriteTo/") {
            seen.report(format!("path = {}", request.raw_path));
        }
        if call == 1 {
            if !request.query.get("rewriteToken").is_empty() {
                seen.report(format!(
                    "first continuation token = {:?}",
                    request.query.get("rewriteToken")
                ));
            }
            return TestResponse::body(200, r#"{"done":false,"rewriteToken":"next-token"}"#)
                .header("content-type", "application/json");
        }
        if request.query.get("rewriteToken") != "next-token" {
            seen.report(format!(
                "second continuation token = {:?}",
                request.query.get("rewriteToken")
            ));
        }
        TestResponse::body(200, r#"{"done":true}"#).header("content-type", "application/json")
    })
    .await;
    let backend = anonymous_gcs(&server.url, "bucket");
    backend
        .copy(&OpCtx::default(), "source/one", "destination/two")
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    problems.check();
}

#[tokio::test]
async fn a_provider_copy_without_a_new_token_stops() {
    let server = TestServer::start(|_| TestResponse::body(200, r#"{"done":false,"rewriteToken":""}"#)).await;
    let backend = anonymous_gcs(&server.url, "bucket");
    let error = backend.copy(&OpCtx::default(), "a", "b").await.unwrap_err();
    assert!(error.to_string().contains("returned no new rewrite token"), "{error}");
}

#[test]
fn the_api_url_keeps_the_path_of_the_endpoint() {
    let backend = anonymous_gcs("https://example.test/emulator/v1", "bucket");
    assert_eq!(
        backend.api_url("storage/v1/b/a%20bucket/o", &[("prefix", "a/b")]),
        "https://example.test/emulator/v1/storage/v1/b/a%20bucket/o?prefix=a%2Fb"
    );
    let backend = anonymous_gcs("https://example.test", "test-bucket");
    assert_eq!(
        backend.object_metadata_url("dir/a b+é.txt", &[]),
        "https://example.test/storage/v1/b/test-bucket/o/dir%2Fa%20b%2B%C3%A9.txt"
    );
}

#[tokio::test]
async fn a_read_passes_not_modified_through() {
    let problems = Arc::new(Problems::default());
    let seen = problems.clone();
    let server = TestServer::start(move |request| {
        if request.header("if-none-match") != "\"etag\"" {
            seen.report(format!("If-None-Match = {:?}", request.header("if-none-match")));
        }
        if request.query.get("alt") != "media" {
            seen.report(format!("alt = {:?}", request.query.get("alt")));
        }
        TestResponse::status(304).header("etag", "\"etag\"")
    })
    .await;
    let backend = anonymous_gcs(&server.url, "bucket");
    let response = backend
        .get(
            &OpCtx::default(),
            "object.txt",
            &header(&[("if-none-match", "\"etag\"")]),
        )
        .await
        .unwrap();
    assert_eq!(response.status, 304);
    assert_eq!(response.headers.get("etag").unwrap(), "\"etag\"");
    problems.check();
}

#[tokio::test]
async fn the_resumable_upload_goes_from_the_start_to_the_abort() {
    let problems = Arc::new(Problems::default());
    let address: Arc<OnceLock<String>> = Arc::new(OnceLock::new());
    let chunks = Arc::new(AtomicUsize::new(0));
    let (seen, base, counter) = (problems.clone(), address.clone(), chunks.clone());
    let server = TestServer::start(move |request| {
        if request.method == Method::POST && request.path.contains("/upload/storage/v1/b/bucket/o") {
            if request.query.get("uploadType") != "resumable" {
                seen.report(format!("uploadType = {:?}", request.query.get("uploadType")));
            }
            if request.header("x-upload-content-length") != "10" {
                seen.report(format!("length = {:?}", request.header("x-upload-content-length")));
            }
            let location = format!("{}/resumable/session-1", base.get().unwrap());
            return TestResponse::status(200).header("location", &location);
        }
        if request.method == Method::PUT && request.path == "/resumable/session-1" {
            let range = request.header("content-range").to_owned();
            if range == "bytes */10" {
                return TestResponse::status(308).header("range", "bytes=0-4");
            }
            let call = counter.fetch_add(1, Ordering::SeqCst) + 1;
            if call == 1 {
                if range != "bytes 0-4/10" {
                    seen.report(format!("first range = {range:?}"));
                }
                return TestResponse::status(308).header("range", "bytes=0-4");
            }
            if range != "bytes 5-9/10" {
                seen.report(format!("second range = {range:?}"));
            }
            return TestResponse::status(200);
        }
        if request.method == Method::DELETE && request.path == "/resumable/session-1" {
            return TestResponse::status(499);
        }
        seen.report(format!("unexpected request: {} {}", request.method, request.path));
        TestResponse::status(400)
    })
    .await;
    address.set(server.url.clone()).unwrap();
    let backend = anonymous_gcs(&server.url, "bucket");
    let ctx = OpCtx::default();
    let session = backend
        .initiate_resumable(&ctx, "large.bin", 10, "application/octet-stream")
        .await
        .unwrap();
    assert_eq!(session, format!("{}/resumable/session-1", server.url));
    let (next, complete) = backend
        .upload_chunk(&ctx, &session, full("12345"), 0, 5, 10, "application/octet-stream")
        .await
        .unwrap();
    assert_eq!((next, complete), (5, false));
    let (queried, complete) = backend.query_resumable(&ctx, &session, 10).await.unwrap();
    assert_eq!((queried, complete), (5, false));
    let (next, complete) = backend
        .upload_chunk(&ctx, &session, full("67890"), 5, 5, 10, "application/octet-stream")
        .await
        .unwrap();
    assert_eq!((next, complete), (10, true));
    backend.abort_resumable(&ctx, &session).await.unwrap();
    assert!(
        backend
            .upload_chunk(&ctx, &session, full("x"), 9, 2, 10, "")
            .await
            .is_err()
    );
    problems.check();
}

#[test]
fn a_resumable_url_of_an_unexpected_host_is_refused() {
    let backend = anonymous_gcs("https://storage.googleapis.com", "bucket");
    assert!(
        backend
            .validate_resumable_url("https://attacker.example/upload")
            .is_err()
    );
    assert!(
        backend
            .validate_resumable_url("https://storage.googleapis.com/upload?upload_id=1")
            .is_ok()
    );
    assert!(
        backend
            .validate_resumable_url("https://www.googleapis.com/upload/storage/v1/b/x/o?upload_id=1")
            .is_ok()
    );
    assert!(
        backend
            .validate_resumable_url("http://storage.googleapis.com/upload")
            .is_err()
    );
    assert!(
        backend
            .validate_resumable_url("ftp://storage.googleapis.com/upload")
            .is_err()
    );
    assert!(
        backend
            .validate_resumable_url("https://user@storage.googleapis.com/upload")
            .is_err()
    );
    assert!(
        backend
            .validate_resumable_url("https://storage.googleapis.com/upload#x")
            .is_err()
    );
    assert_eq!(
        backend.validate_resumable_url("/upload/x?id=1").unwrap().text(),
        "https://storage.googleapis.com/upload/x?id=1"
    );
    let local = anonymous_gcs("http://127.0.0.1:4443/base", "bucket");
    assert!(local.validate_resumable_url("http://127.0.0.1:4443/x").is_ok());
    assert!(local.validate_resumable_url("http://127.0.0.1:4444/x").is_err());
    assert!(
        local
            .validate_resumable_url("https://storage.googleapis.com/x")
            .is_err()
    );
    assert_eq!(resumable_next_offset("bytes=0-1048575"), 1_048_576);
    assert_eq!(resumable_next_offset(""), 0);
    assert_eq!(resumable_next_offset("bytes=0-x"), 0);
    assert_eq!(resumable_next_offset("0-9"), 10);
}

#[tokio::test]
async fn a_read_forwards_the_range_and_the_resume_condition() {
    let problems = Arc::new(Problems::default());
    let seen = problems.clone();
    let server = TestServer::start(move |request| {
        if request.header("range") != "bytes=100-" {
            seen.report(format!("Range = {:?}", request.header("range")));
        }
        if request.header("if-range") != "\"etag\"" {
            seen.report(format!("If-Range = {:?}", request.header("if-range")));
        }
        if request.query.get("alt") != "media" {
            seen.report(format!("alt = {:?}", request.query.get("alt")));
        }
        TestResponse::body(206, "end").header("content-range", "bytes 100-102/103")
    })
    .await;
    let backend = anonymous_gcs(&server.url, "bucket");
    let response = backend
        .get(
            &OpCtx::default(),
            "object.bin",
            &header(&[("range", "bytes=100-"), ("if-range", "\"etag\"")]),
        )
        .await
        .unwrap();
    assert_eq!(response.status, 206);
    problems.check();
}

#[tokio::test]
async fn the_generations_of_an_object_list_read_delete_and_restore() {
    let problems = Arc::new(Problems::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let (seen, counter) = (problems.clone(), calls.clone());
    let server = TestServer::start(move |request| {
        counter.fetch_add(1, Ordering::SeqCst);
        let query = &request.query;
        let object_path = request.path.ends_with("/storage/v1/b/bucket/o/folder/file.txt");
        if request.method == Method::GET && request.path == "/storage/v1/b/bucket/o" && query.get("versions") == "true" {
            if query.get("prefix") != "folder/file.txt" {
                seen.report(format!("prefix = {:?}", query.get("prefix")));
            }
            return TestResponse::body(
                200,
                r#"{"nextPageToken":"next","items":[
{"name":"folder/file.txt","size":"3","updated":"2026-01-01T00:00:00Z","timeDeleted":"2026-01-02T00:00:00Z","etag":"old","contentType":"text/plain","generation":"1","md5Hash":"YWJj","crc32c":"Nks/tw=="},
{"name":"folder/file.txt","size":"4","updated":"2026-01-03T00:00:00Z","etag":"current","contentType":"text/plain","generation":"2"},
{"name":"folder/file.txt-copy","size":"9","updated":"2026-01-04T00:00:00Z","generation":"3"}]}"#,
            )
            .header("content-type", "application/json");
        }
        if request.method == Method::GET && object_path && query.get("generation") == "1" && query.get("alt").is_empty() {
            return TestResponse::body(
                200,
                r#"{"name":"folder/file.txt","size":"3","updated":"2026-01-01T00:00:00Z","etag":"old","contentType":"text/plain","generation":"1","metageneration":"2","md5Hash":"YWJj","crc32c":"Nks/tw==","metadata":{"owner":"ops"}}"#,
            );
        }
        if request.method == Method::GET && object_path && query.get("generation") == "1" && query.get("alt") == "media" {
            if request.header("range") != "bytes=0-1" {
                seen.report(format!("Range = {:?}", request.header("range")));
            }
            return TestResponse::body(206, "ab").header("content-range", "bytes 0-1/3");
        }
        if request.method == Method::DELETE && query.get("generation") == "1" {
            return TestResponse::status(204);
        }
        if request.method == Method::POST && request.path.contains("/rewriteTo/") {
            if query.get("sourceGeneration") != "1" {
                seen.report(format!("sourceGeneration = {:?}", query.get("sourceGeneration")));
            }
            return TestResponse::body(200, r#"{"done":true}"#);
        }
        seen.report(format!("unexpected request: {} {}?{}", request.method, request.path, request.raw_query));
        TestResponse::status(400)
    })
    .await;
    let backend = anonymous_gcs(&server.url, "bucket");
    let ctx = OpCtx::default();
    let page = backend.list_versions(&ctx, "folder/file.txt", "", 100).await.unwrap();
    assert_eq!(page.next_page_token, "");
    assert_eq!(page.versions.len(), 2);
    assert_eq!(page.versions[0].version, "2");
    assert!(page.versions[0].is_current);
    assert!(!page.versions[1].is_current);
    assert_eq!(page.versions[1].checksums["md5"], "YWJj");
    assert_eq!(page.versions[1].checksums["crc32c"], "Nks/tw==");
    let head = backend.head_version(&ctx, "folder/file.txt", "1").await.unwrap();
    assert_eq!(head.headers.get("x-goog-generation").unwrap(), "1");
    assert_eq!(head.headers.get("x-goog-hash").unwrap(), "crc32c=Nks/tw==,md5=YWJj");
    assert_eq!(head.headers.get("content-length").unwrap(), "3");
    assert_eq!(
        head.headers.get("last-modified").unwrap(),
        "Thu, 01 Jan 2026 00:00:00 GMT"
    );
    assert_eq!(head.headers.get("x-goog-meta-owner").unwrap(), "ops");
    let response = backend
        .get_version(&ctx, "folder/file.txt", "1", &header(&[("range", "bytes=0-1")]))
        .await
        .unwrap();
    let (body, _) = read_limited(response.body, 1024).await.unwrap();
    assert_eq!(&body[..], b"ab");
    backend.delete_version(&ctx, "folder/file.txt", "1").await.unwrap();
    backend
        .restore_version(&ctx, "folder/file.txt", "1", &HeaderMap::new())
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 5);
    problems.check();
}

#[tokio::test]
async fn a_write_that_creates_only_uses_the_generation_precondition() {
    let problems = Arc::new(Problems::default());
    let seen = problems.clone();
    let server = TestServer::start(move |request| {
        if request.method != Method::POST {
            seen.report(format!("method = {}", request.method));
        }
        if request.query.get("uploadType") != "media" {
            seen.report(format!("uploadType = {:?}", request.query.get("uploadType")));
        }
        if request.query.get("ifGenerationMatch") != "0" {
            seen.report(format!(
                "ifGenerationMatch = {:?}",
                request.query.get("ifGenerationMatch")
            ));
        }
        TestResponse::status(412)
    })
    .await;
    let backend = anonymous_gcs(&server.url, "bucket");
    let error = backend
        .put_if_absent(&OpCtx::default(), "existing.txt", full("value"), 5, "text/plain")
        .await
        .unwrap_err();
    let api = error.as_api().unwrap();
    assert_eq!((api.status, api.code.as_str()), (409, "object_exists"));
    problems.check();
}

#[tokio::test]
async fn a_gcs_error_gives_the_status_and_the_message_of_the_body() {
    let server = TestServer::start(|request| match request.path.as_str() {
        "/storage/v1/b/bucket/o" => TestResponse::body(
            403,
            r#"{"error":{"code":403,"message":"no access","status":"PERMISSION_DENIED"}}"#,
        ),
        _ => TestResponse::body(404, "Not Found"),
    })
    .await;
    let backend = anonymous_gcs(&server.url, "bucket");
    let error = backend
        .list(&OpCtx::default(), &ListOptions::default())
        .await
        .unwrap_err();
    let upstream = error.as_upstream().unwrap();
    assert_eq!(
        (upstream.status, upstream.code.as_str(), upstream.message.as_str()),
        (403, "PERMISSION_DENIED", "no access")
    );
    let error = backend.delete(&OpCtx::default(), "x").await.unwrap_err();
    assert_eq!(error.as_upstream().unwrap().message, "Not Found");
}

#[tokio::test]
async fn a_listing_gives_the_objects_the_folders_and_the_next_token() {
    let problems = Arc::new(Problems::default());
    let seen = problems.clone();
    let server = TestServer::start(move |request| {
        let expected = [
            ("prefix", "a/"),
            ("delimiter", "/"),
            ("includeTrailingDelimiter", "false"),
            ("maxResults", "5"),
            ("pageToken", "token"),
            ("startOffset", "a/0"),
            ("fields", "items(name,size,updated,etag,contentType),prefixes,nextPageToken"),
        ];
        for (name, value) in expected {
            if request.query.get(name) != value {
                seen.report(format!("{name} = {:?}", request.query.get(name)));
            }
        }
        TestResponse::body(
            200,
            r#"{"prefixes":["a/sub/"],"nextPageToken":"next","items":[{"name":"a/1.txt","size":"12","updated":"2026-01-02T03:04:05.250Z","etag":"e","contentType":"text/plain"},{"name":"a/2","size":null}]} trailing"#,
        )
    })
    .await;
    let backend = anonymous_gcs(&server.url, "bucket");
    let options = ListOptions {
        prefix: "a/".to_owned(),
        delimiter: "/".to_owned(),
        max_results: 5,
        page_token: "token".to_owned(),
        start_after: "a/0".to_owned(),
    };
    let page = backend.list(&OpCtx::default(), &options).await.unwrap();
    assert_eq!(page.prefixes, vec!["a/sub/".to_owned()]);
    assert_eq!(page.next_page_token, "next");
    assert_eq!(page.objects.len(), 2);
    assert_eq!(page.objects[0].size, 12);
    assert_eq!(page.objects[0].content_type, "text/plain");
    assert_eq!(
        page.objects[0].last_modified.unwrap().rfc3339_nano(),
        "2026-01-02T03:04:05.25Z"
    );
    assert_eq!(page.objects[1].size, 0);
    problems.check();
}
