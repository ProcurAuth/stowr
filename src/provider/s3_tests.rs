//! The tests of the S3 back end against a local test server.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use http::header::{AUTHORIZATION, HeaderValue};
use http::{HeaderMap, Method};

use super::s3::sigv4;
use super::test_server::{Problems, TestRequest, TestResponse, TestServer};
use super::testing::{anonymous_s3, signed_s3};
use super::{ChecksumTransfer, S3Backend, S3Request};
use crate::common::ctx::OpCtx;
use crate::common::error::Error;
use crate::common::http::{full, read_limited};
use crate::common::md5::md5;
use crate::common::storage::{
    Backend, BatchDeleter, CapabilityStateName, CompletedPart, ConditionalWriter, ListOptions, MultipartPartLister,
    MultipartUploadApi, VersionStore,
};
use crate::common::time::Timestamp;

fn header(pairs: &[(&'static str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
        headers.insert(*name, HeaderValue::from_str(value).unwrap());
    }
    headers
}

#[test]
fn the_object_url_keeps_the_endpoint_path_and_escapes_the_key() {
    let backend = anonymous_s3("https://example.test/base", "my bucket");
    assert_eq!(
        backend.object_url::<&str, &str>("a//./../b +é.txt", &[]),
        "https://example.test/base/my%20bucket/a//./../b%20%2B%C3%A9.txt"
    );
    assert_eq!(
        backend.object_url("", &[("prefix", "a b/+"), ("max-keys", "2"), ("empty", "")]),
        "https://example.test/base/my%20bucket?empty=&max-keys=2&prefix=a%20b%2F%2B"
    );
    assert_eq!(
        backend.copy_source_header("dir/a b.txt", "v 1"),
        "/my%20bucket/dir/a%20b.txt?versionId=v+1"
    );
}

#[tokio::test]
async fn a_copy_detects_an_error_inside_a_successful_answer() {
    let server = TestServer::start(|_| {
        TestResponse::body(
            200,
            "<Error><Code>InternalError</Code><Message>copy failed</Message></Error>",
        )
        .header("content-type", "application/xml")
    })
    .await;
    let backend = anonymous_s3(&server.url, "bucket");
    let error = backend
        .copy(&OpCtx::default(), "source", "destination")
        .await
        .unwrap_err();
    assert!(error.to_string().contains("InternalError: copy failed"), "{error}");
    assert_eq!(error.status(), 502);
}

#[tokio::test]
async fn a_read_passes_not_modified_through() {
    let problems = Arc::new(Problems::default());
    let seen = problems.clone();
    let server = TestServer::start(move |request| {
        if request.header("if-none-match") != "\"etag\"" {
            seen.report(format!("If-None-Match = {:?}", request.header("if-none-match")));
        }
        TestResponse::status(304).header("etag", "\"etag\"")
    })
    .await;
    let backend = anonymous_s3(&server.url, "bucket");
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
async fn the_multipart_upload_goes_from_the_start_to_the_abort() {
    let problems = Arc::new(Problems::default());
    let calls = Arc::new(Mutex::new(Vec::new()));
    let (seen, recorded) = (problems.clone(), calls.clone());
    let server = TestServer::start(move |request| {
        recorded
            .lock()
            .unwrap()
            .push(format!("{} {}", request.method, request.raw_query));
        let query = &request.query;
        if request.method == Method::POST && query.has("uploads") {
            return TestResponse::body(
                200,
                "<InitiateMultipartUploadResult><UploadId>upload-123</UploadId></InitiateMultipartUploadResult>",
            );
        }
        if request.method == Method::PUT && query.get("partNumber") == "1" {
            if request.text() != "part-one" {
                seen.report(format!("part body = {:?}", request.text()));
            }
            return TestResponse::status(200).header("etag", "\"etag-one\"");
        }
        if request.method == Method::POST && query.get("uploadId") == "upload-123" {
            let body = request.text();
            if !body.contains("<PartNumber>1</PartNumber>") || !body.contains("<ETag>&#34;etag-one&#34;</ETag>") {
                seen.report(format!("completion body = {body}"));
            }
            return TestResponse::body(200, "<CompleteMultipartUploadResult/>");
        }
        if request.method == Method::DELETE && query.get("uploadId") == "upload-123" {
            return TestResponse::status(204);
        }
        seen.report(format!(
            "unexpected request: {} {}?{}",
            request.method, request.path, request.raw_query
        ));
        TestResponse::status(400)
    })
    .await;
    let backend = anonymous_s3(&server.url, "bucket");
    let ctx = OpCtx::default();
    let upload_id = backend
        .initiate(&ctx, "large.bin", "application/octet-stream")
        .await
        .unwrap();
    assert_eq!(upload_id, "upload-123");
    let etag = MultipartUploadApi::upload_part(&backend, &ctx, "large.bin", &upload_id, 1, full("part-one"), 8)
        .await
        .unwrap();
    assert_eq!(etag, "etag-one");
    let parts = [CompletedPart {
        number: 1,
        etag,
        checksum_sha256: String::new(),
    }];
    backend.complete(&ctx, "large.bin", &upload_id, &parts).await.unwrap();
    backend.abort(&ctx, "large.bin", &upload_id).await.unwrap();
    assert_eq!(calls.lock().unwrap().len(), 4, "{:?}", calls.lock().unwrap());
    problems.check();
}

#[tokio::test]
async fn the_multipart_completion_detects_an_embedded_error() {
    let server = TestServer::start(|_| {
        TestResponse::body(
            200,
            "<Error><Code>InternalError</Code><Message>failed</Message></Error>",
        )
    })
    .await;
    let backend = anonymous_s3(&server.url, "bucket");
    let parts = [CompletedPart {
        number: 1,
        etag: "etag".to_owned(),
        checksum_sha256: String::new(),
    }];
    let error = backend
        .complete(&OpCtx::default(), "large.bin", "upload", &parts)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("InternalError"), "{error}");
    let error = backend
        .complete(&OpCtx::default(), "large.bin", "upload", &[])
        .await
        .unwrap_err();
    assert!(error.to_string().contains("without parts"), "{error}");
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
        if request.header("accept-encoding") != "identity" {
            seen.report(format!("Accept-Encoding = {:?}", request.header("accept-encoding")));
        }
        TestResponse::body(206, "end").header("content-range", "bytes 100-102/103")
    })
    .await;
    let backend = anonymous_s3(&server.url, "bucket");
    let response = backend
        .get(
            &OpCtx::default(),
            "object.bin",
            &header(&[("range", "bytes=100-"), ("if-range", "\"etag\"")]),
        )
        .await
        .unwrap();
    assert_eq!(response.status, 206);
    let (body, _) = read_limited(response.body, 1024).await.unwrap();
    assert_eq!(&body[..], b"end");
    problems.check();
}

#[tokio::test]
async fn the_versions_of_an_object_list_read_delete_and_restore() {
    let problems = Arc::new(Problems::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let (seen, counter) = (problems.clone(), calls.clone());
    let server = TestServer::start(move |request| {
        counter.fetch_add(1, Ordering::SeqCst);
        let query = &request.query;
        if request.method == Method::GET && query.has("versions") {
            if query.get("prefix") != "folder/file.txt" {
                seen.report(format!("prefix = {:?}", query.get("prefix")));
            }
            if query.get("max-keys") != "250" {
                seen.report(format!("max-keys = {:?}", query.get("max-keys")));
            }
            return TestResponse::body(
                200,
                r#"<ListVersionsResult>
<IsTruncated>true</IsTruncated><NextKeyMarker>folder/file.txt</NextKeyMarker><NextVersionIdMarker>v1</NextVersionIdMarker>
<Version><Key>folder/file.txt</Key><VersionId>v1</VersionId><IsLatest>false</IsLatest><LastModified>2026-01-01T00:00:00.000Z</LastModified><ETag>&quot;etag-1&quot;</ETag><Size>3</Size></Version>
<Version><Key>folder/file.txt</Key><VersionId>v2</VersionId><IsLatest>true</IsLatest><LastModified>2026-01-02T00:00:00.000Z</LastModified><ETag>&quot;etag-2&quot;</ETag><Size>4</Size></Version>
<DeleteMarker><Key>folder/file.txt</Key><VersionId>deleted</VersionId><IsLatest>false</IsLatest><LastModified>2025-12-31T00:00:00.000Z</LastModified></DeleteMarker>
<Version><Key>folder/file.txt-copy</Key><VersionId>other</VersionId><IsLatest>true</IsLatest><LastModified>2026-01-03T00:00:00.000Z</LastModified><Size>5</Size></Version>
</ListVersionsResult>"#,
            );
        }
        if request.method == Method::HEAD && query.get("versionId") == "v1" {
            if request.header("x-amz-checksum-mode") != "ENABLED" {
                seen.report(format!("checksum mode = {:?}", request.header("x-amz-checksum-mode")));
            }
            return TestResponse::status(200)
                .header("content-length", "3")
                .header("x-amz-checksum-sha256", "YWJj");
        }
        if request.method == Method::GET && query.get("versionId") == "v1" {
            if request.header("range") != "bytes=0-1" {
                seen.report(format!("Range = {:?}", request.header("range")));
            }
            return TestResponse::body(206, "ab").header("content-range", "bytes 0-1/3");
        }
        if request.method == Method::DELETE && query.get("versionId") == "v1" {
            return TestResponse::status(204);
        }
        if request.method == Method::PUT && query.get("versionId").is_empty() {
            if request.header("x-amz-copy-source") != "/bucket/folder/file.txt?versionId=v1" {
                seen.report(format!("copy source = {:?}", request.header("x-amz-copy-source")));
            }
            return TestResponse::body(200, "<CopyObjectResult/>");
        }
        seen.report(format!("unexpected request: {} {}?{}", request.method, request.path, request.raw_query));
        TestResponse::status(400)
    })
    .await;
    let backend = anonymous_s3(&server.url, "bucket");
    let ctx = OpCtx::default();
    let page = backend.list_versions(&ctx, "folder/file.txt", "", 250).await.unwrap();
    assert_eq!(page.versions.len(), 3, "{:?}", page.versions);
    assert_eq!(page.versions[0].version, "v2");
    assert!(page.versions[0].is_current);
    assert_eq!(page.versions[0].etag, "etag-2");
    assert_eq!(page.versions[0].size, 4);
    assert!(page.versions[2].delete_marker);
    assert_eq!(page.versions[2].version, "deleted");
    let cursor = super::s3::tests_support::decode_cursor(&page.next_page_token).unwrap();
    assert_eq!(cursor, ("folder/file.txt".to_owned(), "v1".to_owned()));
    let head = backend.head_version(&ctx, "folder/file.txt", "v1").await.unwrap();
    assert_eq!(head.headers.get("x-amz-checksum-sha256").unwrap(), "YWJj");
    let response = backend
        .get_version(&ctx, "folder/file.txt", "v1", &header(&[("range", "bytes=0-1")]))
        .await
        .unwrap();
    assert_eq!(response.status, 206);
    let (body, _) = read_limited(response.body, 1024).await.unwrap();
    assert_eq!(&body[..], b"ab");
    backend.delete_version(&ctx, "folder/file.txt", "v1").await.unwrap();
    backend
        .restore_version(&ctx, "folder/file.txt", "v1", &HeaderMap::new())
        .await
        .unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 5);
    problems.check();
}

#[tokio::test]
async fn a_bad_version_page_token_is_refused() {
    let backend = anonymous_s3("http://127.0.0.1:1", "bucket");
    let error = backend
        .list_versions(&OpCtx::default(), "key", "%%%", 10)
        .await
        .unwrap_err();
    assert_eq!(error.status(), 400);
    assert_eq!(error.code(), "invalid_page_token");
    assert_eq!(error.public_message(), "version page token is invalid");
}

#[tokio::test]
async fn the_list_of_the_parts_follows_the_pages_and_sorts() {
    let problems = Arc::new(Problems::default());
    let seen = problems.clone();
    let server = TestServer::start(move |request| {
        if request.method != Method::GET || request.query.get("uploadId") != "upload-1" {
            seen.report(format!("unexpected request: {} {}?{}", request.method, request.path, request.raw_query));
            return TestResponse::status(400);
        }
        if request.query.get("part-number-marker").is_empty() {
            return TestResponse::body(
                200,
                "<ListPartsResult><IsTruncated>true</IsTruncated><NextPartNumberMarker>1</NextPartNumberMarker><Part><PartNumber>1</PartNumber><ETag>&quot;one&quot;</ETag><Size>5</Size></Part></ListPartsResult>",
            );
        }
        if request.query.get("part-number-marker") != "1" {
            seen.report(format!("marker = {:?}", request.query.get("part-number-marker")));
        }
        TestResponse::body(
            200,
            "<ListPartsResult><IsTruncated>false</IsTruncated><Part><PartNumber>2</PartNumber><ETag>&quot;two&quot;</ETag><Size>7</Size></Part></ListPartsResult>",
        )
    })
    .await;
    let backend = anonymous_s3(&server.url, "bucket");
    let parts = backend
        .list_parts(&OpCtx::default(), "large.bin", "upload-1")
        .await
        .unwrap();
    assert_eq!(parts.len(), 2);
    assert_eq!(parts[0].number, 1);
    assert_eq!(parts[1].etag, "two");
    assert_eq!(parts[1].size, 7);
    problems.check();
}

#[tokio::test]
async fn a_write_that_creates_only_uses_the_atomic_precondition() {
    let problems = Arc::new(Problems::default());
    let seen = problems.clone();
    let server = TestServer::start(move |request| {
        if request.method != Method::PUT {
            seen.report(format!("method = {}", request.method));
        }
        if request.header("if-none-match") != "*" {
            seen.report(format!("If-None-Match = {:?}", request.header("if-none-match")));
        }
        TestResponse::status(412)
    })
    .await;
    let backend = anonymous_s3(&server.url, "bucket");
    let error = backend
        .put_if_absent(&OpCtx::default(), "existing.txt", full("value"), 5, "text/plain")
        .await
        .unwrap_err();
    let api = error.as_api().unwrap();
    assert_eq!((api.status, api.code.as_str()), (409, "object_exists"));
    problems.check();
}

#[tokio::test]
async fn a_batch_delete_sends_one_delete_objects_request() {
    let problems = Arc::new(Problems::default());
    let body = Arc::new(Mutex::new(String::new()));
    let (seen, kept) = (problems.clone(), body.clone());
    let server = TestServer::start(move |request| {
        if request.method != Method::POST || !request.query.has("delete") || request.path != "/bucket" {
            seen.report(format!(
                "unexpected request: {} {}?{}",
                request.method, request.path, request.raw_query
            ));
        }
        let digest = STANDARD.encode(md5(&request.body));
        if request.header("content-md5") != digest {
            seen.report(format!("Content-MD5 = {:?}", request.header("content-md5")));
        }
        *kept.lock().unwrap() = request.text();
        TestResponse::body(200, "<DeleteResult/>").header("content-type", "application/xml")
    })
    .await;
    let backend = anonymous_s3(&server.url, "bucket");
    let keys = vec!["a/one.txt".to_owned(), "a/two & three.txt".to_owned()];
    backend.delete_many(&OpCtx::default(), &keys).await.unwrap();
    let text = body.lock().unwrap().clone();
    for want in [
        "<Quiet>true</Quiet>",
        "<Key>a/one.txt</Key>",
        "<Key>a/two &amp; three.txt</Key>",
    ] {
        assert!(text.contains(want), "body {text} lacks {want}");
    }
    problems.check();
}

#[tokio::test]
async fn a_batch_delete_reports_the_refused_keys_and_the_embedded_errors() {
    let cases = [
        (
            "per key",
            "<DeleteResult><Error><Key>a</Key><Code>AccessDenied</Code><Message>no</Message></Error><Error><Key>b</Key><Code>AccessDenied</Code><Message>no</Message></Error></DeleteResult>",
        ),
        (
            "embedded",
            "<Error><Code>InternalError</Code><Message>failed</Message></Error>",
        ),
    ];
    for (name, answer) in cases {
        let server = TestServer::start(move |_| TestResponse::body(200, answer)).await;
        let backend = anonymous_s3(&server.url, "bucket");
        let keys = vec!["a".to_owned(), "b".to_owned(), "c".to_owned()];
        let error = backend.delete_many(&OpCtx::default(), &keys).await.unwrap_err();
        if name == "per key" {
            let text = error.to_string();
            assert!(
                text.contains("AccessDenied") && text.contains("2 of 3"),
                "{name}: {text}"
            );
            let Error::BatchDelete(batch) = &error else {
                panic!("{name}: {error:?}");
            };
            assert_eq!(batch.failures.len(), 2);
            assert_eq!(batch.failures[1].key, "b");
            assert_eq!(error.status(), 502);
        } else {
            assert!(error.to_string().contains("InternalError: failed"), "{name}: {error}");
        }
    }
}

#[tokio::test]
async fn a_batch_delete_refuses_more_than_the_limit() {
    let backend = anonymous_s3("http://127.0.0.1:1", "bucket");
    let keys = vec![String::new(); super::s3::MAX_DELETE_BATCH + 1];
    assert!(backend.delete_many(&OpCtx::default(), &keys).await.is_err());
    assert!(backend.delete_many(&OpCtx::default(), &[]).await.is_ok());
}

#[tokio::test]
async fn a_listing_gives_the_objects_the_folders_and_the_next_token() {
    let problems = Arc::new(Problems::default());
    let seen = problems.clone();
    let server = TestServer::start(move |request| {
        let query = &request.query;
        let expected = [
            ("list-type", "2"),
            ("prefix", "a b/"),
            ("delimiter", "/"),
            ("max-keys", "2"),
            ("continuation-token", "token"),
            ("start-after", "a b/0"),
        ];
        for (name, value) in expected {
            if query.get(name) != value {
                seen.report(format!("{name} = {:?}", query.get(name)));
            }
        }
        TestResponse::body(
            200,
            r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><IsTruncated>true</IsTruncated>
<Contents><Key>a b/1.txt</Key><LastModified>2026-01-02T03:04:05.000Z</LastModified><ETag>"e1"</ETag><Size>12</Size></Contents>
<Contents><Key>a b/2.txt</Key><LastModified>2026-01-02T03:04:05Z</LastModified><ETag>&quot;e2&quot;</ETag><Size>0</Size></Contents>
<CommonPrefixes><Prefix>a b/sub/</Prefix></CommonPrefixes><NextContinuationToken>next</NextContinuationToken></ListBucketResult>"#,
        )
    })
    .await;
    let backend = anonymous_s3(&server.url, "bucket");
    let options = ListOptions {
        prefix: "a b/".to_owned(),
        delimiter: "/".to_owned(),
        max_results: 2,
        page_token: "token".to_owned(),
        start_after: "a b/0".to_owned(),
    };
    let page = backend.list(&OpCtx::default(), &options).await.unwrap();
    assert_eq!(page.objects.len(), 2);
    assert_eq!(page.objects[0].key, "a b/1.txt");
    assert_eq!(page.objects[0].size, 12);
    assert_eq!(page.objects[0].etag, "e1");
    assert_eq!(
        page.objects[0].last_modified,
        Timestamp::parse_rfc3339("2026-01-02T03:04:05Z")
    );
    assert_eq!(page.objects[1].etag, "e2");
    assert_eq!(page.prefixes, vec!["a b/sub/".to_owned()]);
    assert_eq!(page.next_page_token, "next");
    problems.check();

    let broken = TestServer::start(|_| {
        TestResponse::body(
            200,
            "<ListBucketResult><Contents><Size>x</Size></Contents></ListBucketResult>",
        )
    })
    .await;
    let error = anonymous_s3(&broken.url, "bucket")
        .list(&OpCtx::default(), &ListOptions::default())
        .await
        .unwrap_err();
    assert!(error.to_string().starts_with("decode s3 list response"), "{error}");
}

#[tokio::test]
async fn a_provider_error_gives_the_code_and_the_message_of_the_document() {
    let server = TestServer::start(|request| match request.path.as_str() {
        "/bucket/missing" => TestResponse::body(
            404,
            "<Error><Code>NoSuchKey</Code><Message>The key does not exist</Message></Error>",
        ),
        "/bucket/plain" => TestResponse::body(500, " plain text "),
        _ => TestResponse::status(403),
    })
    .await;
    let backend = anonymous_s3(&server.url, "bucket");
    let ctx = OpCtx::default();
    let error = backend.delete(&ctx, "missing").await.unwrap_err();
    let upstream = error.as_upstream().unwrap();
    assert_eq!(
        (upstream.status, upstream.code.as_str(), upstream.message.as_str()),
        (404, "NoSuchKey", "The key does not exist")
    );
    assert_eq!(
        error.public_message(),
        "the storage provider returned HTTP 404 (NoSuchKey)"
    );
    let error = backend.delete(&ctx, "plain").await.unwrap_err();
    assert_eq!(error.as_upstream().unwrap().message, "plain text");
    let error = backend.delete(&ctx, "other").await.unwrap_err();
    assert_eq!(error.as_upstream().unwrap().message, "403 Forbidden");

    let answer = backend
        .send(
            &ctx,
            S3Request {
                method: Method::GET,
                key: "missing",
                query: vec![("tagging".to_owned(), String::new())],
                headers: HeaderMap::new(),
                body: None,
            },
            1 << 20,
        )
        .await
        .unwrap();
    assert_eq!(answer.status, 404);
    let error = S3Backend::s3_error(&answer);
    assert_eq!(error.as_upstream().unwrap().code, "NoSuchKey");
}

#[tokio::test]
async fn a_head_without_the_checksum_mode_follows_a_refusal() {
    let calls = Arc::new(Mutex::new(Vec::new()));
    let recorded = calls.clone();
    let server = TestServer::start(move |request| {
        let mode = request.header("x-amz-checksum-mode").to_owned();
        recorded.lock().unwrap().push(mode.clone());
        if mode.is_empty() {
            TestResponse::status(200).header("content-length", "7")
        } else {
            TestResponse::status(400)
        }
    })
    .await;
    let backend = anonymous_s3(&server.url, "bucket");
    let head = backend.head(&OpCtx::default(), "object").await.unwrap();
    assert_eq!(head.headers.get("content-length").unwrap(), "7");
    assert_eq!(*calls.lock().unwrap(), vec!["ENABLED".to_owned(), String::new()]);
}

#[tokio::test]
async fn a_write_sends_the_checksum_and_the_tags_and_keeps_the_echo() {
    let problems = Arc::new(Problems::default());
    let seen = problems.clone();
    let server = TestServer::start(move |request| {
        for (name, value) in [
            ("x-amz-checksum-sha256", "c2hh"),
            ("x-amz-tagging", "a=1&b=x+y"),
            ("content-type", "text/plain"),
            ("content-length", "5"),
        ] {
            if request.header(name) != value {
                seen.report(format!("{name} = {:?}", request.header(name)));
            }
        }
        if request.text() != "value" {
            seen.report(format!("body = {:?}", request.text()));
        }
        TestResponse::status(200).header("x-amz-checksum-sha256", " c2hh ")
    })
    .await;
    let backend = anonymous_s3(&server.url, "bucket");
    let transfer = Arc::new(ChecksumTransfer {
        sha256: "c2hh".to_owned(),
        ..ChecksumTransfer::default()
    });
    let tags = vec![
        crate::lifecycle::Tag {
            key: "b".to_owned(),
            value: "x y".to_owned(),
        },
        crate::lifecycle::Tag {
            key: "a".to_owned(),
            value: "1".to_owned(),
        },
    ];
    let ctx = OpCtx {
        checksum: Some(transfer.clone()),
        upload_tags: Some(tags.into()),
        ..OpCtx::default()
    };
    backend
        .put(&ctx, "object.txt", full("value"), 5, "text/plain")
        .await
        .unwrap();
    assert_eq!(*transfer.echoed.lock().unwrap(), "c2hh");
    problems.check();
}

#[tokio::test]
async fn a_multipart_start_with_a_checksum_asks_for_the_algorithm() {
    let problems = Arc::new(Problems::default());
    let seen = problems.clone();
    let server = TestServer::start(move |request| {
        if request.header("x-amz-checksum-algorithm") != "SHA256" {
            seen.report(format!("algorithm = {:?}", request.header("x-amz-checksum-algorithm")));
        }
        TestResponse::body(
            200,
            "<InitiateMultipartUploadResult><UploadId> </UploadId></InitiateMultipartUploadResult>",
        )
    })
    .await;
    let backend = anonymous_s3(&server.url, "bucket");
    let ctx = OpCtx {
        checksum: Some(Arc::new(ChecksumTransfer::default())),
        ..OpCtx::default()
    };
    let error = backend.initiate(&ctx, "large.bin", "").await.unwrap_err();
    assert!(error.to_string().contains("did not return an upload id"), "{error}");
    problems.check();
}

/// The signature that a test server computes again from the request that it got.
fn signature_of(request: &TestRequest) -> String {
    let mut headers = request.headers.clone();
    headers.remove(AUTHORIZATION);
    let date = request.header("x-amz-date");
    let rfc3339 = format!(
        "{}-{}-{}T{}:{}:{}Z",
        &date[0..4],
        &date[4..6],
        &date[6..8],
        &date[9..11],
        &date[11..13],
        &date[13..15]
    );
    let uri: http::Uri = if request.raw_query.is_empty() {
        format!("http://{}{}", request.header("host"), request.raw_path)
    } else {
        format!(
            "http://{}{}?{}",
            request.header("host"),
            request.raw_path,
            request.raw_query
        )
    }
    .parse()
    .unwrap();
    let credentials = sigv4::Credentials {
        access_key_id: "test-id".to_owned(),
        secret_access_key: "test-secret".to_owned(),
        session_token: String::new(),
    };
    let unsigned = request.header("x-amz-content-sha256") == sigv4::UNSIGNED_PAYLOAD;
    sigv4::sign(
        &request.method,
        &uri,
        &mut headers,
        unsigned,
        &credentials,
        "test",
        Timestamp::parse_rfc3339(&rfc3339).unwrap(),
    )
    .unwrap();
    headers.get(AUTHORIZATION).unwrap().to_str().unwrap().to_owned()
}

#[tokio::test]
async fn a_signed_request_carries_the_signature_of_what_the_server_gets() {
    let problems = Arc::new(Problems::default());
    let seen = problems.clone();
    let server = TestServer::start(move |request| {
        let sent = request.header("authorization");
        if !sent.starts_with("AWS4-HMAC-SHA256 Credential=test-id/") || sent != signature_of(&request) {
            seen.report(format!(
                "{} {}: Authorization = {sent:?}",
                request.method, request.raw_path
            ));
        }
        TestResponse::body(200, "<ListBucketResult/>")
    })
    .await;
    let backend = signed_s3(&server.url, "my bucket");
    let ctx = OpCtx::default();
    let options = ListOptions {
        prefix: "a b+c/".to_owned(),
        ..ListOptions::default()
    };
    backend.list(&ctx, &options).await.unwrap();
    backend
        .put(&ctx, "dir/é file.txt", full("value"), 5, "text/plain")
        .await
        .unwrap();
    backend
        .get(&ctx, "dir/x", &header(&[("range", "bytes=0-1"), ("if-match", "\"e\"")]))
        .await
        .unwrap();
    problems.check();
}

#[tokio::test]
async fn the_permission_probe_reads_the_listing_and_the_first_object() {
    let server = TestServer::start(|request| {
        if request.method == Method::HEAD {
            return TestResponse::status(403);
        }
        if request.query.get("prefix") == "empty/" {
            return TestResponse::body(200, "<ListBucketResult/>");
        }
        if request.query.get("prefix") == "denied/" {
            return TestResponse::body(403, "<Error><Code>AccessDenied</Code></Error>");
        }
        if request.query.get("prefix") == "broken/" {
            return TestResponse::status(500);
        }
        TestResponse::body(
            200,
            "<ListBucketResult><Contents><Key>a</Key></Contents></ListBucketResult>",
        )
    })
    .await;
    let probe = |prefix: &str| {
        let mut backend = anonymous_s3(&server.url, "bucket");
        backend.cfg.root_prefix = prefix.to_owned();
        backend
    };
    let ctx = OpCtx::default();
    let found = probe("empty/").discover_capabilities(&ctx).await.unwrap();
    let read = &found.states["read"];
    assert_eq!(
        (read.state, read.allowed, read.verified),
        (CapabilityStateName::Unknown, true, false)
    );
    assert_eq!(found.permissions, vec!["s3:ListBucket".to_owned()]);
    assert_eq!(found.states["write"].state, CapabilityStateName::Unknown);
    assert!(found.states["write"].allowed);

    let found = probe("denied/").discover_capabilities(&ctx).await.unwrap();
    let read = &found.states["read"];
    assert_eq!(
        (read.state, read.allowed, read.verified),
        (CapabilityStateName::Denied, false, true)
    );
    assert_eq!(
        read.reason,
        "ListObjectsV2 failed: the storage provider returned HTTP 403 (AccessDenied)"
    );

    let found = probe("full/").discover_capabilities(&ctx).await.unwrap();
    let read = &found.states["read"];
    assert_eq!(
        (read.state, read.source.as_str()),
        (CapabilityStateName::Denied, "s3-read-probe")
    );
    assert_eq!(
        read.reason,
        "ListObjectsV2 succeeded but HeadObject failed: the storage provider returned HTTP 403"
    );

    assert!(probe("broken/").discover_capabilities(&ctx).await.is_err());
}

#[tokio::test]
async fn a_large_listing_parses_away_from_the_runtime() {
    let mut document = String::from("<ListBucketResult>");
    for index in 0..4000 {
        document.push_str(&format!(
            "<Contents><Key>folder/object-{index:05}.bin</Key><Size>{index}</Size><ETag>\"etag-{index}\"</ETag></Contents>"
        ));
    }
    document.push_str("</ListBucketResult>");
    assert!(document.len() > 256 << 10);
    let server = TestServer::start(move |_| TestResponse::body(200, document.clone())).await;
    let page = anonymous_s3(&server.url, "bucket")
        .list(&OpCtx::default(), &ListOptions::default())
        .await
        .unwrap();
    assert_eq!(page.objects.len(), 4000);
    assert_eq!(page.objects[3999].key, "folder/object-03999.bin");
    assert_eq!(page.objects[3999].size, 3999);
}
