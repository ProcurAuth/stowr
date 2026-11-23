//! The tests of the HTTP client: TLS with the fixture certificate, no redirect, the gzip of the answers, the time
//! limits and the cancel.

use std::io::Write as _;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::header::HeaderValue;
use http::{HeaderMap, Method};

use super::client::{StorageClient, Timeouts, build_request};
use super::test_server::{Problems, TestResponse, TestServer, test_roots};
use crate::common::ctx::OpCtx;
use crate::common::error::Error;
use crate::common::http::{channel, full, read_limited};

fn client(insecure: bool, roots: Arc<rustls::RootCertStore>) -> StorageClient {
    StorageClient::with_roots(insecure, roots, Timeouts::default()).unwrap()
}

fn get(url: &str) -> http::Request<crate::common::http::Body> {
    build_request(Method::GET, url, HeaderMap::new(), None).unwrap()
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

#[tokio::test]
async fn tls_works_with_the_roots_that_trust_the_server() {
    let server = TestServer::start_tls(|_| TestResponse::body(200, "secure")).await;
    let answer = client(false, test_roots())
        .fetch(&OpCtx::default(), get(&format!("{}/x", server.url)), 1024)
        .await
        .unwrap();
    assert_eq!((answer.status, &answer.body[..]), (200, &b"secure"[..]));
}

#[tokio::test]
async fn tls_refuses_a_certificate_that_the_roots_do_not_trust() {
    let server = TestServer::start_tls(|_| TestResponse::body(200, "secure")).await;
    let empty = Arc::new(rustls::RootCertStore::empty());
    let error = client(false, empty)
        .fetch(&OpCtx::default(), get(&format!("{}/x", server.url)), 1024)
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Connect(_)), "{error:?}");
    assert_eq!(
        error.public_message(),
        "unable to connect to or authenticate with the storage provider"
    );
}

#[tokio::test]
async fn insecure_skip_verify_accepts_a_certificate_that_the_roots_do_not_trust() {
    let server = TestServer::start_tls(|_| TestResponse::body(200, "accepted")).await;
    let empty = Arc::new(rustls::RootCertStore::empty());
    let answer = client(true, empty)
        .fetch(&OpCtx::default(), get(&format!("{}/x", server.url)), 1024)
        .await
        .unwrap();
    assert_eq!(&answer.body[..], b"accepted");
}

#[tokio::test]
async fn the_client_follows_no_redirect() {
    let server = TestServer::start(|request| {
        if request.path == "/moved" {
            TestResponse::status(302).header("location", "/target")
        } else {
            TestResponse::body(200, "target")
        }
    })
    .await;
    let answer = StorageClient::new(false)
        .unwrap()
        .fetch(&OpCtx::default(), get(&format!("{}/moved", server.url)), 1024)
        .await
        .unwrap();
    assert_eq!(answer.status, 302);
    assert_eq!(answer.header("location"), "/target");
}

#[tokio::test]
async fn a_gzip_answer_comes_back_decoded() {
    let text = "a line of text that repeats. ".repeat(4000);
    let compressed = Bytes::from(gzip(text.as_bytes()));
    let problems = Arc::new(Problems::default());
    let seen = problems.clone();
    let server = TestServer::start(move |request| {
        if request.path == "/range" {
            if !request.header("accept-encoding").is_empty() {
                seen.report(format!(
                    "Accept-Encoding with a range = {:?}",
                    request.header("accept-encoding")
                ));
            }
            return TestResponse::body(206, "abc");
        }
        if request.header("accept-encoding") != "gzip" {
            seen.report(format!("Accept-Encoding = {:?}", request.header("accept-encoding")));
        }
        TestResponse::body(200, compressed.clone()).header("content-encoding", "gzip")
    })
    .await;
    let client = StorageClient::new(false).unwrap();
    let answer = client
        .fetch(&OpCtx::default(), get(&format!("{}/text", server.url)), 1 << 20)
        .await
        .unwrap();
    assert_eq!(answer.body, text.as_bytes());
    assert!(answer.headers.get("content-encoding").is_none());
    assert!(answer.headers.get("content-length").is_none());
    let mut headers = HeaderMap::new();
    headers.insert("range", HeaderValue::from_static("bytes=0-2"));
    let request = build_request(Method::GET, &format!("{}/range", server.url), headers, None).unwrap();
    let answer = client.fetch(&OpCtx::default(), request, 1024).await.unwrap();
    assert_eq!(&answer.body[..], b"abc");
    problems.check();
}

#[tokio::test]
async fn a_broken_gzip_answer_is_an_error_and_an_asked_encoding_stays() {
    let server = TestServer::start(|request| {
        if request.path == "/identity" {
            return TestResponse::body(200, "raw").header("content-encoding", "gzip");
        }
        TestResponse::body(200, "not gzip at all").header("content-encoding", "gzip")
    })
    .await;
    let client = StorageClient::new(false).unwrap();
    let error = client
        .fetch(&OpCtx::default(), get(&format!("{}/broken", server.url)), 1024)
        .await
        .unwrap_err();
    assert!(error.to_string().starts_with("gzip:"), "{error}");
    let mut headers = HeaderMap::new();
    headers.insert("accept-encoding", HeaderValue::from_static("identity"));
    let request = build_request(Method::GET, &format!("{}/identity", server.url), headers, None).unwrap();
    let answer = client.fetch(&OpCtx::default(), request, 1024).await.unwrap();
    assert_eq!(&answer.body[..], b"raw");
    assert_eq!(answer.header("content-encoding"), "gzip");
}

#[tokio::test]
async fn the_headers_of_the_answer_have_a_time_limit() {
    let server = TestServer::start_async(Arc::new(|_| {
        Box::pin(async {
            tokio::time::sleep(Duration::from_secs(5)).await;
            TestResponse::status(200)
        })
    }))
    .await;
    let timeouts = Timeouts {
        headers: Duration::from_millis(200),
        ..Timeouts::default()
    };
    let client = StorageClient::with_roots(false, test_roots(), timeouts).unwrap();
    let started = std::time::Instant::now();
    let error = client
        .fetch(&OpCtx::default(), get(&format!("{}/slow", server.url)), 1024)
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("timeout awaiting response headers"),
        "{error}"
    );
    assert!(started.elapsed() < Duration::from_secs(3));
}

#[tokio::test]
async fn the_time_limit_of_the_headers_starts_after_the_body_of_the_request() {
    let server = TestServer::start(|request| TestResponse::body(200, format!("{} bytes", request.body.len()))).await;
    let timeouts = Timeouts {
        headers: Duration::from_millis(300),
        ..Timeouts::default()
    };
    let client = StorageClient::with_roots(false, test_roots(), timeouts).unwrap();
    let (sender, body) = channel(1);
    tokio::spawn(async move {
        for _ in 0..4 {
            tokio::time::sleep(Duration::from_millis(150)).await;
            if sender.send(Bytes::from_static(b"0123456789")).await.is_err() {
                return;
            }
        }
    });
    let request = build_request(
        Method::PUT,
        &format!("{}/upload", server.url),
        HeaderMap::new(),
        Some((body, 40)),
    )
    .unwrap();
    let answer = client.fetch(&OpCtx::default(), request, 1024).await.unwrap();
    assert_eq!(&answer.body[..], b"40 bytes");
}

#[tokio::test]
async fn an_error_of_the_body_of_the_request_comes_back_as_it_is() {
    let server = TestServer::start(|_| TestResponse::status(200)).await;
    let (sender, body) = channel(1);
    tokio::spawn(async move {
        sender.abort(Error::api(408, "upload_idle", "the upload stopped")).await;
    });
    let request = build_request(
        Method::PUT,
        &format!("{}/upload", server.url),
        HeaderMap::new(),
        Some((body, 10)),
    )
    .unwrap();
    let error = StorageClient::new(false)
        .unwrap()
        .send(&OpCtx::default(), request)
        .await
        .unwrap_err();
    assert!(error.has_code("upload_idle"), "{error:?}");
}

#[tokio::test]
async fn a_cancel_stops_the_request_and_the_body_of_the_answer() {
    let server = TestServer::start_async(Arc::new(|request| {
        Box::pin(async move {
            if request.path == "/wait" {
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
            TestResponse::body(200, "x")
        })
    }))
    .await;
    let client = StorageClient::new(false).unwrap();
    let ctx = OpCtx::default();
    let token = ctx.cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        token.cancel();
    });
    let error = client
        .send(&ctx, get(&format!("{}/wait", server.url)))
        .await
        .unwrap_err();
    assert_eq!(error, Error::Canceled);

    let ctx = OpCtx::default();
    let response = client.send(&ctx, get(&format!("{}/now", server.url))).await.unwrap();
    ctx.cancel.cancel();
    let error = read_limited(response.into_body(), 1024).await.unwrap_err();
    assert_eq!(error, Error::Canceled);

    let ctx = OpCtx::default().with_timeout(Duration::from_millis(100));
    let error = client
        .send(&ctx, get(&format!("{}/wait", server.url)))
        .await
        .unwrap_err();
    assert_eq!(error, Error::Timeout);
}

#[tokio::test]
async fn a_refused_connection_is_a_connection_error() {
    let error = StorageClient::new(false)
        .unwrap()
        .send(&OpCtx::default(), get("http://127.0.0.1:1/x"))
        .await
        .unwrap_err();
    assert!(matches!(error, Error::Connect(_)), "{error:?}");
}

#[tokio::test]
async fn a_request_without_a_body_sends_a_zero_length_except_get_and_head() {
    let server = TestServer::start(|request| {
        TestResponse::body(
            200,
            format!("{}|{}", request.header("content-length"), request.header("host")),
        )
    })
    .await;
    let client = StorageClient::new(false).unwrap();
    let host = server.url.trim_start_matches("http://").to_owned();
    for (method, want) in [
        (Method::GET, format!("|{host}")),
        (Method::DELETE, format!("0|{host}")),
        (Method::PUT, format!("0|{host}")),
    ] {
        let request = build_request(method.clone(), &format!("{}/x", server.url), HeaderMap::new(), None).unwrap();
        let answer = client.fetch(&OpCtx::default(), request, 1024).await.unwrap();
        assert_eq!(String::from_utf8_lossy(&answer.body), want, "{method}");
    }
    let request = build_request(
        Method::POST,
        &format!("{}/x", server.url),
        HeaderMap::new(),
        Some((full("abc"), 3)),
    )
    .unwrap();
    let answer = client.fetch(&OpCtx::default(), request, 1024).await.unwrap();
    assert_eq!(String::from_utf8_lossy(&answer.body), format!("3|{host}"));
}

#[tokio::test]
async fn an_answer_with_many_headers_is_read() {
    let server = TestServer::start(|_| {
        let mut reply = TestResponse::status(200);
        for index in 0..150 {
            reply.headers.insert(
                http::header::HeaderName::from_bytes(format!("x-amz-meta-key-{index}").as_bytes()).unwrap(),
                HeaderValue::from_static("value"),
            );
        }
        reply
    })
    .await;
    let answer = StorageClient::new(false)
        .unwrap()
        .fetch(&OpCtx::default(), get(&format!("{}/x", server.url)), 1024)
        .await
        .unwrap();
    assert_eq!(answer.header("x-amz-meta-key-149"), "value");
}
