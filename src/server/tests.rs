//! The route tests of the HTTP layer: each request goes through the whole dispatch over a back end in memory.

use std::collections::BTreeMap;
use std::io::Read as _;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, CONTENT_TYPE, ETAG, HeaderValue, LAST_MODIFIED};
use http::{HeaderMap, Method};
use http_body::Frame;
use http_body_util::BodyExt;

use super::testing::{TestRequest, TestResponse, app_of, app_with, bucket_config, get, instance, test_config};
use crate::common::BoxFuture;
use crate::common::app::App;
use crate::common::assets;
use crate::common::config::{PERMISSION_DELETE, PERMISSION_READ, PERMISSION_WRITE};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Body, read_limited};
use crate::common::query::{path_escape, query_escape};
use crate::common::storage::{Backend, DiscoveredCapabilities, ListOptions, ListPage, ObjectInfo, ObjectResponse};
use crate::common::time::Timestamp;

// ---------------------------------------------------------------------------------------------------------------
// A back end in memory that counts its calls and can answer ranges in the ways of the providers.
// ---------------------------------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct StoredObject {
    data: Bytes,
    content_type: String,
    modified: Timestamp,
}

#[derive(Debug, Default)]
struct FakeState {
    last: ListOptions,
    get_ranges: Vec<String>,
    get_count: usize,
    head_count: usize,
    list_calls: usize,
    ignore_ranges: bool,
    range_status_ok: bool,
    range_body_full: bool,
    list_pages: Vec<ListPage>,
    forbidden: String,
}

#[derive(Debug, Default)]
struct FakeBackend {
    objects: Mutex<BTreeMap<String, StoredObject>>,
    state: Mutex<FakeState>,
    bytes_read: Arc<AtomicU64>,
}

fn test_time() -> Timestamp {
    Timestamp::parse_rfc3339("2026-01-02T03:04:05Z").unwrap()
}

impl FakeBackend {
    fn with_objects(objects: &[(&str, &str)]) -> Arc<Self> {
        let backend = Self::default();
        for (key, text) in objects {
            backend.put_object(key, text.as_bytes(), "text/plain");
        }
        Arc::new(backend)
    }

    fn put_object(&self, key: &str, data: &[u8], content_type: &str) {
        self.objects.lock().unwrap().insert(
            key.to_owned(),
            StoredObject {
                data: Bytes::copy_from_slice(data),
                content_type: content_type.to_owned(),
                modified: test_time(),
            },
        );
    }

    fn data(&self, key: &str) -> Option<String> {
        self.objects
            .lock()
            .unwrap()
            .get(key)
            .map(|object| String::from_utf8_lossy(&object.data).into_owned())
    }

    fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.state.lock().unwrap()
    }

    fn headers(key: &str, object: &StoredObject, length: usize) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_str(&object.content_type).unwrap());
        headers.insert(CONTENT_LENGTH, HeaderValue::from(length));
        headers.insert(ETAG, HeaderValue::from_str(&format!("\"etag-{key}\"")).unwrap());
        headers.insert(
            LAST_MODIFIED,
            HeaderValue::from_str(&object.modified.http_date()).unwrap(),
        );
        headers.insert("set-cookie", HeaderValue::from_static("should-not-leak=1"));
        headers.insert("x-amz-meta-test", HeaderValue::from_static("visible"));
        headers
    }
}

/// A body that counts the bytes that the server reads from it.
struct CountingBody {
    data: Option<Bytes>,
    counter: Arc<AtomicU64>,
}

impl http_body::Body for CountingBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>>>> {
        match self.data.take() {
            Some(data) if !data.is_empty() => {
                self.counter.fetch_add(data.len() as u64, Ordering::SeqCst);
                Poll::Ready(Some(Ok(Frame::data(data))))
            }
            _ => Poll::Ready(None),
        }
    }
}

fn missing() -> Error {
    Error::upstream(404, "NotFound", "missing")
}

impl Backend for FakeBackend {
    fn list<'a>(&'a self, _ctx: &'a OpCtx, options: &'a ListOptions) -> BoxFuture<'a, Result<ListPage>> {
        Box::pin(async move {
            let mut state = self.state();
            state.last = options.clone();
            state.list_calls += 1;
            if !state.list_pages.is_empty() {
                let mut index = 0;
                if !options.page_token.is_empty() {
                    index = options
                        .page_token
                        .strip_prefix("page-")
                        .and_then(|number| number.parse::<usize>().ok())
                        .filter(|number| *number < state.list_pages.len())
                        .ok_or_else(|| Error::internal(format!("invalid test page token {:?}", options.page_token)))?;
                }
                return Ok(state.list_pages[index].clone());
            }
            drop(state);
            let objects = self.objects.lock().unwrap().clone();
            let mut page = ListPage::default();
            let mut prefixes = std::collections::BTreeSet::new();
            for (key, object) in &objects {
                if !key.starts_with(&options.prefix) || (!options.start_after.is_empty() && *key <= options.start_after)
                {
                    continue;
                }
                if !options.delimiter.is_empty() {
                    let rest = &key[options.prefix.len()..];
                    if let Some(index) = rest.find(&options.delimiter) {
                        prefixes.insert(format!(
                            "{}{}",
                            options.prefix,
                            &rest[..index + options.delimiter.len()]
                        ));
                        continue;
                    }
                }
                page.objects.push(ObjectInfo {
                    key: key.clone(),
                    size: object.data.len() as i64,
                    last_modified: Some(object.modified),
                    etag: format!("etag-{key}"),
                    content_type: object.content_type.clone(),
                    unreadable: false,
                });
            }
            page.prefixes = prefixes.into_iter().collect();
            Ok(page)
        })
    }

    fn head<'a>(&'a self, _ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<ObjectResponse>> {
        Box::pin(async move {
            self.state().head_count += 1;
            let object = self.objects.lock().unwrap().get(key).cloned().ok_or_else(missing)?;
            Ok(ObjectResponse {
                status: 200,
                headers: Self::headers(key, &object, object.data.len()),
                body: crate::common::http::empty(),
            })
        })
    }

    fn get<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        key: &'a str,
        headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        Box::pin(async move {
            let mut state = self.state();
            if !state.forbidden.is_empty() && state.forbidden == key {
                return Err(Error::upstream(403, "AccessDenied", ""));
            }
            let object = self.objects.lock().unwrap().get(key).cloned().ok_or_else(missing)?;
            let range = headers
                .get(http::header::RANGE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .to_owned();
            state.get_count += 1;
            state.get_ranges.push(range.clone());
            let full = object.data.clone();
            let mut data = object.data.clone();
            let mut status = 200;
            let mut content_range = String::new();
            let length = data.len();
            if let Some(raw) = range.trim().strip_prefix("bytes=").filter(|_| !state.ignore_ranges)
                && let Some((left, right)) = raw.split_once('-')
            {
                if left.is_empty() {
                    if let Ok(suffix) = right.parse::<usize>()
                        && suffix > 0
                        && length > 0
                    {
                        let start = length.saturating_sub(suffix);
                        content_range = format!("bytes {start}-{}/{length}", length - 1);
                        data = data.slice(start..length);
                        status = 206;
                    }
                } else {
                    let start = left.parse::<usize>();
                    let end = if right.trim().is_empty() {
                        Ok(length.saturating_sub(1))
                    } else {
                        right.parse::<usize>()
                    };
                    if let (Ok(start), Ok(end)) = (start, end)
                        && start < length
                        && end >= start
                    {
                        let end = end.min(length - 1);
                        content_range = format!("bytes {start}-{end}/{length}");
                        data = data.slice(start..=end);
                        status = 206;
                    }
                }
            }
            let mut response_headers = Self::headers(key, &object, data.len());
            if !content_range.is_empty() {
                response_headers.insert(
                    http::header::CONTENT_RANGE,
                    HeaderValue::from_str(&content_range).unwrap(),
                );
                if state.range_status_ok {
                    status = 200;
                }
                if state.range_body_full {
                    data = full;
                    response_headers.insert(CONTENT_LENGTH, HeaderValue::from(data.len()));
                }
            }
            let body = CountingBody {
                data: Some(data),
                counter: self.bytes_read.clone(),
            };
            Ok(ObjectResponse {
                status,
                headers: response_headers,
                body: body.boxed_unsync(),
            })
        })
    }

    fn put<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        key: &'a str,
        body: Body,
        _size: i64,
        content_type: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let (data, _) = read_limited(body, usize::MAX).await?;
            self.put_object(key, &data, content_type);
            Ok(())
        })
    }

    fn delete<'a>(&'a self, _ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.objects.lock().unwrap().remove(key);
            Ok(())
        })
    }

    fn copy<'a>(&'a self, _ctx: &'a OpCtx, source: &'a str, destination: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let mut objects = self.objects.lock().unwrap();
            let object = objects.get(source).cloned().ok_or_else(missing)?;
            objects.insert(destination.to_owned(), object);
            Ok(())
        })
    }

    fn discover_capabilities<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<DiscoveredCapabilities>> {
        Box::pin(async move { Ok(DiscoveredCapabilities::default()) })
    }
}

/// The application of the route tests over the back ends that count their calls: `readonly` and `rw` (root prefix `tenant/`).
struct TestApp {
    app: Arc<App>,
    readonly: Arc<FakeBackend>,
    rw: Arc<FakeBackend>,
}

fn rw_objects() -> Arc<FakeBackend> {
    FakeBackend::with_objects(&[
        ("tenant/folder/direct.txt", "direct"),
        ("tenant/folder/nested/deep.txt", "deep"),
        ("tenant/a//./../b\\c", "opaque"),
    ])
}

fn test_app_over(readonly: Arc<FakeBackend>, rw: Arc<FakeBackend>, max_scan_pages: u32) -> TestApp {
    let mut rw_config = bucket_config("rw", "tenant/", &[PERMISSION_READ, PERMISSION_WRITE, PERMISSION_DELETE]);
    rw_config.max_scan_pages = max_scan_pages;
    let app = app_of(vec![
        instance(bucket_config("readonly", "", &[PERMISSION_READ]), readonly.clone()),
        instance(rw_config, rw.clone()),
    ]);
    TestApp { app, readonly, rw }
}

fn test_app() -> TestApp {
    test_app_over(FakeBackend::with_objects(&[("readonly.txt", "read")]), rw_objects(), 0)
}

async fn post_json(app: &Arc<App>, target: &str, body: &str) -> TestResponse {
    TestRequest::new("POST", target)
        .header("content-type", "application/json")
        .body(body.to_owned())
        .send(app)
        .await
}

// ---------------------------------------------------------------------------------------------------------------
// The routes of the application.
// ---------------------------------------------------------------------------------------------------------------

#[test]
fn the_embedded_index_keeps_a_flat_table() {
    let html = String::from_utf8(assets::file("index.html").unwrap().to_vec()).unwrap();
    for required in ["assets/css/icons.css", "id=\"storageSwitcher\"", "assets/js/app.js"] {
        assert!(html.contains(required), "embedded index is missing {required:?}");
    }
    for forbidden in [" detailed", ":detailed", "#detail", "mdi-chevron-right folder-expander"] {
        assert!(
            !html.contains(forbidden),
            "embedded index contains table-detail markup {forbidden:?}"
        );
    }
}

#[tokio::test]
async fn the_instances_answer_shows_no_credential_and_no_endpoint() {
    let test = test_app();
    let answer = get(&test.app, "/api/instances").await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    let body = answer.text();
    for forbidden in ["internal.invalid", "secret_access_key", "access_key_id"] {
        assert!(!body.contains(forbidden), "response leaked {forbidden:?}: {body}");
    }
    let json = answer.json();
    assert_eq!(json["default"], "readonly");
    assert_eq!(json["instances"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn the_listing_scans_the_configured_pages_and_sorts_only_a_complete_scan() {
    let backend = rw_objects();
    backend.state().list_pages = vec![
        ListPage {
            objects: vec![ObjectInfo {
                key: "tenant/a.txt".to_owned(),
                size: 1,
                ..ObjectInfo::default()
            }],
            prefixes: vec![],
            next_page_token: "page-1".to_owned(),
        },
        ListPage {
            objects: vec![ObjectInfo {
                key: "tenant/b.txt".to_owned(),
                size: 2,
                ..ObjectInfo::default()
            }],
            prefixes: vec![],
            next_page_token: "page-2".to_owned(),
        },
        ListPage {
            objects: vec![ObjectInfo {
                key: "tenant/c.txt".to_owned(),
                size: 3,
                ..ObjectInfo::default()
            }],
            prefixes: vec![],
            next_page_token: String::new(),
        },
    ];
    let readonly = FakeBackend::with_objects(&[]);
    let limited = test_app_over(readonly.clone(), backend.clone(), 2);
    let answer = get(&limited.app, "/api/list?instance=rw&delimiter=/").await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    let json = answer.json();
    assert_eq!(json["scanComplete"], false);
    assert_eq!(json["sortAvailable"], false);
    assert_eq!(json["nextContinuationToken"], "page-2");
    assert_eq!(json["items"].as_array().unwrap().len(), 2);
    {
        let mut state = backend.state();
        assert_eq!(state.list_calls, 2);
        assert_eq!(state.last.max_results, super::api::PROVIDER_LIST_PAGE_SIZE);
        state.list_calls = 0;
    }

    let complete = test_app_over(readonly.clone(), backend.clone(), 3);
    let json = get(&complete.app, "/api/list?instance=rw&delimiter=/").await.json();
    assert_eq!(json["scanComplete"], true);
    assert_eq!(json["sortAvailable"], true);
    assert!(json.get("nextContinuationToken").is_none());
    assert_eq!(json["items"].as_array().unwrap().len(), 3);

    backend.state().list_calls = 0;
    let unlimited = test_app_over(readonly.clone(), backend.clone(), 0);
    let json = get(&unlimited.app, "/api/list?instance=rw&delimiter=/").await.json();
    assert_eq!(json["scanComplete"], true);
    assert_eq!(json["sortAvailable"], true);
    assert_eq!(json["items"].as_array().unwrap().len(), 3);
    assert_eq!(backend.state().list_calls, 3);

    let json = get(
        &unlimited.app,
        "/api/list?instance=rw&delimiter=/&continuationToken=page-2",
    )
    .await
    .json();
    assert_eq!(json["scanComplete"], true);
    assert_eq!(json["sortAvailable"], false);
    assert_eq!(json["items"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn permissions_apply_and_a_rename_copies_then_deletes() {
    let test = test_app();
    let forbidden = TestRequest::new("PUT", "/s3?instance=readonly&key=new.txt")
        .body("blocked")
        .send(&test.app)
        .await;
    assert_eq!(forbidden.status, 403);
    assert!(
        test.readonly.data("new.txt").is_none(),
        "the read-only back end changed"
    );

    let answer = post_json(
        &test.app,
        "/api/rename",
        r#"{"instance":"rw","src":"folder/direct.txt","dst":"folder/renamed.txt","isPrefix":false}"#,
    )
    .await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert_eq!(answer.text(), "{\"moved\":1}\n");
    assert!(
        test.rw.data("tenant/folder/direct.txt").is_none(),
        "source still exists after rename"
    );
    assert_eq!(test.rw.data("tenant/folder/renamed.txt").as_deref(), Some("direct"));
}

#[tokio::test]
async fn a_recursive_listing_uses_the_explicit_empty_delimiter() {
    let test = test_app();
    let answer = get(&test.app, "/api/list?instance=rw&prefix=folder%2F&delimiter=").await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    let json = answer.json();
    assert_eq!(json["delimiter"], "");
    assert_eq!(json["items"].as_array().unwrap().len(), 2);
    assert_eq!(test.rw.state().last.delimiter, "");
}

#[tokio::test]
async fn the_gateway_refuses_two_key_parameters() {
    let test = test_app();
    let answer = get(&test.app, "/s3?instance=rw&key=first&key=second").await;
    assert_eq!(answer.status, 400, "{}", answer.text());
    assert_eq!(answer.text(), "exactly one key query parameter is required\n");
    assert_eq!(answer.header("cache-control"), "no-store");
}

#[tokio::test]
async fn the_gateway_keeps_the_opaque_key_and_filters_the_headers() {
    let test = test_app();
    let answer = get(&test.app, "/s3?instance=rw&key=a%2F%2F.%2F..%2Fb%5Cc").await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert_eq!(answer.text(), "opaque");
    assert_eq!(answer.header("set-cookie"), "", "Set-Cookie leaked");
    assert_eq!(answer.header("x-amz-meta-test"), "visible");
    assert!(answer.header("content-security-policy").contains("sandbox"));
    // The provider headers come after the cache rule of the gateway.
    assert_eq!(answer.header_values("cache-control"), vec!["private, no-store"]);
    let trailers = answer.trailers.expect("the budget trailers");
    // The gateway reads the object with one provider call.
    assert_eq!(trailers["x-stowr-storage-requests"], "1");
    assert!(answer.headers.get_all("trailer").iter().count() == 3);
}

#[tokio::test]
async fn the_preview_gateway_infers_the_media_type_and_forces_inline() {
    let test = test_app();
    test.rw
        .put_object("tenant/video.mp4", b"0123456789", "application/octet-stream");
    let answer = TestRequest::get("/s3?instance=rw&preview=1&key=video.mp4")
        .header("range", "bytes=0-3")
        .send(&test.app)
        .await;
    assert_eq!(answer.status, 206, "{}", answer.text());
    assert_eq!(answer.header("content-type"), "video/mp4");
    assert!(answer.header("content-disposition").starts_with("inline"));
    assert_eq!(answer.header("accept-ranges"), "bytes");
    assert_eq!(answer.text(), "0123");
}

#[tokio::test]
async fn the_preview_gateway_refuses_an_ignored_range_without_reading_the_object() {
    let test = test_app();
    test.rw.state().ignore_ranges = true;
    test.rw
        .put_object("tenant/document.pdf", &vec![b'x'; 1 << 20], "application/pdf");
    let answer = TestRequest::get("/s3?instance=rw&preview=1&key=document.pdf")
        .header("range", "bytes=900000-900031")
        .send(&test.app)
        .await;
    assert_eq!(answer.status, 502, "{}", answer.text());
    assert!(answer.text().contains("refused to scan or buffer the complete object"));
    assert_eq!(test.rw.bytes_read.load(Ordering::SeqCst), 0);
    assert_eq!(test.rw.state().head_count, 0);
}

#[tokio::test]
async fn the_preview_gateway_refuses_a_full_body_with_a_misleading_content_range() {
    let test = test_app();
    {
        let mut state = test.rw.state();
        state.range_status_ok = true;
        state.range_body_full = true;
    }
    test.rw
        .put_object("tenant/document.pdf", &vec![b'x'; 1 << 20], "application/pdf");
    let answer = TestRequest::get("/s3?instance=rw&preview=1&key=document.pdf")
        .header("range", "bytes=900000-900031")
        .send(&test.app)
        .await;
    assert_eq!(answer.status, 502, "{}", answer.text());
    assert!(answer.text().contains("invalid byte count"));
    assert_eq!(test.rw.bytes_read.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn the_preview_gateway_answers_206_for_a_status_200_with_a_content_range() {
    let test = test_app();
    test.rw.state().range_status_ok = true;
    test.rw
        .put_object("tenant/document.pdf", b"0123456789", "application/pdf");
    let answer = TestRequest::get("/s3?instance=rw&preview=1&key=document.pdf")
        .header("range", "bytes=3-6")
        .send(&test.app)
        .await;
    assert_eq!(answer.status, 206, "{}", answer.text());
    assert_eq!(answer.header("content-range"), "bytes 3-6/10");
    assert_eq!(answer.header("content-length"), "4");
    assert_eq!(answer.text(), "3456");
    assert_eq!(test.rw.bytes_read.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn a_prefix_destination_cannot_be_inside_the_source() {
    let test = test_app();
    let answer = post_json(
        &test.app,
        "/api/copy",
        r#"{"instance":"rw","src":"folder/","dst":"folder/copy/","isPrefix":true}"#,
    )
    .await;
    assert_eq!(answer.status, 400);
    assert!(
        answer.text().contains("destination cannot be inside source"),
        "{}",
        answer.text()
    );
}

#[tokio::test]
async fn a_prefix_destination_cannot_contain_the_source() {
    let test = test_app();
    let answer = post_json(
        &test.app,
        "/api/copy",
        r#"{"instance":"rw","src":"folder/nested/","dst":"folder/","isPrefix":true}"#,
    )
    .await;
    assert_eq!(answer.status, 400);
    assert!(
        answer.text().contains("object paths would overlap"),
        "{}",
        answer.text()
    );
    assert_eq!(test.rw.data("tenant/folder/nested/deep.txt").as_deref(), Some("deep"));
}

#[tokio::test]
async fn storage_errors_of_the_api_do_not_show_the_request_url() {
    let error = Error::Connect(
        "s3 request failed: Get \"https://internal.example.test/private?credential=secret\": dial failed".to_owned(),
    );
    let answer = super::testing::collect(crate::common::http::api_error(&error)).await;
    assert!(!answer.text().contains("internal.example.test"), "{}", answer.text());
    assert!(!answer.text().contains("credential"));
    assert_eq!(answer.header("cache-control"), "no-store");
}

#[tokio::test]
async fn a_folder_listing_reads_no_object_header() {
    let test = test_app();
    let answer = get(&test.app, "/api/list?instance=rw&prefix=folder%2F&delimiter=%2F").await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    let state = test.rw.state();
    assert_eq!((state.get_count, state.head_count), (0, 0));
}

#[tokio::test]
async fn the_page_policy_allows_only_same_origin_documents_and_no_plugin() {
    let test = test_app();
    let policy = get(&test.app, "/").await.header("content-security-policy").to_owned();
    assert!(policy.contains("object-src 'none'"), "{policy}");
    for broad in ["object-src *", "object-src https:", "object-src 'self'"] {
        assert!(!policy.contains(broad), "CSP is too broad: {policy}");
    }
}

#[tokio::test]
async fn the_page_policy_forbids_script_evaluation() {
    let test = test_app();
    let policy = get(&test.app, "/").await.header("content-security-policy").to_owned();
    assert!(
        !policy.contains("unsafe-eval") && !policy.contains("unsafe-inline'; style"),
        "{policy}"
    );
    assert!(policy.contains("script-src 'self';"), "{policy}");
}

#[tokio::test]
async fn a_plain_get_of_a_native_pdf_preview_is_not_made_partial() {
    let test = test_app();
    test.rw.put_object(
        "tenant/document.pdf",
        b"%PDF-1.7\nsmall test document",
        "application/pdf",
    );
    let answer = get(&test.app, "/s3?instance=rw&preview=1&key=document.pdf").await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert_eq!(answer.header("content-range"), "");
    assert_eq!(test.rw.state().get_ranges, vec![String::new()]);
}

#[tokio::test]
async fn a_range_only_preview_refuses_unbounded_requests_before_the_storage_read() {
    for range in ["", "bytes=0-", "bytes=-99999999", "bytes=0-99999999", "bytes=0-1,4-5"] {
        let test = test_app();
        let mut request = TestRequest::get("/s3?instance=rw&preview=1&range_only=1&key=document.pdf");
        if !range.is_empty() {
            request = request.header("range", range);
        }
        let answer = request.send(&test.app).await;
        assert_eq!(answer.status, 416, "{range:?}: {}", answer.text());
        assert_eq!(answer.header("cache-control"), "no-store");
        assert_eq!(answer.header("accept-ranges"), "bytes");
        assert_eq!(answer.json()["error"], "bounded_range_required");
        assert_eq!(test.rw.state().get_count, 0);
        assert_eq!(test.rw.bytes_read.load(Ordering::SeqCst), 0);
    }
}

#[tokio::test]
async fn a_range_only_preview_allows_an_exact_bounded_range() {
    let test = test_app();
    test.rw
        .put_object("tenant/document.pdf", b"0123456789", "application/pdf");
    let answer = TestRequest::get("/s3?instance=rw&preview=1&range_only=1&key=document.pdf")
        .header("range", "bytes=2-5")
        .send(&test.app)
        .await;
    assert_eq!((answer.status, answer.text().as_str()), (206, "2345"));
}

#[tokio::test]
async fn the_routes_are_at_the_root_for_a_proxy_that_strips_a_prefix() {
    let test = test_app();
    for path in ["/", "/api/instances", "/healthz"] {
        let answer = get(&test.app, path).await;
        assert_eq!(answer.status, 200, "GET {path}: {}", answer.text());
        assert_eq!(answer.header("x-content-type-options"), "nosniff", "GET {path}");
    }
    let answer = get(&test.app, "/api/instances").await;
    assert!(!answer.text().contains("maxScanPages"), "{}", answer.text());
}

#[test]
fn the_base_address_of_the_friendly_routes() {
    for (path, want) in [
        ("/", "./"),
        ("/index.html", "./"),
        ("/preview.html", "./"),
        ("/-/host/api/", "../../../"),
        ("/-/host/api/folder/", "../../../../"),
        ("/-/host/api/file.pdf", "../../../"),
        ("/-/host/api/folder/file.pdf", "../../../../"),
    ] {
        assert_eq!(super::frontend::frontend_base_href(path), want, "{path}");
    }
}

fn friendly_app() -> Arc<App> {
    let mut api = bucket_config("api", "", &[]);
    api.auth_id = "host".to_owned();
    let mut dash = bucket_config("-", "", &[]);
    dash.auth_id = "-".to_owned();
    app_of(vec![
        instance(api, FakeBackend::with_objects(&[])),
        instance(dash, FakeBackend::with_objects(&[])),
    ])
}

#[tokio::test]
async fn the_friendly_storage_routes_serve_the_pages() {
    let app = friendly_app();
    let cases: [(&str, u16, &str, &str, &str, &str); 9] = [
        ("/", 200, "id=\"browser\"", "<base href=\"./\" />", "", "text/html"),
        ("/-/host/api", 308, "", "", "api/", ""),
        (
            "/-/host/api/",
            200,
            "id=\"browser\"",
            "<base href=\"../../../\" />",
            "",
            "text/html",
        ),
        (
            "/-/-/-/",
            200,
            "id=\"browser\"",
            "<base href=\"../../../\" />",
            "",
            "text/html",
        ),
        (
            "/-/host/api/folder/",
            200,
            "id=\"browser\"",
            "<base href=\"../../../../\" />",
            "",
            "text/html",
        ),
        (
            "/-/host/api/document.pdf",
            200,
            "class=\"preview-root\"",
            "<base href=\"../../../\" />",
            "",
            "text/html",
        ),
        (
            "/-/host/api/folder/document.pdf",
            200,
            "class=\"preview-root\"",
            "<base href=\"../../../../\" />",
            "",
            "text/html",
        ),
        ("/-/api/", 404, "", "", "", ""),
        ("/-/missing/", 404, "", "", "", ""),
    ];
    for (path, status, content, base, location, content_type) in cases {
        let answer = get(&app, path).await;
        assert_eq!(answer.status, status, "GET {path}: {}", answer.text());
        if !location.is_empty() {
            assert_eq!(answer.header("location"), location, "GET {path}");
        }
        let body = answer.text();
        assert!(body.contains(content), "GET {path} lacks {content:?}");
        assert!(body.contains(base), "GET {path} lacks the base {base:?}");
        assert!(answer.header("content-type").contains(content_type), "GET {path}");
    }
    let redirect = get(&app, "/-/host/api?info&x=1").await;
    assert_eq!(redirect.header("location"), "api/?info&x=1");
}

#[tokio::test]
async fn the_object_routes_of_this_folder_refuse_a_write_only_instance() {
    let test = test_app();
    let backend = FakeBackend::with_objects(&[("a.txt", "secret")]);
    let mut config = bucket_config("wo", "", &[PERMISSION_WRITE]);
    config.name = "wo".to_owned();
    let app = app_of(vec![
        instance(bucket_config("readonly", "", &[PERMISSION_READ]), test.readonly.clone()),
        instance(config, backend.clone()),
    ]);
    for endpoint in ["/api/list", "/api/stats", "/s3", "/open/"] {
        let answer = get(
            &app,
            &format!("{endpoint}?instance=wo&key=a.txt&q=secret&entry=x&prefix=&size=6"),
        )
        .await;
        assert_eq!(answer.status, 403, "{endpoint}: {}", answer.text());
    }
    let state = backend.state();
    assert_eq!((state.get_count, state.head_count, state.list_calls), (0, 0, 0));
}

#[tokio::test]
#[ignore = "needs the routes of the job manager and of the previews"]
async fn each_object_read_route_refuses_a_write_only_instance() {
    let backend = FakeBackend::with_objects(&[("a.txt", "secret")]);
    let app = app_of(vec![
        instance(
            bucket_config("readonly", "", &[PERMISSION_READ]),
            FakeBackend::with_objects(&[]),
        ),
        instance(bucket_config("wo", "", &[PERMISSION_WRITE]), backend.clone()),
    ]);
    for endpoint in [
        "/api/list",
        "/api/stats",
        "/api/archive",
        "/api/spreadsheet",
        "/api/delimited",
        "/api/document-count",
        "/api/document/word",
        "/api/parquet",
        "/api/json/raw",
        "/api/json/beautify",
        "/api/json/summary",
        "/api/json/tree",
        "/api/search",
        "/api/media-info",
        "/api/structured-preview",
        "/api/archive-preview",
        "/api/archive-entry",
        "/api/inspect",
        "/api/image-preview",
        "/s3",
        "/open/",
    ] {
        let answer = get(
            &app,
            &format!("{endpoint}?instance=wo&key=a.txt&q=secret&entry=x&prefix=&size=6"),
        )
        .await;
        assert_eq!(answer.status, 403, "{endpoint}: {}", answer.text());
    }
    let state = backend.state();
    assert_eq!((state.get_count, state.head_count, state.list_calls), (0, 0, 0));
}

#[tokio::test]
async fn the_denial_of_one_object_does_not_stop_other_requests() {
    let backend = FakeBackend::with_objects(&[("tenant/ok.txt", "ok")]);
    backend.state().forbidden = "tenant/secret.txt".to_owned();
    let test = test_app_over(FakeBackend::with_objects(&[]), backend, 0);
    assert_eq!(get(&test.app, "/s3?instance=rw&key=secret.txt").await.status, 403);
    assert_eq!(get(&test.app, "/s3?instance=rw&key=ok.txt").await.status, 200);
    // The permissions of the configuration stay hard gates.
    assert!(
        test.app
            .instance("readonly")
            .unwrap()
            .require_permission(PERMISSION_WRITE)
            .is_err()
    );
}

#[tokio::test]
async fn a_denial_of_one_object_is_a_short_hint_of_the_permissions() {
    let backend = FakeBackend::with_objects(&[("tenant/ok.txt", "ok")]);
    backend.state().forbidden = "tenant/secret.txt".to_owned();
    let test = test_app_over(FakeBackend::with_objects(&[]), backend, 0);
    let instance = test.app.instance("rw").unwrap().clone();
    assert_eq!(get(&test.app, "/s3?instance=rw&key=secret.txt").await.status, 403);
    let read = instance.capability(PERMISSION_READ);
    assert_eq!(read.state, crate::common::storage::CapabilityStateName::Denied);
    assert_eq!(read.source, "provider");
    assert_eq!(get(&test.app, "/s3?instance=rw&key=ok.txt").await.status, 200);
    assert_eq!(
        instance.capability(PERMISSION_READ).state,
        crate::common::storage::CapabilityStateName::Allowed
    );
}

#[tokio::test]
async fn the_depth_of_a_page_is_capped() {
    let deep = format!("/-/host/bucket/{}x", "/".repeat(5000));
    assert_eq!(
        super::frontend::frontend_base_href(&deep).matches("../").count(),
        super::frontend::MAX_FRONTEND_DEPTH
    );
    let test = test_app();
    for target in [
        deep.clone(),
        format!("{deep}/"),
        format!("/{}index.html", "a/".repeat(super::frontend::MAX_FRONTEND_DEPTH + 1)),
    ] {
        let answer = get(&test.app, &target).await;
        assert_eq!(answer.status, 404, "path of {} bytes", target.len());
    }
    let deepest = "../".repeat(super::frontend::MAX_FRONTEND_DEPTH);
    assert!(
        !super::frontend::static_cache().has_variant(&deepest),
        "refused paths left a prepared answer"
    );
    // The byte budget stops the cache; the answer is still made.
    let cache = super::frontend::PreparedCache::default();
    let block = vec![0u8; super::frontend::STATIC_CACHE_BYTE_LIMIT / 4];
    for index in 0..8 {
        let entry = cache
            .prepared("v", "big.html", &index.to_string(), || Ok(block.clone()))
            .unwrap();
        assert_eq!(entry.data.len(), block.len());
    }
    assert!(cache.usage().1 <= super::frontend::STATIC_CACHE_BYTE_LIMIT);
}

#[test]
fn the_request_log_hides_object_paths_and_escapes_control_bytes() {
    let mut lines = Vec::new();
    for path in [
        b"/-/host/bucket/customers/secret-report.pdf".as_slice(),
        b"/healthz\nGET /forged 200",
        b"/healthz\n\x1b[31mforged",
    ] {
        let line = super::middleware::LogLine {
            method: Method::GET,
            path: super::middleware::logged_request_path(crate::common::config::LogMode::Anonymous, path),
            status: 200,
            started: std::time::Instant::now(),
            identity: None,
        };
        lines.push(line.text(0));
    }
    let logged = lines.join("\n");
    assert!(
        !logged.contains("secret-report") && logged.contains("\"/-/<path>\""),
        "{logged}"
    );
    assert_eq!(logged.matches('\n').count(), 2, "{logged}");
    assert!(!logged.contains('\u{1b}'), "{logged}");
    assert!(lines[0].starts_with("GET \"/-/<path>\" 200 0B "), "{}", lines[0]);
}

// ---------------------------------------------------------------------------------------------------------------
// The same-origin check, the budget and the gates.
// ---------------------------------------------------------------------------------------------------------------

fn header_map(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
        headers.append(
            http::header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }
    headers
}

async fn refusal_text(response: Option<crate::common::http::Response>) -> (u16, String) {
    match response {
        Some(response) => {
            let answer = super::testing::collect(response).await;
            (answer.status, answer.text())
        }
        None => (204, String::new()),
    }
}

#[tokio::test]
async fn the_same_origin_check_refuses_a_cross_site_browser_request() {
    let refusal = super::middleware::same_origin_refusal(
        &Method::POST,
        &header_map(&[("sec-fetch-site", "cross-site")]),
        "browser.example",
    );
    let (status, body) = refusal_text(refusal).await;
    assert_eq!(status, 403);
    assert!(body.contains("cross_site_request_blocked"), "{body}");
}

#[tokio::test]
async fn the_same_origin_check_uses_the_host_of_the_request_not_the_forwarded_host() {
    let refusal = super::middleware::same_origin_refusal(
        &Method::POST,
        &header_map(&[
            ("origin", "https://attacker.example"),
            ("x-forwarded-host", "attacker.example"),
        ]),
        "internal.example",
    );
    let (status, body) = refusal_text(refusal).await;
    assert_eq!(status, 403);
    assert!(body.contains("origin_mismatch"), "{body}");
}

#[tokio::test]
async fn the_same_origin_check_lets_a_matching_origin_pass() {
    let refusal = super::middleware::same_origin_refusal(
        &Method::POST,
        &header_map(&[("origin", "https://browser.example")]),
        "browser.example",
    );
    assert!(refusal.is_none());
    let test = test_app();
    let answer = TestRequest::new("POST", "/api/delete-prefix")
        .header("host", "browser.example")
        .header("origin", "https://browser.example")
        .body("{\"instance\":\"rw\",\"prefix\":\"\"}")
        .send(&test.app)
        .await;
    assert_eq!(answer.status, 400, "{}", answer.text());
    assert_eq!(answer.json()["error"]["code"], "invalid_prefix");
}

#[tokio::test]
async fn trace_is_not_a_safe_method_for_the_cross_site_check() {
    let refusal = super::middleware::same_origin_refusal(
        &Method::TRACE,
        &header_map(&[("sec-fetch-site", "cross-site")]),
        "browser.example",
    );
    assert_eq!(refusal_text(refusal).await.0, 403);
}

#[test]
fn the_budget_of_a_request_refuses_calls_and_bytes_over_its_ceilings() {
    let budget = crate::instance::budget::Budget::new(1, 4);
    assert!(budget.consume_request().is_ok());
    assert!(budget.consume_request().is_err());
    let error = budget.consume_bytes(6).unwrap_err();
    assert_eq!(error.status(), 429);
    assert_eq!(error.code(), "resource_budget_exceeded");
}

#[tokio::test]
async fn a_gate_wait_follows_a_canceled_request() {
    let gate = crate::instance::gate::Gate::new(1);
    let ctx = OpCtx::default();
    let _held = crate::instance::gate::acquire(&ctx, &[&gate]).await.unwrap();
    let canceled = OpCtx::default();
    canceled.cancel.cancel();
    assert!(crate::instance::gate::acquire(&canceled, &[&gate]).await.is_err());
}

// ---------------------------------------------------------------------------------------------------------------
// The gzip of the JSON answers.
// ---------------------------------------------------------------------------------------------------------------

async fn through_gzip_json(path: &str, accept: &str, response: crate::common::http::Response) -> TestResponse {
    let headers = if accept.is_empty() {
        HeaderMap::new()
    } else {
        header_map(&[("accept-encoding", accept)])
    };
    let response = if super::compress::gzip_json_applies(path, &Method::GET, &headers) {
        super::compress::gzip_json(response).await
    } else {
        response
    };
    super::testing::collect(response).await
}

fn gunzip(data: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::new();
    flate2::read::GzDecoder::new(data).read_to_end(&mut decoded).unwrap();
    decoded
}

#[tokio::test]
async fn gzip_compresses_the_large_json_answers_of_the_api() {
    let payload = serde_json::json!({ "items": "object-name-".repeat(400) });
    let answer = through_gzip_json("/api/list", "gzip", crate::common::http::json(200, &payload)).await;
    assert_eq!(answer.header("content-encoding"), "gzip");
    assert_eq!(answer.header_values("vary"), vec!["Accept-Encoding"]);
    let decoded = String::from_utf8(gunzip(&answer.body)).unwrap();
    assert!(decoded.contains("object-name-object-name-") && decoded.ends_with("}\n"));
    assert_eq!(answer.status, 200);
    assert_eq!(answer.header("content-type"), "application/json; charset=utf-8");
}

#[tokio::test]
async fn gzip_leaves_the_other_answers_alone() {
    let large = Bytes::from(vec![b'x'; 4096]);
    let typed = |content_type: &'static str, encoding: Option<&'static str>| {
        let mut headers = header_map(&[("content-type", content_type)]);
        if let Some(encoding) = encoding {
            headers.insert("content-encoding", HeaderValue::from_static(encoding));
        }
        crate::common::http::answer(200, headers, crate::common::http::full(large.clone()))
    };
    let small = crate::common::http::json(400, &serde_json::json!({ "error": "bad" }));
    let answer = through_gzip_json("/api/list", "gzip", small).await;
    assert_eq!((answer.status, answer.header("content-encoding")), (400, ""));
    assert_eq!(answer.body, Bytes::from_static(b"{\"error\":\"bad\"}\n"));
    for (path, accept, response) in [
        ("/api/list", "", typed("application/json", None)),
        ("/api/archive", "gzip", typed("application/zip", None)),
        ("/s3", "gzip", typed("application/json", None)),
        ("/api/list", "gzip", typed("application/json", Some("br"))),
    ] {
        let answer = through_gzip_json(path, accept, response).await;
        assert_ne!(answer.header("content-encoding"), "gzip", "{path}");
        assert_eq!(answer.status, 200);
        assert_eq!(answer.body, large, "{path}");
    }
}

#[tokio::test]
async fn the_gateway_relays_each_byte_of_a_large_object() {
    let test = test_app();
    let data = "0123456789".repeat(100_000);
    test.rw
        .put_object("tenant/large.bin", data.as_bytes(), "application/octet-stream");
    let answer = get(&test.app, "/s3?instance=rw&key=large.bin").await;
    assert_eq!(answer.status, 200);
    assert_eq!(answer.body.len(), data.len());
    assert_eq!(answer.body, Bytes::from(data));
}

#[test]
fn a_prepared_answer_is_built_one_time_for_each_variant() {
    let version = format!("test-version-{:?}", std::time::Instant::now());
    let builds = AtomicUsize::new(0);
    let build = |variant: &'static str| {
        let builds = &builds;
        move || {
            builds.fetch_add(1, Ordering::SeqCst);
            Ok(variant.as_bytes().to_vec())
        }
    };
    let cache = super::frontend::static_cache();
    let first = cache.prepared(&version, "index.html", "./", build("a")).unwrap();
    let again = cache.prepared(&version, "index.html", "./", build("a")).unwrap();
    let other = cache.prepared(&version, "index.html", "../", build("b")).unwrap();
    assert!(Arc::ptr_eq(&first, &again), "the cache built the prepared answer again");
    assert!(!Arc::ptr_eq(&first, &other));
    assert_eq!(&other.data[..], b"b");
    assert_eq!(builds.load(Ordering::SeqCst), 2);
}

// ---------------------------------------------------------------------------------------------------------------
// The embedded interface: gzip, validators, fingerprints, 404.
// ---------------------------------------------------------------------------------------------------------------

async fn fetch(app: &Arc<App>, path: &str, headers: &[(&str, &str)]) -> TestResponse {
    let mut request = TestRequest::get(path);
    for (name, value) in headers {
        request = request.header(name, value);
    }
    request.send(app).await
}

#[tokio::test]
async fn embedded_assets_get_gzip_when_the_client_accepts_it() {
    let test = test_app();
    let original = assets::file("assets/css/dialogs.css").unwrap();
    let plain = fetch(&test.app, "/assets/css/dialogs.css", &[]).await;
    assert_eq!((plain.status, plain.header("content-encoding")), (200, ""));
    assert_eq!(&plain.body[..], original);
    let compressed = fetch(&test.app, "/assets/css/dialogs.css", &[("accept-encoding", "br, gzip")]).await;
    assert_eq!(compressed.header("content-encoding"), "gzip");
    assert_eq!(
        compressed.header("content-length"),
        "",
        "the identity length must not stay"
    );
    assert_eq!(
        compressed.header_values("vary").first().map(String::as_str),
        Some("Accept-Encoding")
    );
    assert_eq!(gunzip(&compressed.body), original);
    assert!(compressed.body.len() < original.len());
}

#[tokio::test]
async fn embedded_html_gets_gzip_and_keeps_its_base_address() {
    let test = test_app();
    let answer = fetch(&test.app, "/index.html", &[("accept-encoding", "gzip")]).await;
    assert_eq!(answer.header("content-encoding"), "gzip");
    let decoded = String::from_utf8(gunzip(&answer.body)).unwrap();
    assert!(
        decoded.contains("<base href=\"./\""),
        "{}",
        &decoded[..120.min(decoded.len())]
    );
}

#[tokio::test]
async fn the_gzip_of_the_interface_skips_ranges_refusals_and_heads() {
    let test = test_app();
    let ranged = fetch(
        &test.app,
        "/assets/css/dialogs.css",
        &[("accept-encoding", "gzip"), ("range", "bytes=0-9")],
    )
    .await;
    assert_eq!(ranged.status, 206);
    assert_eq!(ranged.header("content-encoding"), "");
    assert_eq!(ranged.body.len(), 10);
    let refused = fetch(
        &test.app,
        "/assets/css/dialogs.css",
        &[("accept-encoding", "gzip;q=0, identity")],
    )
    .await;
    assert_eq!(refused.header("content-encoding"), "");
    let head = TestRequest::new("HEAD", "/assets/css/dialogs.css")
        .header("accept-encoding", "gzip")
        .send(&test.app)
        .await;
    assert_eq!(head.header("content-encoding"), "");
    assert!(head.body.is_empty());
    assert_eq!(
        head.header("content-length"),
        assets::file("assets/css/dialogs.css").unwrap().len().to_string()
    );
}

#[tokio::test]
async fn the_gzip_of_the_interface_covers_svg_assets() {
    let test = test_app();
    let answer = fetch(&test.app, "/favicon.svg", &[("accept-encoding", "gzip")]).await;
    assert_eq!(answer.status, 200);
    assert_eq!(answer.header("content-encoding"), "gzip");
}

#[tokio::test]
async fn first_party_assets_revalidate_with_a_weak_etag() {
    let test = test_app();
    for name in [
        "/assets/css/dialogs.css",
        "/assets/js/app.js",
        "/assets/icons/tabler/folder.svg",
        "/",
    ] {
        let first = fetch(&test.app, name, &[]).await;
        assert_eq!(first.status, 200, "{name}");
        let etag = first.header("etag").to_owned();
        assert!(etag.starts_with("W/\""), "{name}: ETag = {etag:?}");
        assert_eq!(first.header("cache-control"), "no-cache", "{name}");
        let again = fetch(&test.app, name, &[("if-none-match", &etag)]).await;
        assert_eq!((again.status, again.body.len()), (304, 0), "{name}");
        let gzipped = fetch(&test.app, name, &[("accept-encoding", "gzip")]).await;
        assert_eq!(
            gzipped.header("etag"),
            etag,
            "{name}: the gzip form keeps the weak ETag"
        );
    }
}

#[tokio::test]
async fn vendored_assets_are_immutable() {
    let test = test_app();
    let answer = fetch(&test.app, "/assets/vendor/marked/12.0.2/marked.min.js", &[]).await;
    assert_eq!(answer.status, 200);
    assert_eq!(answer.header("cache-control"), "public, max-age=31536000, immutable");
}

#[tokio::test]
async fn unknown_addresses_get_the_styled_404_for_browsers_only() {
    let test = test_app();
    let page = fetch(
        &test.app,
        "/-/no-such-host/no-such-bucket/",
        &[("accept", "text/html,application/xhtml+xml")],
    )
    .await;
    assert_eq!(page.status, 404);
    assert_eq!(page.header("content-type"), "text/html; charset=utf-8");
    let body = page.text();
    assert!(
        body.contains("Page not found") && !body.contains("{{APP_BASE}}"),
        "{body}"
    );
    let plain = fetch(&test.app, "/-/no-such-host/no-such-bucket/", &[]).await;
    assert_eq!((plain.status, plain.text().as_str()), (404, "404 page not found\n"));
    let missing = fetch(
        &test.app,
        "/assets/css/missing.css",
        &[("accept", "text/css,*/*;q=0.1")],
    )
    .await;
    assert_eq!((missing.status, missing.text().as_str()), (404, "404 page not found\n"));
}

/// The fingerprint that a page announces in `<meta name="bb-asset-version" content="...">`.
fn announced_version(body: &str) -> String {
    let marker = "name=\"bb-asset-version\" content=\"";
    let start = body.find(marker).expect("the page announces its asset version") + marker.len();
    let version: String = body[start..]
        .chars()
        .take_while(|character| *character != '"')
        .collect();
    assert_eq!(version.len(), 12);
    assert!(version.chars().all(|character| character.is_ascii_hexdigit()));
    version
}

/// Each value of `href="assets/..."` and `src="assets/..."` of a page.
fn asset_references(body: &str) -> Vec<String> {
    let mut found = Vec::new();
    for marker in ["href=\"assets/", "src=\"assets/"] {
        let mut rest = body;
        while let Some(index) = rest.find(marker) {
            let start = index + marker.len() - "assets/".len();
            let value: String = rest[start..]
                .chars()
                .take_while(|character| *character != '"')
                .collect();
            found.push(value);
            rest = &rest[index + marker.len()..];
        }
    }
    found
}

#[tokio::test]
async fn pages_fingerprint_each_asset_and_fingerprinted_assets_are_immutable() {
    let test = test_app();
    let body = fetch(&test.app, "/", &[]).await.text();
    assert!(!body.contains("{{ASSET_VERSION}}"));
    let version = announced_version(&body);
    for reference in asset_references(&body) {
        assert!(
            reference.ends_with(&format!("?v={version}")),
            "{reference} is not fingerprinted"
        );
    }
    let versioned = fetch(&test.app, &format!("/assets/css/dialogs.css?v={version}"), &[]).await;
    assert_eq!(versioned.header("cache-control"), "public, max-age=31536000, immutable");
    for request in ["/assets/css/dialogs.css", "/assets/css/dialogs.css?v=000000000000"] {
        assert_eq!(
            fetch(&test.app, request, &[]).await.header("cache-control"),
            "no-cache",
            "{request}"
        );
    }
    let icons = fetch(&test.app, "/assets/css/icons.css", &[]).await;
    assert!(icons.text().contains(&format!(".svg?v={version}\")")));
}

#[tokio::test]
async fn a_gzip_body_is_compressed_one_time_for_each_content() {
    let data = Bytes::from("body { color: red; }\n".repeat(200));
    let entry = super::frontend::StaticEntry::new(data.clone());
    let first = entry.gzip().await;
    let second = entry.gzip().await;
    assert_eq!(
        first.as_ptr(),
        second.as_ptr(),
        "the cache compressed the gzip body again"
    );
    assert_eq!(gunzip(&first), data);
}

// ---------------------------------------------------------------------------------------------------------------
// The files of the interface.
// ---------------------------------------------------------------------------------------------------------------

const VENDOR_PREFIX: &str = "assets/vendor";

fn exists(name: &str) -> bool {
    assets::file(name).is_some() || assets::is_folder(name)
}

#[test]
fn the_interface_has_its_files_and_not_the_files_of_the_removed_interface() {
    for expected in [
        "index.html",
        "preview.html",
        "info.html",
        "404.html",
        "favicon.svg",
        "assets/js/info.js",
        "assets/js/switcher.js",
        "assets/js/states.js",
        "assets/css/info.css",
        "assets/css/stowr.css",
        "assets/css/icons.css",
        "assets/css/dialogs.css",
        "assets/css/viewers.css",
        "assets/css/preview.css",
        "assets/icons/tabler/folder.svg",
        "assets/js/app.js",
        "assets/js/theme.js",
        "assets/js/uploads.js",
        "assets/js/session.js",
        "assets/js/common/api.js",
        "assets/vendor/marked/12.0.2/marked.min.js",
        "assets/vendor/highlightjs/11/highlight.min.js",
        "assets/vendor/pdfjs/4.10.38/pdf.min.mjs",
        "assets/vendor/pdfjs/4.10.38/pdf.worker.min.mjs",
        "assets/vendor/pdfjs/4.10.38/LICENSE",
    ] {
        assert!(assets::file(expected).is_some(), "{expected} is not embedded");
    }
    for removed in [
        "assets/css/style.css",
        "assets/css/tokens.css",
        "assets/icons/mdi",
        "assets/vendor/buefy",
        "assets/vendor/github-markdown-css",
        "assets/vendor/highlightjs/11/styles",
    ] {
        assert!(!exists(removed), "{removed} of the removed interface is still embedded");
    }
}

fn extension_of(name: &str) -> &str {
    super::paths::ext(name)
}

fn source_files() -> Vec<(&'static str, String)> {
    assets::FILES
        .iter()
        .filter(|(name, _)| !name.starts_with(VENDOR_PREFIX))
        .filter(|(name, _)| matches!(extension_of(name), ".html" | ".js" | ".css"))
        .map(|(name, data)| (*name, String::from_utf8_lossy(data).into_owned()))
        .collect()
}

#[test]
fn the_interface_uses_each_vendored_file() {
    let vendored: Vec<&str> = assets::FILES
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| name.starts_with(&format!("{VENDOR_PREFIX}/")))
        .filter(|name| matches!(extension_of(name), ".js" | ".mjs" | ".css"))
        .collect();
    assert!(!vendored.is_empty(), "no vendored script");
    let text: String = source_files()
        .into_iter()
        .map(|(_, text)| text)
        .collect::<Vec<_>>()
        .join("\n");
    let text = text.replace("${PDFJS_VERSION}", "4.10.38");
    for name in vendored {
        assert!(text.contains(name), "no page or script loads {name}");
    }
}

#[tokio::test]
async fn the_interface_is_served() {
    let test = test_app();
    let version = super::frontend::frontend_version();
    for page in ["/", "/index.html", "/preview.html", "/info.html"] {
        let answer = fetch(&test.app, page, &[]).await;
        let body = answer.text();
        assert_eq!(answer.status, 200, "{page}");
        assert!(
            body.contains("<meta name=\"bb-frontend\" content=\"stowr\" />"),
            "{page}"
        );
        for asset in ["assets/css/stowr.css", "assets/js/theme.js"] {
            assert!(
                body.contains(&format!("=\"{asset}?v={version}\"")),
                "{page} lacks the fingerprinted {asset}"
            );
        }
        // The theme applies before the first paint: theme.js is the first script and has no defer or async.
        let first = body.find("<script").expect("a script");
        assert!(
            body[first..].starts_with("<script src=\"assets/js/theme.js?v="),
            "{page}"
        );
        assert!(first < body.find("</head>").unwrap(), "{page}");
        assert!(!body.contains("{{"), "{page} keeps a placeholder");
        for header in [
            "content-security-policy",
            "x-content-type-options",
            "x-frame-options",
            "referrer-policy",
        ] {
            assert!(!answer.header(header).is_empty(), "{page} has no {header}");
        }
    }
    let css = fetch(&test.app, &format!("/assets/css/icons.css?v={version}"), &[]).await;
    assert_eq!(css.status, 200);
    assert_eq!(css.header("cache-control"), "public, max-age=31536000, immutable");
    assert!(
        css.text()
            .contains(&format!("url(\"../icons/tabler/folder.svg?v={version}\")"))
    );
    for vendor in [
        "/assets/vendor/marked/12.0.2/marked.min.js",
        "/assets/vendor/pdfjs/4.10.38/pdf.worker.min.mjs",
    ] {
        assert_eq!(fetch(&test.app, vendor, &[]).await.status, 200, "{vendor}");
    }
    let worker = fetch(&test.app, "/assets/vendor/pdfjs/4.10.38/pdf.worker.min.mjs", &[]).await;
    assert_eq!(worker.header("content-type"), "text/javascript; charset=utf-8");
    assert_eq!(fetch(&test.app, "/assets/css/style.css", &[]).await.status, 404);
    let not_found = fetch(&test.app, "/missing-page", &[("accept", "text/html")]).await;
    assert_eq!(not_found.status, 404);
    assert!(not_found.text().contains("assets/css/stowr.css"));
}

/// A run of the characters `[a-z0-9-]` at the start of a text.
fn icon_name(text: &str) -> &str {
    let end = text
        .find(|character: char| !(character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'))
        .unwrap_or(text.len());
    &text[..end]
}

fn is_word(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Each start of a marker in a text.
fn starts_of<'a>(text: &'a str, marker: &'a str) -> impl Iterator<Item = usize> + 'a {
    text.match_indices(marker).map(|(index, _)| index)
}

#[test]
fn the_interface_is_self_contained() {
    let icons = String::from_utf8(assets::file("assets/css/icons.css").unwrap().to_vec()).unwrap();
    // `.mdi-x { --icon:` and `.ic-x { --icon:` are the rules of the icons.
    let mut rules = std::collections::BTreeSet::new();
    for prefix in [".mdi-", ".ic-"] {
        for start in starts_of(&icons, prefix) {
            let name = &icons[start + 1..];
            let length = prefix.len() - 1 + icon_name(&name[prefix.len() - 1..]).len();
            if icons[start + 1 + length..].starts_with(" { --icon:") {
                rules.insert(name[..length].to_owned());
            }
        }
    }
    assert!(rules.len() >= 50, "icons.css has {} icon rules", rules.len());
    let icon_targets = |text: &str| -> Vec<String> {
        starts_of(text, "url(\"../icons/")
            .filter_map(|start| {
                let rest = &text[start + "url(\"../".len()..];
                let length = rest.find(['"', '?']).unwrap_or(rest.len());
                rest[length..].starts_with("\")").then(|| rest[..length].to_owned())
            })
            .collect()
    };
    for target in icon_targets(&icons) {
        assert!(
            exists(&format!("assets/{target}")),
            "icons.css draws the missing file {target}"
        );
    }
    for (name, text) in source_files() {
        for literal in ["http://", "https://", "//cdn."] {
            assert!(
                !text.contains(literal),
                "{name} contains the external URL literal {literal:?}"
            );
        }
        let extension = extension_of(name);
        if extension == ".css" {
            for target in icon_targets(&text) {
                assert!(
                    exists(&format!("assets/{target}")),
                    "{name} draws the missing file {target}"
                );
            }
            continue;
        }
        if extension == ".html" {
            for marker in ["href=\"assets/", "src=\"assets/"] {
                for start in starts_of(&text, marker) {
                    let rest = &text[start + marker.len() - "assets/".len()..];
                    let length = rest.find(['"', '?', '#']).unwrap_or(rest.len());
                    let asset = &rest[..length];
                    assert!(exists(asset), "{name} references the missing asset {asset}");
                }
            }
        }
        let bytes = text.as_bytes();
        // `mdi mdi-x` and `ic ic-x`: a class of an icon.
        for class in ["mdi ", "ic "] {
            for start in starts_of(&text, class) {
                if start > 0 && is_word(bytes[start - 1]) {
                    continue;
                }
                let rest = &text[start + class.len()..];
                let prefix = if rest.starts_with("mdi-") {
                    "mdi-"
                } else if rest.starts_with("ic-") {
                    "ic-"
                } else {
                    continue;
                };
                let icon = format!("{prefix}{}", icon_name(&rest[prefix.len()..]));
                if icon.len() == prefix.len() || icon == "mdi-spin" || icon == "mdi-24px" {
                    continue;
                }
                assert!(
                    rules.contains(&icon),
                    "{name} uses the icon {icon}, which icons.css does not draw"
                );
            }
        }
        // `ic('x'`, `mdi('x'` and `icon('x'`: a helper that draws an icon.
        for helper in ["ic('", "mdi('", "icon('"] {
            for start in starts_of(&text, helper) {
                if start > 0 && is_word(bytes[start - 1]) {
                    continue;
                }
                let rest = &text[start + helper.len()..];
                let icon = icon_name(rest);
                if icon.is_empty() || !rest[icon.len()..].starts_with('\'') {
                    continue;
                }
                let prefix = if helper == "ic('" { "ic-" } else { "mdi-" };
                assert!(
                    rules.contains(&format!("{prefix}{icon}")),
                    "{name} draws the icon {prefix}{icon}, which icons.css does not draw"
                );
            }
        }
        if name == "assets/js/common/detect.js" {
            let start = text.find("function iconForType").expect("detect.js has iconForType");
            let end = text.find("function resolveType").expect("detect.js has resolveType");
            assert!(end > start);
            let section = &text[start..end];
            let mut names = Vec::new();
            for (index, _) in section.match_indices(':') {
                let rest = section[index + 1..].trim_start();
                if let Some(rest) = rest.strip_prefix('\'') {
                    let icon = icon_name(rest);
                    if !icon.is_empty() && rest[icon.len()..].starts_with('\'') {
                        names.push(icon.to_owned());
                    }
                }
            }
            for (index, _) in section.match_indices("|| '") {
                let rest = &section[index + 4..];
                let icon = icon_name(rest);
                if !icon.is_empty() && rest[icon.len()..].starts_with('\'') {
                    names.push(icon.to_owned());
                }
            }
            for icon in names {
                assert!(
                    rules.contains(&format!("mdi-{icon}")),
                    "detect.js gives the icon mdi-{icon}, which icons.css does not draw"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------------------------
// `/open/` and the information page.
// ---------------------------------------------------------------------------------------------------------------

/// The type and the `filename` of a `Content-Disposition` value.
fn disposition(value: &str) -> (String, String) {
    let mut parts = value.split(';');
    let kind = parts.next().unwrap_or("").trim().to_lowercase();
    let mut filename = String::new();
    for part in parts {
        if let Some((name, raw)) = part.trim().split_once('=')
            && name.trim().eq_ignore_ascii_case("filename")
        {
            filename = raw.trim().trim_matches('"').replace("\\\"", "\"");
        }
    }
    (kind, filename)
}

#[tokio::test]
async fn open_uses_the_real_name_and_a_careful_inline_disposition() {
    let test = test_app();
    test.rw
        .put_object("tenant/media/board review.mp4", b"video", "application/octet-stream");
    test.rw
        .put_object("tenant/media/archive.mkv", b"mkv", "video/x-matroska");
    for (key, name, kind, content_type) in [
        ("media/board review.mp4", "board review.mp4", "inline", "video/mp4"),
        ("media/archive.mkv", "archive.mkv", "attachment", "video/x-matroska"),
    ] {
        let target = format!("/open/{}?instance=rw&key={}", path_escape(name), query_escape(key));
        let answer = get(&test.app, &target).await;
        assert_eq!(answer.status, 200, "{name}: {}", answer.text());
        assert_eq!(answer.header("content-type"), content_type, "{name}");
        assert_eq!(
            disposition(answer.header("content-disposition")),
            (kind.to_owned(), name.to_owned())
        );
        assert_eq!(answer.header("accept-ranges"), "bytes");
        assert!(answer.header("content-security-policy").starts_with("sandbox"));
    }
    let redirect = get(&test.app, "/open?instance=rw&key=x").await;
    assert_eq!(redirect.status, 301);
    assert_eq!(redirect.header("location"), "/open/?instance=rw&key=x");
}

#[tokio::test]
async fn the_archive_download_uses_the_name_of_the_folder() {
    let test = test_app();
    let answer = get(&test.app, "/api/archive?instance=rw&prefix=folder%2F&name=folder.zip").await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert_eq!(
        disposition(answer.header("content-disposition")),
        ("attachment".to_owned(), "folder.zip".to_owned())
    );
}

#[tokio::test]
async fn the_information_page_route() {
    let mut api = bucket_config("api", "", &[]);
    api.auth_id = "host".to_owned();
    let app = app_of(vec![instance(api, FakeBackend::with_objects(&[]))]);
    let cases: [(&str, u16, &str, &str); 5] = [
        (
            "/-/host/api/?info",
            200,
            "<body class=\"infoPage\">",
            "<base href=\"../../../\" />",
        ),
        (
            "/-/host/api/?info&lifecycle-abort=logs%2F",
            200,
            "<body class=\"infoPage\">",
            "",
        ),
        (
            "/-/host/api/folder/?info",
            200,
            "Skip to the files",
            "<base href=\"../../../../\" />",
        ),
        ("/-/host/api/", 200, "Skip to the files", ""),
        ("/-/host/missing/?info", 404, "", ""),
    ];
    for (path, status, content, base) in cases {
        let answer = get(&app, path).await;
        let body = answer.text();
        assert_eq!(answer.status, status, "GET {path}");
        assert!(body.contains(content), "GET {path} does not serve {content:?}");
        assert!(body.contains(base), "GET {path} does not have the base {base:?}");
        if status == 200 {
            assert!(!body.contains("{{"), "GET {path} keeps a placeholder");
        }
    }
}

#[tokio::test]
async fn the_instance_facts_give_the_known_flavour() {
    let known = instance(bucket_config("m", "", &[]), FakeBackend::with_objects(&[]));
    {
        let mut rules = known.rules.inner.lock().unwrap();
        rules.flavour = "minio".to_owned();
        rules.flavour_known = true;
    }
    assert_eq!(serde_json::to_value(known.public_info()).unwrap()["flavour"], "minio");
    let unknown = instance(bucket_config("u", "", &[]), FakeBackend::with_objects(&[]));
    let body = serde_json::to_string(&unknown.public_info()).unwrap();
    assert!(
        !body.contains("\"flavour\""),
        "an unknown flavour is in the answer: {body}"
    );
}

// ---------------------------------------------------------------------------------------------------------------
// The router.
// ---------------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_router_redirects_paths_that_are_not_clean() {
    let test = test_app();
    let answer = get(&test.app, "//api//instances?x=1").await;
    assert_eq!(answer.status, 301);
    assert_eq!(answer.header("location"), "/api/instances?x=1");
    assert_eq!(answer.header("content-type"), "text/html; charset=utf-8");
    assert_eq!(
        answer.text(),
        "<a href=\"/api/instances?x=1\">Moved Permanently</a>.\n\n"
    );
    let head = TestRequest::new("HEAD", "/api/../healthz").send(&test.app).await;
    assert_eq!((head.status, head.header("location")), (301, "/healthz"));
    assert!(head.body.is_empty());
    let post = TestRequest::new("POST", "/./api/copy").body("{}").send(&test.app).await;
    assert_eq!((post.status, post.header("content-type")), (301, ""));
    // An escaped segment matches the route of its decoded form.
    assert_eq!(get(&test.app, "/api/inst%61nces").await.status, 200);
}

#[tokio::test]
async fn the_api_answers_have_the_security_headers_and_the_cache_rule() {
    let test = test_app();
    let answer = get(&test.app, "/healthz").await;
    assert_eq!(answer.text(), "{\"instances\":2,\"status\":\"ok\"}\n");
    assert_eq!(answer.header("content-length"), answer.body.len().to_string());
    assert_eq!(answer.header("cache-control"), "no-store");
    assert_eq!(answer.header("x-frame-options"), "SAMEORIGIN");
    let head = TestRequest::new("HEAD", "/healthz").send(&test.app).await;
    assert_eq!(head.header("content-type"), "application/json");
    assert_eq!(head.header("content-length"), "");
    let missing = get(&test.app, "/api/missing").await;
    assert_eq!((missing.status, missing.text().as_str()), (404, "404 page not found\n"));
    assert_eq!(missing.header("cache-control"), "private, no-store");
    let jobs = get(&test.app, "/api/jobs").await;
    assert_eq!(jobs.status, 404);
    let wrong = TestRequest::new("DELETE", "/api/list").send(&test.app).await;
    assert_eq!((wrong.status, wrong.header("allow")), (405, "GET, HEAD"));
    assert_eq!(wrong.text(), "method not allowed\n");
}

#[tokio::test]
async fn the_raw_listing_has_the_xml_form_of_s3() {
    let test = test_app();
    let answer = get(&test.app, "/s3?instance=rw&prefix=folder/&delimiter=/").await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert_eq!(answer.header("content-type"), "application/xml");
    assert_eq!(
        answer.text(),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>rw-bucket</Name><Prefix>folder/</Prefix><Delimiter>/</Delimiter><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated><CommonPrefixes><Prefix>folder/nested/</Prefix></CommonPrefixes><Contents><Key>folder/direct.txt</Key><LastModified>2026-01-02T03:04:05Z</LastModified><ETag>etag-tenant/folder/direct.txt</ETag><Size>6</Size></Contents></ListBucketResult>"
    );
}

#[tokio::test]
async fn the_gateway_writes_deletes_and_answers_options() {
    let test = test_app();
    let put = TestRequest::new("PUT", "/s3?instance=rw&key=new.txt")
        .header("content-type", "text/plain")
        .body("hello")
        .send(&test.app)
        .await;
    assert_eq!(put.status, 204, "{}", put.text());
    assert_eq!(test.rw.data("tenant/new.txt").as_deref(), Some("hello"));
    let options = TestRequest::new("OPTIONS", "/s3?instance=rw&key=new.txt")
        .send(&test.app)
        .await;
    assert_eq!(
        (options.status, options.header("allow")),
        (204, "GET, HEAD, PUT, DELETE, OPTIONS")
    );
    let head = TestRequest::new("HEAD", "/s3?instance=rw&key=new.txt")
        .send(&test.app)
        .await;
    assert_eq!((head.status, head.header("content-length")), (200, "5"));
    assert!(head.body.is_empty());
    let delete = TestRequest::new("DELETE", "/s3?instance=rw&key=new.txt")
        .send(&test.app)
        .await;
    assert_eq!(delete.status, 204);
    assert!(test.rw.data("tenant/new.txt").is_none());
    let missing = get(&test.app, "/s3?instance=rw&key=new.txt").await;
    assert_eq!(missing.status, 404);
    assert_eq!(missing.text(), "the storage provider returned HTTP 404 (NotFound)\n");
    let unknown = get(&test.app, "/s3?instance=nope&key=a").await;
    assert_eq!(unknown.status, 404);
    assert_eq!(unknown.text(), "storage instance \"nope\" does not exist\n");
}

#[tokio::test]
async fn a_copy_of_one_object_answers_the_count() {
    let test = test_app();
    let answer = post_json(
        &test.app,
        "/api/copy",
        r#"{"instance":"rw","src":"folder/direct.txt","dst":"copy.txt"}"#,
    )
    .await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert_eq!(answer.text(), "{\"copied\":1}\n");
    assert_eq!(test.rw.data("tenant/copy.txt").as_deref(), Some("direct"));
    let unknown_member = post_json(&test.app, "/api/copy", r#"{"instance":"rw","source":"a"}"#).await;
    assert_eq!(unknown_member.status, 400);
    assert_eq!(unknown_member.json()["error"]["code"], "invalid_json");
}

#[tokio::test]
async fn the_build_route_gives_the_identity_of_the_build() {
    let test = test_app();
    let answer = get(&test.app, "/api/build").await;
    assert_eq!(answer.status, 200);
    assert_eq!(answer.json()["version"], crate::config::build_info::current().version);
    assert_eq!(answer.header("cache-control"), "no-store");
}

#[test]
fn a_test_application_has_the_open_access_mode() {
    let app = app_with(test_config(), Vec::new());
    assert!(!app.config.access.enforced());
    assert!(app.instances.is_empty());
}

// ---------------------------------------------------------------------------------------------------------------
// The assembly of the application.
// ---------------------------------------------------------------------------------------------------------------

/// A local HTTP server that answers each request with an empty body and the status of a shared value.
async fn status_server(status: Arc<std::sync::atomic::AtomicU16>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let status = status.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buffer = [0u8; 1024];
                while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(count) => head.extend_from_slice(&buffer[..count]),
                    }
                }
                let code = status.load(Ordering::SeqCst);
                let answer = format!("HTTP/1.1 {code} Status\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                let _ = stream.write_all(answer.as_bytes()).await;
            });
        }
    });
    format!("http://{address}")
}

fn s3_bucket(id: &str, permissions: &[&str]) -> crate::common::config::BucketConfig {
    let mut cfg = bucket_config(id, "", permissions);
    cfg.auth_id = "shared".to_owned();
    cfg.bucket = id.to_owned();
    cfg
}

fn anonymous_s3_config(
    endpoint: &str,
    buckets: Vec<crate::common::config::BucketConfig>,
) -> crate::common::config::Config {
    let mut config = test_config();
    config.auths = vec![crate::common::config::AuthConfig {
        id: "shared".to_owned(),
        provider: crate::common::config::Provider::S3,
        mode: "anonymous".to_owned(),
        endpoint: endpoint.to_owned(),
        region: "test".to_owned(),
        ..crate::common::config::AuthConfig::default()
    }];
    config.buckets = buckets;
    config
}

#[tokio::test]
async fn the_buckets_of_one_auth_block_share_its_client() {
    let status = Arc::new(std::sync::atomic::AtomicU16::new(200));
    let endpoint = status_server(status).await;
    let config = anonymous_s3_config(
        &endpoint,
        vec![
            s3_bucket("one", &[PERMISSION_READ]),
            s3_bucket("two", &[PERMISSION_READ, PERMISSION_WRITE]),
        ],
    );
    let app = super::build_app(config).unwrap();
    assert_eq!(app.auths.len(), 1);
    // One reference in the map and one in each back end.
    assert_eq!(Arc::strong_count(&app.auths["shared"]), 3);
    use crate::common::storage::CapabilityStateName;
    assert_eq!(
        app.instance("one").unwrap().capability(PERMISSION_WRITE).state,
        CapabilityStateName::Denied
    );
    assert_eq!(
        app.instance("two").unwrap().capability(PERMISSION_WRITE).state,
        CapabilityStateName::Unknown
    );
}

#[tokio::test]
async fn a_refresh_of_the_permissions_keeps_the_state_on_probe_errors() {
    let status = Arc::new(std::sync::atomic::AtomicU16::new(500));
    let endpoint = status_server(status.clone()).await;
    let mut bucket = s3_bucket("s3", &[]);
    bucket.permissions_defined = false;
    let app = super::build_app(anonymous_s3_config(&endpoint, vec![bucket])).unwrap();
    let instance = app.instance("s3").unwrap();
    // A 5xx probe does not prove that the credentials are denied.
    let read = instance.refresh_capabilities(&OpCtx::default()).await.read;
    assert!(!read.verified && read.allowed, "{read:?}");
    // A canceled probe leaves the shared state as it is.
    status.store(403, Ordering::SeqCst);
    let canceled = OpCtx::default();
    canceled.cancel.cancel();
    let read = instance.refresh_capabilities(&canceled).await.read;
    assert!(!read.verified && read.allowed, "{read:?}");
    // An explicit 403 of the probe of the bucket is a verified denial.
    let read = instance.refresh_capabilities(&OpCtx::default()).await.read;
    assert!(
        read.verified && !read.allowed && read.source == "s3-list-probe",
        "{read:?}"
    );
}

#[tokio::test]
async fn the_assembly_stops_on_an_auth_block_that_cannot_start() {
    let config = anonymous_s3_config("http://127.0.0.1:9", vec![s3_bucket("one", &[PERMISSION_READ])]);
    match super::build_app(config) {
        Ok(app) => assert_eq!(app.instances.len(), 1),
        Err(error) => assert!(error.to_string().starts_with("initialize auth \"shared\": "), "{error}"),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// The HTTP/1.1 runtime over a real connection.
// ---------------------------------------------------------------------------------------------------------------

/// Send raw bytes to a server and read its answer until the server closes the connection.
async fn exchange(address: std::net::SocketAddr, request: &str) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut answer = Vec::new();
    let _ = tokio::time::timeout(std::time::Duration::from_secs(10), stream.read_to_end(&mut answer)).await;
    String::from_utf8_lossy(&answer).into_owned()
}

async fn running_server() -> (
    std::net::SocketAddr,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let test = test_app();
    let listener = super::runtime::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(super::runtime::run_listener(test.app, listener, async move {
        let _ = stop_receiver.await;
        "terminated"
    }));
    (address, stop_sender, server)
}

#[tokio::test]
async fn the_runtime_writes_title_case_headers_a_date_and_a_length() {
    let (address, stop, server) = running_server().await;
    let answer = exchange(
        address,
        "GET /healthz HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(answer.starts_with("HTTP/1.1 200 OK\r\n"), "{answer}");
    for line in [
        "Content-Type: application/json; charset=utf-8\r\n",
        "Content-Length: 30\r\n",
        "X-Content-Type-Options: nosniff\r\n",
        "Cache-Control: no-store\r\n",
        "Date: ",
    ] {
        assert!(answer.contains(line), "{line:?} is not in {answer}");
    }
    assert!(
        answer.ends_with("\r\n\r\n{\"instances\":2,\"status\":\"ok\"}\n"),
        "{answer}"
    );
    let _ = stop.send(());
    server.await.unwrap();
}

#[tokio::test]
async fn the_runtime_sends_the_budget_trailers_to_a_client_that_accepts_them() {
    let (address, stop, server) = running_server().await;
    let answer = exchange(
        address,
        "GET /api/build HTTP/1.1\r\nHost: example.com\r\nTE: trailers\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(answer.contains("Transfer-Encoding: chunked\r\n"), "{answer}");
    assert!(
        answer.contains("Trailer: X-Stowr-Storage-Requests, X-Stowr-Storage-Bytes, X-Stowr-Elapsed-Ms\r\n"),
        "{answer}"
    );
    assert!(answer.contains("\r\n0\r\nX-Stowr-Storage-Requests: 0\r\n"), "{answer}");
    let without = exchange(
        address,
        "HEAD /api/build HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(without.starts_with("HTTP/1.1 200 OK\r\n"), "{without}");
    assert!(without.ends_with("\r\n\r\n"), "a HEAD answer has no body: {without}");
    let _ = stop.send(());
    server.await.unwrap();
}

#[tokio::test]
async fn the_runtime_refuses_a_request_without_host_and_a_bad_escape() {
    let (address, stop, server) = running_server().await;
    let answer = exchange(address, "GET /healthz HTTP/1.1\r\nConnection: close\r\n\r\n").await;
    assert!(answer.starts_with("HTTP/1.1 400 Bad Request\r\n"), "{answer}");
    assert!(
        answer.ends_with("400 Bad Request: missing required Host header"),
        "{answer}"
    );
    let answer = exchange(address, "GET /a%zz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").await;
    assert!(answer.starts_with("HTTP/1.1 400 Bad Request\r\n"), "{answer}");
    let _ = stop.send(());
    server.await.unwrap();
}

#[tokio::test]
async fn the_runtime_keeps_a_connection_for_several_requests_and_stops_gracefully() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (address, stop, server) = running_server().await;
    let mut stream = tokio::net::TcpStream::connect(address).await.unwrap();
    for _ in 0..2 {
        stream
            .write_all(b"GET /healthz HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();
        let mut buffer = vec![0u8; 4096];
        let mut answer = Vec::new();
        while !String::from_utf8_lossy(&answer).ends_with("\"status\":\"ok\"}\n") {
            let count = stream.read(&mut buffer).await.unwrap();
            assert!(count > 0, "the connection closed");
            answer.extend_from_slice(&buffer[..count]);
        }
    }
    // The stop closes the idle connection and ends the listener.
    let _ = stop.send(());
    tokio::time::timeout(std::time::Duration::from_secs(5), server)
        .await
        .expect("the graceful stop ends")
        .unwrap();
    let mut rest = Vec::new();
    let _ = stream.read_to_end(&mut rest).await;
    assert!(rest.is_empty());
}
