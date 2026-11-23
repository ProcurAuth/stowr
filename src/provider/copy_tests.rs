//! The tests of the copy in parts against a fake S3 server. The parts copy real bytes, so a test can compare the
//! result with the source.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http::header::HeaderValue;
use http::{HeaderMap, Method};
use tokio::sync::mpsc;

use super::S3Backend;
use super::s3::copy::copy_metadata_headers;
use super::test_server::{Problems, TestRequest, TestResponse, TestServer};
use super::testing::anonymous_s3;
use crate::common::ctx::OpCtx;
use crate::common::query::{Query, unescape};
use crate::common::storage::{MultipartCopyOptions, RequestGate};
use crate::instance::gate::{self, Gate};

/// One object (or one version) of the fake server.
#[derive(Clone, Debug, Default)]
struct FakeObject {
    data: Vec<u8>,
    headers: HeaderMap,
    tags: String,
}

#[derive(Default)]
struct FakeState {
    objects: HashMap<String, FakeObject>,
    /// The versions, by `key?version`.
    versions: HashMap<String, FakeObject>,
    uploads: HashMap<String, BTreeMap<u32, Vec<u8>>>,
    created: HashMap<String, HeaderMap>,
    no_tags: bool,
    /// The part that gets 500, and the part that waits until the client goes.
    fail_part: u32,
    block_part: u32,
    ranges: Vec<String>,
    copy_sources: Vec<String>,
    if_match: Vec<String>,
    completed: usize,
    aborted: usize,
    copy_objects: usize,
    tagging_queries: usize,
    next_upload: usize,
    in_flight: usize,
    most_in_flight: usize,
}

/// An S3 server for the copy tests: HEAD, the tags, the multipart upload with `UploadPartCopy`, `CopyObject` and
/// `DELETE`.
struct FakeCopyS3 {
    state: Mutex<FakeState>,
    problems: Problems,
    blocked: mpsc::UnboundedSender<()>,
    /// The time that each part takes.
    part_delay: Duration,
}

impl FakeCopyS3 {
    async fn start() -> (Arc<Self>, TestServer, mpsc::UnboundedReceiver<()>) {
        Self::start_with_delay(Duration::ZERO).await
    }

    async fn start_with_delay(part_delay: Duration) -> (Arc<Self>, TestServer, mpsc::UnboundedReceiver<()>) {
        let (blocked, waiting) = mpsc::unbounded_channel();
        let fake = Arc::new(Self {
            state: Mutex::new(FakeState::default()),
            problems: Problems::default(),
            blocked,
            part_delay,
        });
        let handler = fake.clone();
        let server = TestServer::start_async(Arc::new(move |request| {
            let fake = handler.clone();
            Box::pin(async move { fake.serve(request).await })
        }))
        .await;
        (fake, server, waiting)
    }

    fn put(&self, key: &str, data: &[u8], content_type: &str, tags: &str) {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_str(content_type).unwrap());
        headers.insert("cache-control", HeaderValue::from_static("max-age=60"));
        headers.insert("x-amz-meta-origin", HeaderValue::from_static("seed"));
        self.state.lock().unwrap().objects.insert(
            key.to_owned(),
            FakeObject {
                data: data.to_vec(),
                headers,
                tags: tags.to_owned(),
            },
        );
    }

    fn source(state: &FakeState, key: &str, version: &str) -> Option<FakeObject> {
        if version.is_empty() {
            state.objects.get(key).cloned()
        } else {
            state.versions.get(&format!("{key}?{version}")).cloned()
        }
    }

    fn parse_copy_source(&self, value: &str) -> (String, String) {
        let (path, raw_query) = value.split_once('?').unwrap_or((value, ""));
        let key = unescape(path.trim_start_matches("/bucket/"), false).unwrap_or_else(|| {
            self.problems.report(format!("copy source {value:?}"));
            String::new()
        });
        (key, Query::parse(raw_query).get("versionId").to_owned())
    }

    async fn serve(&self, request: TestRequest) -> TestResponse {
        let key = request.path.trim_start_matches("/bucket/").to_owned();
        if request.method == Method::PUT && !request.query.get("partNumber").is_empty() {
            {
                let mut state = self.state.lock().unwrap();
                state.in_flight += 1;
                state.most_in_flight = state.most_in_flight.max(state.in_flight);
            }
            if !self.part_delay.is_zero() {
                tokio::time::sleep(self.part_delay).await;
            }
            let reply = self.upload_part_copy(&request).await;
            self.state.lock().unwrap().in_flight -= 1;
            return reply;
        }
        let mut state = self.state.lock().unwrap();
        let query = &request.query;
        if request.method == Method::HEAD {
            let Some(object) = Self::source(&state, &key, query.get("versionId")) else {
                return TestResponse::status(404);
            };
            let mut reply = TestResponse::status(200);
            reply.headers = object.headers.clone();
            let count = object.tags.split('&').filter(|part| !part.is_empty()).count();
            let mut reply = reply
                .header("etag", &format!("\"etag-{key}\""))
                .header("content-length", &object.data.len().to_string());
            if !state.no_tags {
                reply = reply.header("x-amz-tagging-count", &count.to_string());
            }
            return reply;
        }
        if query.has("tagging") && request.method == Method::GET {
            state.tagging_queries += 1;
            if state.no_tags {
                return TestResponse::status(501);
            }
            let object = Self::source(&state, &key, query.get("versionId")).unwrap_or_default();
            let tags = Query::parse(&object.tags);
            let names: std::collections::BTreeSet<&str> = tags.pairs().iter().map(|(name, _)| name.as_str()).collect();
            let mut body = String::from("<Tagging><TagSet>");
            for name in names {
                body.push_str(&format!(
                    "<Tag><Key>{name}</Key><Value>{}</Value></Tag>",
                    tags.get(name)
                ));
            }
            body.push_str("</TagSet></Tagging>");
            return TestResponse::body(200, body);
        }
        if query.has("uploads") && request.method == Method::POST {
            state.next_upload += 1;
            let id = format!("upload-{}", state.next_upload);
            state.uploads.insert(id.clone(), BTreeMap::new());
            state.created.insert(id.clone(), request.headers.clone());
            return TestResponse::body(
                200,
                format!("<InitiateMultipartUploadResult><UploadId>{id}</UploadId></InitiateMultipartUploadResult>"),
            );
        }
        if !query.get("uploadId").is_empty() && request.method == Method::POST {
            let id = query.get("uploadId").to_owned();
            let mut parts: Vec<(u32, String)> = Vec::new();
            let walked = super::xml::walk(&request.body, |node| match node {
                super::xml::Node::Start(path) if super::xml::at(path, &["Part"]) => parts.push((0, String::new())),
                super::xml::Node::End(path, text) if super::xml::at(path, &["Part", "PartNumber"]) => {
                    if let Some(part) = parts.last_mut() {
                        part.0 = text.parse().unwrap_or(0);
                    }
                }
                super::xml::Node::End(path, text) if super::xml::at(path, &["Part", "ETag"]) => {
                    if let Some(part) = parts.last_mut() {
                        part.1 = text;
                    }
                }
                _ => {}
            });
            if walked.is_err() {
                self.problems.report(format!("complete body: {}", request.text()));
            }
            let mut data = Vec::new();
            for (index, (number, etag)) in parts.iter().enumerate() {
                if *number as usize != index + 1 || *etag != format!("\"part-{number}\"") {
                    self.problems.report(format!("complete part {index} = {number} {etag}"));
                }
                if let Some(bytes) = state.uploads.get(&id).and_then(|upload| upload.get(number)) {
                    data.extend_from_slice(bytes);
                }
            }
            let created = state.created.get(&id).cloned().unwrap_or_default();
            let tags = created
                .get("x-amz-tagging")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .to_owned();
            state.objects.insert(
                key,
                FakeObject {
                    data,
                    headers: copy_metadata_headers(&created),
                    tags,
                },
            );
            state.uploads.remove(&id);
            state.completed += 1;
            return TestResponse::body(200, "<CompleteMultipartUploadResult/>");
        }
        if !query.get("uploadId").is_empty() && request.method == Method::DELETE {
            state.uploads.remove(query.get("uploadId"));
            state.aborted += 1;
            return TestResponse::status(204);
        }
        if request.method == Method::PUT && !request.header("x-amz-copy-source").is_empty() {
            state.copy_objects += 1;
            let (source_key, version) = self.parse_copy_source(request.header("x-amz-copy-source"));
            let Some(object) = Self::source(&state, &source_key, &version) else {
                return TestResponse::status(404);
            };
            state.objects.insert(key, object);
            return TestResponse::body(200, "<CopyObjectResult/>");
        }
        if request.method == Method::DELETE {
            state.objects.remove(&key);
            return TestResponse::status(204);
        }
        self.problems.report(format!(
            "unexpected request {} {}?{}",
            request.method, request.path, request.raw_query
        ));
        TestResponse::status(501)
    }

    async fn upload_part_copy(&self, request: &TestRequest) -> TestResponse {
        let number: u32 = request.query.get("partNumber").parse().unwrap_or(0);
        if number == self.state.lock().unwrap().block_part {
            let _ = self.blocked.send(());
            std::future::pending::<()>().await;
        }
        let mut state = self.state.lock().unwrap();
        state.ranges.push(request.header("x-amz-copy-source-range").to_owned());
        state.copy_sources.push(request.header("x-amz-copy-source").to_owned());
        state
            .if_match
            .push(request.header("x-amz-copy-source-if-match").to_owned());
        if number == state.fail_part {
            return TestResponse::body(
                500,
                "<Error><Code>InternalError</Code><Message>part failed</Message></Error>",
            );
        }
        let (source_key, version) = self.parse_copy_source(request.header("x-amz-copy-source"));
        let object = Self::source(&state, &source_key, &version);
        let upload_id = request.query.get("uploadId").to_owned();
        let (Some(object), true) = (object, state.uploads.contains_key(&upload_id)) else {
            return TestResponse::status(404);
        };
        let range = request.header("x-amz-copy-source-range");
        let bounds = range
            .strip_prefix("bytes=")
            .and_then(|range| range.split_once('-'))
            .and_then(|(first, last)| Some((first.parse::<usize>().ok()?, last.parse::<usize>().ok()?)));
        let Some((first, last)) = bounds else {
            self.problems.report(format!("range {range:?}"));
            return TestResponse::status(400);
        };
        let bytes = object.data[first..=last].to_vec();
        if let Some(upload) = state.uploads.get_mut(&upload_id) {
            upload.insert(number, bytes);
        }
        TestResponse::body(
            200,
            format!("<CopyPartResult><ETag>\"part-{number}\"</ETag></CopyPartResult>"),
        )
    }
}

fn header_of<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers.get(name).and_then(|value| value.to_str().ok()).unwrap_or("")
}

async fn copy(
    backend: &S3Backend,
    ctx: &OpCtx,
    source: &str,
    destination: &str,
    options: MultipartCopyOptions,
    part_size: i64,
) -> crate::common::error::Result<()> {
    backend
        .copy_in_parts(ctx, source, destination, options, part_size)
        .await
}

#[tokio::test]
async fn a_copy_in_parts_keeps_the_metadata_the_tags_and_the_bytes() {
    let (fake, server, _) = FakeCopyS3::start().await;
    let data = b"0123456789abcdefghijklmnopqrstuvwxyz";
    fake.put(
        "dir/source file.bin",
        data,
        "application/x-test",
        "team=blue&state=draft",
    );
    let backend = anonymous_s3(&server.url, "bucket");
    let progress = Arc::new(AtomicI64::new(0));
    let counted = progress.clone();
    let options = MultipartCopyOptions {
        progress: Some(Arc::new(move |part| {
            counted.fetch_add(part, Ordering::SeqCst);
        })),
        ..MultipartCopyOptions::default()
    };
    copy(
        &backend,
        &OpCtx::default(),
        "dir/source file.bin",
        "dir/copy.bin",
        options,
        10,
    )
    .await
    .unwrap();
    let state = fake.state.lock().unwrap();
    assert_eq!(state.objects["dir/copy.bin"].data, data);
    assert_eq!(progress.load(Ordering::SeqCst), data.len() as i64);
    let mut ranges = state.ranges.clone();
    ranges.sort();
    assert_eq!(ranges.join(","), "bytes=0-9,bytes=10-19,bytes=20-29,bytes=30-35");
    for (index, source) in state.copy_sources.iter().enumerate() {
        assert_eq!(source, "/bucket/dir/source%20file.bin");
        assert_eq!(state.if_match[index], "\"etag-dir/source file.bin\"");
    }
    let created = &state.created["upload-1"];
    assert_eq!(header_of(created, "content-type"), "application/x-test");
    assert_eq!(header_of(created, "cache-control"), "max-age=60");
    assert_eq!(header_of(created, "x-amz-meta-origin"), "seed");
    assert_eq!(header_of(created, "x-amz-tagging"), "state=draft&team=blue");
    assert_eq!((state.completed, state.aborted, state.copy_objects), (1, 0, 0));
    fake.problems.check();
}

#[tokio::test]
async fn a_copy_in_parts_reads_the_named_version() {
    let (fake, server, _) = FakeCopyS3::start().await;
    fake.put("doc.txt", b"current version", "text/plain", "");
    {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("text/old"));
        fake.state.lock().unwrap().versions.insert(
            "doc.txt?v1".to_owned(),
            FakeObject {
                data: b"the older version".to_vec(),
                headers,
                tags: "age=old".to_owned(),
            },
        );
    }
    let backend = anonymous_s3(&server.url, "bucket");
    let options = MultipartCopyOptions {
        source_version: "v1".to_owned(),
        ..MultipartCopyOptions::default()
    };
    copy(&backend, &OpCtx::default(), "doc.txt", "doc.txt", options, 5)
        .await
        .unwrap();
    let state = fake.state.lock().unwrap();
    let restored = &state.objects["doc.txt"];
    assert_eq!(restored.data, b"the older version");
    assert_eq!(header_of(&restored.headers, "content-type"), "text/old");
    assert_eq!(restored.tags, "age=old");
    for source in &state.copy_sources {
        assert_eq!(source, "/bucket/doc.txt?versionId=v1");
    }
    fake.problems.check();
}

#[tokio::test]
async fn a_copy_in_parts_replaces_the_metadata_and_the_tags_on_request() {
    let (fake, server, _) = FakeCopyS3::start().await;
    fake.put("a.bin", b"0123456789", "application/octet-stream", "old=yes");
    let backend = anonymous_s3(&server.url, "bucket");
    let mut metadata = HeaderMap::new();
    metadata.insert("content-type", HeaderValue::from_static("text/csv"));
    metadata.insert("x-amz-meta-owner", HeaderValue::from_static("ops"));
    metadata.insert("authorization", HeaderValue::from_static("ignored"));
    let options = MultipartCopyOptions {
        metadata: Some(metadata),
        tags: Some(super::s3::encode_tags(&[crate::lifecycle::Tag {
            key: "new".to_owned(),
            value: "1".to_owned(),
        }])),
        ..MultipartCopyOptions::default()
    };
    copy(&backend, &OpCtx::default(), "a.bin", "a.bin", options, 5)
        .await
        .unwrap();
    let state = fake.state.lock().unwrap();
    let created = &state.created["upload-1"];
    assert_eq!(header_of(created, "content-type"), "text/csv");
    assert_eq!(header_of(created, "x-amz-meta-owner"), "ops");
    assert_eq!(header_of(created, "cache-control"), "");
    assert_eq!(header_of(created, "x-amz-meta-origin"), "");
    assert_eq!(header_of(created, "x-amz-tagging"), "new=1");
    assert_eq!(state.tagging_queries, 0);
    fake.problems.check();
}

#[tokio::test]
async fn a_copy_in_parts_works_without_tags_on_the_provider() {
    let (fake, server, _) = FakeCopyS3::start().await;
    fake.state.lock().unwrap().no_tags = true;
    fake.put("a.bin", b"0123456789", "application/octet-stream", "");
    let backend = anonymous_s3(&server.url, "bucket");
    copy(
        &backend,
        &OpCtx::default(),
        "a.bin",
        "b.bin",
        MultipartCopyOptions::default(),
        5,
    )
    .await
    .unwrap();
    let state = fake.state.lock().unwrap();
    assert_eq!(header_of(&state.created["upload-1"], "x-amz-tagging"), "");
    assert_eq!(state.objects["b.bin"].data, b"0123456789");
    assert_eq!(state.tagging_queries, 1);
    fake.problems.check();
}

#[tokio::test]
async fn a_copy_in_parts_aborts_when_a_part_fails() {
    let (fake, server, _) = FakeCopyS3::start().await;
    fake.state.lock().unwrap().fail_part = 3;
    fake.put("a.bin", &[b'x'; 50], "application/octet-stream", "");
    let backend = anonymous_s3(&server.url, "bucket");
    let error = copy(
        &backend,
        &OpCtx::default(),
        "a.bin",
        "b.bin",
        MultipartCopyOptions::default(),
        5,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("part failed"), "{error}");
    let state = fake.state.lock().unwrap();
    assert_eq!((state.aborted, state.completed, state.uploads.len()), (1, 0, 0));
    assert!(!state.objects.contains_key("b.bin"), "the failed copy made an object");
    fake.problems.check();
}

#[tokio::test]
async fn a_copy_in_parts_aborts_on_a_cancel() {
    let (fake, server, mut blocked) = FakeCopyS3::start().await;
    fake.state.lock().unwrap().block_part = 2;
    fake.put("a.bin", &[b'x'; 50], "application/octet-stream", "");
    let backend = anonymous_s3(&server.url, "bucket");
    let ctx = OpCtx::default();
    let token = ctx.cancel.clone();
    tokio::spawn(async move {
        blocked.recv().await;
        token.cancel();
    });
    let error = copy(&backend, &ctx, "a.bin", "b.bin", MultipartCopyOptions::default(), 5)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("canceled"), "{error}");
    let state = fake.state.lock().unwrap();
    assert_eq!((state.aborted, state.completed), (1, 0));
    fake.problems.check();
}

#[tokio::test]
async fn a_copy_in_parts_stops_before_the_upload_when_the_source_changed() {
    let (fake, server, _) = FakeCopyS3::start().await;
    fake.put("a.bin", b"0123456789", "application/octet-stream", "");
    let backend = anonymous_s3(&server.url, "bucket");
    let options = MultipartCopyOptions {
        expected_etag: "another".to_owned(),
        ..MultipartCopyOptions::default()
    };
    let error = copy(&backend, &OpCtx::default(), "a.bin", "b.bin", options, 5)
        .await
        .unwrap_err();
    assert_eq!(error.status(), 412);
    assert_eq!(error.code(), "preconditionfailed");
    let state = fake.state.lock().unwrap();
    assert_eq!(state.next_upload, 0);
}

#[tokio::test]
async fn each_request_of_a_copy_in_parts_takes_a_slot_of_the_gate() {
    let (fake, server, _) = FakeCopyS3::start_with_delay(Duration::from_millis(20)).await;
    fake.put("a.bin", &[b'y'; 40], "application/octet-stream", "k=v");
    let backend = anonymous_s3(&server.url, "bucket");
    let slots = Gate::new(1);
    let one_slot = slots.clone();
    let taken = Arc::new(AtomicUsize::new(0));
    let gate_taken = taken.clone();
    let gate: RequestGate = Arc::new(move |ctx: OpCtx| {
        let one_slot = one_slot.clone();
        gate_taken.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { gate::acquire(&ctx, &[&one_slot]).await })
    });
    let options = MultipartCopyOptions {
        gate: Some(gate),
        ..MultipartCopyOptions::default()
    };
    copy(&backend, &OpCtx::default(), "a.bin", "b.bin", options, 5)
        .await
        .unwrap();
    let state = fake.state.lock().unwrap();
    assert_eq!(state.most_in_flight, 1, "one slot lets one part at a time");
    // The HEAD, the tags, the start, eight parts and the completion.
    assert_eq!(taken.load(Ordering::SeqCst), 12);
    assert_eq!(state.objects["b.bin"].data, vec![b'y'; 40]);
    assert_eq!(slots.held(), 0);
}

#[tokio::test]
async fn four_parts_go_at_the_same_time_without_a_gate() {
    let (fake, server, _) = FakeCopyS3::start_with_delay(Duration::from_millis(50)).await;
    fake.put("a.bin", &[b'z'; 40], "application/octet-stream", "");
    let backend = anonymous_s3(&server.url, "bucket");
    copy(
        &backend,
        &OpCtx::default(),
        "a.bin",
        "b.bin",
        MultipartCopyOptions::default(),
        5,
    )
    .await
    .unwrap();
    let state = fake.state.lock().unwrap();
    assert_eq!(state.most_in_flight, 4);
    assert_eq!(state.objects["b.bin"].data, vec![b'z'; 40]);
}

#[tokio::test]
async fn the_other_headers_of_a_copy_in_parts_go_to_the_start_of_the_upload() {
    let (fake, server, _) = FakeCopyS3::start().await;
    fake.put("a.bin", b"0123456789", "application/octet-stream", "");
    let backend = anonymous_s3(&server.url, "bucket");
    let mut extra = HeaderMap::new();
    extra.insert("x-amz-storage-class", HeaderValue::from_static("STANDARD_IA"));
    extra.insert("cache-control", HeaderValue::from_static("no-cache"));
    let options = MultipartCopyOptions {
        extra_headers: extra,
        ..MultipartCopyOptions::default()
    };
    copy(&backend, &OpCtx::default(), "a.bin", "b.bin", options, 5)
        .await
        .unwrap();
    let state = fake.state.lock().unwrap();
    let created = &state.created["upload-1"];
    assert_eq!(header_of(created, "x-amz-storage-class"), "STANDARD_IA");
    assert_eq!(header_of(created, "cache-control"), "no-cache");
    assert_eq!(header_of(created, "content-type"), "application/octet-stream");
    assert_eq!(state.tagging_queries, 0, "a source with no tag needs no tag request");
    fake.problems.check();
}
