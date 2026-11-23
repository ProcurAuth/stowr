//! The tests of the archive routes and of the archive jobs, over the memory back end.
//!
//! The test that runs whole jobs is marked `ignore` until the job manager serves: run it with
//! `cargo test -- --ignored`. The same rules have tests over an archive in memory here.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Method};
use http_body::Frame;
use http_body_util::BodyExt;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use super::content::apply_object_safety_headers;
use super::entry::{
    EntryAnswer, ExtractTarget, archive_entry_open_error, entry_answer, entry_integrity, exact_archive_entry,
    extract_archive, validate_selectable_archive_entry,
};
use super::folder::INCOMPLETE_ENTRY_NAME;
use super::zip::tests::{Spec, simple};
use super::zip::writer::{EntryHeader, ZipWriter};
use super::zip::{FLAG_ENCRYPTED, METHOD_DEFLATE, ZipReader};
use super::*;
use crate::common::BoxFuture;
use crate::common::app::App;
use crate::common::config::{
    BucketConfig, Config, PERMISSION_DELETE, PERMISSION_READ, PERMISSION_WRITE, RuntimePolicy,
};
use crate::common::ctx::{GateMode, OpCtx};
use crate::common::error::{Error, Result};
use crate::common::http::{Body, Req, Response, empty, full};
use crate::common::query::Query;
use crate::common::storage::{Backend, DiscoveredCapabilities, ListOptions, ListPage, ObjectResponse};
use crate::instance::Instance;
use crate::instance::gate::{Gate, storage_busy};
use crate::jobs::{JobManager, JobRun, JobState, job_type};
use crate::testkit::{MemoryBackend, MemoryObject};

fn bucket(id: &str, root: &str, permissions: &[&str]) -> BucketConfig {
    BucketConfig {
        id: id.to_owned(),
        name: id.to_owned(),
        auth_id: "test-auth".to_owned(),
        provider: "s3".to_owned(),
        bucket: format!("{id}-bucket"),
        region: "test".to_owned(),
        root_prefix: root.to_owned(),
        permissions_defined: true,
        permissions: permissions.iter().map(|permission| (*permission).to_owned()).collect(),
        ..BucketConfig::default()
    }
}

fn instance(cfg: BucketConfig, backend: Arc<dyn Backend>, policy: &Arc<RuntimePolicy>) -> Arc<Instance> {
    let global = Gate::new(policy.max_concurrent_storage_requests);
    Arc::new(Instance::new(cfg, backend, policy.clone(), global))
}

/// The application of the tests: `readonly` (read) and `rw` (read, write, delete under `tenant/`), and more.
fn application(runtime: RuntimePolicy, rw: Arc<dyn Backend>, more: Vec<(BucketConfig, Arc<dyn Backend>)>) -> Arc<App> {
    let config = Config {
        job_history_limit: 10,
        runtime,
        ..Config::default()
    };
    let policy = Arc::new(config.runtime.clone());
    let readonly: Arc<dyn Backend> = Arc::new(MemoryBackend::with_objects(&[("readonly.txt", "read")]));
    let mut instances = vec![
        instance(bucket("readonly", "", &[PERMISSION_READ]), readonly, &policy),
        instance(
            bucket("rw", "tenant/", &[PERMISSION_READ, PERMISSION_WRITE, PERMISSION_DELETE]),
            rw,
            &policy,
        ),
    ];
    for (cfg, backend) in more {
        instances.push(instance(cfg, backend, &policy));
    }
    let access = crate::access::AccessLayer::new(&config).unwrap();
    Arc::new_cyclic(|weak| App {
        config: Arc::new(config),
        instances,
        auths: BTreeMap::new(),
        jobs: JobManager::new(weak.clone(), 10),
        uploads: crate::uploads::UploadManager::new(),
        sqlite: crate::pv_data::SqliteSessions::new(),
        access,
        resume_token_key: [0; 32],
    })
}

fn memory(objects: &[(&str, &str)]) -> Arc<MemoryBackend> {
    Arc::new(MemoryBackend::with_objects(objects))
}

fn default_objects() -> Arc<MemoryBackend> {
    memory(&[
        ("tenant/folder/direct.txt", "direct"),
        ("tenant/folder/nested/deep.txt", "deep"),
        ("tenant/a//./../b\\c", "opaque"),
    ])
}

fn put_object(backend: &MemoryBackend, key: &str, data: Vec<u8>) {
    backend.objects.lock().unwrap().insert(
        key.to_owned(),
        MemoryObject {
            data: Bytes::from(data),
            content_type: "application/zip".to_owned(),
        },
    );
}

/// A stored archive of these entries, as the tests put it in a bucket.
fn stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut writer = ZipWriter::new();
    for (name, data) in entries {
        writer
            .create(&EntryHeader {
                name: (*name).to_owned(),
                modified: None,
                permissions: 0o600,
            })
            .unwrap();
        writer.write(Bytes::copy_from_slice(data)).unwrap();
    }
    writer.finish().unwrap();
    writer
        .take_output()
        .iter()
        .flat_map(|part| part.iter().copied())
        .collect()
}

fn request(method: Method, target: &str, body: Body) -> Req {
    let (path, raw_query) = target.split_once('?').unwrap_or((target, ""));
    Req {
        method,
        path: path.to_owned(),
        raw_query: raw_query.to_owned(),
        query: Query::parse(raw_query),
        headers: HeaderMap::new(),
        body,
        ctx: OpCtx::default(),
        host: "localhost".to_owned(),
    }
}

fn post_json(target: &str, value: serde_json::Value) -> Req {
    let mut req = request(Method::POST, target, full(value.to_string()));
    req.headers.insert("content-type", "application/json".parse().unwrap());
    req
}

/// An answer read to its end.
struct Collected {
    status: u16,
    headers: HeaderMap,
    body: Vec<u8>,
    trailers: Option<HeaderMap>,
    cut: bool,
}

impl Collected {
    fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
    }

    fn trailer(&self, name: &str) -> &str {
        self.trailers
            .as_ref()
            .and_then(|trailers| trailers.get(name))
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

async fn collect(response: Response) -> Collected {
    let (parts, mut body) = response.into_parts();
    let mut collected = Collected {
        status: parts.status.as_u16(),
        headers: parts.headers,
        body: Vec::new(),
        trailers: None,
        cut: false,
    };
    while let Some(frame) = body.frame().await {
        match frame {
            Ok(frame) => match frame.into_data() {
                Ok(data) => collected.body.extend_from_slice(&data),
                Err(frame) => collected.trailers = frame.into_trailers().ok(),
            },
            Err(_) => {
                collected.cut = true;
                break;
            }
        }
    }
    collected
}

async fn zip_entries(bytes: &[u8]) -> BTreeMap<String, Vec<u8>> {
    let reader = ZipReader::open(Bytes::copy_from_slice(bytes), 0).await.unwrap();
    let mut out = BTreeMap::new();
    for entry in &reader.entries {
        let data = reader.read_entry(entry, u64::MAX).await.unwrap();
        out.insert(entry.name.clone(), data.to_vec());
    }
    out
}

// The ZIP of a folder.

#[tokio::test]
async fn the_archive_download_uses_the_requested_folder_filename() {
    let app = application(RuntimePolicy::default(), default_objects(), Vec::new());
    let target = "/api/archive?instance=rw&prefix=folder%2F&name=folder.zip";
    let answer = collect(handle_archive(app, request(Method::GET, target, empty())).await).await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert_eq!(answer.header("content-disposition"), "attachment; filename=folder.zip");
    assert_eq!(answer.header("content-type"), "application/zip");
    assert_eq!(answer.header("cache-control"), "private, no-store");
    let trailers: Vec<&str> = answer
        .headers
        .get_all("trailer")
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect();
    assert_eq!(
        trailers,
        [
            "X-Stowr-Archive-Status",
            "X-Stowr-Archive-Entries",
            "X-Stowr-Archive-Bytes"
        ]
    );
}

#[tokio::test]
async fn the_folder_archive_holds_each_object_under_its_relative_name() {
    let app = application(RuntimePolicy::default(), default_objects(), Vec::new());
    let target = "/api/archive?instance=rw&prefix=folder";
    let answer = collect(handle_archive(app, request(Method::GET, target, empty())).await).await;
    assert_eq!(answer.status, 200);
    assert!(!answer.cut);
    assert_eq!(answer.header("content-disposition"), "attachment; filename=folder.zip");
    assert_eq!(answer.trailer("x-stowr-archive-status"), "complete");
    assert_eq!(answer.trailer("x-stowr-archive-entries"), "2");
    assert_eq!(answer.trailer("x-stowr-archive-bytes"), "10");
    let entries = zip_entries(&answer.body).await;
    assert_eq!(entries.get("direct.txt").unwrap(), b"direct");
    assert_eq!(entries.get("nested/deep.txt").unwrap(), b"deep");
    assert_eq!(entries.len(), 2);
}

#[tokio::test]
async fn copies_folders_and_unsafe_keys_get_their_member_names() {
    let backend = memory(&[
        ("tenant/d/a/b.txt", "one"),
        ("tenant/d/a\\b.txt", "two"),
        ("tenant/d/sub/", ""),
        ("tenant/d/../x", "never"),
        ("tenant/d/C:/win.txt", "drive"),
    ]);
    let app = application(RuntimePolicy::default(), backend, Vec::new());
    let answer =
        collect(handle_archive(app, request(Method::GET, "/api/archive?instance=rw&prefix=d/", empty())).await).await;
    assert_eq!(answer.trailer("x-stowr-archive-status"), "complete");
    assert_eq!(answer.trailer("x-stowr-archive-entries"), "4");
    let entries = zip_entries(&answer.body).await;
    let names: Vec<&str> = entries.keys().map(String::as_str).collect();
    assert_eq!(names, ["_C:/win.txt", "a/b.txt", "a/b~2.txt", "sub/"]);
    assert_eq!(entries["a/b.txt"], b"one");
    assert_eq!(entries["a/b~2.txt"], b"two");
    let reader = ZipReader::open(Bytes::from(answer.body), 0).await.unwrap();
    let folder = reader.entry("sub/").unwrap();
    assert!(folder.is_dir());
    assert_eq!(folder.external_attributes, 0o100_755 << 16);
    assert_eq!(reader.entry("a/b.txt").unwrap().external_attributes, 0o100_600 << 16);
}

#[tokio::test]
async fn an_empty_prefix_and_another_method_are_refused() {
    let app = application(RuntimePolicy::default(), default_objects(), Vec::new());
    let answer = collect(
        handle_archive(
            app.clone(),
            request(Method::GET, "/api/archive?instance=rw&prefix=missing/", empty()),
        )
        .await,
    )
    .await;
    assert_eq!(answer.status, 404);
    assert!(answer.text().contains("\"code\":\"empty_prefix\""));
    let answer = collect(handle_archive(app, request(Method::POST, "/api/archive?instance=rw", empty())).await).await;
    assert_eq!(answer.status, 405);
    assert_eq!(answer.header("allow"), "GET");
}

#[tokio::test]
async fn an_archive_over_the_entry_limit_ends_with_the_incomplete_member() {
    let runtime = RuntimePolicy {
        max_archive_entries: 1,
        ..RuntimePolicy::default()
    };
    let app = application(runtime, default_objects(), Vec::new());
    let answer = collect(
        handle_archive(
            app,
            request(Method::GET, "/api/archive?instance=rw&prefix=folder/", empty()),
        )
        .await,
    )
    .await;
    assert_eq!(answer.status, 200);
    assert!(!answer.cut);
    assert_eq!(answer.trailer("x-stowr-archive-status"), "incomplete");
    assert_eq!(answer.trailer("x-stowr-archive-entries"), "2");
    assert_eq!(answer.trailer("x-stowr-archive-bytes"), "6");
    let entries = zip_entries(&answer.body).await;
    assert_eq!(entries["direct.txt"], b"direct");
    assert_eq!(
        String::from_utf8_lossy(&entries[INCOMPLETE_ENTRY_NAME]),
        "This archive is incomplete.\n\nCompleted entries: 2\nObject bytes streamed: 6\nReason: the archive exceeds the configured limit of 1 entries\n"
    );
}

#[derive(Debug, Default)]
struct Counters {
    open: usize,
    max_open: usize,
    get_calls: usize,
}

/// A back end with its own storage slots: a body holds its slot until the body drops, a read that must not wait
/// fails at once without a free slot. Each body waits 3 ms before its bytes.
struct GatedBackend {
    inner: MemoryBackend,
    slots: Arc<Semaphore>,
    counters: Arc<Mutex<Counters>>,
    listed_size_delta: i64,
}

struct OpenGuard {
    counters: Arc<Mutex<Counters>>,
    _permit: OwnedSemaphorePermit,
}

impl Drop for OpenGuard {
    fn drop(&mut self) {
        self.counters.lock().unwrap().open -= 1;
    }
}

struct SlowBody {
    inner: Body,
    delay: Option<Pin<Box<tokio::time::Sleep>>>,
    _guard: OpenGuard,
}

impl http_body::Body for SlowBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>>>> {
        let this = &mut *self;
        if let Some(delay) = this.delay.as_mut() {
            if delay.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            this.delay = None;
        }
        Pin::new(&mut this.inner).poll_frame(cx)
    }
}

impl GatedBackend {
    fn new(objects: &[(&str, &str)], slots: usize) -> Self {
        Self {
            inner: MemoryBackend::with_objects(objects),
            slots: Arc::new(Semaphore::new(slots)),
            counters: Arc::new(Mutex::new(Counters::default())),
            listed_size_delta: 0,
        }
    }
}

impl Backend for GatedBackend {
    fn list<'a>(&'a self, ctx: &'a OpCtx, options: &'a ListOptions) -> BoxFuture<'a, Result<ListPage>> {
        Box::pin(async move {
            let mut page = self.inner.list(ctx, options).await?;
            for object in &mut page.objects {
                object.size += self.listed_size_delta;
            }
            Ok(page)
        })
    }

    fn head<'a>(&'a self, ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<ObjectResponse>> {
        self.inner.head(ctx, key)
    }

    fn get<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        Box::pin(async move {
            let permit = if ctx.gate == GateMode::NoWait {
                self.slots.clone().try_acquire_owned().map_err(|_| storage_busy())?
            } else {
                self.slots.clone().acquire_owned().await.map_err(|_| Error::Canceled)?
            };
            let mut response = self.inner.get(ctx, key, headers).await?;
            {
                let mut counters = self.counters.lock().unwrap();
                counters.get_calls += 1;
                counters.open += 1;
                counters.max_open = counters.max_open.max(counters.open);
            }
            let inner = std::mem::replace(&mut response.body, empty());
            response.body = SlowBody {
                inner,
                delay: Some(Box::pin(tokio::time::sleep(Duration::from_millis(3)))),
                _guard: OpenGuard {
                    counters: self.counters.clone(),
                    _permit: permit,
                },
            }
            .boxed_unsync();
            Ok(response)
        })
    }

    fn put<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        body: Body,
        size: i64,
        content_type: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        self.inner.put(ctx, key, body, size, content_type)
    }

    fn delete<'a>(&'a self, ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<()>> {
        self.inner.delete(ctx, key)
    }

    fn copy<'a>(&'a self, ctx: &'a OpCtx, source: &'a str, destination: &'a str) -> BoxFuture<'a, Result<()>> {
        self.inner.copy(ctx, source, destination)
    }

    fn discover_capabilities<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<DiscoveredCapabilities>> {
        self.inner.discover_capabilities(ctx)
    }
}

/// The ZIP of 40 small objects with `slots` storage slots. Gives the back end and the maximum of open bodies.
async fn archive_with_gate(slots: usize, objects: usize) -> (Arc<GatedBackend>, usize) {
    let mut files = BTreeMap::new();
    let mut seed = Vec::new();
    for index in 0..objects {
        let content = format!("content of object {index}");
        files.insert(format!("file-{index:03}.txt"), content.clone());
        seed.push((format!("tenant/many/file-{index:03}.txt"), content));
    }
    let pairs: Vec<(&str, &str)> = seed.iter().map(|(key, text)| (key.as_str(), text.as_str())).collect();
    let backend = Arc::new(GatedBackend::new(&pairs, slots));
    let runtime = RuntimePolicy {
        max_concurrent_requests_per_storage: u32::try_from(slots).unwrap(),
        ..RuntimePolicy::default()
    };
    let app = application(runtime, backend.clone(), Vec::new());
    let target = "/api/archive?instance=rw&prefix=many%2F&name=many.zip";
    let answer = collect(handle_archive(app, request(Method::GET, target, empty())).await).await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    let got = zip_entries(&answer.body).await;
    assert_eq!(
        got.len(),
        files.len(),
        "trailer {}",
        answer.trailer("x-stowr-archive-status")
    );
    for (name, content) in &files {
        assert_eq!(got[name], content.as_bytes(), "{name}");
    }
    let counters = backend.counters.lock().unwrap();
    assert_eq!(counters.open, 0, "object bodies were left open");
    let max_open = counters.max_open;
    drop(counters);
    (backend, max_open)
}

#[tokio::test]
async fn the_archive_prefetch_overlaps_members_when_a_slot_is_free() {
    let (_, max_open) = archive_with_gate(2, 40).await;
    assert!(
        max_open >= 2,
        "the next member was never requested while the current one streamed (max open bodies = {max_open})"
    );
}

#[tokio::test]
async fn the_archive_prefetch_never_takes_a_contended_slot() {
    // With a single slot the prefetch cannot get one: members are fetched one after the other, never two at once.
    let (backend, max_open) = archive_with_gate(1, 40).await;
    assert_eq!(max_open, 1, "max open bodies with a single slot");
    assert_eq!(
        backend.counters.lock().unwrap().get_calls,
        40,
        "every member read exactly once"
    );
}

#[tokio::test]
async fn an_object_that_changes_size_makes_the_archive_incomplete() {
    let mut backend = GatedBackend::new(&[("tenant/s/a.txt", "12345")], 4);
    backend.listed_size_delta = 5;
    let app = application(RuntimePolicy::default(), Arc::new(backend), Vec::new());
    let answer =
        collect(handle_archive(app, request(Method::GET, "/api/archive?instance=rw&prefix=s/", empty())).await).await;
    assert_eq!(answer.trailer("x-stowr-archive-status"), "incomplete");
    assert_eq!(answer.trailer("x-stowr-archive-bytes"), "5");
    let entries = zip_entries(&answer.body).await;
    assert_eq!(entries["a.txt"], b"12345");
    assert!(
        String::from_utf8_lossy(&entries[INCOMPLETE_ENTRY_NAME])
            .ends_with("Reason: an object changed size while the archive was being streamed\n")
    );
}

// One entry of an archive.

async fn reader_of(entries: &[(&str, &[u8])]) -> Arc<ZipReader<Bytes>> {
    Arc::new(ZipReader::open(Bytes::from(stored_zip(entries)), 0).await.unwrap())
}

async fn serve(reader: &Arc<ZipReader<Bytes>>, name: &str, options: EntryAnswer) -> Collected {
    let entry = exact_archive_entry(reader, name).unwrap().clone();
    validate_selectable_archive_entry(&entry, 1 << 20).unwrap();
    let mut response = entry_answer(reader.clone(), entry, options).await.unwrap();
    apply_object_safety_headers(response.headers_mut());
    collect(response).await
}

#[tokio::test]
async fn an_archive_entry_never_serves_active_same_origin_content() {
    let reader = reader_of(&[
        (
            "page.html",
            b"<script src=\"/api/archive-entry?entry=pwn.js\"></script>",
        ),
        ("pwn.js", b"alert(1)"),
        (
            "logo.svg",
            b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>",
        ),
        ("note.txt", b"hello"),
    ])
    .await;
    for name in ["page.html", "pwn.js", "logo.svg"] {
        for head in [false, true] {
            let options = EntryAnswer {
                head,
                inline: true,
                image: false,
            };
            let answer = serve(&reader, name, options).await;
            assert_eq!(answer.status, 200);
            assert!(answer.header("content-security-policy").contains("sandbox"), "{name}");
            assert_eq!(answer.header("content-type"), "application/octet-stream", "{name}");
            assert!(answer.header("content-disposition").starts_with("attachment"), "{name}");
            assert_eq!(answer.header("x-content-type-options"), "nosniff");
            assert_eq!(answer.body.is_empty(), head);
        }
    }
    // An SVG used as an <img> cannot run script and must keep previewing.
    let image = serve(
        &reader,
        "logo.svg",
        EntryAnswer {
            head: false,
            inline: true,
            image: true,
        },
    )
    .await;
    assert_eq!(image.header("content-type"), "image/svg+xml");
    assert!(image.header("content-security-policy").contains("sandbox"));
    // Plain text members still preview inline.
    let text = serve(
        &reader,
        "note.txt",
        EntryAnswer {
            head: false,
            inline: true,
            image: false,
        },
    )
    .await;
    assert_eq!(text.body, b"hello");
    assert!(text.header("content-disposition").starts_with("inline"));
    assert_eq!(text.header("content-length"), "5");
    assert_eq!(text.header("cache-control"), "private, no-store");
}

#[tokio::test]
async fn a_selected_deflated_entry_streams_as_an_attachment() {
    let reader = Arc::new(
        ZipReader::open(
            simple(&[Spec::new("folder/readme.txt", b"inside archive").deflated()]),
            0,
        )
        .await
        .unwrap(),
    );
    assert_eq!(reader.entries[0].method, METHOD_DEFLATE);
    let answer = serve(&reader, "folder/readme.txt", EntryAnswer::default()).await;
    assert_eq!(answer.status, 200);
    assert_eq!(answer.text(), "inside archive");
    assert!(!answer.cut);
    let disposition = answer.header("content-disposition");
    assert!(
        disposition.starts_with("attachment") && disposition.contains("readme.txt"),
        "{disposition}"
    );
}

#[tokio::test]
async fn an_entry_with_a_wrong_checksum_still_ends_after_all_its_bytes() {
    let mut spec = Spec::new("bad.txt", b"payload");
    spec.crc = Some(1);
    let reader = Arc::new(ZipReader::open(simple(&[spec]), 0).await.unwrap());
    let answer = serve(&reader, "bad.txt", EntryAnswer::default()).await;
    assert_eq!(answer.body, b"payload");
    assert!(!answer.cut);
    let mut short = Spec::new("short.txt", b"abc");
    short.size = Some(10);
    let reader = Arc::new(ZipReader::open(simple(&[short]), 0).await.unwrap());
    let answer = serve(&reader, "short.txt", EntryAnswer::default()).await;
    assert!(answer.cut, "a cut entry must not look complete");
}

#[tokio::test]
async fn entries_that_cannot_be_selected_are_refused() {
    let mut link = Spec::new("link", b"/etc/passwd");
    link.creator = 3 << 8;
    link.attributes = 0o120_777 << 16;
    let mut encrypted = Spec::new("secret.bin", b"xxxx");
    encrypted.flags = FLAG_ENCRYPTED;
    let mut unix_dir = Spec::new("unix-dir", b"");
    unix_dir.creator = 3 << 8;
    unix_dir.attributes = 0o040_755 << 16;
    let archive = simple(&[
        Spec::new("docs/", b""),
        unix_dir,
        Spec::new("../evil.txt", b"x"),
        Spec::new("a//b.txt", b"x"),
        Spec::new("a\\b.txt", b"x"),
        link,
        encrypted,
        Spec::new("big.bin", &[0u8; 100]),
        Spec::new("twice.txt", b"1"),
        Spec::new("twice.txt", b"2"),
    ]);
    let reader = ZipReader::open(archive, 0).await.unwrap();
    let code = |name: &str| {
        let entry = exact_archive_entry(&reader, name).unwrap();
        let error = validate_selectable_archive_entry(entry, 99).unwrap_err();
        (error.status(), error.code())
    };
    assert_eq!(code("docs/"), (400, "archive_entry_is_directory".to_owned()));
    assert_eq!(code("unix-dir"), (400, "archive_entry_is_directory".to_owned()));
    assert_eq!(code("../evil.txt"), (400, "unsafe_archive_entry".to_owned()));
    assert_eq!(code("a//b.txt"), (400, "unsafe_archive_entry".to_owned()));
    assert_eq!(code("link"), (403, "archive_symlink_blocked".to_owned()));
    assert_eq!(code("secret.bin"), (422, "archive_entry_encrypted".to_owned()));
    assert_eq!(code("big.bin"), (413, "archive_entry_too_large".to_owned()));
    let big = exact_archive_entry(&reader, "big.bin").unwrap();
    assert_eq!(
        validate_selectable_archive_entry(big, 99).unwrap_err().public_message(),
        "the entry exceeds the configured 99-byte extraction limit"
    );
    assert!(validate_selectable_archive_entry(big, 0).is_ok());
    let backslash = exact_archive_entry(&reader, "a\\b.txt").unwrap();
    assert!(validate_selectable_archive_entry(backslash, 99).is_ok());
    let error = exact_archive_entry(&reader, "twice.txt").unwrap_err();
    assert_eq!(
        (error.status(), error.code()),
        (409, "ambiguous_archive_entry".to_owned())
    );
    let error = exact_archive_entry(&reader, "missing.txt").unwrap_err();
    assert_eq!(
        (error.status(), error.code()),
        (404, "archive_entry_not_found".to_owned())
    );
}

#[tokio::test]
async fn an_entry_that_cannot_be_opened_names_its_reason() {
    let mut bzip = Spec::new("dir/data.bin", b"data");
    bzip.method = 12;
    let reader = ZipReader::open(simple(&[bzip]), 0).await.unwrap();
    let entry = reader.entry("dir/data.bin").unwrap();
    let error = reader.open_entry(entry).await.unwrap_err();
    let answer = archive_entry_open_error(&entry.name, &error);
    assert_eq!(answer.status(), 422);
    assert!(answer.has_code("archive_entry_open_failed"));
    assert_eq!(
        answer.public_message(),
        "archive entry uses an unsupported compression method: data.bin"
    );
    let answer = archive_entry_open_error("x/y.txt", &Error::internal("broken"));
    assert_eq!(
        answer.public_message(),
        "archive entry could not be decompressed: y.txt"
    );
}

// The extraction and the integrity of entries.

/// A destination in memory that refuses an existing key, and keeps each saved state of the job.
#[derive(Default)]
struct MemoryTarget {
    backend: MemoryBackend,
    saved: Mutex<Vec<JobState>>,
}

impl ExtractTarget for MemoryTarget {
    fn put<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        body: Body,
        size: i64,
        content_type: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if self.backend.objects.lock().unwrap().contains_key(key) {
                return Err(Error::api(
                    409,
                    "object_exists",
                    "an object already exists at the destination",
                ));
            }
            self.backend.put(ctx, key, body, size, content_type).await
        })
    }

    fn save(&self, job: &JobState) -> Result<()> {
        self.saved.lock().unwrap().push(job.clone());
        Ok(())
    }
}

fn extraction_job(entries: &[&str]) -> JobState {
    JobState {
        id: "job_test".to_owned(),
        job_type: job_type::EXTRACT_ARCHIVE.to_owned(),
        instance: "rw".to_owned(),
        target_instance: "rw".to_owned(),
        source: "src.zip".to_owned(),
        target: "out/".to_owned(),
        entries: entries.iter().map(|entry| (*entry).to_owned()).collect(),
        ..JobState::default()
    }
}

#[tokio::test]
async fn selected_entries_are_extracted_to_new_objects() {
    let reader = Arc::new(
        ZipReader::open(
            simple(&[
                Spec::new("docs/a.txt", b"alpha").deflated(),
                Spec::new("img/b.png", b"png bytes"),
                Spec::new("c.txt", b"not selected"),
            ]),
            0,
        )
        .await
        .unwrap(),
    );
    let target = MemoryTarget::default();
    let mut job = extraction_job(&["docs/a.txt", "img/b.png"]);
    extract_archive(&OpCtx::default(), reader, &mut job, true, 1 << 20, &target)
        .await
        .unwrap();
    let objects = target.backend.objects.lock().unwrap().clone();
    assert_eq!(objects.len(), 2);
    assert_eq!(&objects["out/docs/a.txt"].data[..], b"alpha");
    assert_eq!(objects["out/docs/a.txt"].content_type, "application/octet-stream");
    assert_eq!(&objects["out/img/b.png"].data[..], b"png bytes");
    assert_eq!(objects["out/img/b.png"].content_type, "image/png");
    assert_eq!(job.processed, 2);
    assert_eq!(job.last_key, "img/b.png");
    let result = job.archive_extract.clone().unwrap();
    assert_eq!(result.extracted, 2);
    assert_eq!(result.bytes, 14);
    assert_eq!(result.archive_key, "src.zip");
    assert_eq!(result.target, "out/");
    assert!(result.completed_at.is_some());
    // The first save comes before the first write, then one for each entry and one at the end.
    assert_eq!(target.saved.lock().unwrap().len(), 4);
    let json = String::from_utf8(crate::common::json::to_vec(&result).unwrap()).unwrap();
    assert!(json.starts_with(
        "{\"archiveKey\":\"src.zip\",\"targetInstance\":\"rw\",\"target\":\"out/\",\"extracted\":2,\"bytes\":14,\"completedAt\":\""
    ));
}

#[tokio::test]
async fn an_extraction_resumes_after_its_last_written_entry() {
    let reader = Arc::new(
        ZipReader::open(simple(&[Spec::new("a", b"1"), Spec::new("b", b"22")]), 0)
            .await
            .unwrap(),
    );
    let target = MemoryTarget::default();
    let mut job = extraction_job(&["a", "b"]);
    job.processed = 1;
    job.archive_extract = Some(ArchiveExtractResult {
        archive_key: "src.zip".to_owned(),
        target_instance: "rw".to_owned(),
        target: "out/".to_owned(),
        extracted: 1,
        bytes: 1,
        ..ArchiveExtractResult::default()
    });
    extract_archive(&OpCtx::default(), reader.clone(), &mut job, true, 0, &target)
        .await
        .unwrap();
    let keys: Vec<String> = target.backend.objects.lock().unwrap().keys().cloned().collect();
    assert_eq!(keys, ["out/b"]);
    assert_eq!(job.archive_extract.as_ref().unwrap().bytes, 3);
    // A result of another archive starts again from the first entry.
    let target = MemoryTarget::default();
    let mut job = extraction_job(&["a", "b"]);
    job.processed = 1;
    job.archive_extract = Some(ArchiveExtractResult {
        archive_key: "other.zip".to_owned(),
        extracted: 1,
        ..ArchiveExtractResult::default()
    });
    extract_archive(&OpCtx::default(), reader.clone(), &mut job, true, 0, &target)
        .await
        .unwrap();
    assert_eq!(target.backend.objects.lock().unwrap().len(), 2);
    // A progress after the end of the selection is refused.
    let mut job = extraction_job(&["a"]);
    job.processed = 5;
    job.archive_extract = Some(ArchiveExtractResult {
        archive_key: "src.zip".to_owned(),
        target_instance: "rw".to_owned(),
        target: "out/".to_owned(),
        extracted: 5,
        ..ArchiveExtractResult::default()
    });
    let error = extract_archive(&OpCtx::default(), reader, &mut job, true, 0, &MemoryTarget::default())
        .await
        .unwrap_err();
    assert!(error.has_code("invalid_archive_progress"));
}

#[tokio::test]
async fn extraction_conflicts_are_refused_before_the_first_write() {
    let reader = Arc::new(
        ZipReader::open(
            simple(&[
                Spec::new("a/b.txt", b"1"),
                Spec::new("a\\b.txt", b"2"),
                Spec::new("src.zip", b"3"),
                Spec::new("dir/", b""),
                Spec::new("same", b"4"),
                Spec::new("same", b"5"),
            ]),
            0,
        )
        .await
        .unwrap(),
    );
    let cases: [(&[&str], &str, bool, &str); 5] = [
        (&["a/b.txt", "a\\b.txt"], "out/", true, "archive_target_collision"),
        (&["src.zip"], "", true, "archive_source_collision"),
        (&["missing"], "out/", true, "archive_entry_not_found"),
        (&["same"], "out/", true, "ambiguous_archive_entry"),
        (&["dir/"], "out/", true, "archive_entry_is_directory"),
    ];
    for (entries, folder, same, code) in cases {
        let target = MemoryTarget::default();
        let mut job = extraction_job(entries);
        job.target = folder.to_owned();
        let error = extract_archive(&OpCtx::default(), reader.clone(), &mut job, same, 0, &target)
            .await
            .unwrap_err();
        assert!(error.has_code(code), "{entries:?}: {error:?}");
        assert!(target.backend.objects.lock().unwrap().is_empty());
        assert!(target.saved.lock().unwrap().is_empty());
    }
    // The same key on another instance is no collision.
    let target = MemoryTarget::default();
    let mut job = extraction_job(&["src.zip"]);
    job.target = String::new();
    extract_archive(&OpCtx::default(), reader.clone(), &mut job, false, 0, &target)
        .await
        .unwrap();
    // An existing destination stops the job with the answer of the write.
    let mut job = extraction_job(&["src.zip"]);
    job.target = String::new();
    let error = extract_archive(&OpCtx::default(), reader, &mut job, false, 0, &target)
        .await
        .unwrap_err();
    assert!(error.has_code("object_exists"));
}

#[tokio::test]
async fn a_canceled_extraction_stops_with_the_control_error() {
    let reader = Arc::new(ZipReader::open(simple(&[Spec::new("a", b"1")]), 0).await.unwrap());
    let ctx = OpCtx::default();
    ctx.cancel.cancel();
    let mut job = extraction_job(&["a"]);
    let error = extract_archive(&ctx, reader, &mut job, true, 0, &MemoryTarget::default())
        .await
        .unwrap_err();
    assert_eq!(error, Error::Canceled);
}

#[tokio::test]
async fn the_integrity_of_an_entry_gives_its_digests() {
    let mut unchecked = Spec::new("zero.txt", b"abc");
    unchecked.crc = Some(0);
    let reader = ZipReader::open(simple(&[Spec::new("dir/abc.txt", b"abc").deflated(), unchecked]), 0)
        .await
        .unwrap();
    let request = ArchiveEntryIntegrityRequest {
        key: "bundle.zip".to_owned(),
        version: String::new(),
        entry: "dir/abc.txt".to_owned(),
    };
    let result = entry_integrity(&OpCtx::default(), &reader, &request, 0).await.unwrap();
    assert_eq!(result.size, 3);
    assert_eq!(
        result.sha256,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(result.md5, "900150983cd24fb0d6963f7d28e17f72");
    assert_eq!(result.crc32, "352441c2");
    assert_eq!(result.expected_crc32, "352441c2");
    assert!(result.crc32_matches);
    let json = String::from_utf8(crate::common::json::to_vec(&result).unwrap()).unwrap();
    assert!(
        json.starts_with("{\"archiveKey\":\"bundle.zip\",\"entry\":\"dir/abc.txt\",\"size\":3,\"compressedSize\":")
    );
    let request = ArchiveEntryIntegrityRequest {
        entry: "zero.txt".to_owned(),
        ..request
    };
    let result = entry_integrity(&OpCtx::default(), &reader, &request, 0).await.unwrap();
    assert_eq!(result.expected_crc32, "00000000");
    assert!(!result.crc32_matches);
    let error = entry_integrity(&OpCtx::default(), &reader, &request, 2)
        .await
        .unwrap_err();
    assert!(error.has_code("archive_entry_too_large"));
}

// The routes of the jobs.

#[tokio::test]
async fn extraction_into_a_read_denied_target_is_refused() {
    let wo: Arc<dyn Backend> = memory(&[("exists.txt", "secret")]);
    let rw = default_objects();
    put_object(&rw, "tenant/src.zip", stored_zip(&[("exists.txt", b"a")]));
    let app = application(
        RuntimePolicy::default(),
        rw,
        vec![(bucket("wo", "", &[PERMISSION_WRITE]), wo)],
    );
    let body = serde_json::json!({
        "instance": "rw", "key": "src.zip", "entries": ["exists.txt"], "targetInstance": "wo", "target": ""
    });
    let answer = collect(handle_archive_extract(app.clone(), post_json("/api/archive-extract", body)).await).await;
    assert_eq!(
        answer.status,
        403,
        "403 so that object_exists is never an oracle: {}",
        answer.text()
    );
    // The job itself enforces the same rule.
    let run = JobRun {
        app: app.clone(),
        ctx: OpCtx::default(),
        id: "direct".to_owned(),
    };
    let mut job = JobState {
        id: "direct".to_owned(),
        job_type: job_type::EXTRACT_ARCHIVE.to_owned(),
        instance: "rw".to_owned(),
        target_instance: "wo".to_owned(),
        source: "src.zip".to_owned(),
        entries: vec!["exists.txt".to_owned()],
        ..JobState::default()
    };
    let error = run_extraction(&run, &mut job).await.unwrap_err();
    assert_eq!(error.status(), 403);
    assert!(error.has_code("permission_denied"));
}

#[tokio::test]
async fn the_extraction_route_checks_its_request() {
    let app = application(RuntimePolicy::default(), default_objects(), Vec::new());
    let cases = [
        (
            serde_json::json!({"instance": "rw", "key": "a.zip", "entries": ["x"], "targetInstance": "nope"}),
            404,
            "unknown_target_instance",
        ),
        (
            serde_json::json!({"instance": "rw", "key": "a.zip", "entries": []}),
            400,
            "empty_archive_selection",
        ),
        (
            serde_json::json!({"instance": "rw", "key": "", "entries": ["x"]}),
            400,
            "invalid_archive",
        ),
        (
            serde_json::json!({"instance": "rw", "key": "a.zip", "entries": ["x"], "other": 1}),
            400,
            "invalid_json",
        ),
        (
            serde_json::json!({"instance": "readonly", "key": "a.zip", "entries": ["x"]}),
            403,
            "permission_denied",
        ),
    ];
    for (body, status, code) in cases {
        let answer =
            collect(handle_archive_extract(app.clone(), post_json("/api/archive-extract", body.clone())).await).await;
        assert_eq!(answer.status, status, "{body}: {}", answer.text());
        assert!(
            answer.text().contains(&format!("\"code\":\"{code}\"")),
            "{body}: {}",
            answer.text()
        );
    }
    let answer =
        collect(handle_archive_extract(app, request(Method::GET, "/api/archive-extract", empty())).await).await;
    assert_eq!(answer.status, 405);
    assert_eq!(answer.header("allow"), "POST");
}

#[tokio::test]
async fn the_entry_routes_check_their_request() {
    let app = application(RuntimePolicy::default(), default_objects(), Vec::new());
    let body = serde_json::json!({"instance": "rw", "key": "a.zip", "entry": " "});
    let answer =
        collect(handle_archive_entry_integrity(app.clone(), post_json("/api/archive-entry/integrity", body)).await)
            .await;
    assert_eq!(answer.status, 400);
    assert!(answer.text().contains("archive key and entry are required"));
    let answer = collect(
        handle_archive_entry(
            app.clone(),
            request(Method::GET, "/api/archive-entry?instance=rw&key=a.zip", empty()),
        )
        .await,
    )
    .await;
    assert_eq!(answer.status, 400);
    assert!(answer.text().contains("\"code\":\"invalid_archive_entry\""));
    assert!(answer.header("content-security-policy").contains("sandbox"));
    let answer = collect(
        handle_archive_entry(
            app.clone(),
            request(Method::GET, "/api/archive-entry?instance=rw&key=a.tar&entry=x", empty()),
        )
        .await,
    )
    .await;
    assert_eq!(answer.status, 415);
    assert!(answer.text().contains("\"code\":\"unsupported_archive\""));
    let answer =
        collect(handle_archive_entry(app, request(Method::DELETE, "/api/archive-entry?instance=rw", empty())).await)
            .await;
    assert_eq!(answer.status, 405);
    assert_eq!(answer.header("allow"), "GET, HEAD");
}

// The routes over the range reader of the instance, and the whole jobs.

fn entry_request(method: Method, key: &str, entry: &str, size: usize, inline: bool, headers: &[(&str, &str)]) -> Req {
    let mut target = format!(
        "/api/archive-entry?instance=rw&key={}&entry={}&size={size}",
        crate::common::query::query_escape(key),
        crate::common::query::query_escape(entry)
    );
    if inline {
        target.push_str("&inline=1");
    }
    let mut req = request(method, &target, empty());
    for (name, value) in headers {
        req.headers.insert(
            http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
    }
    req
}

#[tokio::test]
async fn the_archive_entry_route_never_serves_active_same_origin_content() {
    let rw = default_objects();
    let archive = stored_zip(&[
        (
            "page.html",
            b"<script src=\"/api/archive-entry?entry=pwn.js\"></script>",
        ),
        ("pwn.js", b"alert(1)"),
        (
            "logo.svg",
            b"<svg xmlns=\"http://www.w3.org/2000/svg\"><script>alert(1)</script></svg>",
        ),
        ("note.txt", b"hello"),
    ]);
    let size = archive.len();
    put_object(&rw, "tenant/bundle.zip", archive);
    let app = application(RuntimePolicy::default(), rw, Vec::new());
    for entry in ["page.html", "pwn.js", "logo.svg"] {
        for method in [Method::GET, Method::HEAD] {
            let req = entry_request(method.clone(), "bundle.zip", entry, size, true, &[]);
            let answer = collect(handle_archive_entry(app.clone(), req).await).await;
            assert_eq!(answer.status, 200, "{method} {entry}: {}", answer.text());
            assert!(answer.header("content-security-policy").contains("sandbox"));
            assert_eq!(answer.header("content-type"), "application/octet-stream");
            assert!(answer.header("content-disposition").starts_with("attachment"));
            assert_eq!(answer.header("x-content-type-options"), "nosniff");
        }
    }
    let req = entry_request(
        Method::GET,
        "bundle.zip",
        "logo.svg",
        size,
        true,
        &[("sec-fetch-dest", "image")],
    );
    let image = collect(handle_archive_entry(app.clone(), req).await).await;
    assert_eq!(image.header("content-type"), "image/svg+xml");
    assert!(image.header("content-security-policy").contains("sandbox"));
    let req = entry_request(Method::GET, "bundle.zip", "note.txt", size, true, &[]);
    let text = collect(handle_archive_entry(app, req).await).await;
    assert_eq!(text.text(), "hello");
    assert!(text.header("content-disposition").starts_with("inline"));
}

#[tokio::test]
async fn the_archive_entry_route_rejects_an_oversized_central_directory() {
    let rw = default_objects();
    let names: Vec<String> = (0..5).map(|index| format!("file-{index}.txt")).collect();
    let entries: Vec<(&str, &[u8])> = names.iter().map(|name| (name.as_str(), &b"x"[..])).collect();
    let archive = stored_zip(&entries);
    let size = archive.len();
    put_object(&rw, "tenant/many.zip", archive);
    let runtime = RuntimePolicy {
        max_archive_entries: 3,
        ..RuntimePolicy::default()
    };
    let app = application(runtime, rw, Vec::new());
    let req = entry_request(Method::GET, "many.zip", "file-0.txt", size, false, &[]);
    let answer = collect(handle_archive_entry(app, req).await).await;
    assert_eq!(answer.status, 413, "{}", answer.text());
    assert!(answer.text().contains("archive_too_many_entries"));
}

#[tokio::test]
async fn the_archive_entry_route_streams_a_selected_entry() {
    let rw = default_objects();
    let archive = super::zip::tests::build(
        &[Spec::new("folder/readme.txt", b"inside archive").deflated()],
        b"",
        b"",
        false,
        None,
    );
    let size = archive.len();
    put_object(&rw, "tenant/archive.zip", archive);
    rw.state().get_ranges.clear();
    let app = application(RuntimePolicy::default(), rw.clone(), Vec::new());
    let req = entry_request(Method::GET, "archive.zip", "folder/readme.txt", size, false, &[]);
    let answer = collect(handle_archive_entry(app, req).await).await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert_eq!(answer.text(), "inside archive");
    let disposition = answer.header("content-disposition");
    assert!(disposition.starts_with("attachment") && disposition.contains("readme.txt"));
    // Each read of the archive is an exact byte range.
    let ranges = rw.state().get_ranges.clone();
    assert!(!ranges.is_empty(), "expected at least one byte-range request");
    for value in ranges {
        let (start, end) = value
            .strip_prefix("bytes=")
            .and_then(|range| range.split_once('-'))
            .unwrap_or_else(|| panic!("range {value:?} is not an exact byte range"));
        let (start, end): (i64, i64) = (start.trim().parse().unwrap(), end.trim().parse().unwrap());
        assert!(start >= 0 && end >= start, "range {value:?} is invalid");
    }
}

/// A back end that holds each write until two writes have started: both extraction jobs own a storage slot before
/// either reads its archive.
struct BarrierPutBackend {
    inner: MemoryBackend,
    started: Mutex<usize>,
}

impl Backend for BarrierPutBackend {
    fn list<'a>(&'a self, ctx: &'a OpCtx, options: &'a ListOptions) -> BoxFuture<'a, Result<ListPage>> {
        self.inner.list(ctx, options)
    }

    fn head<'a>(&'a self, ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<ObjectResponse>> {
        self.inner.head(ctx, key)
    }

    fn get<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        self.inner.get(ctx, key, headers)
    }

    fn put<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        body: Body,
        size: i64,
        content_type: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            *self.started.lock().unwrap() += 1;
            let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
            while tokio::time::Instant::now() < deadline && *self.started.lock().unwrap() < 2 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            self.inner.put(ctx, key, body, size, content_type).await
        })
    }

    fn delete<'a>(&'a self, ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<()>> {
        self.inner.delete(ctx, key)
    }

    fn copy<'a>(&'a self, ctx: &'a OpCtx, source: &'a str, destination: &'a str) -> BoxFuture<'a, Result<()>> {
        self.inner.copy(ctx, source, destination)
    }

    fn discover_capabilities<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<DiscoveredCapabilities>> {
        self.inner.discover_capabilities(ctx)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs the job manager"]
async fn concurrent_extract_jobs_do_not_deadlock_on_storage_gates() {
    let backend = Arc::new(BarrierPutBackend {
        inner: MemoryBackend::default(),
        started: Mutex::new(0),
    });
    for index in 0..2u8 {
        let payload = vec![b'a' + index; 12 << 20];
        put_object(
            &backend.inner,
            &format!("tenant/big-{index}.zip"),
            stored_zip(&[("payload.bin", &payload)]),
        );
    }
    // Capacity equals the number of concurrent extraction jobs: each upload holds a slot while its lazy ZIP source
    // needs a second one.
    let runtime = RuntimePolicy {
        max_concurrent_requests_per_storage: 2,
        ..RuntimePolicy::default()
    };
    let app = application(runtime, backend.clone(), Vec::new());
    let mut ids = Vec::new();
    for index in 0..2 {
        let body = serde_json::json!({
            "instance": "rw", "key": format!("big-{index}.zip"), "entries": ["payload.bin"], "target": format!("out-{index}/")
        });
        let answer = collect(handle_archive_extract(app.clone(), post_json("/api/archive-extract", body)).await).await;
        assert_eq!(answer.status, 202, "{}", answer.text());
        let job: serde_json::Value = serde_json::from_slice(&answer.body).unwrap();
        ids.push(job["id"].as_str().unwrap().to_owned());
    }
    for id in &ids {
        let job = app.jobs.wait_for_terminal(id, Duration::from_secs(30)).await.unwrap();
        assert_eq!(job.status, "completed", "{job:?}");
    }
    let objects = backend.inner.objects.lock().unwrap();
    for index in 0..2 {
        assert_eq!(objects[&format!("tenant/out-{index}/payload.bin")].data.len(), 12 << 20);
    }
}

/// The target instance of a job, without the job manager: the create-only write of the instance, no save.
struct InstanceTarget {
    instance: Arc<Instance>,
}

impl ExtractTarget for InstanceTarget {
    fn put<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        body: Body,
        size: i64,
        content_type: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.instance
                .put_if_absent(ctx, &self.instance.full_key(key), body, size, content_type)
                .await
        })
    }

    fn save(&self, _job: &JobState) -> Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn concurrent_extractions_do_not_deadlock_on_storage_gates() {
    let backend = Arc::new(BarrierPutBackend {
        inner: MemoryBackend::default(),
        started: Mutex::new(0),
    });
    for index in 0..2u8 {
        let payload = vec![b'a' + index; 12 << 20];
        put_object(
            &backend.inner,
            &format!("tenant/big-{index}.zip"),
            stored_zip(&[("payload.bin", &payload)]),
        );
    }
    // Two slots: each write holds one while its archive reads take none.
    let runtime = RuntimePolicy {
        max_concurrent_requests_per_storage: 2,
        ..RuntimePolicy::default()
    };
    let app = application(runtime, backend.clone(), Vec::new());
    let rw = app.instance("rw").unwrap().clone();
    let extract = |index: usize| {
        let rw = rw.clone();
        async move {
            let ctx = OpCtx::default().gated(GateMode::Unbounded);
            let key = format!("big-{index}.zip");
            let reader = super::entry::open_archive_reader(
                &ctx.gated(GateMode::Exempt),
                &rw,
                &key,
                "",
                &super::entry::ListedArchive::default(),
                0,
            )
            .await?;
            let mut job = extraction_job(&["payload.bin"]);
            job.source = key;
            job.target = format!("out-{index}/");
            let target = InstanceTarget { instance: rw.clone() };
            extract_archive(&ctx, Arc::new(reader), &mut job, true, 0, &target).await?;
            Ok::<_, Error>(job)
        }
    };
    let (first, second) = tokio::time::timeout(Duration::from_secs(30), async { tokio::join!(extract(0), extract(1)) })
        .await
        .expect("the extractions wait on each other");
    for job in [first.unwrap(), second.unwrap()] {
        assert_eq!(job.archive_extract.unwrap().bytes, 12 << 20);
    }
    let objects = backend.inner.objects.lock().unwrap();
    for index in 0..2 {
        assert_eq!(objects[&format!("tenant/out-{index}/payload.bin")].data.len(), 12 << 20);
    }
}
