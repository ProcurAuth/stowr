//! The test kit: an in-memory back end and the helpers that the tests of each module share.
//!
//! [`MemoryBackend`] acts as a small S3 provider: a listing with or without a delimiter (no page limit, as the
//! tests expect), exact and suffix byte ranges, the S3 multipart upload and the list of its parts, and the versions
//! of the objects when [`MemoryBackend::with_versions`] turns them on. Its [`MemoryState`] counts the calls and
//! lets a test change the answers (ranges ignored, `200` instead of `206`, pages of a listing, a slow listing).
//!
//! A test that changes one call of the back end writes a type that implements [`MemoryLayer`]: each call that the
//! type does not write goes to its memory back end.

use std::collections::BTreeMap;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::HeaderMap;
use http::header::{CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG, HeaderValue, LAST_MODIFIED, RANGE, SET_COOKIE};
use http_body::Frame;
use http_body_util::BodyExt;

use crate::common::BoxFuture;
use crate::common::config::{BucketConfig, PERMISSION_DELETE, PERMISSION_READ, PERMISSION_WRITE, RuntimePolicy};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Body, empty, read_limited};
use crate::common::storage::{
    Backend, BatchDeleter, CompletedPart, ConditionalWriter, DiscoveredCapabilities, FolderRemover, ListOptions,
    ListPage, Mover, MultipartCopier, MultipartPart, MultipartPartLister, MultipartUploadApi, ObjectInfo,
    ObjectResponse, ObjectVersionPage, ResumableApi, StoredObjectVersion, VersionStore,
};
use crate::common::time::Timestamp;
use crate::instance::Instance;
use crate::instance::gate::Gate;

/// The date of the last change of an object that a test puts without a date: 2026-01-02T03:04:05Z.
pub const DEFAULT_MODIFIED: Timestamp = Timestamp {
    secs: 1_767_323_045,
    nanos: 0,
    offset: 0,
};

/// The size of the frames of a body of the memory back end.
const FRAME_BYTES: usize = 32 << 10;

/// One object of the memory back end.
#[derive(Clone, Debug, Default)]
pub struct MemoryObject {
    /// The bytes.
    pub data: Bytes,
    /// The media type.
    pub content_type: String,
}

/// One multipart upload of the memory back end.
#[derive(Clone, Debug, Default)]
pub struct MemoryMultipart {
    /// The full key.
    pub key: String,
    /// The media type.
    pub content_type: String,
    /// The parts by number.
    pub parts: BTreeMap<u32, Bytes>,
}

/// One version of an object of the memory back end.
#[derive(Clone, Debug, Default)]
pub struct MemoryVersion {
    /// The version id.
    pub id: String,
    /// The bytes.
    pub data: Bytes,
    /// The media type.
    pub content_type: String,
    /// The date of the version.
    pub modified: Option<Timestamp>,
    /// True for the current version.
    pub current: bool,
    /// True for a delete marker.
    pub delete_marker: bool,
}

/// The counters and the switches of the memory back end.
#[derive(Debug, Default)]
pub struct MemoryState {
    /// The options of the last listing.
    pub last: ListOptions,
    /// The headers of the last read.
    pub last_get_headers: HeaderMap,
    /// The `Range` header of each read (empty without one).
    pub get_ranges: Vec<String>,
    /// The reads of an existing object.
    pub get_count: usize,
    /// The HEAD requests.
    pub head_count: usize,
    /// The listings.
    pub list_calls: usize,
    /// True: each read ignores its range and gives the whole object with `200`.
    pub ignore_ranges: bool,
    /// True: a range read gives the status `200` with its `Content-Range`.
    pub range_status_ok: bool,
    /// True: a range read gives the whole object with its `Content-Range`.
    pub range_body_full: bool,
    /// The pages that the listing gives instead of the objects. The token of page `n` is `page-n`.
    pub list_pages: Vec<ListPage>,
    /// The time of each listing.
    pub list_delay: Duration,
    /// The multipart uploads by id.
    pub multipart: BTreeMap<String, MemoryMultipart>,
    /// The number of the last multipart upload.
    pub next_upload: u32,
    /// The date of each object that has one. An object without a date has [`DEFAULT_MODIFIED`].
    pub modified: BTreeMap<String, Timestamp>,
    /// True: the back end gives the version functions.
    pub versioned: bool,
    /// The versions by full key.
    pub versions: BTreeMap<String, Vec<MemoryVersion>>,
    /// The deleted versions: `key@version`.
    pub deleted_versions: Vec<String>,
    /// The error of each list of the versions.
    pub version_list_error: Option<Error>,
}

/// A back end that keeps its objects in memory.
#[derive(Debug, Default)]
pub struct MemoryBackend {
    /// The objects by full key.
    pub objects: Mutex<BTreeMap<String, MemoryObject>>,
    /// The counters and the switches.
    pub state: Mutex<MemoryState>,
    /// The bytes of the bodies that the readers took.
    pub get_bytes_read: Arc<AtomicI64>,
}

/// The guard of a mutex, also after a panic of another test thread.
fn guard<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(value) => value,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn insert_header(headers: &mut HeaderMap, name: http::header::HeaderName, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(name, value);
    }
}

/// A body that gives its bytes in frames and counts the bytes that the reader takes.
struct CountingBody {
    data: Bytes,
    counter: Arc<AtomicI64>,
}

impl http_body::Body for CountingBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>>>> {
        if self.data.is_empty() {
            return Poll::Ready(None);
        }
        let count = self.data.len().min(FRAME_BYTES);
        let chunk = self.data.split_to(count);
        self.counter.fetch_add(count as i64, Ordering::SeqCst);
        Poll::Ready(Some(Ok(Frame::data(chunk))))
    }

    fn is_end_stream(&self) -> bool {
        self.data.is_empty()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        http_body::SizeHint::with_exact(self.data.len() as u64)
    }
}

fn missing() -> Error {
    Error::upstream(404, "NotFound", "missing")
}

fn missing_version() -> Error {
    Error::upstream(404, "NoSuchVersion", "missing")
}

impl MemoryBackend {
    /// An empty back end.
    pub fn new() -> Self {
        Self::default()
    }

    /// A back end with these objects (key and text), with the media type `text/plain`.
    pub fn with_objects(objects: &[(&str, &str)]) -> Self {
        let backend = Self::default();
        for (key, text) in objects {
            backend.insert(key, text.to_string(), "text/plain");
        }
        backend
    }

    /// The same back end with the version functions.
    pub fn with_versions(self) -> Self {
        self.state().versioned = true;
        self
    }

    /// The counters and the switches.
    pub fn state(&self) -> MutexGuard<'_, MemoryState> {
        guard(&self.state)
    }

    /// The objects.
    pub fn objects(&self) -> MutexGuard<'_, BTreeMap<String, MemoryObject>> {
        guard(&self.objects)
    }

    /// Put an object without a date.
    pub fn insert(&self, key: &str, data: impl Into<Bytes>, content_type: &str) {
        self.objects().insert(
            key.to_owned(),
            MemoryObject {
                data: data.into(),
                content_type: content_type.to_owned(),
            },
        );
        self.state().modified.remove(key);
    }

    /// Put an object with a date.
    pub fn insert_modified(&self, key: &str, data: impl Into<Bytes>, content_type: &str, modified: Timestamp) {
        self.insert(key, data, content_type);
        self.state().modified.insert(key.to_owned(), modified);
    }

    /// Add a version of a key.
    pub fn add_version(&self, key: &str, version: MemoryVersion) {
        self.state().versions.entry(key.to_owned()).or_default().push(version);
    }

    /// The object at a key.
    pub fn object(&self, key: &str) -> Option<MemoryObject> {
        self.objects().get(key).cloned()
    }

    /// True when an object exists at the key.
    pub fn contains(&self, key: &str) -> bool {
        self.objects().contains_key(key)
    }

    /// The keys, in order.
    pub fn keys(&self) -> Vec<String> {
        self.objects().keys().cloned().collect()
    }

    /// The bytes of the bodies that the readers took.
    pub fn bytes_read(&self) -> i64 {
        self.get_bytes_read.load(Ordering::SeqCst)
    }

    fn modified_of(&self, key: &str) -> Timestamp {
        self.state().modified.get(key).copied().unwrap_or(DEFAULT_MODIFIED)
    }

    fn etag(key: &str) -> String {
        format!("etag-{key}")
    }

    fn object_headers(key: &str, object: &MemoryObject, length: usize, modified: Timestamp) -> HeaderMap {
        let mut headers = HeaderMap::new();
        insert_header(&mut headers, CONTENT_TYPE, &object.content_type);
        insert_header(&mut headers, CONTENT_LENGTH, &length.to_string());
        insert_header(&mut headers, ETAG, &format!("\"{}\"", Self::etag(key)));
        insert_header(&mut headers, LAST_MODIFIED, &modified.http_date());
        headers
    }

    fn add_extra_headers(headers: &mut HeaderMap) {
        insert_header(headers, SET_COOKIE, "should-not-leak=1");
        if let Ok(name) = http::header::HeaderName::from_bytes(b"x-amz-meta-test") {
            headers.insert(name, HeaderValue::from_static("visible"));
        }
    }

    fn body(&self, data: Bytes) -> Body {
        CountingBody {
            data,
            counter: self.get_bytes_read.clone(),
        }
        .boxed_unsync()
    }

    /// The answer of a read of an object: the range of the request, with the switches of the state.
    fn serve_get(&self, key: &str, object: &MemoryObject, modified: Timestamp, request: &HeaderMap) -> ObjectResponse {
        let range = request
            .get(RANGE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_owned();
        let (ignore_ranges, range_status_ok, range_body_full) = {
            let mut state = self.state();
            state.last_get_headers = request.clone();
            state.get_count += 1;
            state.get_ranges.push(range.clone());
            (state.ignore_ranges, state.range_status_ok, state.range_body_full)
        };
        let full = object.data.clone();
        let size = full.len();
        let mut data = full.clone();
        let mut status = 200;
        let mut content_range = String::new();
        let range = range.trim();
        if !ignore_ranges && let Some(raw) = range.strip_prefix("bytes=") {
            match raw.split_once('-') {
                Some(("", suffix)) => {
                    if let Ok(length) = suffix.parse::<usize>()
                        && length > 0
                        && size > 0
                    {
                        let start = size.saturating_sub(length);
                        let end = size - 1;
                        content_range = format!("bytes {start}-{end}/{size}");
                        data = full.slice(start..=end);
                        status = 206;
                    }
                }
                Some((first, last)) => {
                    let start = first.parse::<usize>();
                    let end = if last.trim().is_empty() {
                        Ok(size.saturating_sub(1))
                    } else {
                        last.parse::<usize>()
                    };
                    if let (Ok(start), Ok(end)) = (start, end)
                        && start < size
                        && end >= start
                    {
                        let end = end.min(size - 1);
                        content_range = format!("bytes {start}-{end}/{size}");
                        data = full.slice(start..=end);
                        status = 206;
                    }
                }
                None => {}
            }
        }
        let mut headers = Self::object_headers(key, object, data.len(), modified);
        if !content_range.is_empty() {
            insert_header(&mut headers, CONTENT_RANGE, &content_range);
            if range_status_ok {
                status = 200;
            }
            if range_body_full {
                data = full;
                insert_header(&mut headers, CONTENT_LENGTH, &data.len().to_string());
            }
        }
        Self::add_extra_headers(&mut headers);
        ObjectResponse {
            status,
            headers,
            body: self.body(data),
        }
    }

    fn version_record(&self, key: &str, version: &str) -> Option<MemoryVersion> {
        self.state()
            .versions
            .get(key)
            .and_then(|records| records.iter().find(|record| record.id == version).cloned())
            .filter(|record| !record.delete_marker)
    }

    /// The listing of the objects: no page limit; with a delimiter, the folders after the objects of the page.
    fn list_objects(&self, options: &ListOptions) -> ListPage {
        let objects = self.objects().clone();
        let modified = self.state().modified.clone();
        let mut page = ListPage::default();
        let mut prefixes = std::collections::BTreeSet::new();
        for (key, object) in &objects {
            if !key.starts_with(&options.prefix) {
                continue;
            }
            if !options.start_after.is_empty() && key.as_str() <= options.start_after.as_str() {
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
                last_modified: Some(modified.get(key).copied().unwrap_or(DEFAULT_MODIFIED)),
                etag: Self::etag(key),
                content_type: object.content_type.clone(),
                unreadable: false,
            });
        }
        page.prefixes = prefixes.into_iter().collect();
        page
    }
}

impl Backend for MemoryBackend {
    fn list<'a>(&'a self, _ctx: &'a OpCtx, options: &'a ListOptions) -> BoxFuture<'a, Result<ListPage>> {
        Box::pin(async move {
            let (delay, pages) = {
                let mut state = self.state();
                state.last = options.clone();
                state.list_calls += 1;
                (state.list_delay, state.list_pages.clone())
            };
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            if !pages.is_empty() {
                let mut index = 0;
                if !options.page_token.is_empty() {
                    index = options
                        .page_token
                        .strip_prefix("page-")
                        .unwrap_or(&options.page_token)
                        .parse::<usize>()
                        .ok()
                        .filter(|index| *index < pages.len())
                        .ok_or_else(|| Error::internal(format!("invalid test page token {:?}", options.page_token)))?;
                }
                return Ok(pages[index].clone());
            }
            Ok(self.list_objects(options))
        })
    }

    fn head<'a>(&'a self, _ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<ObjectResponse>> {
        Box::pin(async move {
            self.state().head_count += 1;
            let object = self.object(key).ok_or_else(missing)?;
            let mut headers = Self::object_headers(key, &object, object.data.len(), self.modified_of(key));
            Self::add_extra_headers(&mut headers);
            Ok(ObjectResponse {
                status: 200,
                headers,
                body: empty(),
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
            let object = self.object(key).ok_or_else(missing)?;
            Ok(self.serve_get(key, &object, self.modified_of(key), headers))
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
            self.insert_modified(key, data, content_type, Timestamp::now());
            Ok(())
        })
    }

    fn delete<'a>(&'a self, _ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.objects().remove(key);
            Ok(())
        })
    }

    fn copy<'a>(&'a self, _ctx: &'a OpCtx, source: &'a str, destination: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let object = self.object(source).ok_or_else(missing)?;
            let modified = self.state().modified.get(source).copied();
            self.insert(destination, object.data, &object.content_type);
            if let Some(modified) = modified {
                self.state().modified.insert(destination.to_owned(), modified);
            }
            Ok(())
        })
    }

    fn discover_capabilities<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<DiscoveredCapabilities>> {
        Box::pin(async move { Ok(DiscoveredCapabilities::default()) })
    }

    fn version_store(&self) -> Option<&dyn VersionStore> {
        if self.state().versioned { Some(self) } else { None }
    }

    fn multipart_upload(&self) -> Option<&dyn MultipartUploadApi> {
        Some(self)
    }

    fn part_lister(&self) -> Option<&dyn MultipartPartLister> {
        Some(self)
    }
}

impl MultipartUploadApi for MemoryBackend {
    fn initiate<'a>(&'a self, _ctx: &'a OpCtx, key: &'a str, content_type: &'a str) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move {
            let mut state = self.state();
            state.next_upload += 1;
            let id = format!("upload-{}", state.next_upload);
            state.multipart.insert(
                id.clone(),
                MemoryMultipart {
                    key: key.to_owned(),
                    content_type: content_type.to_owned(),
                    parts: BTreeMap::new(),
                },
            );
            Ok(id)
        })
    }

    fn upload_part<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        upload_id: &'a str,
        number: u32,
        body: Body,
        _size: i64,
    ) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move {
            let (data, _) = read_limited(body, usize::MAX).await?;
            let mut state = self.state();
            let upload = state
                .multipart
                .get_mut(upload_id)
                .ok_or_else(|| Error::internal("multipart upload not found"))?;
            upload.parts.insert(number, data);
            Ok(format!("etag-{number}"))
        })
    }

    fn complete<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        upload_id: &'a str,
        parts: &'a [CompletedPart],
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let upload = self
                .state()
                .multipart
                .remove(upload_id)
                .ok_or_else(|| Error::internal("multipart upload not found"))?;
            let mut data = Vec::new();
            for part in parts {
                if let Some(bytes) = upload.parts.get(&part.number) {
                    data.extend_from_slice(bytes);
                }
            }
            self.insert_modified(&upload.key, data, &upload.content_type, Timestamp::now());
            Ok(())
        })
    }

    fn abort<'a>(&'a self, _ctx: &'a OpCtx, _key: &'a str, upload_id: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.state().multipart.remove(upload_id);
            Ok(())
        })
    }
}

impl MultipartPartLister for MemoryBackend {
    fn list_parts<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        upload_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<MultipartPart>>> {
        Box::pin(async move {
            let state = self.state();
            let upload = state
                .multipart
                .get(upload_id)
                .ok_or_else(|| Error::upstream(404, "NoSuchUpload", "multipart upload not found"))?;
            Ok(upload
                .parts
                .iter()
                .map(|(number, data)| MultipartPart {
                    number: *number,
                    etag: format!("etag-{number}"),
                    size: data.len() as i64,
                    checksum_sha256: String::new(),
                })
                .collect())
        })
    }
}

impl VersionStore for MemoryBackend {
    fn list_versions<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        key: &'a str,
        page_token: &'a str,
        maximum: u32,
    ) -> BoxFuture<'a, Result<ObjectVersionPage>> {
        Box::pin(async move {
            let state = self.state();
            if let Some(error) = &state.version_list_error {
                return Err(error.clone());
            }
            if !page_token.is_empty() {
                return Ok(ObjectVersionPage::default());
            }
            let mut records = state.versions.get(key).cloned().unwrap_or_default();
            if maximum > 0 && records.len() > maximum as usize {
                records.truncate(maximum as usize);
            }
            let mut versions: Vec<StoredObjectVersion> = records
                .into_iter()
                .map(|record| StoredObjectVersion {
                    version: record.id,
                    is_current: record.current,
                    delete_marker: record.delete_marker,
                    size: record.data.len() as i64,
                    last_modified: record.modified,
                    content_type: record.content_type,
                    ..StoredObjectVersion::default()
                })
                .collect();
            crate::instance::versions::sort_versions(&mut versions);
            Ok(ObjectVersionPage {
                versions,
                next_page_token: String::new(),
            })
        })
    }

    fn head_version<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        key: &'a str,
        version: &'a str,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        Box::pin(async move {
            let record = self.version_record(key, version).ok_or_else(missing_version)?;
            let mut headers = HeaderMap::new();
            insert_header(&mut headers, CONTENT_LENGTH, &record.data.len().to_string());
            insert_header(&mut headers, CONTENT_TYPE, &record.content_type);
            insert_header(&mut headers, ETAG, &format!("\"version-{version}\""));
            insert_header(
                &mut headers,
                LAST_MODIFIED,
                &record.modified.unwrap_or_default().http_date(),
            );
            Ok(ObjectResponse {
                status: 200,
                headers,
                body: empty(),
            })
        })
    }

    fn get_version<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        key: &'a str,
        version: &'a str,
        headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        Box::pin(async move {
            let record = self.version_record(key, version).ok_or_else(missing_version)?;
            let object = MemoryObject {
                data: record.data,
                content_type: record.content_type,
            };
            Ok(self.serve_get(key, &object, record.modified.unwrap_or_default(), headers))
        })
    }

    fn delete_version<'a>(&'a self, _ctx: &'a OpCtx, key: &'a str, version: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let mut state = self.state();
            let records = state.versions.entry(key.to_owned()).or_default();
            let position = records
                .iter()
                .position(|record| record.id == version)
                .ok_or_else(missing_version)?;
            records.remove(position);
            state.deleted_versions.push(format!("{key}@{version}"));
            Ok(())
        })
    }

    fn restore_version<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        key: &'a str,
        version: &'a str,
        _extra: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let record = self.version_record(key, version).ok_or_else(missing_version)?;
            self.insert_modified(key, record.data, &record.content_type, Timestamp::now());
            Ok(())
        })
    }
}

/// A test back end over a memory back end. Each call that the type does not write goes to the memory back end. A
/// type that implements this trait is a [`Backend`].
pub trait MemoryLayer: Send + Sync + 'static {
    /// The memory back end below the layer.
    fn memory(&self) -> &MemoryBackend;

    /// One page of a listing.
    fn list<'a>(&'a self, ctx: &'a OpCtx, options: &'a ListOptions) -> BoxFuture<'a, Result<ListPage>> {
        self.memory().list(ctx, options)
    }
    /// The headers of an object.
    fn head<'a>(&'a self, ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<ObjectResponse>> {
        self.memory().head(ctx, key)
    }
    /// The bytes of an object.
    fn get<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        self.memory().get(ctx, key, headers)
    }
    /// Write an object.
    fn put<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        body: Body,
        size: i64,
        content_type: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        self.memory().put(ctx, key, body, size, content_type)
    }
    /// Delete an object.
    fn delete<'a>(&'a self, ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<()>> {
        self.memory().delete(ctx, key)
    }
    /// Copy an object.
    fn copy<'a>(&'a self, ctx: &'a OpCtx, source: &'a str, destination: &'a str) -> BoxFuture<'a, Result<()>> {
        self.memory().copy(ctx, source, destination)
    }
    /// Learn the permissions.
    fn discover_capabilities<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<DiscoveredCapabilities>> {
        self.memory().discover_capabilities(ctx)
    }
    /// The conditional write: none.
    fn conditional_writer(&self) -> Option<&dyn ConditionalWriter> {
        None
    }
    /// The batch delete: none.
    fn batch_deleter(&self) -> Option<&dyn BatchDeleter> {
        None
    }
    /// The copy in parts: none.
    fn multipart_copier(&self) -> Option<&dyn MultipartCopier> {
        None
    }
    /// The move with one rename: none.
    fn mover(&self) -> Option<&dyn Mover> {
        None
    }
    /// The removal of empty folders: none.
    fn folder_remover(&self) -> Option<&dyn FolderRemover> {
        None
    }
    /// The versions of the memory back end.
    fn version_store(&self) -> Option<&dyn VersionStore> {
        self.memory().version_store()
    }
    /// The multipart upload of the memory back end.
    fn multipart_upload(&self) -> Option<&dyn MultipartUploadApi> {
        Some(self.memory())
    }
    /// The list of the parts of the memory back end.
    fn part_lister(&self) -> Option<&dyn MultipartPartLister> {
        Some(self.memory())
    }
    /// The resumable upload: none.
    fn resumable(&self) -> Option<&dyn ResumableApi> {
        None
    }
    /// The list of the incomplete uploads: none.
    fn multipart_lister(&self) -> Option<&dyn crate::uploads::MultipartUploadLister> {
        None
    }
    /// The removal of an incomplete upload: none.
    fn incomplete_upload_remover(&self) -> Option<&dyn crate::uploads::IncompleteUploadRemover> {
        None
    }
    /// The object tags: none.
    fn tagger(&self) -> Option<&dyn crate::lifecycle::ObjectTagger> {
        None
    }
    /// The bucket rules: none.
    fn bucket_rules(&self) -> Option<&dyn crate::lifecycle::BucketRules> {
        None
    }
    /// Object Lock: none.
    fn object_lock(&self) -> Option<&dyn crate::bucket::ObjectLockManager> {
        None
    }
    /// The default encryption: none.
    fn encryption_reader(&self) -> Option<&dyn crate::bucket::EncryptionReader> {
        None
    }
    /// The edit of the metadata: none.
    fn metadata_editor(&self) -> Option<&dyn crate::bucket::MetadataEditor> {
        None
    }
}

impl<T: MemoryLayer> Backend for T {
    fn list<'a>(&'a self, ctx: &'a OpCtx, options: &'a ListOptions) -> BoxFuture<'a, Result<ListPage>> {
        MemoryLayer::list(self, ctx, options)
    }
    fn head<'a>(&'a self, ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<ObjectResponse>> {
        MemoryLayer::head(self, ctx, key)
    }
    fn get<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        MemoryLayer::get(self, ctx, key, headers)
    }
    fn put<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        body: Body,
        size: i64,
        content_type: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        MemoryLayer::put(self, ctx, key, body, size, content_type)
    }
    fn delete<'a>(&'a self, ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<()>> {
        MemoryLayer::delete(self, ctx, key)
    }
    fn copy<'a>(&'a self, ctx: &'a OpCtx, source: &'a str, destination: &'a str) -> BoxFuture<'a, Result<()>> {
        MemoryLayer::copy(self, ctx, source, destination)
    }
    fn discover_capabilities<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<DiscoveredCapabilities>> {
        MemoryLayer::discover_capabilities(self, ctx)
    }
    fn conditional_writer(&self) -> Option<&dyn ConditionalWriter> {
        MemoryLayer::conditional_writer(self)
    }
    fn batch_deleter(&self) -> Option<&dyn BatchDeleter> {
        MemoryLayer::batch_deleter(self)
    }
    fn multipart_copier(&self) -> Option<&dyn MultipartCopier> {
        MemoryLayer::multipart_copier(self)
    }
    fn mover(&self) -> Option<&dyn Mover> {
        MemoryLayer::mover(self)
    }
    fn folder_remover(&self) -> Option<&dyn FolderRemover> {
        MemoryLayer::folder_remover(self)
    }
    fn version_store(&self) -> Option<&dyn VersionStore> {
        MemoryLayer::version_store(self)
    }
    fn multipart_upload(&self) -> Option<&dyn MultipartUploadApi> {
        MemoryLayer::multipart_upload(self)
    }
    fn part_lister(&self) -> Option<&dyn MultipartPartLister> {
        MemoryLayer::part_lister(self)
    }
    fn resumable(&self) -> Option<&dyn ResumableApi> {
        MemoryLayer::resumable(self)
    }
    fn multipart_lister(&self) -> Option<&dyn crate::uploads::MultipartUploadLister> {
        MemoryLayer::multipart_lister(self)
    }
    fn incomplete_upload_remover(&self) -> Option<&dyn crate::uploads::IncompleteUploadRemover> {
        MemoryLayer::incomplete_upload_remover(self)
    }
    fn tagger(&self) -> Option<&dyn crate::lifecycle::ObjectTagger> {
        MemoryLayer::tagger(self)
    }
    fn bucket_rules(&self) -> Option<&dyn crate::lifecycle::BucketRules> {
        MemoryLayer::bucket_rules(self)
    }
    fn object_lock(&self) -> Option<&dyn crate::bucket::ObjectLockManager> {
        MemoryLayer::object_lock(self)
    }
    fn encryption_reader(&self) -> Option<&dyn crate::bucket::EncryptionReader> {
        MemoryLayer::encryption_reader(self)
    }
    fn metadata_editor(&self) -> Option<&dyn crate::bucket::MetadataEditor> {
        MemoryLayer::metadata_editor(self)
    }
}

/// The configuration of a test bucket: name `id`, auth `test-auth`, provider `s3`, bucket `<id>-bucket`, region
/// `test`, and the permissions.
pub fn bucket_config(id: &str, root_prefix: &str, permissions: &[&str]) -> BucketConfig {
    BucketConfig {
        id: id.to_owned(),
        name: id.to_owned(),
        auth_id: "test-auth".to_owned(),
        provider: "s3".to_owned(),
        bucket: format!("{id}-bucket"),
        region: "test".to_owned(),
        permissions: permissions.iter().map(|value| (*value).to_owned()).collect(),
        permissions_defined: true,
        root_prefix: root_prefix.to_owned(),
        ..BucketConfig::default()
    }
}

/// An instance over a back end, with the default limits and its own gate of the process.
pub fn instance_over(cfg: BucketConfig, backend: Arc<dyn Backend>) -> Instance {
    instance_with_policy(cfg, backend, RuntimePolicy::default())
}

/// An instance over a back end, with these limits and its own gate of the process.
pub fn instance_with_policy(cfg: BucketConfig, backend: Arc<dyn Backend>, policy: RuntimePolicy) -> Instance {
    let global = Gate::new(policy.max_concurrent_storage_requests);
    Instance::new(cfg, backend, Arc::new(policy), global)
}

/// The back end of the test instance `rw`: `tenant/folder/direct.txt`, `tenant/folder/nested/deep.txt` and an
/// opaque key `tenant/a//./../b\c`.
pub fn read_write_backend() -> Arc<MemoryBackend> {
    Arc::new(MemoryBackend::with_objects(&[
        ("tenant/folder/direct.txt", "direct"),
        ("tenant/folder/nested/deep.txt", "deep"),
        ("tenant/a//./../b\\c", "opaque"),
    ]))
}

/// The back end of the test instance `readonly`: `readonly.txt`.
pub fn read_only_backend() -> Arc<MemoryBackend> {
    Arc::new(MemoryBackend::with_objects(&[("readonly.txt", "read")]))
}

/// The test instance `rw` over a back end: root prefix `tenant/`, the permissions read, write and delete.
pub fn read_write_instance(backend: Arc<dyn Backend>) -> Arc<Instance> {
    Arc::new(instance_over(
        bucket_config("rw", "tenant/", &[PERMISSION_READ, PERMISSION_WRITE, PERMISSION_DELETE]),
        backend,
    ))
}

/// The test instance `readonly` over a back end: no root prefix, the permission read.
pub fn read_only_instance(backend: Arc<dyn Backend>) -> Arc<Instance> {
    Arc::new(instance_over(
        bucket_config("readonly", "", &[PERMISSION_READ]),
        backend,
    ))
}

/// The bytes of a body, to its end.
pub async fn body_bytes(body: Body) -> Bytes {
    match read_limited(body, usize::MAX).await {
        Ok((bytes, _)) => bytes,
        Err(error) => Bytes::from(format!("<body error: {error}>")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ranges_of(backend: &MemoryBackend) -> Vec<String> {
        backend.state().get_ranges.clone()
    }

    #[tokio::test]
    async fn the_memory_back_end_lists_one_folder_with_its_folders() {
        let backend = MemoryBackend::with_objects(&[("a/1", "x"), ("a/2", "y"), ("b/1", "z"), ("c", "w")]);
        let ctx = OpCtx::default();
        let options = ListOptions {
            delimiter: "/".to_owned(),
            max_results: 2,
            ..ListOptions::default()
        };
        let page = backend.list(&ctx, &options).await.unwrap();
        assert_eq!(page.prefixes, vec!["a/", "b/"]);
        assert_eq!(page.objects.len(), 1);
        assert_eq!(page.objects[0].key, "c");
        assert_eq!(page.objects[0].etag, "etag-c");
        assert_eq!(page.objects[0].last_modified.unwrap().rfc3339(), "2026-01-02T03:04:05Z");
        assert!(page.next_page_token.is_empty());
        let after = ListOptions {
            prefix: "a/".to_owned(),
            start_after: "a/1".to_owned(),
            ..ListOptions::default()
        };
        let page = backend.list(&ctx, &after).await.unwrap();
        assert_eq!(page.objects.len(), 1);
        assert_eq!(page.objects[0].key, "a/2");
        assert_eq!(backend.state().list_calls, 2);
        assert_eq!(backend.state().last.prefix, "a/");
    }

    #[tokio::test]
    async fn the_memory_back_end_gives_the_pages_of_the_test() {
        let backend = MemoryBackend::new();
        backend.state().list_pages = vec![
            ListPage {
                prefixes: vec!["one/".to_owned()],
                next_page_token: "page-1".to_owned(),
                ..ListPage::default()
            },
            ListPage {
                prefixes: vec!["two/".to_owned()],
                ..ListPage::default()
            },
        ];
        let ctx = OpCtx::default();
        let mut options = ListOptions::default();
        let first = backend.list(&ctx, &options).await.unwrap();
        options.page_token = first.next_page_token;
        let second = backend.list(&ctx, &options).await.unwrap();
        assert_eq!(second.prefixes, vec!["two/"]);
        options.page_token = "page-9".to_owned();
        assert!(backend.list(&ctx, &options).await.is_err());
    }

    #[tokio::test]
    async fn the_memory_back_end_serves_exact_and_suffix_ranges() {
        let backend = MemoryBackend::with_objects(&[("k", "0123456789")]);
        let ctx = OpCtx::default();
        let mut headers = HeaderMap::new();
        headers.insert(RANGE, "bytes=2-4".parse().unwrap());
        let response = backend.get(&ctx, "k", &headers).await.unwrap();
        assert_eq!(response.status, 206);
        assert_eq!(response.headers.get(CONTENT_RANGE).unwrap(), "bytes 2-4/10");
        assert_eq!(response.headers.get(CONTENT_LENGTH).unwrap(), "3");
        assert_eq!(response.headers.get(ETAG).unwrap(), "\"etag-k\"");
        assert_eq!(backend.bytes_read(), 0);
        assert_eq!(&body_bytes(response.body).await[..], b"234");
        assert_eq!(backend.bytes_read(), 3);

        headers.insert(RANGE, "bytes=-4".parse().unwrap());
        let response = backend.get(&ctx, "k", &headers).await.unwrap();
        assert_eq!(response.headers.get(CONTENT_RANGE).unwrap(), "bytes 6-9/10");
        assert_eq!(&body_bytes(response.body).await[..], b"6789");

        headers.insert(RANGE, "bytes=8-".parse().unwrap());
        let response = backend.get(&ctx, "k", &headers).await.unwrap();
        assert_eq!(&body_bytes(response.body).await[..], b"89");

        headers.insert(RANGE, "bytes=20-30".parse().unwrap());
        let response = backend.get(&ctx, "k", &headers).await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(&body_bytes(response.body).await[..], b"0123456789");

        backend.state().range_status_ok = true;
        backend.state().range_body_full = true;
        headers.insert(RANGE, "bytes=0-1".parse().unwrap());
        let response = backend.get(&ctx, "k", &headers).await.unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.headers.get(CONTENT_RANGE).unwrap(), "bytes 0-1/10");
        assert_eq!(&body_bytes(response.body).await[..], b"0123456789");

        backend.state().ignore_ranges = true;
        let response = backend.get(&ctx, "k", &headers).await.unwrap();
        assert!(response.headers.get(CONTENT_RANGE).is_none());
        assert_eq!(
            ranges_of(&backend),
            vec![
                "bytes=2-4",
                "bytes=-4",
                "bytes=8-",
                "bytes=20-30",
                "bytes=0-1",
                "bytes=0-1"
            ]
        );
        assert_eq!(backend.state().get_count, 6);
        let error = backend.get(&ctx, "none", &headers).await.err().unwrap();
        assert!(error.is_not_found());
        assert_eq!(backend.state().get_count, 6);
    }

    #[tokio::test]
    async fn the_memory_back_end_keeps_a_multipart_upload() {
        let backend = MemoryBackend::new();
        let ctx = OpCtx::default();
        let id = backend.initiate(&ctx, "k", "text/plain").await.unwrap();
        assert_eq!(id, "upload-1");
        let etag = backend
            .upload_part(&ctx, "k", &id, 2, crate::common::http::full("world"), 5)
            .await
            .unwrap();
        assert_eq!(etag, "etag-2");
        backend
            .upload_part(&ctx, "k", &id, 1, crate::common::http::full("hello "), 6)
            .await
            .unwrap();
        let parts = backend.list_parts(&ctx, "k", &id).await.unwrap();
        assert_eq!(parts.iter().map(|part| part.number).collect::<Vec<_>>(), vec![1, 2]);
        assert_eq!(parts[0].size, 6);
        let completed = [1, 2].map(|number| CompletedPart {
            number,
            etag: format!("etag-{number}"),
            ..CompletedPart::default()
        });
        backend.complete(&ctx, "k", &id, &completed).await.unwrap();
        assert_eq!(&backend.object("k").unwrap().data[..], b"hello world");
        assert!(backend.state().multipart.is_empty());
        let error = backend.list_parts(&ctx, "k", &id).await.err().unwrap();
        assert!(error.is_not_found());
    }

    #[tokio::test]
    async fn the_memory_back_end_keeps_the_versions_when_they_are_on() {
        let backend = MemoryBackend::new();
        assert!(backend.version_store().is_none());
        let backend = backend.with_versions();
        let now = Timestamp::now();
        backend.add_version(
            "k",
            MemoryVersion {
                id: "v1".to_owned(),
                data: Bytes::from_static(b"previous"),
                modified: Some(now.plus_secs(-3600)),
                ..MemoryVersion::default()
            },
        );
        backend.add_version(
            "k",
            MemoryVersion {
                id: "v2".to_owned(),
                data: Bytes::from_static(b"current"),
                modified: Some(now),
                current: true,
                ..MemoryVersion::default()
            },
        );
        let ctx = OpCtx::default();
        let store = backend.version_store().unwrap();
        let page = store.list_versions(&ctx, "k", "", 0).await.unwrap();
        assert_eq!(page.versions[0].version, "v2");
        let response = store.get_version(&ctx, "k", "v1", &HeaderMap::new()).await.unwrap();
        assert_eq!(&body_bytes(response.body).await[..], b"previous");
        store.restore_version(&ctx, "k", "v1", &HeaderMap::new()).await.unwrap();
        assert_eq!(&backend.object("k").unwrap().data[..], b"previous");
        store.delete_version(&ctx, "k", "v1").await.unwrap();
        assert_eq!(backend.state().deleted_versions, vec!["k@v1"]);
        assert!(store.head_version(&ctx, "k", "v1").await.err().unwrap().is_not_found());
    }

    struct CountingDeletes {
        memory: MemoryBackend,
        deletes: Mutex<usize>,
    }

    impl MemoryLayer for CountingDeletes {
        fn memory(&self) -> &MemoryBackend {
            &self.memory
        }
        fn delete<'a>(&'a self, ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<()>> {
            *guard(&self.deletes) += 1;
            self.memory.delete(ctx, key)
        }
    }

    #[tokio::test]
    async fn a_layer_changes_one_call_and_keeps_the_others() {
        let layer = Arc::new(CountingDeletes {
            memory: MemoryBackend::with_objects(&[("a", "x")]),
            deletes: Mutex::new(0),
        });
        let backend: Arc<dyn Backend> = layer.clone();
        let ctx = OpCtx::default();
        backend.delete(&ctx, "a").await.unwrap();
        assert_eq!(*guard(&layer.deletes), 1);
        assert!(!layer.memory.contains("a"));
        assert!(backend.multipart_upload().is_some());
        assert!(backend.head(&ctx, "a").await.is_err());
    }
}
