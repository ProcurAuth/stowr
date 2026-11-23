//! The fakes of the tests: a target in memory that behaves like an S3 provider (with optional SHA-256 checksums) and
//! like a resumable provider, a list of incomplete uploads with the paging of three providers, an instance over it,
//! and an application for the route tests.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, Weak};

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, HeaderValue};
use http::{HeaderMap, Method};

use super::checksum::{composite_checksum, sha256_base64};
use super::session::UploadPartState;
use super::target::{Targets, UploadTarget};
use super::token::derive_cipher_key;
use super::{
    MultipartCursor, MultipartPartsSummary, MultipartUpload, MultipartUploadLister, MultipartUploadPage, UploadManager,
};
use crate::access::AccessLayer;
use crate::common::BoxFuture;
use crate::common::app::App;
use crate::common::config::{
    BucketConfig, Config, PERMISSION_DELETE, PERMISSION_READ, PERMISSION_WRITE, RuntimePolicy,
};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Body, Handler, Req, Response, empty, full, read_limited};
use crate::common::query::Query;
use crate::common::storage::{
    Backend, CompletedPart, DiscoveredCapabilities, ListOptions, ListPage, MultipartPart, ObjectResponse,
};
use crate::common::time::Timestamp;
use crate::instance::Instance;
use crate::instance::gate::Gate;
use crate::jobs::{JobManager, JobState};
use crate::lifecycle::Tag;
use crate::pv_data::SqliteSessions;

// --- A provider with multipart uploads and resumable sessions --------------------------------------------------------

/// One object of the fake store.
#[derive(Clone, Debug, Default)]
pub struct FakeObject {
    /// The bytes.
    pub data: Vec<u8>,
    /// The media type.
    pub content_type: String,
}

struct FakeMultipart {
    key: String,
    content_type: String,
    parts: BTreeMap<u32, Vec<u8>>,
}

struct FakeSession {
    key: String,
    content_type: String,
    data: Vec<u8>,
    total: i64,
}

/// The state of the fake provider.
#[derive(Default)]
pub struct FakeStore {
    next_upload: u32,
    multiparts: BTreeMap<String, FakeMultipart>,
    sessions: BTreeMap<String, FakeSession>,
    digests: BTreeMap<String, BTreeMap<u32, String>>,
    object_hash: BTreeMap<String, String>,
    /// The objects by full key.
    pub objects: BTreeMap<String, FakeObject>,
    /// True when the last initiation asked for the SHA-256 algorithm.
    pub algorithm_requested: bool,
    /// True for a provider that checks, stores and reports SHA-256 checksums.
    pub checksum_provider: bool,
    /// True for a provider with checksums that does not echo them (it stores none).
    pub silent: bool,
    /// True for a provider whose list of parts has no digest, as SeaweedFS.
    pub no_part_checksums: bool,
    /// The parts of the last completion.
    pub completed: Vec<CompletedPart>,
    /// The size that the next `head` reports instead of the real one.
    pub head_size_override: Option<i64>,
    /// The calls of `abort_multipart`: `key#id`.
    pub aborted: Vec<String>,
}

impl FakeStore {
    /// The ids of the multipart uploads that are open.
    pub fn open_multiparts(&self) -> Vec<String> {
        self.multiparts.keys().cloned().collect()
    }
}

/// A target in memory.
pub struct FakeTarget {
    id: String,
    provider: String,
    root_prefix: String,
    permissions: Option<Vec<String>>,
    /// The tags that the target keeps: false answers `501 tagging_unsupported`.
    pub tags_supported: bool,
    /// The provider state.
    pub store: Mutex<FakeStore>,
    /// The incomplete uploads that the target lists.
    pub lister: Arc<FakeLister>,
    abort_error: Mutex<Option<Error>>,
}

/// The key of the cipher of the targets of the tests: the key of the credentials `test-auth` with the secret `stable-test-secret`.
pub fn test_cipher_key() -> [u8; 32] {
    derive_cipher_key("test-auth", b"stable-test-secret\0")
}

impl FakeTarget {
    /// A target with all permissions.
    pub fn new(id: &str, provider: &str, root_prefix: &str) -> Self {
        Self {
            id: id.to_owned(),
            provider: provider.to_owned(),
            root_prefix: root_prefix.to_owned(),
            permissions: None,
            tags_supported: true,
            store: Mutex::new(FakeStore::default()),
            lister: Arc::new(FakeLister::new(ListStyle::Aws)),
            abort_error: Mutex::new(None),
        }
    }

    /// Make each abort of a multipart upload fail with this error.
    pub fn fail_abort_with(&self, error: Error) {
        *self
            .abort_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(error);
    }

    /// The same target with only these permissions.
    pub fn with_permissions(mut self, permissions: &[&str]) -> Self {
        self.permissions = Some(permissions.iter().map(|value| (*value).to_owned()).collect());
        self
    }

    /// The same target with a list of incomplete uploads.
    pub fn with_lister(mut self, lister: Arc<FakeLister>) -> Self {
        self.lister = lister;
        self
    }

    /// Run a function on the state of the provider.
    pub fn with_store<T>(&self, function: impl FnOnce(&mut FakeStore) -> T) -> T {
        let mut store = self.store.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        function(&mut store)
    }

    fn missing_object() -> Error {
        Error::upstream(404, "NoSuchKey", "The specified key does not exist.")
    }

    fn missing_upload() -> Error {
        Error::upstream(404, "NoSuchUpload", "multipart upload not found")
    }
}

impl UploadTarget for FakeTarget {
    fn id(&self) -> &str {
        &self.id
    }

    fn provider(&self) -> &str {
        &self.provider
    }

    fn cipher_key(&self) -> [u8; 32] {
        test_cipher_key()
    }

    fn full_key(&self, relative: &str) -> String {
        format!("{}{}", self.root_prefix, relative.trim_start_matches('/'))
    }

    fn relative_key(&self, full: &str) -> Option<String> {
        full.strip_prefix(self.root_prefix.as_str()).map(str::to_owned)
    }

    fn permitted(&self, permission: &str) -> bool {
        self.permissions
            .as_ref()
            .is_none_or(|permissions| permissions.iter().any(|value| value == permission))
    }

    fn require_permission(&self, permission: &str) -> Result<()> {
        if self.permitted(permission) {
            return Ok(());
        }
        Err(Error::api(
            403,
            "permission_denied",
            format!("instance {:?} does not expose {permission} permission", self.id),
        ))
    }

    fn require_tags(&self, tags: &[Tag]) -> Result<()> {
        if !tags.is_empty() && !self.tags_supported {
            return Err(Error::api(
                501,
                "tagging_unsupported",
                "this storage provider does not support object tags",
            ));
        }
        Ok(())
    }

    fn put_empty<'a>(&'a self, _ctx: &'a OpCtx, key: &'a str, content_type: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.with_store(|store| {
                store.objects.insert(
                    key.to_owned(),
                    FakeObject {
                        data: Vec::new(),
                        content_type: content_type.to_owned(),
                    },
                );
            });
            Ok(())
        })
    }

    fn head<'a>(&'a self, _ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<ObjectResponse>> {
        Box::pin(async move {
            self.with_store(|store| {
                let object = store.objects.get(key).ok_or_else(Self::missing_object)?;
                let size = store.head_size_override.unwrap_or(object.data.len() as i64);
                let mut headers = HeaderMap::new();
                if let Ok(value) = HeaderValue::from_str(&size.to_string()) {
                    headers.insert(CONTENT_LENGTH, value);
                }
                if store.checksum_provider
                    && !store.silent
                    && let Some(hash) = store.object_hash.get(key)
                    && let Ok(value) = HeaderValue::from_str(hash)
                {
                    headers.insert("x-amz-checksum-sha256", value);
                }
                Ok(ObjectResponse {
                    status: 200,
                    headers,
                    body: empty(),
                })
            })
        })
    }

    fn initiate_multipart<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        content_type: &'a str,
    ) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move {
            self.with_store(|store| {
                store.algorithm_requested = ctx.checksum.is_some();
                store.next_upload += 1;
                let id = format!("upload-{}", store.next_upload);
                store.multiparts.insert(
                    id.clone(),
                    FakeMultipart {
                        key: key.to_owned(),
                        content_type: content_type.to_owned(),
                        parts: BTreeMap::new(),
                    },
                );
                Ok(id)
            })
        })
    }

    fn upload_part<'a>(
        &'a self,
        ctx: &'a OpCtx,
        _key: &'a str,
        upload_id: &'a str,
        number: u32,
        body: Body,
        _size: i64,
    ) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move {
            let (data, _) = read_limited(body, usize::MAX).await?;
            self.with_store(|store| {
                if !store.multiparts.contains_key(upload_id) {
                    return Err(Error::internal("multipart upload not found"));
                }
                if let Some(transfer) = &ctx.checksum
                    && store.checksum_provider
                    && !store.silent
                {
                    if transfer.sha256 != sha256_base64(&data) {
                        return Err(Error::upstream(
                            400,
                            "BadDigest",
                            "the checksum does not match the part",
                        ));
                    }
                    store
                        .digests
                        .entry(upload_id.to_owned())
                        .or_default()
                        .insert(number, transfer.sha256.clone());
                    if let Ok(mut echoed) = transfer.echoed.lock() {
                        echoed.clone_from(&transfer.sha256);
                    }
                }
                if let Some(upload) = store.multiparts.get_mut(upload_id) {
                    upload.parts.insert(number, data.to_vec());
                }
                Ok(format!("etag-{number}"))
            })
        })
    }

    fn complete_multipart<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        key: &'a str,
        upload_id: &'a str,
        parts: &'a [CompletedPart],
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.with_store(|store| {
                store.completed = parts.to_vec();
                let states: Vec<UploadPartState> = parts
                    .iter()
                    .map(|part| UploadPartState {
                        part_number: part.number,
                        checksum_sha256: part.checksum_sha256.clone(),
                        ..UploadPartState::default()
                    })
                    .collect();
                if let Ok((digest, count)) = composite_checksum(&states) {
                    store.object_hash.insert(key.to_owned(), format!("{digest}-{count}"));
                }
                let upload = store
                    .multiparts
                    .remove(upload_id)
                    .ok_or_else(|| Error::internal("multipart upload not found"))?;
                let mut data = Vec::new();
                for part in parts {
                    if let Some(bytes) = upload.parts.get(&part.number) {
                        data.extend_from_slice(bytes);
                    }
                }
                store.objects.insert(
                    upload.key,
                    FakeObject {
                        data,
                        content_type: upload.content_type,
                    },
                );
                Ok(())
            })
        })
    }

    fn abort_multipart<'a>(&'a self, _ctx: &'a OpCtx, key: &'a str, upload_id: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let refusal = self
                .abort_error
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            if let Some(error) = refusal {
                return Err(error);
            }
            self.lister.abort(key, upload_id);
            self.with_store(|store| {
                store.aborted.push(format!("{key}#{upload_id}"));
                store.multiparts.remove(upload_id);
            });
            Ok(())
        })
    }

    fn list_multipart_parts<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        upload_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<MultipartPart>>> {
        Box::pin(async move {
            self.with_store(|store| {
                let upload = store.multiparts.get(upload_id).ok_or_else(Self::missing_upload)?;
                let digests = store.digests.get(upload_id);
                Ok(upload
                    .parts
                    .iter()
                    .map(|(number, data)| MultipartPart {
                        number: *number,
                        etag: format!("etag-{number}"),
                        size: data.len() as i64,
                        checksum_sha256: if store.no_part_checksums {
                            String::new()
                        } else {
                            digests.and_then(|map| map.get(number)).cloned().unwrap_or_default()
                        },
                    })
                    .collect())
            })
        })
    }

    fn initiate_resumable<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        key: &'a str,
        total: i64,
        content_type: &'a str,
    ) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move {
            self.with_store(|store| {
                store.next_upload += 1;
                let session = format!("session-{}", store.next_upload);
                store.sessions.insert(
                    session.clone(),
                    FakeSession {
                        key: key.to_owned(),
                        content_type: content_type.to_owned(),
                        data: Vec::new(),
                        total,
                    },
                );
                Ok(session)
            })
        })
    }

    fn upload_resumable_chunk<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        session: &'a str,
        body: Body,
        start: i64,
        _size: i64,
        total: i64,
        _content_type: &'a str,
    ) -> BoxFuture<'a, Result<(i64, bool)>> {
        Box::pin(async move {
            let (data, _) = read_limited(body, usize::MAX).await?;
            self.with_store(|store| {
                let entry = store
                    .sessions
                    .get_mut(session)
                    .ok_or_else(|| Error::upstream(404, "NoSuchSession", "no session"))?;
                if start != entry.data.len() as i64 {
                    return Err(Error::upstream(400, "BadOffset", "the offset is not the end"));
                }
                entry.data.extend_from_slice(&data);
                let next = entry.data.len() as i64;
                if next == total {
                    let done = store.sessions.remove(session);
                    if let Some(done) = done {
                        store.objects.insert(
                            done.key,
                            FakeObject {
                                data: done.data,
                                content_type: done.content_type,
                            },
                        );
                    }
                    return Ok((next, true));
                }
                Ok((next, false))
            })
        })
    }

    fn query_resumable<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        session: &'a str,
        total: i64,
    ) -> BoxFuture<'a, Result<(i64, bool)>> {
        Box::pin(async move {
            self.with_store(|store| match store.sessions.get(session) {
                Some(entry) => Ok((entry.data.len() as i64, entry.data.len() as i64 == entry.total)),
                None => Ok((total, true)),
            })
        })
    }

    fn abort_resumable<'a>(&'a self, _ctx: &'a OpCtx, session: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.with_store(|store| store.sessions.remove(session));
            Ok(())
        })
    }

    fn multipart_available(&self) -> bool {
        true
    }

    fn require_multipart_list(&self) -> Result<()> {
        Ok(())
    }

    fn list_multipart_uploads<'a>(
        &'a self,
        ctx: &'a OpCtx,
        cursor: &'a MultipartCursor,
        maximum: u32,
    ) -> BoxFuture<'a, Result<MultipartUploadPage>> {
        self.lister.list_uploads(ctx, cursor, maximum)
    }

    fn multipart_upload_parts<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        upload_id: &'a str,
    ) -> BoxFuture<'a, Result<MultipartPartsSummary>> {
        self.lister
            .upload_parts(ctx, key, upload_id, super::multiparts::PARTS_PAGE_SIZE)
    }
}

/// The targets of a test, by id of the instance.
#[derive(Default)]
pub struct FakeTargets {
    targets: BTreeMap<String, Arc<FakeTarget>>,
}

impl FakeTargets {
    /// A registry with these targets.
    pub fn new(targets: Vec<Arc<FakeTarget>>) -> Self {
        Self {
            targets: targets.into_iter().map(|target| (target.id.clone(), target)).collect(),
        }
    }
}

impl Targets for FakeTargets {
    fn target(&self, id: &str) -> Option<Arc<dyn UploadTarget>> {
        self.targets
            .get(id)
            .map(|target| target.clone() as Arc<dyn UploadTarget>)
    }
}

// --- The list of the incomplete uploads ------------------------------------------------------------------------------

/// The paging of a provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ListStyle {
    /// Sorts by key and upload id and pages with both markers (AWS and Garage).
    Aws,
    /// Sorts by upload id, sends no date and pages with `NextUploadIdMarker` only.
    SeaweedFs,
    /// Ignores `max-uploads` and sends one page.
    MinIo,
}

/// One incomplete upload of the fake list.
#[derive(Clone, Debug, Default)]
pub struct FakeUpload {
    /// The full key.
    pub key: String,
    /// The upload id.
    pub id: String,
    /// The start. No value gives no date.
    pub initiated: Option<Timestamp>,
    /// The size of each part.
    pub parts: Vec<i64>,
}

impl FakeUpload {
    /// An upload.
    pub fn new(key: &str, id: &str, initiated: Option<Timestamp>) -> Self {
        Self {
            key: key.to_owned(),
            id: id.to_owned(),
            initiated,
            parts: Vec::new(),
        }
    }

    /// The same upload with parts.
    pub fn with_parts(mut self, parts: Vec<i64>) -> Self {
        self.parts = parts;
        self
    }
}

#[derive(Default)]
struct ListerState {
    uploads: Vec<FakeUpload>,
    aborted: Vec<String>,
    stuck: bool,
    gone: BTreeSet<String>,
    refuse_status: Option<u16>,
    failing_parts: bool,
}

/// The incomplete uploads of a fake provider.
pub struct FakeLister {
    style: ListStyle,
    state: Mutex<ListerState>,
}

impl FakeLister {
    /// A list with this paging and no upload.
    pub fn new(style: ListStyle) -> Self {
        Self {
            style,
            state: Mutex::new(ListerState::default()),
        }
    }

    /// A list with uploads.
    pub fn with_uploads(style: ListStyle, uploads: Vec<FakeUpload>) -> Self {
        let lister = Self::new(style);
        lister.with_state(|state| state.uploads = uploads);
        lister
    }

    fn with_state<T>(&self, function: impl FnOnce(&mut ListerState) -> T) -> T {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        function(&mut state)
    }

    /// Make the provider send the markers of the request again.
    pub fn set_stuck(&self) {
        self.with_state(|state| state.stuck = true);
    }

    /// Make the list of the parts of an upload answer `404 NoSuchUpload`.
    pub fn set_gone(&self, id: &str) {
        self.with_state(|state| {
            state.gone.insert(id.to_owned());
        });
    }

    /// Make each request for the parts of an upload fail with a server error.
    pub fn set_failing_parts(&self) {
        self.with_state(|state| state.failing_parts = true);
    }

    /// Make each request answer with a status.
    pub fn refuse_with(&self, status: u16) {
        self.with_state(|state| state.refuse_status = Some(status));
    }

    /// The aborted uploads (`key#id`), in the order of their names.
    pub fn aborted(&self) -> Vec<String> {
        let mut aborted = self.with_state(|state| state.aborted.clone());
        aborted.sort();
        aborted
    }

    /// Remove an upload. Gives true when it existed.
    pub fn abort(&self, key: &str, id: &str) -> bool {
        self.with_state(|state| {
            if let Some(index) = state
                .uploads
                .iter()
                .position(|upload| upload.key == key && upload.id == id)
            {
                state.uploads.remove(index);
                state.aborted.push(format!("{key}#{id}"));
                return true;
            }
            false
        })
    }

    fn page(&self, cursor: &MultipartCursor, maximum: u32) -> Result<MultipartUploadPage> {
        self.with_state(|state| {
            if let Some(status) = state.refuse_status {
                let code = if status == 501 {
                    "NotImplemented"
                } else {
                    "AccessDenied"
                };
                return Err(Error::upstream(status, code, "no"));
            }
            let mut sorted = state.uploads.clone();
            let style = self.style;
            sorted.sort_by(|a, b| {
                if style == ListStyle::SeaweedFs || a.key == b.key {
                    a.id.cmp(&b.id)
                } else {
                    a.key.cmp(&b.key)
                }
            });
            let (key_marker, id_marker) = (&cursor.key_marker, &cursor.upload_id_marker);
            let mut page: Vec<FakeUpload> = Vec::new();
            for upload in sorted {
                match style {
                    ListStyle::SeaweedFs => {
                        if !id_marker.is_empty() && upload.id <= *id_marker {
                            continue;
                        }
                    }
                    ListStyle::Aws => {
                        if !key_marker.is_empty()
                            && (upload.key < *key_marker
                                || (upload.key == *key_marker && (id_marker.is_empty() || upload.id <= *id_marker)))
                        {
                            continue;
                        }
                    }
                    ListStyle::MinIo => {}
                }
                page.push(upload);
            }
            let mut truncated = false;
            if style != ListStyle::MinIo && maximum > 0 && page.len() > maximum as usize {
                page.truncate(maximum as usize);
                truncated = true;
            }
            let next = truncated.then(|| {
                let last = page.last().cloned().unwrap_or_default();
                if state.stuck {
                    MultipartCursor {
                        key_marker: key_marker.clone(),
                        upload_id_marker: id_marker.clone(),
                        skip: 0,
                    }
                } else if style == ListStyle::SeaweedFs {
                    MultipartCursor {
                        upload_id_marker: last.id,
                        ..MultipartCursor::default()
                    }
                } else {
                    MultipartCursor {
                        key_marker: last.key,
                        upload_id_marker: last.id,
                        skip: 0,
                    }
                }
            });
            let uploads = page
                .into_iter()
                .map(|upload| MultipartUpload {
                    key: upload.key,
                    upload_id: upload.id,
                    initiated: if style == ListStyle::SeaweedFs {
                        None
                    } else {
                        upload.initiated
                    },
                })
                .collect();
            Ok(MultipartUploadPage { uploads, next })
        })
    }

    fn parts(&self, key: &str, id: &str, maximum: u32) -> Result<MultipartPartsSummary> {
        self.with_state(|state| {
            if state.failing_parts {
                return Err(Error::upstream(500, "InternalError", "no"));
            }
            let missing = || Error::upstream(404, "NoSuchUpload", "no");
            if state.gone.contains(id) {
                return Err(missing());
            }
            let upload = state
                .uploads
                .iter()
                .find(|upload| upload.key == key && upload.id == id)
                .ok_or_else(missing)?;
            let truncated = maximum > 0 && upload.parts.len() > maximum as usize;
            let kept = if truncated {
                &upload.parts[..maximum as usize]
            } else {
                &upload.parts[..]
            };
            Ok(MultipartPartsSummary {
                parts: kept.len() as u32,
                bytes: kept.iter().sum(),
                at_least: truncated,
                unknown: false,
            })
        })
    }
}

impl MultipartUploadLister for FakeLister {
    fn list_uploads<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        cursor: &'a MultipartCursor,
        maximum: u32,
    ) -> BoxFuture<'a, Result<MultipartUploadPage>> {
        Box::pin(async move { self.page(cursor, maximum) })
    }

    fn upload_parts<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        key: &'a str,
        upload_id: &'a str,
        maximum: u32,
    ) -> BoxFuture<'a, Result<MultipartPartsSummary>> {
        Box::pin(async move { self.parts(key, upload_id, maximum) })
    }
}

// --- An instance and an application ----------------------------------------------------------------------------------

/// A back end whose only function is the list of the incomplete uploads.
pub struct ListBackend {
    /// The list, or `None` for a back end without the list.
    pub lister: Option<Arc<FakeLister>>,
}

fn unused<T: Send + 'static>() -> BoxFuture<'static, Result<T>> {
    Box::pin(async move { Err(Error::internal("this function is not used by the tests")) })
}

impl Backend for ListBackend {
    fn list<'a>(&'a self, _ctx: &'a OpCtx, _options: &'a ListOptions) -> BoxFuture<'a, Result<ListPage>> {
        unused()
    }
    fn head<'a>(&'a self, _ctx: &'a OpCtx, _key: &'a str) -> BoxFuture<'a, Result<ObjectResponse>> {
        unused()
    }
    fn get<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        unused()
    }
    fn put<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _body: Body,
        _size: i64,
        _content_type: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        unused()
    }
    fn delete<'a>(&'a self, _ctx: &'a OpCtx, _key: &'a str) -> BoxFuture<'a, Result<()>> {
        unused()
    }
    fn copy<'a>(&'a self, _ctx: &'a OpCtx, _source: &'a str, _destination: &'a str) -> BoxFuture<'a, Result<()>> {
        unused()
    }
    fn discover_capabilities<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<DiscoveredCapabilities>> {
        unused()
    }
    fn multipart_lister(&self) -> Option<&dyn MultipartUploadLister> {
        self.lister
            .as_deref()
            .map(|lister| lister as &dyn MultipartUploadLister)
    }
}

/// The instance `id` over a back end, with these permissions (all when empty) and this root prefix.
pub fn test_instance(id: &str, backend: ListBackend, root_prefix: &str, permissions: &[&str]) -> Arc<Instance> {
    let cfg = BucketConfig {
        id: id.to_owned(),
        name: id.to_owned(),
        auth_id: "test-auth".to_owned(),
        provider: "s3".to_owned(),
        bucket: format!("{id}-bucket"),
        region: "test".to_owned(),
        permissions: permissions.iter().map(|value| (*value).to_owned()).collect(),
        permissions_defined: !permissions.is_empty(),
        root_prefix: root_prefix.to_owned(),
        ..BucketConfig::default()
    };
    Arc::new(Instance::new(
        cfg,
        Arc::new(backend),
        Arc::new(RuntimePolicy::default()),
        Gate::new(8),
    ))
}

/// An application with the instances `readonly` (read permission, no root prefix) and `rw` (all permissions, root
/// prefix `tenant/`). The instance `rw` lists `lister`.
pub fn test_app(lister: Option<Arc<FakeLister>>) -> Arc<App> {
    let readonly = test_instance("readonly", ListBackend { lister: None }, "", &[PERMISSION_READ]);
    let read_write = test_instance(
        "rw",
        ListBackend { lister },
        "tenant/",
        &[PERMISSION_READ, PERMISSION_WRITE, PERMISSION_DELETE],
    );
    let config = Config::default();
    let access = AccessLayer::new(&config).unwrap();
    Arc::new(App {
        config: Arc::new(config),
        instances: vec![readonly, read_write],
        auths: BTreeMap::new(),
        jobs: JobManager::new(Weak::new(), 10),
        uploads: UploadManager::new(),
        sqlite: SqliteSessions::new(),
        access,
        resume_token_key: [7; 32],
    })
}

/// A request for a handler.
pub fn request(method: Method, target: &str, body: &str, headers: &[(&str, &str)]) -> Req {
    let (path, raw_query) = target.split_once('?').unwrap_or((target, ""));
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        if let (Ok(name), Ok(value)) = (
            http::header::HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            map.insert(name, value);
        }
    }
    Req {
        method,
        path: path.to_owned(),
        raw_query: raw_query.to_owned(),
        query: Query::parse(raw_query),
        headers: map,
        body: full(Bytes::from(body.to_owned())),
        ctx: OpCtx::default(),
        host: "localhost".to_owned(),
    }
}

/// Send a request to a handler. Gives the status, the headers and the body as a text.
pub async fn call(handler: Handler, app: &Arc<App>, request: Req) -> (u16, HeaderMap, String) {
    let response: Response = handler(app.clone(), request).await;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let (bytes, _) = read_limited(response.into_body(), usize::MAX).await.unwrap_or_default();
    (status, headers, String::from_utf8_lossy(&bytes).into_owned())
}

/// The progress of a job in a test: it records each save and never stops the job.
#[derive(Default)]
pub struct Recorder {
    /// The `(processed, aborted)` of each save.
    pub saves: Mutex<Vec<(i64, u64)>>,
}

impl super::JobProgress for Recorder {
    fn check_control(&self) -> Result<()> {
        Ok(())
    }

    fn save(&self, job: &JobState) -> Result<()> {
        if let Ok(mut saves) = self.saves.lock() {
            saves.push((
                job.processed,
                job.multipart_result.as_ref().map_or(0, |result| result.aborted),
            ));
        }
        Ok(())
    }
}
