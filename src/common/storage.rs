//! The storage interfaces: the values of a listing and of an object, and the traits of a storage back end.
//!
//! A back end (S3, GCS, a volume) implements [`Backend`]. The optional functions of a back end are traits; the
//! back end gives each one that it has through an accessor of [`Backend`] (for example [`Backend::version_store`]).
//! The instance (`crate::instance::Instance`) wraps a back end: it adds the concurrency gates, the budgets, the
//! ceilings and the learned permissions. A read-only preview gets only the read functions of the instance.

use std::collections::BTreeMap;
use std::sync::Arc;

use http::HeaderMap;
use serde::Serialize;

use super::BoxFuture;
use super::ctx::OpCtx;
use super::error::Result;
use super::http::Body;
use super::time::Timestamp;

/// The state of a permission: `unknown`, `allowed` or `denied`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CapabilityStateName {
    /// Not tested: the action stays available and the provider decides.
    #[default]
    Unknown,
    /// Allowed.
    Allowed,
    /// Denied.
    Denied,
}

/// One permission of an instance, as `/api/instances` gives it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct CapabilityState {
    /// The state.
    pub state: CapabilityStateName,
    /// True when the interface offers the action.
    pub allowed: bool,
    /// True when a check or an operation proved the state.
    pub verified: bool,
    /// The source: `configuration`, `runtime`, `credentials`, `provider`, `observed`, `derived`, `access`...
    pub source: String,
    /// The reason.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub reason: String,
    /// The end of a short-lived denial that one provider call taught. It never goes to the client.
    #[serde(skip)]
    pub expires: Option<Timestamp>,
}

/// The three permissions of an instance.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Capabilities {
    /// `read`.
    pub read: CapabilityState,
    /// `write`.
    pub write: CapabilityState,
    /// `delete`.
    pub delete: CapabilityState,
    /// The permissions that the provider gave.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub permissions: Vec<String>,
    /// The time of the last check.
    #[serde(rename = "checkedAt", skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<Timestamp>,
    /// The public error of the last check.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

/// What a back end learned about its permissions.
#[derive(Clone, Debug, Default)]
pub struct DiscoveredCapabilities {
    /// The state of each permission that the back end could test.
    pub states: BTreeMap<String, CapabilityState>,
    /// The permissions that the provider gave.
    pub permissions: Vec<String>,
}

/// The options of one page of a listing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListOptions {
    /// The full prefix.
    pub prefix: String,
    /// `/` for one folder, empty for the tree.
    pub delimiter: String,
    /// The most entries of the page.
    pub max_results: u32,
    /// The continuation token of the provider.
    pub page_token: String,
    /// The key after which the page starts.
    pub start_after: String,
}

/// One object of a listing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObjectInfo {
    /// The full key.
    pub key: String,
    /// The size in bytes.
    pub size: i64,
    /// The last change.
    pub last_modified: Option<Timestamp>,
    /// The ETag without quotes.
    pub etag: String,
    /// The media type, when the listing gives it.
    pub content_type: String,
    /// True for an entry of a volume that the server does not read: a symbolic link that leaves the volume or that
    /// does not resolve, or a file that is not a regular file.
    pub unreadable: bool,
}

/// One page of a listing.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ListPage {
    /// The objects.
    pub objects: Vec<ObjectInfo>,
    /// The full prefixes of the folders (with a delimiter only).
    pub prefixes: Vec<String>,
    /// The token of the next page, empty on the last page.
    pub next_page_token: String,
}

/// The answer of a read of an object: the status, the headers and the body.
pub struct ObjectResponse {
    /// The status of the provider (200, 206, 304...).
    pub status: u16,
    /// The headers of the provider.
    pub headers: HeaderMap,
    /// The bytes. An empty body for a HEAD.
    pub body: Body,
}

impl std::fmt::Debug for ObjectResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObjectResponse")
            .field("status", &self.status)
            .field("headers", &self.headers)
            .finish_non_exhaustive()
    }
}

/// One version (or generation) of an object, as `/api/versions` gives it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct StoredObjectVersion {
    /// The version id.
    pub version: String,
    /// True for the current version.
    #[serde(rename = "isCurrent")]
    pub is_current: bool,
    /// True for a delete marker.
    #[serde(rename = "deleteMarker", skip_serializing_if = "std::ops::Not::not")]
    pub delete_marker: bool,
    /// The size.
    pub size: i64,
    /// The last change. No time gives the zero time of the answers.
    #[serde(rename = "lastModified", serialize_with = "crate::common::time::serialize_or_zero")]
    pub last_modified: Option<Timestamp>,
    /// The ETag.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub etag: String,
    /// The media type.
    #[serde(rename = "contentType", skip_serializing_if = "String::is_empty")]
    pub content_type: String,
    /// The checksums of the provider, by name.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub checksums: BTreeMap<String, String>,
}

/// One page of the versions of one key.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObjectVersionPage {
    /// The versions.
    pub versions: Vec<StoredObjectVersion>,
    /// The token of the next page.
    pub next_page_token: String,
}

/// One part of a multipart upload, as the provider lists it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MultipartPart {
    /// The part number, from 1.
    pub number: u32,
    /// The ETag of the part.
    pub etag: String,
    /// The size of the part.
    pub size: i64,
    /// The base64 SHA-256 of the part, when the provider gives it.
    pub checksum_sha256: String,
}

/// One part of the completion of a multipart upload.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompletedPart {
    /// The part number.
    pub number: u32,
    /// The ETag of the part.
    pub etag: String,
    /// The base64 SHA-256 of the part, for an upload with a checksum.
    pub checksum_sha256: String,
}

/// The progress function of a copy in parts: it gets the size of each copied part.
pub type CopyProgress = Arc<dyn Fn(i64) + Send + Sync>;

/// The gate of each provider request of a copy in parts: it counts one request in the budget of the context and
/// takes a slot of the gates of the instance. The gates get the slot back when the value is dropped.
pub type RequestGate = Arc<dyn Fn(OpCtx) -> BoxFuture<'static, Result<crate::instance::gate::Slot>> + Send + Sync>;

/// The options of a copy in parts (docs/ARCHITECTURE.md, "Copy in parts").
#[derive(Clone, Default)]
pub struct MultipartCopyOptions {
    /// The version of the source, or empty for the current version.
    pub source_version: String,
    /// New metadata: the standard headers and the `x-amz-meta-*` headers. `None` keeps the metadata of the source.
    pub metadata: Option<HeaderMap>,
    /// New tags as a query text (`a=b&c=d`). `None` keeps the tags of the source.
    pub tags: Option<String>,
    /// Other headers of `CreateMultipartUpload`.
    pub extra_headers: HeaderMap,
    /// The ETag that the caller read. A source with another ETag stops the copy with 412.
    pub expected_etag: String,
    /// The progress function.
    pub progress: Option<CopyProgress>,
    /// The gate of each provider request of the copy. The instance sets it; `None` takes no slot.
    pub gate: Option<RequestGate>,
}

impl std::fmt::Debug for MultipartCopyOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MultipartCopyOptions")
            .field("source_version", &self.source_version)
            .field("expected_etag", &self.expected_etag)
            .finish_non_exhaustive()
    }
}

/// The functions that each back end has.
pub trait Backend: Send + Sync + 'static {
    /// One page of a listing.
    fn list<'a>(&'a self, ctx: &'a OpCtx, options: &'a ListOptions) -> BoxFuture<'a, Result<ListPage>>;
    /// The headers of an object (HEAD).
    fn head<'a>(&'a self, ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<ObjectResponse>>;
    /// The bytes of an object (GET). The request headers carry `Range` and the conditions.
    fn get<'a>(&'a self, ctx: &'a OpCtx, key: &'a str, headers: &'a HeaderMap)
    -> BoxFuture<'a, Result<ObjectResponse>>;
    /// Write an object. `size` below 0 is an unknown size.
    fn put<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        body: Body,
        size: i64,
        content_type: &'a str,
    ) -> BoxFuture<'a, Result<()>>;
    /// Delete an object.
    fn delete<'a>(&'a self, ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<()>>;
    /// Copy one object with one request.
    fn copy<'a>(&'a self, ctx: &'a OpCtx, source: &'a str, destination: &'a str) -> BoxFuture<'a, Result<()>>;
    /// Learn the permissions of the credentials, without a write.
    fn discover_capabilities<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<DiscoveredCapabilities>>;

    /// A write that creates the object only when no object exists.
    fn conditional_writer(&self) -> Option<&dyn ConditionalWriter> {
        None
    }
    /// The delete of many keys in one request.
    fn batch_deleter(&self) -> Option<&dyn BatchDeleter> {
        None
    }
    /// The copy in parts on the provider.
    fn multipart_copier(&self) -> Option<&dyn MultipartCopier> {
        None
    }
    /// The move of an object with one rename (a volume).
    fn mover(&self) -> Option<&dyn Mover> {
        None
    }
    /// The removal of empty folders (a volume).
    fn folder_remover(&self) -> Option<&dyn FolderRemover> {
        None
    }
    /// The versions of the objects.
    fn version_store(&self) -> Option<&dyn VersionStore> {
        None
    }
    /// The S3 multipart upload.
    fn multipart_upload(&self) -> Option<&dyn MultipartUploadApi> {
        None
    }
    /// The list of the parts of a multipart upload.
    fn part_lister(&self) -> Option<&dyn MultipartPartLister> {
        None
    }
    /// The resumable upload (GCS, a volume).
    fn resumable(&self) -> Option<&dyn ResumableApi> {
        None
    }
    /// The list of the incomplete uploads.
    fn multipart_lister(&self) -> Option<&dyn crate::uploads::MultipartUploadLister> {
        None
    }
    /// The removal of one incomplete upload (a volume).
    fn incomplete_upload_remover(&self) -> Option<&dyn crate::uploads::IncompleteUploadRemover> {
        None
    }
    /// The object tags.
    fn tagger(&self) -> Option<&dyn crate::lifecycle::ObjectTagger> {
        None
    }
    /// The read and the write of the lifecycle rules, the versioning status and the provider flavour.
    fn bucket_rules(&self) -> Option<&dyn crate::lifecycle::BucketRules> {
        None
    }
    /// Object Lock.
    fn object_lock(&self) -> Option<&dyn crate::bucket::ObjectLockManager> {
        None
    }
    /// The default encryption of the bucket.
    fn encryption_reader(&self) -> Option<&dyn crate::bucket::EncryptionReader> {
        None
    }
    /// The edit of the metadata of an object.
    fn metadata_editor(&self) -> Option<&dyn crate::bucket::MetadataEditor> {
        None
    }
}

/// A write that creates the object only when no current object exists.
pub trait ConditionalWriter: Send + Sync {
    /// Write the object when no object exists; else 412 or `object_exists`.
    fn put_if_absent<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        body: Body,
        size: i64,
        content_type: &'a str,
    ) -> BoxFuture<'a, Result<()>>;
}

/// The delete of many keys in one request (S3 `DeleteObjects`).
pub trait BatchDeleter: Send + Sync {
    /// Delete at most 1000 keys. Refused keys give `Error::BatchDelete`.
    fn delete_many<'a>(&'a self, ctx: &'a OpCtx, keys: &'a [String]) -> BoxFuture<'a, Result<()>>;
}

/// The copy of an object in parts on the provider.
pub trait MultipartCopier: Send + Sync {
    /// Copy `source` to `destination` in parts.
    fn copy_multipart<'a>(
        &'a self,
        ctx: &'a OpCtx,
        source: &'a str,
        destination: &'a str,
        options: MultipartCopyOptions,
    ) -> BoxFuture<'a, Result<()>>;
}

/// The move of an object with one rename.
pub trait Mover: Send + Sync {
    /// Move `source` to `destination`.
    fn move_object<'a>(&'a self, ctx: &'a OpCtx, source: &'a str, destination: &'a str) -> BoxFuture<'a, Result<()>>;
}

/// The removal of the empty folders under a prefix.
pub trait FolderRemover: Send + Sync {
    /// Remove the folders under `prefix` (a full key) that hold no file.
    fn remove_empty_folders<'a>(&'a self, ctx: &'a OpCtx, prefix: &'a str) -> BoxFuture<'a, Result<()>>;
}

/// The versions (S3) or generations (GCS) of the objects.
pub trait VersionStore: Send + Sync {
    /// One page of the versions of one key.
    fn list_versions<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        page_token: &'a str,
        maximum: u32,
    ) -> BoxFuture<'a, Result<ObjectVersionPage>>;
    /// The headers of one version.
    fn head_version<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        version: &'a str,
    ) -> BoxFuture<'a, Result<ObjectResponse>>;
    /// The bytes of one version.
    fn get_version<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        version: &'a str,
        headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<ObjectResponse>>;
    /// Delete one version for ever.
    fn delete_version<'a>(&'a self, ctx: &'a OpCtx, key: &'a str, version: &'a str) -> BoxFuture<'a, Result<()>>;
    /// Copy one version onto its key. `extra` are more headers of the copy (S3 only).
    fn restore_version<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        version: &'a str,
        extra: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<()>>;
}

/// The S3 multipart upload.
pub trait MultipartUploadApi: Send + Sync {
    /// Start an upload; gives the upload id.
    fn initiate<'a>(&'a self, ctx: &'a OpCtx, key: &'a str, content_type: &'a str) -> BoxFuture<'a, Result<String>>;
    /// Send one part; gives its ETag.
    fn upload_part<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        upload_id: &'a str,
        number: u32,
        body: Body,
        size: i64,
    ) -> BoxFuture<'a, Result<String>>;
    /// Complete the upload.
    fn complete<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        upload_id: &'a str,
        parts: &'a [CompletedPart],
    ) -> BoxFuture<'a, Result<()>>;
    /// Abort the upload.
    fn abort<'a>(&'a self, ctx: &'a OpCtx, key: &'a str, upload_id: &'a str) -> BoxFuture<'a, Result<()>>;
}

/// The list of the parts of a multipart upload.
pub trait MultipartPartLister: Send + Sync {
    /// Each part of the upload, in the order of the numbers.
    fn list_parts<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        upload_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<MultipartPart>>>;
}

/// The resumable upload of GCS and of a volume. The session is an opaque text of the back end.
pub trait ResumableApi: Send + Sync {
    /// Start a session; gives the session text.
    fn initiate_resumable<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        total: i64,
        content_type: &'a str,
    ) -> BoxFuture<'a, Result<String>>;
    /// Send one chunk; gives the next offset and true when the object is complete.
    #[allow(clippy::too_many_arguments)]
    fn upload_chunk<'a>(
        &'a self,
        ctx: &'a OpCtx,
        session: &'a str,
        body: Body,
        start: i64,
        size: i64,
        total: i64,
        content_type: &'a str,
    ) -> BoxFuture<'a, Result<(i64, bool)>>;
    /// The next offset of a session, and true when the object is complete.
    fn query_resumable<'a>(
        &'a self,
        ctx: &'a OpCtx,
        session: &'a str,
        total: i64,
    ) -> BoxFuture<'a, Result<(i64, bool)>>;
    /// Abort a session.
    fn abort_resumable<'a>(&'a self, ctx: &'a OpCtx, session: &'a str) -> BoxFuture<'a, Result<()>>;
}
