//! The protection and the facts of the objects and of the buckets: Object Lock, the encryption, the edit of the
//! metadata, and the usage and the quota of a bucket with the capacity of its storage (docs/ARCHITECTURE.md,
//! "Object Lock", "Encryption", "Edit of the metadata", "Usage and quota of a bucket").
//!
//! This work package owns the routes `/api/object-lock`, `/api/encryption`, `/api/metadata` and `/api/usage`, the
//! start probes of these functions, the usage readers of Garage, SeaweedFS and MinIO, and the S3 requests of these
//! functions.

use std::sync::Mutex;
use std::sync::atomic::AtomicBool;

use http::HeaderMap;
use serde::Serialize;

use crate::common::BoxFuture;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Route, RouteAccess, route};
use crate::common::time::Timestamp;
use crate::provider::S3Backend;

/// The retention of one version.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Retention {
    /// `GOVERNANCE` or `COMPLIANCE`.
    pub mode: String,
    /// The retain-until date.
    pub retain_until: Option<Timestamp>,
}

/// The Object Lock configuration of a bucket.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObjectLockConfiguration {
    /// True for `ObjectLockEnabled: Enabled`.
    pub enabled: bool,
    /// The default retention: the mode, and the days or the years.
    pub default_mode: String,
    /// The days of the default retention.
    pub default_days: u32,
    /// The years of the default retention.
    pub default_years: u32,
}

/// The default retention of a bucket in `/api/instances` (`objectLockDefault`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ObjectLockDefaultJson {
    /// The mode.
    pub mode: String,
    /// The days.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub days: Option<u32>,
    /// The years.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub years: Option<u32>,
}

/// The default encryption of a bucket.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BucketEncryption {
    /// `AES256`, `aws:kms` or `aws:kms:dsse`.
    pub algorithm: String,
    /// The KMS key id.
    pub kms_key_id: String,
    /// The S3 Bucket Key.
    pub bucket_key_enabled: bool,
}

/// Object Lock of a back end.
pub trait ObjectLockManager: Send + Sync {
    /// The configuration of the bucket.
    fn configuration<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<ObjectLockConfiguration>>;
    /// The retention of a version, or `None`.
    fn retention<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        version: &'a str,
    ) -> BoxFuture<'a, Result<Option<Retention>>>;
    /// The legal hold of a version.
    fn legal_hold<'a>(&'a self, ctx: &'a OpCtx, key: &'a str, version: &'a str) -> BoxFuture<'a, Result<bool>>;
    /// Set the retention of a version.
    fn put_retention<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        version: &'a str,
        retention: &'a Retention,
        bypass_governance: bool,
    ) -> BoxFuture<'a, Result<()>>;
    /// Set or remove the legal hold of a version.
    fn put_legal_hold<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        version: &'a str,
        on: bool,
    ) -> BoxFuture<'a, Result<()>>;
}

/// The default encryption of a bucket.
pub trait EncryptionReader: Send + Sync {
    /// The default encryption, or `None` for a bucket without one.
    fn bucket_encryption<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<Option<BucketEncryption>>>;
}

/// The edit of the metadata of an object (a copy onto itself with `REPLACE`).
pub trait MetadataEditor: Send + Sync {
    /// Replace the metadata of an object, or of one version, when its ETag is `etag`.
    fn replace_metadata<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        version: &'a str,
        etag: &'a str,
        headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<()>>;
}

/// The usage and the quota of a bucket, from an admin API.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct BucketUsage {
    /// The used bytes.
    pub used_bytes: i64,
    /// The objects, or -1 when unknown.
    pub used_objects: i64,
    /// The byte limit, 0 for no limit.
    pub limit_bytes: i64,
    /// The object limit, 0 for no limit.
    pub limit_objects: i64,
    /// True for an approximate number.
    pub approximate: bool,
}

/// The capacity of the storage behind a bucket.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct StorageCapacity {
    /// `cluster`, `disks` or `filesystem`.
    pub scope: String,
    /// The total bytes.
    pub total_bytes: i64,
    /// The used bytes.
    pub used_bytes: i64,
    /// The free bytes.
    pub free_bytes: i64,
    /// True for an approximate number.
    pub approximate: bool,
    /// Why the number is approximate.
    pub approximate_reason: String,
    /// The note of the answer.
    pub note: String,
}

/// A reader of the usage of the buckets (Garage, SeaweedFS, MinIO, a volume).
pub trait BucketUsageReader: Send + Sync {
    /// The usage and the quota of a bucket.
    fn bucket_usage<'a>(&'a self, ctx: &'a OpCtx, bucket: &'a str) -> BoxFuture<'a, Result<BucketUsage>>;
    /// The capacity of the storage, when the reader gives it.
    fn storage_capacity<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<Option<StorageCapacity>>>;
}

/// The state of Object Lock of an instance.
#[derive(Debug, Default)]
pub struct ObjectLockCapability {
    /// The configuration that the start probe read, when the bucket has Object Lock.
    pub probed: Mutex<Option<ObjectLockConfiguration>>,
}

/// The state of the default encryption of an instance.
#[derive(Debug, Default)]
pub struct EncryptionCapability {
    /// `(supported, the default encryption)` from the start probe.
    pub probed: Mutex<Option<(bool, Option<BucketEncryption>)>>,
}

/// The state of the edit of the metadata of an instance.
#[derive(Debug, Default)]
pub struct MetadataCapability {
    /// Set when the provider refused the copy that replaces the metadata.
    pub off: AtomicBool,
}

/// The usage reader of an instance and its cache.
#[derive(Default)]
pub struct UsageCapability {
    /// The reader, with a `usage` block (or a volume).
    pub reader: Mutex<Option<std::sync::Arc<dyn BucketUsageReader>>>,
}

impl std::fmt::Debug for UsageCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsageCapability").finish_non_exhaustive()
    }
}

/// Add the encryption headers of the writes of a bucket (`x-amz-server-side-encryption: AES256` with
/// `encryption = "sse-s3"`), unless the request already names an encryption.
pub fn write_encryption_headers(cfg: &crate::common::config::BucketConfig, headers: &mut HeaderMap) {
    let _ = (cfg, headers);
}

/// The server-side encryption headers of a HEAD answer that a copy onto the same key sends again (SSE-S3 and
/// SSE-KMS, with the KMS key and the S3 Bucket Key).
pub fn kept_encryption_headers(headers: &HeaderMap) -> HeaderMap {
    let _ = headers;
    HeaderMap::new()
}

impl crate::instance::Instance {
    /// Explain a refused delete: an active legal hold or retention of the version gives `409 object_locked`; any
    /// other refusal stays as it is.
    pub async fn explain_lock_refusal(&self, ctx: &OpCtx, key: &str, version: &str, error: Error) -> Error {
        let _ = (ctx, key, version);
        error
    }
}

/// True for the error `409 object_locked`.
pub fn is_object_locked(error: &Error) -> bool {
    error.has_code("object_locked")
}

crate::stub_handler!(handle_metadata, "the route /api/metadata");
crate::stub_handler!(handle_encryption, "the route /api/encryption");
crate::stub_handler!(handle_usage, "the route /api/usage");
crate::stub_handler!(handle_object_lock, "the route /api/object-lock");

/// The routes of this work package.
pub fn routes() -> Vec<Route> {
    vec![
        route("/api/metadata", RouteAccess::HandlerAsks, handle_metadata),
        route("/api/encryption", RouteAccess::HandlerAsks, handle_encryption),
        route("/api/usage", RouteAccess::HandlerAsks, handle_usage),
        route("/api/object-lock", RouteAccess::HandlerAsks, handle_object_lock),
    ]
}

macro_rules! not_served_future {
    ($what:expr) => {
        Box::pin(async move { Err(Error::not_served($what)) })
    };
}

impl ObjectLockManager for S3Backend {
    fn configuration<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<ObjectLockConfiguration>> {
        not_served_future!("the S3 Object Lock")
    }
    fn retention<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _version: &'a str,
    ) -> BoxFuture<'a, Result<Option<Retention>>> {
        not_served_future!("the S3 Object Lock")
    }
    fn legal_hold<'a>(&'a self, _ctx: &'a OpCtx, _key: &'a str, _version: &'a str) -> BoxFuture<'a, Result<bool>> {
        not_served_future!("the S3 Object Lock")
    }
    fn put_retention<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _version: &'a str,
        _retention: &'a Retention,
        _bypass: bool,
    ) -> BoxFuture<'a, Result<()>> {
        not_served_future!("the S3 Object Lock")
    }
    fn put_legal_hold<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _version: &'a str,
        _on: bool,
    ) -> BoxFuture<'a, Result<()>> {
        not_served_future!("the S3 Object Lock")
    }
}

impl EncryptionReader for S3Backend {
    fn bucket_encryption<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<Option<BucketEncryption>>> {
        not_served_future!("the S3 default encryption")
    }
}

impl MetadataEditor for S3Backend {
    fn replace_metadata<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _version: &'a str,
        _etag: &'a str,
        _headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<()>> {
        not_served_future!("the S3 edit of the metadata")
    }
}
