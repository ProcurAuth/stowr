// SPDX-License-Identifier: MIT OR Apache-2.0
//! The protection and the facts of the objects and of the buckets. This folder has four functions: Object Lock, the
//! encryption, the edit of the metadata, and the usage and the quota of a bucket with the capacity of its storage
//! (docs/ARCHITECTURE.md, "Object Lock", "Encryption", "Edit of the metadata", "Usage and quota of a bucket").
//!
//! This module owns the routes `/api/object-lock`, `/api/encryption`, `/api/metadata` and `/api/usage`. It also
//! owns the start probes of these functions and the usage readers of Garage, SeaweedFS and MinIO. It sends the S3
//! requests of these functions.
//!
//! The provider client gives the S3 requests through `S3Backend::send`. It also gives the admin requests of the
//! usage readers through an [`AdminTransport`], and it builds the reader of an `auth` block with
//! [`new_usage_reader`].

pub mod encryption;
pub mod metadata;
pub mod object_lock;
pub mod sign;
pub mod support;
pub mod usage;
pub mod usage_admin;
pub mod usage_capacity;
pub mod usage_garage;
pub mod usage_minio;
pub mod usage_seaweedfs;

#[cfg(test)]
mod testing;
#[cfg(test)]
mod tests;

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;

use http::HeaderMap;
use serde::Serialize;

use crate::common::BoxFuture;
use crate::common::config::{AuthConfig, UsageSource};
use crate::common::ctx::OpCtx;
use crate::common::error::Result;
use crate::common::http::{Route, RouteAccess, route};
use crate::common::time::Timestamp;

pub use encryption::{
    CustomerKeyInfo, customer_key_media_info, customer_key_refusal, kept_encryption_headers, write_encryption_headers,
};
pub use metadata::{MetadataEntry, ObjectHeaders};
pub use object_lock::{
    MAX_LOCK_CHECKS, MAX_LOCKED_KEYS, ObjectLockChange, ObjectLockState, is_object_locked, object_locked_error,
};
pub use usage::{UsageCapability, UsageResult};
pub use usage_admin::{AdminAnswer, AdminCredentials, AdminFailure, AdminTransport, AdminUrl};

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
    /// The mode of the default retention. It is empty for a bucket without a default retention.
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
    #[serde(skip_serializing_if = "String::is_empty")]
    pub kms_key_id: String,
    /// The S3 Bucket Key.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
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
    /// The used bytes, or -1 when unknown.
    pub used_bytes: i64,
    /// The objects, or -1 when unknown.
    pub used_objects: i64,
    /// The byte limit, 0 for no limit.
    pub limit_bytes: i64,
    /// The object limit, 0 for no limit.
    pub limit_objects: i64,
    /// True for an approximate number.
    pub approximate: bool,
    /// The source. The instance sets it: a reader leaves it empty.
    pub source: String,
    /// The time of the count at the source.
    pub as_of: Option<Timestamp>,
    /// The state of the count of the files of a volume: `computing`, `partial` or `ready`. It is empty for a bucket.
    pub self_state: String,
}

/// The capacity of the storage behind a bucket: the disks or the nodes of the provider, for all its buckets. For a
/// volume, it is the file system of the folder. The numbers are raw.
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
    /// True when a part of the storage did not answer, or the storage counts with a delay.
    pub approximate: bool,
    /// Why the number is approximate.
    pub approximate_reason: String,
    /// What the numbers count, for example `raw capacity of 3 storage nodes`.
    pub note: String,
    /// The time of the count at the source.
    pub as_of: Option<Timestamp>,
}

/// A reader of the usage of the buckets (Garage, SeaweedFS, MinIO, a volume).
pub trait BucketUsageReader: Send + Sync {
    /// The usage and the quota of a bucket.
    fn bucket_usage<'a>(&'a self, ctx: &'a OpCtx, bucket: &'a str) -> BoxFuture<'a, Result<BucketUsage>>;

    /// The capacity of the storage, when the reader gives it. The default is no capacity.
    fn storage_capacity<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<Option<StorageCapacity>>> {
        let _ = ctx;
        Box::pin(async { Ok(None) })
    }

    /// The source of the reader: `garage`, `seaweedfs`, `minio` or `statfs`. The default is empty: the instance
    /// then uses `statfs` for a volume.
    fn source(&self) -> &'static str {
        ""
    }

    /// True for a reader whose read costs no request (a volume: a `statfs` call and the count in memory of the size
    /// of the folder). The server reads it at each request, without the cache.
    fn is_live(&self) -> bool {
        false
    }
}

/// The state of Object Lock of an instance.
#[derive(Debug, Default)]
pub struct ObjectLockCapability {
    /// The configuration that the start probe read. It is `Some` only when the bucket has Object Lock.
    pub probed: Mutex<Option<ObjectLockConfiguration>>,
}

/// The state of the default encryption of an instance.
#[derive(Debug, Default)]
pub struct EncryptionCapability {
    /// `(supported, the default encryption)` from the start probe. `supported` is true when the probe read the
    /// default encryption of the bucket, or found that the bucket has none.
    pub probed: Mutex<Option<(bool, Option<BucketEncryption>)>>,
    /// What the provider does with `encryption = "sse-s3"`: `yes`, `no`, `unknown`, or empty without the key.
    pub applied: Mutex<String>,
}

/// The state of the edit of the metadata of an instance.
#[derive(Debug, Default)]
pub struct MetadataCapability {
    /// Set when the provider refused the copy that replaces the metadata.
    pub off: AtomicBool,
}

/// Make the reader of the `usage` block of an `auth` block. It gives `None` without a `usage` block. The
/// transport sends the admin requests; the credentials sign the requests to MinIO.
pub fn new_usage_reader(
    auth: &AuthConfig,
    transport: Arc<dyn AdminTransport>,
    credentials: AdminCredentials,
) -> Result<Option<Arc<dyn BucketUsageReader>>> {
    let Some(usage) = &auth.usage else {
        return Ok(None);
    };
    let endpoint = AdminUrl::parse("usage", &usage.endpoint)?;
    let reader: Arc<dyn BucketUsageReader> = match usage.source {
        UsageSource::Garage => Arc::new(usage_garage::GarageUsageReader {
            endpoint,
            transport,
            token: usage.token.clone(),
        }),
        UsageSource::SeaweedFs => Arc::new(usage_seaweedfs::SeaweedFsUsageReader {
            master: endpoint,
            filer: Some(AdminUrl::parse("usage filer", &usage.filer_endpoint)?),
            transport,
        }),
        UsageSource::MinIo => Arc::new(usage_minio::MinioUsageReader {
            endpoint,
            transport,
            credentials,
            region: auth.region.clone(),
        }),
    };
    Ok(Some(reader))
}

/// The routes of this module.
pub fn routes() -> Vec<Route> {
    vec![
        route("/api/metadata", RouteAccess::HandlerAsks, metadata::handle_metadata),
        route(
            "/api/encryption",
            RouteAccess::HandlerAsks,
            encryption::handle_encryption,
        ),
        route("/api/usage", RouteAccess::HandlerAsks, usage::handle_usage),
        route(
            "/api/object-lock",
            RouteAccess::HandlerAsks,
            object_lock::handle_object_lock,
        ),
    ]
}
