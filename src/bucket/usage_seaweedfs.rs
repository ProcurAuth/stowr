//! The usage reader of SeaweedFS: the master gives the sizes of the volumes, the filer gives the quota. Both
//! requests have no credential: the master and the filer of SeaweedFS must be on a closed network.
//!
//! Measured on SeaweedFS 4.41:
//!
//! - The master: `GET /vol/status` gives `{"Volumes": {"DataCenters": {<dc>: {<rack>: {<node>: [volume, ...]}}}}}`. A
//!   volume has `Id`, `Collection`, `Size`, `FileCount`, `DeleteCount` and `DeletedByteCount`. The volumes of a
//!   bucket have the name of the bucket as their collection. The used bytes are the sum of `Size - DeletedByteCount`
//!   of these volumes: the bytes of the deleted files stay in a volume until a compaction. A replica of a volume has
//!   the same `Id` on another node: the reader counts each `Id` one time. The volume servers send their sizes to the
//!   master every few seconds: the number comes with a delay. The volumes count chunks, not objects: the number of
//!   objects is unknown.
//! - The filer: `GET /buckets/<bucket>?metadata=true` gives the entry of the bucket in JSON, with `Quota` in bytes.
//!   0 is no quota, and a negative value is a quota that `s3.bucket.quota -op=disable` turned off. An unknown bucket
//!   gives 404.

use std::collections::BTreeMap;
use std::sync::Arc;

use http::HeaderMap;
use http::header::{ACCEPT, HeaderValue};
use serde::Deserialize;

use super::usage::USAGE_SOURCE_SEAWEEDFS;
use super::usage_admin::{AdminError, AdminTransport, AdminUrl, get_usage_json};
use super::{BucketUsage, BucketUsageReader, StorageCapacity};
use crate::common::BoxFuture;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::query::query_escape;
use crate::common::time::Timestamp;

/// The size limit of the answer of `/vol/status`. A volume takes about 350 bytes: 16 MiB is about 45000 volumes.
pub const MAX_SEAWEEDFS_VOLUME_STATUS_BYTES: usize = 16 << 20;
/// The size limit of the entry of a bucket at the filer.
pub const MAX_SEAWEEDFS_BUCKET_ENTRY_BYTES: usize = 1 << 20;

/// The reader of SeaweedFS.
pub struct SeaweedFsUsageReader {
    /// The master.
    pub master: AdminUrl,
    /// The filer. It can be empty for a reader that reads the capacity only.
    pub filer: Option<AdminUrl>,
    /// The HTTP client.
    pub transport: Arc<dyn AdminTransport>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct VolumeStatus {
    #[serde(rename = "Volumes")]
    volumes: Option<Volumes>,
}

type Racks = BTreeMap<String, BTreeMap<String, Option<Vec<Volume>>>>;

#[derive(Deserialize, Default)]
#[serde(default)]
struct Volumes {
    #[serde(rename = "DataCenters")]
    data_centers: Option<BTreeMap<String, Racks>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Volume {
    #[serde(rename = "Id")]
    id: u32,
    #[serde(rename = "Collection")]
    collection: String,
    #[serde(rename = "Size")]
    size: i64,
    #[serde(rename = "DeletedByteCount")]
    deleted_byte_count: i64,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct BucketEntry {
    #[serde(rename = "Quota")]
    quota: i64,
}

impl SeaweedFsUsageReader {
    fn headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers
    }

    /// Add the logical size of each volume of the collection of the bucket, one time for each volume id.
    async fn used_bytes(&self, ctx: &OpCtx, bucket: &str) -> std::result::Result<i64, AdminError> {
        let url = self.master.join(&["vol", "status"]);
        let answer: VolumeStatus = get_usage_json(
            self.transport.as_ref(),
            ctx,
            &url,
            Self::headers(),
            "volume status",
            MAX_SEAWEEDFS_VOLUME_STATUS_BYTES,
        )
        .await?;
        let mut sizes: BTreeMap<u32, i64> = BTreeMap::new();
        let centers = answer
            .volumes
            .and_then(|volumes| volumes.data_centers)
            .unwrap_or_default();
        for racks in centers.values() {
            for nodes in racks.values() {
                for volumes in nodes.values().flatten() {
                    for volume in volumes {
                        if volume.collection != bucket {
                            continue;
                        }
                        let size = (volume.size - volume.deleted_byte_count).max(0);
                        let entry = sizes.entry(volume.id).or_insert(0);
                        *entry = (*entry).max(size);
                    }
                }
            }
        }
        Ok(sizes.values().sum())
    }

    /// Read the quota in the entry of the bucket at the filer. 0 is no quota.
    async fn quota(&self, ctx: &OpCtx, bucket: &str) -> std::result::Result<i64, AdminError> {
        let Some(filer) = &self.filer else {
            return Err(AdminError::message("bucket entry: the filer is not configured"));
        };
        let url = format!("{}?metadata={}", filer.join(&["buckets", bucket]), query_escape("true"));
        let entry: BucketEntry = get_usage_json(
            self.transport.as_ref(),
            ctx,
            &url,
            Self::headers(),
            "bucket entry",
            MAX_SEAWEEDFS_BUCKET_ENTRY_BYTES,
        )
        .await?;
        Ok(entry.quota.max(0))
    }

    /// The usage and the quota of the bucket.
    pub async fn usage(&self, ctx: &OpCtx, bucket: &str) -> std::result::Result<BucketUsage, AdminError> {
        let used = self.used_bytes(ctx, bucket).await?;
        let limit = self.quota(ctx, bucket).await?;
        Ok(BucketUsage {
            used_bytes: used,
            used_objects: -1,
            limit_bytes: limit,
            approximate: true,
            as_of: Some(Timestamp::now()),
            ..BucketUsage::default()
        })
    }
}

impl BucketUsageReader for SeaweedFsUsageReader {
    fn bucket_usage<'a>(&'a self, ctx: &'a OpCtx, bucket: &'a str) -> BoxFuture<'a, Result<BucketUsage>> {
        Box::pin(async move { self.usage(ctx, bucket).await.map_err(Error::from) })
    }

    fn storage_capacity<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<Option<StorageCapacity>>> {
        Box::pin(async move { self.capacity(ctx).await.map(Some).map_err(Error::from) })
    }

    fn source(&self) -> &'static str {
        USAGE_SOURCE_SEAWEEDFS
    }
}
