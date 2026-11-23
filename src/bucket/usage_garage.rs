// SPDX-License-Identifier: MIT OR Apache-2.0
//! The usage reader of Garage: one request to the admin API (v2), with the admin token as a bearer token.
//!
//! Measured on Garage v2.4.1: `GET /v2/GetBucketInfo?globalAlias=<bucket>` gives `objects`, `bytes`,
//! `unfinishedMultipartUploadBytes` and `quotas: {maxSize, maxObjects}`. `null` is no quota. A wrong token gives 403,
//! an unknown bucket 404. The counters follow a write at once on one node. In a cluster they follow it after a short
//! delay: the reader does not mark them approximate.
//!
//! The capacity of the cluster comes from `GET /v2/GetClusterStatus`: the data partitions of the nodes that store
//! data. A gateway node has no capacity and stores no data. The admin API does not give the replication factor.

use std::sync::Arc;

use http::HeaderMap;
use http::header::{ACCEPT, AUTHORIZATION, HeaderValue};
use serde::Deserialize;

use super::usage::{STORAGE_SCOPE_CLUSTER, USAGE_SOURCE_GARAGE};
use super::usage_admin::{AdminError, AdminTransport, AdminUrl, get_usage_json};
use super::usage_capacity::{plural, pronoun};
use super::{BucketUsage, BucketUsageReader, StorageCapacity};
use crate::common::BoxFuture;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::query::query_escape;
use crate::common::time::Timestamp;

/// The size limit of the answer of `GetBucketInfo`. The answer lists the keys of the bucket.
pub const MAX_GARAGE_USAGE_BYTES: usize = 1 << 20;
/// The size limit of the answer of `GetClusterStatus`.
const MAX_CAPACITY_ANSWER_BYTES: usize = 1 << 20;

/// The reader of Garage.
pub struct GarageUsageReader {
    /// The admin endpoint.
    pub endpoint: AdminUrl,
    /// The HTTP client.
    pub transport: Arc<dyn AdminTransport>,
    /// The admin token.
    pub token: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct BucketInfo {
    objects: Option<i64>,
    bytes: Option<i64>,
    quotas: Option<Quotas>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Quotas {
    #[serde(rename = "maxSize")]
    max_size: Option<i64>,
    #[serde(rename = "maxObjects")]
    max_objects: Option<i64>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct ClusterStatus {
    nodes: Option<Vec<Node>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Node {
    #[serde(rename = "isUp")]
    is_up: bool,
    role: Option<Role>,
    #[serde(rename = "dataPartition")]
    data_partition: Option<Partition>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Role {
    capacity: Option<i64>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Partition {
    available: i64,
    total: i64,
}

impl GarageUsageReader {
    fn headers(&self, step: &str) -> std::result::Result<HeaderMap, AdminError> {
        let mut headers = HeaderMap::new();
        let value = HeaderValue::from_str(&format!("Bearer {}", self.token))
            .map_err(|_| AdminError::message(format!("{step}: cannot connect to the admin API")))?;
        headers.insert(AUTHORIZATION, value);
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        Ok(headers)
    }

    /// The usage and the quota of the bucket.
    pub async fn usage(&self, ctx: &OpCtx, bucket: &str) -> std::result::Result<BucketUsage, AdminError> {
        let url = format!(
            "{}?globalAlias={}",
            self.endpoint.join(&["v2", "GetBucketInfo"]),
            query_escape(bucket)
        );
        let answer: BucketInfo = get_usage_json(
            self.transport.as_ref(),
            ctx,
            &url,
            self.headers("GetBucketInfo")?,
            "GetBucketInfo",
            MAX_GARAGE_USAGE_BYTES,
        )
        .await?;
        let mut usage = BucketUsage {
            used_bytes: answer.bytes.unwrap_or(-1),
            used_objects: answer.objects.unwrap_or(-1),
            as_of: Some(Timestamp::now()),
            ..BucketUsage::default()
        };
        if let Some(quotas) = answer.quotas {
            usage.limit_bytes = quotas.max_size.filter(|value| *value > 0).unwrap_or(0);
            usage.limit_objects = quotas.max_objects.filter(|value| *value > 0).unwrap_or(0);
        }
        Ok(usage)
    }

    /// The capacity of the cluster: the data partitions of the nodes that store data.
    pub async fn capacity(&self, ctx: &OpCtx) -> std::result::Result<StorageCapacity, AdminError> {
        let url = self.endpoint.join(&["v2", "GetClusterStatus"]);
        let answer: ClusterStatus = get_usage_json(
            self.transport.as_ref(),
            ctx,
            &url,
            self.headers("GetClusterStatus")?,
            "GetClusterStatus",
            MAX_CAPACITY_ANSWER_BYTES,
        )
        .await?;
        let mut capacity = StorageCapacity {
            scope: STORAGE_SCOPE_CLUSTER.to_owned(),
            as_of: Some(Timestamp::now()),
            ..StorageCapacity::default()
        };
        let (mut counted, mut missing) = (0usize, 0usize);
        for node in answer.nodes.unwrap_or_default() {
            // A node without a role, or a gateway node (no capacity), stores no data.
            if node.role.is_none_or(|role| role.capacity.is_none()) {
                continue;
            }
            match node.data_partition {
                Some(partition) if node.is_up && partition.total > 0 => {
                    counted += 1;
                    capacity.total_bytes += partition.total;
                    capacity.free_bytes += partition.available.max(0);
                }
                _ => missing += 1,
            }
        }
        if counted == 0 {
            return Err(AdminError::message(
                "GetClusterStatus: no storage node gives its data partition",
            ));
        }
        capacity.used_bytes = (capacity.total_bytes - capacity.free_bytes).max(0);
        capacity.note = format!(
            "raw capacity of the data partitions of {}, before the replication (the admin API does not give the replication factor)",
            plural(counted, "storage node")
        );
        if missing > 0 {
            capacity.approximate = true;
            capacity.approximate_reason = format!(
                "{} did not give a data partition: {} not counted.",
                plural(missing, "storage node"),
                pronoun(missing)
            );
        }
        Ok(capacity)
    }
}

impl BucketUsageReader for GarageUsageReader {
    fn bucket_usage<'a>(&'a self, ctx: &'a OpCtx, bucket: &'a str) -> BoxFuture<'a, Result<BucketUsage>> {
        Box::pin(async move { self.usage(ctx, bucket).await.map_err(Error::from) })
    }

    fn storage_capacity<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<Option<StorageCapacity>>> {
        Box::pin(async move { self.capacity(ctx).await.map(Some).map_err(Error::from) })
    }

    fn source(&self) -> &'static str {
        USAGE_SOURCE_GARAGE
    }
}
