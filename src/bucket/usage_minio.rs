// SPDX-License-Identifier: MIT OR Apache-2.0
//! The usage reader of MinIO: two requests to the admin API (`/minio/admin/v3`), signed with SigV4 (service `s3`) and
//! the S3 credentials of the `auth` block. The credentials need the admin actions `admin:GetBucketQuota`,
//! `admin:DataUsageInfo` and `admin:StorageInfo` (for the capacity of the storage), for example the policy
//! `consoleAdmin` or the root user.
//!
//! Measured on MinIO RELEASE.2025-10-15T17-29-55Z:
//!
//! - `GET /minio/admin/v3/get-bucket-quota?bucket=<bucket>` gives `{"quota": <bytes>, "size": <bytes>, "rate": 0,
//!   "requests": 0, "quotatype": "hard"}`. A bucket without a quota gives 200 with `"quota": 0`. Older releases answer
//!   404 `XMinioAdminBucketQuotaNotConfigured` without a quota, and newer clients write the limit in `size`: the
//!   reader takes `size`, else `quota`.
//! - `GET /minio/admin/v3/datausageinfo` gives `lastUpdate` and `bucketsUsageInfo: {<bucket>: {"size": <bytes>,
//!   "objectsCount": <count>, ...}}` for all the buckets. The scanner of MinIO makes these numbers, about one time
//!   each minute on a small server: they come with a delay. A zero `lastUpdate` is a server that has not counted yet.

use std::collections::BTreeMap;
use std::sync::Arc;

use http::HeaderMap;
use http::header::{AUTHORIZATION, HeaderName, HeaderValue};
use serde::Deserialize;
use serde::de::DeserializeOwned;

use super::sign::{SigningInput, amz_date, authorization, sha256_hex};
use super::usage::USAGE_SOURCE_MINIO;
use super::usage_admin::{AdminCredentials, AdminError, AdminTransport, AdminUrl, get_usage_json};
use super::{BucketUsage, BucketUsageReader, StorageCapacity};
use crate::common::BoxFuture;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::time::Timestamp;

/// The size limit of the answer of `get-bucket-quota`.
pub const MAX_MINIO_QUOTA_BYTES: usize = 64 << 10;
/// The size limit of the answer of `datausageinfo`. It gives about 1 KiB for each bucket of the server.
pub const MAX_MINIO_DATA_USAGE_BYTES: usize = 16 << 20;

/// The Unix time of 0001-01-01T00:00:00Z, the zero time of a count that has not run.
const ZERO_TIME_UNIX: i64 = -62_135_596_800;

/// The reader of MinIO.
pub struct MinioUsageReader {
    /// The admin endpoint.
    pub endpoint: AdminUrl,
    /// The HTTP client.
    pub transport: Arc<dyn AdminTransport>,
    /// The credentials of the signature.
    pub credentials: AdminCredentials,
    /// The region of the signature.
    pub region: String,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct Quota {
    quota: i64,
    size: i64,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct DataUsage {
    #[serde(rename = "lastUpdate")]
    last_update: Option<Timestamp>,
    #[serde(rename = "bucketsUsageInfo")]
    buckets: Option<BTreeMap<String, BucketUsageInfo>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct BucketUsageInfo {
    size: i64,
    #[serde(rename = "objectsCount")]
    objects_count: i64,
}

impl MinioUsageReader {
    /// Send one signed `GET` request to `/minio/admin/v3/<name>` and decode its JSON answer.
    pub(crate) async fn get<T: DeserializeOwned>(
        &self,
        ctx: &OpCtx,
        name: &str,
        query: &[(String, String)],
        limit: usize,
    ) -> std::result::Result<T, AdminError> {
        let segments = ["minio", "admin", "v3", name];
        let path = self.endpoint.join_path(&segments);
        let headers = self
            .signed_headers(&path, query)
            .map_err(|()| AdminError::message(format!("{name}: cannot sign the request")))?;
        let mut url = self.endpoint.join(&segments);
        if !query.is_empty() {
            url.push('?');
            url.push_str(&super::sign::canonical_query(query));
        }
        get_usage_json(self.transport.as_ref(), ctx, &url, headers, name, limit).await
    }

    fn signed_headers(&self, path: &str, query: &[(String, String)]) -> std::result::Result<HeaderMap, ()> {
        let credentials = &self.credentials;
        if credentials.access_key_id.is_empty() || credentials.secret_access_key.is_empty() || self.region.is_empty() {
            return Err(());
        }
        let time = Timestamp::now();
        let date = amz_date(time);
        let payload_hash = sha256_hex(b"");
        let mut signed: Vec<(String, String)> = vec![
            ("host".to_owned(), self.endpoint.authority.clone()),
            ("x-amz-content-sha256".to_owned(), payload_hash.clone()),
            ("x-amz-date".to_owned(), date.clone()),
        ];
        if !credentials.session_token.is_empty() {
            signed.push(("x-amz-security-token".to_owned(), credentials.session_token.clone()));
        }
        signed.sort();
        let value = authorization(&SigningInput {
            method: "GET",
            canonical_uri: path,
            query,
            headers: &signed,
            payload_hash: &payload_hash,
            access_key_id: &credentials.access_key_id,
            secret_access_key: &credentials.secret_access_key,
            region: &self.region,
            service: "s3",
            time,
        });
        let mut headers = HeaderMap::new();
        for (name, value) in signed {
            if name == "host" {
                continue;
            }
            let (Ok(name), Ok(value)) = (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(&value)) else {
                return Err(());
            };
            headers.insert(name, value);
        }
        headers.insert(AUTHORIZATION, HeaderValue::from_str(&value).map_err(|_| ())?);
        Ok(headers)
    }

    /// The usage and the quota of the bucket.
    pub async fn usage(&self, ctx: &OpCtx, bucket: &str) -> std::result::Result<BucketUsage, AdminError> {
        let query = vec![("bucket".to_owned(), bucket.to_owned())];
        let quota = match self
            .get::<Quota>(ctx, "get-bucket-quota", &query, MAX_MINIO_QUOTA_BYTES)
            .await
        {
            Ok(quota) => quota,
            Err(AdminError::Http { status: 404, code, .. }) if code == "XMinioAdminBucketQuotaNotConfigured" => {
                Quota::default()
            }
            Err(error) => return Err(error),
        };
        let data: DataUsage = self.get(ctx, "datausageinfo", &[], MAX_MINIO_DATA_USAGE_BYTES).await?;
        let Some(last_update) = data.last_update.filter(|time| time.secs != ZERO_TIME_UNIX) else {
            return Err(AdminError::message(
                "datausageinfo: MinIO has not counted the usage of its buckets yet",
            ));
        };
        // A bucket that the last count does not know is newer than the count: it is empty for MinIO.
        let used = data
            .buckets
            .and_then(|buckets| buckets.get(bucket).map(|info| (info.size, info.objects_count)))
            .unwrap_or((0, 0));
        let limit = if quota.size > 0 { quota.size } else { quota.quota };
        Ok(BucketUsage {
            used_bytes: used.0,
            used_objects: used.1,
            limit_bytes: limit.max(0),
            approximate: true,
            as_of: Some(last_update.utc()),
            ..BucketUsage::default()
        })
    }
}

impl BucketUsageReader for MinioUsageReader {
    fn bucket_usage<'a>(&'a self, ctx: &'a OpCtx, bucket: &'a str) -> BoxFuture<'a, Result<BucketUsage>> {
        Box::pin(async move { self.usage(ctx, bucket).await.map_err(Error::from) })
    }

    fn storage_capacity<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<Option<StorageCapacity>>> {
        Box::pin(async move { self.capacity(ctx).await.map(Some).map_err(Error::from) })
    }

    fn source(&self) -> &'static str {
        USAGE_SOURCE_MINIO
    }
}
