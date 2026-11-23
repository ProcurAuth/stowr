//! Server-side encryption (SSE) of the objects.
//!
//! The display: a HEAD answer gives the encryption of an object. `x-amz-server-side-encryption` is `AES256` for
//! SSE-S3 or `aws:kms` for SSE-KMS, with the KMS key id. The details get these headers through `GET
//! /api/media-info`, as the other headers of the object. A provider does not let a client read an object with a key
//! of the client (SSE-C) without that key: it refuses the HEAD and the GET with 400. The server does not ask for such
//! a key. The details then say that the object has a key of the client. `GET /api/encryption` gives the default
//! encryption of the bucket (`GetBucketEncryption`). The start probe reads it one time. A provider without the
//! request (Garage answers 501) hides it.
//!
//! The writes: the key `bucket.encryption = "sse-s3"` adds `x-amz-server-side-encryption: AES256` to each request
//! that writes an object: `PutObject`, `CreateMultipartUpload` (uploads and copies in parts) and `CopyObject` (copy,
//! move, rename, edit of the metadata, restore of a version). A copy without this header gets the default
//! encryption of the destination bucket, so an object can lose its encryption in a copy. An edit of the metadata
//! and a restore keep the SSE-S3 or SSE-KMS headers of their source. The key does not apply to `UploadPart` and
//! `UploadPartCopy`: S3 takes the encryption of a multipart upload from its creation.
//!
//! Measured: SeaweedFS 4.41 encrypts with a key encryption key and answers 500 without it. MinIO encrypts with a KMS
//! and answers 501 without it. Garage v2.4.1 accepts the header and does not encrypt: the server writes a warning
//! at start for such an instance.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, Method};
use serde::Serialize;

use super::support::{
    MAX_ANSWER_BYTES, S3Call, begin_request, decode_document, is_success, observe_permission, quote,
};
use super::{BucketEncryption, EncryptionReader};
use crate::access;
use crate::common::BoxFuture;
use crate::common::app::App;
use crate::common::config::{BucketConfig, Encryption, PERMISSION_READ};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Req, Response, api_error, json, method_not_allowed};
use crate::common::storage::ListOptions;
use crate::instance::Instance;
use crate::provider::S3Backend;
use crate::provider::s3::S3Request;

/// The value of `x-amz-server-side-encryption` for SSE-S3.
pub const SSE_S3_ALGORITHM: &str = "AES256";
/// The header `x-amz-server-side-encryption`.
pub const SSE_HEADER: &str = "x-amz-server-side-encryption";
/// The header that names the KMS key.
pub const SSE_KMS_KEY_HEADER: &str = "x-amz-server-side-encryption-aws-kms-key-id";
/// The header of the S3 Bucket Key.
pub const SSE_BUCKET_KEY_HEADER: &str = "x-amz-server-side-encryption-bucket-key-enabled";
/// The header that tells an object with a key of the client.
pub const SSE_CUSTOMER_ALGORITHM_HEADER: &str = "x-amz-server-side-encryption-customer-algorithm";

/// The headers of a HEAD answer that tell the encryption of the object. The details show them. None of them is a
/// secret: the MD5 of a key of the client (`x-amz-server-side-encryption-customer-key-md5`) does not go to the page.
pub const ENCRYPTION_RESPONSE_HEADERS: [&str; 4] = [
    SSE_HEADER,
    SSE_KMS_KEY_HEADER,
    SSE_BUCKET_KEY_HEADER,
    SSE_CUSTOMER_ALGORITHM_HEADER,
];

/// The provider applies the encryption of the writes.
pub const ENCRYPTION_APPLIED_YES: &str = "yes";
/// The provider does not apply the encryption of the writes.
pub const ENCRYPTION_APPLIED_NO: &str = "no";
/// The server does not know what the provider does.
pub const ENCRYPTION_APPLIED_UNKNOWN: &str = "unknown";

/// The provider flavour `aws`.
pub const FLAVOUR_AWS: &str = "aws";
/// The provider flavour `minio`.
pub const FLAVOUR_MINIO: &str = "minio";
/// The provider flavour `seaweedfs`.
pub const FLAVOUR_SEAWEEDFS: &str = "seaweedfs";
/// The provider flavour `garage`.
pub const FLAVOUR_GARAGE: &str = "garage";

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// What each known provider does with `x-amz-server-side-encryption: AES256`. AWS S3, MinIO and SeaweedFS encrypt
/// the object, or refuse the write when they have no key. Garage accepts the header and does not encrypt.
fn sse_s3_provider_applied(flavour: &str) -> &'static str {
    match flavour {
        FLAVOUR_AWS | FLAVOUR_MINIO | FLAVOUR_SEAWEEDFS => ENCRYPTION_APPLIED_YES,
        FLAVOUR_GARAGE => ENCRYPTION_APPLIED_NO,
        _ => "",
    }
}

/// The display name of a provider flavour.
pub fn flavour_name(flavour: &str) -> &str {
    match flavour {
        FLAVOUR_AWS => "AWS S3",
        FLAVOUR_MINIO => "MinIO",
        FLAVOUR_SEAWEEDFS => "SeaweedFS",
        FLAVOUR_GARAGE => "Garage",
        other => other,
    }
}

/// Add `x-amz-server-side-encryption: AES256` to the headers of a write when the bucket has `encryption =
/// "sse-s3"`. Headers that already name an encryption (the SSE-KMS of the source of an edit of the metadata) stay.
pub fn write_encryption_headers(cfg: &BucketConfig, headers: &mut HeaderMap) {
    if cfg.encryption != Encryption::SseS3
        || header_text(headers, SSE_HEADER).is_some_and(|value| !value.is_empty())
        || header_text(headers, SSE_CUSTOMER_ALGORITHM_HEADER).is_some_and(|value| !value.is_empty())
    {
        return;
    }
    headers.insert(
        HeaderName::from_static(SSE_HEADER),
        HeaderValue::from_static(SSE_S3_ALGORITHM),
    );
}

fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

/// The SSE-S3 and SSE-KMS headers of an answer, without a space at the ends. A copy that sends them keeps the
/// encryption of its source.
pub fn kept_encryption_headers(headers: &HeaderMap) -> HeaderMap {
    let mut kept = HeaderMap::new();
    for name in [SSE_HEADER, SSE_KMS_KEY_HEADER, SSE_BUCKET_KEY_HEADER] {
        let Some(value) = header_text(headers, name).map(str::trim).filter(|value| !value.is_empty()) else {
            continue;
        };
        if let Ok(value) = HeaderValue::from_str(value) {
            kept.insert(HeaderName::from_static(name), value);
        }
    }
    kept
}

fn no_bucket_encryption(error: &Error) -> bool {
    error
        .as_upstream()
        .is_some_and(|upstream| upstream.code == "ServerSideEncryptionConfigurationNotFoundError")
}

/// Read `GetBucketEncryption`. A bucket without a default encryption gives `None`.
pub async fn read_bucket_encryption(s3: &dyn S3Call, ctx: &OpCtx) -> Result<Option<BucketEncryption>> {
    let request = S3Request {
        method: Method::GET,
        key: "",
        query: vec![("encryption".to_owned(), String::new())],
        headers: HeaderMap::new(),
        body: None,
    };
    let answer = s3.call(ctx, request, MAX_ANSWER_BYTES).await?;
    if !is_success(answer.status) {
        let error = s3.provider_error(&answer);
        if no_bucket_encryption(&error) {
            return Ok(None);
        }
        return Err(error);
    }
    let Some(root) = decode_document(&answer.body, "bucket encryption")? else {
        return Ok(None);
    };
    for rule in root.children_named("Rule") {
        let algorithm = rule
            .text_at(&["ApplyServerSideEncryptionByDefault", "SSEAlgorithm"])
            .trim()
            .to_owned();
        if !algorithm.is_empty() {
            return Ok(Some(BucketEncryption {
                algorithm,
                kms_key_id: rule
                    .text_at(&["ApplyServerSideEncryptionByDefault", "KMSMasterKeyID"])
                    .trim()
                    .to_owned(),
                bucket_key_enabled: rule.text_at(&["BucketKeyEnabled"]).trim().eq_ignore_ascii_case("true"),
            }));
        }
    }
    Ok(None)
}

impl EncryptionReader for S3Backend {
    fn bucket_encryption<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<Option<BucketEncryption>>> {
        Box::pin(async move { read_bucket_encryption(self, ctx).await })
    }
}

// --- The instance -------------------------------------------------------------------------------------------------

impl Instance {
    /// The default encryption of the bucket at start (`AES256`, `aws:kms` or `aws:kms:dsse`; empty when the bucket
    /// has none), and what the provider does with the encryption of the writes (`yes`, `no`, `unknown`; empty for an
    /// instance without the key). The page shows a lock next to the name of the bucket from these two facts.
    pub fn encryption_state(&self) -> (String, String) {
        self.encryption
            .state
            .lock()
            .map(|state| state.clone())
            .unwrap_or_default()
    }

    /// True when the page can read the default encryption of the bucket. Until the probe has run, the answer is no.
    pub fn bucket_encryption_available(&self) -> bool {
        self.backend.encryption_reader().is_some() && self.encryption.on.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// The provider of the instance. The lifecycle probe keeps it; without it, the back end tells it.
    pub(crate) async fn provider_flavour(&self, ctx: &OpCtx) -> String {
        if let Ok(inner) = self.rules.inner.lock()
            && !inner.flavour.is_empty()
        {
            return inner.flavour.clone();
        }
        let Some(rules) = self.backend.bucket_rules() else {
            return String::new();
        };
        let probe = ctx.with_timeout(PROBE_TIMEOUT);
        probe
            .run(rules.provider_flavour(&probe))
            .await
            .unwrap_or_default()
    }

    /// Read the default encryption of the bucket. An answer (a configuration, or "no configuration") shows it. A
    /// provider without the request (501, 405) and any other failure hide it. The request is a read. An instance
    /// without the read permission is not probed. For an instance with `encryption = "sse-s3"`, the probe finds the
    /// provider and keeps what it does with the header. On Garage, the probe writes a warning.
    pub async fn probe_bucket_encryption(&self, ctx: &OpCtx) {
        let Some(reader) = self.backend.encryption_reader() else {
            return;
        };
        if !self.permitted(PERMISSION_READ) {
            return;
        }
        let probe = ctx.with_timeout(PROBE_TIMEOUT);
        let result = probe.run(reader.bucket_encryption(&probe)).await;
        self.encryption
            .on
            .store(result.is_ok(), std::sync::atomic::Ordering::SeqCst);
        let algorithm = match &result {
            Ok(Some(configuration)) => configuration.algorithm.clone(),
            _ => String::new(),
        };
        let mut applied = String::new();
        if self.cfg.encryption == Encryption::SseS3 {
            let flavour = self.provider_flavour(&probe).await;
            applied = sse_s3_provider_applied(&flavour).to_owned();
            if applied.is_empty() {
                applied = ENCRYPTION_APPLIED_UNKNOWN.to_owned();
            }
            if flavour == FLAVOUR_GARAGE {
                crate::log!(
                    "config.warning bucket {} encryption = {}: the provider is Garage, which accepts x-amz-server-side-encryption and does not encrypt the objects",
                    quote(&self.cfg.id),
                    quote(self.cfg.encryption.as_str())
                );
            }
        }
        if let Ok(mut state) = self.encryption.state.lock() {
            *state = (algorithm, applied);
        }
    }

    /// Read the default encryption of the bucket in a slot of the gates of the instance.
    pub async fn read_bucket_encryption(&self, ctx: &OpCtx) -> Result<Option<BucketEncryption>> {
        let Some(reader) = self.backend.encryption_reader() else {
            return Err(bucket_encryption_unsupported());
        };
        if !self.encryption.on.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(bucket_encryption_unsupported());
        }
        let _slot = begin_request(self, ctx).await?;
        let result = reader.bucket_encryption(ctx).await;
        observe_permission(self, PERMISSION_READ, result.as_ref().err());
        result
    }
}

fn bucket_encryption_unsupported() -> Error {
    Error::api(
        501,
        "bucket_encryption_unsupported",
        "this storage provider does not give the default encryption of the bucket",
    )
}

// --- Objects with a key of the client (SSE-C) ---------------------------------------------------------------------

/// True for the refusal of a read of an object with a key of the client. The providers answer 400 with different
/// texts: SeaweedFS "Customer provided keys must provide the customer key", Garage "Object is encrypted", AWS and
/// MinIO "The object was stored using a form of Server Side Encryption". The answer to a HEAD has no text.
pub fn customer_key_refusal(error: &Error) -> bool {
    let Some(upstream) = error.as_upstream() else {
        return false;
    };
    if upstream.status != 400 {
        return false;
    }
    let text = format!("{} {}", upstream.code, upstream.message).to_lowercase();
    text.contains("encrypt") || text.contains("customer")
}

/// The details of an object that the provider refused to read because it has a key of the client.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CustomerKeyInfo {
    /// The size from the listing, or 0 when the listing does not give it.
    pub size: i64,
    /// The headers that the listing or the list of the versions gives: `etag`, `last-modified`, `x-amz-version-id`.
    pub headers: BTreeMap<String, String>,
}

/// The details of an object that the provider refused to read with `error`, when the refusal is for a key of the
/// client. A refused HEAD has no text: a GET of one byte gives the text of the refusal. The size, the ETag and the
/// date come from the listing (or from the list of the versions). The result is `None` for any other error.
pub async fn customer_key_media_info(
    ctx: &OpCtx,
    instance: &Instance,
    key: &str,
    error: &Error,
) -> Option<CustomerKeyInfo> {
    let upstream = error.as_upstream()?;
    if upstream.status != 400 {
        return None;
    }
    let full = instance.full_key(key);
    if !customer_key_refusal(error) {
        let mut range = HeaderMap::new();
        range.insert(http::header::RANGE, HeaderValue::from_static("bytes=0-0"));
        match instance.get(ctx, &full, &range).await {
            Ok(response) => {
                drop(response);
                return None;
            }
            Err(get_error) if customer_key_refusal(&get_error) => {}
            Err(_) => return None,
        }
    }
    let mut info = CustomerKeyInfo::default();
    let version = ctx.version();
    if !version.is_empty() {
        info.headers.insert("x-amz-version-id".to_owned(), version.to_owned());
        if let Ok(page) = instance.list_versions(ctx, &full, "", 1000).await {
            for item in &page.versions {
                if item.version == version && !item.delete_marker {
                    info.size = item.size;
                    info.headers.insert("etag".to_owned(), format!("\"{}\"", item.etag));
                    info.headers.insert(
                        "last-modified".to_owned(),
                        item.last_modified.map(|value| value.http_date()).unwrap_or_default(),
                    );
                }
            }
        }
    } else {
        let options = ListOptions {
            prefix: full.clone(),
            max_results: 1,
            ..ListOptions::default()
        };
        if let Ok(page) = instance.list(ctx, &options).await {
            for item in &page.objects {
                if item.key == full {
                    info.size = item.size;
                    info.headers.insert("etag".to_owned(), format!("\"{}\"", item.etag));
                    info.headers.insert(
                        "last-modified".to_owned(),
                        item.last_modified.map(|value| value.http_date()).unwrap_or_default(),
                    );
                }
            }
        }
    }
    Some(info)
}

// --- HTTP ---------------------------------------------------------------------------------------------------------

/// The answer of `/api/encryption`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptionResponse {
    /// The instance.
    pub instance: String,
    /// The encryption that the server asks for each object that it writes: empty or `sse-s3`.
    pub uploads: String,
    /// The default encryption of the bucket. Null means that the bucket has none.
    pub bucket_default: Option<BucketEncryption>,
}

/// `GET` gives the default encryption of the bucket and the encryption of the writes of the instance (permission
/// read).
pub fn handle_encryption(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        if req.method != Method::GET {
            return method_not_allowed(&["GET"]);
        }
        match serve(&app, req).await {
            Ok(response) => response,
            Err(error) => api_error(&error),
        }
    })
}

async fn serve(app: &App, req: Req) -> Result<Response> {
    let Req { query, ctx, .. } = req;
    let instance = app.instance_of("", query.get("instance"))?.clone();
    instance.require_permission(PERMISSION_READ)?;
    access::authorize_read(app, &ctx, &instance, "").await?;
    let config = instance.read_bucket_encryption(&ctx).await?;
    Ok(json(
        200,
        &EncryptionResponse {
            instance: instance.cfg.id.clone(),
            uploads: instance.cfg.encryption.as_str().to_owned(),
            bucket_default: config,
        },
    ))
}
