// SPDX-License-Identifier: MIT OR Apache-2.0
//! The per-object integrity (docs/PREVIEWS.md, "Per-object integrity"): a job reads the complete object in a stream,
//! computes SHA-256, MD5, CRC-32 and CRC-32C, and compares them with the checksums of the provider. It keeps no
//! byte of the object. A composite value of the provider is shown but not compared.

use std::collections::BTreeMap;
use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use http::header::{HeaderValue, IF_MATCH};
use http::{HeaderMap, Method};
use http_body_util::BodyExt;
use serde::{Deserialize, Serialize};

use super::digest::Crc32c;
use super::{JobRun, JobState, job_status, job_type};
use crate::common::BoxFuture;
use crate::common::app::App;
use crate::common::config::PERMISSION_READ;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Req, Response, api_error, decode_json, json, method_not_allowed};
use crate::common::md5::Md5;
use crate::common::misc::{clean_relative_key, hex};
use crate::instance::ceiling::ceilings_of;
use crate::instance::versions::provider_checksums;

/// How long a route waits for an analysis job before it answers 202.
pub const ANALYSIS_INLINE_WAIT: std::time::Duration = std::time::Duration::from_millis(100);

/// The request of an integrity job.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct IntegrityRequest {
    /// The relative key.
    pub key: String,
    /// The version.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version: String,
}

/// The digests of one object and their comparison with the provider.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct IntegrityEntry {
    /// The relative key.
    pub key: String,
    /// The version.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version: String,
    /// The bytes that the job read.
    pub size: i64,
    /// The media type of the provider.
    #[serde(rename = "contentType", skip_serializing_if = "String::is_empty")]
    pub content_type: String,
    /// The ETag without quotes.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub etag: String,
    /// The `Last-Modified` header of the provider.
    #[serde(rename = "lastModified", skip_serializing_if = "String::is_empty")]
    pub last_modified: String,
    /// SHA-256 in hexadecimal.
    pub sha256: String,
    /// SHA-256 in base64.
    #[serde(rename = "sha256Base64")]
    pub sha256_base64: String,
    /// MD5 in hexadecimal.
    pub md5: String,
    /// MD5 in base64.
    #[serde(rename = "md5Base64")]
    pub md5_base64: String,
    /// CRC-32 (IEEE) in hexadecimal.
    pub crc32: String,
    /// CRC-32C in hexadecimal.
    pub crc32c: String,
    /// The checksums of the provider, by algorithm.
    #[serde(rename = "providerChecksums", skip_serializing_if = "BTreeMap::is_empty")]
    pub provider_checksums: BTreeMap<String, String>,
    /// The result of each comparison that the values allow.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub matches: BTreeMap<String, bool>,
}

/// The result of an integrity job.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct IntegrityResult {
    /// The entries: one for the object of the job.
    pub entries: Vec<IntegrityEntry>,
}

/// The base64 rules of the provider values: the standard alphabet with its padding. The bits after the last
/// character can be any value.
const LENIENT_STANDARD: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_allow_trailing_bits(true)
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
);

/// Compare a value of the provider with a digest. The first flag is the result. The second flag is false when the
/// value cannot be compared: an empty value, or a composite value that is not a digest of the whole object.
pub fn checksum_matches(value: &str, sum: &[u8]) -> (bool, bool) {
    let value = value.trim_matches('"').trim();
    if value.is_empty() {
        return (false, false);
    }
    if value.eq_ignore_ascii_case(&hex(sum)) || value == STANDARD.encode(sum) {
        return (true, true);
    }
    let compact: String = value.chars().filter(|c| *c != '\r' && *c != '\n').collect();
    match LENIENT_STANDARD.decode(compact.as_bytes()) {
        Ok(decoded) if decoded.len() == sum.len() => (decoded == sum, true),
        _ => (false, false),
    }
}

fn checksum_matches_u32(value: &str, sum: u32) -> (bool, bool) {
    checksum_matches(value, &sum.to_be_bytes())
}

/// True for an ETag that is the MD5 of the object: 32 hexadecimal digits, not an ETag of a multipart upload.
fn is_simple_md5_etag(value: &str) -> bool {
    value.len() == 32 && !value.contains('-') && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers.get(name).and_then(|value| value.to_str().ok()).unwrap_or("")
}

/// Read one object (or one version) to its end and give its digests and their comparison with the provider.
pub async fn compute_object_integrity(
    ctx: &OpCtx,
    app: &App,
    instance_id: &str,
    key: &str,
    version: &str,
) -> Result<IntegrityEntry> {
    let Some(instance) = app.instances.iter().find(|instance| instance.cfg.id == instance_id) else {
        return Err(Error::api(404, "unknown_instance", "storage instance was not found"));
    };
    let key = clean_relative_key(key);
    if key.is_empty() {
        return Err(Error::api(400, "invalid_key", "object key is required"));
    }
    let full_key = instance.full_key(&key);
    let head = instance.head_version(ctx, &full_key, version).await?;
    let raw_size = header(&head.headers, "content-length").trim();
    let mut expected_size = -1i64;
    if !raw_size.is_empty() {
        match raw_size.parse::<i64>() {
            Ok(size) if size >= 0 => expected_size = size,
            _ => {
                return Err(Error::internal(
                    "provider returned an invalid Content-Length for integrity verification",
                ));
            }
        }
    }
    let etag_header = header(&head.headers, "etag").trim().to_owned();
    let mut request_headers = HeaderMap::new();
    if !etag_header.is_empty()
        && let Ok(value) = HeaderValue::from_str(&etag_header)
    {
        request_headers.insert(IF_MATCH, value);
    }
    let response = instance.get_version(ctx, &full_key, version, &request_headers).await?;
    if response.status != 200 {
        return Err(Error::internal(format!(
            "provider returned HTTP {} instead of a complete object for integrity verification",
            response.status
        )));
    }
    let mut body = response.body;
    let mut sha = aws_lc_rs::digest::Context::new(&aws_lc_rs::digest::SHA256);
    let mut md5 = Md5::new();
    let mut crc_ieee = flate2::Crc::new();
    let mut crc_castagnoli = Crc32c::new();
    let mut written = 0i64;
    ctx.run(async {
        while let Some(frame) = body.frame().await {
            if let Ok(data) = frame?.into_data() {
                sha.update(&data);
                md5.update(&data);
                crc_ieee.update(&data);
                crc_castagnoli.update(&data);
                written += i64::try_from(data.len()).unwrap_or(i64::MAX);
            }
        }
        Ok(())
    })
    .await?;
    if expected_size >= 0 && written != expected_size {
        return Err(Error::internal(
            "object size changed while integrity was being verified",
        ));
    }
    let sha_sum = sha.finish();
    let sha_sum = sha_sum.as_ref();
    let md5_sum = md5.finish();
    let crc32 = crc_ieee.sum();
    let crc32c = crc_castagnoli.sum();

    let provider = provider_checksums(&head.headers);
    let mut matches = BTreeMap::new();
    let comparisons: [(&str, (bool, bool)); 4] = [
        (
            "sha256",
            compare(&provider, "sha256", |value| checksum_matches(value, sha_sum)),
        ),
        (
            "md5",
            compare(&provider, "md5", |value| checksum_matches(value, &md5_sum)),
        ),
        (
            "crc32",
            compare(&provider, "crc32", |value| checksum_matches_u32(value, crc32)),
        ),
        (
            "crc32c",
            compare(&provider, "crc32c", |value| checksum_matches_u32(value, crc32c)),
        ),
    ];
    for (name, (matched, comparable)) in comparisons {
        if comparable {
            matches.insert(name.to_owned(), matched);
        }
    }
    let etag = etag_header.trim_matches('"').to_owned();
    if is_simple_md5_etag(&etag) {
        matches.insert("etagMd5".to_owned(), etag.eq_ignore_ascii_case(&hex(&md5_sum)));
    }
    Ok(IntegrityEntry {
        key,
        version: version.to_owned(),
        size: written,
        content_type: header(&head.headers, "content-type").to_owned(),
        etag,
        last_modified: header(&head.headers, "last-modified").to_owned(),
        sha256: hex(sha_sum),
        sha256_base64: STANDARD.encode(sha_sum),
        md5: hex(&md5_sum),
        md5_base64: STANDARD.encode(md5_sum),
        crc32: format!("{crc32:08x}"),
        crc32c: format!("{crc32c:08x}"),
        provider_checksums: provider,
        matches,
    })
}

/// The comparison of one checksum of the provider, or "not comparable" when the provider gives no value.
fn compare(provider: &BTreeMap<String, String>, name: &str, check: impl Fn(&str) -> (bool, bool)) -> (bool, bool) {
    match provider.get(name) {
        Some(value) if !value.is_empty() => check(value),
        _ => (false, false),
    }
}

/// Run the job `integrity`.
pub(super) async fn run_integrity(run: &JobRun, job: &mut JobState) -> Result<()> {
    let Some(request) = job.integrity_request.clone() else {
        return Err(Error::internal("integrity request is missing"));
    };
    run.check_control()?;
    let entry = compute_object_integrity(&run.ctx, &run.app, &job.instance, &request.key, &request.version).await?;
    job.processed = 1;
    job.integrity = Some(IntegrityResult { entries: vec![entry] });
    run.save(job)
}

/// The body of `POST /api/integrity`.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
struct IntegrityBody {
    #[serde(deserialize_with = "nullable")]
    instance: String,
    #[serde(deserialize_with = "nullable")]
    key: String,
    #[serde(deserialize_with = "nullable")]
    version: String,
}

/// A member of a JSON request: `null` gives the default value, as an absent member does.
pub(super) fn nullable<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// The handler of `POST /api/integrity`: start the integrity job of one object (or one version). The answer is the
/// completed job when it ends within 100 ms, else `202` with the queued job.
pub fn handle_integrity(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        if req.method != Method::POST {
            return method_not_allowed(&["POST"]);
        }
        integrity_route(app, req)
            .await
            .unwrap_or_else(|error| api_error(&error))
    })
}

async fn integrity_route(app: Arc<App>, req: Req) -> Result<Response> {
    let Req { body, ctx, query, .. } = req;
    let request: IntegrityBody = decode_json(body).await?;
    let instance = app.instance_of(&request.instance, query.get("instance"))?.clone();
    let key = clean_relative_key(&request.key);
    instance.require_permission(PERMISSION_READ)?;
    if key.is_empty() {
        return Err(Error::api(
            400,
            "invalid_integrity_request",
            "an object key is required",
        ));
    }
    crate::access::authorize_read(&app, &ctx, &instance, &key).await?;
    let ceilings = ceilings_of(&ctx);
    let job = app.jobs.create(JobState {
        job_type: job_type::INTEGRITY.to_owned(),
        instance: instance.cfg.id.clone(),
        integrity_request: Some(IntegrityRequest {
            key,
            version: request.version,
        }),
        ceilings: (!ceilings.is_empty()).then(|| Arc::new(crate::instance::ceiling::Ceilings::from_map(&ceilings))),
        ..JobState::default()
    })?;
    Ok(analysis_job_answer(&app, &job).await)
}

/// The answer of a route that starts an analysis job (the integrity of an object or of an archive entry): the job
/// when it ends or pauses within 100 ms, a failure as an error (the refusal of a ceiling, else `422
/// analysis_failed`), else `202` with the job.
pub async fn analysis_job_answer(app: &App, job: &JobState) -> Response {
    if let Some(done) = app.jobs.wait_for_terminal(&job.id, ANALYSIS_INLINE_WAIT).await {
        if done.status == job_status::FAILED {
            if let Some(refusal) = &done.refusal {
                return api_error(refusal);
            }
            return api_error(&Error::api(422, "analysis_failed", done.error.clone()));
        }
        return json(200, &done.public());
    }
    json(202, &job.public())
}
