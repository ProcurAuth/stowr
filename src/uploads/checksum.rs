//! The SHA-256 checksums of the uploads: the header `X-Checksum-Sha256`, the composite checksum of an S3 multipart
//! object, and the helpers of the direct upload (`PUT /s3`).
//!
//! The browser computes the SHA-256 digest of each chunk. The server sends the digest to the provider, which
//! refuses a part with other bytes (docs/ARCHITECTURE.md, "Upload checksums").

use std::sync::Arc;

use aws_lc_rs::digest;
use base64::Engine as _;
use base64::alphabet;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use http::HeaderMap;

use super::session::{UploadPartState, UploadSession};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::lifecycle::Tag;
use crate::provider::ChecksumTransfer;

/// The value of the field `checksum` of an upload with the SHA-256 digest of each chunk.
pub const UPLOAD_CHECKSUM_SHA256: &str = "sha256";
/// The header of a request body with its digest.
pub const CHECKSUM_HEADER: &str = "X-Checksum-Sha256";

/// The standard base64 form, with the padding. A digest that has bits after its last character is valid.
pub(crate) fn standard_base64() -> GeneralPurpose {
    GeneralPurpose::new(
        &alphabet::STANDARD,
        GeneralPurposeConfig::new().with_decode_allow_trailing_bits(true),
    )
}

/// The base64 form of a SHA-256 digest of bytes.
pub fn sha256_base64(data: &[u8]) -> String {
    standard_base64().encode(digest::digest(&digest::SHA256, data).as_ref())
}

fn invalid_checksum() -> Error {
    Error::api(
        400,
        "invalid_checksum",
        format!("{CHECKSUM_HEADER} must be the base64 encoding of a 32-byte SHA-256 digest"),
    )
}

/// Read the header `X-Checksum-Sha256`: an empty text, or a base64 digest of 32 bytes (else `400 invalid_checksum`).
pub fn parse_checksum_header(headers: &HeaderMap) -> Result<String> {
    let value = headers
        .get(CHECKSUM_HEADER)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .trim();
    if value.is_empty() {
        return Ok(String::new());
    }
    match standard_base64().decode(value) {
        Ok(raw) if raw.len() == 32 => Ok(value.to_owned()),
        _ => Err(invalid_checksum()),
    }
}

/// The checksum that S3 reports for a multipart object: the SHA-256 of the part digests (base64), and the number of
/// parts. An error gives the number of the first part that has no valid digest.
pub fn composite_checksum(parts: &[UploadPartState]) -> std::result::Result<(String, usize), u32> {
    let mut context = digest::Context::new(&digest::SHA256);
    for part in parts {
        match standard_base64().decode(&part.checksum_sha256) {
            Ok(raw) if raw.len() == 32 => context.update(&raw),
            _ => return Err(part.part_number),
        }
    }
    Ok((standard_base64().encode(context.finish().as_ref()), parts.len()))
}

/// Compare the checksum that the provider reports with the one of the parts. S3 writes `<digest>-<number of parts>`.
/// Other providers write the digest only.
pub fn same_composite_checksum(reported: &str, digest: &str, count: usize) -> bool {
    let mut reported = reported.trim();
    if let Some(dash) = reported.rfind('-') {
        if reported[dash + 1..] != count.to_string() {
            return false;
        }
        reported = &reported[..dash];
    }
    reported == digest
}

/// Set `checksum_verified` when the provider keeps the digest of every part. When the provider also reports the
/// checksum of the whole object, it must be the one that the digests of the parts give.
pub fn verify_upload_checksum(headers: &HeaderMap, upload: &mut UploadSession) -> Result<()> {
    upload.checksum_verified = false;
    if upload.parts.is_empty() || upload.parts.iter().any(|part| !part.checksum_stored) {
        return Ok(());
    }
    let Ok((composite, count)) = composite_checksum(&upload.parts) else {
        return Ok(());
    };
    let reported = headers
        .get("x-amz-checksum-sha256")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .trim();
    if !reported.is_empty() && !same_composite_checksum(reported, &composite, count) {
        return Err(Error::internal(format!(
            "the upload completed but the SHA-256 checksum of the provider ({reported}) is not the one of the uploaded parts ({composite}-{count})"
        )));
    }
    upload.checksum_verified = true;
    Ok(())
}

/// The context of the write of one body that has a digest, and the transfer that gets the digest that the provider
/// sends back. An empty digest gives the context as it is and no transfer.
pub fn with_checksum_transfer(ctx: &OpCtx, digest: &str) -> (OpCtx, Option<Arc<ChecksumTransfer>>) {
    if digest.is_empty() {
        return (ctx.clone(), None);
    }
    let transfer = Arc::new(ChecksumTransfer {
        sha256: digest.to_owned(),
        ..ChecksumTransfer::default()
    });
    let mut next = ctx.clone();
    next.checksum = Some(transfer.clone());
    (next, Some(transfer))
}

/// True when the provider answers with the digest that the client sends: it checks the bytes of the object.
pub fn checksum_confirmed(transfer: &ChecksumTransfer) -> bool {
    transfer
        .echoed
        .lock()
        .map(|echoed| !transfer.sha256.is_empty() && *echoed == transfer.sha256)
        .unwrap_or(false)
}

/// The context of the write of an object that has tags.
pub fn with_upload_tags(ctx: &OpCtx, tags: &[Tag]) -> OpCtx {
    let mut next = ctx.clone();
    if !tags.is_empty() {
        next.upload_tags = Some(Arc::from(tags));
    }
    next
}
