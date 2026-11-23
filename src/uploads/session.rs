// SPDX-License-Identifier: MIT OR Apache-2.0
//! The upload session: its state in memory, the form that the client sees, the size of a chunk and the
//! `Content-Range` of a chunk.

use serde::Serialize;

use crate::common::time::Timestamp;

/// The session sends chunks.
pub const STATUS_UPLOADING: &str = "uploading";
/// The object is complete.
pub const STATUS_COMPLETED: &str = "completed";
/// A person canceled the upload.
pub const STATUS_CANCELED: &str = "canceled";

/// The smallest part of an S3 multipart upload, except the last part.
pub const MINIMUM_S3_PART_SIZE: i64 = 5 << 20;
/// The largest part of an S3 multipart upload.
pub const MAXIMUM_S3_PART_SIZE: i64 = 5 << 30;
/// The most parts of an S3 multipart upload.
pub const MAXIMUM_S3_PARTS: i64 = 10_000;
/// The largest object that an upload writes: 5 TiB.
pub const MAXIMUM_OBJECT_SIZE: i64 = 5 << 40;
/// The size unit of a chunk of a GCS resumable upload.
pub const GCS_CHUNK_ALIGNMENT: i64 = 256 << 10;
/// The most upload sessions in the memory of the process. This bound keeps the memory small when a person leaves
/// a browser tab. A resume token that the client keeps can make a session again.
pub const MAX_IN_MEMORY_UPLOAD_SESSIONS: usize = 4;

/// One part that the provider holds.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UploadPartState {
    /// The part number, from 1.
    pub part_number: u32,
    /// The ETag of the part.
    pub etag: String,
    /// The size of the part.
    pub size: i64,
    /// The base64 digest of the part, when the upload has the SHA-256 checksum.
    pub checksum_sha256: String,
    /// True when the provider answered with the same digest: it checked the bytes of the part.
    pub checksum_stored: bool,
}

/// One upload session. The process keeps it in memory only.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UploadSession {
    /// The id: `upl_` and the first 16 bytes of the SHA-256 of the resume token, in hexadecimal.
    pub id: String,
    /// The id of the instance.
    pub instance: String,
    /// The relative key.
    pub key: String,
    /// `s3`, `gcs` or `fs`.
    pub provider: String,
    /// `uploading`, `completed` or `canceled`.
    pub status: String,
    /// The media type.
    pub content_type: String,
    /// The size of the object.
    pub total_size: i64,
    /// The bytes that the provider holds.
    pub uploaded_bytes: i64,
    /// The size of a chunk.
    pub chunk_size: i64,
    /// The upload id of the S3 multipart upload.
    pub provider_upload_id: String,
    /// The session of a GCS or volume resumable upload.
    pub session_url: String,
    /// The parts of an S3 upload.
    pub parts: Vec<UploadPartState>,
    /// The public error of the last failure.
    pub error: String,
    /// The creation.
    pub created_at: Timestamp,
    /// The last change.
    pub updated_at: Timestamp,
    /// The end of a completed upload.
    pub completed_at: Option<Timestamp>,
    /// True when the check of the final object (the size, and the checksum) is good.
    pub verified: bool,
    /// `sha256` when each chunk carries its SHA-256 digest, else empty.
    pub checksum: String,
    /// True when the provider confirmed the digest of every part.
    pub checksum_verified: bool,
    /// The resume token.
    pub resume_token: String,
    /// The last progress. It moves at the creation and at a real progress only, so a poll of the status cannot keep
    /// an abandoned session alive.
    pub last_activity: Timestamp,
}

/// The form of a session that the client sees (the provider coordinates stay hidden).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PublicUpload {
    /// The id.
    pub id: String,
    /// The instance.
    pub instance: String,
    /// The relative key.
    pub key: String,
    /// The provider.
    pub provider: String,
    /// The status.
    pub status: String,
    /// The media type.
    #[serde(rename = "contentType")]
    pub content_type: String,
    /// The size of the object.
    #[serde(rename = "totalSize")]
    pub total_size: i64,
    /// The bytes that the provider holds.
    #[serde(rename = "uploadedBytes")]
    pub uploaded_bytes: i64,
    /// The offset of the next chunk.
    #[serde(rename = "nextOffset")]
    pub next_offset: i64,
    /// The size of a chunk.
    #[serde(rename = "chunkSize")]
    pub chunk_size: i64,
    /// The number of parts.
    #[serde(rename = "partCount", skip_serializing_if = "is_zero")]
    pub part_count: usize,
    /// The public error.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
    /// The creation.
    #[serde(rename = "createdAt")]
    pub created_at: Timestamp,
    /// The last change.
    #[serde(rename = "updatedAt")]
    pub updated_at: Timestamp,
    /// The end.
    #[serde(rename = "completedAt", skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<Timestamp>,
    /// True when the check of the final object is good.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub verified: bool,
    /// `sha256` or nothing.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub checksum: String,
    /// True when the provider confirmed the digest of every part.
    #[serde(rename = "checksumVerified", skip_serializing_if = "std::ops::Not::not")]
    pub checksum_verified: bool,
    /// The resume token.
    #[serde(rename = "resumeToken", skip_serializing_if = "String::is_empty")]
    pub resume_token: String,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

impl UploadSession {
    /// The form that the client sees.
    pub fn public(&self) -> PublicUpload {
        PublicUpload {
            id: self.id.clone(),
            instance: self.instance.clone(),
            key: self.key.clone(),
            provider: self.provider.clone(),
            status: self.status.clone(),
            content_type: self.content_type.clone(),
            total_size: self.total_size,
            uploaded_bytes: self.uploaded_bytes,
            next_offset: self.uploaded_bytes,
            chunk_size: self.chunk_size,
            part_count: self.parts.len(),
            error: self.error.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            completed_at: self.completed_at,
            verified: self.verified,
            checksum: self.checksum.clone(),
            checksum_verified: self.checksum_verified,
            resume_token: self.resume_token.clone(),
        }
    }
}

/// The size of a chunk for a provider and a total size. An error gives the message of the `400 invalid_size` answer.
pub fn upload_chunk_size(provider: &str, total: i64) -> Result<i64, String> {
    if !(0..=MAXIMUM_OBJECT_SIZE).contains(&total) {
        return Err(format!("object size must be between 0 and {MAXIMUM_OBJECT_SIZE} bytes"));
    }
    if provider == "s3" {
        const MEBIBYTE: i64 = 1 << 20;
        let mut chunk = 16 << 20;
        let minimum_for_part_limit = (total + MAXIMUM_S3_PARTS - 1) / MAXIMUM_S3_PARTS;
        if minimum_for_part_limit > chunk {
            chunk = minimum_for_part_limit;
        }
        chunk = (chunk + MEBIBYTE - 1) / MEBIBYTE * MEBIBYTE;
        if chunk < MINIMUM_S3_PART_SIZE {
            chunk = MINIMUM_S3_PART_SIZE;
        }
        if chunk > MAXIMUM_S3_PART_SIZE {
            return Err(format!("object is too large for at most {MAXIMUM_S3_PARTS} S3 parts"));
        }
        return Ok(chunk);
    }
    let chunk: i64 = 8 << 20;
    Ok((chunk + GCS_CHUNK_ALIGNMENT - 1) / GCS_CHUNK_ALIGNMENT * GCS_CHUNK_ALIGNMENT)
}

const CONTENT_RANGE_FORM: &str = "Content-Range must use bytes start-end/total";

/// Read `Content-Range: bytes start-end/total`. An error gives the message of the `400 invalid_content_range` answer.
pub fn parse_content_range(value: &str) -> Result<(i64, i64, i64), &'static str> {
    let value = value.trim();
    let rest = value.strip_prefix("bytes ").ok_or(CONTENT_RANGE_FORM)?;
    let (range, total) = rest.split_once('/').ok_or(CONTENT_RANGE_FORM)?;
    let (start, end) = range.split_once('-').ok_or(CONTENT_RANGE_FORM)?;
    let start: i64 = start.parse().map_err(|_| "invalid Content-Range start")?;
    let end: i64 = end.parse().map_err(|_| "invalid Content-Range end")?;
    let total: i64 = total.parse().map_err(|_| "invalid Content-Range total")?;
    if start < 0 || end < start || total <= end {
        return Err("Content-Range is outside the object size");
    }
    Ok((start, end, total))
}

/// The nanoseconds from `earlier` to `later`. The value is negative when `later` is before `earlier`.
pub fn nanos_between(later: Timestamp, earlier: Timestamp) -> i128 {
    let seconds = i128::from(later.secs) - i128::from(earlier.secs);
    seconds * 1_000_000_000 + i128::from(later.nanos) - i128::from(earlier.nanos)
}
