//! The ZIP archives: the reader of a central directory over exact byte ranges, the streamed writer of the ZIP of a
//! folder, the read of one entry, the extraction of entries to objects and the integrity of entries
//! (docs/ARCHITECTURE.md, "Archive extraction"; docs/SECURITY.md, "Archive members").
//!
//! The ZIP reader of this work package is also the reader of the Office Open XML, EPUB, JAR and APK previews.
//!
//! - [`zip`]: [`zip::ZipReader`] (the central directory, the entries, the entry streams) and
//!   [`zip::writer::ZipWriter`].
//! - `folder`: `GET /api/archive`, the ZIP of a folder.
//! - `entry`: `GET|HEAD /api/archive-entry`, `POST /api/archive-extract`, `POST /api/archive-entry/integrity`, and
//!   the runners of the jobs `extract_archive` and `archive_entry_integrity`.

pub mod content;
pub mod entry;
pub mod folder;
pub mod md5;
pub mod names;
pub mod stream;
pub mod zip;

use serde::Serialize;

use crate::common::http::{Route, RouteAccess, route};

pub use entry::{
    handle_archive_entry, handle_archive_entry_integrity, handle_archive_extract, run_entry_integrity, run_extraction,
};
pub use folder::handle_archive;

/// The result of an extraction. The job keeps it; its public form shows it after the end of the job.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ArchiveExtractResult {
    /// The relative key of the archive.
    #[serde(rename = "archiveKey")]
    pub archive_key: String,
    /// The version of the archive.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version: String,
    /// The instance of the destination.
    #[serde(rename = "targetInstance")]
    pub target_instance: String,
    /// The destination folder.
    pub target: String,
    /// The extracted entries.
    pub extracted: i64,
    /// The extracted bytes.
    pub bytes: i64,
    /// The end of the extraction; the zero time before the end.
    #[serde(rename = "completedAt", serialize_with = "crate::common::time::serialize_or_zero")]
    pub completed_at: Option<crate::common::time::Timestamp>,
}

/// The request of an archive entry integrity job.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ArchiveEntryIntegrityRequest {
    /// The relative key of the archive.
    pub key: String,
    /// The version of the archive.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version: String,
    /// The exact name of the entry.
    pub entry: String,
}

/// The result of an archive entry integrity job.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ArchiveEntryIntegrityResult {
    /// The relative key of the archive.
    #[serde(rename = "archiveKey")]
    pub archive_key: String,
    /// The version of the archive.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version: String,
    /// The name of the entry.
    pub entry: String,
    /// The bytes of the entry.
    pub size: i64,
    /// The compressed bytes of the entry.
    #[serde(rename = "compressedSize")]
    pub compressed_size: i64,
    /// The SHA-256 in hexadecimal.
    pub sha256: String,
    /// The MD5 in hexadecimal.
    pub md5: String,
    /// The CRC-32 of the bytes, 8 hexadecimal digits.
    pub crc32: String,
    /// The CRC-32 of the central directory, 8 hexadecimal digits.
    #[serde(rename = "expectedCrc32")]
    pub expected_crc32: String,
    /// True when the two CRC-32 agree.
    #[serde(rename = "crc32Matches")]
    pub crc32_matches: bool,
}

/// The routes of this work package.
pub fn routes() -> Vec<Route> {
    vec![
        route("/api/archive", RouteAccess::HandlerAsks, handle_archive),
        route("/api/archive-entry", RouteAccess::HandlerAsks, handle_archive_entry),
        route(
            "/api/archive-entry/integrity",
            RouteAccess::HandlerAsks,
            handle_archive_entry_integrity,
        ),
        route("/api/archive-extract", RouteAccess::HandlerAsks, handle_archive_extract),
    ]
}

#[cfg(test)]
mod tests;
