//! The ZIP archives: the reader of a central directory over exact byte ranges, the streamed writer of the ZIP of a
//! folder, the read of one entry, the extraction of entries to objects and the integrity of entries
//! (docs/ARCHITECTURE.md, "Archive extraction"; docs/SECURITY.md, "Archive members").
//!
//! The ZIP reader of this work package is also the reader of the Office Open XML, EPUB, JAR and APK previews.

pub mod zip;

use serde::Serialize;

use crate::common::error::{Error, Result};
use crate::common::http::{Route, RouteAccess, route};

/// The result of an extraction.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ArchiveExtractResult {}

/// The request of an archive entry integrity job.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ArchiveEntryIntegrityRequest {
    /// The entries.
    pub entries: Vec<String>,
}

/// The result of an archive entry integrity job.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ArchiveEntryIntegrityResult {}

/// Run the job `extract_archive`.
pub async fn run_extraction(run: &crate::jobs::JobRun, job: &mut crate::jobs::JobState) -> Result<()> {
    let _ = (run, job);
    Err(Error::not_served("the job extract_archive"))
}

/// Run the job `archive_entry_integrity`.
pub async fn run_entry_integrity(run: &crate::jobs::JobRun, job: &mut crate::jobs::JobState) -> Result<()> {
    let _ = (run, job);
    Err(Error::not_served("the job archive_entry_integrity"))
}

crate::stub_handler!(handle_archive, "the route /api/archive");
crate::stub_handler!(handle_archive_entry, "the route /api/archive-entry");
crate::stub_handler!(handle_archive_entry_integrity, "the route /api/archive-entry/integrity");
crate::stub_handler!(handle_archive_extract, "the route /api/archive-extract");

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
