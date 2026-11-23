// SPDX-License-Identifier: MIT OR Apache-2.0
//! The previews of data files and the details of documents: SQLite (a reader of the database pages over byte
//! ranges, with sessions in memory), Parquet (the footer and the Thrift compact metadata), and the details of the
//! documents (SQLite header, Parquet summary, and the calls to the Office and structured readers)
//! (docs/PREVIEWS.md, "SQLite", "Parquet").
//!
//! Each reader reads exact byte ranges and has strict limits. A crafted file gives a `422` error.

mod details;
mod parquet;
mod sqlite;
mod text;
mod thrift;

#[cfg(test)]
mod tests;

use std::collections::BTreeMap;
use std::sync::Arc;

use http::HeaderMap;

use crate::common::ctx::OpCtx;
use crate::common::error::Result;
use crate::common::http::{Route, RouteAccess, route};
use crate::instance::Instance;

pub use parquet::handle_parquet;
pub use sqlite::sessions::{SqliteSessions, handle_sqlite_sessions};

/// The details of a document for `/api/media-info`: the container, its properties and the storage values.
///
/// `handled` is false for a format that the document readers do not handle: the media readers continue. For a handled
/// format, the details of the answer take the size from `size` (from the headers when it is 0 or less) and the media
/// type and the headers from `headers`.
#[derive(Clone, Debug, Default)]
pub struct DocumentDetails {
    /// The container label.
    pub container: String,
    /// The properties, by label.
    pub properties: BTreeMap<String, String>,
    /// True when a document reader handled the format.
    pub handled: bool,
    /// The headers of the storage answer (a HEAD or the first range read).
    pub headers: HeaderMap,
    /// The size of the object, or 0 or less when the headers give it.
    pub size: i64,
}

/// The details of a document (delimited text, text, JSON, Office Open XML, spreadsheet, SQLite, Parquet, and the
/// structured formats). A details request never reads a whole object.
pub async fn inspect_document_details(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    extension: &str,
    content_type: &str,
    listed: &crate::pv_media::MediaSourceMetadata,
) -> Result<DocumentDetails> {
    details::inspect(ctx, instance, key, extension, content_type, listed).await
}

/// The routes of this module.
pub fn routes() -> Vec<Route> {
    vec![
        route("/api/parquet", RouteAccess::HandlerAsks, handle_parquet),
        route("/api/sqlite/sessions", RouteAccess::HandlerAsks, handle_sqlite_sessions),
        route(
            "/api/sqlite/sessions/",
            RouteAccess::HandlerAsks,
            handle_sqlite_sessions,
        ),
    ]
}
