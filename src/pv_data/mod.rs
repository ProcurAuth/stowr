//! The previews of data files and the details of documents: SQLite (a reader of the database pages over byte
//! ranges, with sessions in memory), Parquet (the footer and the Thrift compact metadata), and the summaries of
//! the details (delimited dimensions, line counts, worksheet dimensions, SQLite header, Parquet summary).

use std::sync::Arc;

use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Route, RouteAccess, route};
use crate::instance::Instance;

/// The SQLite preview sessions in memory (their life is `server.session_ttl_seconds`).
#[derive(Debug, Default)]
pub struct SqliteSessions {}

impl SqliteSessions {
    /// A table with no session.
    pub fn new() -> Self {
        Self {}
    }

    /// Stop the cleanup of the expired sessions.
    pub fn close(&self) {}
}

/// The details of a document for `/api/media-info`: the container and its properties.
#[derive(Clone, Debug, Default)]
pub struct DocumentDetails {
    /// The container label.
    pub container: String,
    /// The properties, by label.
    pub properties: std::collections::BTreeMap<String, String>,
}

/// The details of a document (delimited text, text, spreadsheet, SQLite, Parquet).
pub async fn inspect_document_details(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    extension: &str,
    content_type: &str,
    listed: &crate::pv_media::MediaSourceMetadata,
) -> Result<DocumentDetails> {
    let _ = (ctx, instance, key, extension, content_type, listed);
    Err(Error::not_served("the details of the documents"))
}

crate::stub_handler!(handle_parquet, "the route /api/parquet");
crate::stub_handler!(handle_sqlite_sessions, "the route /api/sqlite/sessions");

/// The routes of this work package.
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
