//! The previews of text and office documents: JSON (raw, beautified, summary, tree), delimited text (CSV, TSV,
//! PSV), the search in a document, Excel-family worksheets, Word documents, and the package properties of Office
//! Open XML files (docs/PREVIEWS.md, "JSON", "Tabular data", "Office Open XML").
//!
//! Each preview reads exact byte ranges and bounded structures; a total that needs a complete scan comes only
//! after an explicit action.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Route, RouteAccess, route};
use crate::instance::Instance;

/// The package properties of an Office Open XML file (Word, Excel, PowerPoint, Visio) for the details.
pub async fn office_properties(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    extension: &str,
) -> Result<BTreeMap<String, String>> {
    let _ = (ctx, instance, key, extension);
    Err(Error::not_served("the Office Open XML properties"))
}

crate::stub_handler!(handle_spreadsheet, "the route /api/spreadsheet");
crate::stub_handler!(handle_delimited, "the route /api/delimited");
crate::stub_handler!(handle_document_count, "the route /api/document-count");
crate::stub_handler!(handle_word, "the route /api/document/word");
crate::stub_handler!(handle_json_raw, "the route /api/json/raw");
crate::stub_handler!(handle_json_beautify, "the route /api/json/beautify");
crate::stub_handler!(handle_json_summary, "the route /api/json/summary");
crate::stub_handler!(handle_json_tree, "the route /api/json/tree");
crate::stub_handler!(handle_search, "the route /api/search");

/// The routes of this work package.
pub fn routes() -> Vec<Route> {
    vec![
        route("/api/spreadsheet", RouteAccess::HandlerAsks, handle_spreadsheet),
        route("/api/delimited", RouteAccess::HandlerAsks, handle_delimited),
        route("/api/document-count", RouteAccess::HandlerAsks, handle_document_count),
        route("/api/document/word", RouteAccess::HandlerAsks, handle_word),
        route("/api/json/raw", RouteAccess::HandlerAsks, handle_json_raw),
        route("/api/json/beautify", RouteAccess::HandlerAsks, handle_json_beautify),
        route("/api/json/summary", RouteAccess::HandlerAsks, handle_json_summary),
        route("/api/json/tree", RouteAccess::HandlerAsks, handle_json_tree),
        route("/api/search", RouteAccess::HandlerAsks, handle_search),
    ]
}
