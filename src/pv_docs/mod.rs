//! The previews of text and office documents: JSON (raw, beautified, summary, tree), delimited text (CSV, TSV,
//! PSV), the search in a document, Excel-family worksheets, Word documents, and the package properties of Office
//! Open XML files (docs/PREVIEWS.md, "JSON", "Tabular data", "Office Open XML").
//!
//! Each preview reads exact byte ranges and bounded structures; a total that needs a complete scan comes only
//! after an explicit action.
//!
//! The modules of this folder:
//! - `json`, `delimited` (with `csv`), `search`, `spreadsheet`, `word` and `office` hold the routes and the readers.
//! - `count` has the explicit counts of the details and of `/api/document-count`.
//! - `stream` reads an object in order. `xml` is a strict reader of XML over a stream. `package` opens an Office
//!   package as a ZIP archive and runs a parser on a blocking thread over the bytes of one part.
//! - `util` has the text helpers, `compare` the filters and the order of the cell values, and `request` has the
//!   start of each route.

pub mod compare;
pub mod count;
pub mod csv;
pub mod delimited;
pub mod json;
pub mod office;
pub mod package;
pub mod request;
pub mod search;
pub mod spreadsheet;
pub mod stream;
pub mod util;
pub mod word;
pub mod xml;

#[cfg(test)]
mod test_support;

use crate::common::http::{Route, RouteAccess, route};

pub use office::office_properties;

/// The routes of this module.
pub fn routes() -> Vec<Route> {
    vec![
        route(
            "/api/spreadsheet",
            RouteAccess::HandlerAsks,
            spreadsheet::handle_spreadsheet,
        ),
        route("/api/delimited", RouteAccess::HandlerAsks, delimited::handle_delimited),
        route(
            "/api/document-count",
            RouteAccess::HandlerAsks,
            count::handle_document_count,
        ),
        route("/api/document/word", RouteAccess::HandlerAsks, word::handle_word),
        route("/api/json/raw", RouteAccess::HandlerAsks, json::handle_raw),
        route("/api/json/beautify", RouteAccess::HandlerAsks, json::handle_beautify),
        route("/api/json/summary", RouteAccess::HandlerAsks, json::handle_summary),
        route("/api/json/tree", RouteAccess::HandlerAsks, json::handle_tree),
        route("/api/search", RouteAccess::HandlerAsks, search::handle_search),
    ]
}
