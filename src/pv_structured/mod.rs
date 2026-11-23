//! The previews of structured text and of packages: vCard, iCalendar, email (EML, MIME, MHTML), certificates,
//! certificate requests and keys (a small DER reader), PDF metadata, and the ZIP-compatible packages (ZIP, JAR,
//! APK, XPI, CRX, VSIX, EPUB) through the reader of `crate::archive::zip` (docs/PREVIEWS.md, "Structured text",
//! "ZIP-compatible packages").

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Route, RouteAccess, route};
use crate::instance::Instance;

/// The structured metadata of an object for the details: the container and its properties.
pub async fn inspect_structured_metadata(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    extension: &str,
    content_type: &str,
    listed: &crate::pv_media::MediaSourceMetadata,
) -> Result<(String, BTreeMap<String, String>)> {
    let _ = (ctx, instance, key, extension, content_type, listed);
    Err(Error::not_served("the structured metadata"))
}

crate::stub_handler!(handle_structured_preview, "the route /api/structured-preview");
crate::stub_handler!(handle_archive_preview, "the route /api/archive-preview");

/// The routes of this work package.
pub fn routes() -> Vec<Route> {
    vec![
        route(
            "/api/structured-preview",
            RouteAccess::HandlerAsks,
            handle_structured_preview,
        ),
        route("/api/archive-preview", RouteAccess::HandlerAsks, handle_archive_preview),
    ]
}
