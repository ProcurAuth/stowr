//! The details of the media and the route `/api/media-info`: the dimensions, the duration and the metadata of
//! images, audio and video read from bounded headers and trailers (PNG, JPEG and EXIF, WebP, TIFF and RAW, HEIF,
//! ISO base media, Matroska, MP3, FLAC, WAV, Ogg, FITS, EXR, JPEG 2000, SVG...), the embedded previews of RAW files
//! (`/api/image-preview`), and the dispatch of the details to the document and structured readers.

use crate::common::http::{Route, RouteAccess, route};
use crate::common::time::Timestamp;

/// What the listing already knows about an object: the size, the ETag, the date and the media type. A reader that
/// has these values sends no HEAD request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MediaSourceMetadata {
    /// The size, or -1 when unknown.
    pub size: i64,
    /// The ETag.
    pub etag: String,
    /// The last change.
    pub last_modified: Option<Timestamp>,
    /// The media type.
    pub content_type: String,
}

crate::stub_handler!(handle_media_info, "the route /api/media-info");
crate::stub_handler!(handle_image_preview, "the route /api/image-preview");

/// The routes of this work package.
pub fn routes() -> Vec<Route> {
    vec![
        route("/api/media-info", RouteAccess::HandlerAsks, handle_media_info),
        route("/api/image-preview", RouteAccess::HandlerAsks, handle_image_preview),
    ]
}
