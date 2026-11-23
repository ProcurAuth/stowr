//! The details of the media and the route `/api/media-info`: the dimensions, the duration and the metadata of
//! images, audio and video read from bounded headers and trailers (PNG, JPEG and EXIF, WebP, TIFF and RAW, HEIF,
//! ISO base media, Matroska, MP3, FLAC, WAV, Ogg, FITS, EXR, JPEG 2000, SVG...), the embedded previews of RAW files
//! (`/api/image-preview`), and the dispatch of the details to the document and structured readers.
//!
//! A details request never reads a complete media object: each reader asks for the byte ranges that its format
//! declares, with a guard of 128 MiB for one structure (docs/PREVIEWS.md).

mod adaptive;
mod audio;
mod bin;
mod details;
mod image;
mod iso;
mod matroska;
mod metadata;
mod preview;
mod text;
mod tiff;

use std::collections::BTreeMap;

use serde::Serialize;

use crate::common::http::{Route, RouteAccess, route};
use crate::common::time::Timestamp;

pub use adaptive::{
    MAX_METADATA_STRUCTURE_BYTES, METADATA_GROWTH_FLOOR, metadata_range_length, metadata_structure_limit,
};
pub use details::{
    extension_may_contain_inspectable_metadata, handle_media_info, media_container, parse_int64_default,
    populate_media_storage_fields,
};
pub use preview::{MAX_EMBEDDED_IMAGE_PREVIEW_BYTES, handle_image_preview};

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

/// The answer of `/api/media-info`: the storage facts of the object, then the facts that a reader of its format
/// found. The members with an empty value are not in the JSON text.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaInfoResponse {
    /// The instance.
    pub instance: String,
    /// The relative key.
    pub key: String,
    /// The size in bytes.
    pub size: i64,
    /// The media type of the storage, without its parameters.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub mime: String,
    /// The object headers of the storage, by lower-case name.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    /// The container label, for example `PNG`, `MP4` or `CSV`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub container: String,
    /// The width in pixels.
    #[serde(skip_serializing_if = "is_zero")]
    pub width: i64,
    /// The height in pixels.
    #[serde(skip_serializing_if = "is_zero")]
    pub height: i64,
    /// The duration in seconds.
    #[serde(skip_serializing_if = "is_zero_float")]
    pub duration_seconds: f64,
    /// The codecs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub codecs: Vec<String>,
    /// The tracks of a container.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tracks: Vec<MediaTrackInfo>,
    /// The properties, by label.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub properties: BTreeMap<String, String>,
    /// True for an object with a key of the client (SSE-C): the provider refused to read it.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub customer_key: bool,
}

/// One track of a media container.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MediaTrackInfo {
    /// The position of the track in the answer, from 0.
    pub index: i64,
    /// `video`, `audio`, `subtitle` or the handler of the container.
    #[serde(rename = "type")]
    pub kind: String,
    /// The codec.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub codec: String,
    /// The long name of the codec.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub codec_long_name: String,
    /// The profile.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub profile: String,
    /// The pixel format.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub pixel_format: String,
    /// The language.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub language: String,
    /// The title.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub title: String,
    /// The label.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub label: String,
    /// The width in pixels.
    #[serde(skip_serializing_if = "is_zero")]
    pub width: i64,
    /// The height in pixels.
    #[serde(skip_serializing_if = "is_zero")]
    pub height: i64,
    /// The channels.
    #[serde(skip_serializing_if = "is_zero")]
    pub channels: i64,
    /// The channel layout.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub channel_layout: String,
    /// The sample rate in hertz.
    #[serde(skip_serializing_if = "is_zero")]
    pub sample_rate: i64,
    /// The bit rate in bits per second.
    #[serde(skip_serializing_if = "is_zero")]
    pub bit_rate: i64,
    /// The frame rate.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub frame_rate: String,
    /// True for the default track.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub default: bool,
    /// True for a forced track.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub forced: bool,
    /// The mode of a subtitle track.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub subtitle_mode: String,
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}

fn is_zero_float(value: &f64) -> bool {
    *value == 0.0
}

/// The routes of this work package.
pub fn routes() -> Vec<Route> {
    vec![
        route("/api/media-info", RouteAccess::HandlerAsks, handle_media_info),
        route("/api/image-preview", RouteAccess::HandlerAsks, handle_image_preview),
    ]
}

#[cfg(test)]
mod tests;

#[cfg(test)]
#[path = "parser_tests.rs"]
mod parser_tests;
