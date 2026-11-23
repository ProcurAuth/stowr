//! The metadata that the readers find, its merge, and the reader of a bounded part of a file (the dimensions of the
//! usual images, EXIF, MP3, WAV, FLAC and Ogg).

use std::collections::BTreeMap;
use std::collections::HashSet;

use super::MediaTrackInfo;
use super::audio::{parse_flac_metadata, parse_mp3_metadata, parse_wav_metadata};
use super::image::parse_image_dimensions;
use super::text::contains;
use super::tiff::parse_exif_metadata;

/// The metadata that a reader finds in a file.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct MediaMetadata {
    /// The width in pixels, 0 when unknown.
    pub width: i64,
    /// The height in pixels, 0 when unknown.
    pub height: i64,
    /// The duration in seconds, 0 when unknown.
    pub duration_seconds: f64,
    /// The codecs.
    pub codecs: Vec<String>,
    /// The properties, by label.
    pub properties: BTreeMap<String, String>,
    /// The tracks of a container.
    pub tracks: Vec<MediaTrackInfo>,
}

impl MediaMetadata {
    /// Keep a property. The value loses the spaces at its two ends. The function ignores an empty value.
    pub fn set(&mut self, label: &str, value: &str) {
        let value = value.trim();
        if !value.is_empty() {
            self.properties.insert(label.to_owned(), value.to_owned());
        }
    }

    /// Add the metadata of another reader. Dimensions and a duration above 0 replace the current values. The codecs
    /// of this metadata stay, and each first occurrence of a codec of this metadata or of `source` comes after them.
    /// The properties of `source` replace the properties with the same label.
    pub fn merge(&mut self, source: MediaMetadata) {
        if source.width > 0 && source.height > 0 {
            self.width = source.width;
            self.height = source.height;
        }
        if source.duration_seconds > 0.0 {
            self.duration_seconds = source.duration_seconds;
        }
        let all: Vec<String> = self.codecs.iter().chain(source.codecs.iter()).cloned().collect();
        let mut seen = HashSet::with_capacity(all.len());
        for codec in all {
            let codec = codec.trim();
            if codec.is_empty() || !seen.insert(codec.to_owned()) {
                continue;
            }
            self.codecs.push(codec.to_owned());
        }
        for (label, value) in &source.properties {
            self.set(label, value);
        }
    }
}

/// The metadata of a bounded part of a file: the dimensions of the usual images, EXIF, and the audio headers that
/// the extension names.
pub(crate) fn parse_bounded_file_metadata(
    data: &[u8],
    extension: &str,
    content_type: &str,
    object_size: i64,
) -> MediaMetadata {
    let mut result = MediaMetadata::default();
    if let Some((width, height)) = parse_image_dimensions(data, extension, content_type) {
        result.width = width;
        result.height = height;
    }
    if let Some(exif) = parse_exif_metadata(data) {
        result.merge(exif);
    }
    match extension {
        "mp3" => result.merge(parse_mp3_metadata(data, object_size)),
        "wav" | "wave" => result.merge(parse_wav_metadata(data)),
        "flac" => result.merge(parse_flac_metadata(data)),
        "ogg" | "oga" | "opus" | "ogv" => {
            if contains(data, b"OpusHead") {
                result.codecs.push("opus".to_owned());
            } else if contains(data, b"vorbis") {
                result.codecs.push("vorbis".to_owned());
            }
        }
        _ => {}
    }
    result
}

/// Add a value that is not empty after the removal of the spaces at its two ends, when the list does not have it.
pub(crate) fn push_unique(values: &mut Vec<String>, value: &str) {
    let value = value.trim();
    if value.is_empty() || values.iter().any(|existing| existing == value) {
        return;
    }
    values.push(value.to_owned());
}
