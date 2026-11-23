//! The ISO base media file format (MP4, MOV, M4A, HEIF, AVIF, CR3): the boxes of a `moov` or `meta` box, the
//! duration of `mvhd`, the dimensions of `tkhd` and `ispe`, and the tracks (handler, language, sample entry).

use super::MediaTrackInfo;
use super::bin::{be16, be32, be64};
use super::text::{contains, find, lossy};

/// The codecs that the reader finds by their four-character code anywhere in the metadata.
const KNOWN_CODECS: [&str; 11] = [
    "avc1", "avc3", "hvc1", "hev1", "vp09", "av01", "mp4v", "mp4a", "Opus", "ac-3", "ec-3",
];

/// The largest track width or height that `tkhd` can give.
const MAX_TRACK_DIMENSION: i64 = 100_000;

/// The dimensions, the duration and the codecs of the metadata of an ISO base media file. The largest `tkhd`
/// dimensions and the longest `mvhd` duration win; the codecs are in alphabetical order.
pub(crate) fn parse_iso_base_media(segments: &[&[u8]]) -> (i64, i64, f64, Vec<String>) {
    let (mut width, mut height) = (0i64, 0i64);
    let mut duration = 0f64;
    let mut codecs: Vec<String> = Vec::new();
    for data in segments {
        for codec in KNOWN_CODECS {
            if contains(data, codec.as_bytes()) && !codecs.iter().any(|known| known == codec) {
                codecs.push(codec.to_owned());
            }
        }
        for payload in find_iso_box_payloads(data, b"mvhd") {
            let value = parse_mvhd_duration(payload);
            if value > 0.0 && (duration == 0.0 || value > duration) {
                duration = value;
            }
        }
        for payload in find_iso_box_payloads(data, b"tkhd") {
            let (candidate_width, candidate_height) = parse_tkhd_dimensions(payload);
            if candidate_width * candidate_height > width * height {
                width = candidate_width;
                height = candidate_height;
            }
        }
    }
    codecs.sort();
    (width, height, duration, codecs)
}

/// The payloads of each box of a type anywhere in the bytes: a search of the four-character code, then a check of
/// the size before it.
pub(crate) fn find_iso_box_payloads<'a>(data: &'a [u8], box_type: &[u8; 4]) -> Vec<&'a [u8]> {
    let mut payloads = Vec::with_capacity(2);
    let mut search_from = 4usize;
    while search_from + 4 <= data.len() {
        let Some(relative) = find(&data[search_from..], box_type) else {
            break;
        };
        let type_offset = search_from + relative;
        let box_start = type_offset - 4;
        let mut box_size = i64::from(be32(data, box_start));
        let mut payload_start = type_offset + 4;
        if box_size == 1 {
            if payload_start + 8 > data.len() {
                search_from = type_offset + 1;
                continue;
            }
            box_size = be64(data, payload_start) as i64;
            payload_start += 8;
        }
        if box_size >= (payload_start - box_start) as i64 && box_size <= (data.len() - box_start) as i64 {
            let box_end = box_start + box_size as usize;
            if payload_start <= box_end {
                payloads.push(&data[payload_start..box_end]);
            }
        }
        search_from = type_offset + box_type.len();
    }
    payloads
}

/// The duration in seconds of an `mvhd` payload (version 0 or 1).
pub(crate) fn parse_mvhd_duration(payload: &[u8]) -> f64 {
    if payload.len() < 20 {
        return 0.0;
    }
    if payload[0] == 1 {
        if payload.len() < 32 {
            return 0.0;
        }
        let timescale = be32(payload, 20);
        let duration = be64(payload, 24);
        if timescale == 0 {
            return 0.0;
        }
        return duration as f64 / f64::from(timescale);
    }
    let timescale = be32(payload, 12);
    let duration = be32(payload, 16);
    if timescale == 0 {
        return 0.0;
    }
    f64::from(duration) / f64::from(timescale)
}

/// The width and the height of a `tkhd` payload: the two fixed-point numbers at its end.
pub(crate) fn parse_tkhd_dimensions(payload: &[u8]) -> (i64, i64) {
    if payload.len() < 8 {
        return (0, 0);
    }
    let width = i64::from(be32(payload, payload.len() - 8) >> 16);
    let height = i64::from(be32(payload, payload.len() - 4) >> 16);
    if width <= 0 || height <= 0 || width > MAX_TRACK_DIMENSION || height > MAX_TRACK_DIMENSION {
        return (0, 0);
    }
    (width, height)
}

/// One box of a list of boxes.
#[derive(Clone, Copy, Debug)]
pub(crate) struct IsoBox<'a> {
    /// The four-character type.
    pub box_type: &'a [u8],
    /// The payload after the header.
    pub payload: &'a [u8],
}

/// The boxes that follow each other in `data[start..end]` (10000 at most). The list stops at the first box that
/// does not fit.
pub(crate) fn iso_child_boxes(data: &[u8], start: usize, end: usize) -> Vec<IsoBox<'_>> {
    let end = end.min(data.len());
    let mut out = Vec::new();
    let mut offset = start;
    let mut count = 0;
    while offset + 8 <= end && count < 10_000 {
        count += 1;
        let mut size = i64::from(be32(data, offset));
        let box_type = &data[offset + 4..offset + 8];
        let mut header_size = 8usize;
        if size == 1 {
            if offset + 16 > end {
                break;
            }
            size = be64(data, offset + 8) as i64;
            header_size = 16;
        } else if size == 0 {
            size = (end - offset) as i64;
        }
        if size < header_size as i64 || size > (end - offset) as i64 {
            break;
        }
        let box_end = offset + size as usize;
        out.push(IsoBox {
            box_type,
            payload: &data[offset + header_size..box_end],
        });
        offset = box_end;
    }
    out
}

/// The first child box of a type.
pub(crate) fn iso_find_child<'a>(data: &'a [u8], box_type: &[u8]) -> Option<IsoBox<'a>> {
    iso_child_boxes(data, 0, data.len())
        .into_iter()
        .find(|item| item.box_type == box_type)
}

/// The tracks of the `moov` box at the root of `data`: the type of the handler, the dimensions, the language and
/// the sample entry. `None` without a `moov` box.
pub(crate) fn parse_iso_tracks(data: &[u8]) -> Option<Vec<MediaTrackInfo>> {
    let moov = iso_child_boxes(data, 0, data.len())
        .into_iter()
        .find(|item| item.box_type == b"moov")?
        .payload;
    let mut tracks = Vec::new();
    for trak in iso_child_boxes(moov, 0, moov.len()) {
        if trak.box_type != b"trak" {
            continue;
        }
        let mut track = MediaTrackInfo {
            index: tracks.len() as i64,
            ..MediaTrackInfo::default()
        };
        if let Some(tkhd) = iso_find_child(trak.payload, b"tkhd") {
            (track.width, track.height) = parse_tkhd_dimensions(tkhd.payload);
        }
        let Some(mdia) = iso_find_child(trak.payload, b"mdia") else {
            continue;
        };
        if let Some(hdlr) = iso_find_child(mdia.payload, b"hdlr")
            && hdlr.payload.len() >= 12
        {
            let handler = &hdlr.payload[8..12];
            track.kind = match handler {
                b"vide" => "video".to_owned(),
                b"soun" => "audio".to_owned(),
                b"subt" | b"sbtl" | b"text" | b"clcp" => "subtitle".to_owned(),
                _ => lossy(handler).trim().to_owned(),
            };
        }
        if let Some(mdhd) = iso_find_child(mdia.payload, b"mdhd") {
            track.language = parse_mdhd_language(mdhd.payload);
        }
        if let Some(stsd) = iso_find_child(mdia.payload, b"minf")
            .and_then(|minf| iso_find_child(minf.payload, b"stbl"))
            .and_then(|stbl| iso_find_child(stbl.payload, b"stsd"))
        {
            parse_iso_track_sample_entry(&mut track, stsd.payload);
        }
        if !track.kind.is_empty() {
            tracks.push(track);
        }
    }
    for (index, track) in tracks.iter_mut().enumerate() {
        track.index = index as i64;
    }
    Some(tracks)
}

/// The codec of the first sample entry of an `stsd` payload, with the dimensions of a video entry and the channels
/// and the sample rate of an audio entry.
pub(crate) fn parse_iso_track_sample_entry(track: &mut MediaTrackInfo, payload: &[u8]) {
    if payload.len() < 16 {
        return;
    }
    let entry_size = be32(payload, 8) as usize;
    if entry_size < 8 || 8 + entry_size > payload.len() {
        return;
    }
    track.codec = lossy(&payload[12..16]);
    let entry = &payload[16..8 + entry_size];
    if track.kind == "video" && entry.len() >= 28 {
        let width = i64::from(be16(entry, 24));
        if width > 0 {
            track.width = width;
        }
        let height = i64::from(be16(entry, 26));
        if height > 0 {
            track.height = height;
        }
    }
    if track.kind == "audio" && entry.len() >= 28 {
        track.channels = i64::from(be16(entry, 16));
        track.sample_rate = i64::from(be32(entry, 24) >> 16);
    }
}

/// The ISO 639-2 language of an `mdhd` payload (three packed letters), or an empty text.
pub(crate) fn parse_mdhd_language(payload: &[u8]) -> String {
    if payload.len() < 24 {
        return String::new();
    }
    let offset = if payload[0] == 1 { 32 } else { 20 };
    if offset + 2 > payload.len() {
        return String::new();
    }
    let packed = be16(payload, offset);
    if packed == 0 {
        return String::new();
    }
    let letters = [
        (((packed >> 10) & 0x1f) as u8).wrapping_add(0x60),
        (((packed >> 5) & 0x1f) as u8).wrapping_add(0x60),
        ((packed & 0x1f) as u8).wrapping_add(0x60),
    ];
    if letters.iter().any(|letter| !letter.is_ascii_lowercase()) {
        return String::new();
    }
    letters.iter().map(|letter| char::from(*letter)).collect()
}

/// The dimensions of the first `ispe` box (the image spatial extents of HEIF and AVIF).
pub(crate) fn parse_ispe_image_dimensions(data: &[u8]) -> (i64, i64) {
    for payload in find_iso_box_payloads(data, b"ispe") {
        if payload.len() >= 12 {
            let width = i64::from(be32(payload, 4));
            let height = i64::from(be32(payload, 8));
            if width > 0 && height > 0 {
                return (width, height);
            }
        }
    }
    (0, 0)
}
