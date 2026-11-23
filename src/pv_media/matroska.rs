//! The Matroska and WebM header: the EBML elements of the segment before the first cluster (Info and Tracks).

use super::MediaTrackInfo;
use super::bin::{be32, be64};
use super::metadata::{MediaMetadata, push_unique};
use super::text::{float_to_int, lossy};

/// The ID of the EBML header.
const EBML_HEADER: [u8; 4] = [0x1a, 0x45, 0xdf, 0xa3];
/// The ID of the segment.
const SEGMENT: u64 = 0x1853_8067;
/// The ID of a cluster: the header metadata ends before it.
const CLUSTER: u64 = 0x1f43_b675;
/// The ID of the segment information.
const INFO: u64 = 0x1549_a966;
/// The ID of the tracks.
const TRACKS: u64 = 0x1654_ae6b;

/// One element: the ID, the size of the payload, the start of the payload, and true for an unknown size.
struct Element {
    id: u64,
    size: u64,
    payload: usize,
    unknown: bool,
}

/// The element at `offset`, or `None` when its ID or its size is not complete in the bytes.
fn read_element(data: &[u8], offset: usize) -> Option<Element> {
    let (id, id_length, _) = read_ebml_vint(data, offset, true)?;
    let (size, size_length, unknown) = read_ebml_vint(data, offset + id_length, false)?;
    Some(Element {
        id,
        size,
        payload: offset + id_length + size_length,
        unknown,
    })
}

/// The metadata of a Matroska header. The result is the metadata, true when the header metadata is complete (a
/// cluster comes, or Info and Tracks are in the bytes), and true when the bytes start with an EBML header.
pub(crate) fn parse_matroska_header(data: &[u8]) -> (MediaMetadata, bool, bool) {
    let mut result = MediaMetadata::default();
    if data.len() < 4 || data[..4] != EBML_HEADER {
        return (result, true, false);
    }
    let mut segment_offset = None;
    let mut offset = 0;
    while offset < data.len() {
        let Some(element) = read_element(data, offset) else {
            return (result, false, true);
        };
        if element.id == SEGMENT {
            segment_offset = Some(element.payload);
            break;
        }
        if element.unknown || element.size > (data.len() - element.payload) as u64 {
            return (result, false, true);
        }
        offset = element.payload + element.size as usize;
    }
    let Some(segment_offset) = segment_offset else {
        return (result, false, true);
    };
    let mut timecode_scale = 1_000_000f64;
    let mut duration_units = 0f64;
    let (mut info_found, mut tracks_found) = (false, false);
    let mut offset = segment_offset;
    while offset < data.len() {
        let Some(element) = read_element(data, offset) else {
            return (result, false, true);
        };
        if element.id == CLUSTER {
            if duration_units > 0.0 {
                result.duration_seconds = duration_units * timecode_scale / 1_000_000_000.0;
            }
            return (result, true, true);
        }
        if element.unknown || element.size > (data.len() - element.payload) as u64 {
            return (result, false, true);
        }
        let end = element.payload + element.size as usize;
        let payload = &data[element.payload..end];
        match element.id {
            INFO => {
                info_found = true;
                (timecode_scale, duration_units) =
                    parse_matroska_info(payload, timecode_scale, duration_units, &mut result);
            }
            TRACKS => {
                tracks_found = true;
                result.tracks = parse_matroska_tracks(payload);
                for track in &result.tracks {
                    if !track.codec.is_empty() {
                        push_unique(&mut result.codecs, &track.codec);
                    }
                    if track.kind == "video"
                        && track.width.wrapping_mul(track.height) > result.width.wrapping_mul(result.height)
                    {
                        result.width = track.width;
                        result.height = track.height;
                    }
                }
            }
            _ => {}
        }
        offset = end;
    }
    if duration_units > 0.0 {
        result.duration_seconds = duration_units * timecode_scale / 1_000_000_000.0;
    }
    (result, info_found && tracks_found, true)
}

/// An EBML variable-size integer at `offset`: the value (with its length marker for an ID), its length, and true
/// for the reserved value of an unknown size.
pub(crate) fn read_ebml_vint(data: &[u8], offset: usize, keep_marker: bool) -> Option<(u64, usize, bool)> {
    let first = *data.get(offset)?;
    let mut mask = 0x80u8;
    let mut length = 1usize;
    while length <= 8 && first & mask == 0 {
        mask >>= 1;
        length += 1;
    }
    if length > 8 || offset + length > data.len() {
        return None;
    }
    let mut value = if keep_marker {
        u64::from(first)
    } else {
        u64::from(first & !mask)
    };
    for index in 1..length {
        value = (value << 8) | u64::from(data[offset + index]);
    }
    let unknown = !keep_marker && value == (1u64 << (7 * length)) - 1;
    Some((value, length, unknown))
}

/// Call `visit` for each element of `data` with its ID and its payload. The walk stops at an element that does not
/// fit.
fn walk_simple_ebml(data: &[u8], mut visit: impl FnMut(u64, &[u8])) {
    let mut offset = 0;
    while offset < data.len() {
        let Some(element) = read_element(data, offset) else {
            return;
        };
        if element.unknown || element.size > (data.len() - element.payload) as u64 {
            return;
        }
        let end = element.payload + element.size as usize;
        visit(element.id, &data[element.payload..end]);
        offset = end;
    }
}

/// Read the segment information: the timecode scale, the duration, the title and the applications.
fn parse_matroska_info(data: &[u8], scale: f64, duration: f64, metadata: &mut MediaMetadata) -> (f64, f64) {
    let (mut scale, mut duration) = (scale, duration);
    walk_simple_ebml(data, |id, value| match id {
        0x2a_d7b1 => {
            let number = ebml_unsigned(value);
            if number > 0 {
                scale = number as f64;
            }
        }
        0x4489 => duration = ebml_float(value),
        0x7ba9 => metadata.set("Title", &lossy(value)),
        0x4d80 => metadata.set("Muxing application", &lossy(value)),
        0x5741 => metadata.set("Writing application", &lossy(value)),
        _ => {}
    });
    (scale, duration)
}

/// The track entries of the Tracks element. The reader does not keep an entry without a known type.
fn parse_matroska_tracks(data: &[u8]) -> Vec<MediaTrackInfo> {
    let mut tracks = Vec::new();
    walk_simple_ebml(data, |id, value| {
        if id == 0xae {
            let mut track = parse_matroska_track_entry(value);
            track.index = tracks.len() as i64;
            if !track.kind.is_empty() {
                tracks.push(track);
            }
        }
    });
    tracks
}

fn parse_matroska_track_entry(data: &[u8]) -> MediaTrackInfo {
    let mut track = MediaTrackInfo::default();
    walk_simple_ebml(data, |id, value| match id {
        0x83 => match ebml_unsigned(value) {
            1 => track.kind = "video".to_owned(),
            2 => track.kind = "audio".to_owned(),
            17 => track.kind = "subtitle".to_owned(),
            _ => {}
        },
        0x86 => track.codec = lossy(value),
        0x536e => track.title = lossy(value),
        0x22_b59c => track.language = lossy(value),
        0x88 => track.default = ebml_unsigned(value) != 0,
        0xe0 => walk_simple_ebml(value, |id, value| match id {
            0xb0 => track.width = ebml_unsigned(value) as i64,
            0xba => track.height = ebml_unsigned(value) as i64,
            _ => {}
        }),
        0xe1 => walk_simple_ebml(value, |id, value| match id {
            0xb5 => track.sample_rate = float_to_int(ebml_float(value).round()),
            0x9f => track.channels = ebml_unsigned(value) as i64,
            _ => {}
        }),
        _ => {}
    });
    track
}

/// An EBML unsigned integer of any length. A value longer than 8 bytes loses its high bytes.
fn ebml_unsigned(data: &[u8]) -> u64 {
    data.iter().fold(0u64, |value, byte| (value << 8) | u64::from(*byte))
}

/// An EBML float of 4 or 8 bytes, else 0.
fn ebml_float(data: &[u8]) -> f64 {
    match data.len() {
        4 => f64::from(f32::from_bits(be32(data, 0))),
        8 => f64::from_bits(be64(data, 0)),
        _ => 0.0,
    }
}
