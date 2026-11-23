// SPDX-License-Identifier: MIT OR Apache-2.0
//! The TIFF structures: classic TIFF, BigTIFF and the TIFF-like headers of camera RAW files (Olympus ORF, Panasonic
//! RW2). The reader follows only the declared offsets of the image file directories (IFD): it never scans the image
//! data for tags. It gives the EXIF properties (camera, lens, exposure, GPS), the embedded JPEG preview of a RAW file
//! and the preview of a Fujifilm RAF file.

use std::collections::{HashMap, HashSet};

use super::bin::{Order, be32};
use super::metadata::MediaMetadata;
use super::text::{format_fixed, format_general, latin1, trim_bytes};

/// The layout of a TIFF structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TiffLayout {
    /// The byte order.
    pub order: Order,
    /// True for BigTIFF.
    pub big: bool,
    /// The offset of the first IFD.
    pub first_ifd: u64,
    /// The size of the entry count of an IFD.
    pub count_size: usize,
    /// The size of one IFD entry.
    pub entry_size: usize,
    /// The largest value that an entry holds in itself.
    pub inline_value_size: i64,
    /// The size of the offset of the next IFD.
    pub next_offset_size: usize,
}

/// The layout of the TIFF header at the start of `data`, or `None`.
pub(crate) fn parse_tiff_layout(data: &[u8]) -> Option<TiffLayout> {
    if data.len() < 8 {
        return None;
    }
    let order = match &data[..2] {
        b"II" => Order::Little,
        b"MM" => Order::Big,
        _ => return None,
    };
    match order.u16(data, 2) {
        42 | 0x4f52 | 0x5352 | 0x0055 => Some(TiffLayout {
            order,
            big: false,
            first_ifd: u64::from(order.u32(data, 4)),
            count_size: 2,
            entry_size: 12,
            inline_value_size: 4,
            next_offset_size: 4,
        }),
        43 => {
            if data.len() < 16 || order.u16(data, 4) != 8 || order.u16(data, 6) != 0 {
                return None;
            }
            Some(TiffLayout {
                order,
                big: true,
                first_ifd: order.u64(data, 8),
                count_size: 8,
                entry_size: 20,
                inline_value_size: 8,
                next_offset_size: 8,
            })
        }
        _ => None,
    }
}

/// The size in bytes of one value of a TIFF type, or 0 for an unknown type.
pub(crate) fn tiff_type_size(type_id: u16) -> i64 {
    match type_id {
        1 | 2 | 6 | 7 => 1,
        3 | 8 => 2,
        4 | 9 | 11 => 4,
        5 | 10 | 12 => 8,
        _ => 0,
    }
}

/// One IFD entry: the type, the count and the value or the offset of the value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct TiffEntry {
    type_id: u16,
    count: u64,
    value: [u8; 8],
}

/// A reader of a TIFF structure in memory.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TiffReader<'a> {
    data: &'a [u8],
    layout: TiffLayout,
}

impl<'a> TiffReader<'a> {
    /// A reader of `data` and the offset of its first IFD, when `data` starts with a TIFF header and the first IFD
    /// is inside `data`.
    pub fn new(data: &'a [u8]) -> Option<(Self, u64)> {
        let layout = parse_tiff_layout(data)?;
        if layout.first_ifd == 0 || layout.first_ifd >= data.len() as u64 {
            return None;
        }
        Some((Self { data, layout }, layout.first_ifd))
    }

    /// The entries of the IFD at `offset`, by tag (4096 entries at most). An IFD outside the data is empty.
    pub fn read_ifd(&self, offset: u64) -> HashMap<u16, TiffEntry> {
        let mut out = HashMap::new();
        let length = self.data.len() as u64;
        if offset > length || self.layout.count_size as u64 > length - offset {
            return out;
        }
        let mut cursor = offset as usize;
        let order = self.layout.order;
        let count = if self.layout.big {
            order.u64(self.data, cursor)
        } else {
            u64::from(order.u16(self.data, cursor))
        }
        .min(4096);
        cursor += self.layout.count_size;
        let mut index = 0;
        while index < count && cursor + self.layout.entry_size <= self.data.len() {
            let entry = &self.data[cursor..cursor + self.layout.entry_size];
            let mut value = [0u8; 8];
            let count = if self.layout.big {
                value.copy_from_slice(&entry[12..20]);
                order.u64(entry, 4)
            } else {
                value[..4].copy_from_slice(&entry[8..12]);
                u64::from(order.u32(entry, 4))
            };
            out.insert(
                order.u16(entry, 0),
                TiffEntry {
                    type_id: order.u16(entry, 2),
                    count,
                    value,
                },
            );
            cursor += self.layout.entry_size;
            index += 1;
        }
        out
    }

    /// The bytes of the value of an entry (1 MiB at most), or `None`.
    fn entry_bytes<'b>(&self, entry: &'b TiffEntry) -> Option<&'b [u8]>
    where
        'a: 'b,
    {
        if entry.count > i64::MAX as u64 {
            return None;
        }
        let size = tiff_type_size(entry.type_id).wrapping_mul(entry.count as i64);
        if size <= 0 || size > self.data.len() as i64 || size > 1 << 20 {
            return None;
        }
        if size <= self.layout.inline_value_size {
            return Some(&entry.value[..size as usize]);
        }
        let offset = if self.layout.big {
            self.layout.order.u64(&entry.value, 0)
        } else {
            u64::from(self.layout.order.u32(&entry.value, 0))
        };
        if offset > i64::MAX as u64 {
            return None;
        }
        let end = (offset as i64).checked_add(size)?;
        if end > self.data.len() as i64 {
            return None;
        }
        Some(&self.data[offset as usize..end as usize])
    }

    /// The text of an entry, without the NUL bytes and the spaces at its two ends. A value that is not UTF-8 is
    /// ISO 8859-1.
    pub fn as_string(&self, entry: Option<&TiffEntry>) -> String {
        let entry = entry.copied().unwrap_or_default();
        let Some(data) = self.entry_bytes(&entry) else {
            return String::new();
        };
        let data = trim_bytes(data, b"\x00 \t\r\n");
        match std::str::from_utf8(data) {
            Ok(text) => text.trim().to_owned(),
            Err(_) => latin1(data).trim().to_owned(),
        }
    }

    /// The first unsigned integer of an entry (BYTE, SHORT or LONG), or 0.
    pub fn as_uint(&self, entry: Option<&TiffEntry>) -> u64 {
        let entry = entry.copied().unwrap_or_default();
        let Some(data) = self.entry_bytes(&entry) else {
            return 0;
        };
        let order = self.layout.order;
        match entry.type_id {
            1 | 6 | 7 => u64::from(data[0]),
            3 | 8 if data.len() >= 2 => u64::from(order.u16(data, 0)),
            4 | 9 if data.len() >= 4 => u64::from(order.u32(data, 0)),
            _ => 0,
        }
    }

    /// The first rational of an entry (signed for SRATIONAL), or `None` for a zero denominator.
    pub fn as_rational(&self, entry: Option<&TiffEntry>) -> Option<f64> {
        let entry = entry.copied().unwrap_or_default();
        let data = self.entry_bytes(&entry)?;
        if data.len() < 8 {
            return None;
        }
        let order = self.layout.order;
        if entry.type_id == 10 {
            let numerator = order.u32(data, 0) as i32;
            let denominator = order.u32(data, 4) as i32;
            if denominator == 0 {
                return None;
            }
            return Some(f64::from(numerator) / f64::from(denominator));
        }
        let numerator = order.u32(data, 0);
        let denominator = order.u32(data, 4);
        if denominator == 0 {
            return None;
        }
        Some(f64::from(numerator) / f64::from(denominator))
    }

    /// The degrees of three rationals (degrees, minutes, seconds), or `None`.
    pub fn as_dms(&self, entry: Option<&TiffEntry>) -> Option<f64> {
        let entry = entry.copied().unwrap_or_default();
        let data = self.entry_bytes(&entry)?;
        if data.len() < 24 || (entry.type_id != 5 && entry.type_id != 10) {
            return None;
        }
        let order = self.layout.order;
        let mut values = [0f64; 3];
        for (index, value) in values.iter_mut().enumerate() {
            let numerator = order.u32(data, index * 8);
            let denominator = order.u32(data, index * 8 + 4);
            if denominator == 0 {
                return None;
            }
            *value = f64::from(numerator) / f64::from(denominator);
        }
        Some(values[0] + values[1] / 60.0 + values[2] / 3600.0)
    }
}

/// The EXIF payload of the APP1 segment of a JPEG image: the TIFF structure after `Exif\0\0`.
pub(crate) fn jpeg_exif_payload(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 4 || data[0] != 0xff || data[1] != 0xd8 {
        return None;
    }
    let mut offset = 2;
    while offset + 4 <= data.len() {
        while offset < data.len() && data[offset] == 0xff {
            offset += 1;
        }
        if offset >= data.len() {
            break;
        }
        let marker = data[offset];
        offset += 1;
        if marker == 0xd8 || marker == 0xd9 || (0xd0..=0xd7).contains(&marker) || marker == 0x01 {
            continue;
        }
        if offset + 2 > data.len() {
            break;
        }
        let length = usize::from(super::bin::be16(data, offset));
        if length < 2 || offset + length > data.len() {
            break;
        }
        let payload = &data[offset + 2..offset + length];
        if marker == 0xe1 && payload.len() >= 6 && payload[..6] == *b"Exif\x00\x00" {
            return Some(&payload[6..]);
        }
        offset += length;
    }
    None
}

/// The EXIF metadata of a JPEG image or of a TIFF structure: the camera, the software, the capture date, the
/// orientation, the dimensions, the lens, the exposure and the GPS position.
pub(crate) fn parse_exif_metadata(data: &[u8]) -> Option<MediaMetadata> {
    let tiff = jpeg_exif_payload(data).unwrap_or(data);
    let (reader, first_ifd) = TiffReader::new(tiff)?;
    let mut result = MediaMetadata::default();
    let base = reader.read_ifd(first_ifd);
    result.set("Camera make", &reader.as_string(base.get(&0x010f)));
    result.set("Camera model", &reader.as_string(base.get(&0x0110)));
    result.set("Software", &reader.as_string(base.get(&0x0131)));
    result.set("Captured", &reader.as_string(base.get(&0x0132)));
    let orientation = reader.as_uint(base.get(&0x0112));
    if orientation > 0 {
        result.set("Orientation", &orientation_label(orientation));
    }
    let width = reader.as_uint(base.get(&0x0100)) as i64;
    if width > 0 {
        result.width = width;
    }
    let height = reader.as_uint(base.get(&0x0101)) as i64;
    if height > 0 {
        result.height = height;
    }

    let exif_offset = reader.as_uint(base.get(&0x8769));
    if exif_offset > 0 {
        let exif = reader.read_ifd(exif_offset);
        let captured = reader.as_string(exif.get(&0x9003));
        if !captured.is_empty() {
            result.set("Captured", &captured);
        }
        result.set("Lens", &reader.as_string(exif.get(&0xa434)));
        result.set("Lens make", &reader.as_string(exif.get(&0xa433)));
        let iso = reader.as_uint(exif.get(&0x8827));
        if iso > 0 {
            result.set("ISO", &iso.to_string());
        }
        if let Some(value) = reader.as_rational(exif.get(&0x829a)).filter(|value| *value > 0.0) {
            result.set("Exposure", &format_exposure(value));
        }
        if let Some(value) = reader.as_rational(exif.get(&0x829d)).filter(|value| *value > 0.0) {
            result.set("Aperture", &format!("f/{}", format_fixed(value, 1)));
        }
        if let Some(value) = reader.as_rational(exif.get(&0x920a)).filter(|value| *value > 0.0) {
            result.set("Focal length", &format!("{} mm", format_fixed(value, 1)));
        }
        let focal35 = reader.as_uint(exif.get(&0xa405));
        if focal35 > 0 {
            result.set("35 mm equivalent", &format!("{focal35} mm"));
        }
        let width = reader.as_uint(exif.get(&0xa002)) as i64;
        if width > 0 {
            result.width = width;
        }
        let height = reader.as_uint(exif.get(&0xa003)) as i64;
        if height > 0 {
            result.height = height;
        }
    }

    let gps_offset = reader.as_uint(base.get(&0x8825));
    if gps_offset > 0 {
        let gps = reader.read_ifd(gps_offset);
        let latitude = reader.as_dms(gps.get(&0x0002));
        let longitude = reader.as_dms(gps.get(&0x0004));
        let south = is_reference(&reader.as_string(gps.get(&0x0001)), 'S');
        let west = is_reference(&reader.as_string(gps.get(&0x0003)), 'W');
        if let (Some(latitude), Some(longitude)) = (latitude, longitude) {
            let latitude = if south { -latitude } else { latitude };
            let longitude = if west { -longitude } else { longitude };
            if latitude.abs() <= 90.0 && longitude.abs() <= 180.0 {
                result.set(
                    "GPS",
                    &format!("{}, {}", format_fixed(latitude, 6), format_fixed(longitude, 6)),
                );
            }
        }
        if let Some(altitude) = reader.as_rational(gps.get(&0x0006)) {
            let below = reader.as_uint(gps.get(&0x0005)) == 1;
            let altitude = if below { -altitude } else { altitude };
            result.set("GPS altitude", &format!("{} m", format_fixed(altitude, 1)));
        }
    }
    Some(result)
}

/// True when a GPS reference is the letter, in any case (the long s matches `S`).
fn is_reference(value: &str, letter: char) -> bool {
    let mut characters = value.chars();
    let (Some(first), None) = (characters.next(), characters.next()) else {
        return false;
    };
    first.eq_ignore_ascii_case(&letter) || (letter == 'S' && first == '\u{17f}')
}

/// The label of an EXIF orientation, or its number.
pub(crate) fn orientation_label(value: u64) -> String {
    match value {
        1 => "Normal",
        2 => "Mirrored horizontally",
        3 => "Rotated 180°",
        4 => "Mirrored vertically",
        5 => "Mirrored and rotated 90°",
        6 => "Rotated 90° clockwise",
        7 => "Mirrored and rotated 270°",
        8 => "Rotated 90° counter-clockwise",
        _ => return value.to_string(),
    }
    .to_owned()
}

/// An exposure time: `1/250 s` below one second, else three significant digits (`2 s`).
pub(crate) fn format_exposure(value: f64) -> String {
    if value > 0.0 && value < 1.0 {
        let denominator = (1.0 / value).round();
        if denominator > 0.0 {
            return format!("1/{} s", format_fixed(denominator, 0));
        }
    }
    format!("{} s", format_general(value, 3))
}

/// The offset and the length of the JPEG preview of a Fujifilm RAF file, from its header.
pub(crate) fn raf_preview_range(data: &[u8]) -> Option<(i64, i64)> {
    if data.len() < 92 || !data.starts_with(b"FUJIFILMCCD-RAW ") {
        return None;
    }
    let offset = i64::from(be32(data, 84));
    let length = i64::from(be32(data, 88));
    if length <= 0 || offset > 1 << 50 || length > 1 << 34 {
        return None;
    }
    Some((offset, length))
}

/// The offset and the length of the embedded JPEG preview of a TIFF-based RAW file: the JPEG interchange format
/// tags of the first IFD, of its sub-IFDs or of its EXIF IFD (five levels at most).
pub(crate) fn embedded_tiff_jpeg_range(data: &[u8]) -> Option<(i64, i64)> {
    let (reader, first_ifd) = TiffReader::new(data)?;
    let mut visited = HashSet::new();
    inspect_preview_ifd(&reader, first_ifd, 0, &mut visited)
}

fn inspect_preview_ifd(
    reader: &TiffReader<'_>,
    offset: u64,
    depth: usize,
    visited: &mut HashSet<u64>,
) -> Option<(i64, i64)> {
    if depth > 5 || !visited.insert(offset) {
        return None;
    }
    let tags = reader.read_ifd(offset);
    let jpeg_offset = reader.as_uint(tags.get(&0x0201)) as i64;
    let jpeg_length = reader.as_uint(tags.get(&0x0202)) as i64;
    if jpeg_offset >= 0 && jpeg_length > 0 {
        return Some((jpeg_offset, jpeg_length));
    }
    for tag in [0x014a, 0x8769] {
        let child = reader.as_uint(tags.get(&tag));
        if child > 0
            && let Some(found) = inspect_preview_ifd(reader, child, depth + 1, visited)
        {
            return Some(found);
        }
    }
    None
}

/// True for the tags whose values the metadata reader needs (dimensions, camera, EXIF, GPS, sub-IFDs, preview).
pub(crate) fn tiff_metadata_tag(tag: u16) -> bool {
    matches!(
        tag,
        0x0100
            | 0x0101
            | 0x010f
            | 0x0110
            | 0x0112
            | 0x0131
            | 0x0132
            | 0x014a
            | 0x0201
            | 0x0202
            | 0x829a
            | 0x829d
            | 0x8769
            | 0x8825
            | 0x8827
            | 0x9003
            | 0x920a
            | 0xa002
            | 0xa003
            | 0xa405
            | 0xa433
            | 0xa434
            | 0x0001
            | 0x0002
            | 0x0003
            | 0x0004
            | 0x0005
            | 0x0006
    )
}

/// The first `count` unsigned integers of a value (BYTE, SHORT or LONG).
pub(crate) fn tiff_uint_values(order: Order, type_id: u16, data: &[u8], count: usize) -> Vec<u64> {
    let mut out = Vec::with_capacity(count.min(4096));
    match type_id {
        1 | 6 | 7 => out.extend(data.iter().take(count).map(|byte| u64::from(*byte))),
        3 | 8 => out.extend(
            data.as_chunks::<2>()
                .0
                .iter()
                .take(count)
                .map(|pair| u64::from(order.u16(pair, 0))),
        ),
        4 | 9 => out.extend(
            data.as_chunks::<4>()
                .0
                .iter()
                .take(count)
                .map(|quad| u64::from(order.u32(quad, 0))),
        ),
        _ => {}
    }
    out
}
