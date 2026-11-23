//! The dimensions of the images from their headers: PNG, GIF, WebP, JPEG, BMP, PSD, TGA, ICO, DDS, PCX, SGI, QOI,
//! farbfeld, the PNM family, Radiance HDR, FITS, OpenEXR, JPEG 2000 and SVG.

use std::collections::HashMap;

use super::bin::{be16, be32, le16, le32};
use super::text::{find, float_to_int, fold_lower, fold_upper, lossy, lower_bytes, parse_float, parse_int};

/// The signature of a PNG file.
pub(crate) const PNG_SIGNATURE: [u8; 8] = [137, 80, 78, 71, 13, 10, 26, 10];

fn positive(width: i64, height: i64) -> Option<(i64, i64)> {
    (width > 0 && height > 0).then_some((width, height))
}

/// The dimensions of a PNG, GIF, WebP or JPEG image that the extension or the media type names.
pub(crate) fn parse_image_dimensions(data: &[u8], extension: &str, content_type: &str) -> Option<(i64, i64)> {
    if extension == "png" || content_type == "image/png" {
        if data.len() >= 24 && data[..8] == PNG_SIGNATURE {
            return positive(i64::from(be32(data, 16)), i64::from(be32(data, 20)));
        }
        return None;
    }
    if extension == "gif" || content_type == "image/gif" {
        if data.len() >= 10 && (&data[..6] == b"GIF87a" || &data[..6] == b"GIF89a") {
            return positive(i64::from(le16(data, 6)), i64::from(le16(data, 8)));
        }
        return None;
    }
    if extension == "webp" || content_type == "image/webp" {
        return parse_webp_dimensions(data);
    }
    if extension == "jpg" || extension == "jpeg" || content_type == "image/jpeg" {
        return parse_jpeg_dimensions(data);
    }
    None
}

/// The dimensions of the first start-of-frame segment of a JPEG image.
pub(crate) fn parse_jpeg_dimensions(data: &[u8]) -> Option<(i64, i64)> {
    if data.len() < 4 || data[0] != 0xff || data[1] != 0xd8 {
        return None;
    }
    let mut offset = 2;
    while offset + 4 <= data.len() {
        while offset < data.len() && data[offset] != 0xff {
            offset += 1;
        }
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
        let length = usize::from(be16(data, offset));
        if length < 2 || offset + length > data.len() {
            break;
        }
        if is_jpeg_start_of_frame(marker) && length >= 7 {
            let height = i64::from(be16(data, offset + 3));
            let width = i64::from(be16(data, offset + 5));
            return positive(width, height);
        }
        offset += length;
    }
    None
}

/// True for the markers of a start-of-frame segment.
fn is_jpeg_start_of_frame(marker: u8) -> bool {
    matches!(
        marker,
        0xc0 | 0xc1 | 0xc2 | 0xc3 | 0xc5 | 0xc6 | 0xc7 | 0xc9 | 0xca | 0xcb | 0xcd | 0xce | 0xcf
    )
}

/// The dimensions of a WebP image: the first chunk (`VP8X`, `VP8L` or `VP8 `) of the first 30 bytes.
pub(crate) fn parse_webp_dimensions(data: &[u8]) -> Option<(i64, i64)> {
    if data.len() < 30 || &data[..4] != b"RIFF" || &data[8..12] != b"WEBP" {
        return None;
    }
    let byte = |index: usize| i64::from(data[index]);
    match &data[12..16] {
        b"VP8X" => positive(
            1 + byte(24) + (byte(25) << 8) + (byte(26) << 16),
            1 + byte(27) + (byte(28) << 8) + (byte(29) << 16),
        ),
        b"VP8L" => {
            if data[20] != 0x2f {
                return None;
            }
            positive(
                1 + byte(21) + ((byte(22) & 0x3f) << 8),
                1 + (byte(22) >> 6) + (byte(23) << 2) + ((byte(24) & 0x0f) << 10),
            )
        }
        b"VP8 " => {
            if data[23] != 0x9d || data[24] != 0x01 || data[25] != 0x2a {
                return None;
            }
            positive(i64::from(le16(data, 26) & 0x3fff), i64::from(le16(data, 28) & 0x3fff))
        }
        _ => None,
    }
}

/// The dimensions of the images with a fixed header that the extension names (BMP, PSD, TGA, ICO, DDS, PCX, SGI,
/// QOI, farbfeld). For another extension, an image media type gives the PNG, GIF, WebP or JPEG dimensions.
pub(crate) fn parse_additional_image_dimensions(
    data: &[u8],
    extension: &str,
    content_type: &str,
) -> Option<(i64, i64)> {
    let extension = fold_lower(extension);
    match extension.as_str() {
        "bmp" | "dib" if data.len() >= 26 && &data[..2] == b"BM" => {
            let width = i64::from(le32(data, 18) as i32);
            let height = i64::from(le32(data, 22) as i32).abs();
            return positive(width, height);
        }
        "psd" | "psb" if data.len() >= 26 && &data[..4] == b"8BPS" => {
            return positive(i64::from(be32(data, 18)), i64::from(be32(data, 14)));
        }
        "tga" if data.len() >= 18 => {
            return positive(i64::from(le16(data, 12)), i64::from(le16(data, 14)));
        }
        "ico" | "cur" if data.len() >= 8 && le16(data, 0) == 0 && le16(data, 4) > 0 => {
            let width = if data[6] == 0 { 256 } else { i64::from(data[6]) };
            let height = if data[7] == 0 { 256 } else { i64::from(data[7]) };
            return Some((width, height));
        }
        "dds" if data.len() >= 20 && &data[..4] == b"DDS " => {
            return positive(i64::from(le32(data, 16)), i64::from(le32(data, 12)));
        }
        "pcx" if data.len() >= 12 && data[0] == 0x0a => {
            let x_min = i64::from(le16(data, 4));
            let y_min = i64::from(le16(data, 6));
            let x_max = i64::from(le16(data, 8));
            let y_max = i64::from(le16(data, 10));
            return positive(x_max - x_min + 1, y_max - y_min + 1);
        }
        "sgi" | "rgb" | "rgba" | "bw" if data.len() >= 10 && be16(data, 0) == 0x01da => {
            return positive(i64::from(be16(data, 6)), i64::from(be16(data, 8)));
        }
        "qoi" if data.len() >= 14 && &data[..4] == b"qoif" => {
            return positive(i64::from(be32(data, 4)), i64::from(be32(data, 8)));
        }
        "ff" | "farbfeld" if data.len() >= 16 && &data[..8] == b"farbfeld" => {
            return positive(i64::from(be32(data, 8)), i64::from(be32(data, 12)));
        }
        _ => {}
    }
    if content_type.starts_with("image/") {
        return parse_image_dimensions(data, &extension, content_type);
    }
    None
}

/// The dimensions of a PNM header (P1 to P7). The result is the width, the height, true when the header is
/// complete, and true when the data is a valid PNM header.
pub(crate) fn parse_pnm_dimensions(data: &[u8]) -> (i64, i64, bool, bool) {
    if data.len() < 2 || data[0] != b'P' || data[1] < b'1' || data[1] > b'7' {
        return (0, 0, data.len() >= 2, false);
    }
    if data[1] == b'7' {
        let text = lossy(data).replace("\r\n", "\n");
        let Some(end) = text.find("\nENDHDR") else {
            return (0, 0, false, true);
        };
        let (mut width, mut height) = (0, 0);
        for line in text[..end].split('\n') {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() != 2 {
                continue;
            }
            let Some(value) = parse_int(fields[1]).filter(|value| *value > 0) else {
                continue;
            };
            match fold_upper(fields[0]).as_str() {
                "WIDTH" => width = value,
                "HEIGHT" => height = value,
                _ => {}
            }
        }
        return (width, height, true, width > 0 && height > 0);
    }
    let separator = |byte: u8| matches!(byte, b' ' | b'\t' | b'\r' | b'\n');
    let mut tokens: Vec<&[u8]> = Vec::with_capacity(4);
    let mut index = 2;
    while index < data.len() && tokens.len() < 3 {
        while index < data.len() && separator(data[index]) {
            index += 1;
        }
        if index >= data.len() {
            break;
        }
        if data[index] == b'#' {
            match data[index..].iter().position(|byte| *byte == b'\n') {
                Some(newline) => {
                    index += newline + 1;
                    continue;
                }
                None => return (0, 0, false, true),
            }
        }
        let start = index;
        while index < data.len() && !separator(data[index]) && data[index] != b'#' {
            index += 1;
        }
        if start < index {
            tokens.push(&data[start..index]);
        }
    }
    if tokens.len() < 2 {
        return (0, 0, false, true);
    }
    let number = |token: &[u8]| std::str::from_utf8(token).ok().and_then(parse_int);
    let width = number(tokens[0]);
    let height = number(tokens[1]);
    match (width, height) {
        (Some(width), Some(height)) => (width, height, true, width > 0 && height > 0),
        (width, height) => (width.unwrap_or(0), height.unwrap_or(0), true, false),
    }
}

/// The dimensions of a Radiance HDR header: the first line with four fields that names X and Y. The result is the
/// width, the height, true when the header is complete, and true when the data is a valid HDR header.
pub(crate) fn parse_radiance_hdr_dimensions(data: &[u8]) -> (i64, i64, bool, bool) {
    if data.len() >= 2 && !data.starts_with(b"#?") {
        return (0, 0, true, false);
    }
    let text = lossy(data).replace("\r\n", "\n");
    for line in text.split('\n') {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() != 4 {
            continue;
        }
        let (mut x, mut y) = (0, 0);
        for index in [0, 2] {
            let Some(value) = parse_int(fields[index + 1]).filter(|value| *value > 0) else {
                continue;
            };
            match fold_upper(fields[index].trim_start_matches(['+', '-'])).as_str() {
                "X" => x = value,
                "Y" => y = value,
                _ => {}
            }
        }
        if x > 0 && y > 0 {
            return (x, y, true, true);
        }
    }
    (0, 0, false, true)
}

/// Read the 80-byte cards of a FITS header: keep `NAXIS1` and `NAXIS2`. True when the `END` card comes.
pub(crate) fn parse_fits_cards(data: &[u8], width: &mut i64, height: &mut i64) -> bool {
    let mut offset = 0;
    while offset + 80 <= data.len() {
        let card = &data[offset..offset + 80];
        offset += 80;
        let keyword = lossy(&card[..8]);
        let keyword = keyword.trim();
        if keyword == "END" {
            return true;
        }
        if card[8] != b'=' {
            continue;
        }
        let value = lossy(&card[10..]);
        let value = value.split('/').next().unwrap_or("").trim();
        let Some(parsed) = parse_int(value).filter(|parsed| *parsed > 0) else {
            continue;
        };
        match keyword {
            "NAXIS1" => *width = parsed,
            "NAXIS2" => *height = parsed,
            _ => {}
        }
    }
    false
}

/// The largest size of one structure that a reader accepts: 128 MiB.
const MAX_STRUCTURE_BYTES: i64 = 128 << 20;

/// The dimensions of the data window of an OpenEXR header. The result is the width, the height, the number of
/// bytes that the next step needs, true when the header is complete, and true when the data is a valid header.
pub(crate) fn parse_exr_dimensions(data: &[u8]) -> (i64, i64, i64, bool, bool) {
    let length = data.len() as i64;
    if data.len() < 8 {
        return (0, 0, 8, false, true);
    }
    if le32(data, 0) != 0x0131_2f76 {
        return (0, 0, 8, true, false);
    }
    let (mut width, mut height) = (0i64, 0i64);
    let mut offset = 8usize;
    for _ in 0..10_000 {
        let Some(name_end) = data[offset..].iter().position(|byte| *byte == 0) else {
            return (0, 0, length + 256, false, true);
        };
        let name_end = name_end + offset;
        if name_end == offset {
            return (width, height, name_end as i64 + 1, true, true);
        }
        let name = &data[offset..name_end];
        offset = name_end + 1;
        let Some(type_end) = data[offset..].iter().position(|byte| *byte == 0) else {
            return (0, 0, length + 256, false, true);
        };
        let type_end = type_end + offset;
        let type_name = &data[offset..type_end];
        offset = type_end + 1;
        if offset + 4 > data.len() {
            return (0, 0, offset as i64 + 4, false, true);
        }
        let size = i64::from(le32(data, offset));
        offset += 4;
        if size > MAX_STRUCTURE_BYTES {
            return (0, 0, offset as i64, true, false);
        }
        let end = offset as i64 + size;
        if end > length {
            return (0, 0, end, false, true);
        }
        if name == b"dataWindow" && type_name == b"box2i" && size >= 16 {
            let x_min = le32(data, offset) as i32;
            let y_min = le32(data, offset + 4) as i32;
            let x_max = le32(data, offset + 8) as i32;
            let y_max = le32(data, offset + 12) as i32;
            if x_max >= x_min && y_max >= y_min {
                width = i64::from(x_max.wrapping_sub(x_min)) + 1;
                height = i64::from(y_max.wrapping_sub(y_min)) + 1;
            }
        }
        offset = end as usize;
    }
    (width, height, offset as i64, true, false)
}

/// The dimensions of the image and tile size segment (SIZ) of a JPEG 2000 codestream.
pub(crate) fn parse_j2k_codestream_dimensions(data: &[u8]) -> Option<(i64, i64)> {
    if data.len() < 4 || data[0] != 0xff || data[1] != 0x4f {
        return None;
    }
    let mut offset = 2;
    while offset + 4 <= data.len() {
        if data[offset] != 0xff {
            offset += 1;
            continue;
        }
        let marker = data[offset + 1];
        offset += 2;
        if marker == 0x51 {
            if offset + 2 > data.len() {
                return None;
            }
            let length = usize::from(be16(data, offset));
            if length < 38 || offset + length > data.len() {
                return None;
            }
            let payload = &data[offset + 2..offset + length];
            let x_size = be32(payload, 2);
            let y_size = be32(payload, 6);
            let x_origin = be32(payload, 10);
            let y_origin = be32(payload, 14);
            if x_size > x_origin && y_size > y_origin {
                return Some((i64::from(x_size - x_origin), i64::from(y_size - y_origin)));
            }
            return None;
        }
        if marker == 0x93 || marker == 0xd9 {
            break;
        }
        if offset + 2 > data.len() {
            break;
        }
        let length = usize::from(be16(data, offset));
        if length < 2 || offset + length > data.len() {
            break;
        }
        offset += length;
    }
    None
}

/// The start tag of the `svg` element: from `<svg` (any case) to the next `>`. `None` while the bytes do not hold
/// the complete tag.
pub(crate) fn find_svg_start_tag(data: &[u8]) -> Option<&[u8]> {
    let lower = lower_bytes(data);
    let start = find(&lower, b"<svg")?;
    let end = lower[start..].iter().position(|byte| *byte == b'>')?;
    let from = start.min(data.len());
    let to = (start + end + 1).min(data.len());
    Some(&data[from..to])
}

/// The dimensions of an SVG start tag: `width` and `height`, else the size of `viewBox`.
pub(crate) fn parse_svg_start_tag(tag: &[u8]) -> (i64, i64) {
    let attributes = parse_loose_xml_attributes(tag);
    let attribute = |name: &str| attributes.get(name).map_or(&[][..], Vec::as_slice);
    let width = parse_svg_length(attribute("width"));
    let height = parse_svg_length(attribute("height"));
    if width > 0 && height > 0 {
        return (width, height);
    }
    let view_box = lossy(attribute("viewbox")).replace(',', " ");
    let fields: Vec<&str> = view_box.split_whitespace().collect();
    if fields.len() == 4
        && let (Some(view_width), Some(view_height)) = (parse_float(fields[2]), parse_float(fields[3]))
        && view_width > 0.0
        && view_height > 0.0
    {
        return (float_to_int(view_width.round()), float_to_int(view_height.round()));
    }
    (width, height)
}

/// The attributes of a start tag, by lower-case name. The reader accepts any text: it skips an attribute without a
/// quoted value.
pub(crate) fn parse_loose_xml_attributes(tag: &[u8]) -> HashMap<String, Vec<u8>> {
    let mut attributes = HashMap::new();
    let length = tag.len();
    let mut index = 0;
    while index < length {
        while index < length && matches!(tag[index], b'<' | b'>' | b'/' | b' ' | b'\t' | b'\r' | b'\n') {
            index += 1;
        }
        let start = index;
        while index < length && !matches!(tag[index], b'=' | b' ' | b'\t' | b'>') {
            index += 1;
        }
        let name = fold_lower(lossy(&tag[start..index]).trim());
        while index < length && matches!(tag[index], b' ' | b'\t') {
            index += 1;
        }
        if name.is_empty() || index >= length || tag[index] != b'=' {
            while index < length && tag[index] != b' ' && tag[index] != b'>' {
                index += 1;
            }
            continue;
        }
        index += 1;
        while index < length && matches!(tag[index], b' ' | b'\t') {
            index += 1;
        }
        if index >= length {
            break;
        }
        let quote = tag[index];
        if quote != b'\'' && quote != b'"' {
            continue;
        }
        index += 1;
        let value_start = index;
        while index < length && tag[index] != quote {
            index += 1;
        }
        attributes.insert(name, tag[value_start..index].to_vec());
        if index < length {
            index += 1;
        }
    }
    attributes
}

/// An SVG length in pixels: the number at the start of the value, rounded. A percentage, an empty value or a value
/// that is not above 0 gives 0.
pub(crate) fn parse_svg_length(value: &[u8]) -> i64 {
    let value = lossy(value);
    let value = value.trim();
    if value.is_empty() || value.ends_with('%') {
        return 0;
    }
    let end = value
        .bytes()
        .position(|byte| !(byte.is_ascii_digit() || byte == b'.' || byte == b'+' || byte == b'-'))
        .unwrap_or(value.len());
    if end == 0 {
        return 0;
    }
    match parse_float(&value[..end]) {
        Some(number) if number > 0.0 => float_to_int(number.round()),
        _ => 0,
    }
}
