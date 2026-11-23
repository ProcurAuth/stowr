// SPDX-License-Identifier: MIT OR Apache-2.0
//! The PEM reader and the base64 decoder of the structured readers.

/// One PEM block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PemBlock {
    /// The type of the block, from the line `-----BEGIN <type>-----`.
    pub kind: String,
    /// The decoded bytes.
    pub bytes: Vec<u8>,
}

const PEM_BEGIN: &[u8] = b"-----BEGIN ";
const PEM_NEWLINE_BEGIN: &[u8] = b"\n-----BEGIN ";
const PEM_NEWLINE_END: &[u8] = b"\n-----END ";
const PEM_DASHES: &[u8] = b"-----";

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

fn trim_right_blank(data: &[u8]) -> &[u8] {
    let mut end = data.len();
    while end > 0 && (data[end - 1] == b' ' || data[end - 1] == b'\t') {
        end -= 1;
    }
    &data[..end]
}

/// The first line of the data without its line end and without the blanks at its end, and the rest.
fn get_line(data: &[u8]) -> (&[u8], &[u8]) {
    match data.iter().position(|byte| *byte == b'\n') {
        None => (trim_right_blank(data), &data[data.len()..]),
        Some(index) => {
            let mut end = index;
            if index > 0 && data[index - 1] == b'\r' {
                end -= 1;
            }
            (trim_right_blank(&data[..end]), &data[index + 1..])
        }
    }
}

/// Decode the first PEM block of the data. Gives the block and the data after it.
pub fn decode(data: &[u8]) -> Option<(PemBlock, &[u8])> {
    let mut rest = data;
    loop {
        if rest.starts_with(PEM_BEGIN) {
            rest = &rest[PEM_BEGIN.len()..];
        } else {
            let position = find(rest, PEM_NEWLINE_BEGIN)?;
            rest = &rest[position + PEM_NEWLINE_BEGIN.len()..];
        }
        let (type_line, after) = get_line(rest);
        rest = after;
        if !type_line.ends_with(PEM_DASHES) {
            continue;
        }
        let type_line = &type_line[..type_line.len() - PEM_DASHES.len()];
        let mut header_count = 0usize;
        loop {
            if rest.is_empty() {
                return None;
            }
            let (line, next) = get_line(rest);
            if !line.contains(&b':') {
                break;
            }
            header_count += 1;
            rest = next;
        }
        let end_prefix = &PEM_NEWLINE_END[1..];
        let (end_index, end_trailer_index) = if header_count == 0 && rest.starts_with(end_prefix) {
            (0, end_prefix.len())
        } else {
            match find(rest, PEM_NEWLINE_END) {
                Some(index) => (index, index + PEM_NEWLINE_END.len()),
                None => continue,
            }
        };
        let end_trailer = &rest[end_trailer_index..];
        let end_trailer_length = type_line.len() + PEM_DASHES.len();
        if end_trailer.len() < end_trailer_length {
            continue;
        }
        let rest_of_end_line = &end_trailer[end_trailer_length..];
        let end_trailer = &end_trailer[..end_trailer_length];
        if !end_trailer.starts_with(type_line) || !end_trailer.ends_with(PEM_DASHES) {
            continue;
        }
        if !get_line(rest_of_end_line).0.is_empty() {
            continue;
        }
        let text: Vec<u8> = rest[..end_index]
            .iter()
            .copied()
            .filter(|byte| *byte != b' ' && *byte != b'\t')
            .collect();
        let Some(bytes) = decode_base64(&text) else {
            continue;
        };
        let (_, after) = get_line(&rest[end_index + PEM_NEWLINE_END.len() - 1..]);
        return Some((
            PemBlock {
                kind: String::from_utf8_lossy(type_line).into_owned(),
                bytes,
            },
            after,
        ));
    }
}

/// Every PEM block of the data, in order.
pub fn decode_all(data: &[u8]) -> Vec<PemBlock> {
    let mut blocks = Vec::new();
    let mut rest = data;
    while let Some((block, after)) = decode(rest) {
        blocks.push(block);
        rest = after;
    }
    blocks
}

fn base64_value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode standard base64 with padding. The decoder skips the characters CR and LF, accepts bits that are not
/// zero in the last character, and refuses data after the padding.
pub fn decode_base64(source: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(source.len() / 4 * 3);
    let mut index = 0;
    while index < source.len() {
        let mut quantum = [0u8; 4];
        let mut length = 4;
        let mut trailing_garbage = false;
        let mut position = 0;
        while position < 4 {
            if index == source.len() {
                if position == 0 {
                    return Some(out);
                }
                // Padding is required.
                return None;
            }
            let byte = source[index];
            index += 1;
            if let Some(value) = base64_value(byte) {
                quantum[position] = value;
                position += 1;
                continue;
            }
            if byte == b'\n' || byte == b'\r' {
                continue;
            }
            if byte != b'=' {
                return None;
            }
            match position {
                0 | 1 => return None,
                2 => {
                    while index < source.len() && (source[index] == b'\n' || source[index] == b'\r') {
                        index += 1;
                    }
                    if index == source.len() || source[index] != b'=' {
                        return None;
                    }
                    index += 1;
                }
                _ => {}
            }
            while index < source.len() && (source[index] == b'\n' || source[index] == b'\r') {
                index += 1;
            }
            if index < source.len() {
                trailing_garbage = true;
            }
            length = position;
            break;
        }
        let value = (u32::from(quantum[0]) << 18)
            | (u32::from(quantum[1]) << 12)
            | (u32::from(quantum[2]) << 6)
            | u32::from(quantum[3]);
        let bytes = [(value >> 16) as u8, (value >> 8) as u8, value as u8];
        out.extend_from_slice(&bytes[..length - 1]);
        if trailing_garbage {
            return None;
        }
    }
    Some(out)
}

/// The standard base64 text of bytes, with padding.
pub fn encode_base64(bytes: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}
