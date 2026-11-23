//! The text of an HTML fragment: the tags, the scripts and the styles go away, the line breaks stay, the character
//! references become characters.

use super::entities::{DOUBLE, LONGEST_WITHOUT_SEMICOLON, SINGLE};

/// The characters of the references `&#128;` to `&#159;`, which a browser reads as Windows characters.
const REPLACEMENTS: [u32; 32] = [
    0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D,
    0x017D, 0x008F, 0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A,
    0x0153, 0x009D, 0x017E, 0x0178,
];

fn push_char(out: &mut Vec<u8>, value: u32) {
    let character = char::from_u32(value).unwrap_or('\u{fffd}');
    let mut buffer = [0u8; 4];
    out.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
}

fn lookup_single(name: &str) -> Option<u32> {
    SINGLE
        .binary_search_by(|(entry, _)| (*entry).cmp(name))
        .ok()
        .map(|index| SINGLE[index].1)
}

fn lookup_double(name: &str) -> Option<(u32, u32)> {
    DOUBLE
        .binary_search_by(|(entry, _, _)| (*entry).cmp(name))
        .ok()
        .map(|index| (DOUBLE[index].1, DOUBLE[index].2))
}

/// Decode the character reference at `source` (the byte is `&`): write the result and give the new position.
fn unescape_entity(bytes: &[u8], source: usize, out: &mut Vec<u8>) -> usize {
    let rest = &bytes[source..];
    if rest.len() <= 1 {
        out.push(bytes[source]);
        return source + 1;
    }
    let mut index = 1;
    if rest[index] == b'#' {
        if rest.len() <= 3 {
            out.push(bytes[source]);
            return source + 1;
        }
        index += 1;
        let mut character = rest[index];
        let mut hex = false;
        if character == b'x' || character == b'X' {
            hex = true;
            index += 1;
        }
        let mut value: i32 = 0;
        while index < rest.len() {
            character = rest[index];
            index += 1;
            if hex {
                if let Some(digit) = (character as char).to_digit(16) {
                    value = value.wrapping_mul(16).wrapping_add(digit as i32);
                    continue;
                }
            } else if character.is_ascii_digit() {
                value = value.wrapping_mul(10).wrapping_add(i32::from(character - b'0'));
                continue;
            }
            if character != b';' {
                index -= 1;
            }
            break;
        }
        if index <= 3 {
            out.push(bytes[source]);
            return source + 1;
        }
        let code = if (0x80..=0x9f).contains(&value) {
            REPLACEMENTS[(value - 0x80) as usize]
        } else if value <= 0 || (0xd800..=0xdfff).contains(&value) || value > 0x10_ffff {
            0xfffd
        } else {
            value as u32
        };
        push_char(out, code);
        return source + index;
    }
    while index < rest.len() {
        let character = rest[index];
        index += 1;
        if character.is_ascii_alphanumeric() {
            continue;
        }
        if character != b';' {
            index -= 1;
        }
        break;
    }
    let name = &rest[1..index];
    if !name.is_empty()
        && let Ok(name) = std::str::from_utf8(name)
    {
        if let Some(value) = lookup_single(name) {
            push_char(out, value);
            return source + index;
        }
        if let Some((first, second)) = lookup_double(name) {
            push_char(out, first);
            push_char(out, second);
            return source + index;
        }
        let mut longest = name.len() - 1;
        if longest > LONGEST_WITHOUT_SEMICOLON {
            longest = LONGEST_WITHOUT_SEMICOLON;
        }
        let mut length = longest;
        while length > 1 {
            if let Some(value) = lookup_single(&name[..length]) {
                push_char(out, value);
                return source + length + 1;
            }
            length -= 1;
        }
    }
    out.extend_from_slice(&bytes[source..source + index]);
    source + index
}

/// Decode the character references of a text.
pub fn unescape(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut source = 0;
    while source < bytes.len() {
        if bytes[source] == b'&' {
            source = unescape_entity(bytes, source, &mut out);
        } else {
            out.push(bytes[source]);
            source += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn starts_with_ignore_case(bytes: &[u8], prefix: &str) -> bool {
    bytes.len() >= prefix.len() && bytes[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
}

fn is_space(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\n' | 0x0c | b'\r' | b' ')
}

/// The end of the end tag `</name  >` at the start of the bytes, when there is one.
fn closing_tag_end(bytes: &[u8], name: &str) -> Option<usize> {
    let opening = format!("</{name}");
    if !starts_with_ignore_case(bytes, &opening) {
        return None;
    }
    let mut index = opening.len();
    while index < bytes.len() && is_space(bytes[index]) {
        index += 1;
    }
    (bytes.get(index) == Some(&b'>')).then_some(index + 1)
}

/// Replace each block `<name ...> ... </name>` with a space. The block ends at the first end tag.
fn replace_blocks(text: &str, name: &str) -> String {
    let bytes = text.as_bytes();
    let opening = format!("<{name}");
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < bytes.len() {
        let Some(offset) = (index..bytes.len()).find(|position| starts_with_ignore_case(&bytes[*position..], &opening))
        else {
            break;
        };
        let after_name = offset + opening.len();
        let Some(close) = bytes[after_name..].iter().position(|byte| *byte == b'>') else {
            break;
        };
        let content_start = after_name + close + 1;
        let Some(end) = (content_start..bytes.len())
            .find_map(|position| closing_tag_end(&bytes[position..], name).map(|length| position + length))
        else {
            break;
        };
        out.push_str(&text[index..offset]);
        out.push(' ');
        index = end;
    }
    out.push_str(&text[index..]);
    out
}

/// The length of the line break tag at the start of the bytes: `<br>`, `<br/>`, `</p>`, `</div>`, `</li>` or `</tr>`.
fn line_break_length(bytes: &[u8]) -> Option<usize> {
    for tag in ["</p>", "</div>", "</li>", "</tr>"] {
        if starts_with_ignore_case(bytes, tag) {
            return Some(tag.len());
        }
    }
    if starts_with_ignore_case(bytes, "<br") {
        let mut index = 3;
        while index < bytes.len() && is_space(bytes[index]) {
            index += 1;
        }
        if bytes.get(index) == Some(&b'/') {
            index += 1;
        }
        if bytes.get(index) == Some(&b'>') {
            return Some(index + 1);
        }
    }
    None
}

fn replace_line_breaks(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    let mut copied = 0;
    while index < bytes.len() {
        if bytes[index] == b'<'
            && let Some(length) = line_break_length(&bytes[index..])
        {
            out.push_str(&text[copied..index]);
            out.push('\n');
            index += length;
            copied = index;
            continue;
        }
        index += 1;
    }
    out.push_str(&text[copied..]);
    out
}

fn replace_tags(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    let mut copied = 0;
    while index < bytes.len() {
        if bytes[index] == b'<' {
            let Some(close) = bytes[index + 1..].iter().position(|byte| *byte == b'>') else {
                break;
            };
            out.push_str(&text[copied..index]);
            out.push(' ');
            index += close + 2;
            copied = index;
            continue;
        }
        index += 1;
    }
    out.push_str(&text[copied..]);
    out
}

/// The plain text of an HTML fragment: one line for each block, the words separated by one space.
pub fn to_plain_text(value: &str) -> String {
    let value = replace_blocks(value, "script");
    let value = replace_blocks(&value, "style");
    let value = replace_line_breaks(&value);
    let value = replace_tags(&value);
    let value = unescape(&value).replace('\r', "");
    let mut lines: Vec<String> = Vec::new();
    for line in value.split('\n') {
        let joined = line.split_whitespace().collect::<Vec<_>>().join(" ");
        if !joined.is_empty() {
            lines.push(joined);
        }
    }
    lines.join("\n")
}
