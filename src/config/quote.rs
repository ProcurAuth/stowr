// SPDX-License-Identifier: MIT OR Apache-2.0
//! The quoted form of a text in the messages and in the effective configuration, and the escapes of a quoted string
//! of the HCL file.
//!
//! The quoted form puts the text between double quotes. It writes `"` and `\` with a backslash, a printable
//! character as it is, `\a \b \f \n \r \t \v` for these controls, `\xHH` for another control and for each byte that is
//! not UTF-8, `\uHHHH` or `\UHHHHHHHH` for another character that is not printable.

use super::printable::is_printable;

const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

/// The quoted form of a text, between double quotes.
pub fn quote(text: &str) -> String {
    quote_bytes(text.as_bytes())
}

/// The quoted form of bytes, between double quotes. Each byte that is not part of a UTF-8 character gives `\xHH`.
pub fn quote_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() + 2);
    out.push('"');
    for chunk in bytes.utf8_chunks() {
        for c in chunk.valid().chars() {
            push_escaped(&mut out, c, '"');
        }
        for byte in chunk.invalid() {
            push_hex_byte(&mut out, *byte);
        }
    }
    out.push('"');
    out
}

/// The quoted form of one character between single quotes. A value that is not a character gives U+FFFD.
pub fn quote_char(value: u32) -> String {
    let c = char::from_u32(value).unwrap_or(char::REPLACEMENT_CHARACTER);
    let mut out = String::with_capacity(8);
    out.push('\'');
    push_escaped(&mut out, c, '\'');
    out.push('\'');
    out
}

fn push_hex_byte(out: &mut String, byte: u8) {
    out.push_str("\\x");
    out.push(char::from(LOWER_HEX[usize::from(byte >> 4)]));
    out.push(char::from(LOWER_HEX[usize::from(byte & 0xf)]));
}

fn push_hex(out: &mut String, value: u32, digits: u32) {
    for index in (0..digits).rev() {
        let nibble = (value >> (index * 4)) & 0xf;
        out.push(char::from(LOWER_HEX[nibble as usize]));
    }
}

fn push_escaped(out: &mut String, c: char, quote: char) {
    if c == quote || c == '\\' {
        out.push('\\');
        out.push(c);
        return;
    }
    if is_printable(c) {
        out.push(c);
        return;
    }
    match c {
        '\u{7}' => out.push_str("\\a"),
        '\u{8}' => out.push_str("\\b"),
        '\u{c}' => out.push_str("\\f"),
        '\n' => out.push_str("\\n"),
        '\r' => out.push_str("\\r"),
        '\t' => out.push_str("\\t"),
        '\u{b}' => out.push_str("\\v"),
        _ => {
            let value = u32::from(c);
            if value < 0x20 || value == 0x7f {
                out.push_str("\\x");
                push_hex(out, value, 2);
            } else if value < 0x10000 {
                out.push_str("\\u");
                push_hex(out, value, 4);
            } else {
                out.push_str("\\U");
                push_hex(out, value, 8);
            }
        }
    }
}

fn hex_value(byte: u8) -> Option<u32> {
    match byte {
        b'0'..=b'9' => Some(u32::from(byte - b'0')),
        b'a'..=b'f' => Some(u32::from(byte - b'a') + 10),
        b'A'..=b'F' => Some(u32::from(byte - b'A') + 10),
        _ => None,
    }
}

/// The value of a quoted string of the HCL file (`raw` has the two double quotes). The escapes are `\a \b \f \n \r \t
/// \v \\ \"`, `\xHH` (one byte), `\NNN` (one byte in octal, 0 to 377), `\uHHHH` and `\UHHHHHHHH` (one character). A
/// byte that is not part of a UTF-8 character gives U+FFFD. Any other form gives `None`.
pub(super) fn unquote(raw: &[u8]) -> Option<Vec<u8>> {
    let inner = raw.strip_prefix(b"\"")?.strip_suffix(b"\"")?;
    if !inner.contains(&b'\\')
        && !inner.contains(&b'"')
        && !inner.contains(&b'\n')
        && let Ok(text) = std::str::from_utf8(inner)
    {
        return Some(text.as_bytes().to_vec());
    }
    let mut out = Vec::with_capacity(inner.len());
    let mut rest = inner;
    while let Some(&first) = rest.first() {
        if first == b'"' || first == b'\n' {
            return None;
        }
        if first >= 0x80 {
            let (c, width) = decode_char(rest);
            let mut buffer = [0u8; 4];
            out.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
            rest = rest.get(width..)?;
            continue;
        }
        if first != b'\\' {
            out.push(first);
            rest = rest.get(1..)?;
            continue;
        }
        let escape = *rest.get(1)?;
        rest = rest.get(2..)?;
        match escape {
            b'a' => out.push(0x07),
            b'b' => out.push(0x08),
            b'f' => out.push(0x0c),
            b'n' => out.push(b'\n'),
            b'r' => out.push(b'\r'),
            b't' => out.push(b'\t'),
            b'v' => out.push(0x0b),
            b'\\' => out.push(b'\\'),
            b'"' => out.push(b'"'),
            b'x' | b'u' | b'U' => {
                let digits = match escape {
                    b'x' => 2,
                    b'u' => 4,
                    _ => 8,
                };
                let mut value: u32 = 0;
                for index in 0..digits {
                    value = (value << 4) | hex_value(*rest.get(index)?)?;
                }
                rest = rest.get(digits..)?;
                if escape == b'x' {
                    out.push(u8::try_from(value).ok()?);
                } else {
                    let c = char::from_u32(value)?;
                    let mut buffer = [0u8; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
                }
            }
            b'0'..=b'7' => {
                let mut value = u32::from(escape - b'0');
                for index in 0..2 {
                    let digit = *rest.get(index)?;
                    if !(b'0'..=b'7').contains(&digit) {
                        return None;
                    }
                    value = (value << 3) | u32::from(digit - b'0');
                }
                rest = rest.get(2..)?;
                out.push(u8::try_from(value).ok()?);
            }
            _ => return None,
        }
    }
    Some(out)
}

/// The first character of bytes and its width. A byte that does not start a UTF-8 character gives U+FFFD and the
/// width 1.
fn decode_char(bytes: &[u8]) -> (char, usize) {
    let width = match bytes.first() {
        Some(0xc2..=0xdf) => 2,
        Some(0xe0..=0xef) => 3,
        Some(0xf0..=0xf4) => 4,
        _ => 1,
    };
    if let Some(part) = bytes.get(..width)
        && let Ok(text) = std::str::from_utf8(part)
        && let Some(c) = text.chars().next()
    {
        return (c, width);
    }
    (char::REPLACEMENT_CHARACTER, 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_escapes_the_quotes_the_controls_and_the_characters_that_are_not_printable() {
        assert_eq!(quote(""), "\"\"");
        assert_eq!(quote("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(quote("\u{7}\u{8}\u{c}\n\r\t\u{b}"), "\"\\a\\b\\f\\n\\r\\t\\v\"");
        assert_eq!(quote("\u{1}\u{7f}"), "\"\\x01\\x7f\"");
        assert_eq!(quote("é日本"), "\"é日本\"");
        assert_eq!(quote("\u{a0}\u{ad}\u{200b}"), "\"\\u00a0\\u00ad\\u200b\"");
        assert_eq!(quote("\u{85}"), "\"\\u0085\"");
        assert_eq!(quote("\u{e0000}"), "\"\\U000e0000\"");
        assert_eq!(quote("'"), "\"'\"");
    }

    #[test]
    fn quote_bytes_writes_each_byte_that_is_not_utf8_in_hexadecimal() {
        assert_eq!(quote_bytes(b"a\xc3"), "\"a\\xc3\"");
        assert_eq!(quote_bytes(b"\xe2\x82A"), "\"\\xe2\\x82A\"");
        assert_eq!(quote_bytes(b"\xed\xa0\x80"), "\"\\xed\\xa0\\x80\"");
    }

    #[test]
    fn quote_char_uses_single_quotes() {
        assert_eq!(quote_char(u32::from(b'-')), "'-'");
        assert_eq!(quote_char(u32::from(b'\'')), "'\\''");
        assert_eq!(quote_char(0), "'\\x00'");
        assert_eq!(quote_char(0xc3), "'Ã'");
        assert_eq!(quote_char(0x85), "'\\u0085'");
        assert_eq!(quote_char(u32::from(b'"')), "'\"'");
    }

    #[test]
    fn unquote_reads_each_escape() {
        let read = |raw: &str| unquote(raw.as_bytes());
        assert_eq!(read("\"A\\nB\""), Some(b"A\nB".to_vec()));
        assert_eq!(
            read("\"\\a\\b\\f\\r\\t\\v\\\\\\\"\""),
            Some(b"\x07\x08\x0c\r\t\x0b\\\"".to_vec())
        );
        assert_eq!(
            read("\"\\x41\\101\\u00e9\\U0001F600\""),
            Some("AAé😀".as_bytes().to_vec())
        );
        assert_eq!(read("\"\\xff\""), Some(vec![0xff]));
        assert_eq!(read("\"\\'\""), None);
        assert_eq!(read("\"\\q\""), None);
        assert_eq!(read("\"\\x4\""), None);
        assert_eq!(read("\"\\400\""), None);
        assert_eq!(read("\"\\18\""), None);
        assert_eq!(read("\"\\ud800\""), None);
        assert_eq!(read("\"\\U00110000\""), None);
        assert_eq!(read("\"plain\""), Some(b"plain".to_vec()));
    }

    #[test]
    fn unquote_replaces_each_byte_that_is_not_utf8() {
        assert_eq!(unquote(b"\"a\xffb\""), Some("a\u{fffd}b".as_bytes().to_vec()));
        assert_eq!(unquote(b"\"\\n\xc3\""), Some("\n\u{fffd}".as_bytes().to_vec()));
    }
}
