// SPDX-License-Identifier: MIT OR Apache-2.0
//! The JSON encoding of the answers.
//!
//! The answers keep one exact form, so that a client sees the same bytes for the same value:
//!
//! - the characters `<`, `>` and `&` are escaped as `\u003c`, `\u003e` and `\u0026`, so that the text is safe to put
//!   in an HTML page or in a `<script>` element. U+2028 and U+2029 are escaped as `\u2028` and `\u2029`, so that the
//!   text is also a valid JavaScript literal;
//! - a control character has the form `\u00XX`, except `\n`, `\r` and `\t`;
//! - a number with a fraction has the shortest form that reads back to the same value. The exponent form applies
//!   below 1e-6 and from 1e21 (`1e-7`, `1e+21`);
//! - the members of a map are in the order of their names (use `BTreeMap`, never `HashMap`);
//! - an answer body ends with one line end ([`to_body`]).

use std::io;

use serde::Serialize;
use serde_json::ser::{CharEscape, Formatter, Serializer};

use super::error::{Error, Result};

/// The formatter of the answers.
#[derive(Clone, Copy, Debug, Default)]
pub struct AnswerFormatter;

const HEX: &[u8; 16] = b"0123456789abcdef";

fn write_unicode_escape<W: ?Sized + io::Write>(writer: &mut W, code: u32) -> io::Result<()> {
    let bytes = [
        b'\\',
        b'u',
        HEX[((code >> 12) & 0xf) as usize],
        HEX[((code >> 8) & 0xf) as usize],
        HEX[((code >> 4) & 0xf) as usize],
        HEX[(code & 0xf) as usize],
    ];
    writer.write_all(&bytes)
}

impl Formatter for AnswerFormatter {
    fn write_string_fragment<W: ?Sized + io::Write>(&mut self, writer: &mut W, fragment: &str) -> io::Result<()> {
        let mut start = 0;
        for (index, character) in fragment.char_indices() {
            let escape = matches!(character, '<' | '>' | '&' | '\u{2028}' | '\u{2029}');
            if escape {
                writer.write_all(&fragment.as_bytes()[start..index])?;
                write_unicode_escape(writer, character as u32)?;
                start = index + character.len_utf8();
            }
        }
        writer.write_all(&fragment.as_bytes()[start..])
    }

    fn write_char_escape<W: ?Sized + io::Write>(&mut self, writer: &mut W, escape: CharEscape) -> io::Result<()> {
        match escape {
            CharEscape::Quote => writer.write_all(b"\\\""),
            CharEscape::ReverseSolidus => writer.write_all(b"\\\\"),
            CharEscape::LineFeed => writer.write_all(b"\\n"),
            CharEscape::CarriageReturn => writer.write_all(b"\\r"),
            CharEscape::Tab => writer.write_all(b"\\t"),
            CharEscape::Backspace => write_unicode_escape(writer, 0x08),
            CharEscape::FormFeed => write_unicode_escape(writer, 0x0c),
            CharEscape::AsciiControl(byte) => write_unicode_escape(writer, u32::from(byte)),
            _ => Ok(()),
        }
    }

    fn write_f64<W: ?Sized + io::Write>(&mut self, writer: &mut W, value: f64) -> io::Result<()> {
        writer.write_all(format_float(value).as_bytes())
    }

    fn write_f32<W: ?Sized + io::Write>(&mut self, writer: &mut W, value: f32) -> io::Result<()> {
        writer.write_all(format_float(f64::from(value)).as_bytes())
    }
}

/// The text of a number of an answer: the shortest decimal form, or the exponent form below 1e-6 and from 1e21.
pub fn format_float(value: f64) -> String {
    let magnitude = value.abs();
    if magnitude != 0.0 && !(1e-6..1e21).contains(&magnitude) {
        let text = format!("{value:e}");
        match text.split_once('e') {
            Some((mantissa, exponent)) if !exponent.starts_with('-') => format!("{mantissa}e+{exponent:0>2}"),
            _ => text,
        }
    } else {
        format!("{value}")
    }
}

/// The JSON bytes of a value, without a line end.
pub fn to_vec<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(256);
    let mut serializer = Serializer::with_formatter(&mut out, AnswerFormatter);
    value
        .serialize(&mut serializer)
        .map_err(|error| Error::internal(format!("encode JSON: {error}")))?;
    Ok(out)
}

/// The body of a JSON answer: the JSON bytes and one line end.
pub fn to_body<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
    let mut out = to_vec(value)?;
    out.push(b'\n');
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn html_characters_and_controls_have_the_unicode_form() {
        let text = to_vec(&"<a href=\"x\">&\u{8}\u{c}\u{1}\n\u{2028}</a>").unwrap();
        assert_eq!(
            String::from_utf8(text).unwrap(),
            r#""\u003ca href=\"x\"\u003e\u0026\u0008\u000c\u0001\n\u2028\u003c/a\u003e""#
        );
    }

    #[test]
    fn numbers_keep_the_form_of_the_answers() {
        assert_eq!(format_float(3.0), "3");
        assert_eq!(format_float(99.9), "99.9");
        assert_eq!(format_float(0.000_001), "0.000001");
        assert_eq!(format_float(1e-7), "1e-7");
        assert_eq!(format_float(1e21), "1e+21");
        assert_eq!(format_float(1.5e22), "1.5e+22");
        assert_eq!(format_float(1e20), "100000000000000000000");
    }

    #[test]
    fn maps_are_in_the_order_of_their_names_and_the_body_ends_with_a_line_end() {
        let mut map = BTreeMap::new();
        map.insert("b", 1);
        map.insert("a", 2);
        assert_eq!(to_body(&map).unwrap(), b"{\"a\":2,\"b\":1}\n");
    }
}
