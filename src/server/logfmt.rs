//! The forms of the values of the request log: a quoted text that no control character can break, and a duration in
//! milliseconds.

use std::fmt::Write as _;
use std::time::Duration;

/// True for a character that the quoted form shows as it is.
fn printable(character: char) -> bool {
    if character == ' ' {
        return true;
    }
    if character.is_control() || character.is_whitespace() {
        return false;
    }
    let code = u32::from(character);
    // The format characters, the private use areas and the special characters of Unicode.
    !matches!(
        code,
        0x00AD
            | 0x0600..=0x0605
            | 0x061C
            | 0x06DD
            | 0x070F
            | 0x180E
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x206F
            | 0xE000..=0xF8FF
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0xFFFE..=0xFFFF
            | 0xF0000..=0x10FFFF
    )
}

/// The quoted form of bytes: `"` around the text, `\"` and `\\`, the usual escapes `\a \b \f \n \r \t \v`, `\xNN` for
/// a byte that is not valid UTF-8 or a control character below `U+0080`, and `\uNNNN` or `\UNNNNNNNN` for the other
/// characters that a log must not show.
pub fn quote(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() + 2);
    out.push('"');
    let mut rest = bytes;
    while !rest.is_empty() {
        let (valid, invalid) = match std::str::from_utf8(rest) {
            Ok(text) => (text, &[][..]),
            Err(error) => {
                let (head, tail) = rest.split_at(error.valid_up_to());
                (std::str::from_utf8(head).unwrap_or(""), tail)
            }
        };
        for character in valid.chars() {
            match character {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\u{7}' => out.push_str("\\a"),
                '\u{8}' => out.push_str("\\b"),
                '\u{c}' => out.push_str("\\f"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                '\u{b}' => out.push_str("\\v"),
                other if printable(other) => out.push(other),
                other if u32::from(other) < 0x20 || other == '\u{7f}' => {
                    let _ = write!(out, "\\x{:02x}", u32::from(other));
                }
                other if u32::from(other) < 0x10000 => {
                    let _ = write!(out, "\\u{:04x}", u32::from(other));
                }
                other => {
                    let _ = write!(out, "\\U{:08x}", u32::from(other));
                }
            }
        }
        match invalid.first() {
            Some(byte) => {
                let _ = write!(out, "\\x{byte:02x}");
                rest = &invalid[1..];
            }
            None => rest = &[],
        }
    }
    out.push('"');
    out
}

/// A duration rounded to the millisecond: `0s`, `12ms`, `1.5s`, `2m3.004s`, `1h0m0s`.
pub fn duration_ms(elapsed: Duration) -> String {
    let nanos = elapsed.as_nanos();
    let millis = (nanos + 500_000) / 1_000_000;
    if millis == 0 {
        return "0s".to_owned();
    }
    if millis < 1000 {
        return format!("{millis}ms");
    }
    let seconds = millis / 1000;
    let fraction = millis % 1000;
    let mut out = String::new();
    let hours = seconds / 3600;
    let minutes = (seconds / 60) % 60;
    if hours > 0 {
        let _ = write!(out, "{hours}h{minutes}m");
    } else if minutes > 0 {
        let _ = write!(out, "{minutes}m");
    }
    let _ = write!(out, "{}", seconds % 60);
    if fraction > 0 {
        let digits = format!("{fraction:03}");
        out.push('.');
        out.push_str(digits.trim_end_matches('0'));
    }
    out.push('s');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_quoted_form_escapes_control_characters() {
        assert_eq!(quote(b"/healthz\nGET /forged 200"), "\"/healthz\\nGET /forged 200\"");
        assert_eq!(quote(b"/a\x1b[31m"), "\"/a\\x1b[31m\"");
        assert_eq!(quote(b"/\xff\"x"), "\"/\\xff\\\"x\"");
        assert_eq!(quote("/é\u{2028}".as_bytes()), "\"/é\\u2028\"");
    }

    #[test]
    fn durations_have_the_millisecond_form() {
        assert_eq!(duration_ms(Duration::from_micros(400)), "0s");
        assert_eq!(duration_ms(Duration::from_micros(600)), "1ms");
        assert_eq!(duration_ms(Duration::from_millis(999)), "999ms");
        assert_eq!(duration_ms(Duration::from_millis(1500)), "1.5s");
        assert_eq!(duration_ms(Duration::from_millis(123_004)), "2m3.004s");
        assert_eq!(duration_ms(Duration::from_secs(3600)), "1h0m0s");
    }
}
