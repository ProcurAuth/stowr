// SPDX-License-Identifier: MIT OR Apache-2.0
//! The forms of the values of the request log: a quoted text that no control character can break, and a duration in
//! milliseconds.

use std::fmt::Write as _;
use std::time::Duration;

/// The quoted form of bytes: `"` around the text, `\"` and `\\`, the usual escapes `\a \b \f \n \r \t \v`, `\xNN` for
/// a byte that is not valid UTF-8 or a control character below `U+0080`, and `\uNNNN` or `\UNNNNNNNN` for the other
/// characters that a log must not show.
pub fn quote(bytes: &[u8]) -> String {
    crate::config::quote::quote_bytes(bytes)
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
