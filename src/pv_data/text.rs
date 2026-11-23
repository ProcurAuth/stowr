//! The text forms of the data previews: the simple case maps, the replacement of invalid UTF-8, the quoted form of a
//! name in a message, the short form of a float and the strict readers of integer and float texts.
//!
//! The previews compare, search and sort the values in these forms, so each form is exact and the same in each
//! preview.

/// The lower case of a text, one character at a time. A character keeps its form when its lower case has more than
/// one character, except `İ`, which gives `i`.
pub(crate) fn lower(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        if character.is_ascii() {
            out.push(character.to_ascii_lowercase());
            continue;
        }
        if character == '\u{130}' {
            out.push('i');
            continue;
        }
        let mut mapped = character.to_lowercase();
        match (mapped.next(), mapped.next()) {
            (Some(single), None) => out.push(single),
            _ => out.push(character),
        }
    }
    out
}

/// The simple upper case of a Greek letter with a subscript iota, else `None`.
fn greek_iota_upper(character: char) -> Option<char> {
    let code = u32::from(character);
    let mapped = match code {
        0x1F80..=0x1F87 | 0x1F90..=0x1F97 | 0x1FA0..=0x1FA7 => code + 8,
        0x1FB3 | 0x1FC3 | 0x1FF3 => code + 9,
        _ => return None,
    };
    char::from_u32(mapped)
}

/// The upper case of a text, one character at a time. A character keeps its form when its upper case has more than
/// one character, except the Greek letters with a subscript iota, which have a simple upper case.
pub(crate) fn upper(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        if character.is_ascii() {
            out.push(character.to_ascii_uppercase());
            continue;
        }
        if let Some(mapped) = greek_iota_upper(character) {
            out.push(mapped);
            continue;
        }
        let mut mapped = character.to_uppercase();
        match (mapped.next(), mapped.next()) {
            (Some(single), None) => out.push(single),
            _ => out.push(character),
        }
    }
    out
}

/// The text of bytes with one `U+FFFD` for each byte that is not part of valid UTF-8.
pub(crate) fn lossy_each_byte(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid());
        for _ in chunk.invalid() {
            out.push('\u{FFFD}');
        }
    }
    out
}

/// The text of bytes with one `U+FFFD` for each run of bytes that are not valid UTF-8.
pub(crate) fn lossy_each_run(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut in_run = false;
    for chunk in bytes.utf8_chunks() {
        if !chunk.valid().is_empty() {
            out.push_str(chunk.valid());
            in_run = false;
        }
        if !chunk.invalid().is_empty() && !in_run {
            out.push('\u{FFFD}');
            in_run = true;
        }
    }
    out
}

/// True for a character that a quoted name shows as it is.
fn printable(character: char) -> bool {
    if character == ' ' {
        return true;
    }
    if character.is_control() || character.is_whitespace() {
        return false;
    }
    let code = u32::from(character);
    let format = matches!(
        code,
        0xAD | 0x600..=0x605
            | 0x61C
            | 0x6DD
            | 0x70F
            | 0x890..=0x891
            | 0x8E2
            | 0x180E
            | 0x200B..=0x200F
            | 0x202A..=0x202E
            | 0x2060..=0x2064
            | 0x2066..=0x206F
            | 0xFEFF
            | 0xFFF9..=0xFFFB
            | 0x110BD
            | 0x110CD
            | 0x13430..=0x1343F
            | 0x1BCA0..=0x1BCA3
            | 0x1D173..=0x1D17A
            | 0xE0001
            | 0xE0020..=0xE007F
    );
    let private = matches!(code, 0xE000..=0xF8FF | 0xF0000..=0xFFFFD | 0x100000..=0x10FFFD);
    let noncharacter = (0xFDD0..=0xFDEF).contains(&code) || code & 0xFFFE == 0xFFFE;
    !(format || private || noncharacter)
}

/// The quoted form of a name in a message: double quotes, `\"` and `\\`, the short escapes of the control
/// characters, `\xNN` for another ASCII control, `\uNNNN` or `\UNNNNNNNN` for another character that is not shown.
pub(crate) fn quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for character in text.chars() {
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
            other if u32::from(other) < 0x80 => out.push_str(&format!("\\x{:02x}", u32::from(other))),
            other if u32::from(other) < 0x10000 => out.push_str(&format!("\\u{:04x}", u32::from(other))),
            other => out.push_str(&format!("\\U{:08x}", u32::from(other))),
        }
    }
    out.push('"');
    out
}

/// The short text of a float: the shortest digits that read back to the same value, in the exponent form when the
/// exponent is below -4 or from 6 (`1.234567e+06`, `1e-05`), else in the plain form (`123456`, `0.0001`).
pub(crate) fn format_float_short(value: f64) -> String {
    if value.is_nan() {
        return "NaN".to_owned();
    }
    if value.is_infinite() {
        return if value > 0.0 { "+Inf" } else { "-Inf" }.to_owned();
    }
    let sign = if value.is_sign_negative() { "-" } else { "" };
    if value == 0.0 {
        return format!("{sign}0");
    }
    let scientific = format!("{:e}", value.abs());
    let (mantissa, exponent) = scientific.split_once('e').unwrap_or((scientific.as_str(), "0"));
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let exponent: i64 = exponent.parse().unwrap_or(0);
    if !(-4..6).contains(&exponent) {
        let mut out = String::from(sign);
        out.push_str(digits.get(..1).unwrap_or("0"));
        if digits.len() > 1 {
            out.push('.');
            out.push_str(digits.get(1..).unwrap_or(""));
        }
        out.push('e');
        out.push(if exponent < 0 { '-' } else { '+' });
        out.push_str(&format!("{:02}", exponent.unsigned_abs()));
        return out;
    }
    let mut out = String::from(sign);
    if exponent < 0 {
        out.push_str("0.");
        for _ in 0..(-exponent - 1) {
            out.push('0');
        }
        out.push_str(&digits);
        return out;
    }
    let integer_digits = (exponent + 1) as usize;
    if digits.len() <= integer_digits {
        out.push_str(&digits);
        for _ in digits.len()..integer_digits {
            out.push('0');
        }
    } else {
        out.push_str(digits.get(..integer_digits).unwrap_or(""));
        out.push('.');
        out.push_str(digits.get(integer_digits..).unwrap_or(""));
    }
    out
}

/// Read a base 10 integer: an optional sign and digits, nothing else. The flag is false for a text that is not an
/// integer (the value is 0) and for a value out of the range (the value is the nearest limit).
pub(crate) fn parse_int(text: &str) -> (i64, bool) {
    let (negative, digits) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return (0, false);
    }
    let mut magnitude: u64 = 0;
    let mut overflow = false;
    for byte in digits.bytes() {
        match magnitude
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(byte - b'0')))
        {
            Some(value) => magnitude = value,
            None => {
                overflow = true;
                break;
            }
        }
    }
    let limit = if negative { 1u64 << 63 } else { (1u64 << 63) - 1 };
    if overflow || magnitude > limit {
        return (if negative { i64::MIN } else { i64::MAX }, false);
    }
    if negative {
        (0i64.wrapping_sub_unsigned(magnitude), true)
    } else {
        (magnitude as i64, true)
    }
}

/// The integer of a float as a conversion of the processor gives it: the value rounded toward zero, or the lowest
/// integer for a value that is not a number or is out of the range.
pub(crate) fn float_to_int(value: f64) -> i64 {
    if value.is_nan() || value >= 9_223_372_036_854_775_808.0 || value < -9_223_372_036_854_775_808.0 {
        return i64::MIN;
    }
    value.trunc() as i64
}

/// The length of the common start of a text and a lower-case word, without regard to case.
fn common_prefix_ignore_case(text: &[u8], word: &[u8]) -> usize {
    text.iter()
        .zip(word)
        .take_while(|(left, right)| left.to_ascii_lowercase() == **right)
        .count()
}

/// The special values: an optional sign and `inf` or `infinity`, or `nan`, without regard to case.
fn special_float(text: &str) -> Option<f64> {
    let bytes = text.as_bytes();
    let (sign, rest, signed) = match bytes.first() {
        Some(b'+') => (1.0, &bytes[1..], true),
        Some(b'-') => (-1.0, &bytes[1..], true),
        _ => (1.0, bytes, false),
    };
    let infinity = common_prefix_ignore_case(rest, b"infinity");
    if (infinity == 3 || infinity == 8) && rest.len() == infinity {
        return Some(sign * f64::INFINITY);
    }
    if !signed && rest.len() == 3 && common_prefix_ignore_case(rest, b"nan") == 3 {
        return Some(f64::NAN);
    }
    None
}

/// True when the underscores of a number are each between two digits, or between a base prefix and a digit.
fn underscores_ok(text: &[u8]) -> bool {
    let mut saw = b'^';
    let mut index = 0;
    let text = match text.first() {
        Some(b'-' | b'+') => &text[1..],
        _ => text,
    };
    let mut hex = false;
    if text.len() >= 2 && text[0] == b'0' && matches!(text[1].to_ascii_lowercase(), b'b' | b'o' | b'x') {
        index = 2;
        saw = b'0';
        hex = text[1].eq_ignore_ascii_case(&b'x');
    }
    while index < text.len() {
        let byte = text[index];
        if byte.is_ascii_digit() || (hex && byte.is_ascii_hexdigit()) {
            saw = b'0';
        } else if byte == b'_' {
            if saw != b'0' {
                return false;
            }
            saw = b'_';
        } else {
            if saw == b'_' {
                return false;
            }
            saw = b'!';
        }
        index += 1;
    }
    saw != b'_'
}

/// The parts of a hexadecimal float: the mantissa, the binary exponent and the flag of the lost digits.
struct HexParts {
    mantissa: u64,
    exponent: i64,
    truncated: bool,
}

/// The float of a hexadecimal mantissa and a binary exponent, rounded to the nearest even value. `None` when the
/// value is out of the range.
fn hex_float(parts: HexParts, negative: bool) -> Option<f64> {
    const MANTISSA_BITS: u32 = 52;
    const EXPONENT_BITS: u32 = 11;
    const BIAS: i64 = -1023;
    let max_exponent = (1i64 << EXPONENT_BITS) + BIAS - 2;
    let min_exponent = BIAS + 1;
    let mut mantissa = parts.mantissa;
    let mut exponent = parts.exponent + i64::from(MANTISSA_BITS);
    while mantissa != 0 && mantissa >> (MANTISSA_BITS + 2) == 0 {
        mantissa <<= 1;
        exponent -= 1;
    }
    if parts.truncated {
        mantissa |= 1;
    }
    while mantissa >> (1 + MANTISSA_BITS + 2) != 0 {
        mantissa = (mantissa >> 1) | (mantissa & 1);
        exponent += 1;
    }
    while mantissa > 1 && exponent < min_exponent - 2 {
        mantissa = (mantissa >> 1) | (mantissa & 1);
        exponent += 1;
    }
    let mut round = mantissa & 3;
    mantissa >>= 2;
    round |= mantissa & 1;
    exponent += 2;
    if round == 3 {
        mantissa += 1;
        if mantissa == 1 << (1 + MANTISSA_BITS) {
            mantissa >>= 1;
            exponent += 1;
        }
    }
    if mantissa >> MANTISSA_BITS == 0 {
        exponent = BIAS;
    }
    if exponent > max_exponent {
        return None;
    }
    let mut bits = mantissa & ((1 << MANTISSA_BITS) - 1);
    bits |= (((exponent - BIAS) as u64) & ((1 << EXPONENT_BITS) - 1)) << MANTISSA_BITS;
    if negative {
        bits |= 1 << (MANTISSA_BITS + EXPONENT_BITS);
    }
    Some(f64::from_bits(bits))
}

/// Read a float: decimal (`1.5`, `.5`, `5.`, `1e3`, `1_000`) or hexadecimal with a binary exponent (`0x1.8p1`), or
/// a special value (`inf`, `-Infinity`, `NaN`). `None` for another text, for a text with spaces and for a value out of
/// the range.
pub(crate) fn parse_float(text: &str) -> Option<f64> {
    if let Some(value) = special_float(text) {
        return Some(value);
    }
    let bytes = text.as_bytes();
    let mut index = 0;
    let mut negative = false;
    if let Some(sign @ (b'+' | b'-')) = bytes.first() {
        negative = *sign == b'-';
        index = 1;
    }
    let mut hex = false;
    if index + 2 < bytes.len() && bytes[index] == b'0' && bytes[index + 1].eq_ignore_ascii_case(&b'x') {
        hex = true;
        index += 2;
    }
    let base: u64 = if hex { 16 } else { 10 };
    let max_digits = if hex { 16 } else { 19 };
    let mut underscores = false;
    let mut saw_dot = false;
    let mut saw_digits = false;
    let mut digits: i64 = 0;
    let mut mantissa_digits: i64 = 0;
    let mut decimal_point: i64 = 0;
    let mut mantissa: u64 = 0;
    let mut truncated = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'_' {
            underscores = true;
        } else if byte == b'.' {
            if saw_dot {
                break;
            }
            saw_dot = true;
            decimal_point = digits;
        } else if byte.is_ascii_digit() || (hex && byte.is_ascii_hexdigit()) {
            saw_digits = true;
            if byte == b'0' && digits == 0 {
                decimal_point -= 1;
            } else {
                digits += 1;
                let digit = u64::from((byte as char).to_digit(16).unwrap_or(0));
                if mantissa_digits < max_digits {
                    mantissa = mantissa.wrapping_mul(base).wrapping_add(digit);
                    mantissa_digits += 1;
                } else if byte != b'0' {
                    truncated = true;
                }
            }
        } else {
            break;
        }
        index += 1;
    }
    if !saw_digits {
        return None;
    }
    if !saw_dot {
        decimal_point = digits;
    }
    if hex {
        decimal_point *= 4;
        mantissa_digits *= 4;
    }
    let exponent_char = if hex { b'p' } else { b'e' };
    let mut exponent_value: i64 = 0;
    if index < bytes.len() && bytes[index].to_ascii_lowercase() == exponent_char {
        index += 1;
        if index >= bytes.len() {
            return None;
        }
        let mut exponent_sign = 1;
        if bytes[index] == b'+' {
            index += 1;
        } else if bytes[index] == b'-' {
            index += 1;
            exponent_sign = -1;
        }
        if index >= bytes.len() || !bytes[index].is_ascii_digit() {
            return None;
        }
        let mut exponent: i64 = 0;
        while index < bytes.len() && (bytes[index].is_ascii_digit() || bytes[index] == b'_') {
            if bytes[index] == b'_' {
                underscores = true;
            } else if exponent < 10_000 {
                exponent = exponent * 10 + i64::from(bytes[index] - b'0');
            }
            index += 1;
        }
        exponent_value = exponent * exponent_sign;
    } else if hex {
        return None;
    }
    if underscores && !underscores_ok(&bytes[..index]) {
        return None;
    }
    if index != bytes.len() {
        return None;
    }
    if hex {
        let binary_exponent = if mantissa != 0 {
            decimal_point + exponent_value - mantissa_digits
        } else {
            0
        };
        return hex_float(
            HexParts {
                mantissa,
                exponent: binary_exponent,
                truncated,
            },
            negative,
        );
    }
    let cleaned: String = text.chars().filter(|character| *character != '_').collect();
    match cleaned.parse::<f64>() {
        Ok(value) if value.is_finite() => Some(value),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_case_maps_change_one_character_at_a_time() {
        assert_eq!(upper("ıſßᾀᾈﬀǅ"), "ISßᾈᾈﬀǄ");
        assert_eq!(lower("İǅΣ"), "iǆσ");
        assert_eq!(lower("ΣΑΣ"), "σασ");
        assert_eq!(upper("create table"), "CREATE TABLE");
    }

    #[test]
    fn invalid_bytes_become_replacement_characters() {
        assert_eq!(lossy_each_byte(b"a\xf0\x9f\x98b"), "a\u{FFFD}\u{FFFD}\u{FFFD}b");
        assert_eq!(lossy_each_run(b"a\xf0\x9f\x98\xffb\xffc"), "a\u{FFFD}b\u{FFFD}c");
        assert_eq!(lossy_each_run("été".as_bytes()), "été");
    }

    #[test]
    fn quoted_names_escape_what_they_do_not_show() {
        assert_eq!(
            quote("a\"b\\c\u{200b}\u{1}é\u{ad}\u{e000} \u{a0}\u{2028}"),
            "\"a\\\"b\\\\c\\u200b\\x01é\\u00ad\\ue000 \\u00a0\\u2028\""
        );
    }

    #[test]
    fn short_floats_use_the_exponent_form_outside_the_plain_range() {
        let cases = [
            (1_234_567.0, "1.234567e+06"),
            (123_456.0, "123456"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (1.5, "1.5"),
            (100.0, "100"),
            (1e21, "1e+21"),
            (1e20, "1e+20"),
            (3.0, "3"),
            (-0.0, "-0"),
            (1.0 / 3.0, "0.3333333333333333"),
            (-2.5e-7, "-2.5e-07"),
            (1e100, "1e+100"),
        ];
        for (value, want) in cases {
            assert_eq!(format_float_short(value), want, "{value}");
        }
        assert_eq!(format_float_short(f64::INFINITY), "+Inf");
        assert_eq!(format_float_short(f64::NAN), "NaN");
    }

    #[test]
    fn integers_have_a_sign_and_digits_only() {
        assert_eq!(parse_int("+5"), (5, true));
        assert_eq!(parse_int("-12"), (-12, true));
        assert_eq!(parse_int(" 1"), (0, false));
        assert_eq!(parse_int("99999999999999999999"), (i64::MAX, false));
        assert_eq!(parse_int("-9223372036854775808"), (i64::MIN, true));
        assert_eq!(parse_int("-99999999999999999999"), (i64::MIN, false));
        assert_eq!(parse_int(""), (0, false));
    }

    #[test]
    fn floats_follow_the_strict_grammar() {
        let accepted = [
            ("1_000", 1000.0),
            ("1_23.50_0_0e+1_2", 1.235e14),
            ("0x1p4", 16.0),
            ("0x1.8p1", 3.0),
            ("1e-400", 0.0),
            ("+inf", f64::INFINITY),
            ("-Infinity", f64::NEG_INFINITY),
            (".5", 0.5),
            ("5.", 5.0),
            ("1.e3", 1000.0),
            ("0x_1p0", 1.0),
            ("-0x1p-2", -0.25),
        ];
        for (text, want) in accepted {
            assert_eq!(parse_float(text), Some(want), "{text}");
        }
        assert!(parse_float("nan").is_some_and(f64::is_nan));
        for text in [
            "_1", "1__0", "0x10", "1e400", "+nan", "1,5", " 1", "", ".", "e5", "1e", "inff", "0x",
        ] {
            assert_eq!(parse_float(text), None, "{text}");
        }
    }

    #[test]
    fn float_conversions_to_integers_round_toward_zero() {
        assert_eq!(float_to_int(2.9), 2);
        assert_eq!(float_to_int(-2.9), -2);
        assert_eq!(float_to_int(1e30), i64::MIN);
        assert_eq!(float_to_int(f64::NAN), i64::MIN);
    }
}
