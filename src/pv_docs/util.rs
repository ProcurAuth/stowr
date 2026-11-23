//! Small text helpers of the previews: UTF-8 decoding with the rules of a byte stream, truncation on a character
//! border, simple lower case, the number syntax of the previews, the stable sort of the previews and the quoted form
//! of a name in a message.

/// The replacement character.
pub const REPLACEMENT: char = '\u{FFFD}';

/// The first byte of a multi-byte sequence: the width of the sequence, or 0 for a byte that cannot start one.
fn sequence_width(first: u8) -> usize {
    match first {
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        _ => 0,
    }
}

/// The range that the second byte of a sequence must be in.
fn second_byte_range(first: u8) -> (u8, u8) {
    match first {
        0xE0 => (0xA0, 0xBF),
        0xED => (0x80, 0x9F),
        0xF0 => (0x90, 0xBF),
        0xF4 => (0x80, 0x8F),
        _ => (0x80, 0xBF),
    }
}

/// True when the bytes start with a complete sequence, or with a sequence that cannot be completed: the decoder
/// then gives one replacement character for one byte. False when more bytes are needed.
pub fn full_rune(bytes: &[u8]) -> bool {
    let Some(&first) = bytes.first() else {
        return false;
    };
    if first < 0x80 {
        return true;
    }
    let width = sequence_width(first);
    if width == 0 || bytes.len() >= width {
        return true;
    }
    let (low, high) = second_byte_range(first);
    if bytes.len() > 1 && (bytes[1] < low || bytes[1] > high) {
        return true;
    }
    bytes.len() > 2 && !(0x80..=0xBF).contains(&bytes[2])
}

/// Decode the first character of the bytes. A byte that does not start a valid sequence gives the replacement
/// character and the width 1. Empty bytes give the width 0.
pub fn decode_rune(bytes: &[u8]) -> (char, usize) {
    let Some(&first) = bytes.first() else {
        return (REPLACEMENT, 0);
    };
    if first < 0x80 {
        return (char::from(first), 1);
    }
    let width = sequence_width(first);
    if width == 0 || bytes.len() < width {
        return (REPLACEMENT, 1);
    }
    match std::str::from_utf8(&bytes[..width]) {
        Ok(text) => (text.chars().next().unwrap_or(REPLACEMENT), width),
        Err(_) => (REPLACEMENT, 1),
    }
}

/// The text of bytes: each byte that is not part of a valid sequence becomes one replacement character.
pub fn lossy_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut rest = bytes;
    loop {
        match std::str::from_utf8(rest) {
            Ok(text) => {
                out.push_str(text);
                return out;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                if let Ok(text) = std::str::from_utf8(&rest[..valid]) {
                    out.push_str(text);
                }
                let invalid = error.error_len().unwrap_or(rest.len() - valid);
                for _ in 0..invalid {
                    out.push(REPLACEMENT);
                }
                rest = &rest[valid + invalid..];
            }
        }
    }
}

/// The text of bytes: each run of bytes that is not valid UTF-8 becomes one replacement character.
pub fn to_valid_utf8(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut rest = bytes;
    loop {
        match std::str::from_utf8(rest) {
            Ok(text) => {
                out.push_str(text);
                return out;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                if let Ok(text) = std::str::from_utf8(&rest[..valid]) {
                    out.push_str(text);
                }
                out.push(REPLACEMENT);
                let mut skip = valid + error.error_len().unwrap_or(rest.len() - valid);
                // The bytes that follow and are not valid belong to the same run.
                while skip < rest.len() {
                    match std::str::from_utf8(&rest[skip..]) {
                        Ok(_) => break,
                        Err(next) if next.valid_up_to() == 0 => {
                            skip += next.error_len().unwrap_or(rest.len() - skip);
                        }
                        Err(_) => break,
                    }
                }
                rest = &rest[skip..];
            }
        }
    }
}

/// The text up to `limit` bytes, cut on the border of a character.
pub fn truncate_utf8_bytes(value: &str, limit: usize) -> &str {
    if limit == 0 || value.is_empty() {
        return "";
    }
    if value.len() <= limit {
        return value;
    }
    let mut end = limit;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

/// The lower case of one character with the simple mapping: one character for one character.
pub fn lower_char(value: char) -> char {
    if value.is_ascii() {
        return value.to_ascii_lowercase();
    }
    value.to_lowercase().next().unwrap_or(value)
}

/// The lower case of a text, character by character, with no rule of context.
pub fn lower(value: &str) -> String {
    if value.is_ascii() {
        return value.to_ascii_lowercase();
    }
    value.chars().map(lower_char).collect()
}

/// The lower case of bytes, character by character. A byte that is not valid UTF-8 becomes the replacement
/// character. The result can be longer or shorter than the bytes.
pub fn lower_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.is_ascii() {
        return bytes.to_ascii_lowercase();
    }
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    let mut buffer = [0u8; 4];
    while index < bytes.len() {
        let (value, width) = decode_rune(&bytes[index..]);
        index += width.max(1);
        out.extend_from_slice(lower_char(value).encode_utf8(&mut buffer).as_bytes());
    }
    out
}

/// The position of the first copy of `needle` in `haystack`.
pub fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    if needle.len() > haystack.len() {
        return None;
    }
    let first = needle[0];
    let last_start = haystack.len() - needle.len();
    let mut index = 0;
    while index <= last_start {
        let offset = haystack[index..=last_start].iter().position(|byte| *byte == first)?;
        index += offset;
        if &haystack[index..index + needle.len()] == needle {
            return Some(index);
        }
        index += 1;
    }
    None
}

/// The whole number of a text: an optional sign and the decimal digits. A value above the range gives the limit
/// of the range with `false`.
pub fn parse_integer(text: &str) -> (i64, bool) {
    let bytes = text.as_bytes();
    let (negative, digits) = match bytes.first() {
        Some(b'-') => (true, &bytes[1..]),
        Some(b'+') => (false, &bytes[1..]),
        _ => (false, bytes),
    };
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return (0, false);
    }
    let mut value: i128 = 0;
    for digit in digits {
        value = value * 10 + i128::from(digit - b'0');
        if value > i128::from(i64::MAX) + 2 {
            value = i128::from(i64::MAX) + 2;
        }
    }
    if negative {
        let signed = -value;
        if signed < i128::from(i64::MIN) {
            return (i64::MIN, false);
        }
        return (i64::try_from(signed).unwrap_or(i64::MIN), true);
    }
    match i64::try_from(value) {
        Ok(value) => (value, true),
        Err(_) => (i64::MAX, false),
    }
}

/// The whole number of a text, or `None` when the text is not a number or is out of range.
pub fn parse_i64(text: &str) -> Option<i64> {
    match parse_integer(text) {
        (value, true) => Some(value),
        _ => None,
    }
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
pub fn parse_float(text: &str) -> Option<f64> {
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

/// Sort a slice and keep the order of the equal items: insertion sorts of 20 items, then in-place merges with
/// rotations. The result depends only on `less`, also when `less` is not a consistent order.
pub fn stable_sort<T>(items: &mut [T], mut less: impl FnMut(&T, &T) -> bool) {
    let count = items.len();
    let mut block = 20;
    let mut start = 0;
    let mut end = block;
    while end <= count {
        insertion_sort(items, start, end, &mut less);
        start = end;
        end += block;
    }
    insertion_sort(items, start, count, &mut less);
    while block < count {
        start = 0;
        end = 2 * block;
        while end <= count {
            sym_merge(items, start, start + block, end, &mut less);
            start = end;
            end += 2 * block;
        }
        let middle = start + block;
        if middle < count {
            sym_merge(items, start, middle, count, &mut less);
        }
        block *= 2;
    }
}

fn insertion_sort<T>(items: &mut [T], start: usize, end: usize, less: &mut impl FnMut(&T, &T) -> bool) {
    for index in start + 1..end {
        let mut current = index;
        while current > start && less(&items[current], &items[current - 1]) {
            items.swap(current, current - 1);
            current -= 1;
        }
    }
}

fn sym_merge<T>(items: &mut [T], a: usize, m: usize, b: usize, less: &mut impl FnMut(&T, &T) -> bool) {
    if m - a == 1 {
        let mut i = m;
        let mut j = b;
        while i < j {
            let h = (i + j) / 2;
            if less(&items[h], &items[a]) {
                i = h + 1;
            } else {
                j = h;
            }
        }
        let mut k = a;
        while k + 1 < i {
            items.swap(k, k + 1);
            k += 1;
        }
        return;
    }
    if b - m == 1 {
        let mut i = a;
        let mut j = m;
        while i < j {
            let h = (i + j) / 2;
            if !less(&items[m], &items[h]) {
                i = h + 1;
            } else {
                j = h;
            }
        }
        let mut k = m;
        while k > i {
            items.swap(k, k - 1);
            k -= 1;
        }
        return;
    }
    let middle = (a + b) / 2;
    let n = middle + m;
    let (mut start, mut r) = if m > middle { (n - b, middle) } else { (a, m) };
    let p = n - 1;
    while start < r {
        let c = (start + r) / 2;
        if !less(&items[p - c], &items[c]) {
            start = c + 1;
        } else {
            r = c;
        }
    }
    let end = n - start;
    if start < m && m < end {
        rotate(items, start, m, end);
    }
    if a < start && start < middle {
        sym_merge(items, a, start, middle, less);
    }
    if middle < end && end < b {
        sym_merge(items, middle, end, b, less);
    }
}

fn rotate<T>(items: &mut [T], a: usize, m: usize, b: usize) {
    let mut i = m - a;
    let mut j = b - m;
    while i != j {
        if i > j {
            swap_range(items, m - i, m, j);
            i -= j;
        } else {
            swap_range(items, m - i, m + j - i, i);
            j -= i;
        }
    }
    swap_range(items, m - i, m, i);
}

fn swap_range<T>(items: &mut [T], a: usize, b: usize, count: usize) {
    for index in 0..count {
        items.swap(a + index, b + index);
    }
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
pub fn quote(text: &str) -> String {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stable_sort_keeps_the_order_of_equal_values() {
        let mut state = 12345u64;
        for length in [0usize, 1, 2, 19, 20, 21, 40, 41, 157, 1000] {
            let mut data: Vec<(u32, usize)> = (0..length)
                .map(|index| {
                    state = state
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    (u32::try_from((state >> 33) % 7).unwrap(), index)
                })
                .collect();
            let mut expected = data.clone();
            expected.sort_by_key(|item| item.0);
            stable_sort(&mut data, |left: &(u32, usize), right: &(u32, usize)| left.0 < right.0);
            assert_eq!(data, expected, "length {length}");
        }
    }

    #[test]
    fn invalid_bytes_become_replacement_characters() {
        assert_eq!(lossy_bytes(b"a\xE2\x82b"), "a\u{FFFD}\u{FFFD}b");
        assert_eq!(to_valid_utf8(b"a\xE2\x82b\xFF\xFFc"), "a\u{FFFD}b\u{FFFD}c");
        assert_eq!(to_valid_utf8(b"ok"), "ok");
        assert_eq!(to_valid_utf8(b"\xFF"), "\u{FFFD}");
    }

    #[test]
    fn a_rune_decodes_with_its_width() {
        assert_eq!(decode_rune("é".as_bytes()), ('é', 2));
        assert_eq!(decode_rune(&[0xE2, 0x82]), (REPLACEMENT, 1));
        assert_eq!(decode_rune(&[0xFF]), (REPLACEMENT, 1));
        assert_eq!(decode_rune(&[]), (REPLACEMENT, 0));
        assert!(!full_rune(&[0xE2, 0x82]));
        assert!(full_rune(&[0xE2, 0x41]));
        assert!(full_rune(&[0xFF]));
    }

    #[test]
    fn a_cut_stays_on_a_character_border() {
        assert_eq!(truncate_utf8_bytes("aé", 2), "a");
        assert_eq!(truncate_utf8_bytes("aé", 3), "aé");
        assert_eq!(truncate_utf8_bytes("abc", 0), "");
    }

    #[test]
    fn the_lower_case_has_no_rule_of_context() {
        assert_eq!(lower("ΑΣ"), "ασ");
        assert_eq!(lower("ABC"), "abc");
        assert_eq!(lower_bytes(b"A\xFFB"), "a\u{FFFD}b".as_bytes());
    }

    #[test]
    fn numbers_follow_the_syntax_of_the_previews() {
        for valid in [
            "0",
            "-1",
            "+1.5",
            ".5",
            "5.",
            "1e5",
            "1E-5",
            "inf",
            "-Infinity",
            "NaN",
            "1_000",
            "0x1p-2",
            "0x1.8p3",
        ] {
            assert!(parse_float(valid).is_some(), "{valid}");
        }
        for invalid in [
            "", "abc", "1e", "e5", "+nan", "1__0", "_1", "1_", "0x1", "1e999", "infx", "1.2.3", "--1", "0x", "1 ",
        ] {
            assert!(parse_float(invalid).is_none(), "{invalid}");
        }
        assert_eq!(parse_float("0x1.8p3"), Some(12.0));
        assert_eq!(parse_float("1_0.5"), Some(10.5));
    }

    #[test]
    fn whole_numbers_saturate_out_of_range() {
        assert_eq!(parse_integer("42"), (42, true));
        assert_eq!(parse_integer("+7"), (7, true));
        assert_eq!(parse_integer("-7"), (-7, true));
        assert_eq!(parse_integer("x"), (0, false));
        assert_eq!(parse_integer("99999999999999999999"), (i64::MAX, false));
        assert_eq!(parse_integer("-99999999999999999999"), (i64::MIN, false));
        assert_eq!(parse_i64(""), None);
    }

    #[test]
    fn the_search_of_bytes_finds_the_first_copy() {
        assert_eq!(find_bytes(b"abcabc", b"ca"), Some(2));
        assert_eq!(find_bytes(b"abc", b"d"), None);
        assert_eq!(find_bytes(b"ab", b"abc"), None);
        assert_eq!(find_bytes(b"aab", b"ab"), Some(1));
    }

    #[test]
    fn quoted_names_escape_what_they_do_not_show() {
        assert_eq!(
            quote("a\"b\\c\u{200b}\u{1}é\u{ad}\u{e000} \u{a0}\u{2028}"),
            "\"a\\\"b\\\\c\\u200b\\x01é\\u00ad\\ue000 \\u00a0\\u2028\""
        );
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
    fn the_stable_sort_keeps_the_order_of_equal_items() {
        let mut items: Vec<(u32, usize)> = (0..500).map(|index| ((index * 7919 % 13) as u32, index)).collect();
        stable_sort(&mut items, |left, right| left.0 < right.0);
        for pair in items.windows(2) {
            assert!(pair[0].0 < pair[1].0 || (pair[0].0 == pair[1].0 && pair[0].1 < pair[1].1));
        }
        let mut cyclic = vec!["9", "1e1", "1f", "9", "1e1", "1f"];
        stable_sort(&mut cyclic, |left, right| {
            crate::pv_docs::compare::compare_values(left, right).is_lt()
        });
        assert_eq!(cyclic.len(), 6);
    }

    #[test]
    fn integers_have_a_sign_and_digits_only() {
        assert_eq!(parse_integer("+5"), (5, true));
        assert_eq!(parse_integer("-12"), (-12, true));
        assert_eq!(parse_integer(" 1"), (0, false));
        assert_eq!(parse_integer("99999999999999999999"), (i64::MAX, false));
        assert_eq!(parse_integer("-9223372036854775808"), (i64::MIN, true));
        assert_eq!(parse_integer("-99999999999999999999"), (i64::MIN, false));
        assert_eq!(parse_integer(""), (0, false));
    }

    #[test]
    fn each_invalid_byte_or_each_invalid_run_becomes_one_replacement_character() {
        assert_eq!(lossy_bytes(b"a\xf0\x9f\x98b"), "a\u{FFFD}\u{FFFD}\u{FFFD}b");
        assert_eq!(to_valid_utf8(b"a\xf0\x9f\x98\xffb\xffc"), "a\u{FFFD}b\u{FFFD}c");
        assert_eq!(to_valid_utf8("été".as_bytes()), "été");
    }
}
