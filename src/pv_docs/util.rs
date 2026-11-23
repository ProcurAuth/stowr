//! Small text helpers of the previews: UTF-8 decoding with the rules of a byte stream, truncation on a character
//! border, simple lower case, and the number syntax of the previews.

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

/// Underscores in a number: each one is between two digits, or between the prefix of the base and a digit.
fn underscores_valid(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;
    if matches!(bytes.first(), Some(b'+' | b'-')) {
        index = 1;
    }
    let mut saw = b'^';
    let mut hex = false;
    if bytes.len() >= index + 2
        && bytes[index] == b'0'
        && matches!(bytes[index + 1].to_ascii_lowercase(), b'b' | b'o' | b'x')
    {
        saw = b'0';
        hex = bytes[index + 1].eq_ignore_ascii_case(&b'x');
        index += 2;
    }
    while index < bytes.len() {
        let current = bytes[index];
        index += 1;
        if current.is_ascii_digit() || (hex && matches!(current.to_ascii_lowercase(), b'a'..=b'f')) {
            saw = b'0';
            continue;
        }
        if current == b'_' {
            if saw != b'0' {
                return false;
            }
            saw = b'_';
            continue;
        }
        if saw == b'_' {
            return false;
        }
        saw = b'!';
    }
    saw != b'_'
}

/// A number with a base of 16: `0x`, digits with an optional point, and the exponent `p` (it is not optional).
fn parse_hex_float(text: &str) -> Option<f64> {
    let (negative, rest) = match text.as_bytes().first() {
        Some(b'-') => (true, &text[1..]),
        Some(b'+') => (false, &text[1..]),
        _ => (false, text),
    };
    let rest = rest.get(2..)?;
    let mut mantissa = 0f64;
    let mut exponent: i64 = 0;
    let mut saw_digit = false;
    let mut saw_point = false;
    let mut index = 0;
    let bytes = rest.as_bytes();
    while index < bytes.len() {
        let current = bytes[index];
        match current {
            b'_' => {}
            b'.' => {
                if saw_point {
                    break;
                }
                saw_point = true;
            }
            _ => {
                let Some(digit) = char::from(current).to_digit(16) else {
                    break;
                };
                saw_digit = true;
                mantissa = mantissa * 16.0 + f64::from(digit);
                if saw_point {
                    exponent -= 4;
                }
            }
        }
        index += 1;
    }
    if !saw_digit || index >= bytes.len() || !bytes[index].eq_ignore_ascii_case(&b'p') {
        return None;
    }
    index += 1;
    let mut exponent_negative = false;
    match bytes.get(index) {
        Some(b'+') => index += 1,
        Some(b'-') => {
            exponent_negative = true;
            index += 1;
        }
        _ => {}
    }
    if !bytes.get(index).is_some_and(u8::is_ascii_digit) {
        return None;
    }
    let mut written: i64 = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'_' => {}
            digit if digit.is_ascii_digit() => {
                if written < 10_000 {
                    written = written * 10 + i64::from(digit - b'0');
                }
            }
            _ => return None,
        }
        index += 1;
    }
    exponent += if exponent_negative { -written } else { written };
    let exponent = i32::try_from(exponent.clamp(-5000, 5000)).unwrap_or(0);
    let value = mantissa * 2f64.powi(exponent);
    if value.is_infinite() {
        return None;
    }
    Some(if negative { -value } else { value })
}

/// The number of a text with the syntax of the previews: an optional sign, decimal digits with a point and an
/// exponent, the forms `inf`, `infinity` and `nan` in any case, hexadecimal numbers with the exponent `p`, and
/// underscores between digits. A value out of the range of a 64-bit float is not a number.
pub fn parse_float(text: &str) -> Option<f64> {
    if text.is_empty() {
        return None;
    }
    let lowered = text.to_ascii_lowercase();
    let unsigned = lowered.strip_prefix(['+', '-']).unwrap_or(&lowered);
    let negative = lowered.starts_with('-');
    if matches!(unsigned, "inf" | "infinity") {
        return Some(if negative { f64::NEG_INFINITY } else { f64::INFINITY });
    }
    if lowered == "nan" {
        return Some(f64::NAN);
    }
    let bytes = lowered.as_bytes();
    let has_underscore = bytes.contains(&b'_');
    if has_underscore && !underscores_valid(&lowered) {
        return None;
    }
    let offset = usize::from(matches!(bytes.first(), Some(b'+' | b'-')));
    if bytes.len() >= offset + 3 && bytes[offset] == b'0' && bytes[offset + 1] == b'x' {
        return parse_hex_float(&lowered);
    }
    if !bytes
        .iter()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'.' | b'e' | b'+' | b'-' | b'_'))
    {
        return None;
    }
    let cleaned: String = lowered.chars().filter(|current| *current != '_').collect();
    let value = cleaned.parse::<f64>().ok()?;
    if value.is_infinite() {
        return None;
    }
    Some(value)
}

/// Sort a slice in place, and keep the order of the equal values. The order of the result is the same for each
/// order of the input, also for a comparison that is not transitive.
pub fn stable_sort<T>(data: &mut [T], less: &impl Fn(&T, &T) -> bool) {
    let length = data.len();
    let mut block = 20usize;
    let mut start = 0usize;
    let mut end = block;
    while end <= length {
        insertion_sort(data, start, end, less);
        start = end;
        end += block;
    }
    insertion_sort(data, start, length, less);
    while block < length {
        start = 0;
        end = 2 * block;
        while end <= length {
            merge_symmetric(data, start, start + block, end, less);
            start = end;
            end += 2 * block;
        }
        let middle = start + block;
        if middle < length {
            merge_symmetric(data, start, middle, length, less);
        }
        block *= 2;
    }
}

fn insertion_sort<T>(data: &mut [T], start: usize, end: usize, less: &impl Fn(&T, &T) -> bool) {
    for index in start + 1..end {
        let mut at = index;
        while at > start && less(&data[at], &data[at - 1]) {
            data.swap(at, at - 1);
            at -= 1;
        }
    }
}

fn swap_range<T>(data: &mut [T], first: usize, second: usize, count: usize) {
    for offset in 0..count {
        data.swap(first + offset, second + offset);
    }
}

fn rotate<T>(data: &mut [T], start: usize, middle: usize, end: usize) {
    let mut left = middle - start;
    let mut right = end - middle;
    while left != right {
        if left > right {
            swap_range(data, middle - left, middle, right);
            left -= right;
        } else {
            swap_range(data, middle - left, middle + right - left, left);
            right -= left;
        }
    }
    swap_range(data, middle - left, middle, left);
}

fn merge_symmetric<T>(data: &mut [T], start: usize, middle: usize, end: usize, less: &impl Fn(&T, &T) -> bool) {
    if middle - start == 1 {
        let mut low = middle;
        let mut high = end;
        while low < high {
            let half = (low + high) >> 1;
            if less(&data[half], &data[start]) {
                low = half + 1;
            } else {
                high = half;
            }
        }
        for at in start..low.saturating_sub(1) {
            data.swap(at, at + 1);
        }
        return;
    }
    if end - middle == 1 {
        let mut low = start;
        let mut high = middle;
        while low < high {
            let half = (low + high) >> 1;
            if !less(&data[middle], &data[half]) {
                low = half + 1;
            } else {
                high = half;
            }
        }
        let mut at = middle;
        while at > low {
            data.swap(at, at - 1);
            at -= 1;
        }
        return;
    }
    let mid = (start + end) >> 1;
    let total = mid + middle;
    let (mut from, mut to) = if middle > mid {
        (total - end, mid)
    } else {
        (start, middle)
    };
    let pivot = total - 1;
    while from < to {
        let half = (from + to) >> 1;
        if !less(&data[pivot - half], &data[half]) {
            from = half + 1;
        } else {
            to = half;
        }
    }
    let stop = total - from;
    if from < middle && middle < stop {
        rotate(data, from, middle, stop);
    }
    if start < from && from < mid {
        merge_symmetric(data, start, from, mid, less);
    }
    if mid < stop && stop < end {
        merge_symmetric(data, mid, stop, end, less);
    }
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
            stable_sort(&mut data, &|left: &(u32, usize), right: &(u32, usize)| left.0 < right.0);
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
}
