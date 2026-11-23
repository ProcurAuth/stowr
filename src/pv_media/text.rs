//! The text helpers of the metadata readers: the bytes of a file as text, the case of a text, the integers and the
//! decimal numbers of a text, and the number forms of the properties.

/// The text of bytes. Each byte that is not part of a valid UTF-8 sequence becomes U+FFFD.
pub(crate) fn lossy(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut rest = bytes;
    loop {
        match std::str::from_utf8(rest) {
            Ok(valid) => {
                out.push_str(valid);
                return out;
            }
            Err(error) => {
                let (valid, after) = rest.split_at(error.valid_up_to());
                out.push_str(std::str::from_utf8(valid).unwrap_or_default());
                let invalid = error.error_len().unwrap_or(after.len()).min(after.len());
                for _ in 0..invalid {
                    out.push('\u{fffd}');
                }
                rest = &after[invalid..];
            }
        }
    }
}

/// The text of ISO 8859-1 bytes: each byte is one character.
pub(crate) fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| char::from(*byte)).collect()
}

/// The lower case of a text: each character gets its simple lower-case form.
pub(crate) fn fold_lower(text: &str) -> String {
    if text.is_ascii() {
        return text.to_ascii_lowercase();
    }
    text.chars()
        .map(|character| character.to_lowercase().next().unwrap_or(character))
        .collect()
}

/// The upper case of a text: each character with an upper-case form of one character gets it. The others stay.
pub(crate) fn fold_upper(text: &str) -> String {
    if text.is_ascii() {
        return text.to_ascii_uppercase();
    }
    text.chars()
        .map(|character| {
            let mut upper = character.to_uppercase();
            match (upper.next(), upper.next()) {
                (Some(single), None) => single,
                _ => character,
            }
        })
        .collect()
}

/// The lower case of bytes as the search of a start tag uses it. A byte that is not valid UTF-8 becomes U+FFFD
/// (three bytes): the positions in the result can differ from the positions in the bytes.
pub(crate) fn lower_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.is_ascii() {
        return bytes.to_ascii_lowercase();
    }
    fold_lower(&lossy(bytes)).into_bytes()
}

/// The bytes without the bytes of `set` at their two ends.
pub(crate) fn trim_bytes<'a>(bytes: &'a [u8], set: &[u8]) -> &'a [u8] {
    let start = bytes.iter().position(|byte| !set.contains(byte)).unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|byte| !set.contains(byte))
        .map_or(start, |index| index + 1);
    &bytes[start..end.max(start)]
}

/// The position of `needle` in `haystack`.
pub(crate) fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// True when `haystack` holds `needle`.
pub(crate) fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    find(haystack, needle).is_some()
}

/// A decimal integer with an optional sign, or `None`.
pub(crate) fn parse_int(text: &str) -> Option<i64> {
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse::<i64>().ok()
}

/// A decimal integer with an optional sign. The flag is false for a text that is not an integer (the value is 0)
/// and for an integer out of range (the value is the nearest limit).
pub(crate) fn parse_int_saturating(text: &str) -> (i64, bool) {
    let digits = text.strip_prefix(['+', '-']).unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return (0, false);
    }
    match text.parse::<i64>() {
        Ok(value) => (value, true),
        Err(_) if text.starts_with('-') => (i64::MIN, false),
        Err(_) => (i64::MAX, false),
    }
}

/// A decimal number, or `None`. A finite number out of range is `None`; `inf`, `infinity` and `nan` (any case, with
/// a sign) are numbers.
pub(crate) fn parse_float(text: &str) -> Option<f64> {
    let value = text.parse::<f64>().ok()?;
    if value.is_infinite() {
        let word = text.trim_start_matches(['+', '-']).to_ascii_lowercase();
        if word != "inf" && word != "infinity" {
            return None;
        }
    }
    Some(value)
}

/// The integer part of a number. A number out of the range of the integers (or not a number) gives the smallest
/// integer.
pub(crate) fn float_to_int(value: f64) -> i64 {
    const LIMIT: f64 = 9_223_372_036_854_775_808.0;
    if value.is_nan() || value >= LIMIT || value < -LIMIT {
        return i64::MIN;
    }
    value as i64
}

/// A number with `decimals` digits after the point.
pub(crate) fn format_fixed(value: f64, decimals: usize) -> String {
    format!("{value:.decimals$}")
}

/// A number with at most `precision` significant digits and no zero at the end. The exponent form applies when the
/// exponent is below -4 or not below the precision (`1.23e+03`).
pub(crate) fn format_general(value: f64, precision: usize) -> String {
    if value.is_nan() {
        return "NaN".to_owned();
    }
    if value.is_infinite() {
        return if value > 0.0 { "+Inf" } else { "-Inf" }.to_owned();
    }
    let precision = precision.max(1);
    let negative = value.is_sign_negative();
    let sign = if negative { "-" } else { "" };
    if value == 0.0 {
        return format!("{sign}0");
    }
    let text = format!("{:.*e}", precision - 1, value.abs());
    let (mantissa, exponent) = text.split_once('e').unwrap_or((&text, "0"));
    let exponent = exponent.parse::<i64>().unwrap_or(0);
    let all_digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let digits = all_digits.trim_end_matches('0');
    let digits = if digits.is_empty() { "0" } else { digits }.as_bytes();
    let count = digits.len() as i64;
    let point = exponent + 1;
    let mut exponent_precision = precision as i64;
    if exponent_precision > count && count >= point {
        exponent_precision = count;
    }
    let shown_exponent = point - 1;
    let mut out = String::from(sign);
    if shown_exponent < -4 || shown_exponent >= exponent_precision {
        let shown = (precision as i64).min(count);
        out.push(char::from(digits[0]));
        if shown > 1 {
            out.push('.');
            for index in 1..shown {
                out.push(char::from(digits.get(index as usize).copied().unwrap_or(b'0')));
            }
        }
        out.push('e');
        out.push(if shown_exponent < 0 { '-' } else { '+' });
        let magnitude = shown_exponent.unsigned_abs();
        if magnitude < 10 {
            out.push('0');
        }
        out.push_str(&magnitude.to_string());
        return out;
    }
    let mut shown = precision as i64;
    if shown > point {
        shown = count;
    }
    let fraction = (shown - point).max(0);
    if point > 0 {
        for index in 0..point {
            out.push(char::from(digits.get(index as usize).copied().unwrap_or(b'0')));
        }
    } else {
        out.push('0');
    }
    if fraction > 0 {
        out.push('.');
        for index in 1..=fraction {
            let position = point + index - 1;
            let digit = if position >= 0 {
                digits.get(position as usize).copied().unwrap_or(b'0')
            } else {
                b'0'
            };
            out.push(char::from(digit));
        }
    }
    out
}
