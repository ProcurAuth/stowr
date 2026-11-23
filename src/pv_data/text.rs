// SPDX-License-Identifier: MIT OR Apache-2.0
//! The text forms of the data previews: the simple upper case, the short form of a float and the integer of a float.
//! The lower case, the quoted form of a name, the readers of integer and float texts and the replacement of invalid
//! UTF-8 are in `crate::pv_docs::util`: each preview uses the same forms.

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

/// The integer of a float as a conversion of the processor gives it: the value rounded toward zero, or the lowest
/// integer for a value that is not a number or is out of the range.
pub(crate) fn float_to_int(value: f64) -> i64 {
    if value.is_nan() || value >= 9_223_372_036_854_775_808.0 || value < -9_223_372_036_854_775_808.0 {
        return i64::MIN;
    }
    value.trunc() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pv_docs::util::lower;

    #[test]
    fn the_case_maps_change_one_character_at_a_time() {
        assert_eq!(upper("ıſßᾀᾈﬀǅ"), "ISßᾈᾈﬀǄ");
        assert_eq!(lower("İǅΣ"), "iǆσ");
        assert_eq!(lower("ΣΑΣ"), "σασ");
        assert_eq!(upper("create table"), "CREATE TABLE");
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
    fn float_conversions_to_integers_round_toward_zero() {
        assert_eq!(float_to_int(2.9), 2);
        assert_eq!(float_to_int(-2.9), -2);
        assert_eq!(float_to_int(1e30), i64::MIN);
        assert_eq!(float_to_int(f64::NAN), i64::MIN);
    }
}
