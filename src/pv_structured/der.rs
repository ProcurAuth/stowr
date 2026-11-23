// SPDX-License-Identifier: MIT OR Apache-2.0
//! A strict reader of DER: the elements, the integers, the object identifiers and the times of X.509.
//!
//! The reader follows the rules of a strict DER parser. It gives no value for these inputs:
//! a tag with a high number, an indefinite length, a length that is not the shortest form, and an integer
//! that is not minimal.

use std::fmt::Write as _;

/// The tag of BOOLEAN.
pub const BOOLEAN: u8 = 0x01;
/// The tag of INTEGER.
pub const INTEGER: u8 = 0x02;
/// The tag of BIT STRING.
pub const BIT_STRING: u8 = 0x03;
/// The tag of OCTET STRING.
pub const OCTET_STRING: u8 = 0x04;
/// The tag of OBJECT IDENTIFIER.
pub const OBJECT_IDENTIFIER: u8 = 0x06;
/// The tag of UTF8String.
pub const UTF8_STRING: u8 = 0x0c;
/// The tag of NumericString.
pub const NUMERIC_STRING: u8 = 0x12;
/// The tag of PrintableString.
pub const PRINTABLE_STRING: u8 = 0x13;
/// The tag of T61String.
pub const T61_STRING: u8 = 0x14;
/// The tag of IA5String.
pub const IA5_STRING: u8 = 0x16;
/// The tag of UTCTime.
pub const UTC_TIME: u8 = 0x17;
/// The tag of GeneralizedTime.
pub const GENERALIZED_TIME: u8 = 0x18;
/// The tag of BMPString.
pub const BMP_STRING: u8 = 0x1e;
/// The tag of SEQUENCE.
pub const SEQUENCE: u8 = 0x30;
/// The tag of SET.
pub const SET: u8 = 0x31;

/// The tag of a context-specific element with a number below 31.
pub const fn context(number: u8) -> u8 {
    0x80 | number
}

/// The tag of a constructed context-specific element with a number below 31.
pub const fn context_constructed(number: u8) -> u8 {
    0xa0 | number
}

/// A cursor over DER bytes.
#[derive(Clone, Copy, Debug)]
pub struct Der<'a>(pub &'a [u8]);

impl<'a> Der<'a> {
    /// True when no byte remains.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// True when the next element has this tag.
    pub fn peek_tag(&self, tag: u8) -> bool {
        self.0.first() == Some(&tag)
    }

    /// Read the next element of any tag: the tag, the whole element and its content.
    pub fn read_any_element(&mut self) -> Option<(u8, &'a [u8], &'a [u8])> {
        let data = self.0;
        if data.len() < 2 {
            return None;
        }
        let tag = data[0];
        let length_byte = data[1];
        if tag & 0x1f == 0x1f {
            return None;
        }
        let (header, length) = if length_byte & 0x80 == 0 {
            (2usize, usize::from(length_byte))
        } else {
            let length_length = usize::from(length_byte & 0x7f);
            if length_length == 0 || length_length > 4 || data.len() < 2 + length_length {
                return None;
            }
            let mut value: u32 = 0;
            for byte in &data[2..2 + length_length] {
                value = (value << 8) | u32::from(*byte);
            }
            if value < 128 || value >> ((length_length - 1) * 8) == 0 {
                return None;
            }
            (2 + length_length, value as usize)
        };
        let total = header.checked_add(length)?;
        if total > data.len() {
            return None;
        }
        self.0 = &data[total..];
        Some((tag, &data[..total], &data[header..total]))
    }

    /// Read the next element with this tag: its whole bytes.
    pub fn read_element(&mut self, tag: u8) -> Option<&'a [u8]> {
        let mut probe = *self;
        let (found, full, _) = probe.read_any_element()?;
        if found != tag {
            return None;
        }
        *self = probe;
        Some(full)
    }

    /// Read the next element with this tag: its content.
    pub fn read(&mut self, tag: u8) -> Option<&'a [u8]> {
        let mut probe = *self;
        let (found, _, content) = probe.read_any_element()?;
        if found != tag {
            return None;
        }
        *self = probe;
        Some(content)
    }

    /// Read the next element of any tag: the tag and its content.
    pub fn read_any(&mut self) -> Option<(u8, &'a [u8])> {
        self.read_any_element().map(|(tag, _, content)| (tag, content))
    }

    /// An optional element: `None` when the read fails, `Some(None)` when the element is absent.
    pub fn read_optional(&mut self, tag: u8) -> Option<Option<&'a [u8]>> {
        if self.peek_tag(tag) {
            self.read(tag).map(Some)
        } else {
            Some(None)
        }
    }

    /// Read an optional field with an explicit tag the way a lenient reader does: the length of the wrapper is not
    /// checked against the data, and the field counts as absent when the wrapper has another tag or the element
    /// inside has not the expected tag. `None` when the wrapper has no element inside or the element is not valid.
    pub fn read_explicit_lenient(&mut self, wrapper_tag: u8, inner_tag: u8) -> Option<Option<&'a [u8]>> {
        if !self.peek_tag(wrapper_tag) {
            return Some(None);
        }
        let data = self.0;
        let length_byte = *data.get(1)?;
        let header = if length_byte & 0x80 == 0 {
            2
        } else {
            let count = usize::from(length_byte & 0x7f);
            if count == 0 || data.len() < 2 + count {
                return None;
            }
            let mut length: usize = 0;
            for byte in &data[2..2 + count] {
                if length >= 1 << 23 {
                    return None;
                }
                length = (length << 8) | usize::from(*byte);
                if length == 0 {
                    return None;
                }
            }
            if length < 0x80 {
                return None;
            }
            2 + count
        };
        let inside = data.get(header..)?;
        if inside.is_empty() {
            return None;
        }
        if inside[0] != inner_tag {
            return Some(None);
        }
        let mut inner = Der(inside);
        let content = inner.read(inner_tag)?;
        self.0 = inner.0;
        Some(Some(content))
    }

    /// Skip an optional element. False when the element is present and not valid.
    pub fn skip_optional(&mut self, tag: u8) -> bool {
        self.read_optional(tag).is_some()
    }

    /// Read an INTEGER.
    pub fn read_integer(&mut self) -> Option<BigInt> {
        let content = self.read(INTEGER)?;
        BigInt::from_der_content(content)
    }

    /// Read an INTEGER that fits in 64 bits.
    pub fn read_i64(&mut self) -> Option<i64> {
        let content = self.read(INTEGER)?;
        integer_i64(content)
    }

    /// Read an INTEGER that fits in 32 bits.
    pub fn read_i32(&mut self) -> Option<i32> {
        let value = self.read_i64()?;
        i32::try_from(value).ok()
    }

    /// Read a BOOLEAN: 0 or 0xff.
    pub fn read_boolean(&mut self) -> Option<bool> {
        let content = self.read(BOOLEAN)?;
        match content {
            [0] => Some(false),
            [0xff] => Some(true),
            _ => None,
        }
    }

    /// Read a BIT STRING: the bytes and the number of bits.
    pub fn read_bit_string(&mut self) -> Option<BitString<'a>> {
        let content = self.read(BIT_STRING)?;
        let (&padding, bytes) = content.split_first()?;
        if padding > 7 || (bytes.is_empty() && padding != 0) {
            return None;
        }
        if let Some(last) = bytes.last()
            && last & ((1u8 << padding) - 1) != 0
        {
            return None;
        }
        Some(BitString { bytes })
    }

    /// Read an OBJECT IDENTIFIER.
    pub fn read_oid(&mut self) -> Option<Oid> {
        let content = self.read(OBJECT_IDENTIFIER)?;
        Oid::from_der_content(content)
    }
}

/// A BIT STRING: the bytes after the padding byte.
#[derive(Clone, Copy, Debug)]
pub struct BitString<'a> {
    /// The bytes after the padding byte.
    pub bytes: &'a [u8],
}

fn minimal_integer(content: &[u8]) -> bool {
    match content {
        [] => false,
        [_] => true,
        [0, next, ..] => next & 0x80 != 0,
        [0xff, next, ..] => next & 0x80 == 0,
        _ => true,
    }
}

fn integer_i64(content: &[u8]) -> Option<i64> {
    if !minimal_integer(content) || content.len() > 8 {
        return None;
    }
    let mut value: i64 = if content[0] & 0x80 != 0 { -1 } else { 0 };
    for byte in content {
        value = (value << 8) | i64::from(*byte);
    }
    Some(value)
}

/// A big integer: the sign and the magnitude in big-endian bytes without zero bytes at the start.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BigInt {
    /// True for a value below 0.
    pub negative: bool,
    /// The absolute value, big-endian, without zero bytes at the start. Empty for 0.
    pub magnitude: Vec<u8>,
}

impl BigInt {
    /// The integer of the content of a DER INTEGER. `None` when the encoding is not minimal.
    pub fn from_der_content(content: &[u8]) -> Option<Self> {
        if !minimal_integer(content) {
            return None;
        }
        let negative = content[0] & 0x80 != 0;
        let mut bytes = content.to_vec();
        if negative {
            let mut carry = true;
            for byte in bytes.iter_mut().rev() {
                *byte = !*byte;
                if carry {
                    let (sum, overflow) = byte.overflowing_add(1);
                    *byte = sum;
                    carry = overflow;
                }
            }
        }
        let start = bytes.iter().position(|byte| *byte != 0).unwrap_or(bytes.len());
        bytes.drain(..start);
        Some(Self {
            negative: negative && !bytes.is_empty(),
            magnitude: bytes,
        })
    }

    /// The sign: -1, 0 or 1.
    pub fn sign(&self) -> i32 {
        if self.magnitude.is_empty() {
            0
        } else if self.negative {
            -1
        } else {
            1
        }
    }

    /// The number of bits of the absolute value.
    pub fn bit_length(&self) -> usize {
        match self.magnitude.first() {
            None => 0,
            Some(first) => self.magnitude.len() * 8 - first.leading_zeros() as usize,
        }
    }

    /// The decimal text.
    pub fn to_decimal(&self) -> String {
        if self.magnitude.is_empty() {
            return "0".to_owned();
        }
        // Limbs of 32 bits, most significant first.
        let mut limbs: Vec<u32> = Vec::new();
        let padding = (4 - self.magnitude.len() % 4) % 4;
        let mut padded = vec![0u8; padding];
        padded.extend_from_slice(&self.magnitude);
        for chunk in padded.chunks(4) {
            limbs.push(u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        }
        let mut groups: Vec<u32> = Vec::new();
        while !limbs.is_empty() {
            let mut remainder: u64 = 0;
            for limb in &mut limbs {
                let current = (remainder << 32) | u64::from(*limb);
                *limb = (current / 1_000_000_000) as u32;
                remainder = current % 1_000_000_000;
            }
            groups.push(remainder as u32);
            let skip = limbs.iter().position(|limb| *limb != 0).unwrap_or(limbs.len());
            limbs.drain(..skip);
        }
        let mut text = String::new();
        if self.negative {
            text.push('-');
        }
        for (index, group) in groups.iter().rev().enumerate() {
            if index == 0 {
                let _ = write!(text, "{group}");
            } else {
                let _ = write!(text, "{group:09}");
            }
        }
        text
    }
}

/// An object identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Oid(pub Vec<u64>);

impl Oid {
    /// The identifier of the content of a DER OBJECT IDENTIFIER.
    pub fn from_der_content(content: &[u8]) -> Option<Self> {
        if content.is_empty() {
            return None;
        }
        let mut values: Vec<u64> = Vec::new();
        let mut index = 0;
        while index < content.len() {
            let mut value: u64 = 0;
            let mut shift = 0;
            loop {
                let byte = *content.get(index)?;
                index += 1;
                if shift == 5 {
                    return None;
                }
                if value >= 1 << (31 - 7) {
                    return None;
                }
                if shift == 0 && byte == 0x80 {
                    return None;
                }
                value = (value << 7) | u64::from(byte & 0x7f);
                shift += 1;
                if byte & 0x80 == 0 {
                    break;
                }
            }
            values.push(value);
        }
        let first = values[0];
        let rest = values.split_off(1);
        let mut out = if first < 80 {
            vec![first / 40, first % 40]
        } else {
            vec![2, first - 80]
        };
        out.extend(rest);
        Some(Self(out))
    }

    /// The dotted text.
    pub fn dotted(&self) -> String {
        let mut text = String::new();
        for (index, value) in self.0.iter().enumerate() {
            if index > 0 {
                text.push('.');
            }
            let _ = write!(text, "{value}");
        }
        text
    }

    /// True when the identifier has these arcs.
    pub fn is(&self, arcs: &[u64]) -> bool {
        self.0 == arcs
    }
}

/// A date and a time of day.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DateTime {
    /// The year (0 to 9999).
    pub year: i32,
    /// The month (1 to 12).
    pub month: u32,
    /// The day.
    pub day: u32,
    /// The hour.
    pub hour: u32,
    /// The minute.
    pub minute: u32,
    /// The second.
    pub second: u32,
}

impl DateTime {
    /// The RFC 3339 form in UTC: `1994-11-06T08:49:37Z`.
    pub fn rfc3339(&self) -> String {
        format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second
        )
    }
}

fn is_leap(year: i32) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ => {
            if is_leap(year) {
                29
            } else {
                28
            }
        }
    }
}

/// The days since 0000-03-01 of a date of the proleptic Gregorian calendar.
fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let year = i64::from(year) - i64::from(month <= 2);
    let era = year.div_euclid(400);
    let year_of_era = year.rem_euclid(400);
    let month_index = i64::from((month + 9) % 12);
    let day_of_year = (153 * month_index + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era
}

fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let era = days.div_euclid(146_097);
    let day_of_era = days.rem_euclid(146_097);
    let year_of_era = (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = (day_of_year - (153 * month_index + 2) / 5 + 1) as u32;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    } as u32;
    let year = if month <= 2 { year + 1 } else { year };
    (year as i32, month, day)
}

/// The digits of a fixed field.
fn digits(bytes: &[u8], count: usize) -> Option<(u32, &[u8])> {
    if bytes.len() < count {
        return None;
    }
    let mut value = 0u32;
    for byte in &bytes[..count] {
        if !byte.is_ascii_digit() {
            return None;
        }
        value = value * 10 + u32::from(byte - b'0');
    }
    Some((value, &bytes[count..]))
}

/// The seconds that a text gives as the zone of a time: `Z` is 0, `+hhmm` and `-hhmm` are the offset.
/// A zone `+0000` is not the canonical form and gives `None`.
fn zone(bytes: &[u8]) -> Option<i64> {
    if bytes == b"Z" {
        return Some(0);
    }
    if bytes.len() != 5 || (bytes[0] != b'+' && bytes[0] != b'-') {
        return None;
    }
    let (hours, rest) = digits(&bytes[1..], 2)?;
    let (minutes, _) = digits(rest, 2)?;
    if hours > 24 || minutes > 60 {
        return None;
    }
    let offset = (i64::from(hours) * 60 + i64::from(minutes)) * 60;
    if offset == 0 {
        return None;
    }
    Some(if bytes[0] == b'-' { -offset } else { offset })
}

fn build(year: i32, month: u32, day: u32, hour: u32, minute: u32, second: u32, offset: i64) -> Option<DateTime> {
    if !(1..=12).contains(&month) || day < 1 || day > days_in_month(year, month) {
        return None;
    }
    if hour >= 24 || minute >= 60 || second >= 60 {
        return None;
    }
    if offset == 0 {
        return Some(DateTime {
            year,
            month,
            day,
            hour,
            minute,
            second,
        });
    }
    let local = days_from_civil(year, month, day) * 86_400
        + i64::from(hour) * 3600
        + i64::from(minute) * 60
        + i64::from(second);
    let utc = local - offset;
    let days = utc.div_euclid(86_400);
    let rest = utc.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    Some(DateTime {
        year,
        month,
        day,
        hour: (rest / 3600) as u32,
        minute: ((rest % 3600) / 60) as u32,
        second: (rest % 60) as u32,
    })
}

/// Read a time element (UTCTime or GeneralizedTime) of a certificate.
pub fn read_time(der: &mut Der<'_>) -> Option<DateTime> {
    if der.peek_tag(UTC_TIME) {
        let content = der.read(UTC_TIME)?;
        parse_utc_time(content)
    } else if der.peek_tag(GENERALIZED_TIME) {
        let content = der.read(GENERALIZED_TIME)?;
        parse_generalized_time(content)
    } else {
        None
    }
}

fn parse_utc_time(text: &[u8]) -> Option<DateTime> {
    let (year, rest) = digits(text, 2)?;
    let (month, rest) = digits(rest, 2)?;
    let (day, rest) = digits(rest, 2)?;
    let (hour, rest) = digits(rest, 2)?;
    let (minute, rest) = digits(rest, 2)?;
    let (second, rest) = match digits(rest, 2) {
        Some((value, after)) if after.first().is_some_and(|byte| !byte.is_ascii_digit()) => (value, after),
        _ => (0, rest),
    };
    let offset = zone(rest)?;
    let mut year = if year >= 69 { 1900 + year } else { 2000 + year } as i32;
    if year >= 2050 {
        year -= 100;
    }
    build(year, month, day, hour, minute, second, offset)
}

fn parse_generalized_time(text: &[u8]) -> Option<DateTime> {
    let (year, rest) = digits(text, 4)?;
    let (month, rest) = digits(rest, 2)?;
    let (day, rest) = digits(rest, 2)?;
    let (hour, rest) = digits(rest, 2)?;
    let (minute, rest) = digits(rest, 2)?;
    let (second, rest) = digits(rest, 2)?;
    let offset = zone(rest)?;
    build(year as i32, month, day, hour, minute, second, offset)
}
