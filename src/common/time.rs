//! Dates and times of the answers, of the providers and of the log.
//!
//! A [`Timestamp`] is a point in time with a precision of one nanosecond, and the offset that its text had. The
//! JSON form is RFC 3339 with the fraction that the value needs (`2026-11-23T10:00:00.5Z`). An offset of 0 gives `Z`.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A point in time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Timestamp {
    /// The seconds since 1970-01-01T00:00:00Z.
    pub secs: i64,
    /// The nanoseconds in the second, 0 to 999 999 999.
    pub nanos: u32,
    /// The offset of the text, in seconds east of UTC. The JSON form shows it; 0 shows `Z`.
    pub offset: i32,
}

impl PartialOrd for Timestamp {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Timestamp {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.secs, self.nanos).cmp(&(other.secs, other.nanos))
    }
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];
const WEEKDAYS: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];

/// The civil date of a day number (days since 1970-01-01).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// The day number (days since 1970-01-01) of a civil date.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let m = i64::from(month);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(day) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        _ => 28,
    }
}

impl Timestamp {
    /// The current time, in UTC.
    pub fn now() -> Self {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(elapsed) => Self {
                secs: i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX),
                nanos: elapsed.subsec_nanos(),
                offset: 0,
            },
            Err(_) => Self::default(),
        }
    }

    /// A time from seconds and nanoseconds since 1970-01-01T00:00:00Z, in UTC.
    pub fn from_unix(secs: i64, nanos: u32) -> Self {
        Self {
            secs,
            nanos: nanos.min(999_999_999),
            offset: 0,
        }
    }

    /// The same time in UTC.
    pub fn utc(self) -> Self {
        Self { offset: 0, ..self }
    }

    /// The milliseconds since 1970-01-01T00:00:00Z. Code that needs "no time" uses `Option<Timestamp>`.
    pub fn unix_millis(self) -> i64 {
        self.secs
            .saturating_mul(1000)
            .saturating_add(i64::from(self.nanos / 1_000_000))
    }

    /// The time plus a number of seconds.
    pub fn plus_secs(self, secs: i64) -> Self {
        Self {
            secs: self.secs.saturating_add(secs),
            ..self
        }
    }

    fn local_parts(self) -> (i64, u32, u32, u32, u32, u32) {
        let local = self.secs + i64::from(self.offset);
        let days = local.div_euclid(86_400);
        let rest = local.rem_euclid(86_400) as u32;
        let (year, month, day) = civil_from_days(days);
        (year, month, day, rest / 3600, (rest / 60) % 60, rest % 60)
    }

    fn write_offset(self, out: &mut String) {
        if self.offset == 0 {
            out.push('Z');
            return;
        }
        let sign = if self.offset < 0 { '-' } else { '+' };
        let minutes = self.offset.unsigned_abs() / 60;
        out.push_str(&format!("{sign}{:02}:{:02}", minutes / 60, minutes % 60));
    }

    /// RFC 3339 with seconds: `1994-11-06T08:49:37Z`.
    pub fn rfc3339(self) -> String {
        let (year, month, day, hour, minute, second) = self.local_parts();
        let mut out = format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}");
        self.write_offset(&mut out);
        out
    }

    /// RFC 3339 with the fraction that the value needs, without the zeros at its end: the JSON form.
    pub fn rfc3339_nano(self) -> String {
        let (year, month, day, hour, minute, second) = self.local_parts();
        let mut out = format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}");
        if self.nanos != 0 {
            let fraction = format!("{:09}", self.nanos);
            out.push('.');
            out.push_str(fraction.trim_end_matches('0'));
        }
        self.write_offset(&mut out);
        out
    }

    /// The HTTP date in UTC: `Sun, 06 Nov 1994 08:49:37 GMT`.
    pub fn http_date(self) -> String {
        let utc = self.utc();
        let (year, month, day, hour, minute, second) = utc.local_parts();
        let weekday = WEEKDAYS[utc.secs.div_euclid(86_400).rem_euclid(7) as usize];
        let month_name = MONTHS[(month - 1) as usize];
        format!("{weekday}, {day:02} {month_name} {year:04} {hour:02}:{minute:02}:{second:02} GMT")
    }

    /// The log form in UTC: `1994/11/06 08:49:37`.
    pub fn log_form(self) -> String {
        let (year, month, day, hour, minute, second) = self.utc().local_parts();
        format!("{year:04}/{month:02}/{day:02} {hour:02}:{minute:02}:{second:02}")
    }

    /// Read an RFC 3339 time: `1994-11-06T08:49:37[.fraction](Z|+hh:mm|-hh:mm)`. A text in another form gives
    /// `None`.
    pub fn parse_rfc3339(text: &str) -> Option<Self> {
        let bytes = text.as_bytes();
        if bytes.len() < 20 || bytes[4] != b'-' || bytes[7] != b'-' || !matches!(bytes[10], b'T' | b't') {
            return None;
        }
        if bytes[13] != b':' || bytes[16] != b':' {
            return None;
        }
        let number = |range: std::ops::Range<usize>| -> Option<u32> {
            let part = text.get(range)?;
            if part.bytes().all(|b| b.is_ascii_digit()) {
                part.parse().ok()
            } else {
                None
            }
        };
        let year = i64::from(number(0..4)?);
        let month = number(5..7)?;
        let day = number(8..10)?;
        let hour = number(11..13)?;
        let minute = number(14..16)?;
        let second = number(17..19)?;
        if !(1..=12).contains(&month)
            || day < 1
            || day > days_in_month(year, month)
            || hour > 23
            || minute > 59
            || second > 59
        {
            return None;
        }
        let mut rest = text.get(19..)?;
        let mut nanos = 0u32;
        if let Some(fraction) = rest.strip_prefix('.') {
            let digits = fraction.bytes().take_while(u8::is_ascii_digit).count();
            if digits == 0 || digits > 9 {
                return None;
            }
            let value: u32 = fraction.get(..digits)?.parse().ok()?;
            nanos = value * 10u32.pow(9 - digits as u32);
            rest = fraction.get(digits..)?;
        }
        let offset = match rest {
            "Z" | "z" => 0,
            _ => {
                let sign = match rest.as_bytes().first() {
                    Some(b'+') => 1,
                    Some(b'-') => -1,
                    _ => return None,
                };
                if rest.len() != 6 || rest.as_bytes()[3] != b':' {
                    return None;
                }
                let hours: i32 = rest.get(1..3)?.parse().ok()?;
                let minutes: i32 = rest.get(4..6)?.parse().ok()?;
                if hours > 23 || minutes > 59 {
                    return None;
                }
                sign * (hours * 3600 + minutes * 60)
            }
        };
        let days = days_from_civil(year, month, day);
        let local = days * 86_400 + i64::from(hour * 3600 + minute * 60 + second);
        Some(Self {
            secs: local - i64::from(offset),
            nanos,
            offset,
        })
    }

    /// Read an HTTP date in the IMF-fixdate form: `Sun, 06 Nov 1994 08:49:37 GMT`.
    pub fn parse_http_date(text: &str) -> Option<Self> {
        let parts: Vec<&str> = text.split(' ').collect();
        let [weekday, day, month, year, clock, zone] = parts.as_slice() else {
            return None;
        };
        if !weekday.ends_with(',') || *zone != "GMT" || day.len() != 2 || year.len() != 4 {
            return None;
        }
        let month = MONTHS.iter().position(|name| name == month)? as u32 + 1;
        let day: u32 = day.parse().ok()?;
        let year: i64 = year.parse().ok()?;
        let clock: Vec<&str> = clock.split(':').collect();
        let [hour, minute, second] = clock.as_slice() else {
            return None;
        };
        let (hour, minute, second): (u32, u32, u32) = (hour.parse().ok()?, minute.parse().ok()?, second.parse().ok()?);
        if day < 1 || day > days_in_month(year, month) || hour > 23 || minute > 59 || second > 60 {
            return None;
        }
        let days = days_from_civil(year, month, day);
        Some(Self::from_unix(
            days * 86_400 + i64::from(hour * 3600 + minute * 60 + second),
            0,
        ))
    }
}

/// The text of "no time" in an answer: the zero time, `0001-01-01T00:00:00Z`.
pub const ZERO_TIME_TEXT: &str = "0001-01-01T00:00:00Z";

/// Serialize an optional time: the time, or the zero time for `None`. Use it for a time member that the answers
/// always have.
pub fn serialize_or_zero<S: Serializer>(value: &Option<Timestamp>, serializer: S) -> Result<S::Ok, S::Error> {
    match value {
        Some(time) => serializer.serialize_str(&time.rfc3339_nano()),
        None => serializer.serialize_str(ZERO_TIME_TEXT),
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.rfc3339_nano())
    }
}

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.rfc3339_nano())
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::parse_rfc3339(&text).ok_or_else(|| serde::de::Error::custom(format!("not an RFC 3339 time: {text:?}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forms_of_a_time() {
        let time = Timestamp::parse_rfc3339("1994-11-06T08:49:37.120Z").unwrap();
        assert_eq!(time.rfc3339(), "1994-11-06T08:49:37Z");
        assert_eq!(time.rfc3339_nano(), "1994-11-06T08:49:37.12Z");
        assert_eq!(time.http_date(), "Sun, 06 Nov 1994 08:49:37 GMT");
        assert_eq!(time.log_form(), "1994/11/06 08:49:37");
        assert_eq!(
            Timestamp::parse_http_date("Sun, 06 Nov 1994 08:49:37 GMT")
                .unwrap()
                .secs,
            time.secs
        );
    }

    #[test]
    fn an_offset_stays_in_the_text() {
        let time = Timestamp::parse_rfc3339("2026-11-23T10:00:00+02:00").unwrap();
        assert_eq!(time.rfc3339_nano(), "2026-11-23T10:00:00+02:00");
        assert_eq!(time.utc().rfc3339(), "2026-11-23T08:00:00Z");
        assert!(Timestamp::parse_rfc3339("2026-02-30T10:00:00Z").is_none());
    }
}
