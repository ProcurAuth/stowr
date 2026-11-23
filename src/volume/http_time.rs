// SPDX-License-Identifier: MIT OR Apache-2.0
//! The dates of the conditional headers of a read. A client can send an HTTP date in three forms: the standard form
//! (`Sun, 06 Nov 1994 08:49:37 GMT`), the old form with a long day name and a two-digit year (`Sunday, 06-Nov-94
//! 08:49:37 GMT`), and the form of the C library (`Sun Nov  6 08:49:37 1994`).

use crate::common::time::Timestamp;

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// The days since 1970-01-01 of a civil date.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        _ => 28,
    }
}

fn month_number(name: &str) -> Option<i64> {
    MONTHS
        .iter()
        .position(|month| *month == name)
        .and_then(|index| i64::try_from(index + 1).ok())
}

fn seconds(year: i64, month: i64, day: i64, clock: &str) -> Option<i64> {
    let mut fields = clock.split(':');
    let hour: i64 = fields.next()?.parse().ok()?;
    let minute: i64 = fields.next()?.parse().ok()?;
    let second: i64 = fields.next()?.parse().ok()?;
    if fields.next().is_some() {
        return None;
    }
    if day < 1
        || day > days_in_month(year, month)
        || !(0..24).contains(&hour)
        || !(0..60).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return None;
    }
    Some(days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second)
}

/// `Sunday, 06-Nov-94 08:49:37 GMT`.
fn parse_old_form(text: &str) -> Option<i64> {
    let (weekday, rest) = text.split_once(", ")?;
    if weekday.is_empty() {
        return None;
    }
    let (date, rest) = rest.split_once(' ')?;
    let (clock, zone) = rest.split_once(' ')?;
    if zone != "GMT" {
        return None;
    }
    let mut parts = date.split('-');
    let day: i64 = parts.next()?.parse().ok()?;
    let month = month_number(parts.next()?)?;
    let short: i64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    let year = if short >= 69 { 1900 + short } else { 2000 + short };
    seconds(year, month, day, clock)
}

/// `Sun Nov  6 08:49:37 1994`.
fn parse_c_form(text: &str) -> Option<i64> {
    let parts: Vec<&str> = text.split_whitespace().collect();
    let [_weekday, month, day, clock, year] = parts.as_slice() else {
        return None;
    };
    seconds(year.parse().ok()?, month_number(month)?, day.parse().ok()?, clock)
}

/// The seconds since 1970-01-01T00:00:00Z of an HTTP date in one of the three forms, or `None`.
pub fn parse_http_seconds(text: &str) -> Option<i64> {
    if let Some(time) = Timestamp::parse_http_date(text) {
        return Some(time.secs);
    }
    parse_old_form(text).or_else(|| parse_c_form(text))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_forms_of_an_http_date_give_the_same_second() {
        let expected = Some(784_111_777);
        assert_eq!(parse_http_seconds("Sun, 06 Nov 1994 08:49:37 GMT"), expected);
        assert_eq!(parse_http_seconds("Sunday, 06-Nov-94 08:49:37 GMT"), expected);
        assert_eq!(parse_http_seconds("Sun Nov  6 08:49:37 1994"), expected);
    }

    #[test]
    fn a_text_that_is_not_a_date_gives_nothing() {
        for text in [
            "",
            "yesterday",
            "Sun, 32 Nov 1994 08:49:37 GMT",
            "Sunday, 06-Foo-94 08:49:37 GMT",
        ] {
            assert_eq!(parse_http_seconds(text), None, "{text}");
        }
    }
}
