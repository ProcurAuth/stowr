//! The comparison of cell values: the column filters (`>=`, `<=`, `!=`, `=`, `>`, `<`, else a part of the text), the
//! order of a sort (numbers, then RFC 3339 times, then the text without regard to case; an empty value comes last),
//! and the stable sort that keeps the order of equal values.

use std::cmp::Ordering;

use super::text::{lower, parse_float};

/// True when a value passes a column filter. An empty filter lets each value pass.
pub(crate) fn matches_filter(value: &str, raw_filter: &str) -> bool {
    let filter = raw_filter.trim();
    if filter.is_empty() {
        return true;
    }
    let mut operator = "contains";
    let mut operand = filter;
    for candidate in [">=", "<=", "!=", "=", ">", "<"] {
        if let Some(rest) = filter.strip_prefix(candidate) {
            operator = candidate;
            operand = rest.trim();
            break;
        }
    }
    if operator == "contains" {
        return lower(value).contains(&lower(operand));
    }
    let comparison = compare_values(value, operand);
    match operator {
        "=" => comparison == Ordering::Equal,
        "!=" => comparison != Ordering::Equal,
        ">" => comparison == Ordering::Greater,
        ">=" => comparison != Ordering::Less,
        "<" => comparison == Ordering::Less,
        "<=" => comparison != Ordering::Greater,
        _ => true,
    }
}

/// The order of two values.
pub(crate) fn compare_values(left: &str, right: &str) -> Ordering {
    SortKey::new(left).compare(&SortKey::new(right))
}

/// A value read one time for a sort: the empty flag, the number, the time and the lower-case text.
#[derive(Clone, Debug)]
pub(crate) struct SortKey {
    empty: bool,
    number: Option<f64>,
    time: Option<(i64, u32)>,
    folded: String,
}

impl SortKey {
    /// Read a value for a sort.
    pub(crate) fn new(text: &str) -> Self {
        let trimmed = text.trim();
        if trimmed.is_empty() {
            return Self {
                empty: true,
                number: None,
                time: None,
                folded: String::new(),
            };
        }
        Self {
            empty: false,
            number: parse_float(trimmed),
            time: parse_rfc3339(trimmed),
            folded: lower(trimmed),
        }
    }

    /// The order of two values: two numbers by value, else two times by instant, else the lower-case texts byte by
    /// byte. An empty value comes after each other value.
    pub(crate) fn compare(&self, other: &Self) -> Ordering {
        match (self.empty, other.empty) {
            (true, true) => return Ordering::Equal,
            (true, false) => return Ordering::Greater,
            (false, true) => return Ordering::Less,
            (false, false) => {}
        }
        if let (Some(left), Some(right)) = (self.number, other.number) {
            return if left < right {
                Ordering::Less
            } else if left > right {
                Ordering::Greater
            } else {
                Ordering::Equal
            };
        }
        if let (Some(left), Some(right)) = (self.time, other.time) {
            return left.cmp(&right);
        }
        self.folded.as_bytes().cmp(other.folded.as_bytes())
    }
}

/// The number of days from 1970-01-01 to a date of the proleptic Gregorian calendar.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The number of days of a month.
fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// A fixed number of digits at the start of a text.
fn fixed_digits(text: &[u8], count: usize) -> Option<i64> {
    let part = text.get(..count)?;
    if !part.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(
        part.iter()
            .fold(0i64, |value, digit| value * 10 + i64::from(digit - b'0')),
    )
}

/// Read an RFC 3339 time (`2026-07-25T08:00:00Z`, `2026-07-25T08:00:00.5+02:00`) and give its instant: the seconds
/// from 1970 and the nanoseconds. The hour can have one digit, the fraction can follow a comma, and the offset can
/// reach 24 hours and 60 minutes. `None` for another text.
pub(crate) fn parse_rfc3339(text: &str) -> Option<(i64, u32)> {
    let bytes = text.as_bytes();
    let year = fixed_digits(bytes, 4)?;
    let rest = bytes.get(4..)?.strip_prefix(b"-")?;
    let month = fixed_digits(rest, 2)?;
    let rest = rest.get(2..)?.strip_prefix(b"-")?;
    let day = fixed_digits(rest, 2)?;
    let rest = rest.get(2..)?.strip_prefix(b"T")?;
    let (hour, rest) = match (rest.first(), rest.get(1)) {
        (Some(first), Some(second)) if first.is_ascii_digit() && second.is_ascii_digit() => {
            (i64::from(first - b'0') * 10 + i64::from(second - b'0'), &rest[2..])
        }
        (Some(first), _) if first.is_ascii_digit() => (i64::from(first - b'0'), &rest[1..]),
        _ => return None,
    };
    let rest = rest.strip_prefix(b":")?;
    let minute = fixed_digits(rest, 2)?;
    let rest = rest.get(2..)?.strip_prefix(b":")?;
    let second = fixed_digits(rest, 2)?;
    let mut rest = rest.get(2..)?;
    let mut nanos: i64 = 0;
    if rest.len() >= 2 && matches!(rest[0], b'.' | b',') && rest[1].is_ascii_digit() {
        let count = 1 + rest[1..].iter().take_while(|byte| byte.is_ascii_digit()).count();
        let used = count.min(10);
        let digits = &rest[1..used];
        nanos = digits
            .iter()
            .fold(0i64, |value, digit| value * 10 + i64::from(digit - b'0'));
        for _ in 0..(10 - used) {
            nanos *= 10;
        }
        rest = &rest[count..];
    }
    if !(1..=12).contains(&month) || hour >= 24 || minute >= 60 || second >= 60 {
        return None;
    }
    if day < 1 || day > days_in_month(year, month) {
        return None;
    }
    let offset = match rest {
        [b'Z'] => 0,
        [sign @ (b'+' | b'-'), _, _, b':', _, _] => {
            let hours = fixed_digits(&rest[1..], 2)?;
            let minutes = fixed_digits(&rest[4..], 2)?;
            if hours > 24 || minutes > 60 {
                return None;
            }
            let value = hours * 3600 + minutes * 60;
            if *sign == b'-' { -value } else { value }
        }
        _ => return None,
    };
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second - offset;
    Some((seconds, nanos as u32))
}

/// Sort a slice and keep the order of the equal items: insertion sorts of 20 items, then in-place merges with
/// rotations. The result depends only on `less`, also when `less` is not a consistent order.
pub(crate) fn stable_sort<T>(items: &mut [T], mut less: impl FnMut(&T, &T) -> bool) {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_use_the_first_operator_and_compare_numbers() {
        assert!(matches_filter("beta", "BET"));
        assert!(matches_filter("10", ">9"));
        assert!(matches_filter("10", ">= 10"));
        assert!(!matches_filter("10", "<10"));
        assert!(matches_filter("abc", "!=abd"));
        assert!(matches_filter("anything", "   "));
        assert!(matches_filter("2026-01-02T05:04:05Z", ">2026-01-02T04:04:05Z"));
    }

    #[test]
    fn the_order_puts_empty_values_last_and_numbers_by_value() {
        assert_eq!(compare_values("", ""), Ordering::Equal);
        assert_eq!(compare_values("", "a"), Ordering::Greater);
        assert_eq!(compare_values("9", "10"), Ordering::Less);
        assert_eq!(compare_values("1e1", "9"), Ordering::Greater);
        assert_eq!(compare_values("Beta", "alpha"), Ordering::Greater);
        assert_eq!(compare_values("nan", "1"), Ordering::Equal);
    }

    #[test]
    fn times_follow_the_lenient_rfc3339_rules() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some((0, 0)));
        assert_eq!(
            parse_rfc3339("2026-01-02T5:04:05Z"),
            parse_rfc3339("2026-01-02T05:04:05Z")
        );
        assert_eq!(
            parse_rfc3339("2026-01-02T05:04:05,5Z").map(|time| time.1),
            Some(500_000_000)
        );
        assert!(parse_rfc3339("2026-01-02T05:04:05+24:00").is_some());
        assert!(parse_rfc3339("2026-01-02t05:04:05Z").is_none());
        assert!(parse_rfc3339("2026-01-02T05:04:05z").is_none());
        assert!(parse_rfc3339("2026-02-30T05:04:05Z").is_none());
        assert!(parse_rfc3339("0000-01-01T00:00:00Z").is_some());
        assert_eq!(
            parse_rfc3339("2026-01-02T05:04:05+01:00").map(|time| time.0),
            parse_rfc3339("2026-01-02T04:04:05Z").map(|time| time.0)
        );
    }

    #[test]
    fn the_stable_sort_keeps_the_order_of_equal_items() {
        let mut items: Vec<(u32, usize)> = (0..500).map(|index| ((index * 7919 % 13) as u32, index)).collect();
        stable_sort(&mut items, |left, right| left.0 < right.0);
        for pair in items.windows(2) {
            assert!(pair[0].0 < pair[1].0 || (pair[0].0 == pair[1].0 && pair[0].1 < pair[1].1));
        }
        let mut cyclic = vec!["9", "1e1", "1f", "9", "1e1", "1f"];
        stable_sort(&mut cyclic, |left, right| compare_values(left, right) == Ordering::Less);
        assert_eq!(cyclic.len(), 6);
    }
}
