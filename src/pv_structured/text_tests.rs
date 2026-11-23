// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tests of the structured text readers: folded lines, contacts and calendars.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::fixtures::{bytes, cases, name};
use super::text::{
    MAX_CONTACT_VALUES_PER_FIELD, MAX_UNFOLDED_LINE_BYTES, calendar_metadata, calendar_preview, unfold_lines,
    vcard_metadata, vcard_preview,
};

fn map_value(map: &BTreeMap<String, String>) -> Value {
    serde_json::to_value(map).unwrap_or(Value::Null)
}

/// A null of an expected answer stands for an empty map or an empty list.
fn normalize(value: &Value, empty: Value) -> Value {
    if value.is_null() { empty } else { value.clone() }
}

#[test]
fn contacts_and_calendars_match_the_expected_answers_in_each_case() {
    let mut failures = Vec::new();
    for case in cases("texts") {
        let data = bytes(&case["input"]);
        let checks = [
            (
                "vcard details",
                map_value(&vcard_metadata(&data)),
                normalize(&case["vcardMeta"], json!({})),
            ),
            (
                "vcard preview",
                serde_json::to_value(vcard_preview(&data)).unwrap_or(Value::Null),
                normalize(&case["vcard"], json!([])),
            ),
            (
                "calendar details",
                map_value(&calendar_metadata(&data)),
                normalize(&case["icalMeta"], json!({})),
            ),
            (
                "calendar preview",
                serde_json::to_value(calendar_preview(&data)).unwrap_or(Value::Null),
                case["ical"].clone(),
            ),
            (
                "unfolded lines",
                serde_json::to_value(unfold_lines(&data)).unwrap_or(Value::Null),
                normalize(&case["lines"], json!([])),
            ),
        ];
        for (what, got, want) in checks {
            if got != want {
                failures.push(format!("{} / {what}: got {got}, want {want}", name(case)));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn unfolding_joins_the_continuation_lines_and_drops_empty_lines() {
    let lines = unfold_lines(b"A:1\r\n 2\r\n\t3\r\n\r\nB:x\r\n");
    assert_eq!(lines, vec!["A:123".to_owned(), "B:x".to_owned()]);
}

#[test]
fn unfolding_many_continuations_stays_linear() {
    let mut input = b"A:".to_vec();
    for _ in 0..50_000 {
        input.extend_from_slice(b"\n x");
    }
    let started = std::time::Instant::now();
    let lines = unfold_lines(&input);
    assert!(started.elapsed() < std::time::Duration::from_secs(5));
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].len(), 50_002);
}

#[test]
fn an_unfolded_line_has_a_size_limit() {
    let mut input = b"A:".to_vec();
    for _ in 0..5 {
        input.extend_from_slice(b"\n ");
        input.extend(std::iter::repeat_n(b'x', 1 << 20));
    }
    let lines = unfold_lines(&input);
    assert_eq!(lines.len(), 1);
    assert!(lines[0].len() <= MAX_UNFOLDED_LINE_BYTES);
    assert!(lines[0].len() > MAX_UNFOLDED_LINE_BYTES - 10);
}

#[test]
fn a_contact_keeps_a_limited_number_of_distinct_values() {
    let mut text = String::from("BEGIN:VCARD\nFN:Ada\nEMAIL:dup@example.test\nEMAIL:dup@example.test\n");
    for index in 0..20_000 {
        text.push_str(&format!("EMAIL:user{index}@example.test\n"));
    }
    text.push_str("TEL:+1\nEND:VCARD\n");
    let contacts = vcard_preview(text.as_bytes());
    assert_eq!(contacts.len(), 1);
    assert_eq!(contacts[0].emails.len(), MAX_CONTACT_VALUES_PER_FIELD);
    assert_eq!(contacts[0].emails[0], "dup@example.test");
    assert_eq!(contacts[0].emails[1], "user0@example.test");
    assert_eq!(contacts[0].phones.len(), 1);
}

#[test]
fn a_contact_without_a_formatted_name_takes_its_structured_name() {
    let contacts = vcard_preview(b"BEGIN:VCARD\nN:Smith;John\nEND:VCARD\n");
    assert_eq!(contacts[0].name, "Smith John");
    assert_eq!(contacts[0].structured, "Smith John");
}
