// SPDX-License-Identifier: MIT OR Apache-2.0
//! The structured text formats: vCard and iCalendar. The folded lines, the properties, the records of the
//! previews and the properties of the details.

use std::collections::{BTreeMap, HashSet};

use serde::Serialize;

/// The longest unfolded line: 4 MiB. A longer line loses the rest of its continuations.
pub const MAX_UNFOLDED_LINE_BYTES: usize = 4 << 20;

/// The most values of one kind that a contact keeps: e-mail addresses, phones, addresses, URLs and notes.
pub const MAX_CONTACT_VALUES_PER_FIELD: usize = 256;

/// The text of bytes: each byte that is not part of a valid UTF-8 sequence becomes one U+FFFD.
pub fn lossy(bytes: &[u8]) -> String {
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
                // The prefix is valid UTF-8 by the check above.
                out.push_str(&String::from_utf8_lossy(&rest[..valid]));
                let bad = error.error_len().unwrap_or(rest.len() - valid);
                for _ in 0..bad {
                    out.push('\u{fffd}');
                }
                rest = &rest[valid + bad..];
            }
        }
    }
}

/// The text of bytes: each run of bytes that are not valid UTF-8 becomes one U+FFFD.
pub fn lossy_runs(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut rest = bytes;
    let mut in_run = false;
    loop {
        match std::str::from_utf8(rest) {
            Ok(text) => {
                out.push_str(text);
                return out;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                if valid > 0 {
                    out.push_str(&String::from_utf8_lossy(&rest[..valid]));
                    in_run = false;
                }
                if !in_run {
                    out.push('\u{fffd}');
                    in_run = true;
                }
                let bad = error.error_len().unwrap_or(rest.len() - valid);
                rest = &rest[valid + bad..];
            }
        }
    }
}

/// The logical lines of a text with folded lines. A line that starts with a space or a tab continues the line
/// before it. The line ends are CRLF, CR or LF; an empty line is dropped.
pub fn unfold_lines(text: &[u8]) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    let mut open = false;
    let flush = |current: &mut Vec<u8>, open: &mut bool, lines: &mut Vec<String>| {
        if *open {
            lines.push(lossy(current));
            current.clear();
            *open = false;
        }
    };
    let mut index = 0;
    while index < text.len() {
        // The end of the line: CRLF, CR or LF.
        let mut end = index;
        while end < text.len() && text[end] != b'\n' && text[end] != b'\r' {
            end += 1;
        }
        let line = &text[index..end];
        index = end;
        if index < text.len() {
            if text[index] == b'\r' && text.get(index + 1) == Some(&b'\n') {
                index += 2;
            } else {
                index += 1;
            }
        }
        if line.is_empty() {
            continue;
        }
        if (line[0] == b' ' || line[0] == b'\t') && open {
            let room = MAX_UNFOLDED_LINE_BYTES.saturating_sub(current.len());
            if room > 0 {
                let start = line
                    .iter()
                    .position(|byte| *byte != b' ' && *byte != b'\t')
                    .unwrap_or(line.len());
                let part = &line[start..];
                let part = &part[..part.len().min(room)];
                current.extend_from_slice(part);
            }
            continue;
        }
        flush(&mut current, &mut open, &mut lines);
        current.extend_from_slice(line);
        open = true;
    }
    flush(&mut current, &mut open, &mut lines);
    lines
}

fn equals_ignore_case(left: &str, right: &str) -> bool {
    left.eq_ignore_ascii_case(right)
}

/// The blocks between a begin line and an end line. A line is compared without its blanks at both ends and
/// without a difference of case. A block starts with its begin line and ends with its end line.
pub fn split_blocks<'a>(lines: &'a [String], begin: &str, end: &str) -> Vec<Vec<&'a str>> {
    let mut blocks = Vec::new();
    let mut current: Vec<&str> = Vec::new();
    let mut inside = false;
    for line in lines {
        let trimmed = line.trim();
        if equals_ignore_case(trimmed, begin) {
            inside = true;
            current = vec![line.as_str()];
            continue;
        }
        if inside {
            current.push(line.as_str());
            if equals_ignore_case(trimmed, end) {
                blocks.push(std::mem::take(&mut current));
                inside = false;
            }
        }
    }
    blocks
}

/// The uppercase form of a text: each character has its simple uppercase form.
fn upper(text: &str) -> String {
    text.chars()
        .map(|character| {
            let mut mapped = character.to_uppercase();
            match (mapped.next(), mapped.next()) {
                (Some(single), None) => single,
                _ => character,
            }
        })
        .collect()
}

/// The name of the property of a line: the text before the first `:` and the first `;`, in uppercase.
pub fn property_name(line: &str) -> String {
    let mut prefix = line;
    if let Some(index) = prefix.find(':') {
        prefix = &prefix[..index];
    }
    if let Some(index) = prefix.find(';') {
        prefix = &prefix[..index];
    }
    upper(prefix.trim())
}

/// The value of the property of a line: the text after the first `:`. A written `\n` becomes a space.
pub fn property_value(line: &str) -> String {
    match line.find(':') {
        Some(index) if index + 1 < line.len() => line[index + 1..].replace("\\n", " ").trim().to_owned(),
        _ => String::new(),
    }
}

/// Decode the escapes of a value: `\n`, `\N`, `\,`, `\;` and `\\`. The result has no blank at both ends.
pub fn decode_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut characters = value.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\\'
            && let Some(next) = characters.peek().copied()
        {
            let replacement = match next {
                'n' | 'N' => Some('\n'),
                ',' => Some(','),
                ';' => Some(';'),
                '\\' => Some('\\'),
                _ => None,
            };
            if let Some(replacement) = replacement {
                out.push(replacement);
                characters.next();
                continue;
            }
        }
        out.push(character);
    }
    out.trim().to_owned()
}

/// The first value of a property, decoded. An empty value stops the search.
pub fn first_value(lines: &[&str], property: &str) -> String {
    let property = upper(property);
    for line in lines {
        if property_name(line) == property {
            return decode_value(&property_value(line));
        }
    }
    String::new()
}

/// Set a detail from the first line of a property that has a value.
fn set_first_value(props: &mut BTreeMap<String, String>, lines: &[&str], property: &str, label: &str) {
    let property = upper(property);
    for line in lines {
        if property_name(line) != property {
            continue;
        }
        let value = property_value(line);
        if !value.is_empty() {
            props.insert(label.to_owned(), value);
            return;
        }
    }
}

fn as_refs(lines: &[String]) -> Vec<&str> {
    lines.iter().map(String::as_str).collect()
}

/// The details of a vCard file.
pub fn vcard_metadata(data: &[u8]) -> BTreeMap<String, String> {
    let lines = unfold_lines(data);
    let cards = split_blocks(&lines, "BEGIN:VCARD", "END:VCARD");
    let mut props = BTreeMap::new();
    let Some(first) = cards.first() else {
        return props;
    };
    props.insert("Contacts".to_owned(), cards.len().to_string());
    set_first_value(&mut props, first, "FN", "Name");
    set_first_value(&mut props, first, "N", "Structured name");
    set_first_value(&mut props, first, "ORG", "Organization");
    set_first_value(&mut props, first, "TITLE", "Title");
    set_first_value(&mut props, first, "EMAIL", "Email");
    set_first_value(&mut props, first, "TEL", "Phone");
    set_first_value(&mut props, first, "URL", "URL");
    set_first_value(&mut props, first, "VERSION", "Version");
    props
}

/// The details of an iCalendar file.
pub fn calendar_metadata(data: &[u8]) -> BTreeMap<String, String> {
    let lines = unfold_lines(data);
    let refs = as_refs(&lines);
    let mut props = BTreeMap::new();
    set_first_value(&mut props, &refs, "VERSION", "Version");
    set_first_value(&mut props, &refs, "PRODID", "Product");
    set_first_value(&mut props, &refs, "CALSCALE", "Calendar scale");
    set_first_value(&mut props, &refs, "METHOD", "Method");
    set_first_value(&mut props, &refs, "X-WR-CALNAME", "Calendar name");
    set_first_value(&mut props, &refs, "X-WR-TIMEZONE", "Timezone");
    let count = |begin: &str| {
        lines
            .iter()
            .filter(|line| equals_ignore_case(line.trim(), begin))
            .count()
    };
    for (begin, label) in [
        ("BEGIN:VEVENT", "Events"),
        ("BEGIN:VTODO", "Todos"),
        ("BEGIN:VJOURNAL", "Journals"),
        ("BEGIN:VTIMEZONE", "Timezones"),
    ] {
        let total = count(begin);
        if total > 0 {
            props.insert(label.to_owned(), total.to_string());
        }
    }
    let events = split_blocks(&lines, "BEGIN:VEVENT", "END:VEVENT");
    if let Some(first) = events.first() {
        set_first_value(&mut props, first, "SUMMARY", "First event");
        set_first_value(&mut props, first, "DTSTART", "First start");
        set_first_value(&mut props, first, "DTEND", "First end");
    }
    props
}

/// The label of the container of a contact file.
pub fn contact_container_label(_extension: &str) -> &'static str {
    "vCard contact"
}

/// The label of the container of a calendar file.
pub fn calendar_container_label(extension: &str) -> &'static str {
    if extension == "ifb" {
        "iCalendar free/busy"
    } else {
        "iCalendar"
    }
}

/// One contact of the preview.
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct ContactRecord {
    /// The formatted name.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// The structured name, with the parts separated by spaces.
    #[serde(rename = "structuredName", skip_serializing_if = "String::is_empty")]
    pub structured: String,
    /// The organization.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub organization: String,
    /// The title or the role.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub title: String,
    /// The e-mail addresses.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub emails: Vec<String>,
    /// The phone numbers.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub phones: Vec<String>,
    /// The postal addresses.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
    /// The URLs.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<String>,
    /// The notes.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// Add a value to a list when it is not empty, not a duplicate and the list is below the limit.
fn append_unique(
    values: &mut Vec<String>,
    seen: &mut HashSet<(&'static str, String)>,
    field: &'static str,
    value: &str,
) {
    let value = value.trim();
    if value.is_empty() || values.len() >= MAX_CONTACT_VALUES_PER_FIELD {
        return;
    }
    if seen.insert((field, value.to_owned())) {
        values.push(value.to_owned());
    }
}

/// The text of a postal address: the parts without blanks and not empty, joined with `, `.
fn normalize_address(value: &str) -> String {
    value
        .split(';')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The contacts of a vCard file.
pub fn vcard_preview(data: &[u8]) -> Vec<ContactRecord> {
    let lines = unfold_lines(data);
    let blocks = split_blocks(&lines, "BEGIN:VCARD", "END:VCARD");
    let mut result = Vec::with_capacity(blocks.len());
    for block in blocks {
        let mut record = ContactRecord::default();
        let mut seen: HashSet<(&'static str, String)> = HashSet::new();
        for line in block {
            let name = property_name(line);
            let value = decode_value(&property_value(line));
            if value.is_empty() {
                continue;
            }
            match name.as_str() {
                "FN" => record.name = value,
                "N" => record.structured = value.replace(';', " "),
                "ORG" => record.organization = value.replace(';', " \u{b7} "),
                "TITLE" | "ROLE" => {
                    if record.title.is_empty() {
                        record.title = value;
                    }
                }
                "EMAIL" => append_unique(&mut record.emails, &mut seen, "EMAIL", &value),
                "TEL" => append_unique(&mut record.phones, &mut seen, "TEL", &value),
                "ADR" => append_unique(&mut record.addresses, &mut seen, "ADR", &normalize_address(&value)),
                "URL" => append_unique(&mut record.urls, &mut seen, "URL", &value),
                "NOTE" => append_unique(&mut record.notes, &mut seen, "NOTE", &value),
                _ => {}
            }
        }
        if record.name.is_empty() {
            record.name = record.structured.trim().to_owned();
        }
        result.push(record);
    }
    result
}

/// One event, task, free/busy period or journal entry of the preview.
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct CalendarRecord {
    /// The kind: `Event`, `Todo`, `Free/busy` or `Journal`.
    #[serde(rename = "type", skip_serializing_if = "String::is_empty")]
    pub kind: String,
    /// The identifier.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub uid: String,
    /// The summary.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub summary: String,
    /// The description.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// The place.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub location: String,
    /// The start.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub start: String,
    /// The end.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub end: String,
    /// The due date.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub due: String,
    /// The status.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub status: String,
    /// The organizer.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub organizer: String,
    /// The recurrence rule.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub recurrence: String,
}

/// The calendar of the preview.
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct CalendarPreview {
    /// The name of the calendar.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// The time zone.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub timezone: String,
    /// The method.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub method: String,
    /// The events.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub events: Vec<CalendarRecord>,
    /// The tasks.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub todos: Vec<CalendarRecord>,
    /// The free/busy periods.
    #[serde(rename = "freeBusy", skip_serializing_if = "Vec::is_empty")]
    pub free_busy: Vec<CalendarRecord>,
    /// The journal entries.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub journals: Vec<CalendarRecord>,
}

/// The calendar of an iCalendar file.
pub fn calendar_preview(data: &[u8]) -> CalendarPreview {
    let lines = unfold_lines(data);
    let refs = as_refs(&lines);
    let mut calendar = CalendarPreview {
        name: first_value(&refs, "X-WR-CALNAME"),
        timezone: first_value(&refs, "X-WR-TIMEZONE"),
        method: first_value(&refs, "METHOD"),
        ..CalendarPreview::default()
    };
    let specs: [(&str, &str, &str); 4] = [
        ("BEGIN:VEVENT", "END:VEVENT", "Event"),
        ("BEGIN:VTODO", "END:VTODO", "Todo"),
        ("BEGIN:VFREEBUSY", "END:VFREEBUSY", "Free/busy"),
        ("BEGIN:VJOURNAL", "END:VJOURNAL", "Journal"),
    ];
    for (begin, end, kind) in specs {
        let mut records = Vec::new();
        for block in split_blocks(&lines, begin, end) {
            records.push(CalendarRecord {
                kind: kind.to_owned(),
                uid: first_value(&block, "UID"),
                summary: first_value(&block, "SUMMARY"),
                description: decode_value(&first_value(&block, "DESCRIPTION")),
                location: decode_value(&first_value(&block, "LOCATION")),
                start: first_value(&block, "DTSTART"),
                end: first_value(&block, "DTEND"),
                due: first_value(&block, "DUE"),
                status: first_value(&block, "STATUS"),
                organizer: first_value(&block, "ORGANIZER"),
                recurrence: first_value(&block, "RRULE"),
            });
        }
        match kind {
            "Event" => calendar.events = records,
            "Todo" => calendar.todos = records,
            "Free/busy" => calendar.free_busy = records,
            _ => calendar.journals = records,
        }
    }
    calendar
}
