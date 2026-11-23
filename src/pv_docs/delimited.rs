// SPDX-License-Identifier: MIT OR Apache-2.0
//! The preview of delimited text (CSV, TSV, PSV): pages of records with a signed cursor.
//!
//! A page reads the object in order from the byte offset of the cursor. The first page finds the delimiter in a
//! sample of 128 KiB (the extension `tsv`, `tab` and `psv` fix it), reads the header, and sets the number of
//! columns. A cell has at most 64 KiB. The cursor keeps the offset after the last record that the page gave.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::csv::{CsvFailure, CsvReader};
use super::request::{Call, answer, key_extension, object_target, start};
use super::stream::ObjectStream;
use super::util::lossy_bytes;
use crate::common::BoxFuture;
use crate::common::app::App;
use crate::common::error::{Error, Result};
use crate::common::http::{Req, Response, json};
use crate::common::misc::parse_bounded_int;
use crate::instance::cursor::{decode_signed_cursor, encode_signed_cursor, signed_cursor_scope};
use crate::instance::range::{ObjectVersion, WindowReader};

/// The default number of records in a page.
pub const DEFAULT_PAGE_SIZE: i64 = 100;
/// The largest number of records in a page.
pub const MAX_PAGE_SIZE: i64 = 1000;
/// The most columns of a page.
pub const MAX_COLUMNS: usize = 200;
/// The most bytes of a cell.
pub const MAX_CELL_BYTES: usize = 64 * 1024;
/// The sample that finds the delimiter.
pub const PEEK_BYTES: usize = 128 * 1024;

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}

/// The state that a page keeps for the next page.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DelimitedCursor {
    /// The offset of the next record.
    #[serde(rename = "o")]
    pub offset: i64,
    /// The number of records before the offset, with the header.
    #[serde(rename = "r")]
    pub records: i64,
    /// The number of columns.
    #[serde(rename = "c")]
    pub columns: i64,
    /// The delimiter, as a character code.
    #[serde(rename = "d")]
    pub comma: u32,
    /// The scope of the cursor.
    #[serde(rename = "s")]
    pub scope: String,
    /// The version of the object.
    #[serde(rename = "v", default)]
    pub version: ObjectVersion,
}

/// A page of records.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DelimitedPage {
    /// The names of the columns, on the first page.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<String>,
    /// The records.
    pub rows: Vec<Vec<String>>,
    /// The number of each record, from 1 for the header.
    #[serde(rename = "rowNumbers")]
    pub row_numbers: Vec<i64>,
    /// The cursor of the next page.
    #[serde(rename = "nextCursor", default, skip_serializing_if = "String::is_empty")]
    pub next_cursor: String,
    /// True for the last page.
    pub done: bool,
    /// The number of records that the page can have.
    #[serde(rename = "pageSize")]
    pub page_size: i64,
    /// The number of the first record of the page.
    #[serde(rename = "startRow")]
    pub start_row: i64,
    /// The number of the last record of the page.
    #[serde(rename = "endRow")]
    pub end_row: i64,
    /// The delimiter.
    pub delimiter: String,
    /// True when a record has more columns than the page shows.
    #[serde(rename = "truncatedColumns", default, skip_serializing_if = "is_false")]
    pub truncated_columns: bool,
    /// True when a cell is cut.
    #[serde(rename = "truncatedCells", default, skip_serializing_if = "is_false")]
    pub truncated_cells: bool,
}

/// The answer of `/api/document-count`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct DocumentCount {
    /// The kind of count: `delimited`, `lines` or `spreadsheet`.
    pub kind: String,
    /// The active sheet.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub sheet: String,
    /// The number of lines.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub lines: i64,
    /// The number of rows.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub rows: i64,
    /// The number of columns.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub columns: i64,
}

/// True for the delimiters that a cursor can have.
pub fn valid_comma(value: u32) -> bool {
    matches!(char::from_u32(value), Some(',' | ';' | '\t' | '|'))
}

/// The cursor of a page. An empty text gives `None`.
pub fn decode_delimited_cursor(raw: &str, expected_scope: &str) -> Result<Option<DelimitedCursor>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let cursor: DelimitedCursor = decode_signed_cursor(raw)
        .ok()
        .filter(|cursor: &DelimitedCursor| {
            cursor.scope == expected_scope
                && cursor.offset >= 0
                && cursor.records >= 0
                && cursor.columns >= 1
                && usize::try_from(cursor.columns).is_ok_and(|columns| columns <= MAX_COLUMNS)
                && valid_comma(cursor.comma)
        })
        .ok_or_else(|| {
            Error::api(
                400,
                "invalid_cursor",
                "invalid or expired delimited continuation cursor",
            )
        })?;
    Ok(Some(cursor))
}

/// The count of the fields of the first records of a sample, for one delimiter. At most `limit` records.
fn sample_field_counts(sample: &[u8], delimiter: u8, limit: usize) -> Vec<usize> {
    let mut counts: Vec<usize> = Vec::with_capacity(limit);
    let mut fields = 1usize;
    let mut in_quotes = false;
    let mut after_quote = false;
    let mut row_has_content = false;
    let mut index = 0;
    while index < sample.len() && counts.len() < limit {
        let value = sample[index];
        if in_quotes {
            if value == b'"' {
                in_quotes = false;
                after_quote = true;
            } else if !matches!(value, b' ' | b'\t' | b'\r' | b'\n') {
                row_has_content = true;
            }
            index += 1;
            continue;
        }
        if after_quote {
            if value == b'"' {
                in_quotes = true;
                after_quote = false;
                row_has_content = true;
                index += 1;
                continue;
            }
            after_quote = false;
        }
        match value {
            b'"' => in_quotes = true,
            _ if value == delimiter => fields += 1,
            b'\r' => {
                if index + 1 < sample.len() && sample[index + 1] == b'\n' {
                    index += 1;
                }
                if row_has_content || fields > 1 {
                    counts.push(fields);
                }
                fields = 1;
                row_has_content = false;
            }
            b'\n' => {
                if row_has_content || fields > 1 {
                    counts.push(fields);
                }
                fields = 1;
                row_has_content = false;
            }
            _ => {
                if value != b' ' && value != b'\t' {
                    row_has_content = true;
                }
            }
        }
        index += 1;
    }
    if counts.len() < limit && (row_has_content || fields > 1) {
        counts.push(fields);
    }
    counts
}

/// The delimiter of a sample of text: the one that gives the most records with the same number of fields, then the
/// most fields. The comma wins a tie.
pub fn detect_delimited_separator(sample: &[u8]) -> u8 {
    let candidates = *b",;\t|";
    let mut best = candidates[0];
    let mut best_score: i64 = -1;
    for candidate in candidates {
        let counts = sample_field_counts(sample, candidate, 25);
        let mut frequencies: HashMap<usize, i64> = HashMap::new();
        let mut maximum: i64 = 0;
        for count in counts {
            if count <= 1 {
                continue;
            }
            *frequencies.entry(count).or_insert(0) += 1;
            maximum = maximum.max(i64::try_from(count).unwrap_or(i64::MAX));
        }
        let mode = frequencies.values().copied().max().unwrap_or(0);
        let score = mode * 100 + maximum;
        if score > best_score {
            best = candidate;
            best_score = score;
        }
    }
    best
}

/// The delimiter of an object: fixed by the extension `tsv`, `tab` or `psv`, else found in the sample.
pub fn delimiter_for_object(key: &str, sample: &[u8]) -> u8 {
    match key_extension(key).as_str() {
        "tsv" | "tab" => b'\t',
        "psv" => b'|',
        _ => detect_delimited_separator(sample),
    }
}

/// The text of a record is not empty for a person: at least one field has a character other than white space.
fn record_visible(record: &[Vec<u8>]) -> bool {
    record.iter().any(|field| !lossy_bytes(field).trim().is_empty())
}

/// A cell: at most 64 KiB, cut at the start of a character, with `…` after a cut.
fn truncate_cell(value: &[u8]) -> (String, bool) {
    if value.len() <= MAX_CELL_BYTES {
        return (lossy_bytes(value), false);
    }
    let mut end = MAX_CELL_BYTES;
    while end > 0 && (value[end] & 0xC0) == 0x80 {
        end -= 1;
    }
    let mut text = lossy_bytes(&value[..end]);
    text.push('…');
    (text, true)
}

/// The names of the columns: the first record without the mark of byte order and the white space, `column_N` for
/// an empty name, and `_N` for the second copy of a name and the next ones.
fn normalize_header(header: &[Vec<u8>], columns: usize) -> Vec<String> {
    let mut out = Vec::with_capacity(columns);
    let mut seen: HashMap<String, usize> = HashMap::with_capacity(columns);
    for index in 0..columns {
        let mut base = String::new();
        if let Some(field) = header.get(index) {
            let field = field.strip_prefix(&[0xEF, 0xBB, 0xBF][..]).unwrap_or(field);
            base = lossy_bytes(field).trim().to_owned();
        }
        if base.is_empty() {
            base = format!("column_{}", index + 1);
        }
        let count = seen.entry(base.clone()).or_insert(0);
        *count += 1;
        if *count > 1 {
            out.push(format!("{base}_{count}"));
        } else {
            out.push(base);
        }
    }
    out
}

/// A record with exactly `columns` cells. The flags tell a record with more fields and a cut cell.
fn normalize_record(record: &[Vec<u8>], columns: usize) -> (Vec<String>, bool, bool) {
    let mut out = vec![String::new(); columns];
    let truncated_columns = record.len() > columns;
    let mut truncated_cells = false;
    for (index, slot) in out.iter_mut().enumerate() {
        let Some(field) = record.get(index) else {
            break;
        };
        let (value, truncated) = truncate_cell(field);
        *slot = value;
        truncated_cells = truncated_cells || truncated;
    }
    (out, truncated_columns, truncated_cells)
}

fn invalid_delimited(message: impl Into<String>) -> Error {
    Error::api(422, "invalid_delimited_file", message)
}

/// The error of a failed read of a record: a bad text, or a failed read of the object.
fn read_failure(failure: CsvFailure) -> Error {
    match failure {
        CsvFailure::Parse(message) => invalid_delimited(message),
        CsvFailure::Source(error @ (Error::Canceled | Error::Timeout)) => error,
        CsvFailure::Source(error) => invalid_delimited(error.public_message()),
    }
}

/// The handler of `/api/delimited`: a page of records.
pub fn handle_delimited(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        match start(req) {
            Ok(call) => answer(delimited_page(&app, &call).await),
            Err(refusal) => *refusal,
        }
    })
}

struct Entry {
    values: Vec<Vec<u8>>,
    number: i64,
}

async fn delimited_page(app: &App, req: &Call) -> Result<Response> {
    let target = object_target(app, req, "delimited object key cannot be empty").await?;
    let instance = &target.instance;
    let page_size = parse_bounded_int(req.query.get("pageSize"), DEFAULT_PAGE_SIZE, 1, MAX_PAGE_SIZE);
    let page_len = usize::try_from(page_size).unwrap_or(1);
    let scope = signed_cursor_scope("delimited", &instance.cfg.id, &target.key);
    let decoded = decode_delimited_cursor(req.query.get("cursor"), &scope)?;
    let continuing = decoded.is_some();
    let cursor = decoded.unwrap_or_default();
    let mut version = cursor.version.clone();
    if version.is_empty() {
        version.etag.clone_from(&target.etag);
    }
    let reader = WindowReader::open_version(&req.ctx, instance, &target.key, cursor.offset, &version).await?;
    let mut stream = ObjectStream::windows(reader);
    let mut comma = u8::try_from(cursor.comma).unwrap_or(b',');
    if !continuing {
        let sample = stream.peek(PEEK_BYTES).await?;
        comma = delimiter_for_object(&target.key, &sample);
    }
    let delimiter = char::from(comma).to_string();
    let mut header: Vec<Vec<u8>> = Vec::new();
    let mut committed_offset = cursor.offset;
    let mut committed_records = cursor.records;
    let mut columns = usize::try_from(cursor.columns).unwrap_or(0);
    let mut parser = CsvReader::new(&mut stream, comma);
    if !continuing {
        match parser.read().await {
            Ok(Some(record)) => {
                header = record;
                committed_offset = parser.input_offset();
                committed_records = 1;
                columns = header.len();
            }
            Ok(None) => {
                return Ok(json(
                    200,
                    &DelimitedPage {
                        done: true,
                        page_size,
                        delimiter,
                        ..DelimitedPage::default()
                    },
                ));
            }
            Err(failure) => return Err(read_failure(failure)),
        }
    }
    let mut entries: Vec<Entry> = Vec::with_capacity(page_len.min(1024));
    let mut done = false;
    while entries.len() < page_len {
        let record = match parser.read().await {
            Ok(Some(record)) => record,
            Ok(None) => {
                done = true;
                break;
            }
            Err(failure) => return Err(read_failure(failure)),
        };
        let number = committed_records + 1;
        committed_offset = cursor.offset + parser.input_offset();
        committed_records = number;
        if !record_visible(&record) {
            continue;
        }
        if !continuing && record.len() > columns {
            columns = record.len();
        }
        entries.push(Entry { values: record, number });
    }
    let mut truncated_columns = false;
    let mut truncated_cells = false;
    if columns < 1 {
        columns = 1;
    }
    if columns > MAX_COLUMNS {
        columns = MAX_COLUMNS;
        truncated_columns = true;
    }
    let headers = if continuing {
        Vec::new()
    } else {
        normalize_header(&header, columns)
    };
    let mut rows: Vec<Vec<String>> = Vec::with_capacity(entries.len());
    let mut row_numbers: Vec<i64> = Vec::with_capacity(entries.len());
    for entry in &entries {
        let (row, extra_columns, extra_cells) = normalize_record(&entry.values, columns);
        truncated_columns = truncated_columns || extra_columns;
        truncated_cells = truncated_cells || extra_cells;
        rows.push(row);
        row_numbers.push(entry.number);
    }
    if !done && entries.len() == page_len {
        // Look for the next record that a person sees, or the end. The empty records go into the cursor, so
        // that the next page does not read them again. The record that is visible stays for the next page.
        loop {
            let before_offset = cursor.offset + parser.input_offset();
            let before_records = committed_records;
            let record = match parser.read().await {
                Ok(Some(record)) => record,
                Ok(None) => {
                    done = true;
                    break;
                }
                Err(failure) => return Err(read_failure(failure)),
            };
            if record_visible(&record) {
                committed_offset = before_offset;
                committed_records = before_records;
                break;
            }
            committed_offset = cursor.offset + parser.input_offset();
            committed_records += 1;
        }
    }
    let mut page = DelimitedPage {
        headers,
        rows,
        row_numbers,
        done,
        page_size,
        delimiter,
        truncated_columns,
        truncated_cells,
        ..DelimitedPage::default()
    };
    if let (Some(first), Some(last)) = (page.row_numbers.first(), page.row_numbers.last()) {
        page.start_row = *first;
        page.end_row = *last;
    }
    if !done {
        page.next_cursor = encode_signed_cursor(&DelimitedCursor {
            offset: committed_offset,
            records: committed_records,
            columns: i64::try_from(columns).unwrap_or(0),
            comma: u32::from(comma),
            scope,
            version: stream.version(),
        })?;
    }
    Ok(json(200, &page))
}

#[cfg(test)]
#[path = "delimited_tests.rs"]
mod tests;
