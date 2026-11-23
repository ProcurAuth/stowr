//! The explicit counts of a document: the lines of a JSON text, the records and the columns of delimited text, and
//! the used rows and columns of the active sheet of a workbook. Each count reads the object in order from its
//! start, so a request for the details never does it.

use std::io::Read;
use std::sync::Arc;

use http::HeaderMap;

use super::delimited::{DocumentCount, PEEK_BYTES, detect_delimited_separator};
use super::package::{Fault, HardLimit, parse_entry};
use super::request::{Call, answer, key_extension, object_target, start};
use super::spreadsheet::{
    MAX_OBJECT_BYTES, MAX_SHEET_BYTES, excel_column_index, open_workbook, read_active_sheet_index, read_workbook_sheets,
};
use super::stream::ObjectStream;
use super::util::parse_i64;
use super::xml::{XmlEvent, XmlFault, XmlReader, attribute};
use crate::common::BoxFuture;
use crate::common::app::App;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Req, Response, json};
use crate::common::misc::parse_bounded_int;
use crate::instance::Instance;

/// The records and the columns of delimited text.
#[derive(Clone, Debug, Default)]
pub struct DelimitedSummary {
    /// The records with a value, without the header.
    pub rows: i64,
    /// The columns that have a value in at least one record.
    pub columns: i64,
    /// The headers of the answer of the storage.
    pub headers: HeaderMap,
    /// The bytes that the count read.
    pub total: i64,
}

/// The count of the lines of a text.
#[derive(Clone, Debug, Default)]
pub struct LineCount {
    /// The lines. A last line without a line end counts.
    pub lines: i64,
    /// The headers of the answer of the storage.
    pub headers: HeaderMap,
    /// The bytes that the count read.
    pub total: i64,
}

/// The sheets of a workbook and the size of the active sheet.
#[derive(Clone, Debug, Default)]
pub struct SpreadsheetSummary {
    /// The number of sheets that the preview can read.
    pub sheets: usize,
    /// The name of the active sheet.
    pub active_sheet: String,
    /// The last row with a value.
    pub rows: i64,
    /// The last column with a value.
    pub columns: i64,
}

/// The handler of `/api/document-count`: the count that the type of the document offers.
pub fn handle_document_count(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        match start(req) {
            Ok(call) => answer(document_count(&app, &call).await),
            Err(refusal) => *refusal,
        }
    })
}

async fn document_count(app: &App, req: &Call) -> Result<Response> {
    let target = object_target(app, req, "object key cannot be empty").await?;
    let instance = &target.instance;
    let extension = key_extension(&target.key);
    match extension.as_str() {
        "csv" | "tsv" | "tab" | "psv" => {
            let summary = inspect_delimited_summary(&req.ctx, instance, &target.key, &extension).await?;
            Ok(json(
                200,
                &DocumentCount {
                    kind: "delimited".to_owned(),
                    rows: summary.rows,
                    columns: summary.columns,
                    ..DocumentCount::default()
                },
            ))
        }
        "json" | "geojson" => {
            let count = count_object_lines(&req.ctx, instance, &target.key).await?;
            Ok(json(
                200,
                &DocumentCount {
                    kind: "lines".to_owned(),
                    lines: count.lines,
                    ..DocumentCount::default()
                },
            ))
        }
        "xlsx" | "xlsm" | "xltx" | "xltm" | "xlam" => {
            let known_size = parse_bounded_int(req.query.get("size"), 0, 0, MAX_OBJECT_BYTES);
            let summary = inspect_spreadsheet_dimensions(&req.ctx, instance, &target.key, known_size).await?;
            Ok(json(
                200,
                &DocumentCount {
                    kind: "spreadsheet".to_owned(),
                    sheet: summary.active_sheet,
                    rows: summary.rows,
                    columns: summary.columns,
                    ..DocumentCount::default()
                },
            ))
        }
        _ => Err(Error::api(
            400,
            "unsupported_count",
            "this document type does not expose an explicit count operation",
        )),
    }
}

// --- delimited text ----------------------------------------------------------------------------------------------

/// The counter of the records and of the columns of delimited text. It keeps one flag for each column and no value.
#[derive(Default)]
struct DelimitedCounter {
    delimiter: u8,
    row: Vec<bool>,
    non_empty_columns: Vec<bool>,
    field_non_empty: bool,
    field_started: bool,
    in_quotes: bool,
    after_quote: bool,
    skip_line_feed: bool,
    records: i64,
}

impl DelimitedCounter {
    fn new(delimiter: u8) -> Self {
        Self {
            delimiter,
            ..Self::default()
        }
    }

    fn finish_field(&mut self) {
        self.row.push(self.field_non_empty);
        self.field_non_empty = false;
        self.field_started = false;
    }

    fn finish_record(&mut self) {
        self.finish_field();
        if self.row.iter().any(|value| *value) {
            self.records += 1;
            if self.non_empty_columns.len() < self.row.len() {
                self.non_empty_columns.resize(self.row.len(), false);
            }
            for (index, value) in self.row.iter().enumerate() {
                if *value {
                    self.non_empty_columns[index] = true;
                }
            }
        }
        self.row.clear();
    }

    fn feed(&mut self, bytes: &[u8]) {
        for &value in bytes {
            if self.skip_line_feed {
                self.skip_line_feed = false;
                if value == b'\n' {
                    continue;
                }
            }
            if self.in_quotes {
                self.field_started = true;
                if value == b'"' {
                    self.in_quotes = false;
                    self.after_quote = true;
                } else if !matches!(value, b' ' | b'\t' | b'\r' | b'\n') {
                    self.field_non_empty = true;
                }
                continue;
            }
            if self.after_quote {
                if value == b'"' {
                    self.in_quotes = true;
                    self.after_quote = false;
                    self.field_non_empty = true;
                    continue;
                }
                self.after_quote = false;
            }
            match value {
                b'"' => {
                    if self.field_started {
                        self.field_non_empty = true;
                    } else {
                        self.field_started = true;
                        self.in_quotes = true;
                    }
                }
                _ if value == self.delimiter => self.finish_field(),
                b'\r' => {
                    self.finish_record();
                    self.skip_line_feed = true;
                }
                b'\n' => self.finish_record(),
                _ => {
                    self.field_started = true;
                    if value != b' ' && value != b'\t' {
                        self.field_non_empty = true;
                    }
                }
            }
        }
    }

    /// The rows (the records with a value, without the header) and the columns.
    fn finish(mut self) -> Result<(i64, i64)> {
        if self.in_quotes {
            return Err(Error::api(
                422,
                "invalid_delimited_file",
                "the delimited file ends inside a quoted field",
            ));
        }
        if self.field_started || self.field_non_empty || !self.row.is_empty() {
            self.finish_record();
        }
        let columns = i64::try_from(self.non_empty_columns.iter().filter(|value| **value).count()).unwrap_or(0);
        let rows = if self.records > 0 { self.records - 1 } else { 0 };
        Ok((rows, columns))
    }
}

async fn read_whole_object(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    what: &str,
) -> Result<(ObjectStream, HeaderMap)> {
    let response = instance.get(ctx, &instance.full_key(key), &HeaderMap::new()).await?;
    if !(200..300).contains(&response.status) {
        return Err(Error::internal(format!("read {what}: HTTP {}", response.status)));
    }
    Ok((ObjectStream::body(response.body), response.headers))
}

/// Count the records and the columns of a delimited object. It reads the object once, in order, and keeps one flag
/// for each column. The first record with a value is the header, as in the preview.
pub async fn inspect_delimited_summary(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    extension: &str,
) -> Result<DelimitedSummary> {
    let (mut stream, headers) = read_whole_object(ctx, instance, key, "delimited object").await?;
    let delimiter = match extension.to_lowercase().as_str() {
        "tsv" | "tab" => b'\t',
        "psv" => b'|',
        _ => detect_delimited_separator(&stream.peek(PEEK_BYTES).await?),
    };
    let mut counter = DelimitedCounter::new(delimiter);
    let mut total: i64 = 0;
    while let Some(chunk) = stream.take_chunk().await? {
        total += i64::try_from(chunk.len()).unwrap_or(0);
        counter.feed(&chunk);
    }
    let (rows, columns) = counter.finish()?;
    Ok(DelimitedSummary {
        rows,
        columns,
        headers,
        total,
    })
}

/// Count the lines of an object. A last line without a line end counts.
pub async fn count_object_lines(ctx: &OpCtx, instance: &Arc<Instance>, key: &str) -> Result<LineCount> {
    let response = instance.get(ctx, &instance.full_key(key), &HeaderMap::new()).await?;
    if !(200..300).contains(&response.status) {
        return Err(Error::internal(format!("read text object: HTTP {}", response.status)));
    }
    let mut stream = ObjectStream::body(response.body);
    let mut lines: i64 = 0;
    let mut total: i64 = 0;
    let mut last = 0u8;
    while let Some(chunk) = stream.take_chunk().await? {
        total += i64::try_from(chunk.len()).unwrap_or(0);
        lines += i64::try_from(chunk.iter().filter(|byte| **byte == b'\n').count()).unwrap_or(0);
        last = chunk.last().copied().unwrap_or(last);
    }
    if total > 0 && last != b'\n' {
        lines += 1;
    }
    Ok(LineCount {
        lines,
        headers: response.headers,
        total,
    })
}

// --- workbooks ---------------------------------------------------------------------------------------------------

/// The last row and the last column with a value of a sheet, from the XML of the sheet.
pub fn count_worksheet_dimensions(reader: &mut dyn Read) -> Result<(i64, i64)> {
    count_dimensions_inner(reader).map_err(|fault| match fault {
        Fault::Limit => Error::api(
            413,
            "sheet_too_large",
            format!(
                "the worksheet XML exceeds {} MiB once decompressed",
                MAX_SHEET_BYTES >> 20
            ),
        ),
        _ => Error::api(422, "invalid_sheet", "unable to inspect worksheet dimensions"),
    })
}

/// True when a cell has a formula or a value with text.
fn cell_has_content<R: Read>(xml: &mut XmlReader<R>) -> std::result::Result<bool, XmlFault> {
    let mut depth = 1usize;
    let mut has_content = false;
    while depth > 0 {
        match xml.next_event()? {
            None => return Err(XmlFault::Syntax("unexpected EOF".to_owned())),
            Some(XmlEvent::Start { name, .. }) => {
                depth += 1;
                match name.as_str() {
                    // A formula is meaningful even when the workbook has no value for it.
                    "f" => has_content = true,
                    "v" | "t" => {
                        let value = xml.element_text()?;
                        depth -= 1;
                        if !value.trim().is_empty() {
                            has_content = true;
                        }
                    }
                    _ => {}
                }
            }
            Some(XmlEvent::End { .. }) => depth -= 1,
            Some(XmlEvent::Text(_)) => {}
        }
    }
    Ok(has_content)
}

fn count_worksheet_row<R: Read>(xml: &mut XmlReader<R>) -> std::result::Result<(bool, i64), XmlFault> {
    let mut depth = 1usize;
    let mut visible = false;
    let mut maximum_column: i64 = 0;
    let mut fallback: i64 = 0;
    while depth > 0 {
        match xml.next_event()? {
            None => return Err(XmlFault::Syntax("unexpected EOF".to_owned())),
            Some(XmlEvent::Start { name, attrs }) => {
                if name == "c" {
                    let mut column = fallback;
                    if let Some(parsed) = attribute(&attrs, "r").and_then(excel_column_index) {
                        column = parsed;
                    }
                    fallback = column.wrapping_add(1);
                    if cell_has_content(xml)? {
                        visible = true;
                        if column.wrapping_add(1) > maximum_column {
                            maximum_column = column.wrapping_add(1);
                        }
                    }
                    continue;
                }
                depth += 1;
            }
            Some(XmlEvent::End { .. }) => depth -= 1,
            Some(XmlEvent::Text(_)) => {}
        }
    }
    Ok((visible, maximum_column))
}

fn count_dimensions_inner(reader: &mut dyn Read) -> std::result::Result<(i64, i64), Fault> {
    let mut xml = XmlReader::new(HardLimit::new(reader, MAX_SHEET_BYTES + 1));
    let mut maximum_row: i64 = 0;
    let mut maximum_column: i64 = 0;
    let mut fallback_row: i64 = 0;
    while let Some(event) = xml.next_event()? {
        let XmlEvent::Start { name, attrs } = event else {
            continue;
        };
        if name != "row" {
            continue;
        }
        fallback_row += 1;
        let mut row_number = fallback_row;
        for (attribute_name, value) in &attrs {
            if attribute_name != "r" {
                continue;
            }
            if let Some(parsed) = parse_i64(value.trim()).filter(|parsed| *parsed > 0) {
                row_number = parsed;
                fallback_row = parsed;
            }
        }
        let (visible, row_maximum) = count_worksheet_row(&mut xml)?;
        if visible && row_number > maximum_row {
            maximum_row = row_number;
        }
        if row_maximum > maximum_column {
            maximum_column = row_maximum;
        }
    }
    Ok((maximum_row, maximum_column))
}

/// The sheets of a workbook, the active sheet and the number of its rows and columns with a value. It scans the
/// whole active sheet.
pub async fn inspect_spreadsheet_dimensions(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    known_size: i64,
) -> Result<SpreadsheetSummary> {
    let package = open_workbook(
        ctx,
        instance,
        key,
        known_size,
        "spreadsheet dimensions require a known non-zero object size",
        &format!(
            "spreadsheet dimension scans are limited to {} MiB",
            MAX_OBJECT_BYTES >> 20
        ),
    )
    .await?;
    let sheets = read_workbook_sheets(&package).await?;
    let mut summary = SpreadsheetSummary {
        sheets: sheets.len(),
        ..SpreadsheetSummary::default()
    };
    if sheets.is_empty() {
        return Ok(summary);
    }
    let active = read_active_sheet_index(&package, &sheets).await?;
    let sheet = &sheets[active];
    summary.active_sheet.clone_from(&sheet.name);
    let Some(part) = package.part(&sheet.target) else {
        return Ok(summary);
    };
    let stream = package.reader.open_entry(part).await?;
    let (rows, columns) = parse_entry(stream, count_worksheet_dimensions).await??;
    summary.rows = rows;
    summary.columns = columns;
    Ok(summary)
}

/// The sheets of a workbook and the active sheet, without the used rows and columns: they need a scan of the whole
/// sheet, and the details never do it. Gives the headers and the size that the reads found.
pub async fn inspect_spreadsheet_summary(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    known_size: i64,
) -> Result<(SpreadsheetSummary, HeaderMap, i64)> {
    let package = open_workbook(
        ctx,
        instance,
        key,
        known_size,
        "spreadsheet details require a known non-zero object size",
        &format!("spreadsheet details are limited to {} MiB", MAX_OBJECT_BYTES >> 20),
    )
    .await?;
    let sheets = read_workbook_sheets(&package).await?;
    let mut summary = SpreadsheetSummary {
        sheets: sheets.len(),
        ..SpreadsheetSummary::default()
    };
    let headers = package.reader.source.headers();
    let size = package.reader.source.size_or_zero();
    if sheets.is_empty() {
        return Ok((summary, headers, size));
    }
    let active = read_active_sheet_index(&package, &sheets).await?;
    summary.active_sheet.clone_from(&sheets[active].name);
    Ok((summary, headers, size))
}

#[cfg(test)]
#[path = "count_tests.rs"]
mod tests;
