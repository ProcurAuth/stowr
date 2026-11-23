//! One page of the rows of a table: the search in the visible columns, the column filters, the optional sort and the
//! totals.
//!
//! Without a sort, the walk stops after the page unless the client asks for the exact totals (`count=1`). A sort
//! keeps the matching rows in memory with two limits: 150,000 rows and 64 MiB of values (a long text keeps 4,096
//! characters, a blob keeps only its size).

use std::collections::BTreeMap;

use serde::Serialize;

use super::schema::{ColumnInfo, TableDefinition};
use super::{Database, Flow, Value, blob_label, invalid, null_when_empty};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::pv_data::compare::{SortKey, matches_filter, stable_sort};
use crate::pv_data::text::lower;

/// The largest number of matching rows of a sort.
pub(crate) const MAX_SORT_ROWS: usize = 150_000;
/// The largest size of the matching rows of a sort: 64 MiB.
pub(crate) const MAX_SORT_BYTES: i64 = 64 << 20;
/// The number of characters of a text that a page shows; a longer text ends with `…`.
pub(crate) const MAX_DISPLAY_CHARS: usize = 4096;
/// The size that a sort counts for each row.
const SORT_ROW_OVERHEAD: i64 = 64;
/// The size that a sort counts for each value, in addition to the bytes of a text.
const SORT_VALUE_OVERHEAD: i64 = 24;

/// The request of a page.
#[derive(Clone, Copy, Debug)]
pub(crate) struct TableQuery<'a> {
    /// The page number, from 0.
    pub(crate) page: i64,
    /// The rows of a page (1 to 1000).
    pub(crate) page_size: i64,
    /// The search text, or an empty text.
    pub(crate) search: &'a str,
    /// The filters by column name.
    pub(crate) filters: &'a BTreeMap<String, String>,
    /// The sort column, or an empty text.
    pub(crate) sort_column: &'a str,
    /// `asc` or `desc`.
    pub(crate) sort_direction: &'a str,
    /// True to read each row for the exact totals.
    pub(crate) exact_totals: bool,
}

/// The table of a page.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub(crate) struct PageTable {
    /// The name.
    pub(crate) name: String,
    /// Always `table`.
    #[serde(rename = "type")]
    pub(crate) kind: String,
    /// The visible columns.
    #[serde(serialize_with = "null_when_empty")]
    pub(crate) columns: Vec<ColumnInfo>,
}

/// One page of a table.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub(crate) struct PageAnswer {
    /// The id of the session.
    pub(crate) id: String,
    /// The table.
    pub(crate) table: PageTable,
    /// The rows: the shown value of each visible column.
    pub(crate) rows: Vec<BTreeMap<String, Value>>,
    /// The page number.
    pub(crate) page: i64,
    /// The rows of a page.
    #[serde(rename = "pageSize")]
    pub(crate) page_size: i64,
    /// True when more matching rows follow.
    #[serde(rename = "hasMore")]
    pub(crate) has_more: bool,
    /// The matching rows, or -1 when the walk stopped after the page.
    #[serde(rename = "totalRows")]
    pub(crate) total_rows: i64,
    /// The rows of the table, or -1 when the walk stopped after the page.
    #[serde(rename = "sourceTotalRows")]
    pub(crate) source_total_rows: i64,
    /// The search text.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) query: String,
    /// The visible columns.
    #[serde(serialize_with = "null_when_empty")]
    pub(crate) columns: Vec<ColumnInfo>,
    /// True when `totalRows` is exact.
    #[serde(rename = "totalKnown")]
    pub(crate) total_known: bool,
    /// True when `sourceTotalRows` is exact.
    #[serde(rename = "sourceTotalKnown")]
    pub(crate) source_total_known: bool,
    /// The rows that the walk read.
    #[serde(rename = "scannedRows")]
    pub(crate) scanned_rows: i64,
}

impl PageAnswer {
    /// True when a value of the page has no JSON form (a float that is not finite).
    pub(crate) fn has_unencodable_value(&self) -> bool {
        self.rows.iter().any(|row| row.values().any(Value::is_unencodable))
    }
}

/// Cut a text after 4,096 characters and add `…`.
pub(crate) fn truncate_text(value: &str) -> String {
    if value.len() <= MAX_DISPLAY_CHARS {
        return value.to_owned();
    }
    match value.char_indices().nth(MAX_DISPLAY_CHARS) {
        Some((index, _)) => format!("{}…", &value[..index]),
        None => value.to_owned(),
    }
}

/// The value that a page shows: the label of a blob, a text cut after 4,096 characters, else the value.
fn display_value(value: Option<&Value>) -> Value {
    match value {
        None => Value::Null,
        Some(Value::Blob(bytes)) => Value::Text(blob_label(bytes.len())),
        Some(Value::BlobSize(size)) => Value::Text(blob_label(*size)),
        Some(Value::Text(text)) => Value::Text(truncate_text(text)),
        Some(other) => other.clone(),
    }
}

/// The shown values of the visible columns of a row.
fn output_row(columns: &[ColumnInfo], row: &BTreeMap<String, Value>) -> BTreeMap<String, Value> {
    columns
        .iter()
        .map(|column| (column.name.clone(), display_value(row.get(&column.name))))
        .collect()
}

/// Make a row of a sort smaller (a text keeps 4,096 characters, a blob keeps its size) and give the size that the
/// sort counts for it.
pub(crate) fn compact_sort_row(row: &mut BTreeMap<String, Value>) -> i64 {
    let mut size = SORT_ROW_OVERHEAD;
    for value in row.values_mut() {
        match value {
            Value::Text(text) => {
                let cut = truncate_text(text);
                size += cut.len() as i64;
                *text = cut;
            }
            Value::Blob(bytes) => *value = Value::BlobSize(bytes.len()),
            _ => {}
        }
        size += SORT_VALUE_OVERHEAD;
    }
    size
}

/// True when the search text is in the text of a visible column, without regard to case. The blobs do not count.
pub(crate) fn row_matches(row: &BTreeMap<String, Value>, columns: &[ColumnInfo], search: &str) -> bool {
    if search.is_empty() {
        return true;
    }
    let needle = lower(search);
    columns.iter().any(|column| {
        let value = row.get(&column.name);
        match value {
            Some(Value::Blob(_)) => false,
            Some(value) => lower(&value.text()).contains(&needle),
            None => "".contains(&needle),
        }
    })
}

/// True when a row passes each column filter. A blob passes only an empty filter.
pub(crate) fn row_matches_filters(row: &BTreeMap<String, Value>, filters: &BTreeMap<String, String>) -> bool {
    filters.iter().all(|(column, filter)| match row.get(column) {
        Some(Value::Blob(_)) => filter.trim().is_empty(),
        Some(value) => matches_filter(&value.text(), filter),
        None => matches_filter("", filter),
    })
}

/// A matching row of a sort.
struct SortRow {
    row_id: i64,
    values: BTreeMap<String, Value>,
}

/// Walk the rows of a table: the table B-tree, or the index B-tree of a `WITHOUT ROWID` table.
async fn walk_rows(
    ctx: &OpCtx,
    database: &Database,
    definition: &TableDefinition,
    visitor: &mut super::Visitor<'_>,
) -> Result<Flow> {
    if definition.without_row_id {
        database.walk_index(ctx, definition.root_page, visitor).await
    } else {
        database.walk_table(ctx, definition.root_page, visitor).await
    }
}

/// Sort the matching rows by the value of a column, then by the row id, and keep the order of equal rows.
fn sort_rows(rows: Vec<SortRow>, column: &str, descending: bool) -> Vec<SortRow> {
    let mut keyed: Vec<(SortKey, String, SortRow)> = rows
        .into_iter()
        .map(|row| {
            let text = row.values.get(column).map(Value::text).unwrap_or_default();
            (SortKey::new(&text), format!("{:020}", row.row_id), row)
        })
        .collect();
    stable_sort(&mut keyed, |left, right| {
        let comparison = left.0.compare(&right.0).then_with(|| left.1.cmp(&right.1));
        if descending {
            comparison.is_gt()
        } else {
            comparison.is_lt()
        }
    });
    keyed.into_iter().map(|(_, _, row)| row).collect()
}

/// The first and the last row number of a page, and the page and its size in their ranges.
fn page_bounds(page: i64, page_size: i64) -> (i64, i64, i64, i64) {
    let page = page.max(0);
    let page_size = page_size.clamp(1, 1000);
    let start = page.saturating_mul(page_size);
    (page, page_size, start, start.saturating_add(page_size))
}

/// Read one page of a table.
pub(crate) async fn query_table(
    ctx: &OpCtx,
    database: &Database,
    definition: &TableDefinition,
    query: &TableQuery<'_>,
) -> Result<PageAnswer> {
    let (page, page_size, start, end) = page_bounds(query.page, query.page_size);
    let columns = &definition.info.columns;
    let table = PageTable {
        name: definition.info.name.clone(),
        kind: definition.info.kind.clone(),
        columns: columns.clone(),
    };
    let mut source_total: i64 = 0;
    if !query.sort_column.is_empty() && matches!(query.sort_direction, "asc" | "desc") {
        let mut matches: Vec<SortRow> = Vec::with_capacity(((page_size * 4) as usize).min(MAX_SORT_ROWS));
        let mut buffered: i64 = 0;
        walk_rows(ctx, database, definition, &mut |row_id: i64, values: Vec<Value>| {
            ctx.check()?;
            source_total += 1;
            let mut mapped = definition.map_record(row_id, values);
            if !row_matches(&mapped, columns, query.search) || !row_matches_filters(&mapped, query.filters) {
                return Ok(Flow::Continue);
            }
            if matches.len() >= MAX_SORT_ROWS {
                return Err(invalid(
                    "sort_result_too_large",
                    format!(
                        "sorting is limited to {MAX_SORT_ROWS} matching SQLite rows; add filters to narrow the result"
                    ),
                ));
            }
            buffered += compact_sort_row(&mut mapped);
            if buffered > MAX_SORT_BYTES {
                return Err(invalid(
                    "sort_result_too_large",
                    format!(
                        "sorting is limited to {} MiB of matching SQLite data; add filters to narrow the result",
                        MAX_SORT_BYTES >> 20
                    ),
                ));
            }
            matches.push(SortRow { row_id, values: mapped });
            Ok(Flow::Continue)
        })
        .await?;
        let column = query.sort_column.to_owned();
        let descending = query.sort_direction == "desc";
        let sorted = tokio::task::spawn_blocking(move || sort_rows(matches, &column, descending))
            .await
            .map_err(|error| Error::internal(format!("sort of the SQLite rows: {error}")))?;
        let filtered_total = sorted.len() as i64;
        let from = (start.min(filtered_total)) as usize;
        let to = (end.min(filtered_total)) as usize;
        let rows = sorted[from..to]
            .iter()
            .map(|row| output_row(columns, &row.values))
            .collect();
        return Ok(PageAnswer {
            table,
            rows,
            page,
            page_size,
            has_more: filtered_total > end,
            total_rows: filtered_total,
            source_total_rows: source_total,
            total_known: true,
            source_total_known: true,
            scanned_rows: source_total,
            query: query.search.to_owned(),
            columns: columns.clone(),
            ..PageAnswer::default()
        });
    }
    let mut rows = Vec::with_capacity(page_size as usize);
    let mut filtered_total: i64 = 0;
    let flow = walk_rows(ctx, database, definition, &mut |row_id: i64, values: Vec<Value>| {
        ctx.check()?;
        source_total += 1;
        let mapped = definition.map_record(row_id, values);
        if !row_matches(&mapped, columns, query.search) || !row_matches_filters(&mapped, query.filters) {
            return Ok(Flow::Continue);
        }
        if filtered_total >= start && filtered_total < end {
            rows.push(output_row(columns, &mapped));
        }
        filtered_total += 1;
        if !query.exact_totals && filtered_total > end {
            return Ok(Flow::Stop);
        }
        Ok(Flow::Continue)
    })
    .await?;
    let stopped = flow == Flow::Stop;
    Ok(PageAnswer {
        table,
        rows,
        page,
        page_size,
        has_more: stopped || filtered_total > end,
        total_rows: if stopped { -1 } else { filtered_total },
        source_total_rows: if stopped { -1 } else { source_total },
        total_known: !stopped,
        source_total_known: !stopped,
        scanned_rows: source_total,
        query: query.search.to_owned(),
        columns: columns.clone(),
        ..PageAnswer::default()
    })
}
