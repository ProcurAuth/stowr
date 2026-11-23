//! The schema of a SQLite database: the rows of `sqlite_schema` (page 1), and a small reader of `CREATE TABLE` that
//! finds the columns, their declared types, the primary key, the row id alias, `WITHOUT ROWID` and the virtual
//! generated columns. The reader never runs SQL. A table that it cannot read (a virtual table, an unusual
//! definition) is not in the list; the other tables stay readable.

use std::collections::BTreeMap;

use serde::Serialize;

use super::{Database, Flow, Value, invalid};
use crate::common::ctx::OpCtx;
use crate::common::error::Result;
use crate::pv_data::text::{lossy_each_byte, lower, upper};

/// One row of the schema table.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SchemaEntry {
    /// The type, in lower case (`table`, `index`, `view`, `trigger`).
    pub(crate) kind: String,
    /// The name.
    pub(crate) name: String,
    /// The name of the table.
    pub(crate) table: String,
    /// The root page, or 0.
    pub(crate) root_page: u32,
    /// The SQL text.
    pub(crate) sql: String,
}

/// One column of a table, as the answers show it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct ColumnInfo {
    /// The name.
    pub(crate) name: String,
    /// The declared type.
    #[serde(rename = "declaredType", skip_serializing_if = "String::is_empty")]
    pub(crate) declared_type: String,
    /// True for a column of the primary key.
    #[serde(rename = "primaryKey", skip_serializing_if = "std::ops::Not::not")]
    pub(crate) primary_key: bool,
}

/// One table, as the answers show it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct TableInfo {
    /// The name.
    pub(crate) name: String,
    /// Always `table`.
    #[serde(rename = "type")]
    pub(crate) kind: String,
    /// The visible columns.
    pub(crate) columns: Vec<ColumnInfo>,
}

/// One column of a table definition.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ColumnDefinition {
    /// The name.
    pub(crate) name: String,
    /// The declared type.
    pub(crate) declared_type: String,
    /// True for a column of the primary key.
    pub(crate) primary_key: bool,
    /// True for the `INTEGER PRIMARY KEY` column of a row id table: its value is the row id.
    pub(crate) row_id_alias: bool,
    /// True for a virtual generated column: the record does not store it.
    pub(crate) virtual_generated: bool,
}

/// A table definition: the visible table, the root page and the order of the stored values.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct TableDefinition {
    /// The table as the answers show it.
    pub(crate) info: TableInfo,
    /// The root page of its B-tree.
    pub(crate) root_page: u32,
    /// True for a `WITHOUT ROWID` table (an index B-tree).
    pub(crate) without_row_id: bool,
    /// The columns, in the order of the definition.
    pub(crate) columns: Vec<ColumnDefinition>,
    /// The index of the column of each stored value.
    pub(crate) storage_order: Vec<usize>,
}

impl TableDefinition {
    /// The values of a record by column name. The row id alias takes the row id when the record stores NULL.
    pub(crate) fn map_record(&self, row_id: i64, values: Vec<Value>) -> BTreeMap<String, Value> {
        let mut mapped = BTreeMap::new();
        let mut values = values.into_iter();
        for column_index in &self.storage_order {
            let value = values.next().unwrap_or(Value::Null);
            let Some(column) = self.columns.get(*column_index) else {
                continue;
            };
            let value = if column.row_id_alias && value == Value::Null {
                Value::Integer(row_id)
            } else {
                value
            };
            mapped.insert(column.name.clone(), value);
        }
        mapped
    }
}

/// The rows of the schema table (page 1). A row with fewer than five values is not in the list.
pub(crate) async fn read_schema(ctx: &OpCtx, database: &Database) -> Result<Vec<SchemaEntry>> {
    let mut entries = Vec::with_capacity(32);
    database
        .walk_table(ctx, 1, &mut |_: i64, values: Vec<Value>| {
            if values.len() < 5 {
                return Ok(Flow::Continue);
            }
            entries.push(SchemaEntry {
                kind: lower(&values[0].text()),
                name: values[1].text(),
                table: values[2].text(),
                root_page: values[3].integer().max(0) as u32,
                sql: values[4].text(),
            });
            Ok(Flow::Continue)
        })
        .await?;
    Ok(entries)
}

/// The tables of a database: the visible tables in the order of their lower-case names, and the definitions by
/// name. The tables `sqlite_*`, the tables without a root page and the tables that the reader cannot read are not in
/// the list.
pub(crate) async fn inspect_tables(
    ctx: &OpCtx,
    database: &Database,
) -> Result<(Vec<TableInfo>, BTreeMap<String, TableDefinition>)> {
    let entries = read_schema(ctx, database).await?;
    let mut definitions = BTreeMap::new();
    let mut infos = Vec::with_capacity(entries.len());
    for entry in entries {
        if entry.kind != "table" || lower(&entry.name).starts_with("sqlite_") || entry.root_page == 0 {
            continue;
        }
        let Ok(definition) = parse_create_table(&entry) else {
            continue;
        };
        infos.push(definition.info.clone());
        definitions.insert(definition.info.name.clone(), definition);
    }
    infos.sort_by_cached_key(|info| lower(&info.name).into_bytes());
    Ok((infos, definitions))
}

/// The tail of a text from a byte offset. An offset in the middle of a character gives the replacement characters
/// of the cut bytes.
fn tail(text: &str, start: usize) -> String {
    match text.get(start..) {
        Some(rest) => rest.to_owned(),
        None => lossy_each_byte(text.as_bytes().get(start..).unwrap_or(&[])),
    }
}

/// The part of a text between two byte offsets, with the same rule as [`tail`].
fn between(text: &str, start: usize, end: usize) -> String {
    match text.get(start..end) {
        Some(part) => part.to_owned(),
        None => lossy_each_byte(text.as_bytes().get(start..end).unwrap_or(&[])),
    }
}

/// The byte offset of the first occurrence of a needle.
fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// Split a definition list at the commas of the top level: not in quotes, brackets or parentheses. The parts are
/// trimmed; the empty parts are not in the list.
pub(crate) fn split_definition_list(value: &str) -> Vec<String> {
    let characters: Vec<char> = value.chars().collect();
    let mut parts = Vec::with_capacity(16);
    let mut start = 0;
    let mut depth = 0usize;
    let mut quote: Option<char> = None;
    let mut bracket = false;
    let mut escaped = false;
    for (index, current) in characters.iter().copied().enumerate() {
        if bracket {
            if current == ']' {
                bracket = false;
            }
            continue;
        }
        if let Some(open) = quote {
            if escaped {
                escaped = false;
                continue;
            }
            if current == open {
                if characters.get(index + 1) == Some(&open) {
                    escaped = true;
                    continue;
                }
                quote = None;
            }
            continue;
        }
        match current {
            '\'' | '"' | '`' => quote = Some(current),
            '[' => bracket = true,
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                let part: String = characters[start..index].iter().collect();
                parts.push(part.trim().to_owned());
                start = index + 1;
            }
            _ => {}
        }
    }
    let part: String = characters[start.min(characters.len())..].iter().collect();
    parts.push(part.trim().to_owned());
    parts.retain(|part| !part.is_empty());
    parts
}

/// Read the identifier at the start of a text: quoted with `"`, `'` or `` ` `` (a doubled quote is one quote), in
/// brackets, or up to a space, a comma or a parenthesis. Gives the name and the trimmed rest.
pub(crate) fn parse_identifier(value: &str) -> Option<(String, String)> {
    let trimmed = value.trim();
    let bytes = trimmed.as_bytes();
    let first = *bytes.first()?;
    match first {
        b'"' | b'\'' | b'`' => {
            let mut name = Vec::new();
            let mut index = 1;
            while index < bytes.len() {
                let current = bytes[index];
                if current == first {
                    if bytes.get(index + 1) == Some(&first) {
                        name.push(first);
                        index += 2;
                        continue;
                    }
                    let rest = tail(trimmed, index + 1);
                    return Some((lossy_each_byte(&name), rest.trim().to_owned()));
                }
                name.push(current);
                index += 1;
            }
            None
        }
        b'[' => {
            let end = bytes[1..].iter().position(|byte| *byte == b']')? + 1;
            let rest = tail(trimmed, end + 1);
            Some((between(trimmed, 1, end), rest.trim().to_owned()))
        }
        _ => {
            let end = bytes
                .iter()
                .position(|byte| b" \t\r\n,()".contains(byte))
                .unwrap_or(bytes.len());
            if end == 0 {
                return None;
            }
            let rest = tail(trimmed, end);
            Some((between(trimmed, 0, end), rest.trim().to_owned()))
        }
    }
}

/// True for a byte of a word of SQL: a digit, an upper-case letter or `_`.
fn word_byte(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_digit() || byte.is_ascii_uppercase()
}

/// True when a text has a keyword as a whole word, without regard to case.
pub(crate) fn contains_keyword(value: &str, keyword: &str) -> bool {
    let upper_value = upper(value);
    let haystack = upper_value.as_bytes();
    let keyword = keyword.to_ascii_uppercase();
    let needle = keyword.as_bytes();
    let Some(mut index) = find_bytes(haystack, needle) else {
        return false;
    };
    loop {
        let left_ok = index == 0 || !word_byte(haystack[index - 1]);
        let right = index + needle.len();
        let right_ok = right >= haystack.len() || !word_byte(haystack[right]);
        if left_ok && right_ok {
            return true;
        }
        match find_bytes(&haystack[index + 1..], needle) {
            Some(next) => index += next + 1,
            None => return false,
        }
    }
}

/// True for a space of SQL.
fn sql_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\r' | b'\n')
}

/// The declared type of a column: the words before the first constraint keyword at the top level.
pub(crate) fn declared_type(definition: &str) -> String {
    const CONSTRAINTS: [&str; 10] = [
        "PRIMARY",
        "NOT",
        "UNIQUE",
        "CHECK",
        "DEFAULT",
        "COLLATE",
        "REFERENCES",
        "GENERATED",
        "AS",
        "CONSTRAINT",
    ];
    let trimmed = definition.trim();
    let bytes = trimmed.as_bytes();
    let mut depth = 0usize;
    let mut quote: Option<u8> = None;
    let mut end = bytes.len();
    let mut index = 0;
    while index < bytes.len() {
        let current = bytes[index];
        if let Some(open) = quote {
            if current == open {
                if bytes.get(index + 1) == Some(&open) {
                    index += 2;
                    continue;
                }
                quote = None;
            }
            index += 1;
            continue;
        }
        match current {
            b'\'' | b'"' | b'`' => {
                quote = Some(current);
                index += 1;
                continue;
            }
            b'(' => {
                depth += 1;
                index += 1;
                continue;
            }
            b')' => {
                depth = depth.saturating_sub(1);
                index += 1;
                continue;
            }
            _ => {}
        }
        if depth == 0 && sql_space(current) {
            let mut word_start = index;
            while word_start < bytes.len() && sql_space(bytes[word_start]) {
                word_start += 1;
            }
            let mut word_end = word_start;
            while word_end < bytes.len() && (bytes[word_end].is_ascii_alphabetic() || bytes[word_end] == b'_') {
                word_end += 1;
            }
            if word_end > word_start {
                let word = trimmed[word_start..word_end].to_ascii_uppercase();
                if CONSTRAINTS.contains(&word.as_str()) {
                    end = index;
                    break;
                }
            }
        }
        index += 1;
    }
    between(trimmed, 0, end).trim().to_owned()
}

/// The end of a parenthesized list that starts at `open`: the offset of its closing parenthesis. Quotes hide the
/// parentheses.
fn closing_parenthesis(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth: i64 = 0;
    let mut quote: Option<u8> = None;
    let mut index = open;
    while index < bytes.len() {
        let current = bytes[index];
        if let Some(open_quote) = quote {
            if current == open_quote {
                if bytes.get(index + 1) == Some(&open_quote) {
                    index += 2;
                    continue;
                }
                quote = None;
            }
            index += 1;
            continue;
        }
        match current {
            b'\'' | b'"' | b'`' => quote = Some(current),
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
        index += 1;
    }
    None
}

/// The columns of a table constraint `PRIMARY KEY (...)`.
pub(crate) fn table_primary_key(segment: &str) -> Vec<String> {
    const KEYWORD: &str = "PRIMARY KEY";
    let upper_segment = upper(segment);
    let Some(position) = find_bytes(upper_segment.as_bytes(), KEYWORD.as_bytes()) else {
        return Vec::new();
    };
    let bytes = segment.as_bytes();
    let Some(after) = bytes.get(position + KEYWORD.len()..) else {
        return Vec::new();
    };
    let Some(open) = after.iter().position(|byte| *byte == b'(') else {
        return Vec::new();
    };
    let open = open + position + KEYWORD.len();
    let Some(close) = closing_parenthesis(bytes, open) else {
        return Vec::new();
    };
    split_definition_list(&between(segment, open + 1, close))
        .iter()
        .filter_map(|part| parse_identifier(part).map(|(name, _)| name))
        .collect()
}

/// Read a `CREATE TABLE` definition. A virtual table, a table without a column list and a table without a readable
/// column give a `422` error.
pub(crate) fn parse_create_table(entry: &SchemaEntry) -> Result<TableDefinition> {
    let sql = entry.sql.trim();
    if upper(sql).contains("CREATE VIRTUAL TABLE") || entry.root_page == 0 {
        return Err(invalid(
            "unsupported_sqlite_virtual_table",
            "virtual SQLite tables are not available in the embedded preview reader",
        ));
    }
    let bytes = sql.as_bytes();
    let Some(open) = bytes.iter().position(|byte| *byte == b'(') else {
        return Err(invalid(
            "invalid_sqlite_schema",
            "a SQLite table definition is missing its column list",
        ));
    };
    let Some(close) = closing_parenthesis(bytes, open) else {
        return Err(invalid(
            "invalid_sqlite_schema",
            "a SQLite table definition has an unterminated column list",
        ));
    };
    let segments = split_definition_list(&between(sql, open + 1, close));
    let mut columns: Vec<ColumnDefinition> = Vec::with_capacity(segments.len());
    let mut table_key: Vec<String> = Vec::new();
    for segment in &segments {
        let mut trimmed = segment.trim().to_owned();
        let mut upper_segment = upper(&trimmed);
        while upper_segment.starts_with("CONSTRAINT ") {
            let Some((_, remainder)) = parse_identifier(tail(&trimmed, "CONSTRAINT ".len()).trim()) else {
                break;
            };
            trimmed = remainder;
            upper_segment = upper(&trimmed);
        }
        if upper_segment.starts_with("PRIMARY KEY") {
            table_key = table_primary_key(&trimmed);
            continue;
        }
        if upper_segment.starts_with("UNIQUE")
            || upper_segment.starts_with("CHECK")
            || upper_segment.starts_with("FOREIGN KEY")
        {
            continue;
        }
        let Some((name, remainder)) = parse_identifier(&trimmed) else {
            continue;
        };
        if name.is_empty() {
            continue;
        }
        columns.push(ColumnDefinition {
            name,
            declared_type: declared_type(&remainder),
            primary_key: contains_keyword(&remainder, "PRIMARY KEY"),
            row_id_alias: false,
            virtual_generated: contains_keyword(&remainder, "GENERATED") && contains_keyword(&remainder, "VIRTUAL"),
        });
    }
    if columns.is_empty() {
        return Err(invalid(
            "invalid_sqlite_schema",
            "the SQLite table does not expose any readable columns",
        ));
    }
    let without_row_id = upper(&tail(sql, close + 1)).contains("WITHOUT ROWID");
    let mut column_index: BTreeMap<String, usize> = BTreeMap::new();
    for (index, column) in columns.iter().enumerate() {
        column_index.insert(lower(&column.name), index);
    }
    if table_key.is_empty() {
        table_key = columns
            .iter()
            .filter(|column| column.primary_key)
            .map(|column| column.name.clone())
            .collect();
    } else {
        for name in &table_key {
            if let Some(index) = column_index.get(&lower(name)) {
                columns[*index].primary_key = true;
            }
        }
    }
    if !without_row_id
        && table_key.len() == 1
        && let Some(index) = column_index.get(&lower(&table_key[0])).copied()
    {
        let normalized_type = upper(columns[index].declared_type.trim());
        let definition_upper = upper(&segments[index.min(segments.len() - 1)]);
        if normalized_type == "INTEGER" && !definition_upper.contains("PRIMARY KEY DESC") {
            columns[index].row_id_alias = true;
        }
    }
    let mut storage_order = Vec::with_capacity(columns.len());
    let mut stored = vec![false; columns.len()];
    if without_row_id {
        for name in &table_key {
            if let Some(index) = column_index.get(&lower(name)).copied()
                && !columns[index].virtual_generated
            {
                storage_order.push(index);
                stored[index] = true;
            }
        }
    }
    for (index, column) in columns.iter().enumerate() {
        if column.virtual_generated || stored[index] {
            continue;
        }
        storage_order.push(index);
    }
    let info_columns = columns
        .iter()
        .filter(|column| !column.virtual_generated)
        .map(|column| ColumnInfo {
            name: column.name.clone(),
            declared_type: column.declared_type.clone(),
            primary_key: column.primary_key,
        })
        .collect();
    Ok(TableDefinition {
        info: TableInfo {
            name: entry.name.clone(),
            kind: "table".to_owned(),
            columns: info_columns,
        },
        root_page: entry.root_page,
        without_row_id,
        columns,
        storage_order,
    })
}
