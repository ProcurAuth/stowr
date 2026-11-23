//! The preview of an XLSX or XLSM workbook on the server: the list of the sheets, and pages of one sheet with a
//! filter, a search and a sort.
//!
//! The reader opens the central directory of the package over exact ranges and reads only the parts that it
//! needs: the workbook, its relations, the shared strings, the styles and the selected sheet. The sheet is a
//! stream, and the page keeps the rows of the page only. The limits are in the constants of this file.

use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::compare::{compare_values, matches_filter};
use super::package::{Fault, HardLimit, Package, Truncate, join_path, open_sized_source, parse_entry};
use super::request::{Call, answer, key_extension, read_instance, required_key, start};
use super::util::{lower, parse_float, parse_i64, parse_integer, quote, stable_sort, truncate_utf8_bytes};
use super::xml::{XmlEvent, XmlFault, XmlReader, last_attribute};
use crate::access;
use crate::archive::zip::ZipEntry;
use crate::common::BoxFuture;
use crate::common::app::App;
use crate::common::error::{Error, Result};
use crate::common::http::{Req, Response, json};
use crate::common::misc::{CancelToken, parse_bounded_int};
use crate::common::time::Timestamp;
use crate::instance::range::RangeSource;

/// The largest workbook: 512 MiB.
pub const MAX_OBJECT_BYTES: i64 = 512 << 20;
/// The most rows that a read of a sheet keeps in count.
pub const MAX_ROWS: usize = 2_000_000;
/// The most columns of a page.
pub const MAX_COLUMNS: i64 = 200;
/// The most matching rows of a sort.
pub const MAX_SORT_ROWS: usize = 150_000;
/// The most shared strings.
pub const MAX_SHARED_STRINGS: usize = 2_000_000;
/// The most bytes of all the shared strings.
pub const MAX_SHARED_STRING_BYTES: usize = 128 << 20;
/// The most bytes of the XML of a sheet, once decompressed.
pub const MAX_SHEET_BYTES: u64 = 256 << 20;
/// The most bytes of a cell.
pub const MAX_CELL_BYTES: usize = 32 << 10;
/// The most bytes that the cells of a sheet can take from the shared strings. A cell with a shared string uses
/// the entry of the table, so the response and the work grow with the references, not with the table.
pub const MAX_REFERENCED_BYTES: i64 = 1 << 30;
/// The most bytes of a page.
pub const MAX_PAGE_BYTES: usize = 32 << 20;
/// The number of steps between two checks of the cancellation.
pub const CANCEL_CHECK_EVERY: u64 = 1024;
/// The most bytes of the small parts of a workbook (the workbook, its relations, the styles).
pub const MAX_SMALL_PART_BYTES: u64 = 32 << 20;

const BINARY_EXCEL_SIGNATURE: [u8; 8] = [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1];

fn is_false(value: &bool) -> bool {
    !*value
}

/// A sheet of a workbook.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SheetInfo {
    /// The place of the sheet in the list of the sheets that the preview can read.
    pub index: i64,
    /// The name.
    pub name: String,
    /// `hidden` or `veryhidden` for a hidden sheet.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub hidden: String,
    /// The name of the part of the sheet in the package.
    #[serde(skip)]
    pub target: String,
}

/// A row of a page.
#[derive(Debug, Serialize, Deserialize)]
pub struct SheetRow {
    /// The number of the row in the sheet.
    pub number: i64,
    /// The cells, one for each column of the page.
    pub cells: Vec<String>,
}

/// The answer of `/api/spreadsheet`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SheetPage {
    /// The instance.
    pub instance: String,
    /// The key.
    pub key: String,
    /// The sheets.
    pub sheets: Vec<SheetInfo>,
    /// The sheet of the page.
    pub sheet: SheetInfo,
    /// The names of the columns.
    pub headers: Vec<String>,
    /// The rows of the page.
    pub rows: Vec<SheetRow>,
    /// The number of rows that match.
    #[serde(rename = "totalRows")]
    pub total_rows: i64,
    /// The number of rows with a cell that has a value.
    #[serde(rename = "sourceRows")]
    pub source_rows: i64,
    /// The number of the page, from 0.
    pub page: i64,
    /// The size of the page.
    #[serde(rename = "pageSize")]
    pub page_size: i64,
    /// True when the sheet has more rows than the reader counts.
    #[serde(rename = "truncatedRows", default, skip_serializing_if = "is_false")]
    pub truncated_rows: bool,
    /// True when the sheet has more columns than the page shows.
    #[serde(rename = "truncatedColumns", default, skip_serializing_if = "is_false")]
    pub truncated_columns: bool,
    /// True when a cell is cut.
    #[serde(rename = "truncatedCells", default, skip_serializing_if = "is_false")]
    pub truncated_cells: bool,
    /// True for a file with macros: the preview ignores them.
    #[serde(rename = "macrosIgnored", default, skip_serializing_if = "is_false")]
    pub macros_ignored: bool,
}

/// The number formats of the cell styles that show a date.
#[derive(Debug, Default)]
pub struct Styles {
    /// The styles (the positions in `cellXfs`) that show a date.
    pub date_styles: HashSet<i64>,
}

/// The query of a page.
#[derive(Debug)]
pub struct SheetQuery {
    /// The number of the page, from 0.
    pub page: i64,
    /// The size of the page.
    pub page_size: usize,
    /// The filters, by column.
    pub filters: HashMap<i64, String>,
    /// The search in each cell.
    pub global_search: String,
    /// The column of the sort, or -1.
    pub sort_column: i64,
    /// `asc` or `desc`.
    pub sort_direction: String,
}

impl Default for SheetQuery {
    fn default() -> Self {
        Self {
            page: 0,
            page_size: 100,
            filters: HashMap::new(),
            global_search: String::new(),
            sort_column: -1,
            sort_direction: String::new(),
        }
    }
}

/// A row of the sheet: the number and the cells by column.
struct Record {
    row_number: i64,
    cells: HashMap<i64, Arc<str>>,
}

impl Record {
    fn cell(&self, column: i64) -> &str {
        self.cells.get(&column).map_or("", |value| value)
    }
}

/// What a read of a sheet failed with.
enum Fail {
    Fault(Fault),
    Error(Error),
}

impl From<XmlFault> for Fail {
    fn from(fault: XmlFault) -> Self {
        Self::Fault(fault.into())
    }
}

impl From<Error> for Fail {
    fn from(error: Error) -> Self {
        Self::Error(error)
    }
}

/// The work budget of the read of one sheet.
struct ReadState<'a> {
    cancel: &'a CancelToken,
    ticks: u64,
    referenced_bytes: i64,
    truncated_cells: bool,
}

impl ReadState<'_> {
    fn tick(&mut self) -> Result<()> {
        self.ticks += 1;
        if self.ticks.is_multiple_of(CANCEL_CHECK_EVERY) {
            return self.cancel.check();
        }
        Ok(())
    }
}

// --- the names of the columns ------------------------------------------------------------------------------------

/// The index of the column that a reference starts with: `A` is 0, `Z` is 25, `AA` is 26. The letters stop at
/// the first character that is not a letter. A reference with no letter at its start is not a column.
pub fn excel_column_index(reference: &str) -> Option<i64> {
    let value = reference.trim();
    if value.is_empty() {
        return None;
    }
    let mut column: i64 = 0;
    let mut letters = 0;
    for current in value.chars() {
        let current = current.to_ascii_uppercase();
        if !current.is_ascii_uppercase() {
            break;
        }
        column = column
            .wrapping_mul(26)
            .wrapping_add(i64::from(u32::from(current) - u32::from('A') + 1));
        letters += 1;
    }
    (letters > 0).then(|| column.wrapping_sub(1))
}

/// The name of a column from its index.
pub fn excel_column_name(index: i64) -> String {
    if index < 0 {
        return String::new();
    }
    let mut output: Vec<u8> = Vec::new();
    let mut value = index;
    while value >= 0 {
        output.push(b'A' + u8::try_from(value % 26).unwrap_or(0));
        value = value / 26 - 1;
    }
    output.reverse();
    String::from_utf8(output).unwrap_or_default()
}

// --- the comparison of values ------------------------------------------------------------------------------------

fn row_matches(record: &Record, filters: &HashMap<i64, String>, global_search: &str) -> bool {
    let query = lower(global_search.trim());
    if !query.is_empty() && !record.cells.values().any(|value| lower(value).contains(&query)) {
        return false;
    }
    filters
        .iter()
        .all(|(column, filter)| matches_filter(record.cell(*column), filter))
}

// --- the dates ---------------------------------------------------------------------------------------------------

/// The text of a date serial of a workbook: `2006-01-02`, or `2006-01-02T15:04:05Z` when it has a time.
pub fn format_serial_date(serial: f64) -> String {
    let seconds = (serial * 24.0 * 60.0 * 60.0).round();
    // The epoch of the serials is 1899-12-30, 25569 days before 1970-01-01.
    let nanoseconds = (seconds as i64).wrapping_mul(1_000_000_000);
    let moment = Timestamp::from_unix(-25_569 * 86_400 + nanoseconds / 1_000_000_000, 0).rfc3339();
    if (serial - serial.round()).abs() < 1e-9 {
        return moment.chars().take(10).collect();
    }
    moment
}

/// True for a number format that shows a date or a time.
pub fn is_date_number_format(id: i64, code: &str) -> bool {
    if (14..=22).contains(&id) || (27..=36).contains(&id) || (45..=47).contains(&id) || (50..=58).contains(&id) {
        return true;
    }
    if code.is_empty() {
        return false;
    }
    let mut letters = String::new();
    let mut quoted = false;
    let mut bracketed = false;
    for current in lower(code).chars() {
        match current {
            '"' => quoted = !quoted,
            '[' => {
                if !quoted {
                    bracketed = true;
                }
            }
            ']' => {
                if !quoted {
                    bracketed = false;
                }
            }
            _ => {
                if !quoted && !bracketed && current.is_alphabetic() {
                    letters.push(current);
                }
            }
        }
    }
    letters.contains(['y', 'd']) || (letters.contains('m') && letters.contains(['h', 's']))
}

// --- the query ---------------------------------------------------------------------------------------------------

/// The query of a request.
pub fn parse_query(req: &Call) -> Result<SheetQuery> {
    let mut query = SheetQuery {
        page: parse_bounded_int(req.query.get("page"), 0, 0, i64::from(i32::MAX)),
        page_size: usize::try_from(parse_bounded_int(req.query.get("pageSize"), 100, 1, 1000)).unwrap_or(100),
        global_search: req.query.get("search").trim().to_owned(),
        ..SheetQuery::default()
    };
    if query.global_search.len() > 1024 {
        return Err(Error::api(
            400,
            "search_query_too_long",
            "spreadsheet search queries are limited to 1024 characters",
        ));
    }
    let raw = req.query.get("filters").trim();
    if !raw.is_empty() {
        let filters: Option<std::collections::BTreeMap<String, Option<String>>> =
            serde_json::from_str(raw).map_err(|_| {
                Error::api(
                    400,
                    "invalid_filters",
                    "filters must be a JSON object keyed by Excel column name",
                )
            })?;
        for (name, value) in filters.unwrap_or_default() {
            let column = excel_column_index(&name)
                .filter(|column| *column < MAX_COLUMNS)
                .ok_or_else(|| {
                    Error::api(
                        400,
                        "invalid_filter_column",
                        format!("invalid filter column {}", quote(&name)),
                    )
                })?;
            let value = value.unwrap_or_default();
            if !value.trim().is_empty() {
                query.filters.insert(column, value);
            }
        }
    }
    let raw = req.query.get("sortColumn").trim();
    if !raw.is_empty() {
        let column = excel_column_index(raw)
            .filter(|column| *column < MAX_COLUMNS)
            .ok_or_else(|| {
                Error::api(
                    400,
                    "invalid_sort_column",
                    "sortColumn must be a visible Excel column name",
                )
            })?;
        query.sort_column = column;
        query.sort_direction = req.query.get("sortDirection").trim().to_lowercase();
        if query.sort_direction != "asc" && query.sort_direction != "desc" {
            return Err(Error::api(
                400,
                "invalid_sort_direction",
                "sortDirection must be asc or desc",
            ));
        }
    }
    Ok(query)
}

// --- the package -------------------------------------------------------------------------------------------------

fn container_error(signature: &[u8]) -> Error {
    if signature.len() >= BINARY_EXCEL_SIGNATURE.len() && signature[..8] == BINARY_EXCEL_SIGNATURE {
        return Error::api(
            422,
            "unsupported_xls_container",
            "this file uses the binary XLS format even though its name ends in .xlsx or .xlsm; download it or convert it to XLSX or CSV",
        );
    }
    Error::api(
        422,
        "invalid_workbook_container",
        "the file extension says XLSX/XLSM, but the object is not an Office ZIP package; verify the source file or download the original",
    )
}

/// The package of an object that a workbook preview opens. `size_message` tells what needs a size. The errors of the
/// size, of the container and of the central directory have the codes of the workbook previews.
pub async fn open_workbook_package(
    source: RangeSource,
    size: Option<i64>,
    unknown_size_message: &str,
    too_large_message: &str,
) -> Result<Package> {
    let Some(size) = size.filter(|size| *size > 0) else {
        return Err(Error::api(422, "unknown_workbook_size", unknown_size_message));
    };
    if size > MAX_OBJECT_BYTES {
        return Err(Error::api(413, "workbook_too_large", too_large_message));
    }
    let signature = source.read_range(0, size.min(8)).await?;
    let is_zip = signature.len() >= 4
        && signature[0] == b'P'
        && signature[1] == b'K'
        && matches!((signature[2], signature[3]), (3, 4) | (5, 6) | (7, 8));
    if !is_zip {
        return Err(container_error(&signature));
    }
    match crate::archive::zip::ZipReader::open(source, 0).await {
        Ok(reader) => Ok(Package::new(reader)),
        Err(error) if crate::archive::zip::is_format_error(&error) => Err(Error::api(
            422,
            "invalid_workbook_package",
            "the Office ZIP package is incomplete or its central directory cannot be read",
        )),
        Err(error) => Err(error),
    }
}

/// Open a workbook for a preview: the size from the caller or from the end of the object, the limits and the
/// container.
pub async fn open_workbook(
    ctx: &crate::common::ctx::OpCtx,
    instance: &Arc<crate::instance::Instance>,
    key: &str,
    known_size: i64,
    unknown_size_message: &str,
    too_large_message: &str,
) -> Result<Package> {
    let (source, size) = open_sized_source(ctx, instance, key, known_size, "").await?;
    open_workbook_package(source, size, unknown_size_message, too_large_message).await
}

// --- the small parts ---------------------------------------------------------------------------------------------

/// A value of the workbook part that the sheets of the preview need.
#[derive(Debug, Default)]
pub struct WorkbookXml {
    /// The `activeTab` of the first view.
    pub active_tab: Option<i64>,
    /// The sheets: the name, the state and the relation.
    pub sheets: Vec<WorkbookSheet>,
}

/// A `sheet` element of the workbook part.
#[derive(Debug, Default)]
pub struct WorkbookSheet {
    /// The name.
    pub name: String,
    /// The state.
    pub state: String,
    /// The identifier of the relation.
    pub rel_id: String,
}

/// An integer attribute: an empty value is 0, a value with other text is an error.
fn integer_attribute(value: Option<&str>) -> std::result::Result<i64, XmlFault> {
    match value.map(str::trim) {
        None | Some("") => Ok(0),
        Some(text) => parse_i64(text).ok_or_else(|| XmlFault::Syntax(format!("invalid integer {text:?}"))),
    }
}

/// Read the elements of a document at a path of names below the root. `visit` gets the path, with the name of the
/// element at its end, and the attributes. The read stops at the end of the root element.
fn read_paths<R: Read>(
    reader: R,
    mut visit: impl FnMut(&[String], &[(String, String)]) -> std::result::Result<(), XmlFault>,
) -> std::result::Result<(), XmlFault> {
    let mut xml = XmlReader::new(reader);
    let mut path: Vec<String> = Vec::new();
    while let Some(event) = xml.next_event()? {
        match event {
            XmlEvent::Start { name, attrs } => {
                path.push(name);
                if path.len() > 1 {
                    visit(&path[1..], &attrs)?;
                }
            }
            XmlEvent::End { .. } => {
                path.pop();
                if path.is_empty() {
                    return Ok(());
                }
            }
            XmlEvent::Text(_) => {}
        }
    }
    Err(XmlFault::Syntax("unexpected EOF".to_owned()))
}

fn decode_workbook<R: Read>(reader: R) -> std::result::Result<WorkbookXml, XmlFault> {
    let mut workbook = WorkbookXml::default();
    let mut first_view = true;
    read_paths(reader, |path, attrs| {
        match path {
            [first, second] if first == "bookViews" && second == "workbookView" => {
                let tab = integer_attribute(last_attribute(attrs, "activeTab"))?;
                if first_view {
                    workbook.active_tab = Some(tab);
                    first_view = false;
                }
            }
            [first, second] if first == "sheets" && second == "sheet" => {
                workbook.sheets.push(WorkbookSheet {
                    name: last_attribute(attrs, "name").unwrap_or("").to_owned(),
                    state: last_attribute(attrs, "state").unwrap_or("").to_owned(),
                    rel_id: last_attribute(attrs, "id").unwrap_or("").to_owned(),
                });
            }
            _ => {}
        }
        Ok(())
    })?;
    Ok(workbook)
}

fn decode_relationships<R: Read>(reader: R) -> std::result::Result<Vec<(String, String)>, XmlFault> {
    let mut relationships: Vec<(String, String)> = Vec::new();
    read_paths(reader, |path, attrs| {
        if let [only] = path
            && only == "Relationship"
        {
            relationships.push((
                last_attribute(attrs, "Id").unwrap_or("").to_owned(),
                last_attribute(attrs, "Target").unwrap_or("").to_owned(),
            ));
        }
        Ok(())
    })?;
    Ok(relationships)
}

fn decode_styles<R: Read>(reader: R) -> std::result::Result<Styles, XmlFault> {
    let mut custom: HashMap<i64, String> = HashMap::new();
    let mut formats: Vec<i64> = Vec::new();
    read_paths(reader, |path, attrs| {
        match path {
            [first, second] if first == "numFmts" && second == "numFmt" => {
                let id = integer_attribute(last_attribute(attrs, "numFmtId"))?;
                custom.insert(id, last_attribute(attrs, "formatCode").unwrap_or("").to_owned());
            }
            [first, second] if first == "cellXfs" && second == "xf" => {
                formats.push(integer_attribute(last_attribute(attrs, "numFmtId"))?);
            }
            _ => {}
        }
        Ok(())
    })?;
    let mut styles = Styles::default();
    for (index, id) in formats.iter().enumerate() {
        let code = custom.get(id).map_or("", String::as_str);
        if is_date_number_format(*id, code) {
            styles.date_styles.insert(i64::try_from(index).unwrap_or(0));
        }
    }
    Ok(styles)
}

fn invalid_workbook(message: &str) -> Error {
    Error::api(422, "invalid_workbook", message)
}

/// The sheets of a workbook that the preview can read, in the order of the workbook.
pub async fn read_workbook_sheets(package: &Package) -> Result<Vec<SheetInfo>> {
    let (Some(workbook_part), Some(relationship_part)) = (
        package.part("xl/workbook.xml"),
        package.part("xl/_rels/workbook.xml.rels"),
    ) else {
        return Err(invalid_workbook("the workbook is missing its worksheet index"));
    };
    let workbook = read_small_part(package, workbook_part, workbook_of)
        .await?
        .map_err(|_| invalid_workbook("unable to read the workbook worksheet index"))?;
    let relationships = read_small_part(package, relationship_part, relationships_of)
        .await?
        .map_err(|_| invalid_workbook("unable to read workbook relationships"))?;
    let mut targets: HashMap<String, String> = HashMap::new();
    for (id, raw_target) in relationships {
        let mut target = raw_target.trim().replace('\\', "/");
        if target.is_empty() || target.contains(':') {
            continue;
        }
        if target.starts_with('/') {
            target = target.trim_start_matches('/').to_owned();
        } else if !target.starts_with("xl/") {
            target = join_path("xl", &target);
        }
        let target = super::package::clean_path(&target);
        if target == ".." || target.starts_with("../") {
            continue;
        }
        targets.insert(id, target);
    }
    let mut result: Vec<SheetInfo> = Vec::with_capacity(workbook.sheets.len());
    for sheet in &workbook.sheets {
        let target = targets.get(&sheet.rel_id).cloned().unwrap_or_default();
        if target.is_empty() || package.part(&target).is_none() {
            continue;
        }
        let mut hidden = sheet.state.trim().to_lowercase();
        if hidden != "hidden" && hidden != "veryhidden" {
            hidden.clear();
        }
        result.push(SheetInfo {
            index: 0,
            name: sheet.name.clone(),
            hidden,
            target,
        });
    }
    for (index, sheet) in result.iter_mut().enumerate() {
        sheet.index = i64::try_from(index).unwrap_or(0);
    }
    Ok(result)
}

/// The place, in `sheets`, of the sheet that the workbook shows first (the active tab). A workbook that names none
/// gives 0.
pub async fn read_active_sheet_index(package: &Package, sheets: &[SheetInfo]) -> Result<usize> {
    let Some(part) = package.part("xl/workbook.xml") else {
        return Ok(0);
    };
    if sheets.is_empty() {
        return Ok(0);
    }
    let workbook = read_small_part(package, part, workbook_of)
        .await?
        .map_err(|_| invalid_workbook("unable to read the active worksheet"))?;
    let mut active = workbook.active_tab.filter(|tab| *tab >= 0).unwrap_or(0);
    if usize::try_from(active).is_ok_and(|tab| tab >= workbook.sheets.len()) {
        active = 0;
    }
    let name = usize::try_from(active)
        .ok()
        .and_then(|tab| workbook.sheets.get(tab))
        .map(|sheet| sheet.name.as_str())
        .unwrap_or("");
    Ok(sheets.iter().position(|sheet| sheet.name == name).unwrap_or(0))
}

/// Parse a small part of the package with a function. The function sees the first 32 MiB of the part. The error of
/// the outer result is a failed open of the part. The inner result is the answer of the function.
async fn read_small_part<T, F>(package: &Package, part: &ZipEntry, parse: F) -> Result<std::result::Result<T, Fault>>
where
    T: Send + 'static,
    F: FnOnce(&mut dyn Read) -> std::result::Result<T, XmlFault> + Send + 'static,
{
    let stream = package.reader.open_entry(part).await?;
    parse_entry(stream, move |reader: &mut dyn Read| parse(reader).map_err(Fault::from)).await
}

fn workbook_of(reader: &mut dyn Read) -> std::result::Result<WorkbookXml, XmlFault> {
    decode_workbook(Truncate::new(reader, MAX_SMALL_PART_BYTES))
}

fn relationships_of(reader: &mut dyn Read) -> std::result::Result<Vec<(String, String)>, XmlFault> {
    decode_relationships(Truncate::new(reader, MAX_SMALL_PART_BYTES))
}

fn styles_of(reader: &mut dyn Read) -> std::result::Result<Styles, XmlFault> {
    decode_styles(Truncate::new(reader, MAX_SMALL_PART_BYTES))
}

fn shared_strings_error() -> Error {
    Error::api(422, "invalid_shared_strings", "unable to read workbook shared strings")
}

/// The text of the `t` elements below the element that the last start event opened, up to its end tag.
fn read_rich_text<R: Read>(xml: &mut XmlReader<R>) -> std::result::Result<String, XmlFault> {
    let mut builder = String::new();
    let mut depth = 1usize;
    while depth > 0 {
        match xml.next_event()? {
            None => return Err(XmlFault::Syntax("unexpected EOF".to_owned())),
            Some(XmlEvent::Start { name, .. }) => {
                depth += 1;
                if name == "t" {
                    builder.push_str(&xml.element_text()?);
                    depth -= 1;
                }
            }
            Some(XmlEvent::End { .. }) => depth -= 1,
            Some(XmlEvent::Text(_)) => {}
        }
    }
    Ok(builder)
}

/// The shared strings of a workbook. A package without the part gives none.
pub async fn read_shared_strings(package: &Package) -> Result<Vec<Arc<str>>> {
    let Some(part) = package.part("xl/sharedStrings.xml") else {
        return Ok(Vec::new());
    };
    let stream = package.reader.open_entry(part).await?;
    let outcome = parse_entry(stream, |reader| -> std::result::Result<Vec<Arc<str>>, Fail> {
        let mut xml = XmlReader::new(Truncate::new(reader, MAX_SHARED_STRING_BYTES as u64 + 1));
        let mut values: Vec<Arc<str>> = Vec::new();
        let mut consumed: usize = 0;
        loop {
            let event = match xml.next_event() {
                Ok(Some(event)) => event,
                Ok(None) => break,
                Err(_) => return Err(Fail::Error(shared_strings_error())),
            };
            let XmlEvent::Start { name, .. } = event else {
                continue;
            };
            if name != "si" {
                continue;
            }
            // A fault inside an item has no typed answer.
            let value = read_rich_text(&mut xml).map_err(|fault| Fail::Error(Error::internal(fault.to_string())))?;
            consumed += value.len();
            if values.len() >= MAX_SHARED_STRINGS || consumed > MAX_SHARED_STRING_BYTES {
                return Err(Fail::Error(Error::api(
                    422,
                    "shared_strings_too_large",
                    "the workbook shared string table is too large to preview",
                )));
            }
            values.push(Arc::from(value));
        }
        Ok(values)
    })
    .await?;
    match outcome {
        Ok(values) => Ok(values),
        Err(Fail::Error(error)) => Err(error),
        Err(Fail::Fault(_)) => Err(shared_strings_error()),
    }
}

/// The styles of a workbook. A package without the part gives none.
pub async fn read_styles(package: &Package) -> Result<Styles> {
    let Some(part) = package.part("xl/styles.xml") else {
        return Ok(Styles::default());
    };
    read_small_part(package, part, styles_of)
        .await?
        .map_err(|_| Error::api(422, "invalid_styles", "unable to read workbook styles"))
}

// --- the sheet ---------------------------------------------------------------------------------------------------

fn sheet_failure(fail: Fail, cancel: &CancelToken) -> Error {
    match fail {
        Fail::Error(error) => match error {
            Error::Api(_) | Error::Canceled | Error::Timeout => error,
            _ => Error::api(422, "invalid_sheet", "unable to parse the selected worksheet"),
        },
        Fail::Fault(fault) => {
            if cancel.is_canceled() {
                return Error::Canceled;
            }
            match fault {
                Fault::Limit => Error::api(
                    413,
                    "sheet_too_large",
                    format!(
                        "the worksheet XML exceeds {} MiB once decompressed",
                        MAX_SHEET_BYTES >> 20
                    ),
                ),
                Fault::Source(error @ (Error::Api(_) | Error::Canceled | Error::Timeout)) => error,
                _ => Error::api(422, "invalid_sheet", "unable to parse the selected worksheet"),
            }
        }
    }
}

fn read_cell_value<R: Read>(
    xml: &mut XmlReader<R>,
    attrs: &[(String, String)],
    fallback_column: i64,
    shared: &[Arc<str>],
    styles: &Styles,
    state: &mut ReadState<'_>,
) -> std::result::Result<(i64, Arc<str>), Fail> {
    let mut column = fallback_column;
    let mut cell_type = "";
    let mut style_index: i64 = -1;
    for (name, value) in attrs {
        match name.as_str() {
            "r" => {
                if let Some(parsed) = excel_column_index(value) {
                    column = parsed;
                }
            }
            "t" => cell_type = value,
            "s" => style_index = parse_integer(value).0,
            _ => {}
        }
    }
    let mut raw = String::new();
    let mut inline = String::new();
    let mut depth = 1usize;
    while depth > 0 {
        match xml.next_event()? {
            None => return Err(XmlFault::Syntax("unexpected EOF".to_owned()).into()),
            Some(XmlEvent::Start { name, .. }) => {
                depth += 1;
                match name.as_str() {
                    "v" => {
                        raw = xml.element_text()?;
                        depth -= 1;
                    }
                    "is" => {
                        inline = read_rich_text(xml)?;
                        depth -= 1;
                    }
                    _ => {}
                }
            }
            Some(XmlEvent::End { .. }) => depth -= 1,
            Some(XmlEvent::Text(_)) => {}
        }
    }
    let raw = raw.trim();
    let value: Arc<str> = match cell_type {
        "s" => {
            let index = parse_integer(raw);
            match usize::try_from(index.0) {
                Ok(position) if index.1 && position < shared.len() => {
                    // Each reference counts, not each entry: many cells can point at one large string.
                    let entry = &shared[position];
                    state.referenced_bytes += i64::try_from(entry.len().min(MAX_CELL_BYTES)).unwrap_or(0);
                    if state.referenced_bytes > MAX_REFERENCED_BYTES {
                        return Err(Fail::Error(Error::api(
                            413,
                            "sheet_expansion_too_large",
                            "the worksheet references too much shared string data to preview",
                        )));
                    }
                    entry.clone()
                }
                _ => Arc::from(""),
            }
        }
        "inlineStr" => Arc::from(inline),
        "b" => Arc::from(if raw == "1" { "TRUE" } else { "FALSE" }),
        "d" => Arc::from(raw),
        "e" => Arc::from(if raw.is_empty() { "#ERROR" } else { raw }),
        _ => {
            if styles.date_styles.contains(&style_index)
                && !raw.is_empty()
                && let Some(serial) = parse_float(raw)
            {
                Arc::from(format_serial_date(serial))
            } else {
                Arc::from(raw)
            }
        }
    };
    Ok((column, value))
}

fn read_cell<R: Read>(
    xml: &mut XmlReader<R>,
    attrs: &[(String, String)],
    fallback_column: i64,
    shared: &[Arc<str>],
    styles: &Styles,
    state: &mut ReadState<'_>,
) -> std::result::Result<(i64, Arc<str>), Fail> {
    let (column, mut value) = read_cell_value(xml, attrs, fallback_column, shared, styles, state)?;
    if value.len() > MAX_CELL_BYTES {
        value = Arc::from(truncate_utf8_bytes(&value, MAX_CELL_BYTES));
        state.truncated_cells = true;
    }
    Ok((column, value))
}

struct RowRead {
    record: Record,
    visible: bool,
    beyond_limit: bool,
}

fn read_row<R: Read>(
    xml: &mut XmlReader<R>,
    attrs: &[(String, String)],
    shared: &[Arc<str>],
    styles: &Styles,
    state: &mut ReadState<'_>,
) -> std::result::Result<RowRead, Fail> {
    let mut row_number = last_attribute(attrs, "r").map_or(0, |value| parse_integer(value).0);
    let mut cells: HashMap<i64, Arc<str>> = HashMap::new();
    let mut next_column: i64 = 0;
    let mut visible = false;
    let mut beyond_limit = false;
    let mut depth = 1usize;
    while depth > 0 {
        match xml.next_event()? {
            None => return Err(XmlFault::Syntax("unexpected EOF".to_owned()).into()),
            Some(XmlEvent::Start {
                name,
                attrs: cell_attrs,
            }) => {
                depth += 1;
                if name == "c" {
                    state.tick()?;
                    let (column, value) = read_cell(xml, &cell_attrs, next_column, shared, styles, state)?;
                    depth -= 1;
                    next_column = column.wrapping_add(1);
                    if !value.trim().is_empty() {
                        visible = true;
                        if column >= MAX_COLUMNS {
                            beyond_limit = true;
                        } else {
                            cells.insert(column, value);
                        }
                    } else if column < MAX_COLUMNS {
                        cells.insert(column, Arc::from(""));
                    }
                }
            }
            Some(XmlEvent::End { .. }) => depth -= 1,
            Some(XmlEvent::Text(_)) => {}
        }
    }
    if row_number <= 0 {
        row_number = 1;
    }
    Ok(RowRead {
        record: Record { row_number, cells },
        visible,
        beyond_limit,
    })
}

/// Read a page of a sheet from the bytes of its XML. The reader stops when the XML is larger than the limit.
pub fn read_spreadsheet_sheet(
    cancel: &CancelToken,
    reader: &mut dyn Read,
    sheets: &[SheetInfo],
    sheet_index: usize,
    shared: &[Arc<str>],
    styles: &Styles,
    query: &SheetQuery,
) -> Result<SheetPage> {
    read_sheet_inner(cancel, reader, sheets, sheet_index, shared, styles, query)
        .map_err(|fail| sheet_failure(fail, cancel))
}

fn read_sheet_inner(
    cancel: &CancelToken,
    reader: &mut dyn Read,
    sheets: &[SheetInfo],
    sheet_index: usize,
    shared: &[Arc<str>],
    styles: &Styles,
    query: &SheetQuery,
) -> std::result::Result<SheetPage, Fail> {
    let mut xml = XmlReader::new(HardLimit::new(reader, MAX_SHEET_BYTES + 1));
    let mut state = ReadState {
        cancel,
        ticks: 0,
        referenced_bytes: 0,
        truncated_cells: false,
    };
    let mut active_columns: HashSet<i64> = HashSet::new();
    let mut page_records: Vec<Record> = Vec::with_capacity(query.page_size.min(1024));
    let mut sort_records: Vec<Record> = Vec::new();
    let mut source_rows: usize = 0;
    let mut parsed_rows: usize = 0;
    let mut matched_rows: i64 = 0;
    let mut truncated_rows = false;
    let mut truncated_columns = false;
    let page_size = i64::try_from(query.page_size).unwrap_or(i64::MAX);
    let page_start = query.page.saturating_mul(page_size);
    while let Some(event) = xml.next_event()? {
        let XmlEvent::Start { name, attrs } = event else {
            continue;
        };
        if name != "row" {
            continue;
        }
        // A row with no visible cell is not a source row, so it has its own budget.
        parsed_rows += 1;
        if parsed_rows > MAX_ROWS {
            truncated_rows = true;
            break;
        }
        state.tick()?;
        let row = read_row(&mut xml, &attrs, shared, styles, &mut state)?;
        if row.beyond_limit {
            truncated_columns = true;
        }
        if !row.visible {
            continue;
        }
        source_rows += 1;
        if source_rows > MAX_ROWS {
            truncated_rows = true;
            break;
        }
        let record = row.record;
        for (column, value) in &record.cells {
            if !value.trim().is_empty() {
                active_columns.insert(*column);
            }
        }
        if !row_matches(&record, &query.filters, &query.global_search) {
            continue;
        }
        matched_rows += 1;
        if query.sort_column >= 0 {
            if sort_records.len() >= MAX_SORT_ROWS {
                return Err(Fail::Error(Error::api(
                    422,
                    "sort_result_too_large",
                    format!("sorting is limited to {MAX_SORT_ROWS} matching rows; add filters to narrow the result"),
                )));
            }
            sort_records.push(record);
            continue;
        }
        if matched_rows > page_start && page_records.len() < query.page_size {
            page_records.push(record);
        }
    }
    let mut columns: Vec<i64> = active_columns.into_iter().collect();
    columns.sort_unstable();
    if columns.len() > usize::try_from(MAX_COLUMNS).unwrap_or(200) {
        columns.truncate(usize::try_from(MAX_COLUMNS).unwrap_or(200));
        truncated_columns = true;
    }
    if query.sort_column >= 0 {
        let column = query.sort_column;
        let descending = query.sort_direction == "desc";
        stable_sort(&mut sort_records, |left: &Record, right: &Record| {
            let comparison = compare_values(left.cell(column), right.cell(column));
            if comparison.is_eq() {
                return left.row_number < right.row_number;
            }
            if descending {
                comparison.is_gt()
            } else {
                comparison.is_lt()
            }
        });
        let start = usize::try_from(page_start)
            .unwrap_or(usize::MAX)
            .min(sort_records.len());
        let end = (start + query.page_size).min(sort_records.len());
        page_records.extend(sort_records.drain(start..end));
    }
    let mut rows: Vec<SheetRow> = Vec::with_capacity(page_records.len());
    let mut page_bytes: usize = 0;
    for record in &page_records {
        let mut cells: Vec<String> = Vec::with_capacity(columns.len());
        for column in &columns {
            let value = record.cell(*column);
            // Four bytes stand for the quotes, the comma and the escapes of each cell, so a page of empty
            // cells has a limit too.
            page_bytes += value.len() + 4;
            cells.push(value.to_owned());
        }
        if page_bytes > MAX_PAGE_BYTES {
            return Err(Fail::Error(Error::api(
                413,
                "spreadsheet_page_too_large",
                format!(
                    "this page of the worksheet exceeds {} MiB; request a smaller page size",
                    MAX_PAGE_BYTES >> 20
                ),
            )));
        }
        rows.push(SheetRow {
            number: record.row_number,
            cells,
        });
    }
    let headers: Vec<String> = columns.iter().map(|column| excel_column_name(*column)).collect();
    Ok(SheetPage {
        sheets: sheets.to_vec(),
        sheet: sheets.get(sheet_index).cloned().unwrap_or_default(),
        headers,
        rows,
        total_rows: matched_rows,
        source_rows: i64::try_from(source_rows).unwrap_or(i64::MAX),
        page: query.page,
        page_size,
        truncated_rows,
        truncated_columns,
        truncated_cells: state.truncated_cells,
        ..SheetPage::default()
    })
}

// --- the route ---------------------------------------------------------------------------------------------------

/// The handler of `/api/spreadsheet`.
pub fn handle_spreadsheet(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        match start(req) {
            Ok(call) => answer(spreadsheet(&app, &call).await),
            Err(refusal) => *refusal,
        }
    })
}

async fn spreadsheet(app: &App, req: &Call) -> Result<Response> {
    let instance = read_instance(app, req)?;
    let key = required_key(req, "spreadsheet key cannot be empty")?;
    access::authorize_read(app, &req.ctx, &instance, &key).await?;
    let extension = key_extension(&key);
    if extension != "xlsx" && extension != "xlsm" {
        return Err(Error::api(
            400,
            "unsupported_spreadsheet",
            "server-side spreadsheet preview supports XLSX and XLSM files",
        ));
    }
    let query = parse_query(req)?;
    let known_size = parse_bounded_int(req.query.get("size"), 0, 0, MAX_OBJECT_BYTES);
    let package = open_workbook(
        &req.ctx,
        &instance,
        &key,
        known_size,
        "spreadsheet preview requires a known non-zero object size",
        &format!("spreadsheet previews are limited to {} MiB", MAX_OBJECT_BYTES >> 20),
    )
    .await?;
    let sheets = read_workbook_sheets(&package).await?;
    if sheets.is_empty() {
        return Err(Error::api(
            422,
            "empty_workbook",
            "the workbook does not contain any worksheets",
        ));
    }
    let last = i64::try_from(sheets.len() - 1).unwrap_or(0);
    let sheet_index = usize::try_from(parse_bounded_int(req.query.get("sheet"), 0, 0, last)).unwrap_or(0);
    let shared = read_shared_strings(&package).await?;
    let styles = read_styles(&package).await?;
    let Some(part) = sheets.get(sheet_index).and_then(|sheet| package.part(&sheet.target)) else {
        return Err(Error::api(
            422,
            "missing_sheet",
            "the selected worksheet is missing from the workbook",
        ));
    };
    let stream = package.reader.open_entry(part).await?;
    let cancel = req.ctx.cancel.clone();
    let sheets_for_page = sheets.clone();
    let page = parse_entry(stream, move |reader| {
        read_spreadsheet_sheet(&cancel, reader, &sheets_for_page, sheet_index, &shared, &styles, &query)
    })
    .await??;
    let mut page = page;
    page.instance.clone_from(&instance.cfg.id);
    page.key = key;
    page.macros_ignored = extension == "xlsm";
    Ok(json(200, &page))
}

#[cfg(test)]
#[path = "spreadsheet_tests.rs"]
mod tests;
