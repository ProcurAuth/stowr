//! The details of an Excel-family workbook: the sheets that a preview can read, the active sheet, and (only for an
//! explicit count) the used rows and columns of the active sheet.
//!
//! The details read the ZIP central directory and the small workbook parts only. The count of the dimensions reads
//! the XML of the active sheet in order, on a thread for blocking work, and keeps no cell in memory.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::HeaderMap;
use quick_xml::Reader;
use quick_xml::escape::resolve_predefined_entity;
use quick_xml::events::{BytesStart, Event};
use tokio::sync::mpsc;

use super::text::parse_int;
use crate::archive::zip::{ZipEntry, ZipReader};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::instance::Instance;
use crate::instance::range::RangeSource;

/// The largest workbook object of the details and of the count: 512 MiB.
pub(crate) const MAX_OBJECT_BYTES: i64 = 512 << 20;
/// The bytes of a small part (the workbook, its relationships) that the reader reads.
const SMALL_PART_BYTES: u64 = 32 << 20;
/// The chunks that wait between the read of a part and its parser.
const CHANNEL_DEPTH: usize = 4;
/// The signature of a binary XLS file (an OLE compound file).
const XLS_SIGNATURE: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// The summary of a workbook.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpreadsheetSummary {
    /// The sheets that a preview can read.
    pub sheets: usize,
    /// The name of the active sheet, or an empty text without a sheet.
    pub active_sheet: String,
    /// The last used row of the active sheet (only after a count).
    pub rows: i64,
    /// The last used column of the active sheet (only after a count).
    pub columns: i64,
}

/// A sheet of the workbook index.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Sheet {
    name: String,
    target: String,
}

/// An open workbook: the ZIP archive and its parts by clean name (of two parts with the same name, the last counts).
struct Workbook {
    reader: ZipReader,
    files: HashMap<String, usize>,
}

impl Workbook {
    fn part(&self, name: &str) -> Option<&ZipEntry> {
        self.files.get(name).and_then(|index| self.reader.entries.get(*index))
    }
}

/// The lexical form of a path: no empty part, no `.` part, the `..` parts resolved, `.` for an empty path.
pub(crate) fn clean_path(path: &str) -> String {
    let rooted = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.last().is_some_and(|last| *last != "..") {
                    parts.pop();
                } else if !rooted {
                    parts.push("..");
                }
            }
            other => parts.push(other),
        }
    }
    let joined = parts.join("/");
    match (rooted, joined.is_empty()) {
        (true, _) => format!("/{joined}"),
        (false, true) => ".".to_owned(),
        (false, false) => joined,
    }
}

/// The error of a package that is not a ZIP archive: a binary XLS file has its own message.
fn container_error(signature: &[u8]) -> Error {
    if signature.len() >= XLS_SIGNATURE.len() && signature[..XLS_SIGNATURE.len()] == XLS_SIGNATURE {
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

/// Open a workbook: the size from the listing or from the end of the object, the limits, the ZIP signature and the
/// central directory.
async fn open_workbook(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    known_size: i64,
    unknown_size_message: &str,
    too_large_message: &str,
) -> Result<Workbook> {
    let mut source = RangeSource::open(ctx, instance, key).await?;
    source.set_known_size(known_size);
    if source.size_or_zero() <= 0 {
        source.read_suffix(64 << 10).await?;
    }
    let size = source.size_or_zero();
    if size <= 0 {
        return Err(Error::api(422, "unknown_workbook_size", unknown_size_message));
    }
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
    let reader = match ZipReader::open(source, 0).await {
        Ok(reader) => reader,
        Err(error) if error.has_code("invalid_zip") => {
            return Err(Error::api(
                422,
                "invalid_workbook_package",
                "the Office ZIP package is incomplete or its central directory cannot be read",
            ));
        }
        Err(error) => return Err(error),
    };
    let mut files = HashMap::with_capacity(reader.entries.len());
    for (index, entry) in reader.entries.iter().enumerate() {
        files.insert(clean_path(entry.name.trim_start_matches('/')), index);
    }
    Ok(Workbook { reader, files })
}

/// A reader of the chunks of a part on the thread of its parser. The end of the channel is the end of the part; a
/// failed read of the part gives an error.
struct ChannelReader {
    receiver: mpsc::Receiver<Bytes>,
    current: Bytes,
    failed: Arc<Mutex<Option<Error>>>,
}

impl Read for ChannelReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        while self.current.is_empty() {
            match self.receiver.blocking_recv() {
                Some(chunk) => self.current = chunk,
                None => {
                    let failed = match self.failed.lock() {
                        Ok(slot) => slot.is_some(),
                        Err(poisoned) => poisoned.into_inner().is_some(),
                    };
                    if failed {
                        return Err(std::io::Error::other("the read of the part failed"));
                    }
                    return Ok(0);
                }
            }
        }
        let count = out.len().min(self.current.len());
        out[..count].copy_from_slice(&self.current[..count]);
        self.current = self.current.slice(count..);
        Ok(count)
    }
}

/// Keep the error of the read of a part for its parser.
fn keep_error(slot: &Mutex<Option<Error>>, error: Error) {
    match slot.lock() {
        Ok(mut slot) => *slot = Some(error),
        Err(poisoned) => *poisoned.into_inner() = Some(error),
    }
}

/// Send the decompressed bytes of a part to its parser, chunk by chunk. The parser can stop first: then the read stops
/// too. An error of the read goes to `failed` before the end of the channel. Gives true when a chunk went to the
/// parser.
async fn send_part(
    reader: &ZipReader,
    entry: &ZipEntry,
    sender: mpsc::Sender<Bytes>,
    failed: &Mutex<Option<Error>>,
) -> bool {
    let mut sent = false;
    let result = async {
        let mut stream = reader.open_entry(entry).await?;
        while let Some(chunk) = stream.next_chunk().await? {
            sent = true;
            if sender.send(chunk).await.is_err() {
                break;
            }
        }
        Ok::<(), Error>(())
    }
    .await;
    if let Err(error) = result {
        keep_error(failed, error);
    }
    drop(sender);
    sent
}

/// What the parse of a part gives: the result of the parser, the error of the read of the part, and a flag that
/// tells if the read gave bytes before its error.
struct PartOutcome<T> {
    value: T,
    error: Option<Error>,
    sent: bool,
}

/// Parse a part on a thread for blocking work. The parser reads the part in order, at most `limit` bytes when a limit
/// is given.
async fn parse_part<T, F>(reader: &ZipReader, entry: &ZipEntry, limit: Option<u64>, parse: F) -> Result<PartOutcome<T>>
where
    T: Send + 'static,
    F: FnOnce(&mut dyn BufRead) -> T + Send + 'static,
{
    let (sender, receiver) = mpsc::channel(CHANNEL_DEPTH);
    let failed = Arc::new(Mutex::new(None));
    let channel = ChannelReader {
        receiver,
        current: Bytes::new(),
        failed: failed.clone(),
    };
    let task = tokio::task::spawn_blocking(move || match limit {
        Some(limit) => parse(&mut BufReader::new(channel.take(limit))),
        None => parse(&mut BufReader::new(channel)),
    });
    let sent = send_part(reader, entry, sender, &failed).await;
    let value = task
        .await
        .map_err(|error| Error::internal(format!("parse of a workbook part: {error}")))?;
    let error = match failed.lock() {
        Ok(mut slot) => slot.take(),
        Err(poisoned) => poisoned.into_inner().take(),
    };
    Ok(PartOutcome { value, error, sent })
}

/// An error of the XML of a part.
#[derive(Debug)]
struct XmlFault(String);

impl From<quick_xml::Error> for XmlFault {
    fn from(error: quick_xml::Error) -> Self {
        Self(error.to_string())
    }
}

impl From<quick_xml::escape::EscapeError> for XmlFault {
    fn from(error: quick_xml::escape::EscapeError) -> Self {
        Self(error.to_string())
    }
}

impl From<quick_xml::events::attributes::AttrError> for XmlFault {
    fn from(error: quick_xml::events::attributes::AttrError) -> Self {
        Self(error.to_string())
    }
}

/// The attributes of an element by local name, the values with their references resolved. Of two attributes with
/// the same local name, the last counts.
fn attributes(start: &BytesStart<'_>) -> std::result::Result<Vec<(String, String)>, XmlFault> {
    let mut out = Vec::new();
    let mut iterator = start.attributes();
    iterator.with_checks(false);
    for attribute in iterator {
        let attribute = attribute?;
        let local = attribute.key.local_name();
        let name: &str = local.as_ref();
        let value = quick_xml::escape::unescape(&attribute.value)?;
        out.push((name.to_owned(), value.replace("\r\n", "\n").replace('\r', "\n")));
    }
    Ok(out)
}

/// The value of the last attribute with this local name.
fn attribute<'a>(attributes: &'a [(String, String)], name: &str) -> Option<&'a str> {
    attributes
        .iter()
        .rev()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

/// The local name of an element.
fn local_name(start: &BytesStart<'_>) -> String {
    let local = start.local_name();
    let name: &str = local.as_ref();
    name.to_owned()
}

/// A reader of XML with the checks of the end names, and without duplicate checks of the attributes.
fn xml_reader<R: BufRead>(input: R) -> Reader<R> {
    let mut reader = Reader::from_reader(input);
    let config = reader.config_mut();
    config.check_end_names = true;
    config.expand_empty_elements = true;
    reader
}

/// Read the elements of a document below its root element: `visit` gets the names of the path below the root and
/// the attributes of each element. The read stops at the end of the root element.
fn read_paths<R: BufRead>(
    input: R,
    mut visit: impl FnMut(&[String], &[(String, String)]) -> std::result::Result<(), XmlFault>,
) -> std::result::Result<(), XmlFault> {
    let mut reader = xml_reader(input);
    let mut buffer = Vec::new();
    let mut path: Vec<String> = Vec::new();
    loop {
        buffer.clear();
        match reader.read_event_into(&mut buffer)? {
            Event::Start(start) => {
                path.push(local_name(&start));
                if path.len() > 1 {
                    let attributes = attributes(&start)?;
                    visit(&path[1..], &attributes)?;
                }
            }
            Event::End(_) => {
                path.pop();
                if path.is_empty() {
                    return Ok(());
                }
            }
            Event::GeneralRef(reference) => {
                if reference.resolve_char_ref()?.is_none() && resolve_predefined_entity(&reference).is_none() {
                    return Err(XmlFault(format!("invalid character entity &{};", &*reference)));
                }
            }
            Event::Eof => return Err(XmlFault("unexpected EOF".to_owned())),
            _ => {}
        }
    }
}

/// The values of the workbook part: the `activeTab` of the first view and the sheets (name, state, relation).
#[derive(Debug, Default)]
struct WorkbookXml {
    views: Vec<i64>,
    sheets: Vec<(String, String, String)>,
}

/// An integer attribute: empty is 0, another text that is not an integer is an error.
fn integer_attribute(value: Option<&str>) -> std::result::Result<i64, XmlFault> {
    let text = value.unwrap_or("").trim();
    if text.is_empty() {
        return Ok(0);
    }
    match parse_int(text) {
        (value, true) => Ok(value),
        _ => Err(XmlFault(format!("invalid integer {text:?}"))),
    }
}

fn decode_workbook(input: &mut dyn BufRead) -> std::result::Result<WorkbookXml, XmlFault> {
    let mut workbook = WorkbookXml::default();
    read_paths(input, |path, attributes| {
        match path {
            [first, second] if first == "bookViews" && second == "workbookView" => {
                workbook
                    .views
                    .push(integer_attribute(attribute(attributes, "activeTab"))?);
            }
            [first, second] if first == "sheets" && second == "sheet" => workbook.sheets.push((
                attribute(attributes, "name").unwrap_or("").to_owned(),
                attribute(attributes, "state").unwrap_or("").to_owned(),
                attribute(attributes, "id").unwrap_or("").to_owned(),
            )),
            _ => {}
        }
        Ok(())
    })?;
    Ok(workbook)
}

fn decode_relationships(input: &mut dyn BufRead) -> std::result::Result<Vec<(String, String)>, XmlFault> {
    let mut relationships = Vec::new();
    read_paths(input, |path, attributes| {
        if let [only] = path
            && only == "Relationship"
        {
            relationships.push((
                attribute(attributes, "Id").unwrap_or("").to_owned(),
                attribute(attributes, "Target").unwrap_or("").to_owned(),
            ));
        }
        Ok(())
    })?;
    Ok(relationships)
}

/// Read a small part with a decoder. Any failure, also a failed read of the part, gives `422 invalid_workbook`.
async fn read_small_part<T, F>(workbook: &Workbook, entry: &ZipEntry, decode: F, message: &str) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(&mut dyn BufRead) -> std::result::Result<T, XmlFault> + Send + 'static,
{
    let invalid = || Error::api(422, "invalid_workbook", message);
    match parse_part(&workbook.reader, entry, Some(SMALL_PART_BYTES), decode)
        .await?
        .value
    {
        Ok(value) => Ok(value),
        Err(_) => Err(invalid()),
    }
}

/// The sheets that a preview can read: each sheet of the workbook index with a relation to a part of the package.
async fn workbook_sheets(workbook: &Workbook) -> Result<Vec<Sheet>> {
    let (Some(index_part), Some(relationship_part)) = (
        workbook.part("xl/workbook.xml"),
        workbook.part("xl/_rels/workbook.xml.rels"),
    ) else {
        return Err(Error::api(
            422,
            "invalid_workbook",
            "the workbook is missing its worksheet index",
        ));
    };
    let index = read_small_part(
        workbook,
        index_part,
        decode_workbook,
        "unable to read the workbook worksheet index",
    )
    .await?;
    let relationships = read_small_part(
        workbook,
        relationship_part,
        decode_relationships,
        "unable to read workbook relationships",
    )
    .await?;
    let mut targets: HashMap<String, String> = HashMap::new();
    for (id, raw_target) in relationships {
        let mut target = raw_target.trim().replace('\\', "/");
        if target.is_empty() || target.contains(':') {
            continue;
        }
        if target.starts_with('/') {
            target = target.trim_start_matches('/').to_owned();
        } else if !target.starts_with("xl/") {
            target = clean_path(&format!("xl/{target}"));
        }
        let target = clean_path(&target);
        if target == ".." || target.starts_with("../") {
            continue;
        }
        targets.insert(id, target);
    }
    Ok(index
        .sheets
        .iter()
        .filter_map(|(name, _, relation)| {
            let target = targets.get(relation)?;
            workbook.part(target)?;
            Some(Sheet {
                name: name.clone(),
                target: target.clone(),
            })
        })
        .collect())
}

/// The place, in `sheets`, of the active sheet of the workbook: the sheet of the `activeTab` of the first view.
async fn active_sheet_index(workbook: &Workbook, sheets: &[Sheet]) -> Result<usize> {
    let Some(part) = workbook.part("xl/workbook.xml") else {
        return Ok(0);
    };
    if sheets.is_empty() {
        return Ok(0);
    }
    let index = read_small_part(workbook, part, decode_workbook, "unable to read the active worksheet").await?;
    let mut active = index.views.first().copied().filter(|tab| *tab >= 0).unwrap_or(0);
    if usize::try_from(active).map_or(true, |tab| tab >= index.sheets.len()) {
        active = 0;
    }
    let name = usize::try_from(active)
        .ok()
        .and_then(|tab| index.sheets.get(tab))
        .map_or("", |sheet| sheet.0.as_str());
    Ok(sheets.iter().position(|sheet| sheet.name == name).unwrap_or(0))
}

/// The summary of a workbook for the details: the sheets and the active sheet, without the dimensions. Gives the
/// headers and the size of the object too.
pub(crate) async fn inspect_spreadsheet_summary(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    known_size: i64,
) -> Result<(SpreadsheetSummary, HeaderMap, i64)> {
    let workbook = open_workbook(
        ctx,
        instance,
        key,
        known_size,
        "spreadsheet details require a known non-zero object size",
        &format!("spreadsheet details are limited to {} MiB", MAX_OBJECT_BYTES >> 20),
    )
    .await?;
    let sheets = workbook_sheets(&workbook).await?;
    let mut summary = SpreadsheetSummary {
        sheets: sheets.len(),
        ..SpreadsheetSummary::default()
    };
    let headers = workbook.reader.source.headers();
    let size = workbook.reader.source.size_or_zero();
    if sheets.is_empty() {
        return Ok((summary, headers, size));
    }
    let active = active_sheet_index(&workbook, &sheets).await?;
    summary.active_sheet = sheets[active].name.clone();
    Ok((summary, headers, size))
}

/// The summary of a workbook with the last used row and column of the active sheet. The count reads the whole
/// sheet: only an explicit count action calls it.
pub async fn inspect_spreadsheet_dimensions(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    known_size: i64,
) -> Result<SpreadsheetSummary> {
    let workbook = open_workbook(
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
    let sheets = workbook_sheets(&workbook).await?;
    let mut summary = SpreadsheetSummary {
        sheets: sheets.len(),
        ..SpreadsheetSummary::default()
    };
    if sheets.is_empty() {
        return Ok(summary);
    }
    let active = &sheets[active_sheet_index(&workbook, &sheets).await?];
    summary.active_sheet = active.name.clone();
    let Some(part) = workbook.part(&active.target) else {
        return Ok(summary);
    };
    let outcome = parse_part(&workbook.reader, part, None, |input| count_worksheet_dimensions(input)).await?;
    match (outcome.value, outcome.error) {
        (Ok((rows, columns)), _) => {
            summary.rows = rows;
            summary.columns = columns;
            Ok(summary)
        }
        (Err(_), Some(error)) if !outcome.sent => Err(error),
        (Err(SheetFault::Sheet), _) => Err(invalid_sheet()),
        (Err(SheetFault::Raw(text)), error) => Err(error.unwrap_or_else(|| Error::internal(text))),
    }
}

/// The error of a sheet that the count cannot read.
fn invalid_sheet() -> Error {
    Error::api(422, "invalid_sheet", "unable to inspect worksheet dimensions")
}

/// The failure of a count: an error of the document outside a row (`invalid_sheet`), or an error in a row.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum SheetFault {
    /// An error outside a row.
    Sheet,
    /// An error in a row, with its text.
    Raw(String),
}

/// The events of a sheet that the count uses.
enum SheetEvent {
    Start(String, Vec<(String, String)>),
    End,
    Text(String),
    Eof,
}

/// A reader of the events of a sheet: it checks the end names and gives an error for an end of the document inside
/// an element.
struct SheetReader<R: BufRead> {
    reader: Reader<R>,
    buffer: Vec<u8>,
    depth: usize,
}

impl<R: BufRead> SheetReader<R> {
    fn new(input: R) -> Self {
        Self {
            reader: xml_reader(input),
            buffer: Vec::new(),
            depth: 0,
        }
    }

    fn next(&mut self) -> std::result::Result<SheetEvent, XmlFault> {
        loop {
            self.buffer.clear();
            let event = match self.reader.read_event_into(&mut self.buffer)? {
                Event::Start(start) => {
                    let attributes = attributes(&start)?;
                    self.depth += 1;
                    SheetEvent::Start(local_name(&start), attributes)
                }
                Event::End(_) => {
                    self.depth = self.depth.saturating_sub(1);
                    SheetEvent::End
                }
                Event::Text(text) => SheetEvent::Text(text.xml10_content().into_owned()),
                Event::CData(data) => SheetEvent::Text(data.xml10_content().into_owned()),
                Event::GeneralRef(reference) => {
                    if let Some(character) = reference.resolve_char_ref()? {
                        SheetEvent::Text(character.to_string())
                    } else if let Some(text) = resolve_predefined_entity(&reference) {
                        SheetEvent::Text(text.to_owned())
                    } else {
                        return Err(XmlFault(format!("invalid character entity &{};", &*reference)));
                    }
                }
                Event::Eof => {
                    if self.depth > 0 {
                        return Err(XmlFault("unexpected EOF".to_owned()));
                    }
                    SheetEvent::Eof
                }
                _ => continue,
            };
            return Ok(event);
        }
    }
}

/// Count the used rows and columns of a sheet: the last row number with a cell that has a value or a formula, and the
/// last column of such a cell. A row without `r` follows the previous row; a cell without `r` follows the previous
/// cell. An error outside a row is `SheetFault::Sheet`; an error in a row is `SheetFault::Raw`.
pub(crate) fn count_worksheet_dimensions(input: &mut dyn BufRead) -> std::result::Result<(i64, i64), SheetFault> {
    let mut reader = SheetReader::new(input);
    let mut maximum_row: i64 = 0;
    let mut maximum_column: i64 = 0;
    let mut fallback_row: i64 = 0;
    loop {
        let event = reader.next().map_err(|_| SheetFault::Sheet)?;
        let (name, attributes) = match event {
            SheetEvent::Eof => break,
            SheetEvent::Start(name, attributes) => (name, attributes),
            _ => continue,
        };
        if name != "row" {
            continue;
        }
        fallback_row += 1;
        let mut row_number = fallback_row;
        for (key, value) in &attributes {
            if key != "r" {
                continue;
            }
            if let (parsed, true) = parse_int(value.trim())
                && parsed > 0
            {
                row_number = parsed;
                fallback_row = parsed;
            }
        }
        let (visible, row_maximum) = count_worksheet_row(&mut reader).map_err(|fault| SheetFault::Raw(fault.0))?;
        if visible && row_number > maximum_row {
            maximum_row = row_number;
        }
        if row_maximum > maximum_column {
            maximum_column = row_maximum;
        }
    }
    Ok((maximum_row, maximum_column))
}

/// The index of the column of a cell reference: `A` is 0, `AA` is 26. The letters stop at the first other character.
pub(crate) fn excel_column_index(reference: &str) -> Option<i64> {
    let value = reference.trim();
    let mut column: i64 = 0;
    let mut letters = 0;
    for character in value.chars() {
        let character = character.to_ascii_uppercase();
        if !character.is_ascii_uppercase() {
            break;
        }
        column = column
            .wrapping_mul(26)
            .wrapping_add(i64::from(u32::from(character) - u32::from('A') + 1));
        letters += 1;
    }
    (letters > 0).then(|| column.wrapping_sub(1))
}

/// Read the rest of a row after its start: true when a cell has content, and the last column with content.
fn count_worksheet_row<R: BufRead>(reader: &mut SheetReader<R>) -> std::result::Result<(bool, i64), XmlFault> {
    let mut depth = 1usize;
    let mut visible = false;
    let mut maximum_column: i64 = 0;
    let mut fallback: i64 = 0;
    while depth > 0 {
        match reader.next()? {
            SheetEvent::Start(name, attributes) => {
                if name == "c" {
                    let mut column = fallback;
                    for (key, value) in &attributes {
                        if key == "r"
                            && let Some(parsed) = excel_column_index(value)
                        {
                            column = parsed;
                        }
                    }
                    fallback = column.wrapping_add(1);
                    if cell_has_content(reader)? {
                        visible = true;
                        if column.wrapping_add(1) > maximum_column {
                            maximum_column = column.wrapping_add(1);
                        }
                    }
                    continue;
                }
                depth += 1;
            }
            SheetEvent::End => depth -= 1,
            SheetEvent::Text(_) => {}
            SheetEvent::Eof => return Err(XmlFault("unexpected EOF".to_owned())),
        }
    }
    Ok((visible, maximum_column))
}

/// Read the rest of a cell after its start: true for a formula, or for a value or a text that is not blank.
fn cell_has_content<R: BufRead>(reader: &mut SheetReader<R>) -> std::result::Result<bool, XmlFault> {
    let mut depth = 1usize;
    let mut has_content = false;
    while depth > 0 {
        match reader.next()? {
            SheetEvent::Start(name, _) => {
                depth += 1;
                match name.as_str() {
                    "f" => has_content = true,
                    "v" | "t" => {
                        if !element_text(reader)?.trim().is_empty() {
                            has_content = true;
                        }
                        depth -= 1;
                    }
                    _ => {}
                }
            }
            SheetEvent::End => depth -= 1,
            SheetEvent::Text(_) => {}
            SheetEvent::Eof => return Err(XmlFault("unexpected EOF".to_owned())),
        }
    }
    Ok(has_content)
}

/// The text of the element that the last start opened, up to its end: its own character data, without the text of
/// the elements in it.
fn element_text<R: BufRead>(reader: &mut SheetReader<R>) -> std::result::Result<String, XmlFault> {
    let mut text = String::new();
    let mut depth = 1usize;
    while depth > 0 {
        match reader.next()? {
            SheetEvent::Start(..) => depth += 1,
            SheetEvent::End => depth -= 1,
            SheetEvent::Text(value) if depth == 1 => text.push_str(&value),
            SheetEvent::Text(_) => {}
            SheetEvent::Eof => return Err(XmlFault("unexpected EOF".to_owned())),
        }
    }
    Ok(text)
}
