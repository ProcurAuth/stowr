//! The preview of a Word document (DOCX, DOCM, DOTX, DOTM) on the server: the paragraphs, the headings, the list
//! items and the tables of `word/document.xml`, as text.
//!
//! The reader opens the central directory over exact ranges and reads the one part `word/document.xml` as a
//! stream. The limits are in the constants of this file. The preview ignores the macros and the styles.

use std::io::Read;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::package::{Fault, HardLimit, Package, open_sized_source, parse_entry};
use super::request::{Call, answer, read_instance, start};
use super::util::{parse_i64, truncate_utf8_bytes};
use super::xml::{XmlEvent, XmlFault, XmlReader, attribute};
use crate::access;
use crate::archive::zip::ZipReader;
use crate::common::BoxFuture;
use crate::common::app::App;
use crate::common::error::{Error, Result};
use crate::common::http::{Req, Response, json};

/// The largest document: 8 GiB.
pub const MAX_OBJECT_BYTES: i64 = 8 << 30;
/// The most bytes of `word/document.xml`, once decompressed.
pub const MAX_XML_BYTES: u64 = 64 << 20;
/// The most parts of a package.
pub const MAX_ARCHIVE_FILES: usize = 20_000;
/// The most blocks of an answer.
pub const MAX_BLOCKS: usize = 20_000;
/// The most bytes of text of an answer.
pub const MAX_TEXT_BYTES: usize = 8 << 20;
/// The most cells of the tables of an answer.
pub const MAX_TABLE_CELLS: usize = 200_000;
/// The most bytes of the text of one cell.
pub const MAX_CELL_TEXT_BYTES: usize = 1 << 20;

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}

/// A block of the document.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct WordBlock {
    /// `paragraph`, `heading`, `list-item` or `table`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The text.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub text: String,
    /// The level of a heading or of a list item.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub level: i64,
    /// True for a numbered list item.
    #[serde(default, skip_serializing_if = "is_false")]
    pub ordered: bool,
    /// The rows of a table.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rows: Vec<Vec<String>>,
}

/// The answer of `/api/document/word`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct WordPreview {
    /// The instance.
    pub instance: String,
    /// The key.
    pub key: String,
    /// The blocks.
    pub blocks: Vec<WordBlock>,
    /// True when a limit stopped the read.
    #[serde(default, skip_serializing_if = "is_false")]
    pub truncated: bool,
    /// True for a file with macros: the preview ignores them.
    #[serde(rename = "macrosIgnored", default, skip_serializing_if = "is_false")]
    pub macros_ignored: bool,
    /// The bytes that the read took from the storage.
    #[serde(rename = "storageBytes")]
    pub storage_bytes: i64,
    /// The requests that the read sent to the storage.
    #[serde(rename = "storageRequests")]
    pub storage_requests: i64,
}

/// The counts of the limits of one read.
#[derive(Debug, Default)]
pub struct Limits {
    blocks: usize,
    text_bytes: usize,
    cells: usize,
    truncated: bool,
}

impl Limits {
    /// Take the text into the budget: the text that fits, cut on a character border. The flag `truncated` is set
    /// when a part does not fit.
    fn add_text(&mut self, value: String) -> String {
        if value.is_empty() {
            return value;
        }
        let remaining = MAX_TEXT_BYTES as i64 - self.text_bytes as i64;
        if remaining <= 0 {
            self.truncated = true;
            return String::new();
        }
        let mut value = value;
        let remaining = usize::try_from(remaining).unwrap_or(0);
        if value.len() > remaining {
            value = truncate_utf8_bytes(&value, remaining).to_owned();
            self.truncated = true;
        }
        self.text_bytes += value.len();
        value
    }
}

/// The text of a paragraph or of a cell: the line ends are line feeds, each line has no white space at its ends, and
/// the text has none.
pub fn normalize_text(value: &str) -> String {
    let value = value.replace("\r\n", "\n").replace('\r', "\n");
    let lines: Vec<&str> = value.split('\n').map(str::trim).collect();
    lines.join("\n").trim().to_owned()
}

/// The level of a heading from the style (`Heading2`, `Titre3`) or from the outline level. 0 for no heading.
pub fn heading_level(style: &str, outline_level: i64) -> i64 {
    if outline_level > 0 {
        return outline_level.min(6);
    }
    let lowered = style.trim().to_lowercase();
    if !lowered.starts_with("heading") && !lowered.starts_with("titre") {
        return 0;
    }
    let bytes = lowered.as_bytes();
    for index in (0..bytes.len()).rev() {
        if !bytes[index].is_ascii_digit() {
            if index == bytes.len() - 1 {
                return 1;
            }
            let level = super::util::parse_integer(&lowered[index + 1..]).0;
            return level.clamp(1, 6);
        }
    }
    1
}

fn xml_failure(fault: XmlFault) -> Fault {
    Fault::from(fault)
}

fn word_attribute(attrs: &[(String, String)], local: &str) -> String {
    attribute(attrs, local).unwrap_or("").trim().to_owned()
}

fn unexpected_end() -> Fault {
    Fault::Syntax("unexpected end of the data".to_owned())
}

fn read_paragraph<R: Read>(xml: &mut XmlReader<R>, limits: &mut Limits) -> std::result::Result<WordBlock, Fault> {
    let mut block = WordBlock {
        kind: "paragraph".to_owned(),
        ..WordBlock::default()
    };
    let mut text = String::new();
    let mut depth = 1usize;
    let mut in_text = false;
    let mut style = String::new();
    let mut outline_level: i64 = 0;
    let mut list_level: i64 = 0;
    let mut list = false;
    while depth > 0 {
        match xml.next_event().map_err(xml_failure)? {
            None => return Err(unexpected_end()),
            Some(XmlEvent::Start { name, attrs }) => {
                depth += 1;
                match name.as_str() {
                    "t" | "delText" | "instrText" => in_text = true,
                    "tab" => text.push('\t'),
                    "br" | "cr" => text.push('\n'),
                    "pStyle" => style = word_attribute(&attrs, "val"),
                    "outlineLvl" => {
                        if let Some(parsed) = parse_i64(&word_attribute(&attrs, "val")) {
                            outline_level = parsed.saturating_add(1);
                        }
                    }
                    "numPr" => list = true,
                    "ilvl" => {
                        if let Some(parsed) = parse_i64(&word_attribute(&attrs, "val")) {
                            list_level = parsed.saturating_add(1);
                        }
                    }
                    _ => {}
                }
            }
            Some(XmlEvent::Text(value)) => {
                if in_text {
                    text.push_str(&value);
                }
            }
            Some(XmlEvent::End { name }) => {
                if matches!(name.as_str(), "t" | "delText" | "instrText") {
                    in_text = false;
                }
                depth -= 1;
            }
        }
    }
    block.text = limits.add_text(normalize_text(&text));
    if block.text.is_empty() {
        return Ok(block);
    }
    let level = heading_level(&style, outline_level);
    if level > 0 {
        block.kind = "heading".to_owned();
        block.level = level;
    } else if list {
        block.kind = "list-item".to_owned();
        block.level = list_level.max(1);
    }
    Ok(block)
}

fn read_table_cell<R: Read>(xml: &mut XmlReader<R>, limits: &mut Limits) -> std::result::Result<String, Fault> {
    let mut text = String::new();
    let mut depth = 1usize;
    let mut in_text = false;
    let mut paragraph_has_text = false;
    while depth > 0 {
        match xml.next_event().map_err(xml_failure)? {
            None => return Err(unexpected_end()),
            Some(XmlEvent::Start { name, .. }) => {
                depth += 1;
                match name.as_str() {
                    "t" | "delText" => in_text = true,
                    "tab" => text.push('\t'),
                    "br" | "cr" => text.push('\n'),
                    _ => {}
                }
            }
            Some(XmlEvent::Text(value)) => {
                if in_text && text.len() < MAX_CELL_TEXT_BYTES {
                    text.push_str(&value);
                    paragraph_has_text = true;
                }
            }
            Some(XmlEvent::End { name }) => {
                if name == "t" || name == "delText" {
                    in_text = false;
                }
                if name == "p" && paragraph_has_text && depth > 1 {
                    text.push('\n');
                    paragraph_has_text = false;
                }
                depth -= 1;
            }
        }
        if text.len() >= MAX_CELL_TEXT_BYTES {
            limits.truncated = true;
        }
    }
    Ok(limits.add_text(normalize_text(&text)))
}

fn read_table_row<R: Read>(xml: &mut XmlReader<R>, limits: &mut Limits) -> std::result::Result<Vec<String>, Fault> {
    let mut row: Vec<String> = Vec::with_capacity(8);
    let mut depth = 1usize;
    while depth > 0 {
        match xml.next_event().map_err(xml_failure)? {
            None => return Err(unexpected_end()),
            Some(XmlEvent::Start { name, .. }) => {
                depth += 1;
                if name == "tc" {
                    let cell = read_table_cell(xml, limits)?;
                    depth -= 1;
                    row.push(cell);
                    limits.cells += 1;
                    if limits.cells >= MAX_TABLE_CELLS {
                        limits.truncated = true;
                    }
                }
            }
            Some(XmlEvent::End { .. }) => depth -= 1,
            Some(XmlEvent::Text(_)) => {}
        }
    }
    Ok(row)
}

fn read_table<R: Read>(xml: &mut XmlReader<R>, limits: &mut Limits) -> std::result::Result<WordBlock, Fault> {
    let mut block = WordBlock {
        kind: "table".to_owned(),
        ..WordBlock::default()
    };
    let mut depth = 1usize;
    while depth > 0 {
        if limits.cells >= MAX_TABLE_CELLS || limits.text_bytes >= MAX_TEXT_BYTES {
            limits.truncated = true;
            xml.skip_to_depth(depth).map_err(xml_failure)?;
            break;
        }
        match xml.next_event().map_err(xml_failure)? {
            None => return Err(unexpected_end()),
            Some(XmlEvent::Start { name, .. }) => {
                depth += 1;
                if name == "tr" {
                    let row = read_table_row(xml, limits)?;
                    depth -= 1;
                    if !row.is_empty() {
                        block.rows.push(row);
                    }
                }
            }
            Some(XmlEvent::End { .. }) => depth -= 1,
            Some(XmlEvent::Text(_)) => {}
        }
    }
    Ok(block)
}

/// Read the blocks of the XML of a document body. `truncated` tells that a limit stopped the read.
pub fn parse_document_xml<R: Read>(reader: R, limits: &mut Limits) -> std::result::Result<Vec<WordBlock>, Fault> {
    let mut xml = XmlReader::new(reader);
    let mut blocks: Vec<WordBlock> = Vec::with_capacity(64);
    while let Some(event) = xml.next_event().map_err(xml_failure)? {
        let XmlEvent::Start { name, .. } = event else {
            continue;
        };
        if limits.blocks >= MAX_BLOCKS || limits.text_bytes >= MAX_TEXT_BYTES || limits.cells >= MAX_TABLE_CELLS {
            limits.truncated = true;
            break;
        }
        match name.as_str() {
            "p" => {
                let block = read_paragraph(&mut xml, limits)?;
                if !block.text.is_empty() {
                    blocks.push(block);
                    limits.blocks += 1;
                }
            }
            "tbl" => {
                let block = read_table(&mut xml, limits)?;
                if !block.rows.is_empty() {
                    blocks.push(block);
                    limits.blocks += 1;
                }
            }
            _ => {}
        }
    }
    Ok(blocks)
}

/// The handler of `/api/document/word`.
pub fn handle_word(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        match start(req) {
            Ok(call) => answer(word_preview(&app, &call).await),
            Err(refusal) => *refusal,
        }
    })
}

fn invalid_size() -> Error {
    Error::api(400, "invalid_size", "size must be a non-negative integer")
}

/// The size that a request gives: 0 for none.
pub fn optional_object_size(raw: &str) -> Result<i64> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(0);
    }
    match parse_i64(raw) {
        Some(value) if value >= 0 => Ok(value),
        _ => Err(invalid_size()),
    }
}

async fn word_preview(app: &App, req: &Call) -> Result<Response> {
    let instance = read_instance(app, req)?;
    let key = req.query.get("key").trim_start_matches('/').to_owned();
    if key.is_empty() {
        return Err(Error::api(400, "missing_key", "key is required"));
    }
    access::authorize_read(app, &req.ctx, &instance, &key).await?;
    let known_size = optional_object_size(req.query.get("size"))?;
    let mut response = read_word_preview(req, &instance, &key, known_size, req.query.get("etag")).await?;
    response.instance.clone_from(&instance.cfg.id);
    response.key = key;
    Ok(json(200, &response))
}

fn invalid_docx(message: &str) -> Error {
    Error::api(422, "invalid_docx", message)
}

/// The blocks of a document at a key.
pub async fn read_word_preview(
    req: &Call,
    instance: &Arc<crate::instance::Instance>,
    key: &str,
    known_size: i64,
    expected_etag: &str,
) -> Result<WordPreview> {
    let (source, size) = open_sized_source(&req.ctx, instance, key, known_size, expected_etag).await?;
    let Some(size) = size.filter(|size| *size > 0) else {
        return Err(Error::api(
            422,
            "unknown_document_size",
            "DOCX preview requires a known non-zero object size",
        ));
    };
    if size > MAX_OBJECT_BYTES {
        return Err(Error::api(
            413,
            "document_too_large",
            format!(
                "DOCX previews are limited to objects smaller than {} GiB",
                MAX_OBJECT_BYTES >> 30
            ),
        ));
    }
    let reader: ZipReader = match ZipReader::open(source, MAX_ARCHIVE_FILES).await {
        Ok(reader) => reader,
        Err(error @ (Error::Canceled | Error::Timeout)) => return Err(error),
        Err(error) if error.has_code(crate::archive::zip::CODE_TOO_MANY_ENTRIES) => {
            return Err(Error::api(
                413,
                "document_archive_too_large",
                "the DOCX package contains too many archive members",
            ));
        }
        Err(_) => return Err(invalid_docx("the object is not a valid DOCX package")),
    };
    let package = Package::new(reader);
    let Some(document) = package
        .reader
        .entries
        .iter()
        .find(|entry| super::package::part_name(&entry.name) == "word/document.xml")
    else {
        return Err(invalid_docx("the DOCX package is missing word/document.xml"));
    };
    if document.size > MAX_XML_BYTES {
        return Err(too_large_xml());
    }
    let stream = package
        .reader
        .open_entry(document)
        .await
        .map_err(|_| invalid_docx("unable to open the DOCX document body"))?;
    let parsed = parse_entry(stream, |reader| {
        let mut limits = Limits::default();
        let blocks = parse_document_xml(HardLimit::new(reader, MAX_XML_BYTES + 1), &mut limits);
        blocks.map(|blocks| (blocks, limits.truncated))
    })
    .await?;
    let (blocks, truncated) = match parsed {
        Ok(parsed) => parsed,
        Err(Fault::Limit) => return Err(too_large_xml()),
        Err(_) => {
            return Err(Error::api(
                422,
                "invalid_docx_xml",
                "the DOCX document body could not be parsed",
            ));
        }
    };
    let extension_is_docm = key.to_lowercase().ends_with(".docm");
    Ok(WordPreview {
        blocks,
        truncated,
        macros_ignored: extension_is_docm,
        storage_bytes: package.reader.source.bytes_read(),
        storage_requests: i64::try_from(package.reader.source.request_count()).unwrap_or(i64::MAX),
        ..WordPreview::default()
    })
}

fn too_large_xml() -> Error {
    Error::api(
        413,
        "document_xml_too_large",
        "the DOCX document body exceeds the preview limit",
    )
}

#[cfg(test)]
#[path = "word_tests.rs"]
mod tests;
