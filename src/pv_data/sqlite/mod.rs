// SPDX-License-Identifier: MIT OR Apache-2.0
//! The SQLite reader of the previews. It reads the pages of a SQLite 3 database file over exact byte ranges and never
//! runs SQL: the header, the B-tree pages of the tables and of the `WITHOUT ROWID` tables, the overflow pages and
//! the records (docs/PREVIEWS.md, "SQLite").
//!
//! Each walk has limits: the depth of a B-tree (128), the size of one record (64 MiB), each page and each overflow
//! page at most one time, each cell of a page at most one time. A crafted file gives a `422` error, never a loop.

pub(crate) mod query;
pub(crate) mod schema;
pub(crate) mod sessions;

#[cfg(test)]
mod tests;

use std::collections::HashSet;

use serde::{Serialize, Serializer};

use super::text::format_float_short;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::instance::range::RangeSource;
use crate::pv_docs::util::to_valid_utf8;

/// The deepest B-tree that a walk reads.
pub(crate) const MAX_BTREE_DEPTH: usize = 128;
/// The largest record that a walk reads: 64 MiB.
pub(crate) const MAX_RECORD_PAYLOAD: i64 = 64 << 20;
/// The magic text at the start of a SQLite 3 file.
pub(crate) const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";
/// The number of pages between two yields of a walk to the other tasks.
const PAGES_PER_YIELD: usize = 64;

/// A `422` error of the reader.
pub(crate) fn invalid(code: &str, message: impl Into<String>) -> Error {
    Error::api(422, code, message)
}

/// The error of a read that ends before the requested bytes.
pub(crate) fn unexpected_end() -> Error {
    Error::internal("unexpected end of the data")
}

/// One value of a record.
#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Value {
    /// NULL.
    Null,
    /// An integer.
    Integer(i64),
    /// A float.
    Real(f64),
    /// A text.
    Text(String),
    /// A blob.
    Blob(Vec<u8>),
    /// A blob of which only the size stays (a row of a sort).
    BlobSize(usize),
}

impl Value {
    /// The text of a value for the search, the filters and the sort: an empty text for NULL, the decimal integer, the
    /// short float, the text, or `[BLOB n bytes]`.
    pub(crate) fn text(&self) -> String {
        match self {
            Self::Null => String::new(),
            Self::Integer(value) => value.to_string(),
            Self::Real(value) => format_float_short(*value),
            Self::Text(value) => value.clone(),
            Self::Blob(value) => blob_label(value.len()),
            Self::BlobSize(size) => blob_label(*size),
        }
    }

    /// The integer of a value: the integer, the float rounded toward zero, the integer of a text, else 0.
    pub(crate) fn integer(&self) -> i64 {
        match self {
            Self::Integer(value) => *value,
            Self::Real(value) => super::text::float_to_int(*value),
            Self::Text(value) => crate::pv_docs::util::parse_integer(value.trim()).0,
            _ => 0,
        }
    }

    /// True for a float that is not a number or is infinite: the JSON form has no such number.
    pub(crate) fn is_unencodable(&self) -> bool {
        matches!(self, Self::Real(value) if !value.is_finite())
    }
}

/// Serialize a list as `null` when it is empty.
pub(crate) fn null_when_empty<S: Serializer, T: Serialize>(
    value: &[T],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    if value.is_empty() {
        serializer.serialize_none()
    } else {
        value.serialize(serializer)
    }
}

/// The label of a blob: `[BLOB n bytes]`.
pub(crate) fn blob_label(size: usize) -> String {
    format!("[BLOB {size} bytes]")
}

impl Serialize for Value {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Null => serializer.serialize_unit(),
            Self::Integer(value) => serializer.serialize_i64(*value),
            Self::Real(value) => serializer.serialize_f64(*value),
            Self::Text(value) => serializer.serialize_str(value),
            Self::Blob(value) => serializer.serialize_str(&blob_label(value.len())),
            Self::BlobSize(size) => serializer.serialize_str(&blob_label(*size)),
        }
    }
}

/// A set of page numbers (or of offsets in a page) as a bitmap.
#[derive(Debug, Default)]
pub(crate) struct PageSet {
    bits: Vec<u64>,
}

impl PageSet {
    /// Add a page; true when the set already had it.
    pub(crate) fn add(&mut self, page: u32) -> bool {
        let word = (page / 64) as usize;
        if word >= self.bits.len() {
            let grown = word + 1 + self.bits.len() / 2;
            self.bits.resize(grown, 0);
        }
        let mask = 1u64 << (page % 64);
        if self.bits[word] & mask != 0 {
            return true;
        }
        self.bits[word] |= mask;
        false
    }
}

/// The bytes of a database: in memory, or an object read over byte ranges.
#[derive(Debug)]
pub(crate) enum DatabaseSource {
    /// The bytes in memory (the tests).
    #[cfg(test)]
    Memory(bytes::Bytes),
    /// An object read over byte ranges.
    Remote(RangeSource),
}

impl DatabaseSource {
    /// Fill `buffer` from `offset`; gives the number of bytes. Fewer bytes than the buffer is the end of the file.
    async fn read_at(&self, buffer: &mut [u8], offset: i64) -> Result<usize> {
        match self {
            #[cfg(test)]
            Self::Memory(data) => {
                let Ok(start) = usize::try_from(offset) else {
                    return Ok(0);
                };
                if start >= data.len() {
                    return Ok(0);
                }
                let count = buffer.len().min(data.len() - start);
                buffer[..count].copy_from_slice(&data[start..start + count]);
                Ok(count)
            }
            Self::Remote(source) => source.read_at(buffer, offset).await,
        }
    }
}

/// An open database: the source, the size and the values of the header.
#[derive(Debug)]
pub(crate) struct Database {
    source: DatabaseSource,
    size: i64,
    page_size: usize,
    usable_size: usize,
    page_count: u32,
    encoding: u32,
}

/// What a visitor of the records tells the walk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Flow {
    /// Read the next record.
    Continue,
    /// Stop the walk.
    Stop,
}

/// The visitor of the records of a walk: the row id (0 in an index) and the values.
pub(crate) type Visitor<'a> = dyn FnMut(i64, Vec<Value>) -> Result<Flow> + Send + 'a;

/// The kind of a B-tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TreeKind {
    /// A table B-tree: the leaf cells have a row id and the record.
    Table,
    /// An index B-tree (a `WITHOUT ROWID` table): each cell has a record.
    Index,
}

/// An interior page of a walk: its bytes, its cells and the next cell to read.
struct Frame {
    page: Vec<u8>,
    header_offset: usize,
    pointers: Vec<usize>,
    next: usize,
    depth: usize,
    cell_pending: bool,
    right_done: bool,
}

/// The result of the entry in a page: an interior page to walk, or a leaf page that the walk read.
enum Entered {
    Interior(Frame),
    Leaf(Flow),
}

/// The state of one walk: the visited pages, the overflow pages and the count of pages.
#[derive(Default)]
struct WalkState {
    visited: HashSet<u32>,
    overflow_seen: PageSet,
    pages: usize,
}

/// Read a SQLite varint: the value and its width, or `None` when the bytes end first.
pub(crate) fn read_varint(data: &[u8], offset: usize) -> Option<(u64, usize)> {
    if offset >= data.len() {
        return None;
    }
    let mut value: u64 = 0;
    for index in 0..8 {
        let current = *data.get(offset + index)?;
        value = (value << 7) | u64::from(current & 0x7f);
        if current & 0x80 == 0 {
            return Some((value, index + 1));
        }
    }
    let last = *data.get(offset + 8)?;
    Some(((value << 8) | u64::from(last), 9))
}

/// The number of payload bytes that stay in the cell; the others are on overflow pages.
pub(crate) fn local_payload_size(payload_size: i64, usable_size: usize, table_leaf: bool) -> Result<usize> {
    if !(0..=MAX_RECORD_PAYLOAD).contains(&payload_size) {
        return Err(invalid(
            "sqlite_record_too_large",
            format!(
                "a SQLite record exceeds the {} MiB preview safety limit",
                MAX_RECORD_PAYLOAD >> 20
            ),
        ));
    }
    if payload_size == 0 {
        return Ok(0);
    }
    let usable = usable_size as i64;
    if usable < 480 {
        return Err(invalid(
            "invalid_sqlite_usable_page",
            "the SQLite database has too little usable space per page",
        ));
    }
    let minimum = ((usable - 12) * 32 / 255) - 23;
    let maximum = if table_leaf {
        usable - 35
    } else {
        ((usable - 12) * 64 / 255) - 23
    };
    if payload_size <= maximum {
        return Ok(payload_size as usize);
    }
    let candidate = minimum + ((payload_size - minimum) % (usable - 4));
    if candidate <= maximum {
        return Ok(candidate as usize);
    }
    Ok(minimum as usize)
}

/// The text of a value in the encoding of the database (1 UTF-8, 2 UTF-16 little-endian, 3 UTF-16 big-endian).
fn decode_text(data: &[u8], encoding: u32) -> String {
    match encoding {
        2 | 3 => {
            let units = data.as_chunks::<2>().0.iter().map(|pair| {
                if encoding == 2 {
                    u16::from_le_bytes([pair[0], pair[1]])
                } else {
                    u16::from_be_bytes([pair[0], pair[1]])
                }
            });
            char::decode_utf16(units)
                .map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER))
                .collect()
        }
        _ => match std::str::from_utf8(data) {
            Ok(text) => text.to_owned(),
            Err(_) => to_valid_utf8(data),
        },
    }
}

/// The signed big-endian integer of 1 to 8 bytes.
fn signed_integer(data: &[u8]) -> i64 {
    if data.is_empty() {
        return 0;
    }
    let mut value: u64 = 0;
    for byte in data {
        value = (value << 8) | u64::from(*byte);
    }
    let bits = data.len() * 8;
    if bits < 64 && value & (1u64 << (bits - 1)) != 0 {
        value |= u64::MAX << bits;
    }
    value as i64
}

/// The page offsets of the cells of a B-tree page. Each offset is in the page and appears one time.
fn cell_pointers(page: &[u8], header_offset: usize, header_size: usize, count: usize) -> Result<Vec<usize>> {
    let start = header_offset + header_size;
    if start + count * 2 > page.len() {
        return Err(invalid(
            "invalid_sqlite_btree",
            "a SQLite B-tree page has an invalid cell pointer array",
        ));
    }
    let mut pointers = Vec::with_capacity(count);
    let mut seen = PageSet::default();
    for index in 0..count {
        let at = start + index * 2;
        let pointer = usize::from(u16::from_be_bytes([page[at], page[at + 1]]));
        if pointer == 0 || pointer >= page.len() {
            return Err(invalid(
                "invalid_sqlite_cell",
                "a SQLite cell pointer points outside its page",
            ));
        }
        if seen.add(pointer as u32) {
            return Err(invalid(
                "invalid_sqlite_cell",
                "a SQLite page lists the same cell more than once",
            ));
        }
        pointers.push(pointer);
    }
    Ok(pointers)
}

/// The big-endian 32-bit integer at an offset (the bytes are in the page).
fn be_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]])
}

impl Database {
    /// Open a database: check the header (magic, page size, reserved space, encoding) and count the pages.
    pub(crate) async fn open(source: DatabaseSource, size: i64) -> Result<Self> {
        if size < 100 {
            return Err(invalid(
                "invalid_sqlite",
                "the object is too small to be a SQLite 3 database",
            ));
        }
        let mut header = [0u8; 100];
        if source.read_at(&mut header, 0).await? < header.len() {
            return Err(unexpected_end());
        }
        if &header[..16] != SQLITE_MAGIC {
            return Err(invalid("invalid_sqlite", "the object is not a SQLite 3 database"));
        }
        let mut page_size = usize::from(u16::from_be_bytes([header[16], header[17]]));
        if page_size == 1 {
            page_size = 65_536;
        }
        if !(512..=65_536).contains(&page_size) || !page_size.is_power_of_two() {
            return Err(invalid(
                "invalid_sqlite_page_size",
                "the SQLite database declares an invalid page size",
            ));
        }
        let reserved = usize::from(header[20]);
        if reserved >= page_size - 32 {
            return Err(invalid(
                "invalid_sqlite_reserved_space",
                "the SQLite database declares invalid reserved page space",
            ));
        }
        let pages = (size + page_size as i64 - 1) / page_size as i64;
        if pages > i64::from(u32::MAX) {
            return Err(invalid(
                "sqlite_too_large",
                "the SQLite database declares more pages than the preview reader supports",
            ));
        }
        let mut page_count = pages as u32;
        let declared = be_u32(&header, 28);
        if declared > 0 && declared < page_count {
            page_count = declared;
        }
        let mut encoding = be_u32(&header, 56);
        if encoding == 0 {
            encoding = 1;
        }
        if !(1..=3).contains(&encoding) {
            return Err(invalid(
                "unsupported_sqlite_encoding",
                "the SQLite database uses an unsupported text encoding",
            ));
        }
        Ok(Self {
            source,
            size,
            page_size,
            usable_size: page_size - reserved,
            page_count,
            encoding,
        })
    }

    /// Read one page (pages start at 1).
    async fn read_page(&self, page_number: u32) -> Result<Vec<u8>> {
        let outside = || {
            invalid(
                "invalid_sqlite_page",
                "the SQLite database references a page outside the file",
            )
        };
        if page_number == 0 || page_number > self.page_count {
            return Err(outside());
        }
        let offset = i64::from(page_number - 1) * self.page_size as i64;
        if offset >= self.size {
            return Err(outside());
        }
        let mut page = vec![0u8; self.page_size];
        let read = self.source.read_at(&mut page, offset).await?;
        if read < self.page_size {
            return Err(invalid(
                "truncated_sqlite_page",
                "the SQLite database ends in the middle of a page",
            ));
        }
        Ok(page)
    }

    /// The payload of a cell: the local bytes, then the chain of overflow pages. An overflow page that the walk
    /// already read is an error.
    async fn read_payload(
        &self,
        page: &[u8],
        start: usize,
        payload_size: i64,
        table_leaf: bool,
        overflow_seen: &mut PageSet,
    ) -> Result<Vec<u8>> {
        let local = local_payload_size(payload_size, self.usable_size, table_leaf)?;
        if start > self.usable_size || start + local > self.usable_size || start + local > page.len() {
            return Err(invalid("invalid_sqlite_cell", "a SQLite cell points outside its page"));
        }
        let total = payload_size as usize;
        let mut payload = Vec::with_capacity(total);
        payload.extend_from_slice(&page[start..start + local.min(total)]);
        if payload.len() == total {
            return Ok(payload);
        }
        let pointer_offset = start + local;
        if pointer_offset + 4 > self.usable_size || pointer_offset + 4 > page.len() {
            return Err(invalid(
                "invalid_sqlite_overflow",
                "a SQLite overflow pointer is missing",
            ));
        }
        let mut next_page = be_u32(page, pointer_offset);
        while payload.len() < total {
            if next_page == 0 || next_page > self.page_count {
                return Err(invalid(
                    "invalid_sqlite_overflow",
                    "a SQLite record references an invalid overflow page",
                ));
            }
            if overflow_seen.add(next_page) {
                return Err(invalid(
                    "sqlite_overflow_cycle",
                    "a SQLite overflow page is referenced more than once",
                ));
            }
            let overflow = self.read_page(next_page).await?;
            if self.usable_size < 4 {
                return Err(invalid(
                    "invalid_sqlite_overflow",
                    "a SQLite overflow page is too small",
                ));
            }
            let next = be_u32(&overflow, 0);
            let available = (self.usable_size - 4).min(total - payload.len());
            payload.extend_from_slice(&overflow[4..4 + available]);
            next_page = next;
        }
        Ok(payload)
    }

    /// The values of a record: the header of serial types, then the values.
    pub(crate) fn decode_record(&self, payload: &[u8]) -> Result<Vec<Value>> {
        let invalid_header = || invalid("invalid_sqlite_record", "a SQLite record has an invalid header");
        let (header_size, consumed) = read_varint(payload, 0).ok_or_else(invalid_header)?;
        if header_size < consumed as u64 || header_size > payload.len() as u64 {
            return Err(invalid_header());
        }
        let header_size = header_size as usize;
        let mut serials = Vec::with_capacity(16);
        let mut offset = consumed;
        while offset < header_size {
            match read_varint(payload, offset) {
                Some((serial, width)) if offset + width <= header_size => {
                    serials.push(serial);
                    offset += width;
                }
                _ => {
                    return Err(invalid(
                        "invalid_sqlite_record",
                        "a SQLite record has an invalid serial type",
                    ));
                }
            }
        }
        let mut values = Vec::with_capacity(serials.len());
        let mut data_offset = header_size;
        for serial in serials {
            let length: u64 = match serial {
                0 | 8 | 9 => 0,
                1..=4 => serial,
                5 => 6,
                6 | 7 => 8,
                10 | 11 => {
                    return Err(invalid(
                        "unsupported_sqlite_serial_type",
                        "a SQLite record uses a reserved serial type",
                    ));
                }
                _ if serial & 1 == 0 => (serial - 12) / 2,
                _ => (serial - 13) / 2,
            };
            let end = usize::try_from(length)
                .ok()
                .and_then(|length| data_offset.checked_add(length))
                .filter(|end| *end <= payload.len())
                .ok_or_else(|| invalid("truncated_sqlite_record", "a SQLite record payload is truncated"))?;
            let field = &payload[data_offset..end];
            data_offset = end;
            values.push(match serial {
                0 => Value::Null,
                1..=6 => Value::Integer(signed_integer(field)),
                7 => {
                    let mut bits = [0u8; 8];
                    bits.copy_from_slice(field);
                    Value::Real(f64::from_bits(u64::from_be_bytes(bits)))
                }
                8 => Value::Integer(0),
                9 => Value::Integer(1),
                _ if serial & 1 == 0 => Value::Blob(field.to_vec()),
                _ => Value::Text(decode_text(field, self.encoding)),
            });
        }
        Ok(values)
    }

    /// Walk a table B-tree in the order of the row ids and give each record to the visitor. `Flow::Stop` when the
    /// visitor stopped the walk.
    pub(crate) async fn walk_table(&self, ctx: &OpCtx, root: u32, visitor: &mut Visitor<'_>) -> Result<Flow> {
        self.walk(ctx, root, TreeKind::Table, visitor).await
    }

    /// Walk an index B-tree (a `WITHOUT ROWID` table) in the order of the keys and give each record to the visitor
    /// with the row id 0.
    pub(crate) async fn walk_index(&self, ctx: &OpCtx, root: u32, visitor: &mut Visitor<'_>) -> Result<Flow> {
        self.walk(ctx, root, TreeKind::Index, visitor).await
    }

    async fn walk(&self, ctx: &OpCtx, root: u32, kind: TreeKind, visitor: &mut Visitor<'_>) -> Result<Flow> {
        let mut state = WalkState::default();
        let mut stack: Vec<Frame> = Vec::new();
        match self.enter(ctx, root, 0, kind, &mut state, visitor).await? {
            Entered::Interior(frame) => stack.push(frame),
            Entered::Leaf(Flow::Stop) => return Ok(Flow::Stop),
            Entered::Leaf(Flow::Continue) => {}
        }
        while let Some(frame) = stack.last_mut() {
            if frame.cell_pending {
                frame.cell_pending = false;
                let pointer = frame.pointers[frame.next - 1];
                let (payload_size, width) = read_varint(&frame.page, pointer + 4)
                    .ok_or_else(|| invalid("invalid_sqlite_cell", "a SQLite index cell has an invalid payload size"))?;
                let payload = self
                    .read_payload(
                        &frame.page,
                        pointer + 4 + width,
                        payload_size as i64,
                        false,
                        &mut state.overflow_seen,
                    )
                    .await?;
                let values = self.decode_record(&payload)?;
                if visitor(0, values)? == Flow::Stop {
                    return Ok(Flow::Stop);
                }
                continue;
            }
            let child = if frame.next < frame.pointers.len() {
                let pointer = frame.pointers[frame.next];
                frame.next += 1;
                if pointer + 4 > frame.page.len() {
                    let message = match kind {
                        TreeKind::Table => "a SQLite interior cell is truncated",
                        TreeKind::Index => "a SQLite interior index cell is truncated",
                    };
                    return Err(invalid("invalid_sqlite_cell", message));
                }
                frame.cell_pending = kind == TreeKind::Index;
                be_u32(&frame.page, pointer)
            } else if !frame.right_done {
                frame.right_done = true;
                be_u32(&frame.page, frame.header_offset + 8)
            } else {
                stack.pop();
                continue;
            };
            let depth = frame.depth + 1;
            match self.enter(ctx, child, depth, kind, &mut state, visitor).await? {
                Entered::Interior(next) => stack.push(next),
                Entered::Leaf(Flow::Stop) => return Ok(Flow::Stop),
                Entered::Leaf(Flow::Continue) => {}
            }
        }
        Ok(Flow::Continue)
    }

    /// Enter a page: check the depth and the cycles, read the page, and read the cells of a leaf page.
    async fn enter(
        &self,
        ctx: &OpCtx,
        page_number: u32,
        depth: usize,
        kind: TreeKind,
        state: &mut WalkState,
        visitor: &mut Visitor<'_>,
    ) -> Result<Entered> {
        ctx.check()?;
        if depth > MAX_BTREE_DEPTH {
            return Err(invalid(
                "sqlite_btree_too_deep",
                "the SQLite B-tree exceeds the preview depth limit",
            ));
        }
        if !state.visited.insert(page_number) {
            return Err(invalid("sqlite_btree_cycle", "the SQLite B-tree contains a cycle"));
        }
        state.pages += 1;
        if state.pages.is_multiple_of(PAGES_PER_YIELD) {
            tokio::task::yield_now().await;
        }
        let page = self.read_page(page_number).await?;
        let header_offset = if page_number == 1 { 100 } else { 0 };
        if header_offset + 8 > page.len() {
            return Err(invalid("invalid_sqlite_btree", "a SQLite B-tree page is truncated"));
        }
        let page_type = page[header_offset];
        let cell_count = usize::from(u16::from_be_bytes([page[header_offset + 3], page[header_offset + 4]]));
        match (kind, page_type) {
            (TreeKind::Table, 0x05) | (TreeKind::Index, 0x02) => {
                if header_offset + 12 > page.len() {
                    let message = match kind {
                        TreeKind::Table => "a SQLite interior table page is truncated",
                        TreeKind::Index => "a SQLite interior index page is truncated",
                    };
                    return Err(invalid("invalid_sqlite_btree", message));
                }
                let pointers = cell_pointers(&page, header_offset, 12, cell_count)?;
                Ok(Entered::Interior(Frame {
                    page,
                    header_offset,
                    pointers,
                    next: 0,
                    depth,
                    cell_pending: false,
                    right_done: false,
                }))
            }
            (TreeKind::Table, 0x0d) => {
                let pointers = cell_pointers(&page, header_offset, 8, cell_count)?;
                for pointer in pointers {
                    let (payload_size, payload_width) = read_varint(&page, pointer).ok_or_else(|| {
                        invalid("invalid_sqlite_cell", "a SQLite table cell has an invalid payload size")
                    })?;
                    let (row_id, row_id_width) = read_varint(&page, pointer + payload_width).ok_or_else(|| {
                        invalid(
                            "invalid_sqlite_cell",
                            "a SQLite table cell has an invalid row identifier",
                        )
                    })?;
                    let payload = self
                        .read_payload(
                            &page,
                            pointer + payload_width + row_id_width,
                            payload_size as i64,
                            true,
                            &mut state.overflow_seen,
                        )
                        .await?;
                    let values = self.decode_record(&payload)?;
                    if visitor(row_id as i64, values)? == Flow::Stop {
                        return Ok(Entered::Leaf(Flow::Stop));
                    }
                }
                Ok(Entered::Leaf(Flow::Continue))
            }
            (TreeKind::Index, 0x0a) => {
                let pointers = cell_pointers(&page, header_offset, 8, cell_count)?;
                for pointer in pointers {
                    let (payload_size, width) = read_varint(&page, pointer).ok_or_else(|| {
                        invalid("invalid_sqlite_cell", "a SQLite index cell has an invalid payload size")
                    })?;
                    let payload = self
                        .read_payload(
                            &page,
                            pointer + width,
                            payload_size as i64,
                            false,
                            &mut state.overflow_seen,
                        )
                        .await?;
                    let values = self.decode_record(&payload)?;
                    if visitor(0, values)? == Flow::Stop {
                        return Ok(Entered::Leaf(Flow::Stop));
                    }
                }
                Ok(Entered::Leaf(Flow::Continue))
            }
            (TreeKind::Table, other) => Err(invalid(
                "unsupported_sqlite_table_btree",
                format!("the SQLite table root uses unsupported B-tree page type 0x{other:02x}"),
            )),
            (TreeKind::Index, other) => Err(invalid(
                "unsupported_sqlite_index_btree",
                format!("the SQLite table root uses unsupported index B-tree page type 0x{other:02x}"),
            )),
        }
    }
}
