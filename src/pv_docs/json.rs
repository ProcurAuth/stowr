//! The previews of JSON: the raw text, the beautified text, the summary and the tree.
//!
//! Each route reads an object in order, from a byte offset, with exact ranges. A page has at most 256 KiB or 2000
//! lines. A signed cursor keeps the state of the next page: the offset, the line, the open containers and the
//! state of a string. A tree page keeps the offset after a separator.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::request::{Call, answer, object_target, start};
use super::stream::ObjectStream;
use super::util::{lossy_bytes, parse_float, parse_i64, to_valid_utf8};
use crate::common::BoxFuture;
use crate::common::app::App;
use crate::common::error::{Error, Result};
use crate::common::http::{Req, Response, json};
use crate::instance::Instance;
use crate::instance::cursor::{decode_signed_cursor, encode_signed_cursor, signed_cursor_scope};
use crate::instance::range::{ObjectVersion, WindowReader};

/// The largest text of a page: 256 KiB.
pub const TEXT_PAGE_BYTES: usize = 256 * 1024;
/// The most lines of a page.
pub const TEXT_PAGE_LINES: i64 = 2000;
/// The default number of children in a tree page.
pub const TREE_DEFAULT_PAGE_SIZE: usize = 50;
/// The largest number of children in a tree page.
pub const TREE_MAX_PAGE_SIZE: usize = 200;
/// The bytes of the preview of a value.
pub const TREE_PREVIEW_BYTES: usize = 1024;
/// The bytes of the preview of a key.
pub const TREE_KEY_PREVIEW_BYTES: usize = 2048;
/// The deepest nesting that the previews accept.
pub const MAX_NESTING_DEPTH: usize = 10_000;

fn is_false(value: &bool) -> bool {
    !*value
}

fn is_zero_byte(value: &u8) -> bool {
    *value == 0
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}

/// The state that a text page keeps for the next page.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TextCursor {
    /// The offset of the next byte.
    #[serde(rename = "o")]
    pub offset: i64,
    /// The number of the next line.
    #[serde(rename = "l")]
    pub line: i64,
    /// True when the page ends inside a line.
    #[serde(rename = "c", default, skip_serializing_if = "is_false")]
    pub continued: bool,
    /// The open containers: `{` or `[` for each.
    #[serde(rename = "k", default, skip_serializing_if = "String::is_empty")]
    pub stack: String,
    /// True inside a string.
    #[serde(rename = "q", default, skip_serializing_if = "is_false")]
    pub in_string: bool,
    /// True after a backslash in a string.
    #[serde(rename = "e", default, skip_serializing_if = "is_false")]
    pub escaped: bool,
    /// True inside a number or a word.
    #[serde(rename = "n", default, skip_serializing_if = "is_false")]
    pub in_scalar: bool,
    /// The separator that waits for its line: `o` after an opening, `c` after a comma.
    #[serde(rename = "p", default, skip_serializing_if = "is_zero_byte")]
    pub pending: u8,
    /// The scope of the cursor.
    #[serde(rename = "s")]
    pub scope: String,
    /// The version of the object.
    #[serde(rename = "v", default)]
    pub version: ObjectVersion,
}

/// A page of text.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TextPage {
    /// The text.
    pub text: String,
    /// The cursor of the next page.
    #[serde(rename = "nextCursor", default, skip_serializing_if = "String::is_empty")]
    pub next_cursor: String,
    /// True for the last page.
    pub done: bool,
    /// The first line of the page.
    #[serde(rename = "lineStart")]
    pub line_start: i64,
    /// The line where the page ends.
    #[serde(rename = "lineEnd")]
    pub line_end: i64,
    /// True when the page starts inside a line.
    #[serde(default, skip_serializing_if = "is_false")]
    pub continued: bool,
    /// True when the page starts inside a string.
    #[serde(rename = "startInString", default, skip_serializing_if = "is_false")]
    pub start_in_string: bool,
    /// True when the page starts after a backslash.
    #[serde(rename = "startEscaped", default, skip_serializing_if = "is_false")]
    pub start_escaped: bool,
}

/// The counts of the summary.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Summary {
    /// The number of lines of the raw text.
    #[serde(rename = "rawLines")]
    pub raw_lines: i64,
    /// The number of pages of the raw text.
    #[serde(rename = "rawPages")]
    pub raw_pages: i64,
    /// The number of lines of the beautified text.
    #[serde(rename = "beautifyLines")]
    pub beautify_lines: i64,
    /// The number of pages of the beautified text.
    #[serde(rename = "beautifyPages")]
    pub beautify_pages: i64,
    /// The first raw page.
    #[serde(rename = "rawPage", default, skip_serializing_if = "Option::is_none")]
    pub raw_page: Option<TextPage>,
}

/// A node of the tree.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TreeNode {
    /// The key or the index.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub label: String,
    /// The type: object, array, string, number, boolean, null or unknown.
    #[serde(rename = "type")]
    pub kind: String,
    /// A short text of the value.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub preview: String,
    /// True for an object and for an array.
    pub container: bool,
    /// The offset of the first byte of the value.
    pub start: i64,
    /// The offset after the last byte of the value.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub end: i64,
    /// The number of children.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub count: i64,
    /// True when the count is complete.
    #[serde(rename = "countKnown", default, skip_serializing_if = "is_false")]
    pub count_known: bool,
}

/// The state that a tree page keeps for the next page.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TreeCursor {
    /// The offset of the next child.
    #[serde(rename = "o")]
    pub offset: i64,
    /// The index of the next child.
    #[serde(rename = "i")]
    pub index: i64,
    /// The offset of the container.
    #[serde(rename = "n")]
    pub start: i64,
    /// The type of the container.
    #[serde(rename = "t")]
    pub kind: String,
    /// The scope of the cursor.
    #[serde(rename = "s")]
    pub scope: String,
    /// The version of the object.
    #[serde(rename = "v", default)]
    pub version: ObjectVersion,
}

/// A page of the tree.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct TreePage {
    /// The container, or the value of a document that is not a container.
    pub node: TreeNode,
    /// The children.
    pub children: Option<Vec<TreeNode>>,
    /// The cursor of the next page.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub cursor: String,
    /// The index of the next child.
    #[serde(rename = "nextIndex", default, skip_serializing_if = "is_zero")]
    pub next_index: i64,
    /// True for the last page.
    pub done: bool,
}

fn invalid_cursor(message: &str) -> Error {
    Error::api(400, "invalid_cursor", message)
}

fn invalid_json(message: impl Into<String>) -> Error {
    Error::api(422, "invalid_json", message)
}

fn source_ended() -> Error {
    Error::internal("the JSON source ended before the expected end")
}

/// The cursor of a text page. An empty text gives the fallback.
pub fn decode_text_cursor(raw: &str, fallback: TextCursor, expected_scope: &str) -> Result<TextCursor> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(TextCursor {
            scope: expected_scope.to_owned(),
            ..fallback
        });
    }
    let cursor: TextCursor = decode_signed_cursor(raw)
        .ok()
        .filter(|cursor: &TextCursor| cursor.scope == expected_scope && cursor.offset >= 0 && cursor.line >= 1)
        .ok_or_else(|| invalid_cursor("invalid or expired JSON continuation cursor"))?;
    if cursor.stack.len() > MAX_NESTING_DEPTH {
        return Err(invalid_cursor("JSON continuation cursor exceeds the nesting limit"));
    }
    if cursor.stack.bytes().any(|byte| byte != b'{' && byte != b'[') {
        return Err(invalid_cursor("invalid JSON continuation cursor"));
    }
    if cursor.pending != 0 && cursor.pending != b'o' && cursor.pending != b'c' {
        return Err(invalid_cursor("invalid JSON continuation cursor"));
    }
    Ok(cursor)
}

/// The cursor of a tree page. An empty text gives `None`.
pub fn decode_tree_cursor(raw: &str, expected_scope: &str) -> Result<Option<TreeCursor>> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let cursor: TreeCursor = decode_signed_cursor(raw)
        .ok()
        .filter(|cursor: &TreeCursor| {
            cursor.scope == expected_scope
                && cursor.offset >= 0
                && cursor.index >= 0
                && cursor.start >= 0
                && (cursor.kind == "object" || cursor.kind == "array")
        })
        .ok_or_else(|| invalid_cursor("invalid or expired JSON tree continuation cursor"))?;
    Ok(Some(cursor))
}

fn non_negative_offset(value: &str, fallback: i64) -> Result<i64> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(fallback);
    }
    match parse_i64(value) {
        Some(parsed) if parsed >= 0 => Ok(parsed),
        _ => Err(Error::api(
            400,
            "invalid_offset",
            "JSON byte offsets must be non-negative integers",
        )),
    }
}

fn limit_in_range(value: &str, fallback: usize, maximum: usize) -> Result<usize> {
    let value = value.trim();
    if value.is_empty() {
        return Ok(fallback);
    }
    match parse_i64(value) {
        Some(parsed) if parsed > 0 && usize::try_from(parsed).is_ok_and(|parsed| parsed <= maximum) => {
            Ok(usize::try_from(parsed).unwrap_or(fallback))
        }
        _ => Err(Error::api(
            400,
            "invalid_limit",
            format!("limit must be between 1 and {maximum}"),
        )),
    }
}

/// The reader of the object of a JSON route, from an offset. A version of a cursor wins over the ETag.
async fn open_stream(
    req: &Call,
    instance: &Arc<Instance>,
    key: &str,
    offset: i64,
    etag: &str,
    mut version: ObjectVersion,
) -> Result<ObjectStream> {
    if version.is_empty() {
        version.etag = etag.to_owned();
    }
    let reader = WindowReader::open_version(&req.ctx, instance, key, offset, &version).await?;
    Ok(ObjectStream::windows(reader))
}

/// The change of the state of a string after a character of raw text.
fn consume_raw_state(state: &mut TextCursor, value: char) {
    if state.in_string {
        if state.escaped {
            state.escaped = false;
        } else if value == '\\' {
            state.escaped = true;
        } else if value == '"' {
            state.in_string = false;
        }
        return;
    }
    if value == '"' {
        state.in_string = true;
        state.escaped = false;
    }
}

fn matching_close(open: u8) -> u8 {
    match open {
        b'{' => b'}',
        b'[' => b']',
        _ => 0,
    }
}

/// The byte of a character: the low 8 bits.
fn low_byte(value: char) -> u8 {
    (u32::from(value) & 0xFF) as u8
}

fn push_stack(stack: &mut String, value: char) -> Result<()> {
    if stack.len() >= MAX_NESTING_DEPTH {
        return Err(Error::api(
            422,
            "json_too_deep",
            "JSON nesting exceeds the supported limit",
        ));
    }
    stack.push(value);
    Ok(())
}

fn pop_stack(stack: &mut String, close: u8) -> Result<()> {
    let top = stack.as_bytes().last().copied().unwrap_or(0);
    if stack.is_empty() || matching_close(top) != close {
        return Err(invalid_json("JSON contains mismatched container delimiters"));
    }
    stack.pop();
    Ok(())
}

/// Where the beautified text goes: the page or the counter of the summary.
trait Sink {
    fn rune(&mut self, value: char);
    fn text(&mut self, value: &str);
    fn newline(&mut self, depth: usize);
}

/// The text of a beautified page.
#[derive(Default)]
struct PageText {
    text: String,
    lines: i64,
}

impl Sink for PageText {
    fn rune(&mut self, value: char) {
        self.text.push(value);
    }

    fn text(&mut self, value: &str) {
        self.text.push_str(value);
    }

    fn newline(&mut self, depth: usize) {
        self.text.push('\n');
        self.lines += 1;
        for _ in 0..depth {
            self.text.push_str("  ");
        }
    }
}

/// The counts of the pages of a text: the bytes of the page, the line and the number of pages.
struct PageCounter {
    page_bytes: i64,
    page_start_line: i64,
    line: i64,
    pages: i64,
}

impl PageCounter {
    fn new() -> Self {
        Self {
            page_bytes: 0,
            page_start_line: 1,
            line: 1,
            pages: 0,
        }
    }

    fn finish_input_rune(&mut self) {
        let page_bytes = i64::try_from(TEXT_PAGE_BYTES).unwrap_or(i64::MAX);
        if self.page_bytes < page_bytes && self.line - self.page_start_line < TEXT_PAGE_LINES {
            return;
        }
        self.pages += 1;
        self.page_bytes = 0;
        self.page_start_line = self.line;
    }

    fn finish_document(&mut self) {
        if self.page_bytes > 0 || self.pages == 0 {
            self.pages += 1;
        }
    }
}

impl Sink for PageCounter {
    fn rune(&mut self, value: char) {
        self.page_bytes += i64::try_from(value.len_utf8()).unwrap_or(4);
        if value == '\n' {
            self.line += 1;
        }
    }

    fn text(&mut self, value: &str) {
        self.page_bytes += i64::try_from(value.len()).unwrap_or(0);
        self.line += i64::try_from(value.matches('\n').count()).unwrap_or(0);
    }

    fn newline(&mut self, depth: usize) {
        self.page_bytes += 1;
        self.line += 1;
        self.page_bytes += i64::try_from(depth * 2).unwrap_or(0);
    }
}

fn is_json_space(value: char) -> bool {
    matches!(value, ' ' | '\t' | '\r' | '\n')
}

/// Write one character of the beautified text and change the state.
fn beautify_rune<S: Sink>(state: &mut TextCursor, sink: &mut S, value: char) -> Result<()> {
    if state.in_string {
        sink.rune(value);
        if state.escaped {
            state.escaped = false;
        } else if value == '\\' {
            state.escaped = true;
        } else if value == '"' {
            state.in_string = false;
        }
        return Ok(());
    }
    if state.in_scalar {
        if is_json_space(value) || matches!(value, ',' | ']' | '}') {
            state.in_scalar = false;
        } else {
            sink.rune(value);
            return Ok(());
        }
    }
    if is_json_space(value) {
        return Ok(());
    }
    if state.pending != 0 {
        let top = state.stack.as_bytes().last().copied().unwrap_or(0);
        if state.pending == b'o' && !state.stack.is_empty() && matching_close(top) == low_byte(value) {
            state.pending = 0;
            pop_stack(&mut state.stack, low_byte(value))?;
            sink.rune(value);
            return Ok(());
        }
        sink.newline(state.stack.len());
        state.pending = 0;
    }
    match value {
        '"' => {
            state.in_string = true;
            state.escaped = false;
            sink.rune(value);
        }
        '{' | '[' => {
            sink.rune(value);
            push_stack(&mut state.stack, value)?;
            state.pending = b'o';
        }
        ',' => {
            sink.rune(value);
            state.pending = b'c';
        }
        ':' => sink.text(": "),
        '}' | ']' => {
            pop_stack(&mut state.stack, low_byte(value))?;
            sink.newline(state.stack.len());
            sink.rune(value);
        }
        _ => {
            state.in_scalar = true;
            sink.rune(value);
        }
    }
    Ok(())
}

// --- /api/json/raw -----------------------------------------------------------------------------------------------

/// The handler of `/api/json/raw`: a page of the text of the object, byte for byte.
pub fn handle_raw(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        match start(req) {
            Ok(call) => answer(raw_page(&app, &call).await),
            Err(refusal) => *refusal,
        }
    })
}

async fn raw_page(app: &App, req: &Call) -> Result<Response> {
    let target = object_target(app, req, "JSON object key cannot be empty").await?;
    let instance = &target.instance;
    let scope = signed_cursor_scope("json-raw", &instance.cfg.id, &target.key);
    let mut cursor = decode_text_cursor(
        req.query.get("cursor"),
        TextCursor {
            line: 1,
            ..TextCursor::default()
        },
        &scope,
    )?;
    let mut stream = open_stream(
        req,
        instance,
        &target.key,
        cursor.offset,
        &target.etag,
        cursor.version.clone(),
    )
    .await?;
    let mut output = String::with_capacity(TEXT_PAGE_BYTES + 4);
    let start_line = cursor.line;
    let mut line = cursor.line;
    let continued = cursor.continued;
    let start_in_string = cursor.in_string;
    let start_escaped = cursor.escaped;
    let mut done = false;
    while output.len() < TEXT_PAGE_BYTES && line - start_line < TEXT_PAGE_LINES {
        let Some((value, _)) = stream.read_rune().await? else {
            done = true;
            break;
        };
        output.push(value);
        if value == '\n' {
            line += 1;
        }
        consume_raw_state(&mut cursor, value);
    }
    if output.is_empty() && !done {
        done = true;
    }
    if !done && stream.peek_byte().await?.is_none() {
        done = true;
    }
    let next_cursor = if done {
        String::new()
    } else {
        encode_signed_cursor(&TextCursor {
            offset: stream.offset(),
            line,
            continued: !output.ends_with('\n'),
            in_string: cursor.in_string,
            escaped: cursor.escaped,
            scope,
            version: stream.version(),
            ..TextCursor::default()
        })?
    };
    Ok(json(
        200,
        &TextPage {
            text: output,
            next_cursor,
            done,
            line_start: start_line,
            line_end: line,
            continued,
            start_in_string,
            start_escaped,
        },
    ))
}

// --- /api/json/beautify ------------------------------------------------------------------------------------------

/// The handler of `/api/json/beautify`: a page of the text with the indentation of two spaces.
pub fn handle_beautify(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        match start(req) {
            Ok(call) => answer(beautify_page(&app, &call).await),
            Err(refusal) => *refusal,
        }
    })
}

async fn beautify_page(app: &App, req: &Call) -> Result<Response> {
    let target = object_target(app, req, "JSON object key cannot be empty").await?;
    let instance = &target.instance;
    let scope = signed_cursor_scope("json-beautify", &instance.cfg.id, &target.key);
    let cursor = decode_text_cursor(
        req.query.get("cursor"),
        TextCursor {
            line: 1,
            ..TextCursor::default()
        },
        &scope,
    )?;
    let mut stream = open_stream(
        req,
        instance,
        &target.key,
        cursor.offset,
        &target.etag,
        cursor.version.clone(),
    )
    .await?;
    let mut state = cursor.clone();
    let start_line = state.line;
    let mut output = PageText {
        text: String::with_capacity(TEXT_PAGE_BYTES + 4),
        lines: 0,
    };
    let mut done = false;
    while output.text.len() < TEXT_PAGE_BYTES && state.line - start_line < TEXT_PAGE_LINES {
        let Some((value, _)) = stream.read_rune().await? else {
            done = true;
            break;
        };
        let result = beautify_rune(&mut state, &mut output, value);
        state.line = start_line + output.lines;
        result?;
    }
    if !done && stream.peek_byte().await?.is_none() {
        done = true;
    }
    if done {
        if state.in_string || state.escaped || !state.stack.is_empty() {
            return Err(invalid_json("JSON ended before all strings or containers were closed"));
        }
        state.pending = 0;
    }
    state.offset = stream.offset();
    let next_cursor = if done {
        String::new()
    } else {
        state.scope = scope;
        state.version = stream.version();
        encode_signed_cursor(&state)?
    };
    Ok(json(
        200,
        &TextPage {
            text: output.text,
            next_cursor,
            done,
            line_start: start_line,
            line_end: state.line,
            continued: cursor.in_string || cursor.in_scalar,
            start_in_string: cursor.in_string,
            start_escaped: cursor.escaped,
        },
    ))
}

// --- /api/json/summary -------------------------------------------------------------------------------------------

/// The handler of `/api/json/summary`: the lines and the pages of the raw and beautified texts, and the first raw
/// page. It reads the whole object in order.
pub fn handle_summary(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        match start(req) {
            Ok(call) => answer(summary(&app, &call).await),
            Err(refusal) => *refusal,
        }
    })
}

async fn summary(app: &App, req: &Call) -> Result<Response> {
    let target = object_target(app, req, "JSON object key cannot be empty").await?;
    let instance = &target.instance;
    let mut stream = open_stream(req, instance, &target.key, 0, &target.etag, ObjectVersion::default()).await?;
    let mut raw_counter = PageCounter::new();
    let mut beautify_counter = PageCounter::new();
    let mut beautify_state = TextCursor {
        line: 1,
        ..TextCursor::default()
    };
    let mut raw_page_output = String::with_capacity(TEXT_PAGE_BYTES + 4);
    let mut raw_page_state = TextCursor {
        line: 1,
        ..TextCursor::default()
    };
    let mut raw_page_boundary = false;
    let mut raw_page_has_more = false;
    let mut raw_page_offset: i64 = 0;
    let mut raw_page_cursor = TextCursor::default();
    while let Some((value, size)) = stream.read_rune().await? {
        raw_page_offset += i64::try_from(size).unwrap_or(1);
        if raw_page_boundary {
            raw_page_has_more = true;
        } else {
            raw_page_output.push(value);
            if value == '\n' {
                raw_page_state.line += 1;
            }
            consume_raw_state(&mut raw_page_state, value);
            if raw_page_output.len() >= TEXT_PAGE_BYTES || raw_page_state.line > TEXT_PAGE_LINES {
                raw_page_boundary = true;
                raw_page_cursor = TextCursor {
                    offset: raw_page_offset,
                    line: raw_page_state.line,
                    continued: !raw_page_output.ends_with('\n'),
                    in_string: raw_page_state.in_string,
                    escaped: raw_page_state.escaped,
                    ..TextCursor::default()
                };
            }
        }
        raw_counter.rune(value);
        raw_counter.finish_input_rune();
        beautify_rune(&mut beautify_state, &mut beautify_counter, value)?;
        beautify_counter.finish_input_rune();
    }
    if beautify_state.in_string || beautify_state.escaped || !beautify_state.stack.is_empty() {
        return Err(invalid_json("JSON ended before all strings or containers were closed"));
    }
    raw_counter.finish_document();
    beautify_counter.finish_document();
    let mut raw_page = TextPage {
        text: raw_page_output,
        done: !raw_page_has_more,
        line_start: 1,
        line_end: raw_page_state.line,
        ..TextPage::default()
    };
    if raw_page_has_more {
        raw_page_cursor.scope = signed_cursor_scope("json-raw", &instance.cfg.id, &target.key);
        raw_page_cursor.version = stream.version();
        raw_page.next_cursor = encode_signed_cursor(&raw_page_cursor)?;
    }
    Ok(json(
        200,
        &Summary {
            raw_lines: raw_counter.line,
            raw_pages: raw_counter.pages,
            beautify_lines: beautify_counter.line,
            beautify_pages: beautify_counter.pages,
            raw_page: Some(raw_page),
        },
    ))
}

// --- /api/json/tree ----------------------------------------------------------------------------------------------

/// The text of a string with its escapes decoded. `None` when the string is not valid: a character below U+0020,
/// an escape that does not exist, or a bad `\u` escape. A byte that is not UTF-8 gives a replacement character.
fn decode_json_string(raw: &[u8]) -> Option<String> {
    let mut out = String::with_capacity(raw.len());
    let mut index = 0;
    let hex4 = |at: usize| -> Option<u32> {
        let digits = raw.get(at..at + 4)?;
        let mut value = 0u32;
        for digit in digits {
            value = value * 16 + char::from(*digit).to_digit(16)?;
        }
        Some(value)
    };
    while index < raw.len() {
        let byte = raw[index];
        if byte < 0x20 {
            return None;
        }
        if byte == b'\\' {
            let escape = *raw.get(index + 1)?;
            index += 2;
            match escape {
                b'"' => out.push('"'),
                b'\\' => out.push('\\'),
                b'/' => out.push('/'),
                b'b' => out.push('\u{8}'),
                b'f' => out.push('\u{c}'),
                b'n' => out.push('\n'),
                b'r' => out.push('\r'),
                b't' => out.push('\t'),
                b'u' => {
                    let first = hex4(index)?;
                    index += 4;
                    if (0xD800..0xE000).contains(&first) {
                        let pair =
                            (first < 0xDC00 && raw.get(index) == Some(&b'\\') && raw.get(index + 1) == Some(&b'u'))
                                .then(|| hex4(index + 2))
                                .flatten()
                                .filter(|second| (0xDC00..0xE000).contains(second));
                        if let Some(second) = pair {
                            index += 6;
                            let code = 0x10000 + ((first - 0xD800) << 10) + (second - 0xDC00);
                            out.push(char::from_u32(code).unwrap_or(super::util::REPLACEMENT));
                        } else {
                            out.push(super::util::REPLACEMENT);
                        }
                    } else {
                        out.push(char::from_u32(first).unwrap_or(super::util::REPLACEMENT));
                    }
                }
                _ => return None,
            }
            continue;
        }
        if byte < 0x80 {
            out.push(char::from(byte));
            index += 1;
            continue;
        }
        let (value, width) = super::util::decode_rune(&raw[index..]);
        out.push(value);
        index += width.max(1);
    }
    Some(out)
}

/// The preview of a string from its raw bytes (with the escapes). A complete string gives its decoded text. A cut
/// string, or a string that is not valid, gives a text where the usual escapes are replaced by symbols.
pub fn string_preview(raw: &[u8], complete: bool) -> String {
    if complete && let Some(value) = decode_json_string(raw) {
        return value;
    }
    let text = to_valid_utf8(raw);
    let text = text.replace("\\n", "↵");
    let text = text.replace("\\r", "");
    let text = text.replace("\\t", "⇥");
    let text = text.replace("\\\"", "\"");
    let text = text.replace("\\\\", "\\");
    to_valid_utf8(text.as_bytes())
}

/// Skip the white space. False at the end of the object.
async fn skip_whitespace(stream: &mut ObjectStream) -> Result<bool> {
    loop {
        match stream.peek_byte().await? {
            None => return Ok(false),
            Some(b' ' | b'\t' | b'\r' | b'\n') => {
                stream.read_byte().await?;
            }
            Some(_) => return Ok(true),
        }
    }
}

struct StringRead {
    end: i64,
    preview: String,
    truncated: bool,
}

/// Read a string at the position. It keeps at most `capture_limit` bytes of its raw text.
async fn read_json_string(stream: &mut ObjectStream, capture_limit: usize) -> Result<StringRead> {
    let start = stream.offset();
    let opening = stream.read_byte().await?.ok_or_else(source_ended)?;
    if opening != b'"' {
        return Err(invalid_json(format!("expected JSON string at byte {start}")));
    }
    let mut captured: Vec<u8> = Vec::with_capacity(capture_limit.min(256));
    let mut escaped = false;
    let mut truncated = false;
    loop {
        let Some(value) = stream.read_byte().await? else {
            return Err(invalid_json("JSON ended inside a string"));
        };
        if escaped {
            if captured.len() + 2 <= capture_limit {
                captured.push(b'\\');
                captured.push(value);
            } else {
                truncated = true;
            }
            escaped = false;
            continue;
        }
        if value == b'\\' {
            escaped = true;
            continue;
        }
        if value == b'"' {
            return Ok(StringRead {
                end: stream.offset(),
                preview: string_preview(&captured, !truncated),
                truncated,
            });
        }
        if captured.len() < capture_limit {
            captured.push(value);
        } else {
            truncated = true;
        }
    }
}

/// Skip a container. Gives the offset after it and the number of its direct children.
async fn skip_json_container(stream: &mut ObjectStream) -> Result<(i64, i64)> {
    let opening = stream.read_byte().await?.ok_or_else(source_ended)?;
    if opening != b'{' && opening != b'[' {
        return Err(invalid_json("expected a JSON object or array"));
    }
    let mut stack: Vec<u8> = vec![opening];
    let mut in_string = false;
    let mut escaped = false;
    let mut expect_entry = true;
    let mut direct_children: i64 = 0;
    while !stack.is_empty() {
        let Some(value) = stream.read_byte().await? else {
            return Err(invalid_json("JSON ended before a container was closed"));
        };
        if in_string {
            if escaped {
                escaped = false;
            } else if value == b'\\' {
                escaped = true;
            } else if value == b'"' {
                in_string = false;
            }
            continue;
        }
        if stack.len() == 1 {
            if expect_entry {
                match value {
                    b' ' | b'\t' | b'\r' | b'\n' => continue,
                    close if close == matching_close(opening) => {
                        stack.clear();
                        continue;
                    }
                    _ => {
                        direct_children += 1;
                        expect_entry = false;
                    }
                }
            } else if value == b',' {
                expect_entry = true;
                continue;
            }
        }
        match value {
            b'"' => in_string = true,
            b'{' | b'[' => {
                if stack.len() >= MAX_NESTING_DEPTH {
                    return Err(Error::api(
                        422,
                        "json_too_deep",
                        "JSON nesting exceeds the supported limit",
                    ));
                }
                stack.push(value);
            }
            b'}' | b']' => {
                let top = stack.last().copied().unwrap_or(0);
                if matching_close(top) != value {
                    return Err(invalid_json(format!(
                        "mismatched JSON delimiter at byte {}",
                        stream.offset() - 1
                    )));
                }
                stack.pop();
            }
            _ => {}
        }
    }
    Ok((stream.offset(), direct_children))
}

fn is_scalar_delimiter(value: u8) -> bool {
    matches!(value, b' ' | b'\t' | b'\r' | b'\n' | b',' | b']' | b'}')
}

/// The node of the value at the position. A container is skipped, and its end and its count are known.
async fn inspect_json_value(stream: &mut ObjectStream) -> Result<TreeNode> {
    if !skip_whitespace(stream).await? {
        return Err(source_ended());
    }
    let start = stream.offset();
    let value = stream.peek_byte().await?.ok_or_else(source_ended)?;
    match value {
        b'{' | b'[' => {
            let (kind, preview) = if value == b'[' {
                ("array", "[…]")
            } else {
                ("object", "{…}")
            };
            let (end, count) = skip_json_container(stream).await?;
            Ok(TreeNode {
                kind: kind.to_owned(),
                preview: preview.to_owned(),
                container: true,
                start,
                end,
                count,
                count_known: true,
                ..TreeNode::default()
            })
        }
        b'"' => {
            let read = read_json_string(stream, TREE_PREVIEW_BYTES).await?;
            let mut preview = read.preview;
            if read.truncated {
                preview.push('…');
            }
            Ok(TreeNode {
                kind: "string".to_owned(),
                preview: format!("\"{preview}\""),
                start,
                end: read.end,
                ..TreeNode::default()
            })
        }
        _ => {
            let mut captured: Vec<u8> = Vec::with_capacity(64);
            let mut truncated = false;
            while let Some(current) = stream.peek_byte().await? {
                if is_scalar_delimiter(current) {
                    break;
                }
                stream.read_byte().await?;
                if captured.len() < TREE_PREVIEW_BYTES {
                    captured.push(current);
                } else {
                    truncated = true;
                }
            }
            let text = lossy_bytes(&captured);
            let mut raw = text.trim().to_owned();
            let kind = if raw == "true" || raw == "false" {
                "boolean"
            } else if raw == "null" {
                "null"
            } else if parse_float(&raw).is_none() {
                "unknown"
            } else {
                "number"
            };
            if truncated {
                raw.push('…');
            }
            Ok(TreeNode {
                kind: kind.to_owned(),
                preview: raw,
                start,
                end: stream.offset(),
                ..TreeNode::default()
            })
        }
    }
}

struct TreeChildren {
    children: Vec<TreeNode>,
    next_offset: i64,
    next_index: i64,
    done: bool,
}

/// Read the children of a container: at most `limit`.
async fn read_tree_page(
    stream: &mut ObjectStream,
    node: &TreeNode,
    cursor_provided: bool,
    mut next_index: i64,
    limit: usize,
) -> Result<TreeChildren> {
    if node.kind != "object" && node.kind != "array" {
        return Ok(TreeChildren {
            children: Vec::new(),
            next_offset: 0,
            next_index,
            done: true,
        });
    }
    if !cursor_provided {
        if !skip_whitespace(stream).await? {
            return Err(source_ended());
        }
        let opening = stream.read_byte().await?.ok_or_else(source_ended)?;
        let expected = if node.kind == "array" { b'[' } else { b'{' };
        if opening != expected {
            return Err(invalid_json(format!(
                "JSON {} no longer starts at byte {}",
                node.kind, node.start
            )));
        }
    }
    let closing = if node.kind == "array" { b']' } else { b'}' };
    let mut children: Vec<TreeNode> = Vec::with_capacity(limit.min(256));
    while children.len() < limit {
        if !skip_whitespace(stream).await? {
            return Err(invalid_json("JSON ended while reading container children"));
        }
        let current = stream.peek_byte().await?.ok_or_else(source_ended)?;
        if current == closing {
            stream.read_byte().await?;
            return Ok(TreeChildren {
                children,
                next_offset: 0,
                next_index,
                done: true,
            });
        }
        let mut label = next_index.to_string();
        if node.kind == "object" {
            let key = read_json_string(stream, TREE_KEY_PREVIEW_BYTES).await?;
            label = key.preview;
            if key.truncated {
                label.push('…');
            }
            if !skip_whitespace(stream).await? {
                return Err(source_ended());
            }
            let colon = stream.read_byte().await?;
            if colon != Some(b':') {
                return Err(invalid_json(format!(
                    "expected ':' after JSON property at byte {}",
                    stream.offset()
                )));
            }
        }
        let mut child = inspect_json_value(stream).await?;
        child.label = label;
        children.push(child);
        next_index += 1;
        if !skip_whitespace(stream).await? {
            return Err(source_ended());
        }
        let separator = stream.read_byte().await?.ok_or_else(source_ended)?;
        if separator == b',' {
            if children.len() >= limit {
                return Ok(TreeChildren {
                    children,
                    next_offset: stream.offset(),
                    next_index,
                    done: false,
                });
            }
        } else if separator == closing {
            return Ok(TreeChildren {
                children,
                next_offset: 0,
                next_index,
                done: true,
            });
        } else {
            return Err(invalid_json(format!(
                "expected ',' or closing delimiter at byte {}",
                stream.offset() - 1
            )));
        }
    }
    Ok(TreeChildren {
        children,
        next_offset: stream.offset(),
        next_index,
        done: false,
    })
}

/// The handler of `/api/json/tree`: the children of a container, from the start of the document or from a node.
pub fn handle_tree(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        match start(req) {
            Ok(call) => answer(tree_page(&app, &call).await),
            Err(refusal) => *refusal,
        }
    })
}

async fn tree_page(app: &App, req: &Call) -> Result<Response> {
    let target = object_target(app, req, "JSON object key cannot be empty").await?;
    let instance = &target.instance;
    let mut start = non_negative_offset(req.query.get("start"), 0)?;
    let scope = signed_cursor_scope("json-tree", &instance.cfg.id, &target.key);
    let cursor_state = decode_tree_cursor(req.query.get("cursor"), &scope)?;
    let mut next_index = non_negative_offset(req.query.get("index"), 0)?;
    let limit = limit_in_range(req.query.get("limit"), TREE_DEFAULT_PAGE_SIZE, TREE_MAX_PAGE_SIZE)?;
    let mut node_type = req.query.get("type").trim().to_lowercase();
    if !node_type.is_empty() && node_type != "object" && node_type != "array" {
        return Err(Error::api(
            400,
            "invalid_node_type",
            "JSON tree node type must be object or array",
        ));
    }
    let mut stream_offset = start;
    let mut version = ObjectVersion {
        etag: target.etag.clone(),
        ..ObjectVersion::default()
    };
    let cursor_provided = cursor_state.is_some();
    if let Some(state) = cursor_state {
        if start != 0 && start != state.start {
            return Err(Error::api(
                400,
                "invalid_cursor_scope",
                "the JSON tree cursor does not belong to this node",
            ));
        }
        if !node_type.is_empty() && node_type != state.kind {
            return Err(Error::api(
                400,
                "invalid_cursor_scope",
                "the JSON tree cursor does not belong to this node type",
            ));
        }
        stream_offset = state.offset;
        start = state.start;
        next_index = state.index;
        node_type = state.kind;
        version = state.version;
    }
    let mut stream = open_stream(req, instance, &target.key, stream_offset, &target.etag, version).await?;
    let mut node;
    if node_type.is_empty() {
        if !matches!(skip_whitespace(&mut stream).await, Ok(true)) {
            return Err(invalid_json("JSON document is empty"));
        }
        let root_start = stream.offset();
        let opening = stream.peek_byte().await?.ok_or_else(source_ended)?;
        if opening == b'{' || opening == b'[' {
            node = TreeNode {
                kind: "object".to_owned(),
                preview: "{…}".to_owned(),
                container: true,
                start: root_start,
                ..TreeNode::default()
            };
            if opening == b'[' {
                "array".clone_into(&mut node.kind);
                "[…]".clone_into(&mut node.preview);
            }
        } else {
            let node = inspect_json_value(&mut stream).await?;
            return Ok(json(
                200,
                &TreePage {
                    node,
                    children: None,
                    done: true,
                    ..TreePage::default()
                },
            ));
        }
    } else {
        node = TreeNode {
            preview: if node_type == "object" { "{…}" } else { "[…]" }.to_owned(),
            kind: node_type,
            container: true,
            start,
            ..TreeNode::default()
        };
    }
    let page = read_tree_page(&mut stream, &node, cursor_provided, next_index, limit).await?;
    if page.done {
        node.count = page.next_index;
        node.count_known = true;
    }
    let cursor = if !page.done && page.next_offset > 0 {
        encode_signed_cursor(&TreeCursor {
            offset: page.next_offset,
            index: page.next_index,
            start: node.start,
            kind: node.kind.clone(),
            scope,
            version: stream.version(),
        })?
    } else {
        String::new()
    };
    Ok(json(
        200,
        &TreePage {
            node,
            children: Some(page.children),
            cursor,
            next_index: page.next_index,
            done: page.done,
        },
    ))
}

#[cfg(test)]
#[path = "json_tests.rs"]
mod tests;
