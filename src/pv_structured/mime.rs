//! The MIME reader of the e-mail preview: the header block, the media type with its parameters, the quoted-printable
//! decoder and the multipart reader.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};

use super::text::lossy;

/// The headers of a message or of a part: the canonical name and the values in order.
pub type Headers = BTreeMap<String, Vec<String>>;

/// A byte that a header name may hold.
fn is_header_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
        )
}

/// The canonical form of a header name: the first letter and each letter after a dash in uppercase. A name with a
/// byte that no name may hold has no form (`None`); a name with a space stays as it is.
pub fn canonical_key(name: &[u8]) -> Option<String> {
    let mut has_space = false;
    for byte in name {
        if is_header_name_byte(*byte) {
            continue;
        }
        if *byte == b' ' {
            has_space = true;
            continue;
        }
        return None;
    }
    if has_space {
        return Some(String::from_utf8_lossy(name).into_owned());
    }
    let mut out = String::with_capacity(name.len());
    let mut upper = true;
    for byte in name {
        let mut byte = *byte;
        if upper && byte.is_ascii_lowercase() {
            byte = byte.to_ascii_uppercase();
        } else if !upper && byte.is_ascii_uppercase() {
            byte = byte.to_ascii_lowercase();
        }
        out.push(char::from(byte));
        upper = byte == b'-';
    }
    Some(out)
}

/// The canonical form of a name of a header that the program asks for.
pub fn canonical_key_str(name: &str) -> String {
    canonical_key(name.as_bytes()).unwrap_or_else(|| name.to_owned())
}

/// The value of the first header with this name, or an empty text.
pub fn header_get<'a>(headers: &'a Headers, name: &str) -> &'a str {
    headers
        .get(&canonical_key_str(name))
        .and_then(|values| values.first())
        .map_or("", String::as_str)
}

/// The value of the first header whose name matches without a difference of case, or an empty text.
pub fn first_header_value<'a>(headers: &'a Headers, name: &str) -> &'a str {
    headers
        .iter()
        .find(|(key, values)| key.eq_ignore_ascii_case(name) && !values.is_empty())
        .map_or("", |(_, values)| values[0].as_str())
}

/// Why the read of a header block stopped before a blank line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderError {
    /// The data ended.
    EndOfData,
    /// The block is not valid.
    Malformed,
    /// The block is too large.
    TooLarge,
}

/// A reader of lines: the line end is LF, and a CR before it goes away.
struct LineReader<'a> {
    data: &'a [u8],
    position: usize,
}

impl<'a> LineReader<'a> {
    fn read_line(&mut self) -> Option<&'a [u8]> {
        if self.position >= self.data.len() {
            return None;
        }
        let rest = &self.data[self.position..];
        match rest.iter().position(|byte| *byte == b'\n') {
            Some(index) => {
                self.position += index + 1;
                let mut line = &rest[..index];
                if let Some((&b'\r', head)) = line.split_last() {
                    line = head;
                }
                Some(line)
            }
            None => {
                self.position = self.data.len();
                Some(rest)
            }
        }
    }

    /// Skip the blanks and the tabs; gives the number of bytes.
    fn skip_blanks(&mut self) -> usize {
        let mut count = 0;
        while self.position < self.data.len() && (self.data[self.position] == b' ' || self.data[self.position] == b'\t')
        {
            self.position += 1;
            count += 1;
        }
        count
    }
}

fn trim_blanks(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| *byte != b' ' && *byte != b'\t')
        .unwrap_or(bytes.len());
    let bytes = &bytes[start..];
    let end = bytes
        .iter()
        .rposition(|byte| *byte != b' ' && *byte != b'\t')
        .map_or(0, |index| index + 1);
    &bytes[..end]
}

/// The result of the read of a header block.
pub struct HeaderBlock {
    /// The headers that the reader found before it stopped.
    pub headers: Headers,
    /// The number of bytes that the block uses, with its blank line.
    pub consumed: usize,
    /// The reason why the block ended, when it did not end with a blank line.
    pub error: Option<HeaderError>,
}

/// A byte that a header value may hold: a printable character, a blank, a tab or a byte above 0x7f.
fn is_header_value_byte(byte: u8) -> bool {
    (0x21..0x7f).contains(&byte) || byte == b' ' || byte == b'\t' || byte >= 0x80
}

/// The kind of reader of a header block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HeaderMode {
    /// The header of a message: a line with a name that no name may hold keeps the name as it is, a line with no
    /// name does not count, and a value has any byte.
    Message,
    /// The header of a part of a multipart body: a name that no name may hold, a missing name and a control byte
    /// in a value make the block not valid. The block has bounds.
    Part,
}

/// Read the header block at the start of the data: lines `Name: value` with continuation lines, to a blank line.
/// `max_memory` and `max_headers` bound the block of a part.
pub fn read_header_block(data: &[u8], mode: HeaderMode, max_memory: i64, max_headers: i64) -> HeaderBlock {
    let strict = mode == HeaderMode::Part;
    let mut reader = LineReader { data, position: 0 };
    let mut headers = Headers::new();
    let mut max_memory = max_memory;
    let mut max_headers = max_headers;
    macro_rules! finish {
        ($error:expr) => {
            return HeaderBlock {
                headers,
                consumed: reader.position,
                error: $error,
            }
        };
    }
    if max_memory < 0 {
        finish!(Some(HeaderError::TooLarge));
    }
    if matches!(data.first(), Some(b' ' | b'\t')) {
        finish!(Some(HeaderError::Malformed));
    }
    loop {
        let Some(first) = reader.read_line() else {
            finish!(Some(HeaderError::EndOfData));
        };
        if first.is_empty() {
            finish!(None);
        }
        if strict && !first.contains(&b':') {
            finish!(Some(HeaderError::Malformed));
        }
        if first.len() as i64 > max_memory {
            finish!(Some(HeaderError::TooLarge));
        }
        let mut line: Vec<u8> = trim_blanks(first).to_vec();
        let limit = max_memory - line.len() as i64;
        // The continuation lines start with a blank or a tab.
        while reader.skip_blanks() > 0 {
            line.push(b' ');
            if line.len() as i64 >= limit {
                finish!(Some(HeaderError::TooLarge));
            }
            let Some(continued) = reader.read_line() else {
                // The data ends in the blanks of a continuation: the line keeps what it has.
                break;
            };
            if continued.len() as i64 > limit - line.len() as i64 {
                break;
            }
            line.extend_from_slice(trim_blanks(continued));
        }
        if !strict && line.is_empty() {
            // A line of blanks ends the block of a message.
            finish!(None);
        }
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            finish!(Some(HeaderError::Malformed));
        };
        let (name, value) = (&line[..colon], &line[colon + 1..]);
        let key = if strict {
            let Some(key) = canonical_key(name).filter(|key| !key.is_empty()) else {
                finish!(Some(HeaderError::Malformed));
            };
            if !value.iter().all(|byte| is_header_value_byte(*byte)) {
                finish!(Some(HeaderError::Malformed));
            }
            key
        } else {
            let key = canonical_key(name).unwrap_or_else(|| lossy(name));
            if key.is_empty() {
                continue;
            }
            key
        };
        max_headers -= 1;
        if max_headers < 0 {
            finish!(Some(HeaderError::TooLarge));
        }
        let value_start = value
            .iter()
            .position(|byte| *byte != b' ' && *byte != b'\t')
            .unwrap_or(value.len());
        let value = lossy(&value[value_start..]);
        if !headers.contains_key(&key) {
            max_memory -= key.len() as i64 + 200;
        }
        max_memory -= value.len() as i64;
        if max_memory < 0 {
            finish!(Some(HeaderError::TooLarge));
        }
        headers.entry(key).or_default().push(value);
    }
}

/// A media type with its parameters.
#[derive(Clone, Debug, Default)]
pub struct MediaType {
    /// The media type in lowercase, or an empty text.
    pub media_type: String,
    /// The parameters: the names in lowercase.
    pub params: HashMap<String, String>,
    /// True when the text is not a valid media type.
    pub failed: bool,
}

fn is_tspecial(byte: u8) -> bool {
    b"()<>@,;:\\\"/[]?=".contains(&byte)
}

fn is_token_char(byte: u8) -> bool {
    byte > 0x20 && byte < 0x7f && !is_tspecial(byte)
}

fn consume_token(value: &str) -> (&str, &str) {
    for (index, byte) in value.bytes().enumerate() {
        if !is_token_char(byte) {
            return (&value[..index], &value[index..]);
        }
    }
    (value, "")
}

fn consume_value(value: &str) -> (String, &str) {
    if value.is_empty() {
        return (String::new(), value);
    }
    if !value.starts_with('"') {
        let (token, rest) = consume_token(value);
        return (token.to_owned(), rest);
    }
    let bytes = value.as_bytes();
    let mut buffer: Vec<u8> = Vec::new();
    let mut index = 1;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'"' {
            return (lossy(&buffer), &value[index + 1..]);
        }
        if byte == b'\\' && index + 1 < bytes.len() && is_tspecial(bytes[index + 1]) {
            buffer.push(bytes[index + 1]);
            index += 2;
            continue;
        }
        if byte == b'\r' || byte == b'\n' {
            return (String::new(), value);
        }
        buffer.push(byte);
        index += 1;
    }
    (String::new(), value)
}

fn trim_start_space(value: &str) -> &str {
    value.trim_start_matches(char::is_whitespace)
}

/// One parameter: the name, the value and the rest. A name that is empty means that the text has no parameter.
fn consume_media_param(value: &str) -> (String, String, &str) {
    let rest = trim_start_space(value);
    let Some(rest) = rest.strip_prefix(';') else {
        return (String::new(), String::new(), value);
    };
    let rest = trim_start_space(rest);
    let (param, rest) = consume_token(rest);
    let param = param.to_lowercase();
    if param.is_empty() {
        return (String::new(), String::new(), value);
    }
    let rest = trim_start_space(rest);
    let Some(rest) = rest.strip_prefix('=') else {
        return (String::new(), String::new(), value);
    };
    let rest = trim_start_space(rest);
    let (parsed, rest_after) = consume_value(rest);
    if parsed.is_empty() && rest_after.len() == rest.len() {
        return (String::new(), String::new(), value);
    }
    (param, parsed, rest_after)
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Decode the `%XX` escapes. `None` when an escape is not valid.
fn percent_unescape(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            out.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return None;
        }
        let high = hex_value(bytes[index + 1])?;
        let low = hex_value(bytes[index + 2])?;
        out.push(high << 4 | low);
        index += 3;
    }
    Some(lossy(&out))
}

/// Decode a value of the form `charset'language'text` with percent escapes.
fn decode_extended(value: &str) -> Option<String> {
    let (charset, rest) = value.split_once('\'')?;
    let (_, text) = rest.split_once('\'')?;
    match charset.to_lowercase().as_str() {
        "us-ascii" | "utf-8" => percent_unescape(text),
        _ => None,
    }
}

/// Read a media type with its parameters (the form of the header Content-Type and Content-Disposition). The
/// parameters with a number or a star (RFC 2231) are joined and decoded.
pub fn parse_media_type(value: &str) -> MediaType {
    let base = value.split(';').next().unwrap_or("");
    let media_type = base.to_lowercase();
    let media_type = media_type.trim().to_owned();
    // The check of the media type.
    {
        let (first, rest) = consume_token(&media_type);
        let valid = if first.is_empty() {
            false
        } else if rest.is_empty() {
            true
        } else if let Some(after) = rest.strip_prefix('/') {
            let (subtype, remaining) = consume_token(after);
            !subtype.is_empty() && remaining.is_empty()
        } else {
            false
        };
        if !valid {
            return MediaType {
                failed: true,
                ..MediaType::default()
            };
        }
    }
    let mut params: HashMap<String, String> = HashMap::new();
    let mut continuation: HashMap<String, HashMap<String, String>> = HashMap::new();
    let mut remaining = &value[base.len()..];
    while !remaining.is_empty() {
        remaining = trim_start_space(remaining);
        if remaining.is_empty() {
            break;
        }
        let (key, parsed, rest) = consume_media_param(remaining);
        if key.is_empty() {
            if rest.trim() == ";" {
                break;
            }
            return MediaType {
                media_type,
                failed: true,
                ..MediaType::default()
            };
        }
        let map = match key.split_once('*') {
            Some((base_name, _)) => continuation.entry(base_name.to_owned()).or_default(),
            None => &mut params,
        };
        if let Some(existing) = map.get(&key)
            && *existing != parsed
        {
            return MediaType {
                failed: true,
                ..MediaType::default()
            };
        }
        map.insert(key, parsed);
        remaining = rest;
    }
    for (key, pieces) in continuation {
        let single = format!("{key}*");
        if let Some(piece) = pieces.get(&single) {
            if let Some(decoded) = decode_extended(piece) {
                params.insert(key, decoded);
            }
            continue;
        }
        let mut buffer = String::new();
        let mut valid = false;
        for index in 0usize.. {
            let simple = format!("{key}*{index}");
            if let Some(piece) = pieces.get(&simple) {
                valid = true;
                buffer.push_str(piece);
                continue;
            }
            let encoded = format!("{simple}*");
            let Some(piece) = pieces.get(&encoded) else {
                break;
            };
            valid = true;
            if index == 0 {
                if let Some(decoded) = decode_extended(piece) {
                    buffer.push_str(&decoded);
                }
            } else if let Some(decoded) = percent_unescape(piece) {
                buffer.push_str(&decoded);
            }
        }
        if valid {
            params.insert(key, buffer);
        }
    }
    MediaType {
        media_type,
        params,
        failed: false,
    }
}

/// The result of a quoted-printable decode: the bytes, and true when the decoder met an error.
pub struct Decoded {
    /// The bytes that the decoder produced.
    pub bytes: Vec<u8>,
    /// True when the decoder stopped with an error.
    pub failed: bool,
}

/// The longest line that the decoder reads at one time.
const LINE_BUFFER: usize = 4096;

/// Decode quoted-printable text. A malformed escape stays as it is when the next byte is not a line end.
pub fn decode_quoted_printable(data: &[u8]) -> Decoded {
    let mut out: Vec<u8> = Vec::with_capacity(data.len());
    let mut position = 0usize;
    let mut line: Vec<u8> = Vec::new();
    let mut line_index = 0usize;
    // The last read error: `None`, the end of the data (clean) or another error.
    let mut read_error: Option<bool> = None;
    loop {
        if line_index >= line.len() {
            if let Some(is_end) = read_error {
                return Decoded {
                    bytes: out,
                    failed: !is_end,
                };
            }
            let rest = &data[position..];
            let window = &rest[..rest.len().min(LINE_BUFFER)];
            let (chunk, error) = match window.iter().position(|byte| *byte == b'\n') {
                Some(index) => (&rest[..=index], None),
                None if rest.len() < LINE_BUFFER => (rest, Some(true)),
                None => (window, Some(false)),
            };
            position += chunk.len();
            read_error = error;
            let has_lf = chunk.ends_with(b"\n");
            let has_crlf = chunk.ends_with(b"\r\n");
            let mut kept = chunk.len();
            while kept > 0 && matches!(chunk[kept - 1], b'\n' | b'\r' | b' ' | b'\t') {
                kept -= 1;
            }
            let mut current: Vec<u8> = chunk[..kept].to_vec();
            if current.ends_with(b"=") {
                let stripped_start = chunk[kept..]
                    .iter()
                    .position(|byte| *byte != b' ' && *byte != b'\t')
                    .map_or(chunk.len(), |index| kept + index);
                let right_stripped = &chunk[stripped_start..];
                current.pop();
                let line_end_next = right_stripped.starts_with(b"\n") || right_stripped.starts_with(b"\r\n");
                if !line_end_next && !(right_stripped.is_empty() && !current.is_empty() && read_error == Some(true)) {
                    read_error = Some(false);
                }
            } else if has_lf {
                if has_crlf {
                    current.extend_from_slice(b"\r\n");
                } else {
                    current.push(b'\n');
                }
            }
            line = current;
            line_index = 0;
            continue;
        }
        let mut byte = line[line_index];
        if byte == b'=' {
            let remaining = &line[line_index + 1..];
            let decoded = if remaining.len() < 2 {
                None
            } else {
                match (hex_value(remaining[0]), hex_value(remaining[1])) {
                    (Some(high), Some(low)) => Some(high << 4 | low),
                    _ => None,
                }
            };
            match decoded {
                Some(value) => {
                    byte = value;
                    line_index += 2;
                }
                None => {
                    let next = line.get(line_index + 1).copied();
                    match next {
                        Some(next) if next != b'\r' && next != b'\n' => byte = b'=',
                        _ => {
                            return Decoded {
                                bytes: out,
                                failed: true,
                            };
                        }
                    }
                }
            }
        } else if byte == b'\t' || byte == b'\r' || byte == b'\n' || byte >= 0x80 {
            // Kept as it is.
        } else if !(b' '..=b'~').contains(&byte) {
            return Decoded {
                bytes: out,
                failed: true,
            };
        }
        out.push(byte);
        line_index += 1;
    }
}

/// One part of a multipart body.
pub struct Part<'a> {
    /// The headers of the part. A quoted-printable part has no header `Content-Transfer-Encoding`.
    pub headers: Headers,
    /// The body of the part. A quoted-printable part is decoded.
    pub body: Cow<'a, [u8]>,
    /// True when the body ended without a boundary or with a decoder error: the preview skips the body.
    pub failed: bool,
}

const MAX_PART_HEADER_BYTES: i64 = 10 << 20;
const MAX_PART_HEADERS: i64 = 10_000;
/// The size of the buffer of the multipart reader: a line is at most this long.
const BOUNDARY_LINE_LIMIT: usize = 4096;

/// A reader of the parts of a multipart body.
pub struct MultipartReader<'a> {
    data: &'a [u8],
    position: usize,
    nl: Vec<u8>,
    nl_dash_boundary: Vec<u8>,
    dash_boundary: Vec<u8>,
    dash_boundary_dash: Vec<u8>,
    parts_read: usize,
    clean_end: bool,
}

/// The end of the data of a part: the end and whether a boundary ended it.
struct BodyEnd {
    end: usize,
    clean: bool,
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// True when the text after a prefix of a boundary ends the boundary.
/// A blank, a tab or a line end must follow, or two dashes, or the data must end.
fn matches_after_prefix(buffer: &[u8], prefix_length: usize) -> bool {
    if buffer.len() == prefix_length {
        return true;
    }
    match buffer[prefix_length] {
        b' ' | b'\t' | b'\r' | b'\n' => true,
        b'-' => buffer.get(prefix_length + 1) == Some(&b'-'),
        _ => false,
    }
}

fn skip_blanks(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| *byte != b' ' && *byte != b'\t')
        .unwrap_or(bytes.len());
    &bytes[start..]
}

impl<'a> MultipartReader<'a> {
    /// A reader over the body of a multipart message. `clean_end` is false when the body is the data of a part
    /// that ended without a boundary.
    pub fn new(data: &'a [u8], boundary: &str, clean_end: bool) -> Self {
        let dash_boundary = [b"--".as_slice(), boundary.as_bytes()].concat();
        let nl = b"\r\n".to_vec();
        Self {
            data,
            position: 0,
            nl_dash_boundary: [nl.as_slice(), dash_boundary.as_slice()].concat(),
            dash_boundary_dash: [dash_boundary.as_slice(), b"--".as_slice()].concat(),
            dash_boundary,
            nl,
            parts_read: 0,
            clean_end,
        }
    }

    fn is_final_boundary(&self, line: &[u8]) -> bool {
        if !line.starts_with(&self.dash_boundary_dash) {
            return false;
        }
        let rest = skip_blanks(&line[self.dash_boundary_dash.len()..]);
        rest.is_empty() || rest == self.nl.as_slice()
    }

    fn is_boundary_delimiter_line(&mut self, line: &[u8]) -> bool {
        if !line.starts_with(&self.dash_boundary) {
            return false;
        }
        let rest = skip_blanks(&line[self.dash_boundary.len()..]);
        if self.parts_read == 0 && rest == b"\n" {
            self.nl.remove(0);
            self.nl_dash_boundary.remove(0);
        }
        rest == self.nl.as_slice()
    }

    /// One line, with its line end. The error is `Some(true)` at the end of the data.
    /// The error is `Some(false)` for a line that is too long, or for data that has no clean end.
    fn read_slice(&mut self) -> (&'a [u8], Option<bool>) {
        let rest = &self.data[self.position..];
        let window = &rest[..rest.len().min(BOUNDARY_LINE_LIMIT)];
        match window.iter().position(|byte| *byte == b'\n') {
            Some(index) => {
                self.position += index + 1;
                (&rest[..=index], None)
            }
            None if rest.len() < BOUNDARY_LINE_LIMIT => {
                self.position = self.data.len();
                (rest, Some(self.clean_end))
            }
            None => {
                self.position += window.len();
                (window, Some(false))
            }
        }
    }

    /// The end of the body of the part that starts at `from`.
    fn scan_body(&self, from: usize) -> BodyEnd {
        let mut consumed = 0usize;
        loop {
            let buffer = &self.data[from + consumed..];
            if consumed == 0 {
                if buffer.starts_with(&self.dash_boundary) {
                    if matches_after_prefix(buffer, self.dash_boundary.len()) {
                        return BodyEnd { end: from, clean: true };
                    }
                    consumed += self.dash_boundary.len();
                    continue;
                }
                if self.dash_boundary.starts_with(buffer) {
                    return BodyEnd {
                        end: from,
                        clean: false,
                    };
                }
            }
            if let Some(index) = find(buffer, &self.nl_dash_boundary) {
                if matches_after_prefix(&buffer[index..], self.nl_dash_boundary.len()) {
                    return BodyEnd {
                        end: from + consumed + index,
                        clean: true,
                    };
                }
                consumed += index + self.nl_dash_boundary.len();
                continue;
            }
            if self.nl_dash_boundary.starts_with(buffer) {
                return BodyEnd {
                    end: from + consumed,
                    clean: false,
                };
            }
            let first = self.nl_dash_boundary[0];
            if let Some(index) = buffer.iter().rposition(|byte| *byte == first)
                && self.nl_dash_boundary.starts_with(&buffer[index..])
            {
                return BodyEnd {
                    end: from + consumed + index,
                    clean: false,
                };
            }
            return BodyEnd {
                end: from + consumed + buffer.len(),
                clean: false,
            };
        }
    }

    /// The next part, or `None` at the end of the body or at the first error.
    pub fn next_part(&mut self) -> Option<Part<'a>> {
        if self.dash_boundary == b"--" {
            return None;
        }
        let mut expect_new_part = false;
        loop {
            let (line, error) = self.read_slice();
            if error == Some(true) && self.is_final_boundary(line) {
                return None;
            }
            if error.is_some() {
                return None;
            }
            if self.is_boundary_delimiter_line(line) {
                self.parts_read += 1;
                return self.new_part();
            }
            if self.is_final_boundary(line) {
                return None;
            }
            if expect_new_part {
                return None;
            }
            if self.parts_read == 0 {
                continue;
            }
            if line == self.nl.as_slice() {
                expect_new_part = true;
                continue;
            }
            return None;
        }
    }

    fn new_part(&mut self) -> Option<Part<'a>> {
        let block = read_header_block(
            &self.data[self.position..],
            HeaderMode::Part,
            MAX_PART_HEADER_BYTES,
            MAX_PART_HEADERS,
        );
        if block.error.is_some() {
            return None;
        }
        let mut headers = block.headers;
        let start = self.position + block.consumed;
        let body_end = self.scan_body(start);
        self.position = body_end.end;
        let raw = &self.data[start..body_end.end];
        let mut failed = !body_end.clean;
        let mut body: Cow<'a, [u8]> = Cow::Borrowed(raw);
        if header_get(&headers, "Content-Transfer-Encoding").eq_ignore_ascii_case("quoted-printable") {
            headers.remove("Content-Transfer-Encoding");
            let decoded = decode_quoted_printable(raw);
            failed = failed || decoded.failed;
            body = Cow::Owned(decoded.bytes);
        }
        Some(Part { headers, body, failed })
    }
}
