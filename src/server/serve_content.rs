// SPDX-License-Identifier: MIT OR Apache-2.0
//! The answer of a known content: the conditions (`If-Match`, `If-None-Match`, `If-Range`), the ranges (one range, or
//! several ranges as `multipart/byteranges`), `HEAD`, and the error answers of a bad range.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::header::{
    ACCEPT_RANGES, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG, HeaderName, HeaderValue,
    LAST_MODIFIED, X_CONTENT_TYPE_OPTIONS,
};
use http::{HeaderMap, Method};
use http_body::Frame;
use http_body_util::BodyExt;

use crate::common::error::{Error, Result};
use crate::common::http::{Response, answer, empty, full};
use crate::common::misc::{hex, random_bytes};

/// One range of a content: the start and the length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteRange {
    /// The first byte.
    pub start: u64,
    /// The number of bytes.
    pub length: u64,
}

impl ByteRange {
    fn content_range(self, size: u64) -> String {
        format!("bytes {}-{}/{}", self.start, self.start + self.length - 1, size)
    }
}

/// The error of a `Range` header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangeError {
    /// The header is not valid.
    Invalid,
    /// No range starts inside the content.
    NoOverlap,
}

impl RangeError {
    fn text(self) -> &'static str {
        match self {
            Self::Invalid => "invalid range",
            Self::NoOverlap => "invalid range: failed to overlap",
        }
    }
}

fn trim_text(value: &str) -> &str {
    value.trim_matches(|character| matches!(character, ' ' | '\t' | '\n' | '\r'))
}

fn parse_decimal(text: &str) -> Option<u64> {
    let digits = text.strip_prefix('+').unwrap_or(text);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    digits.parse::<u64>().ok().filter(|value| i64::try_from(*value).is_ok())
}

/// Read a `Range` header for a content of `size` bytes. An empty header gives no range.
pub fn parse_range(header: &str, size: u64) -> std::result::Result<Vec<ByteRange>, RangeError> {
    if header.is_empty() {
        return Ok(Vec::new());
    }
    let Some(specs) = header.strip_prefix("bytes=") else {
        return Err(RangeError::Invalid);
    };
    let mut ranges = Vec::new();
    let mut no_overlap = false;
    for spec in specs.split(',') {
        let spec = trim_text(spec);
        if spec.is_empty() {
            continue;
        }
        let Some((start, end)) = spec.split_once('-') else {
            return Err(RangeError::Invalid);
        };
        let (start, end) = (trim_text(start), trim_text(end));
        if start.is_empty() {
            if end.is_empty() || end.starts_with('-') {
                return Err(RangeError::Invalid);
            }
            let suffix = parse_decimal(end).ok_or(RangeError::Invalid)?.min(size);
            ranges.push(ByteRange {
                start: size - suffix,
                length: suffix,
            });
            continue;
        }
        let first = parse_decimal(start).ok_or(RangeError::Invalid)?;
        if first >= size {
            no_overlap = true;
            continue;
        }
        let length = if end.is_empty() {
            size - first
        } else {
            let last = parse_decimal(end).ok_or(RangeError::Invalid)?;
            if first > last {
                return Err(RangeError::Invalid);
            }
            last.min(size - 1) - first + 1
        };
        ranges.push(ByteRange { start: first, length });
    }
    if no_overlap && ranges.is_empty() {
        return Err(RangeError::NoOverlap);
    }
    Ok(ranges)
}

/// Read one entity tag at the start of a text: `"x"` or `W/"x"`. Gives the tag and the rest, or `None`.
fn scan_etag(text: &str) -> Option<(&str, &str)> {
    let text = trim_text(text);
    let start = if text.starts_with("W/") { 2 } else { 0 };
    let bytes = text.as_bytes();
    if bytes.len() < start + 2 || bytes[start] != b'"' {
        return None;
    }
    for (index, &byte) in bytes.iter().enumerate().skip(start + 1) {
        match byte {
            b'"' => return Some((&text[..=index], &text[index + 1..])),
            0x21 | 0x23..=0x7e | 0x80..=0xff => {}
            _ => return None,
        }
    }
    None
}

fn strong_match(left: &str, right: &str) -> bool {
    left == right && left.starts_with('"')
}

fn weak_match(left: &str, right: &str) -> bool {
    left.trim_start_matches("W/") == right.trim_start_matches("W/")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Condition {
    None,
    True,
    False,
}

fn header_text<'a>(headers: &'a HeaderMap, name: &HeaderName) -> &'a str {
    headers.get(name).and_then(|value| value.to_str().ok()).unwrap_or("")
}

fn check_if_match(request: &HeaderMap, etag: &str) -> Condition {
    let mut rest = header_text(request, &http::header::IF_MATCH);
    if rest.is_empty() {
        return Condition::None;
    }
    loop {
        rest = trim_text(rest);
        if rest.is_empty() {
            break;
        }
        if let Some(after) = rest.strip_prefix(',') {
            rest = after;
            continue;
        }
        if rest.starts_with('*') {
            return Condition::True;
        }
        let Some((tag, remain)) = scan_etag(rest) else {
            break;
        };
        if strong_match(tag, etag) {
            return Condition::True;
        }
        rest = remain;
    }
    Condition::False
}

fn check_if_none_match(request: &HeaderMap, etag: &str) -> Condition {
    let mut rest = header_text(request, &http::header::IF_NONE_MATCH);
    if rest.is_empty() {
        return Condition::None;
    }
    loop {
        rest = trim_text(rest);
        if rest.is_empty() {
            break;
        }
        if let Some(after) = rest.strip_prefix(',') {
            rest = after;
            continue;
        }
        if rest.starts_with('*') {
            return Condition::False;
        }
        let Some((tag, remain)) = scan_etag(rest) else {
            break;
        };
        if weak_match(tag, etag) {
            return Condition::False;
        }
        rest = remain;
    }
    Condition::True
}

/// The `If-Range` check of a content without a modification time: only a strong tag that matches keeps the range.
fn check_if_range(method: &Method, request: &HeaderMap, etag: &str) -> Condition {
    if method != Method::GET && method != Method::HEAD {
        return Condition::None;
    }
    let value = header_text(request, &http::header::IF_RANGE);
    if value.is_empty() {
        return Condition::None;
    }
    match scan_etag(value) {
        Some((tag, _)) if strong_match(tag, etag) => Condition::True,
        _ => Condition::False,
    }
}

/// The error answer of a content: the message as text, the headers of the content kept except the length.
fn content_error(mut headers: HeaderMap, status: u16, message: &str) -> Response {
    headers.remove(CONTENT_LENGTH);
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    answer(status, headers, full(format!("{message}\n")))
}

fn set_header(headers: &mut HeaderMap, name: HeaderName, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(name, value);
    }
}

/// The parts of a `multipart/byteranges` body, sent one after the other.
struct MultipartBody {
    content: Bytes,
    ranges: Vec<ByteRange>,
    content_type: String,
    size: u64,
    boundary: String,
    next: usize,
    // The data of the current part that waits: the head of the part is already out.
    pending: Option<Bytes>,
    done: bool,
}

impl MultipartBody {
    fn part_head(&self, index: usize, range: ByteRange) -> String {
        let separator = if index == 0 { "" } else { "\r\n" };
        format!(
            "{separator}--{}\r\nContent-Range: {}\r\nContent-Type: {}\r\n\r\n",
            self.boundary,
            range.content_range(self.size),
            self.content_type
        )
    }

    fn encoded_size(&self) -> u64 {
        let mut total = 0u64;
        for (index, range) in self.ranges.iter().enumerate() {
            total += self.part_head(index, *range).len() as u64 + range.length;
        }
        total + format!("\r\n--{}--\r\n", self.boundary).len() as u64
    }
}

impl http_body::Body for MultipartBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>>>> {
        if let Some(data) = self.pending.take() {
            return Poll::Ready(Some(Ok(Frame::data(data))));
        }
        if self.done {
            return Poll::Ready(None);
        }
        if let Some(range) = self.ranges.get(self.next).copied() {
            let head = self.part_head(self.next, range);
            let start = usize::try_from(range.start).unwrap_or(usize::MAX);
            let end = usize::try_from(range.start + range.length).unwrap_or(usize::MAX);
            let slice = self.content.get(start..end).map(|_| self.content.slice(start..end));
            self.pending = slice.filter(|data| !data.is_empty());
            self.next += 1;
            return Poll::Ready(Some(Ok(Frame::data(Bytes::from(head)))));
        }
        self.done = true;
        let tail = format!("\r\n--{}--\r\n", self.boundary);
        Poll::Ready(Some(Ok(Frame::data(Bytes::from(tail)))))
    }
}

/// The random boundary of a multipart body: 30 random bytes in hexadecimal.
fn random_boundary() -> String {
    let mut buffer = [0u8; 30];
    if random_bytes(&mut buffer).is_err() {
        return hex(&[0x5a; 30]);
    }
    hex(&buffer)
}

/// Answer with a known content. `headers` holds the headers that the caller set before: `Content-Type` (an empty value
/// is kept), `ETag`, `Cache-Control`, `Content-Encoding`... The content has no modification time.
pub fn serve_content(method: &Method, request: &HeaderMap, mut headers: HeaderMap, content: Bytes) -> Response {
    let etag = header_text(&headers, &ETAG).to_owned();
    // `If-Unmodified-Since` and `If-Modified-Since` need a modification time: the content has none.
    if check_if_match(request, &etag) == Condition::False {
        return answer(412, headers, empty());
    }
    if check_if_none_match(request, &etag) == Condition::False {
        if method == Method::GET || method == Method::HEAD {
            headers.remove(CONTENT_TYPE);
            headers.remove(CONTENT_LENGTH);
            headers.remove(CONTENT_ENCODING);
            if headers.contains_key(ETAG) {
                headers.remove(LAST_MODIFIED);
            }
            return answer(304, headers, empty());
        }
        return answer(412, headers, empty());
    }
    let mut range_header = header_text(request, &http::header::RANGE).to_owned();
    if !range_header.is_empty() && check_if_range(method, request, &etag) == Condition::False {
        range_header.clear();
    }
    let content_type = header_text(&headers, &CONTENT_TYPE).to_owned();
    let size = content.len() as u64;
    let mut ranges = match parse_range(&range_header, size) {
        Ok(ranges) => ranges,
        Err(RangeError::NoOverlap) if size == 0 => Vec::new(),
        Err(error) => {
            if error == RangeError::NoOverlap {
                set_header(&mut headers, CONTENT_RANGE, &format!("bytes */{size}"));
            }
            return content_error(headers, 416, error.text());
        }
    };
    if ranges.iter().map(|range| range.length).sum::<u64>() > size {
        ranges.clear();
    }
    let mut status = 200;
    let mut send_size = size;
    let mut body = full(content.clone());
    if ranges.len() == 1 {
        let range = ranges[0];
        status = 206;
        send_size = range.length;
        set_header(&mut headers, CONTENT_RANGE, &range.content_range(size));
        let start = usize::try_from(range.start).unwrap_or(usize::MAX);
        let end = usize::try_from(range.start + range.length).unwrap_or(usize::MAX);
        body = full(content.slice(start.min(content.len())..end.min(content.len())));
    } else if ranges.len() > 1 {
        status = 206;
        let multipart = MultipartBody {
            content,
            ranges: ranges.clone(),
            content_type,
            size,
            boundary: random_boundary(),
            next: 0,
            pending: None,
            done: false,
        };
        send_size = multipart.encoded_size();
        set_header(
            &mut headers,
            CONTENT_TYPE,
            &format!("multipart/byteranges; boundary={}", multipart.boundary),
        );
        body = multipart.boxed_unsync();
    }
    headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    if !ranges.is_empty() || header_text(&headers, &CONTENT_ENCODING).is_empty() {
        set_header(&mut headers, CONTENT_LENGTH, &send_size.to_string());
    }
    if method == Method::HEAD {
        body = empty();
    }
    answer(status, headers, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::http::read_limited;

    fn headers_with_etag(etag: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/css; charset=utf-8"));
        headers.insert(ETAG, HeaderValue::from_str(etag).unwrap());
        headers
    }

    fn request(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(
                HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        headers
    }

    async fn body_of(response: Response) -> Vec<u8> {
        read_limited(response.into_body(), 1 << 20).await.unwrap().0.to_vec()
    }

    #[test]
    fn ranges_follow_the_byte_range_rules() {
        assert_eq!(parse_range("", 10), Ok(vec![]));
        assert_eq!(
            parse_range("bytes=0-3", 10),
            Ok(vec![ByteRange { start: 0, length: 4 }])
        );
        assert_eq!(parse_range("bytes=-3", 10), Ok(vec![ByteRange { start: 7, length: 3 }]));
        assert_eq!(
            parse_range("bytes=-30", 10),
            Ok(vec![ByteRange { start: 0, length: 10 }])
        );
        assert_eq!(parse_range("bytes=5-", 10), Ok(vec![ByteRange { start: 5, length: 5 }]));
        assert_eq!(
            parse_range("bytes=5-99", 10),
            Ok(vec![ByteRange { start: 5, length: 5 }])
        );
        assert_eq!(parse_range("bytes=10-", 10), Err(RangeError::NoOverlap));
        assert_eq!(parse_range("bytes=4-2", 10), Err(RangeError::Invalid));
        assert_eq!(parse_range("items=0-1", 10), Err(RangeError::Invalid));
        assert_eq!(parse_range("bytes=--1", 10), Err(RangeError::Invalid));
        assert_eq!(parse_range("bytes=0-1, ,4-5", 10).unwrap().len(), 2);
    }

    #[tokio::test]
    async fn a_single_range_gives_206_and_the_part() {
        let response = serve_content(
            &Method::GET,
            &request(&[("range", "bytes=2-4")]),
            headers_with_etag("W/\"abc\""),
            Bytes::from_static(b"0123456789"),
        );
        assert_eq!(response.status(), 206);
        assert_eq!(response.headers()[CONTENT_RANGE], "bytes 2-4/10");
        assert_eq!(response.headers()[CONTENT_LENGTH], "3");
        assert_eq!(body_of(response).await, b"234");
    }

    #[tokio::test]
    async fn several_ranges_give_a_multipart_body_of_the_announced_length() {
        let response = serve_content(
            &Method::GET,
            &request(&[("range", "bytes=0-1,4-5")]),
            headers_with_etag("W/\"abc\""),
            Bytes::from_static(b"0123456789"),
        );
        assert_eq!(response.status(), 206);
        let content_type = response.headers()[CONTENT_TYPE].to_str().unwrap().to_owned();
        let boundary = content_type
            .strip_prefix("multipart/byteranges; boundary=")
            .unwrap()
            .to_owned();
        assert_eq!(boundary.len(), 60);
        let length: usize = response.headers()[CONTENT_LENGTH].to_str().unwrap().parse().unwrap();
        let body = String::from_utf8(body_of(response).await).unwrap();
        assert_eq!(body.len(), length);
        assert_eq!(
            body,
            format!(
                "--{boundary}\r\nContent-Range: bytes 0-1/10\r\nContent-Type: text/css; charset=utf-8\r\n\r\n01\r\n--{boundary}\r\nContent-Range: bytes 4-5/10\r\nContent-Type: text/css; charset=utf-8\r\n\r\n45\r\n--{boundary}--\r\n"
            )
        );
    }

    #[tokio::test]
    async fn conditions_give_304_412_and_ignore_a_weak_if_range() {
        let content = Bytes::from_static(b"0123456789");
        let not_modified = serve_content(
            &Method::GET,
            &request(&[("if-none-match", "\"x\", W/\"abc\"")]),
            headers_with_etag("W/\"abc\""),
            content.clone(),
        );
        assert_eq!(not_modified.status(), 304);
        assert!(not_modified.headers().get(CONTENT_TYPE).is_none());
        let failed = serve_content(
            &Method::GET,
            &request(&[("if-match", "W/\"abc\"")]),
            headers_with_etag("W/\"abc\""),
            content.clone(),
        );
        assert_eq!(failed.status(), 412);
        let ignored = serve_content(
            &Method::GET,
            &request(&[("range", "bytes=0-1"), ("if-range", "W/\"abc\"")]),
            headers_with_etag("W/\"abc\""),
            content.clone(),
        );
        assert_eq!(ignored.status(), 200);
        let refused = serve_content(
            &Method::GET,
            &request(&[("range", "bytes=20-")]),
            headers_with_etag("W/\"abc\""),
            content,
        );
        assert_eq!(refused.status(), 416);
        assert_eq!(refused.headers()[CONTENT_RANGE], "bytes */10");
        assert_eq!(body_of(refused).await, b"invalid range: failed to overlap\n");
    }
}
