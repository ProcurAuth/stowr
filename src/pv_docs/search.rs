//! The search of a text in an object. The route reads the object in order, in fragments of at most 256 KiB that end
//! at a line feed, and keeps the end of a fragment so that a match can cross the border of two fragments.

use std::sync::Arc;

use http::HeaderMap;
use serde::{Deserialize, Serialize};

use super::request::{Call, answer, read_instance, start};
use super::stream::ObjectStream;
use super::util::{find_bytes, lower_bytes, to_valid_utf8};
use crate::access;
use crate::common::BoxFuture;
use crate::common::app::App;
use crate::common::error::{Error, Result};
use crate::common::http::{Req, Response, json};
use crate::common::misc::clean_relative_key;
use crate::instance::ops::is_successful_read_status;

/// The longest query: 1024 bytes.
pub const MAX_QUERY_BYTES: usize = 1024;
/// The most matches in an answer.
pub const MAX_RESULTS: usize = 250;
/// The largest fragment: 256 KiB.
pub const READER_BYTES: usize = 256 << 10;
/// The bytes of a snippet around a match.
pub const SNIPPET_BYTES: usize = 220;

fn is_zero(value: &i64) -> bool {
    *value == 0
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// One match.
#[derive(Debug, Serialize, Deserialize)]
pub struct SearchMatch {
    /// The offset of the match in the object.
    pub offset: i64,
    /// The line of the match, from 1.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub line: i64,
    /// The text around the match.
    pub snippet: String,
}

/// The answer of the search.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SearchResult {
    /// The instance.
    pub instance: String,
    /// The key.
    pub key: String,
    /// The query.
    pub query: String,
    /// The first matches.
    pub matches: Vec<SearchMatch>,
    /// The number of matches.
    pub total: i64,
    /// True when `total` is more than the matches of the answer.
    #[serde(default, skip_serializing_if = "is_false")]
    pub truncated: bool,
    /// The bytes that the search read.
    #[serde(rename = "bytesScanned")]
    pub bytes_scanned: i64,
}

/// The handler of `/api/search`.
pub fn handle_search(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        match start(req) {
            Ok(call) => answer(search(&app, &call).await),
            Err(refusal) => *refusal,
        }
    })
}

async fn search(app: &App, req: &Call) -> Result<Response> {
    let instance = read_instance(app, req)?;
    let key = clean_relative_key(req.query.get("key"));
    let query = req.query.get("q").trim().to_owned();
    if key.is_empty() || query.is_empty() {
        return Err(Error::api(400, "invalid_search", "key and q are required"));
    }
    if query.len() > MAX_QUERY_BYTES {
        return Err(Error::api(
            400,
            "search_query_too_long",
            format!("search queries are limited to {MAX_QUERY_BYTES} bytes"),
        ));
    }
    access::authorize_read(app, &req.ctx, &instance, &key).await?;
    let response = instance
        .get(&req.ctx, &instance.full_key(&key), &HeaderMap::new())
        .await?;
    if !is_successful_read_status(response.status) {
        return Err(Error::internal(format!("search object: HTTP {}", response.status)));
    }
    let mut result = search_document_stream(ObjectStream::body(response.body), query.as_bytes()).await?;
    result.instance.clone_from(&instance.cfg.id);
    result.key = key;
    result.query = query;
    Ok(json(200, &result))
}

fn is_rune_start(byte: u8) -> bool {
    byte & 0xC0 != 0x80
}

/// The text around a match: the white space is one space, a line end is a symbol, a cut at the start or at the end
/// has `…`.
fn snippet(window: &[u8], index: usize, query_length: usize) -> String {
    let mut start = index.saturating_sub(SNIPPET_BYTES / 2).min(window.len());
    let mut end = window.len().min(index + query_length + SNIPPET_BYTES / 2);
    while start > 0 && start < window.len() && !is_rune_start(window[start]) {
        start -= 1;
    }
    while end < window.len() && !is_rune_start(window[end]) {
        end += 1;
    }
    let value = to_valid_utf8(&window[start.min(end)..end]);
    let value = value.replace('\r', " ").replace('\n', " ↵ ");
    let mut value = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if start > 0 {
        value.insert(0, '…');
    }
    if end < window.len() {
        value.push('…');
    }
    value
}

/// Search a text without case in a stream. A match is at most once for an offset.
pub async fn search_document_stream(mut stream: ObjectStream, query: &[u8]) -> Result<SearchResult> {
    let mut result = SearchResult::default();
    if query.is_empty() {
        return Ok(result);
    }
    let lower_query = lower_bytes(query);
    let mut line_number: i64 = 1;
    let mut fragment_start: i64 = 0;
    let mut carry: Vec<u8> = Vec::new();
    let mut last_offset: i64 = -1;
    while let Some(fragment) = stream.read_slice(READER_BYTES).await? {
        let mut window: Vec<u8> = Vec::with_capacity(carry.len() + fragment.len());
        window.extend_from_slice(&carry);
        window.extend_from_slice(&fragment);
        let window_start = fragment_start - i64::try_from(carry.len()).unwrap_or(0);
        let lower_window = lower_bytes(&window);
        let mut search_at = 0usize;
        while search_at + lower_query.len() <= lower_window.len() {
            let Some(found) = find_bytes(&lower_window[search_at..], &lower_query) else {
                break;
            };
            let index = found + search_at;
            let offset = window_start + i64::try_from(index).unwrap_or(0);
            if offset > last_offset {
                result.total += 1;
                last_offset = offset;
                if result.matches.len() < MAX_RESULTS {
                    result.matches.push(SearchMatch {
                        offset,
                        line: line_number,
                        snippet: snippet(&window, index, query.len()),
                    });
                }
            }
            search_at = index + lower_query.len().max(1);
        }
        fragment_start += i64::try_from(fragment.len()).unwrap_or(0);
        result.bytes_scanned += i64::try_from(fragment.len()).unwrap_or(0);
        let keep = window.len().min(query.len().saturating_sub(1));
        carry = window[window.len() - keep..].to_vec();
        if fragment.last() == Some(&b'\n') {
            line_number += 1;
            carry.clear();
        }
    }
    result.truncated = result.total > i64::try_from(result.matches.len()).unwrap_or(0);
    Ok(result)
}

#[cfg(test)]
#[path = "search_tests.rs"]
mod tests;
