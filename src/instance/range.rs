// SPDX-License-Identifier: MIT OR Apache-2.0
//! The range readers of the previews.
//!
//! A [`RangeSource`] reads exact byte ranges of one object (one version). It checks each answer `206` and its
//! `Content-Range`, binds the reads to the ETag, the generation or the date of the first answer, refuses an answer
//! that is larger than the range, and keeps a small cache of the read spans (`server.max_range_cache_bytes`). Two
//! reads of the same range at the same time make one provider request. Clones of a source made with
//! [`RangeSource::with_context`] share the cache and the binding: a preview session uses one source for several
//! requests.
//!
//! A [`WindowReader`] reads an object in order, one window of 256 KiB after the other. It never sends an open
//! range: the provider cannot send the rest of a very large object.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use bytes::{Bytes, BytesMut};
use http::HeaderMap;
use http::header::{
    CONTENT_LENGTH, CONTENT_RANGE, ETAG, HeaderValue, IF_MATCH, IF_UNMODIFIED_SINCE, LAST_MODIFIED, RANGE,
};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use super::Instance;
use super::ceiling::{check_read_ceiling, header_text};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::read_limited;
use crate::common::storage::ObjectResponse;

/// The largest range of one read: 128 MiB.
pub const MAX_SINGLE_RANGE_BYTES: i64 = 128 << 20;

/// The window of a [`WindowReader`]: 256 KiB.
pub const SEQUENTIAL_WINDOW_BYTES: i64 = 256 << 10;

/// The header of the generation of a GCS object.
const GENERATION_HEADER: &str = "x-goog-generation";
/// The precondition of the generation of a GCS read.
const GENERATION_MATCH_HEADER: &str = "x-goog-if-generation-match";

/// The version of the object that a reader is bound to: the ETag, else the generation, else the date of the last
/// change. The cursors of the previews keep it with short JSON names.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectVersion {
    /// The ETag, with its quotes.
    #[serde(rename = "e", default, skip_serializing_if = "String::is_empty")]
    pub etag: String,
    /// The generation of a GCS object.
    #[serde(rename = "g", default, skip_serializing_if = "String::is_empty")]
    pub version: String,
    /// The date of the last change, as the provider gives it.
    #[serde(rename = "m", default, skip_serializing_if = "String::is_empty")]
    pub modified: String,
}

impl ObjectVersion {
    /// True when the value binds nothing.
    pub fn is_empty(&self) -> bool {
        self.etag.trim().is_empty() && self.version.trim().is_empty() && self.modified.trim().is_empty()
    }
}

/// An expected ETag with its quotes: a weak ETag and a quoted ETag stay; `*` and an empty text stay.
pub fn normalize_expected_etag(value: &str) -> String {
    let value = value.trim();
    if value.is_empty() || value == "*" || value.starts_with("W/\"") || value.starts_with('"') {
        return value.to_owned();
    }
    format!("\"{}\"", value.trim_matches('"'))
}

/// One cached span of the object.
#[derive(Clone, Debug)]
struct Span {
    start: i64,
    data: Bytes,
}

impl Span {
    fn end(&self) -> i64 {
        self.start + self.data.len() as i64
    }
}

/// The result of a provider read that other readers wait for.
type FlightResult = Option<Result<Bytes>>;

/// The shared state of a source: the binding, the counters, the cache and the reads in flight.
#[derive(Debug, Default)]
struct RangeState {
    size: i64,
    headers: Option<HeaderMap>,
    etag: String,
    generation: String,
    modified: String,
    requests: u64,
    bytes: i64,
    /// The spans, the most recent first.
    cache: VecDeque<Span>,
    cache_bytes: i64,
    max_cache_bytes: i64,
    inflight: HashMap<String, watch::Receiver<FlightResult>>,
}

/// The owner of a read in flight. Its drop removes the flight: a read that its caller canceled does not stop the
/// readers that come later.
struct FlightGuard {
    state: Arc<Mutex<RangeState>>,
    key: String,
    sender: watch::Sender<FlightResult>,
}

impl FlightGuard {
    fn finish(self, result: &Result<Bytes>) {
        let _ = self.sender.send(Some(result.clone()));
    }
}

impl Drop for FlightGuard {
    fn drop(&mut self) {
        if let Ok(mut state) = self.state.lock() {
            state.inflight.remove(&self.key);
        }
    }
}

enum Flight {
    Owner(FlightGuard),
    Waiter(watch::Receiver<FlightResult>),
}

fn object_changed() -> Error {
    Error::api(412, "object_changed", "the object changed while it was being previewed")
}

fn invalid_range() -> Error {
    Error::internal("invalid object metadata range")
}

fn bad_gateway(code: &str, message: &str) -> Error {
    Error::api(502, code, message)
}

/// The start, the end and the total of a `Content-Range` answer header (`bytes start-end/total`).
fn parse_content_range(value: &str) -> Option<(i64, i64, i64)> {
    let value = value.trim();
    if value.len() < 6 || !value[..6].eq_ignore_ascii_case("bytes ") {
        return None;
    }
    let (bounds, total) = value[6..].trim().split_once('/')?;
    if bounds == "*" || total == "*" {
        return None;
    }
    let total = total.trim().parse::<i64>().ok().filter(|total| *total >= 0)?;
    let (start, end) = bounds.trim().split_once('-')?;
    let start = start.trim().parse::<i64>().ok().filter(|start| *start >= 0)?;
    let end = end.trim().parse::<i64>().ok()?;
    if end < start || (total > 0 && end >= total) {
        return None;
    }
    Some((start, end, total))
}

/// A reader of exact byte ranges of one object.
pub struct RangeSource {
    /// The instance.
    pub instance: Arc<Instance>,
    /// The context of the reads.
    pub ctx: OpCtx,
    /// The relative key: the reads add the root prefix of the instance.
    pub key: String,
    version: String,
    state: Arc<Mutex<RangeState>>,
}

impl std::fmt::Debug for RangeSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RangeSource")
            .field("key", &self.key)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl RangeSource {
    /// Open the object at a relative key: the current version, or the version of the context.
    pub async fn open(ctx: &OpCtx, instance: &Arc<Instance>, key: &str) -> Result<Self> {
        Self::open_version(ctx, instance, key, "").await
    }

    /// Open one version of the object at a relative key. An empty version reads the current object, or the
    /// version of the context.
    pub async fn open_version(ctx: &OpCtx, instance: &Arc<Instance>, key: &str, version: &str) -> Result<Self> {
        let max_cache_bytes = match instance.policy.max_range_cache_bytes {
            value if value > 0 => value,
            _ => crate::common::config::RuntimePolicy::default().max_range_cache_bytes,
        };
        Ok(Self {
            instance: instance.clone(),
            ctx: ctx.clone(),
            key: key.to_owned(),
            version: version.trim().to_owned(),
            state: Arc::new(Mutex::new(RangeState {
                max_cache_bytes,
                ..RangeState::default()
            })),
        })
    }

    /// A source for another context that shares the cache, the binding and the counters of this source.
    pub fn with_context(&self, ctx: &OpCtx) -> Self {
        Self {
            instance: self.instance.clone(),
            ctx: ctx.clone(),
            key: self.key.clone(),
            version: self.version.clone(),
            state: self.state.clone(),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, RangeState> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// The size of the object, when a read or the listing told it.
    pub fn size(&self) -> Option<i64> {
        Some(self.lock().size).filter(|size| *size > 0)
    }

    /// The size of the object, or 0 when no read told it (or for an empty object).
    pub fn size_or_zero(&self) -> i64 {
        self.lock().size
    }

    /// Give the size of the listing: the first read does not need a HEAD. A size of 0 or less does nothing.
    pub fn set_known_size(&mut self, size: i64) {
        if size <= 0 {
            return;
        }
        let mut state = self.lock();
        if state.size == 0 {
            state.size = size;
        }
    }

    /// Give the ETag that the reads must find. An empty text does nothing; a bound ETag stays.
    pub fn set_expected_etag(&mut self, etag: &str) {
        let etag = normalize_expected_etag(etag);
        if etag.is_empty() {
            return;
        }
        let mut state = self.lock();
        if state.etag.is_empty() {
            state.etag = etag;
        }
    }

    /// Give the version that the reads must find (for example from a cursor). A bound value stays.
    pub fn set_expected_version(&mut self, version: &ObjectVersion) {
        let etag = normalize_expected_etag(&version.etag);
        let mut state = self.lock();
        if state.etag.is_empty() {
            state.etag = etag;
        }
        if state.generation.is_empty() {
            state.generation = version.version.trim().to_owned();
        }
        if state.modified.is_empty() {
            state.modified = version.modified.trim().to_owned();
        }
    }

    /// The version that the reads are bound to.
    pub fn version(&self) -> ObjectVersion {
        let state = self.lock();
        ObjectVersion {
            etag: state.etag.clone(),
            version: state.generation.clone(),
            modified: state.modified.clone(),
        }
    }

    /// The headers of the first answer, or an empty map before the first read.
    pub fn headers(&self) -> HeaderMap {
        self.lock().headers.clone().unwrap_or_default()
    }

    /// The provider calls and the bytes of the reads.
    pub fn counters(&self) -> (u64, i64) {
        let state = self.lock();
        (state.requests, state.bytes)
    }

    /// The provider calls of the reads.
    pub fn request_count(&self) -> u64 {
        self.lock().requests
    }

    /// The bytes of the reads.
    pub fn bytes_read(&self) -> i64 {
        self.lock().bytes
    }

    /// Remove each span of the cache.
    pub fn clear_cache(&self) {
        let mut state = self.lock();
        state.cache.clear();
        state.cache_bytes = 0;
    }

    /// The headers of a read: the range, and the precondition of the binding.
    fn request_headers(&self, range: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Ok(value) = HeaderValue::from_str(range) {
            headers.insert(RANGE, value);
        }
        let state = self.lock();
        let (name, value) = if !state.etag.is_empty() {
            (IF_MATCH.as_str(), state.etag.as_str())
        } else if !state.generation.is_empty() {
            (GENERATION_MATCH_HEADER, state.generation.as_str())
        } else if !state.modified.is_empty() {
            (IF_UNMODIFIED_SINCE.as_str(), state.modified.as_str())
        } else {
            return headers;
        };
        if let (Ok(name), Ok(value)) = (
            http::header::HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(value),
        ) {
            headers.insert(name, value);
        }
        headers
    }

    /// Check an answer against the binding, then keep its size, its headers and its binding values.
    fn validate_and_record(&self, headers: &HeaderMap, total: i64, received: i64) -> Result<()> {
        let etag = header_text(headers, ETAG.as_str());
        let generation = header_text(headers, GENERATION_HEADER);
        let modified = header_text(headers, LAST_MODIFIED.as_str());
        let mut state = self.lock();
        if state.size > 0 && total > 0 && state.size != total {
            return Err(object_changed());
        }
        if !state.etag.is_empty() && !etag.is_empty() && state.etag != etag {
            return Err(object_changed());
        }
        if !state.generation.is_empty() && !generation.is_empty() && state.generation != generation {
            return Err(Error::api(
                412,
                "object_changed",
                "the object generation changed while it was being previewed",
            ));
        }
        if state.etag.is_empty()
            && state.generation.is_empty()
            && !state.modified.is_empty()
            && !modified.is_empty()
            && state.modified != modified
        {
            return Err(object_changed());
        }
        if state.headers.is_none() {
            state.headers = Some(headers.clone());
        }
        if state.size == 0 {
            state.size = total;
        }
        if state.etag.is_empty() {
            state.etag = etag.to_owned();
        }
        if state.generation.is_empty() {
            state.generation = generation.to_owned();
        }
        if state.modified.is_empty() {
            state.modified = modified.to_owned();
        }
        state.requests += 1;
        state.bytes += received;
        Ok(())
    }

    fn begin_flight(&self, key: &str) -> Flight {
        let mut state = self.lock();
        if let Some(receiver) = state.inflight.get(key) {
            return Flight::Waiter(receiver.clone());
        }
        let (sender, receiver) = watch::channel(None);
        state.inflight.insert(key.to_owned(), receiver);
        Flight::Owner(FlightGuard {
            state: self.state.clone(),
            key: key.to_owned(),
            sender,
        })
    }

    async fn wait_flight(&self, mut receiver: watch::Receiver<FlightResult>) -> Result<Bytes> {
        let waited = self
            .ctx
            .run(async {
                match receiver.wait_for(Option::is_some).await {
                    Ok(value) => Ok(value.clone()),
                    // The owner went away without a result: its caller canceled it.
                    Err(_) => Err(Error::Canceled),
                }
            })
            .await?;
        waited.unwrap_or(Err(Error::Canceled))
    }

    /// Read the body of an answer: at most `expected + 1` bytes.
    async fn read_body(response: ObjectResponse, expected: i64) -> Result<Bytes> {
        let maximum = usize::try_from(expected.saturating_add(1)).unwrap_or(usize::MAX);
        let (data, _) = read_limited(response.body, maximum).await?;
        Ok(data)
    }

    /// One provider read of `length` bytes from `start`. Two reads of the same range share one request.
    async fn fetch(&self, start: i64, length: i64) -> Result<Bytes> {
        if start < 0 || length <= 0 || length > MAX_SINGLE_RANGE_BYTES {
            return Err(invalid_range());
        }
        let end = start + length - 1;
        let flight_key = format!("{start}:{end}");
        let guard = match self.begin_flight(&flight_key) {
            Flight::Waiter(receiver) => return self.wait_flight(receiver).await,
            Flight::Owner(guard) => guard,
        };
        let result = self.fetch_owned(start, end, length).await;
        guard.finish(&result);
        result
    }

    async fn fetch_owned(&self, start: i64, end: i64, length: i64) -> Result<Bytes> {
        let headers = self.request_headers(&format!("bytes={start}-{end}"));
        let full_key = self.instance.full_key(&self.key);
        let response = self
            .instance
            .get_version(&self.ctx, &full_key, &self.version, &headers)
            .await?;
        if response.status == 412 {
            return Err(object_changed());
        }
        if response.status == 200 {
            let content_length = header_text(&response.headers, CONTENT_LENGTH.as_str()).parse::<i64>();
            // An empty object has no byte range. Some providers answer 200 with an empty body instead of 416: that
            // answer cannot move a large object.
            if content_length == Ok(0) && start == 0 {
                self.validate_and_record(&response.headers, 0, 0)?;
                return Ok(Bytes::new());
            }
            if !self.instance.policy.allow_full_object_fallback {
                return Err(bad_gateway(
                    "range_not_supported",
                    "the storage provider ignored the byte-range request; the complete object was not downloaded",
                ));
            }
            let content_length = match content_length {
                Ok(value) if start == 0 && value >= 0 && value <= length => value,
                _ => {
                    return Err(bad_gateway(
                        "range_not_supported",
                        "the storage provider ignored a byte-range request",
                    ));
                }
            };
            let headers = response.headers.clone();
            let data = Self::read_body(response, length).await?;
            let received = data.len() as i64;
            if received != content_length || received > length {
                return Err(bad_gateway(
                    "range_length_mismatch",
                    "the storage provider returned an invalid byte count",
                ));
            }
            self.validate_and_record(&headers, content_length, received)?;
            return Ok(data);
        }
        if response.status != 206 {
            return Err(Error::upstream(response.status, "MetadataRangeReadFailed", ""));
        }
        let Some((range_start, range_end, total)) =
            parse_content_range(header_text(&response.headers, CONTENT_RANGE.as_str())).filter(|range| range.2 > 0)
        else {
            return Err(bad_gateway(
                "invalid_content_range",
                "the storage provider returned an invalid Content-Range header",
            ));
        };
        let expected_end = end.min(total - 1);
        if start >= total || range_start != start || range_end != expected_end {
            return Err(bad_gateway(
                "range_mismatch",
                "the storage provider returned a different byte range than requested",
            ));
        }
        let expected = range_end - range_start + 1;
        let advertised = header_text(&response.headers, CONTENT_LENGTH.as_str());
        if !advertised.is_empty() && advertised.parse::<i64>() != Ok(expected) {
            return Err(bad_gateway(
                "range_length_mismatch",
                "the storage provider advertised an invalid range length",
            ));
        }
        let headers = response.headers.clone();
        let data = Self::read_body(response, expected).await?;
        if data.len() as i64 != expected {
            return Err(bad_gateway(
                "range_truncated",
                "the storage provider returned a truncated or oversized byte range",
            ));
        }
        self.validate_and_record(&headers, total, expected)?;
        Ok(data)
    }

    /// Keep a span in the cache: the most recent first, the oldest out when the cache is full.
    fn cache_span(&self, start: i64, data: &Bytes) {
        if data.is_empty() {
            return;
        }
        let mut state = self.lock();
        let length = data.len() as i64;
        if state.max_cache_bytes <= 0 || length > state.max_cache_bytes {
            return;
        }
        let end = start + length;
        let mut removed = 0;
        state.cache.retain(|span| {
            let same = span.start == start && span.end() == end;
            if same {
                removed += span.data.len() as i64;
            }
            !same
        });
        state.cache_bytes -= removed;
        state.cache.push_front(Span {
            start,
            data: data.clone(),
        });
        state.cache_bytes += length;
        while state.cache_bytes > state.max_cache_bytes {
            let Some(last) = state.cache.pop_back() else {
                break;
            };
            state.cache_bytes -= last.data.len() as i64;
        }
    }

    /// The cached span that holds the byte at `offset`; it becomes the most recent span.
    fn cached_span_at(&self, offset: i64) -> Option<Span> {
        let mut state = self.lock();
        let position = state
            .cache
            .iter()
            .position(|span| offset >= span.start && offset < span.end())?;
        let span = state.cache.remove(position)?;
        state.cache.push_front(span.clone());
        Some(span)
    }

    /// True when the cache holds the byte at `offset`: a read of it makes no provider request.
    pub fn has_byte(&self, offset: i64) -> bool {
        self.cached_span_at(offset).is_some()
    }

    /// The start of the first cached span after `offset` and before `limit`, else `limit`.
    fn next_cached_start(&self, offset: i64, limit: i64) -> i64 {
        let state = self.lock();
        state
            .cache
            .iter()
            .map(|span| span.start)
            .filter(|start| *start > offset && *start < limit)
            .min()
            .unwrap_or(limit)
    }

    /// Read `length` bytes from `start`. At the end of the object, the bytes are fewer than `length`: no byte at or
    /// after the end. The ceiling `object.read` of the context applies to the size of the object, also to the bytes
    /// of the cache.
    pub async fn read_range(&self, start: i64, length: i64) -> Result<Bytes> {
        if start < 0 || length <= 0 || length > MAX_SINGLE_RANGE_BYTES {
            return Err(invalid_range());
        }
        let mut length = length;
        let size = self.size_or_zero();
        if size > 0 {
            // A cached span can come from a request with a higher ceiling: the ceiling of this request applies too.
            check_read_ceiling(&self.ctx, size)?;
            if start >= size {
                return Ok(Bytes::new());
            }
            length = length.min(size - start);
        }
        let end = start + length;
        let mut out = BytesMut::new();
        let mut cursor = start;
        while cursor < end {
            if let Some(span) = self.cached_span_at(cursor) {
                let copy_end = end.min(span.end());
                let from = (cursor - span.start) as usize;
                let to = (copy_end - span.start) as usize;
                if out.is_empty() && cursor == start && copy_end == end {
                    return Ok(span.data.slice(from..to));
                }
                out.extend_from_slice(&span.data[from..to]);
                cursor = copy_end;
                continue;
            }
            let gap_end = self.next_cached_start(cursor, end);
            let fetched = self.fetch(cursor, gap_end - cursor).await?;
            if fetched.is_empty() {
                return Ok(out.freeze());
            }
            self.cache_span(cursor, &fetched);
            let fetched_length = fetched.len() as i64;
            if out.is_empty() && cursor == start && fetched_length == end - start {
                return Ok(fetched);
            }
            out.extend_from_slice(&fetched);
            cursor += fetched_length;
            if cursor < gap_end {
                return Ok(out.freeze());
            }
        }
        Ok(out.freeze())
    }

    /// Fill `buffer` from `offset`; gives the number of bytes. A number below the length of the buffer is the end
    /// of the object.
    pub async fn read_at(&self, buffer: &mut [u8], offset: i64) -> Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let data = self.read_range(offset, buffer.len() as i64).await?;
        let count = data.len().min(buffer.len());
        buffer[..count].copy_from_slice(&data[..count]);
        Ok(count)
    }

    /// Read the first `length` bytes (fewer for a smaller object). A length of 0 or less reads nothing.
    pub async fn read_prefix(&self, length: i64) -> Result<Bytes> {
        if length <= 0 {
            return Ok(Bytes::new());
        }
        let length = match self.size() {
            Some(size) => length.min(size),
            None => length,
        };
        self.read_range(0, length).await
    }

    /// Read the last `length` bytes. When the size is not known, one exact suffix request gives the size and the
    /// bytes: the end of a ZIP archive needs both.
    pub async fn read_suffix(&self, length: i64) -> Result<Bytes> {
        if length <= 0 || length > MAX_SINGLE_RANGE_BYTES {
            return Err(Error::internal("invalid object metadata suffix length"));
        }
        if let Some(size) = self.size() {
            let length = length.min(size);
            return self.read_range(size - length, length).await;
        }
        let flight_key = format!("suffix:{length}");
        let guard = match self.begin_flight(&flight_key) {
            Flight::Waiter(receiver) => return self.wait_flight(receiver).await,
            Flight::Owner(guard) => guard,
        };
        let result = self.fetch_suffix(length).await;
        guard.finish(&result);
        result
    }

    async fn fetch_suffix(&self, length: i64) -> Result<Bytes> {
        let headers = self.request_headers(&format!("bytes=-{length}"));
        let full_key = self.instance.full_key(&self.key);
        let response = self
            .instance
            .get_version(&self.ctx, &full_key, &self.version, &headers)
            .await?;
        if response.status == 412 {
            return Err(object_changed());
        }
        if response.status == 200 {
            if !self.instance.policy.allow_full_object_fallback {
                return Err(bad_gateway(
                    "range_not_supported",
                    "the storage provider ignored the suffix byte-range request; the complete object was not downloaded",
                ));
            }
            let content_length = match header_text(&response.headers, CONTENT_LENGTH.as_str()).parse::<i64>() {
                Ok(value) if value >= 0 && value <= length => value,
                _ => {
                    return Err(bad_gateway(
                        "range_not_supported",
                        "the storage provider ignored a suffix byte-range request",
                    ));
                }
            };
            let headers = response.headers.clone();
            let data = Self::read_body(response, length).await?;
            if data.len() as i64 != content_length {
                return Err(bad_gateway(
                    "range_length_mismatch",
                    "the storage provider returned an invalid suffix length",
                ));
            }
            self.validate_and_record(&headers, content_length, data.len() as i64)?;
            self.cache_span(0, &data);
            return Ok(data);
        }
        if response.status != 206 {
            return Err(Error::upstream(response.status, "MetadataRangeReadFailed", ""));
        }
        let Some((range_start, range_end, total)) =
            parse_content_range(header_text(&response.headers, CONTENT_RANGE.as_str())).filter(|range| range.2 > 0)
        else {
            return Err(bad_gateway(
                "invalid_content_range",
                "the storage provider returned an invalid suffix Content-Range",
            ));
        };
        let expected_start = (total - length).max(0);
        if range_start != expected_start || range_end != total - 1 {
            return Err(bad_gateway(
                "range_mismatch",
                "the storage provider returned a different suffix range than requested",
            ));
        }
        let expected = range_end - range_start + 1;
        let headers = response.headers.clone();
        let data = Self::read_body(response, expected).await?;
        if data.len() as i64 != expected {
            return Err(bad_gateway(
                "range_truncated",
                "the storage provider returned a truncated or oversized suffix range",
            ));
        }
        self.validate_and_record(&headers, total, expected)?;
        self.cache_span(range_start, &data);
        Ok(data)
    }
}

/// A reader of an object in order, from an offset, one window after the other.
pub struct WindowReader {
    /// The source of the windows.
    pub source: RangeSource,
    /// The next offset.
    pub offset: i64,
    window: i64,
    buffer: Bytes,
    closed: bool,
}

impl std::fmt::Debug for WindowReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowReader")
            .field("source", &self.source)
            .field("offset", &self.offset)
            .finish_non_exhaustive()
    }
}

impl WindowReader {
    /// Open the object at a relative key and at an offset, bound to an ETag when it is not empty.
    pub async fn open(ctx: &OpCtx, instance: &Arc<Instance>, key: &str, offset: i64, etag: &str) -> Result<Self> {
        let version = ObjectVersion {
            etag: etag.to_owned(),
            ..ObjectVersion::default()
        };
        Self::open_version(ctx, instance, key, offset, &version).await
    }

    /// Open the object at a relative key and at an offset, bound to a version (for example from a cursor). A
    /// negative offset gives `400 invalid_offset`.
    pub async fn open_version(
        ctx: &OpCtx,
        instance: &Arc<Instance>,
        key: &str,
        offset: i64,
        version: &ObjectVersion,
    ) -> Result<Self> {
        if offset < 0 {
            return Err(Error::api(
                400,
                "invalid_offset",
                "object stream offset cannot be negative",
            ));
        }
        let mut source = RangeSource::open(ctx, instance, key).await?;
        source.set_expected_version(version);
        Ok(Self {
            source,
            offset,
            window: SEQUENTIAL_WINDOW_BYTES,
            buffer: Bytes::new(),
            closed: false,
        })
    }

    /// The next bytes, or an empty value at the end of the object.
    pub async fn next_chunk(&mut self) -> Result<Bytes> {
        if self.closed {
            return Err(Error::internal("read of a closed object stream"));
        }
        if !self.buffer.is_empty() {
            return Ok(std::mem::take(&mut self.buffer));
        }
        if let Some(size) = self.source.size()
            && self.offset >= size
        {
            return Ok(Bytes::new());
        }
        let length = if self.window <= 0 || self.window > MAX_SINGLE_RANGE_BYTES {
            SEQUENTIAL_WINDOW_BYTES
        } else {
            self.window
        };
        let data = self.source.read_range(self.offset, length).await?;
        self.offset += data.len() as i64;
        Ok(data)
    }

    /// Fill `destination` with the next bytes; gives the number of bytes, 0 at the end of the object.
    pub async fn read(&mut self, destination: &mut [u8]) -> Result<usize> {
        if destination.is_empty() {
            return Ok(0);
        }
        if self.buffer.is_empty() {
            self.buffer = self.next_chunk().await?;
        }
        let count = destination.len().min(self.buffer.len());
        destination[..count].copy_from_slice(&self.buffer[..count]);
        let _ = self.buffer.split_to(count);
        Ok(count)
    }

    /// The version that the reads are bound to.
    pub fn version(&self) -> ObjectVersion {
        self.source.version()
    }

    /// The headers of the first answer.
    pub fn headers(&self) -> HeaderMap {
        self.source.headers()
    }

    /// Close the reader: a later read is an error.
    pub fn close(&mut self) {
        self.closed = true;
        self.buffer = Bytes::new();
    }
}

#[cfg(test)]
#[path = "range_tests.rs"]
mod tests;
