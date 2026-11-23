//! The tests of the range readers.

use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::access::AccessRequest;
use crate::common::BoxFuture;
use crate::common::config::RuntimePolicy;
use crate::common::storage::Backend;
use crate::instance::budget::Budget;
use crate::instance::ceiling::{ACTION_READ, CODE_CEILING_EXCEEDED, MAX_OBJECT_SIZE, ceiling_error_of};
use crate::testkit::{
    MemoryBackend, MemoryLayer, MemoryVersion, bucket_config, instance_with_policy, read_write_instance,
};

/// The instance `rw` over a memory back end with one object at `tenant/<key>`.
fn seeded(key: &str, data: &[u8]) -> (Arc<MemoryBackend>, Arc<Instance>) {
    let backend = Arc::new(MemoryBackend::new());
    backend.insert(&format!("tenant/{key}"), data.to_vec(), "application/octet-stream");
    let instance = read_write_instance(backend.clone());
    (backend, instance)
}

fn with_policy(backend: Arc<dyn Backend>, policy: RuntimePolicy) -> Arc<Instance> {
    Arc::new(instance_with_policy(
        bucket_config("rw", "tenant/", &["read", "write", "delete"]),
        backend,
        policy,
    ))
}

/// Each range of the reads: `bytes=start-end` with both bounds, or the suffix form when `suffix` is true.
fn require_exact_ranges(ranges: &[String]) {
    assert!(!ranges.is_empty(), "expected at least one byte-range request");
    for value in ranges {
        let raw = value
            .strip_prefix("bytes=")
            .unwrap_or_else(|| panic!("{value} is not a byte range"));
        let (start, end) = raw.split_once('-').unwrap_or_else(|| panic!("{value} is malformed"));
        let start: i64 = start.parse().unwrap_or_else(|_| panic!("{value} is open-ended"));
        let end: i64 = end.parse().unwrap_or_else(|_| panic!("{value} is open-ended"));
        assert!(start >= 0 && end >= start, "{value} is invalid");
    }
}

fn pattern(size: usize) -> Vec<u8> {
    (0..size).map(|index| (index % 251) as u8).collect()
}

#[tokio::test]
async fn a_range_read_sends_exact_ranges_and_binds_the_etag() {
    let data = pattern(1000);
    let (backend, instance) = seeded("folder/big.bin", &data);
    let source = RangeSource::open(&OpCtx::default(), &instance, "folder/big.bin")
        .await
        .unwrap();
    assert_eq!(source.size(), None);
    let first = source.read_range(10, 20).await.unwrap();
    assert_eq!(&first[..], &data[10..30]);
    assert_eq!(source.size(), Some(1000));
    assert_eq!(source.version().etag, "\"etag-tenant/folder/big.bin\"");
    let second = source.read_range(500, 10).await.unwrap();
    assert_eq!(&second[..], &data[500..510]);
    let state = backend.state();
    assert_eq!(state.get_ranges, vec!["bytes=10-29", "bytes=500-509"]);
    require_exact_ranges(&state.get_ranges);
    assert_eq!(
        state.last_get_headers.get("if-match").unwrap(),
        "\"etag-tenant/folder/big.bin\""
    );
    assert_eq!(source.counters(), (2, 30));
    assert_eq!(
        source.headers().get("content-type").unwrap(),
        "application/octet-stream"
    );
}

#[tokio::test]
async fn a_read_from_the_cache_makes_no_request_and_a_gap_reads_only_the_gap() {
    let data = pattern(100);
    let (backend, instance) = seeded("k.bin", &data);
    let source = RangeSource::open(&OpCtx::default(), &instance, "k.bin").await.unwrap();
    source.read_range(0, 10).await.unwrap();
    source.read_range(20, 10).await.unwrap();
    let cached = source.read_range(2, 5).await.unwrap();
    assert_eq!(&cached[..], &data[2..7]);
    assert_eq!(backend.state().get_count, 2);
    // From 5 to 25: the cache gives 5..10 and 20..25, one request reads 10..20.
    let merged = source.read_range(5, 20).await.unwrap();
    assert_eq!(&merged[..], &data[5..25]);
    assert_eq!(backend.state().get_ranges.last().unwrap(), "bytes=10-19");
    // A read past the end gives the bytes up to the end, then nothing.
    let tail = source.read_range(95, 50).await.unwrap();
    assert_eq!(&tail[..], &data[95..]);
    assert!(source.read_range(100, 5).await.unwrap().is_empty());
    let prefix = source.read_prefix(1000).await.unwrap();
    assert_eq!(&prefix[..], &data[..]);
    assert!(source.read_prefix(0).await.unwrap().is_empty());
    source.clear_cache();
    source.read_range(0, 1).await.unwrap();
    assert_eq!(backend.state().get_ranges.last().unwrap(), "bytes=0-0");
}

#[tokio::test]
async fn a_suffix_read_finds_the_size_with_one_request() {
    let data = pattern(300);
    let (backend, instance) = seeded("archive.zip", &data);
    let source = RangeSource::open(&OpCtx::default(), &instance, "archive.zip")
        .await
        .unwrap();
    let tail = source.read_suffix(22).await.unwrap();
    assert_eq!(&tail[..], &data[278..]);
    assert_eq!(source.size(), Some(300));
    assert_eq!(backend.state().get_ranges, vec!["bytes=-22"]);
    // The suffix is in the cache; a later suffix with a known size reads an exact range.
    let again = source.read_range(280, 10).await.unwrap();
    assert_eq!(&again[..], &data[280..290]);
    let longer = source.read_suffix(400).await.unwrap();
    assert_eq!(longer.len(), 300);
    assert_eq!(backend.state().get_ranges, vec!["bytes=-22", "bytes=0-277"]);
    assert!(source.read_suffix(0).await.is_err());
}

#[tokio::test]
async fn a_suffix_longer_than_the_object_gives_the_whole_object() {
    let (_, instance) = seeded("small.bin", b"abc");
    let source = RangeSource::open(&OpCtx::default(), &instance, "small.bin")
        .await
        .unwrap();
    assert_eq!(&source.read_suffix(64).await.unwrap()[..], b"abc");
    assert_eq!(source.size(), Some(3));
}

#[tokio::test]
async fn an_empty_object_gives_no_byte() {
    let (_, instance) = seeded("empty.txt", b"");
    let source = RangeSource::open(&OpCtx::default(), &instance, "empty.txt")
        .await
        .unwrap();
    assert!(source.read_range(0, 10).await.unwrap().is_empty());
    assert_eq!(source.size_or_zero(), 0);
    let mut reader = WindowReader::open(&OpCtx::default(), &instance, "empty.txt", 0, "")
        .await
        .unwrap();
    assert!(reader.next_chunk().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_provider_that_ignores_the_range_is_refused_without_the_fallback() {
    let data = pattern(50);
    let (backend, instance) = seeded("k.bin", &data);
    backend.state().ignore_ranges = true;
    let source = RangeSource::open(&OpCtx::default(), &instance, "k.bin").await.unwrap();
    let error = source.read_range(0, 10).await.err().unwrap();
    assert!(error.has_code("range_not_supported"), "{error:?}");
    assert_eq!(error.status(), 502);
    let error = source.read_suffix(10).await.err().unwrap();
    assert!(error.has_code("range_not_supported"));

    // With the fallback, a whole object that fits in the range is accepted; a larger one is not.
    let policy = RuntimePolicy {
        allow_full_object_fallback: true,
        ..RuntimePolicy::default()
    };
    let instance = with_policy(backend.clone(), policy);
    let source = RangeSource::open(&OpCtx::default(), &instance, "k.bin").await.unwrap();
    assert!(
        source
            .read_range(0, 10)
            .await
            .err()
            .unwrap()
            .has_code("range_not_supported")
    );
    let whole = source.read_range(0, 64).await.unwrap();
    assert_eq!(&whole[..], &data[..]);
    let source = RangeSource::open(&OpCtx::default(), &instance, "k.bin").await.unwrap();
    assert_eq!(&source.read_suffix(64).await.unwrap()[..], &data[..]);
    assert!(source.read_range(10, 5).await.is_ok());
}

#[tokio::test]
async fn an_answer_with_the_wrong_bytes_is_refused() {
    let data = pattern(50);
    let (backend, instance) = seeded("k.bin", &data);
    backend.state().range_body_full = true;
    let source = RangeSource::open(&OpCtx::default(), &instance, "k.bin").await.unwrap();
    let error = source.read_range(0, 10).await.err().unwrap();
    assert!(error.has_code("range_length_mismatch"), "{error:?}");

    backend.state().range_body_full = false;
    backend.state().range_status_ok = true;
    let error = source.read_range(0, 10).await.err().unwrap();
    assert!(error.has_code("range_not_supported"), "{error:?}");
}

/// A back end that answers 206 with a range other than the request.
struct ShiftedRanges {
    memory: MemoryBackend,
}

impl MemoryLayer for ShiftedRanges {
    fn memory(&self) -> &MemoryBackend {
        &self.memory
    }
    fn get<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        Box::pin(async move {
            let mut response = self.memory.get(ctx, key, headers).await?;
            response
                .headers
                .insert(CONTENT_RANGE, HeaderValue::from_static("bytes 1-10/50"));
            Ok(response)
        })
    }
}

#[tokio::test]
async fn an_answer_with_another_range_is_refused() {
    let memory = MemoryBackend::new();
    memory.insert("tenant/k.bin", pattern(50), "");
    let instance = read_write_instance(Arc::new(ShiftedRanges { memory }));
    let source = RangeSource::open(&OpCtx::default(), &instance, "k.bin").await.unwrap();
    assert!(source.read_range(0, 10).await.err().unwrap().has_code("range_mismatch"));
    assert!(source.read_suffix(10).await.err().unwrap().has_code("range_mismatch"));
}

#[tokio::test]
async fn a_changed_object_stops_the_reads() {
    let data = pattern(50);
    let (_, instance) = seeded("k.bin", &data);
    let mut source = RangeSource::open(&OpCtx::default(), &instance, "k.bin").await.unwrap();
    source.set_expected_etag("other-etag");
    assert_eq!(source.version().etag, "\"other-etag\"");
    let error = source.read_range(0, 10).await.err().unwrap();
    assert!(error.has_code("object_changed"));
    assert_eq!(error.status(), 412);

    let mut source = RangeSource::open(&OpCtx::default(), &instance, "k.bin").await.unwrap();
    source.set_known_size(40);
    assert!(source.read_range(0, 10).await.err().unwrap().has_code("object_changed"));

    let mut source = RangeSource::open(&OpCtx::default(), &instance, "k.bin").await.unwrap();
    source.set_known_size(50);
    source.set_known_size(10);
    assert_eq!(source.size(), Some(50));
    assert!(source.read_range(0, 10).await.is_ok());
}

#[tokio::test]
async fn the_ceiling_applies_to_a_span_of_the_cache() {
    let (_, instance) = seeded("folder/big.bin", &[b'x'; 100]);
    let source = RangeSource::open(&OpCtx::default(), &instance, "folder/big.bin")
        .await
        .unwrap();
    source.read_range(0, 10).await.unwrap();
    // A request with a lower ceiling reads the same source: the cache gives no data.
    let request = AccessRequest {
        request_id: "rid-cache".to_owned(),
        ..AccessRequest::default()
    };
    request.ceilings.lower(ACTION_READ, MAX_OBJECT_SIZE, 10);
    let ctx = OpCtx {
        access: Some(Arc::new(request)),
        ..OpCtx::default()
    };
    let error = source.with_context(&ctx).read_range(0, 5).await.err().unwrap();
    assert_eq!(
        ceiling_error_of(&error).map(|api| api.code.as_str()),
        Some(CODE_CEILING_EXCEEDED)
    );
}

#[tokio::test]
async fn the_ceiling_refuses_a_range_of_a_big_object_before_any_byte() {
    let (backend, instance) = seeded("folder/big.bin", &[b'x'; 100]);
    let request = AccessRequest::default();
    request.ceilings.lower(ACTION_READ, MAX_OBJECT_SIZE, 10);
    let ctx = OpCtx {
        access: Some(Arc::new(request)),
        ..OpCtx::default()
    };
    let source = RangeSource::open(&ctx, &instance, "folder/big.bin").await.unwrap();
    let error = source.read_range(0, 5).await.err().unwrap();
    assert!(error.has_code(CODE_CEILING_EXCEEDED));
    assert_eq!(backend.bytes_read(), 0);
    assert_eq!(instance.gate.held(), 0);
}

#[tokio::test]
async fn the_reads_count_in_the_budget_of_the_context() {
    let (_, instance) = seeded("k.bin", &pattern(100));
    let budget = Arc::new(Budget::new(10, 1000));
    let ctx = OpCtx::with_budget(budget.clone());
    let source = RangeSource::open(&ctx, &instance, "k.bin").await.unwrap();
    source.read_range(0, 40).await.unwrap();
    source.read_range(50, 10).await.unwrap();
    let usage = budget.usage();
    assert_eq!((usage.storage_requests, usage.storage_bytes), (2, 50));

    let small = Arc::new(Budget::new(10, 20));
    let source = RangeSource::open(&OpCtx::with_budget(small), &instance, "k.bin")
        .await
        .unwrap();
    let error = source.read_range(0, 40).await.err().unwrap();
    assert_eq!(error.status(), 429);
    assert_eq!(error.code(), "resource_budget_exceeded");
}

#[tokio::test]
async fn a_range_out_of_the_limits_is_refused() {
    let (_, instance) = seeded("k.bin", b"abc");
    let source = RangeSource::open(&OpCtx::default(), &instance, "k.bin").await.unwrap();
    for (start, length) in [(-1, 10), (0, 0), (0, MAX_SINGLE_RANGE_BYTES + 1)] {
        assert!(source.read_range(start, length).await.is_err());
    }
    assert!(source.read_range(0, MAX_SINGLE_RANGE_BYTES).await.is_ok());
}

/// A back end whose reads wait: two reads of the same range meet in flight.
struct SlowReads {
    memory: MemoryBackend,
}

impl MemoryLayer for SlowReads {
    fn memory(&self) -> &MemoryBackend {
        &self.memory
    }
    fn get<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        Box::pin(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            self.memory.get(ctx, key, headers).await
        })
    }
}

#[tokio::test]
async fn two_reads_of_the_same_range_share_one_request() {
    let layer = Arc::new(SlowReads {
        memory: MemoryBackend::new(),
    });
    layer.memory.insert("tenant/k.bin", pattern(100), "");
    let instance = read_write_instance(layer.clone());
    let source = Arc::new(RangeSource::open(&OpCtx::default(), &instance, "k.bin").await.unwrap());
    let other = source.clone();
    let (first, second) = tokio::join!(source.read_range(0, 10), other.read_range(0, 10));
    assert_eq!(first.unwrap(), second.unwrap());
    assert_eq!(layer.memory.state().get_count, 1);
    // A canceled owner does not stop a later read.
    let pending = source.read_range(20, 10);
    let _ = tokio::time::timeout(Duration::from_millis(5), pending).await;
    assert_eq!(&source.read_range(20, 10).await.unwrap()[..], &pattern(100)[20..30]);
}

#[tokio::test]
async fn the_cache_keeps_its_limit() {
    let backend = Arc::new(MemoryBackend::new());
    backend.insert("tenant/k.bin", pattern(100), "");
    let policy = RuntimePolicy {
        max_range_cache_bytes: 25,
        ..RuntimePolicy::default()
    };
    let instance = with_policy(backend.clone(), policy);
    let source = RangeSource::open(&OpCtx::default(), &instance, "k.bin").await.unwrap();
    source.read_range(0, 10).await.unwrap();
    source.read_range(20, 10).await.unwrap();
    source.read_range(40, 10).await.unwrap();
    // The first span left the cache.
    source.read_range(0, 10).await.unwrap();
    source.read_range(40, 10).await.unwrap();
    assert_eq!(backend.state().get_count, 4);
    // A span larger than the cache is not kept.
    source.read_range(50, 30).await.unwrap();
    source.read_range(50, 30).await.unwrap();
    assert_eq!(backend.state().get_count, 6);
}

#[tokio::test]
async fn a_version_reads_without_the_preconditions() {
    let backend = Arc::new(MemoryBackend::new().with_versions());
    backend.add_version(
        "tenant/doc.txt",
        MemoryVersion {
            id: "v1".to_owned(),
            data: bytes::Bytes::from_static(b"previous text"),
            ..MemoryVersion::default()
        },
    );
    let instance = read_write_instance(backend.clone());
    instance.set_versioning_available(true);
    let mut source = RangeSource::open_version(&OpCtx::default(), &instance, "doc.txt", "v1")
        .await
        .unwrap();
    source.set_expected_etag("\"etag-tenant/doc.txt\"");
    assert_eq!(&source.read_range(0, 8).await.unwrap()[..], b"previous");
    assert!(backend.state().last_get_headers.get("if-match").is_none());
    // The version of the context also applies to a source without its own version.
    let ctx = OpCtx::default().with_version(Some("v1"));
    let source = RangeSource::open(&ctx, &instance, "doc.txt").await.unwrap();
    assert_eq!(&source.read_suffix(4).await.unwrap()[..], b"text");
}

#[tokio::test]
async fn the_window_reader_reads_in_order_with_exact_windows() {
    let data = pattern(600 << 10);
    let (backend, instance) = seeded("big.csv", &data);
    let mut reader = WindowReader::open(&OpCtx::default(), &instance, "big.csv", 100, "")
        .await
        .unwrap();
    let mut out = Vec::new();
    loop {
        let chunk = reader.next_chunk().await.unwrap();
        if chunk.is_empty() {
            break;
        }
        out.extend_from_slice(&chunk);
    }
    assert_eq!(&out[..], &data[100..]);
    let ranges = backend.state().get_ranges.clone();
    require_exact_ranges(&ranges);
    assert_eq!(ranges.len(), 3);
    assert_eq!(ranges[0], format!("bytes=100-{}", 100 + SEQUENTIAL_WINDOW_BYTES - 1));
    assert_eq!(reader.version().etag, "\"etag-tenant/big.csv\"");
    assert!(reader.headers().get("etag").is_some());
    reader.close();
    assert!(reader.next_chunk().await.is_err());
}

#[tokio::test]
async fn the_window_reader_fills_small_buffers() {
    let (_, instance) = seeded("small.txt", b"hello world");
    let mut reader = WindowReader::open(&OpCtx::default(), &instance, "small.txt", 6, "etag-tenant/small.txt")
        .await
        .unwrap();
    let mut buffer = [0u8; 3];
    let mut out = Vec::new();
    loop {
        let count = reader.read(&mut buffer).await.unwrap();
        if count == 0 {
            break;
        }
        out.extend_from_slice(&buffer[..count]);
    }
    assert_eq!(&out[..], b"world");
    let error = WindowReader::open(&OpCtx::default(), &instance, "small.txt", -1, "")
        .await
        .err()
        .unwrap();
    assert!(error.has_code("invalid_offset"));
    assert_eq!(error.status(), 400);
}

#[tokio::test]
async fn the_window_reader_finds_a_changed_object() {
    let (_, instance) = seeded("small.txt", b"hello world");
    let mut reader = WindowReader::open(&OpCtx::default(), &instance, "small.txt", 0, "\"another\"")
        .await
        .unwrap();
    assert!(reader.next_chunk().await.err().unwrap().has_code("object_changed"));
}

#[test]
fn an_expected_etag_gets_its_quotes() {
    assert_eq!(normalize_expected_etag(""), "");
    assert_eq!(normalize_expected_etag(" * "), "*");
    assert_eq!(normalize_expected_etag("abc"), "\"abc\"");
    assert_eq!(normalize_expected_etag("\"abc\""), "\"abc\"");
    assert_eq!(normalize_expected_etag("W/\"abc\""), "W/\"abc\"");
    assert_eq!(normalize_expected_etag("abc\""), "\"abc\"");
}

#[test]
fn the_version_of_a_cursor_has_short_names() {
    let version = ObjectVersion {
        etag: "\"e1\"".to_owned(),
        version: String::new(),
        modified: "Sun, 06 Nov 1994 08:49:37 GMT".to_owned(),
    };
    let text = String::from_utf8(crate::common::json::to_vec(&version).unwrap()).unwrap();
    assert_eq!(text, "{\"e\":\"\\\"e1\\\"\",\"m\":\"Sun, 06 Nov 1994 08:49:37 GMT\"}");
    let back: ObjectVersion = serde_json::from_str(&text).unwrap();
    assert_eq!(back, version);
    assert!(ObjectVersion::default().is_empty());
    assert!(!version.is_empty());
}

#[test]
fn a_content_range_needs_its_three_numbers() {
    assert_eq!(parse_content_range("bytes 0-9/100"), Some((0, 9, 100)));
    assert_eq!(parse_content_range("BYTES 5-5/6"), Some((5, 5, 6)));
    assert_eq!(parse_content_range("bytes 0-9/0"), Some((0, 9, 0)));
    for value in [
        "bytes */100",
        "bytes 0-9/*",
        "bytes 9-0/100",
        "bytes 0-100/100",
        "items 0-9/100",
        "bytes 0-9",
    ] {
        assert_eq!(parse_content_range(value), None, "{value}");
    }
}
