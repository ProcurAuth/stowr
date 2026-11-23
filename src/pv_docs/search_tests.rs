//! The tests of the search in a document.

use bytes::Bytes;

use super::*;
use crate::pv_docs::test_support::{get, put, setup};

fn stream(text: &[u8]) -> ObjectStream {
    ObjectStream::memory(vec![Bytes::copy_from_slice(text)])
}

#[tokio::test]
async fn the_search_goes_beyond_the_buffer_of_the_reader() {
    let prefix = "a".repeat(READER_BYTES - 2);
    // The first match crosses the border of two fragments.
    let input = format!("{prefix}Needle\nsecond needle line\n");
    let result = search_document_stream(stream(input.as_bytes()), b"needle")
        .await
        .unwrap();
    assert_eq!(result.total, 2);
    assert_eq!(result.matches.len(), 2);
    assert_eq!((result.matches[0].line, result.matches[1].line), (1, 2));
    assert_eq!(result.bytes_scanned, i64::try_from(input.len()).unwrap());
    assert_eq!(result.matches[0].offset, i64::try_from(READER_BYTES - 2).unwrap());
}

#[tokio::test]
async fn the_matches_that_the_answer_keeps_are_bounded() {
    let input = "x\n".repeat(MAX_RESULTS + 20);
    let result = search_document_stream(stream(input.as_bytes()), b"x").await.unwrap();
    assert_eq!(result.total, i64::try_from(MAX_RESULTS + 20).unwrap());
    assert_eq!(result.matches.len(), MAX_RESULTS);
    assert!(result.truncated);
}

#[tokio::test]
async fn the_search_ignores_case_and_gives_a_snippet() {
    let text = format!(
        "{}Straße ÉCOLE needle\r\nnext Line{}",
        "a ".repeat(200),
        " tail".repeat(100)
    );
    let result = search_document_stream(stream(text.as_bytes()), "école".as_bytes())
        .await
        .unwrap();
    assert_eq!(result.total, 1);
    let snippet = &result.matches[0].snippet;
    assert!(
        snippet.starts_with('…') && snippet.contains("ÉCOLE needle"),
        "{snippet}"
    );
    assert!(!snippet.contains('\r'));
    let result = search_document_stream(stream(b"one\ntwo THREE\nfour"), b"three")
        .await
        .unwrap();
    assert_eq!(result.matches[0].snippet, "two THREE ↵");
    assert_eq!((result.matches[0].line, result.matches[0].offset), (2, 8));
    let result = search_document_stream(stream(b"a\r\nneedle\r\nb"), b"needle")
        .await
        .unwrap();
    assert_eq!(result.matches[0].snippet, "needle ↵");
}

#[tokio::test]
async fn a_query_that_is_not_found_gives_an_empty_list() {
    let result = search_document_stream(stream(b"abc"), b"zzz").await.unwrap();
    assert_eq!((result.total, result.matches.len(), result.truncated), (0, 0, false));
    assert_eq!(result.bytes_scanned, 3);
    let result = search_document_stream(stream(b""), b"zzz").await.unwrap();
    assert_eq!(result.bytes_scanned, 0);
    let result = search_document_stream(stream(b"abc"), b"").await.unwrap();
    assert_eq!(result.total, 0);
}

#[tokio::test]
async fn the_route_searches_the_object_and_checks_its_parameters() {
    let (app, backend) = setup();
    put(
        &backend,
        "doc.txt",
        b"first line\nSecond Needle here\n".to_vec(),
        "text/plain",
    );
    let called = get(&app, "/api/search?instance=rw&key=doc.txt&q=%20needle%20").await;
    let result = called.decode::<SearchResult>();
    assert_eq!(
        (result.instance.as_str(), result.key.as_str(), result.query.as_str()),
        ("rw", "doc.txt", "needle")
    );
    assert_eq!(result.total, 1);
    assert_eq!(result.matches[0].line, 2);
    assert_eq!(called.headers.get("cache-control").unwrap(), "no-store");

    for (target, status, code) in [
        ("/api/search?instance=rw&key=doc.txt", 400, "invalid_search"),
        ("/api/search?instance=rw&q=x", 400, "invalid_search"),
        ("/api/search?instance=none&key=doc.txt&q=x", 404, "unknown_instance"),
    ] {
        let called = get(&app, target).await;
        assert_eq!((called.status, called.code().as_str()), (status, code), "{target}");
    }
    let long = "x".repeat(MAX_QUERY_BYTES + 1);
    let called = get(&app, &format!("/api/search?instance=rw&key=doc.txt&q={long}")).await;
    assert_eq!((called.status, called.code().as_str()), (400, "search_query_too_long"));
    assert_eq!(called.message(), "search queries are limited to 1024 bytes");
    let called = get(&app, "/api/search?instance=rw&key=missing.txt&q=x").await;
    assert_eq!(called.status, 404);
}
