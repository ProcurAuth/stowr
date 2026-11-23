//! The tests of the JSON previews.

use super::*;
use crate::pv_docs::test_support::{
    escape, exact_range_start, get, mutate_cursor, put, require_exact_byte_ranges, setup,
};

const UTF8_MAX_RUNE_BYTES: usize = 4;

fn put_json(backend: &crate::testkit::MemoryBackend, key: &str, value: &str) {
    put(backend, key, value.as_bytes().to_vec(), "application/json");
}

#[tokio::test]
async fn raw_pages_stream_without_a_buffer_of_the_whole_object() {
    let (app, backend) = setup();
    let payload = format!(r#"{{"large":"{}","tail":true}}"#, "x".repeat(TEXT_PAGE_BYTES * 2));
    put_json(&backend, "large.json", &payload);

    let first = get(&app, "/api/json/raw?instance=rw&key=large.json")
        .await
        .decode::<TextPage>();
    assert!(!first.done && !first.next_cursor.is_empty(), "{first:?}");
    assert!(
        first.text.len() <= TEXT_PAGE_BYTES + UTF8_MAX_RUNE_BYTES,
        "{}",
        first.text.len()
    );
    let ranges = backend.state().get_ranges.clone();
    let count = backend.state().get_count;
    assert!(
        (1..=2).contains(&count),
        "unexpected first raw read count: {count} ranges={ranges:?}"
    );
    require_exact_byte_ranges(&ranges);
    assert_eq!(exact_range_start(&ranges[0]), 0, "{ranges:?}");

    let second_url = format!(
        "/api/json/raw?instance=rw&key=large.json&cursor={}",
        escape(&first.next_cursor)
    );
    let second = get(&app, &second_url).await.decode::<TextPage>();
    assert!(!second.text.is_empty(), "expected a second raw page");
    let ranges = backend.state().get_ranges.clone();
    require_exact_byte_ranges(&ranges);
    assert!(
        exact_range_start(ranges.last().unwrap()) > 0,
        "the next raw page should resume from its byte cursor: {ranges:?}"
    );
}

#[tokio::test]
async fn raw_keeps_the_bytes_of_the_source() {
    let (app, backend) = setup();
    let payload = "{\n\t\"unicode\": \"é\\n雪\",\n\t\"spacing\"   : [ 1,  2 ]\n}\n";
    put_json(&backend, "exact.json", payload);

    let response = get(&app, "/api/json/raw?instance=rw&key=exact.json")
        .await
        .decode::<TextPage>();
    assert!(response.done, "the small raw document should fit in one page");
    assert_eq!(response.text, payload);
    assert_eq!(backend.state().get_count, 1);
    let ranges = backend.state().get_ranges.clone();
    require_exact_byte_ranges(&ranges);
    assert_eq!(exact_range_start(&ranges[0]), 0);
}

#[tokio::test]
async fn beautify_uses_the_state_of_the_continuation() {
    let (app, backend) = setup();
    let payload = format!(
        r#"{{"name":"{}","nested":{{"enabled":true}},"items":[1,2,3]}}"#,
        "é".repeat(TEXT_PAGE_BYTES)
    );
    put_json(&backend, "beautify.json", &payload);

    let first = get(&app, "/api/json/beautify?instance=rw&key=beautify.json")
        .await
        .decode::<TextPage>();
    assert!(!first.next_cursor.is_empty() && !first.done, "{first:?}");
    assert!(
        first.text.starts_with("{\n  \"name\": \""),
        "{}",
        &first.text[..80.min(first.text.len())]
    );

    let next = format!(
        "/api/json/beautify?instance=rw&key=beautify.json&cursor={}",
        escape(&first.next_cursor)
    );
    let second = get(&app, &next).await.decode::<TextPage>();
    assert!(!second.text.is_empty(), "expected continuation text");
    assert!(second.continued && second.start_in_string);
    let ranges = backend.state().get_ranges.clone();
    require_exact_byte_ranges(&ranges);
    assert!(
        exact_range_start(ranges.last().unwrap()) > 0,
        "beautify continuation should use resumed bounded ranges: {ranges:?}"
    );
}

#[tokio::test]
async fn the_root_of_the_tree_is_expanded_on_the_server_with_bounded_previews() {
    let (app, backend) = setup();
    let payload = format!(
        r#"{{"small":1,"nested":{{"enabled":true,"values":[1,2,{{"label":"ok"}}]}},"large":"{}","tail":null}}"#,
        "x".repeat(2 * 1024 * 1024)
    );
    put_json(&backend, "tree.json", &payload);

    let root = get(&app, "/api/json/tree?instance=rw&key=tree.json&limit=50")
        .await
        .decode::<TreePage>();
    assert!(
        root.node.kind == "object" && root.node.container && root.done,
        "{root:?}"
    );
    let children = root.children.clone().unwrap();
    let labels: Vec<&str> = children.iter().map(|child| child.label.as_str()).collect();
    assert_eq!(labels.join(","), "small,nested,large,tail");
    let nested = children.iter().find(|child| child.label == "nested").unwrap().clone();
    let large = children.iter().find(|child| child.label == "large").unwrap();
    assert!(
        large.preview.len() <= TREE_PREVIEW_BYTES + 8 && large.preview.ends_with("…\""),
        "the preview of the large string is not bounded: {}",
        large.preview.len()
    );
    let root_reads = backend.state().get_count;
    assert!(root_reads >= 1);
    let ranges = backend.state().get_ranges.clone();
    require_exact_byte_ranges(&ranges);
    assert_eq!(exact_range_start(&ranges[0]), 0);

    let nested_url = format!(
        "/api/json/tree?instance=rw&key=tree.json&type=object&start={}&limit=50",
        nested.start
    );
    let page = get(&app, &nested_url).await.decode::<TreePage>();
    let nested_children = page.children.unwrap();
    assert_eq!(nested_children.len(), 2, "{nested_children:?}");
    assert_eq!(nested_children[0].label, "enabled");
    assert_eq!(nested_children[1].label, "values");
    assert!(
        backend.state().get_count > root_reads,
        "the nested expansion did not issue a bounded read"
    );
    let ranges = backend.state().get_ranges.clone();
    require_exact_byte_ranges(&ranges[root_reads..]);
    assert_eq!(exact_range_start(&ranges[root_reads]), nested.start);
}

#[tokio::test]
async fn tree_pages_resume_after_the_comma() {
    let (app, backend) = setup();
    let values: Vec<String> = (0..125).map(|index| index.to_string()).collect();
    put_json(&backend, "list.json", &format!("[{}]", values.join(",")));

    let first = get(&app, "/api/json/tree?instance=rw&key=list.json&limit=50")
        .await
        .decode::<TreePage>();
    assert!(!first.done && first.children.as_ref().unwrap().len() == 50, "{first:?}");
    assert!(!first.cursor.is_empty() && first.next_index == 50);

    let next = format!(
        "/api/json/tree?instance=rw&key=list.json&type=array&start={}&cursor={}&index={}&limit=50",
        first.node.start,
        escape(&first.cursor),
        first.next_index
    );
    let second = get(&app, &next).await.decode::<TreePage>();
    let children = second.children.unwrap();
    assert!(!second.done && children.len() == 50 && children[0].label == "50");
    assert_eq!(backend.state().get_count, 2, "{:?}", backend.state().get_ranges);
    let ranges = backend.state().get_ranges.clone();
    require_exact_byte_ranges(&ranges);
    let scope = signed_cursor_scope("json-tree", "rw", "list.json");
    let cursor = decode_tree_cursor(&first.cursor, &scope).unwrap().unwrap();
    assert_eq!(exact_range_start(&ranges[1]), cursor.offset);
}

#[tokio::test]
async fn beautify_formats_empty_and_nested_containers() {
    let (app, backend) = setup();
    put_json(
        &backend,
        "small.json",
        r#"{"a":1,"empty":{},"items":[true,false],"nested":{"value":null}}"#,
    );

    let response = get(&app, "/api/json/beautify?instance=rw&key=small.json")
        .await
        .decode::<TextPage>();
    assert!(response.done, "small JSON should fit in one beautified page");
    let expected = "{\n  \"a\": 1,\n  \"empty\": {},\n  \"items\": [\n    true,\n    false\n  ],\n  \"nested\": {\n    \"value\": null\n  }\n}";
    assert_eq!(response.text, expected);
}

#[tokio::test]
async fn the_summary_matches_the_paged_raw_and_beautified_views() {
    let (app, backend) = setup();
    let payload = format!(
        r#"{{"large":"{}","items":[1,2,3],"tail":true}}"#,
        "x".repeat(TEXT_PAGE_BYTES + 4096)
    );
    put_json(&backend, "summary.json", &payload);

    let summary = get(&app, "/api/json/summary?instance=rw&key=summary.json")
        .await
        .decode::<Summary>();
    assert!(
        summary.raw_lines == 1 && summary.raw_pages >= 2 && summary.beautify_lines >= 2 && summary.beautify_pages >= 2,
        "{summary:?}"
    );
    let raw_page = summary.raw_page.as_ref().unwrap();
    assert!(!raw_page.done && !raw_page.next_cursor.is_empty(), "{raw_page:?}");
    assert!(raw_page.text.len() <= TEXT_PAGE_BYTES + UTF8_MAX_RUNE_BYTES && raw_page.line_start == 1);
    assert!(backend.state().get_count >= 1);
    let ranges = backend.state().get_ranges.clone();
    require_exact_byte_ranges(&ranges);
    assert_eq!(exact_range_start(&ranges[0]), 0);

    async fn count_pages(
        app: &std::sync::Arc<crate::common::app::App>,
        endpoint: &str,
        first: Option<&TextPage>,
    ) -> (i64, i64) {
        let mut pages = 0;
        let mut cursor = String::new();
        if let Some(first) = first {
            pages = 1;
            if first.done {
                return (pages, first.line_end);
            }
            cursor = first.next_cursor.clone();
        }
        loop {
            let mut url = endpoint.to_owned();
            if !cursor.is_empty() {
                url.push_str(&format!("&cursor={}", escape(&cursor)));
            }
            let page = get(app, &url).await.decode::<TextPage>();
            pages += 1;
            if page.done {
                return (pages, page.line_end);
            }
            assert!(
                !page.next_cursor.is_empty(),
                "paged JSON response omitted its continuation cursor"
            );
            cursor = page.next_cursor;
        }
    }

    let (raw_pages, raw_lines) = count_pages(
        &app,
        "/api/json/raw?instance=rw&key=summary.json",
        summary.raw_page.as_ref(),
    )
    .await;
    assert_eq!(
        (raw_pages, raw_lines),
        (summary.raw_pages, summary.raw_lines),
        "{summary:?}"
    );
    let (beautify_pages, beautify_lines) =
        count_pages(&app, "/api/json/beautify?instance=rw&key=summary.json", None).await;
    assert_eq!(
        (beautify_pages, beautify_lines),
        (summary.beautify_pages, summary.beautify_lines),
        "{summary:?}"
    );
}

#[tokio::test]
async fn the_tree_reports_the_counts_of_the_elements_of_an_array() {
    let (app, backend) = setup();
    put_json(&backend, "counts.json", r#"{"items":[1,2,{"nested":[3,4,5]}]}"#);

    let root = get(&app, "/api/json/tree?instance=rw&key=counts.json&limit=50")
        .await
        .decode::<TreePage>();
    assert!(root.node.count_known && root.node.count == 1, "{:?}", root.node);
    let children = root.children.unwrap();
    assert!(children.len() == 1 && children[0].kind == "array" && children[0].count_known && children[0].count == 3);

    let url = format!(
        "/api/json/tree?instance=rw&key=counts.json&type=array&start={}&limit=50",
        children[0].start
    );
    let items = get(&app, &url).await.decode::<TreePage>();
    assert!(items.node.count_known && items.node.count == 3, "{:?}", items.node);
    let nodes = items.children.unwrap();
    assert!(nodes.len() == 3 && nodes[2].kind == "object");
    assert_eq!(
        backend.state().get_count,
        2,
        "the count of an array adds no provider read"
    );
}

#[tokio::test]
async fn a_changed_or_foreign_cursor_is_refused() {
    let (app, backend) = setup();
    put_json(
        &backend,
        "a.json",
        &format!(r#"{{"large":"{}"}}"#, "x".repeat(TEXT_PAGE_BYTES * 2)),
    );
    put_json(
        &backend,
        "b.json",
        &format!(r#"{{"large":"{}"}}"#, "x".repeat(TEXT_PAGE_BYTES * 2)),
    );
    let first = get(&app, "/api/json/raw?instance=rw&key=a.json")
        .await
        .decode::<TextPage>();
    let cursor = first.next_cursor;

    let tampered = format!(
        "/api/json/raw?instance=rw&key=a.json&cursor={}",
        escape(&mutate_cursor(&cursor))
    );
    let called = get(&app, &tampered).await;
    assert_eq!((called.status, called.code().as_str()), (400, "invalid_cursor"));
    let foreign = format!("/api/json/raw?instance=rw&key=b.json&cursor={}", escape(&cursor));
    let called = get(&app, &foreign).await;
    assert_eq!((called.status, called.code().as_str()), (400, "invalid_cursor"));
    let other_kind = format!("/api/json/beautify?instance=rw&key=a.json&cursor={}", escape(&cursor));
    assert_eq!(get(&app, &other_kind).await.status, 400);
}

#[test]
fn a_signed_cursor_refuses_a_change_and_another_object() {
    let value = TextCursor {
        offset: 42,
        line: 7,
        scope: signed_cursor_scope("json-raw", "alpha", "a.json"),
        ..TextCursor::default()
    };
    let encoded = encode_signed_cursor(&value).unwrap();
    let fallback = TextCursor {
        line: 1,
        ..TextCursor::default()
    };
    assert!(decode_text_cursor(&mutate_cursor(&encoded), fallback.clone(), &value.scope).is_err());
    let other = signed_cursor_scope("json-raw", "alpha", "b.json");
    assert!(decode_text_cursor(&encoded, fallback.clone(), &other).is_err());
    let decoded = decode_text_cursor(&encoded, fallback, &value.scope).unwrap();
    assert_eq!((decoded.offset, decoded.line), (42, 7));
}

#[test]
fn a_cursor_with_a_bad_state_is_refused() {
    let scope = signed_cursor_scope("json-raw", "a", "k");
    let fallback = || TextCursor {
        line: 1,
        ..TextCursor::default()
    };
    for (name, cursor) in [
        (
            "negative offset",
            TextCursor {
                offset: -1,
                line: 1,
                scope: scope.clone(),
                ..TextCursor::default()
            },
        ),
        (
            "line zero",
            TextCursor {
                offset: 0,
                line: 0,
                scope: scope.clone(),
                ..TextCursor::default()
            },
        ),
        (
            "stack letter",
            TextCursor {
                offset: 0,
                line: 1,
                stack: "{x".to_owned(),
                scope: scope.clone(),
                ..TextCursor::default()
            },
        ),
        (
            "pending byte",
            TextCursor {
                offset: 0,
                line: 1,
                pending: b'z',
                scope: scope.clone(),
                ..TextCursor::default()
            },
        ),
        (
            "stack too deep",
            TextCursor {
                offset: 0,
                line: 1,
                stack: "[".repeat(MAX_NESTING_DEPTH + 1),
                scope: scope.clone(),
                ..TextCursor::default()
            },
        ),
    ] {
        let encoded = encode_signed_cursor(&cursor).unwrap();
        let error = decode_text_cursor(&encoded, fallback(), &scope).unwrap_err();
        assert!(error.has_code("invalid_cursor"), "{name}");
    }
    let empty = decode_text_cursor("  ", fallback(), &scope).unwrap();
    assert_eq!((empty.line, empty.scope.as_str()), (1, scope.as_str()));
}

#[tokio::test]
async fn bad_parameters_have_their_codes() {
    let (app, backend) = setup();
    put_json(&backend, "p.json", "[1,2]");
    for (target, status, code) in [
        ("/api/json/tree?instance=rw&key=p.json&start=-1", 400, "invalid_offset"),
        ("/api/json/tree?instance=rw&key=p.json&index=x", 400, "invalid_offset"),
        ("/api/json/tree?instance=rw&key=p.json&limit=0", 400, "invalid_limit"),
        ("/api/json/tree?instance=rw&key=p.json&limit=201", 400, "invalid_limit"),
        (
            "/api/json/tree?instance=rw&key=p.json&type=string",
            400,
            "invalid_node_type",
        ),
        ("/api/json/tree?instance=rw&key=", 400, "invalid_key"),
        ("/api/json/raw?instance=rw", 400, "invalid_key"),
        ("/api/json/raw?instance=none&key=p.json", 404, "unknown_instance"),
    ] {
        let called = get(&app, target).await;
        assert_eq!((called.status, called.code().as_str()), (status, code), "{target}");
    }
    let called = crate::pv_docs::test_support::call_with(&app, "POST", "/api/json/raw?instance=rw&key=p.json").await;
    assert_eq!(called.status, 405);
    assert_eq!(called.headers.get("allow").unwrap(), "GET");
}

#[tokio::test]
async fn a_cursor_of_another_node_is_refused_by_the_tree() {
    let (app, backend) = setup();
    let values: Vec<String> = (0..125).map(|index| index.to_string()).collect();
    put_json(&backend, "list.json", &format!("[{}]", values.join(",")));
    let first = get(&app, "/api/json/tree?instance=rw&key=list.json&limit=50")
        .await
        .decode::<TreePage>();
    let wrong_start = format!(
        "/api/json/tree?instance=rw&key=list.json&start=7&cursor={}",
        escape(&first.cursor)
    );
    let called = get(&app, &wrong_start).await;
    assert_eq!((called.status, called.code().as_str()), (400, "invalid_cursor_scope"));
    let wrong_type = format!(
        "/api/json/tree?instance=rw&key=list.json&type=object&cursor={}",
        escape(&first.cursor)
    );
    let called = get(&app, &wrong_type).await;
    assert_eq!((called.status, called.code().as_str()), (400, "invalid_cursor_scope"));
}

#[tokio::test]
async fn a_scalar_document_gives_its_node_and_no_children() {
    let (app, backend) = setup();
    put_json(&backend, "scalar.json", "  \"hello\\nworld\" ");
    let called = get(&app, "/api/json/tree?instance=rw&key=scalar.json").await;
    let json = called.json();
    assert_eq!(json["node"]["type"], "string");
    assert_eq!(json["node"]["preview"], "\"hello\nworld\"");
    assert!(json["children"].is_null());
    assert_eq!(json["done"], true);
    put_json(&backend, "empty.json", "   ");
    let called = get(&app, "/api/json/tree?instance=rw&key=empty.json").await;
    assert_eq!((called.status, called.code().as_str()), (422, "invalid_json"));
    assert_eq!(called.message(), "JSON document is empty");
}

#[tokio::test]
async fn invalid_json_gives_422_in_each_view() {
    let (app, backend) = setup();
    put_json(&backend, "open.json", r#"{"a":[1,2"#);
    put_json(&backend, "mismatch.json", r#"{"a":[1,2}}"#);
    let called = get(&app, "/api/json/beautify?instance=rw&key=open.json").await;
    assert_eq!((called.status, called.code().as_str()), (422, "invalid_json"));
    assert_eq!(
        called.message(),
        "JSON ended before all strings or containers were closed"
    );
    let called = get(&app, "/api/json/summary?instance=rw&key=mismatch.json").await;
    assert_eq!((called.status, called.code().as_str()), (422, "invalid_json"));
    assert_eq!(called.message(), "JSON contains mismatched container delimiters");
    let called = get(&app, "/api/json/tree?instance=rw&key=open.json").await;
    assert_eq!(called.status, 422, "{}", called.text());
}

#[test]
fn the_preview_of_a_string_decodes_its_escapes_or_marks_the_symbols() {
    assert_eq!(string_preview(br"a\nb\u00e9\ud83d\ude00", true), "a\nbé😀");
    assert_eq!(string_preview(br"\ud800x", true), "\u{FFFD}x");
    // A bad escape, a control character and a cut string use the symbols.
    assert_eq!(string_preview(br"a\qb\n", true), "a\\qb↵");
    assert_eq!(string_preview(b"a\nb", true), "a\nb");
    assert_eq!(string_preview(br"a\nb\tc\r\\d\q", false), "a↵b⇥c\\d\\q");
    assert_eq!(string_preview(b"a\xFFb", false), "a\u{FFFD}b");
}

#[test]
fn the_beautifier_puts_one_value_on_each_line() {
    let mut state = TextCursor {
        line: 1,
        ..TextCursor::default()
    };
    let mut output = PageText::default();
    for value in r#"{"a":[],"b":{"c":"d, e"},"f":[1,{"g":2}]}"#.chars() {
        beautify_rune(&mut state, &mut output, value).unwrap();
    }
    assert_eq!(
        output.text,
        "{\n  \"a\": [],\n  \"b\": {\n    \"c\": \"d, e\"\n  },\n  \"f\": [\n    1,\n    {\n      \"g\": 2\n    }\n  ]\n}"
    );
    assert_eq!(output.lines, 11);
    assert!(state.stack.is_empty());
}
