//! The tests of the preview of delimited text.

use bytes::Bytes;

use super::*;
use crate::pv_docs::test_support::{
    escape, exact_range_start, get, mutate_cursor, put, require_exact_byte_ranges, setup,
};

fn put_text(backend: &crate::testkit::MemoryBackend, key: &str, data: &[u8], content_type: &str) {
    put(backend, key, data.to_vec(), content_type);
}

#[tokio::test]
async fn tsv_pages_without_a_load_of_the_whole_object() {
    let (app, backend) = setup();
    put_text(
        &backend,
        "table.tsv",
        b"name\tvalue\nalpha\t1\nbeta\t2\ngamma\t3\ndelta\t4\n",
        "text/tab-separated-values",
    );

    let first = get(&app, "/api/delimited?instance=rw&key=table.tsv&pageSize=2")
        .await
        .decode::<DelimitedPage>();
    assert_eq!(first.headers.join(","), "name,value");
    assert!(
        first.rows.len() == 2 && !first.done && !first.next_cursor.is_empty(),
        "{first:?}"
    );
    assert_eq!((first.start_row, first.end_row), (2, 3));
    assert_eq!(first.delimiter, "\t");

    let url = format!(
        "/api/delimited?instance=rw&key=table.tsv&pageSize=2&cursor={}",
        escape(&first.next_cursor)
    );
    let second = get(&app, &url).await.decode::<DelimitedPage>();
    assert!(second.headers.is_empty(), "{second:?}");
    assert!(second.rows.len() == 2 && second.rows[0][0] == "gamma" && second.rows[1][0] == "delta" && second.done);
    assert_eq!(backend.state().get_count, 2);
    let ranges = backend.state().get_ranges.clone();
    require_exact_byte_ranges(&ranges);
    assert!(
        exact_range_start(&ranges[0]) == 0 && exact_range_start(&ranges[1]) > 0,
        "{ranges:?}"
    );
}

#[tokio::test]
async fn a_tsv_larger_than_the_limit_of_the_browser_is_paged() {
    let (app, backend) = setup();
    let target = 33 * 1024 * 1024;
    let row = b"large-value\t42\n";
    let mut data = b"name\tvalue\n".to_vec();
    for _ in 0..(target / row.len() + 1) {
        data.extend_from_slice(row);
    }
    put_text(&backend, "large.tsv", &data, "text/tab-separated-values");

    let page = get(&app, "/api/delimited?instance=rw&key=large.tsv&pageSize=3")
        .await
        .decode::<DelimitedPage>();
    assert!(page.rows.len() == 3 && page.rows[0][0] == "large-value" && !page.done && !page.next_cursor.is_empty());
    assert_eq!(backend.state().get_count, 1);
    require_exact_byte_ranges(&backend.state().get_ranges.clone());
}

#[tokio::test]
async fn the_count_of_a_tsv_is_an_explicit_action() {
    let (app, backend) = setup();
    put_text(
        &backend,
        "table.tsv",
        b"name\tvalue\nalpha\t1\nbeta\t2\n",
        "text/tab-separated-values",
    );

    let result = get(&app, "/api/document-count?instance=rw&key=table.tsv")
        .await
        .decode::<DocumentCount>();
    assert_eq!((result.kind.as_str(), result.rows, result.columns), ("delimited", 2, 2));
    assert_eq!(backend.state().get_count, 1);
}

#[tokio::test]
async fn the_mark_of_byte_order_is_not_in_the_header() {
    let (app, backend) = setup();
    put_text(
        &backend,
        "bom.tsv",
        b"\xef\xbb\xbfid\tvalue\n1\talpha\n",
        "text/tab-separated-values",
    );

    let page = get(&app, "/api/delimited?instance=rw&key=bom.tsv&pageSize=100")
        .await
        .decode::<DelimitedPage>();
    assert_eq!(page.headers, vec!["id".to_owned(), "value".to_owned()]);
}

#[tokio::test]
async fn a_replayed_or_changed_cursor_is_refused() {
    let (app, backend) = setup();
    put_text(&backend, "first.csv", b"id,name\n1,one\n2,two\n", "text/csv");
    put_text(&backend, "second.csv", b"id,name\n3,three\n4,four\n", "text/csv");

    let first = get(&app, "/api/delimited?instance=rw&key=first.csv&pageSize=1")
        .await
        .decode::<DelimitedPage>();
    assert!(!first.next_cursor.is_empty(), "the first page did not return a cursor");

    for (name, cursor, key) in [
        ("tampered", mutate_cursor(&first.next_cursor), "first.csv"),
        ("replayed", first.next_cursor.clone(), "second.csv"),
    ] {
        let url = format!(
            "/api/delimited?instance=rw&key={key}&pageSize=1&cursor={}",
            escape(&cursor)
        );
        let called = get(&app, &url).await;
        assert_eq!(called.status, 400, "{name}: {}", called.text());
        assert_eq!(called.code(), "invalid_cursor", "{name}");
    }
}

#[tokio::test]
async fn a_csv_with_quotes_has_the_columns_of_its_header() {
    let (app, backend) = setup();
    put_text(
        &backend,
        "q.csv",
        b"id,\"note, long\",id,\n1,\"line one\nline two\",x,y\n\n   ,  ,,\n2,\"say \"\"hi\"\"\"\n3,a,b,c,d,e\n",
        "text/csv",
    );
    let page = get(&app, "/api/delimited?instance=rw&key=q.csv")
        .await
        .decode::<DelimitedPage>();
    assert_eq!(
        page.headers,
        ["id", "note, long", "id_2", "column_4", "column_5", "column_6"]
    );
    assert_eq!(page.row_numbers, vec![2, 4, 5]);
    assert_eq!(page.rows[0], ["1", "line one\nline two", "x", "y", "", ""]);
    assert_eq!(page.rows[1], ["2", "say \"hi\"", "", "", "", ""]);
    assert_eq!(page.rows[2], ["3", "a", "b", "c", "d", "e"]);
    assert!(page.done && page.next_cursor.is_empty());
    assert_eq!((page.start_row, page.end_row), (2, 5));
}

#[tokio::test]
async fn a_semicolon_file_is_detected_and_the_delimiter_kept_in_the_cursor() {
    let (app, backend) = setup();
    put_text(&backend, "semi.csv", b"a;b;c\n1;2;3\n4;5;6\n7;8;9\n", "text/csv");
    let first = get(&app, "/api/delimited?instance=rw&key=semi.csv&pageSize=1")
        .await
        .decode::<DelimitedPage>();
    assert_eq!(first.delimiter, ";");
    assert_eq!(first.headers, ["a", "b", "c"]);
    let url = format!(
        "/api/delimited?instance=rw&key=semi.csv&pageSize=5&cursor={}",
        escape(&first.next_cursor)
    );
    let second = get(&app, &url).await.decode::<DelimitedPage>();
    assert_eq!(second.delimiter, ";");
    assert_eq!(second.row_numbers, vec![3, 4]);
    assert_eq!(second.rows[0], ["4", "5", "6"]);
}

#[tokio::test]
async fn a_cell_and_the_columns_are_cut_at_their_limits() {
    let (app, backend) = setup();
    let mut header = String::new();
    let mut row = String::new();
    for index in 0..(MAX_COLUMNS + 5) {
        header.push_str(&format!("h{index},"));
        row.push_str("v,");
    }
    let big = "é".repeat(MAX_CELL_BYTES);
    let text = format!("{header}\n{big}{row}\n");
    put_text(&backend, "wide.csv", text.as_bytes(), "text/csv");
    let page = get(&app, "/api/delimited?instance=rw&key=wide.csv")
        .await
        .decode::<DelimitedPage>();
    assert!(page.truncated_columns && page.truncated_cells, "{:?}", page.row_numbers);
    assert_eq!(page.headers.len(), MAX_COLUMNS);
    assert_eq!(page.rows[0].len(), MAX_COLUMNS);
    assert!(page.rows[0][0].ends_with('…') && page.rows[0][0].len() <= MAX_CELL_BYTES + 3);
}

#[tokio::test]
async fn an_empty_object_gives_one_empty_page_and_a_bad_quote_gives_422() {
    let (app, backend) = setup();
    put_text(&backend, "empty.csv", b"", "text/csv");
    let called = get(&app, "/api/delimited?instance=rw&key=empty.csv").await;
    let json = called.json();
    assert_eq!(json["rows"], serde_json::json!([]));
    assert_eq!(json["rowNumbers"], serde_json::json!([]));
    assert_eq!(
        (json["done"].clone(), json["delimiter"].clone()),
        (true.into(), ",".into())
    );
    assert_eq!(json["startRow"], 0);

    put_text(&backend, "bare.csv", b"a,b\n1,x\"y\n", "text/csv");
    let called = get(&app, "/api/delimited?instance=rw&key=bare.csv").await;
    assert_eq!((called.status, called.code().as_str()), (422, "invalid_delimited_file"));
    assert_eq!(
        called.message(),
        "CSV error on line 2, column 4: a quote in a field that does not start with a quote"
    );

    put_text(&backend, "open.csv", b"a,b\n1,\"x\ny\n", "text/csv");
    let called = get(&app, "/api/delimited?instance=rw&key=open.csv").await;
    assert_eq!(called.status, 422);
    assert_eq!(
        called.message(),
        "CSV error on line 3, column 3, in the record that starts on line 2: a quote is missing or extra in a quoted field"
    );
}

#[tokio::test]
async fn the_count_of_a_document_depends_on_its_type() {
    let (app, backend) = setup();
    put_text(&backend, "t.csv", b"a,b\n1,\n2,x\n\n", "text/csv");
    put_text(&backend, "l.json", b"{\n}\n{", "application/json");
    put_text(&backend, "n.txt", b"x", "text/plain");
    let csv = get(&app, "/api/document-count?instance=rw&key=t.csv")
        .await
        .decode::<DocumentCount>();
    assert_eq!((csv.rows, csv.columns), (2, 2));
    let lines = get(&app, "/api/document-count?instance=rw&key=l.json").await.json();
    assert_eq!(
        (lines["kind"].clone(), lines["lines"].clone()),
        ("lines".into(), 3.into())
    );
    let called = get(&app, "/api/document-count?instance=rw&key=n.txt").await;
    assert_eq!((called.status, called.code().as_str()), (400, "unsupported_count"));
    let called = get(&app, "/api/document-count?instance=rw").await;
    assert_eq!(
        (called.status, called.message().as_str()),
        (400, "object key cannot be empty")
    );
}

#[test]
fn the_delimiter_is_the_one_with_the_most_regular_records() {
    assert_eq!(detect_delimited_separator(b"a,b,c\n1,2,3\n"), b',');
    assert_eq!(detect_delimited_separator(b"a;b;c\n1;2;3\n"), b';');
    assert_eq!(detect_delimited_separator(b"a\tb\n1\t2\n3\t4\n"), b'\t');
    assert_eq!(detect_delimited_separator(b"a|b|c\n1|2|3\n"), b'|');
    assert_eq!(detect_delimited_separator(b"just text\nno delimiter\n"), b',');
    assert_eq!(detect_delimited_separator(b"\"a;b\",c\n\"d;e\",f\n"), b',');
    assert_eq!(delimiter_for_object("x.psv", b"a,b\n"), b'|');
    assert_eq!(delimiter_for_object("x.TAB", b"a,b\n"), b'\t');
    assert_eq!(delimiter_for_object("x.csv", b"a;b\n"), b';');
}

async fn records(text: &[u8], comma: u8) -> Vec<Result<Vec<String>, String>> {
    let mut stream = ObjectStream::memory(vec![Bytes::copy_from_slice(text)]);
    let mut parser = CsvReader::new(&mut stream, comma);
    let mut out = Vec::new();
    loop {
        match parser.read().await {
            Ok(Some(record)) => out.push(Ok(record.iter().map(|field| lossy_bytes(field)).collect())),
            Ok(None) => return out,
            Err(CsvFailure::Parse(message)) => {
                out.push(Err(message));
                return out;
            }
            Err(CsvFailure::Source(error)) => panic!("{error}"),
        }
    }
}

#[tokio::test]
async fn the_reader_of_records_follows_its_rules() {
    let ok = |values: &[&str]| Ok(values.iter().map(|value| (*value).to_owned()).collect::<Vec<_>>());
    assert_eq!(
        records(b"a,b\r\nc,d\r\n", b',').await,
        [ok(&["a", "b"]), ok(&["c", "d"])]
    );
    assert_eq!(records(b"a,b\n\n\nc", b',').await, [ok(&["a", "b"]), ok(&["c"])]);
    assert_eq!(records(b"a,\"b\r\nc\",d\n", b',').await, [ok(&["a", "b\nc", "d"])]);
    assert_eq!(records(b"\"\"\"x\"\"\",y\n", b',').await, [ok(&["\"x\"", "y"])]);
    assert_eq!(records(b"a;;c\n", b';').await, [ok(&["a", "", "c"])]);
    assert_eq!(records(b"a\r", b',').await, [ok(&["a"])]);
    assert_eq!(records(b"", b',').await, Vec::<Result<Vec<String>, String>>::new());
    assert_eq!(
        records(b"a\n\"b\"c\n", b',').await,
        [
            ok(&["a"]),
            Err("CSV error on line 2, column 3: a quote is missing or extra in a quoted field".to_owned())
        ]
    );
    assert_eq!(
        records(b"a,\"b", b',').await,
        [Err(
            "CSV error on line 1, column 5: a quote is missing or extra in a quoted field".to_owned()
        )]
    );
}

#[tokio::test]
async fn the_reader_counts_the_bytes_that_it_took() {
    let mut stream = ObjectStream::memory(vec![Bytes::from_static(b"a,b\r\nc,d\n\ne,f")]);
    let mut parser = CsvReader::new(&mut stream, b',');
    let mut offsets = Vec::new();
    while parser.read().await.unwrap().is_some() {
        offsets.push(parser.input_offset());
    }
    assert_eq!(offsets, [5, 9, 13]);
    assert_eq!(parser.input_offset(), 13);
}
