//! The tests of the counts.

use std::io::Cursor;

use super::*;
use crate::pv_docs::test_support::{get, put, setup, test_workbook};

fn dimensions(xml: &str) -> Result<(i64, i64)> {
    count_worksheet_dimensions(&mut Cursor::new(xml.as_bytes().to_vec()))
}

#[test]
fn the_dimensions_of_a_sheet_are_the_last_row_and_column_with_a_value() {
    let xml = r#"<worksheet><sheetData>
<row r="2"><c r="A2"><v>1</v></c><c r="C2"><f>A2</f></c></row>
<row r="3"><c r="A3"><v> </v></c></row>
<row><c r="B1" t="inlineStr"><is><t>x</t></is></c></row>
<row r="10"><c r="A10"/></row>
</sheetData></worksheet>"#;
    // The row without a number follows the row 3: it is the row 4.
    assert_eq!(dimensions(xml).unwrap(), (4, 3));
    assert_eq!(dimensions("<worksheet/>").unwrap(), (0, 0));
    let error = dimensions("<worksheet><row>").unwrap_err();
    assert!(error.has_code("invalid_sheet"));
}

#[test]
fn the_counter_of_delimited_text_keeps_one_flag_for_each_column() {
    let count = |text: &str, delimiter: u8| {
        let mut counter = DelimitedCounter::new(delimiter);
        counter.feed(text.as_bytes());
        counter.finish()
    };
    assert_eq!(count("a,b\n1,\n2,x\n\n", b',').unwrap(), (2, 2));
    assert_eq!(count("a,b\r\n1,2\r\n", b',').unwrap(), (1, 2));
    assert_eq!(count("a\tb", b'\t').unwrap(), (0, 2));
    assert_eq!(count("", b',').unwrap(), (0, 0));
    assert_eq!(count("a,b\n\"x\ny\",\"\"\n", b',').unwrap(), (1, 2));
    assert!(count("a,\"b", b',').unwrap_err().has_code("invalid_delimited_file"));
    let mut counter = DelimitedCounter::new(b',');
    counter.feed(b"a,b\r");
    counter.feed(b"\n1,2\n");
    assert_eq!(counter.finish().unwrap(), (1, 2));
}

#[tokio::test]
async fn the_dimensions_of_the_active_sheet_come_from_a_scan_of_the_sheet() {
    let (app, backend) = setup();
    put(&backend, "book.xlsx", test_workbook(), "application/octet-stream");
    let instance = app.instance("rw").unwrap().clone();
    let summary = inspect_spreadsheet_dimensions(&OpCtx::default(), &instance, "book.xlsx", 0)
        .await
        .unwrap();
    assert_eq!(
        (
            summary.sheets,
            summary.active_sheet.as_str(),
            summary.rows,
            summary.columns
        ),
        (2, "Data", 5, 2)
    );
    let (details, headers, size) = inspect_spreadsheet_summary(&OpCtx::default(), &instance, "book.xlsx", 0)
        .await
        .unwrap();
    assert_eq!(
        (details.sheets, details.active_sheet.as_str(), details.rows),
        (2, "Data", 0)
    );
    assert!(size > 0 && !headers.is_empty());

    let called = get(&app, "/api/document-count?instance=rw&key=book.xlsx").await;
    let json = called.json();
    assert_eq!(json["kind"], "spreadsheet");
    assert_eq!(
        (json["sheet"].clone(), json["rows"].clone(), json["columns"].clone()),
        ("Data".into(), 5.into(), 2.into())
    );
}

#[tokio::test]
async fn the_count_of_lines_counts_the_last_line_without_a_line_end() {
    let (app, backend) = setup();
    put(&backend, "a.json", b"1\n2\n3".to_vec(), "application/json");
    put(&backend, "b.geojson", b"1\n2\n".to_vec(), "application/json");
    put(&backend, "c.json", Vec::<u8>::new(), "application/json");
    let instance = app.instance("rw").unwrap().clone();
    let ctx = OpCtx::default();
    assert_eq!(count_object_lines(&ctx, &instance, "a.json").await.unwrap().lines, 3);
    let second = count_object_lines(&ctx, &instance, "b.geojson").await.unwrap();
    assert_eq!((second.lines, second.total), (2, 4));
    assert_eq!(count_object_lines(&ctx, &instance, "c.json").await.unwrap().lines, 0);
    let summary = inspect_delimited_summary(&ctx, &instance, "a.json", "csv")
        .await
        .unwrap();
    assert_eq!(summary.total, 5);
}
