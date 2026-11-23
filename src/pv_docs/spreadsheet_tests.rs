// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tests of the preview of workbooks.

use std::io::Cursor;

use super::*;
use crate::pv_docs::test_support::{escape, get, put, setup, test_workbook, zip_bytes};

const SHEET_TYPE: &str = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet";

#[tokio::test]
async fn the_preview_filters_and_pages_on_the_server() {
    let (app, backend) = setup();
    put(&backend, "book.xlsx", test_workbook(), SHEET_TYPE);

    let filters = escape(r#"{"A":"=beta"}"#);
    let url = format!("/api/spreadsheet?instance=rw&key=book.xlsx&sheet=0&page=0&pageSize=50&filters={filters}");
    let response = get(&app, &url).await.decode::<SheetPage>();
    assert!(
        response.sheets.len() == 2 && response.sheets[1].hidden == "hidden",
        "{:?}",
        response.sheets
    );
    assert_eq!(response.headers, ["A", "B"]);
    assert_eq!((response.source_rows, response.total_rows), (3, 1));
    assert!(
        response.rows.len() == 1 && response.rows[0].number == 4,
        "{:?}",
        response.rows
    );
    assert_eq!(response.rows[0].cells, ["beta", "20"]);
    assert_eq!((response.instance.as_str(), response.key.as_str()), ("rw", "book.xlsx"));
    assert_eq!(response.sheet.name, "Data");
    assert!(!response.macros_ignored);
}

#[tokio::test]
async fn the_preview_marks_the_macros_of_an_xlsm_as_ignored() {
    let (app, backend) = setup();
    put(
        &backend,
        "book.xlsm",
        test_workbook(),
        "application/vnd.ms-excel.sheet.macroEnabled.12",
    );
    let response = get(&app, "/api/spreadsheet?instance=rw&key=book.xlsm")
        .await
        .decode::<SheetPage>();
    assert!(response.macros_ignored);
}

fn counts(backend: &crate::testkit::MemoryBackend) -> (usize, usize) {
    let state = backend.state();
    (state.get_count, state.head_count)
}

#[tokio::test]
async fn the_preview_has_no_cache_between_requests() {
    let (app, backend) = setup();
    let workbook = test_workbook();
    let size = workbook.len();
    put(&backend, "book.xlsx", workbook, SHEET_TYPE);
    let url = format!("/api/spreadsheet?instance=rw&key=book.xlsx&size={size}");

    assert_eq!(get(&app, &url).await.status, 200);
    let (first_gets, first_heads) = counts(&backend);
    assert_eq!(get(&app, &url).await.status, 200);
    let (second_gets, second_heads) = counts(&backend);
    assert!(
        first_gets > 0 && second_gets > first_gets && first_heads == 0 && second_heads == 0,
        "first GET/HEAD = {first_gets}/{first_heads}, second = {second_gets}/{second_heads}"
    );
}

#[tokio::test]
async fn the_preview_reads_a_workbook_that_has_a_size_that_nobody_gave() {
    let (app, backend) = setup();
    put(&backend, "book.xlsx", test_workbook(), SHEET_TYPE);
    let response = get(&app, "/api/spreadsheet?instance=rw&key=book.xlsx&sheet=1")
        .await
        .decode::<SheetPage>();
    assert_eq!((response.sheet.name.as_str(), response.rows.len()), ("Archive", 1));
    assert_eq!(response.rows[0].cells, ["archived"]);
}

async fn error_of(app: &std::sync::Arc<crate::common::app::App>, path: &str) -> (u16, String, String) {
    let called = get(app, path).await;
    (called.status, called.code(), called.message())
}

#[tokio::test]
async fn a_text_object_with_the_extension_xlsx_is_explained() {
    let (app, backend) = setup();
    let contents = b"this object is plain text, not an Office package";
    put(&backend, "not-really.xlsx", contents.to_vec(), "text/plain");
    let (status, code, message) = error_of(
        &app,
        &format!(
            "/api/spreadsheet?instance=rw&key=not-really.xlsx&size={}",
            contents.len()
        ),
    )
    .await;
    assert_eq!((status, code.as_str()), (422, "invalid_workbook_container"));
    assert!(message.contains("extension says XLSX/XLSM"), "{message}");
}

#[tokio::test]
async fn a_binary_xls_with_the_extension_xlsx_is_explained() {
    let (app, backend) = setup();
    let mut contents = BINARY_EXCEL_SIGNATURE.to_vec();
    contents.extend_from_slice(&[0; 64]);
    put(
        &backend,
        "binary-xls.xlsx",
        contents.clone(),
        "application/vnd.ms-excel",
    );
    let (status, code, message) = error_of(
        &app,
        &format!(
            "/api/spreadsheet?instance=rw&key=binary-xls.xlsx&size={}",
            contents.len()
        ),
    )
    .await;
    assert_eq!((status, code.as_str()), (422, "unsupported_xls_container"));
    assert!(message.contains("binary XLS format"), "{message}");
}

#[tokio::test]
async fn a_corrupt_office_zip_is_explained() {
    let (app, backend) = setup();
    let contents = vec![b'P', b'K', 3, 4, 0, 0, 0, 0, 1, 2, 3, 4];
    put(&backend, "corrupt.xlsx", contents.clone(), SHEET_TYPE);
    let (status, code, message) = error_of(
        &app,
        &format!("/api/spreadsheet?instance=rw&key=corrupt.xlsx&size={}", contents.len()),
    )
    .await;
    assert_eq!((status, code.as_str()), (422, "invalid_workbook_package"));
    assert!(message.contains("central directory"), "{message}");
}

#[tokio::test]
async fn the_route_checks_its_parameters_and_the_parts_of_the_workbook() {
    let (app, backend) = setup();
    put(&backend, "book.xlsx", test_workbook(), SHEET_TYPE);
    put(&backend, "book.csv", b"a,b\n".to_vec(), "text/csv");
    put(
        &backend,
        "nosheets.xlsx",
        zip_bytes(
            &[
                ("xl/workbook.xml", "<workbook><sheets/></workbook>"),
                ("xl/_rels/workbook.xml.rels", "<Relationships/>"),
            ],
            false,
        ),
        SHEET_TYPE,
    );
    put(
        &backend,
        "noindex.xlsx",
        zip_bytes(&[("a.txt", "x")], false),
        SHEET_TYPE,
    );
    put(
        &backend,
        "badstyles.xlsx",
        zip_bytes(
            &[
                (
                    "xl/workbook.xml",
                    r#"<workbook xmlns:r="r"><sheets><sheet name="S" r:id="rId1"/></sheets></workbook>"#,
                ),
                (
                    "xl/_rels/workbook.xml.rels",
                    r#"<Relationships><Relationship Id="rId1" Target="/xl/worksheets/s.xml"/></Relationships>"#,
                ),
                ("xl/worksheets/s.xml", "<worksheet/>"),
                (
                    "xl/styles.xml",
                    "<styleSheet><cellXfs><xf numFmtId=\"x\"/></cellXfs></styleSheet>",
                ),
            ],
            false,
        ),
        SHEET_TYPE,
    );
    for (target, status, code) in [
        ("/api/spreadsheet?instance=rw&key=", 400, "invalid_key"),
        (
            "/api/spreadsheet?instance=rw&key=book.csv",
            400,
            "unsupported_spreadsheet",
        ),
        (
            "/api/spreadsheet?instance=rw&key=book.xlsx&search=%20"
                .to_owned()
                .as_str(),
            200,
            "",
        ),
        (
            "/api/spreadsheet?instance=rw&key=book.xlsx&filters=%5B%5D",
            400,
            "invalid_filters",
        ),
        (
            "/api/spreadsheet?instance=rw&key=book.xlsx&filters=%7B%22%31%22%3A%22x%22%7D",
            400,
            "invalid_filter_column",
        ),
        (
            "/api/spreadsheet?instance=rw&key=book.xlsx&sortColumn=1",
            400,
            "invalid_sort_column",
        ),
        (
            "/api/spreadsheet?instance=rw&key=book.xlsx&sortColumn=A&sortDirection=up",
            400,
            "invalid_sort_direction",
        ),
        ("/api/spreadsheet?instance=rw&key=nosheets.xlsx", 422, "empty_workbook"),
        ("/api/spreadsheet?instance=rw&key=noindex.xlsx", 422, "invalid_workbook"),
        ("/api/spreadsheet?instance=rw&key=badstyles.xlsx", 422, "invalid_styles"),
        ("/api/spreadsheet?instance=rw&key=missing.xlsx", 404, ""),
    ] {
        let called = get(&app, target).await;
        assert_eq!(called.status, status, "{target}: {}", called.text());
        if !code.is_empty() {
            assert_eq!(called.code(), code, "{target}");
        }
    }
    let long = "x".repeat(1025);
    let called = get(
        &app,
        &format!("/api/spreadsheet?instance=rw&key=book.xlsx&search={long}"),
    )
    .await;
    assert_eq!((called.status, called.code().as_str()), (400, "search_query_too_long"));
    let size = get(&app, "/api/spreadsheet?instance=rw&key=book.xlsx&sheet=9")
        .await
        .decode::<SheetPage>();
    assert_eq!(
        size.sheet.name, "Archive",
        "a sheet number above the last one is the last sheet"
    );
}

#[tokio::test]
async fn a_sort_and_a_search_use_the_values_of_the_cells() {
    let (app, backend) = setup();
    put(&backend, "book.xlsx", test_workbook(), SHEET_TYPE);
    let descending = get(
        &app,
        "/api/spreadsheet?instance=rw&key=book.xlsx&sortColumn=B&sortDirection=desc",
    )
    .await
    .decode::<SheetPage>();
    let numbers: Vec<&str> = descending.rows.iter().map(|row| row.cells[1].as_str()).collect();
    assert_eq!(numbers, ["20", "10", "3"]);
    let found = get(&app, "/api/spreadsheet?instance=rw&key=book.xlsx&search=GAM")
        .await
        .decode::<SheetPage>();
    assert_eq!((found.total_rows, found.rows[0].number), (1, 5));
    let second_page = get(&app, "/api/spreadsheet?instance=rw&key=book.xlsx&pageSize=2&page=1")
        .await
        .decode::<SheetPage>();
    assert_eq!(
        (second_page.rows.len(), second_page.total_rows, second_page.page),
        (1, 3, 1)
    );
}

fn read_test_sheet(cancel: &CancelToken, sheet_xml: &str, shared: &[Arc<str>], page_size: usize) -> Result<SheetPage> {
    let sheets = vec![SheetInfo {
        name: "Sheet1".to_owned(),
        ..SheetInfo::default()
    }];
    let query = SheetQuery {
        page_size,
        ..SheetQuery::default()
    };
    read_spreadsheet_sheet(
        cancel,
        &mut Cursor::new(sheet_xml.as_bytes().to_vec()),
        &sheets,
        0,
        shared,
        &Styles::default(),
        &query,
    )
}

fn aliased_sheet_xml(rows: usize, columns: usize) -> String {
    let mut builder = String::from("<worksheet><sheetData>");
    for row in 1..=rows {
        builder.push_str(&format!("<row r=\"{row}\">"));
        for _ in 0..columns {
            builder.push_str("<c t=\"s\"><v>0</v></c>");
        }
        builder.push_str("</row>");
    }
    builder.push_str("</sheetData></worksheet>");
    builder
}

#[test]
fn a_sheet_caps_the_cell_and_the_page() {
    let shared: Vec<Arc<str>> = vec![Arc::from("a".repeat(64 << 10))];
    let response = read_test_sheet(&CancelToken::new(), &aliased_sheet_xml(10, 2), &shared, 10).unwrap();
    assert!(response.truncated_cells);
    assert_eq!(response.rows[0].cells[0].len(), MAX_CELL_BYTES);
    let error = read_test_sheet(&CancelToken::new(), &aliased_sheet_xml(1000, 2), &shared, 1000).unwrap_err();
    let api = error.as_api().unwrap();
    assert_eq!((api.status, api.code.as_str()), (413, "spreadsheet_page_too_large"));
}

#[test]
fn a_sheet_charges_each_reference_to_a_shared_string() {
    let shared: Vec<Arc<str>> = vec![Arc::from("a".repeat(64 << 10))];
    // 40 000 references to one string are far below the cap of the distinct entries, and above the budget of the
    // references of a sheet.
    let error = read_test_sheet(&CancelToken::new(), &aliased_sheet_xml(200, 200), &shared, 1).unwrap_err();
    assert!(error.has_code("sheet_expansion_too_large"), "{error:?}");
}

#[test]
fn a_sheet_counts_the_empty_rows_and_honours_the_cancellation() {
    let empty = format!(
        "<worksheet><sheetData>{}</sheetData></worksheet>",
        "<row/>".repeat(MAX_ROWS + 1)
    );
    let response = read_test_sheet(&CancelToken::new(), &empty, &[], 10).unwrap();
    assert!(response.truncated_rows && response.source_rows == 0);
    let canceled = CancelToken::new();
    canceled.cancel();
    let short = format!(
        "<worksheet><sheetData>{}</sheetData></worksheet>",
        "<row/>".repeat(5 * usize::try_from(CANCEL_CHECK_EVERY).unwrap())
    );
    let error = read_test_sheet(&canceled, &short, &[], 10).unwrap_err();
    assert!(matches!(error, Error::Canceled), "{error:?}");
}

#[test]
fn a_sheet_that_is_not_xml_gives_422() {
    let error = read_test_sheet(&CancelToken::new(), "<worksheet><row>", &[], 10).unwrap_err();
    let api = error.as_api().unwrap();
    assert_eq!((api.status, api.code.as_str()), (422, "invalid_sheet"));
}

#[test]
fn the_cells_have_their_types_and_dates() {
    let xml = r#"<worksheet><sheetData>
<row r="3"><c r="B3" t="b"><v>1</v></c><c t="b"><v>0</v></c><c r="D3" t="e"/><c r="E3" t="e"><v>#N/A</v></c>
<c r="F3" s="1"><v>45000</v></c><c r="G3" s="1"><v>45000.5</v></c><c r="H3" s="1"><v>text</v></c>
<c r="I3" t="inlineStr"><is><r><t>in</t></r><r><t>line</t></r></is></c><c r="J3" t="d"><v> 2024-01-02 </v></c></row>
</sheetData></worksheet>"#;
    let styles = Styles {
        date_styles: [1].into_iter().collect(),
    };
    let sheets = vec![SheetInfo::default()];
    let page = read_spreadsheet_sheet(
        &CancelToken::new(),
        &mut Cursor::new(xml.as_bytes().to_vec()),
        &sheets,
        0,
        &[],
        &styles,
        &SheetQuery::default(),
    )
    .unwrap();
    assert_eq!(page.headers, ["B", "C", "D", "E", "F", "G", "H", "I", "J"]);
    assert_eq!(
        page.rows[0].cells,
        [
            "TRUE",
            "FALSE",
            "#ERROR",
            "#N/A",
            "2023-03-15",
            "2023-03-15T12:00:00Z",
            "text",
            "inline",
            "2024-01-02"
        ]
    );
    assert_eq!(page.rows[0].number, 3);
}

#[test]
fn the_names_of_the_columns_match_their_indexes() {
    for (name, index) in [
        ("A", 0),
        ("Z", 25),
        ("AA", 26),
        ("AZ", 51),
        ("BA", 52),
        ("ZZ", 701),
        ("AAA", 702),
    ] {
        assert_eq!(excel_column_index(name), Some(index), "{name}");
        assert_eq!(excel_column_name(index), name);
    }
    assert_eq!(excel_column_index(" b2 "), Some(1));
    assert_eq!(excel_column_index("1A"), None);
    assert_eq!(excel_column_index(""), None);
    assert_eq!(excel_column_name(-1), "");
}

#[test]
fn the_values_are_compared_as_numbers_times_or_text() {
    use std::cmp::Ordering::{Equal, Greater, Less};
    assert_eq!(compare_values("10", "9"), Greater);
    assert_eq!(compare_values("-1", "1e0"), Less);
    assert_eq!(compare_values(" 2 ", "2"), Equal);
    assert_eq!(compare_values("", ""), Equal);
    assert_eq!(compare_values("", "a"), Greater);
    assert_eq!(compare_values("a", ""), Less);
    assert_eq!(compare_values("Beta", "alpha"), Greater);
    assert_eq!(compare_values("ABC", "abc"), Equal);
    assert_eq!(
        compare_values("2024-01-02T10:00:00Z", "2024-01-02T11:00:00+02:00"),
        Greater
    );
    assert_eq!(compare_values("9", "abc"), Less);
}

#[test]
fn a_filter_has_an_operator_and_an_operand() {
    assert!(matches_filter("Alpha", "lph"));
    assert!(matches_filter("5", ">=5"));
    assert!(matches_filter("5", "<= 6"));
    assert!(!matches_filter("5", "!=5"));
    assert!(matches_filter("beta", "=BETA"));
    assert!(matches_filter("7", ">6"));
    assert!(!matches_filter("7", "<7"));
    assert!(matches_filter("anything", "  "));
    assert!(matches_filter("", "="));
}

#[test]
fn the_serial_dates_have_the_epoch_of_the_workbooks() {
    assert_eq!(format_serial_date(1.0), "1899-12-31");
    assert_eq!(format_serial_date(60.0), "1900-02-28");
    assert_eq!(format_serial_date(45000.0), "2023-03-15");
    assert_eq!(format_serial_date(45000.25), "2023-03-15T06:00:00Z");
    assert_eq!(format_serial_date(0.0), "1899-12-30");
}

#[test]
fn the_formats_of_dates_are_found_by_their_code() {
    assert!(is_date_number_format(14, ""));
    assert!(is_date_number_format(164, "yyyy-mm-dd"));
    assert!(is_date_number_format(165, "[$-409]hh:mm:ss"));
    assert!(is_date_number_format(166, "m/d/yy"));
    assert!(!is_date_number_format(167, "0.00"));
    assert!(!is_date_number_format(168, "\"day\"0"));
    assert!(!is_date_number_format(169, "[Red]0.0"));
    assert!(!is_date_number_format(170, ""));
}
