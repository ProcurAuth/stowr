//! The tests of the document details, of the Parquet reader, of the Thrift reader and of the counts that the details
//! share with `crate::pv_docs::count`, and the helpers of the route tests of this folder.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Method};

use super::details::text_container_label;
use super::inspect_document_details;
use super::parquet::{flatten_schema, parse_file_metadata, parse_metadata_detail};
use super::thrift::{CompactReader, LIST, STRUCT};
use crate::access::AccessLayer;
use crate::archive::zip::writer::{EntryHeader, ZipWriter};
use crate::common::app::App;
use crate::common::config::{Config, PERMISSION_READ};
use crate::common::ctx::OpCtx;
use crate::common::http::{Req, Response, empty, full, read_limited};
use crate::common::query::Query;
use crate::instance::Instance;
use crate::pv_docs::count::{
    count_object_lines, count_worksheet_dimensions, inspect_delimited_summary, inspect_spreadsheet_dimensions,
    inspect_spreadsheet_summary,
};
use crate::pv_media::MediaSourceMetadata;
use crate::testkit::{MemoryBackend, bucket_config, instance_over};

/// An instance over a new memory back end, with the permission `read`.
pub(crate) fn memory_instance(id: &str) -> (Arc<Instance>, Arc<MemoryBackend>) {
    let backend = Arc::new(MemoryBackend::new());
    let instance = Arc::new(instance_over(
        bucket_config(id, "", &[PERMISSION_READ]),
        backend.clone(),
    ));
    (instance, backend)
}

/// An application over instances, in the mode `open`.
pub(crate) fn application(instances: Vec<Arc<Instance>>) -> Arc<App> {
    let config = Config::default();
    let access = AccessLayer::new(&config).unwrap();
    Arc::new(App {
        config: Arc::new(config),
        instances,
        auths: BTreeMap::new(),
        jobs: crate::jobs::JobManager::default(),
        uploads: crate::uploads::UploadManager::new(),
        sqlite: super::SqliteSessions::new(),
        access,
        resume_token_key: [0; 32],
    })
}

/// The answer of a call: the status, the headers and the body as text.
pub(crate) struct Called {
    pub(crate) status: u16,
    pub(crate) headers: HeaderMap,
    pub(crate) text: String,
}

impl Called {
    /// The body as JSON.
    pub(crate) fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.text).unwrap_or(serde_json::Value::Null)
    }

    /// The code of the error object, or an empty text.
    pub(crate) fn code(&self) -> String {
        self.json()["error"]["code"].as_str().unwrap_or("").to_owned()
    }
}

/// Call a route of this folder with a method, a target and an optional JSON body.
pub(crate) async fn call(app: &Arc<App>, method: &str, target: &str, body: Option<serde_json::Value>) -> Called {
    let (path, raw_query) = target.split_once('?').unwrap_or((target, ""));
    let request = Req {
        method: Method::from_bytes(method.as_bytes()).unwrap(),
        path: path.to_owned(),
        raw_query: raw_query.to_owned(),
        query: Query::parse(raw_query),
        headers: HeaderMap::new(),
        body: body.map_or_else(empty, |value| full(Bytes::from(value.to_string()))),
        ctx: OpCtx::default(),
        host: "localhost".to_owned(),
    };
    let handler = if path == "/api/parquet" {
        super::handle_parquet
    } else if path.starts_with("/api/sqlite/sessions") {
        super::handle_sqlite_sessions
    } else {
        panic!("no route {path}")
    };
    let response: Response = handler(Arc::clone(app), request).await;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let (bytes, _) = read_limited(response.into_body(), usize::MAX).await.unwrap();
    Called {
        status,
        headers,
        text: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

/// What the listing tells about an object of a test: its size.
fn listed(size: usize) -> MediaSourceMetadata {
    MediaSourceMetadata {
        size: size as i64,
        ..MediaSourceMetadata::default()
    }
}

/// The bytes of a ZIP archive with these entries.
fn zip_of(entries: &[(&str, &str)]) -> Bytes {
    let mut writer = ZipWriter::new();
    let mut out = Vec::new();
    for (name, content) in entries {
        writer
            .create(&EntryHeader {
                name: (*name).to_owned(),
                ..EntryHeader::default()
            })
            .unwrap();
        writer.write(Bytes::from(content.to_string())).unwrap();
    }
    writer.finish().unwrap();
    for chunk in writer.take_output() {
        out.extend_from_slice(&chunk);
    }
    Bytes::from(out)
}

// --- Parquet and Thrift ------------------------------------------------------------------------------------------

#[test]
fn the_parquet_summary_reads_the_rows_and_the_top_level_columns() {
    // One root schema element with three children, and 123 rows, in the Thrift compact protocol.
    let metadata = [0x29, 0x1c, 0x55, 0x06, 0x00, 0x16, 0xf6, 0x01, 0x00];
    let summary = parse_file_metadata(&metadata).unwrap();
    assert_eq!((summary.rows, summary.columns), (123, 3));
}

#[tokio::test]
async fn the_thrift_skip_refuses_hostile_metadata() {
    let mut nested = vec![0x7c];
    nested.extend(std::iter::repeat_n(0x1c, 100_000));
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("a map of booleans", vec![0x7b, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x11]),
        ("a list of booleans", vec![0x79, 0xf1, 0x80, 0x80, 0x80, 0x80, 0x08]),
        (
            "a list larger than the data",
            vec![0x79, 0xfc, 0xff, 0xff, 0xff, 0x07, 0x1c],
        ),
        (
            "row groups of the stop type",
            vec![0x49, 0xf0, 0x80, 0x80, 0x80, 0x80, 0x08],
        ),
        ("deeply nested structures", nested),
    ];
    for (name, data) in cases {
        let parse = tokio::task::spawn_blocking(move || parse_metadata_detail(&data).is_err());
        let refused = tokio::time::timeout(Duration::from_secs(2), parse)
            .await
            .unwrap_or_else(|_| panic!("{name}: the parser did not return"))
            .unwrap();
        assert!(refused, "{name}: the reader accepts the hostile metadata");
    }
    let data = vec![0x1c; 200];
    let mut reader = CompactReader::new(&data);
    let error = reader.skip(STRUCT).err().unwrap();
    assert!(error.0.contains("nested too deeply"), "{error}");
    let data = [0x31, 0x01, 0x02, 0x01, 0x15, 0x04, 0x00];
    let mut reader = CompactReader::new(&data);
    reader.skip(LIST).unwrap();
    assert_eq!(reader.pos, 4, "a list of booleans keeps one byte for each element");
    reader.skip(STRUCT).unwrap();
    assert_eq!(reader.pos, data.len());
}

/// A writer of the Thrift compact protocol for the fixtures of the tests.
#[derive(Default)]
struct Compact {
    out: Vec<u8>,
    last: Vec<i16>,
}

impl Compact {
    fn varint(&mut self, mut value: u64) {
        while value >= 0x80 {
            self.out.push((value as u8) | 0x80);
            value >>= 7;
        }
        self.out.push(value as u8);
    }

    fn field(&mut self, id: i16, kind: u8) {
        let last = self.last.last().copied().unwrap_or(0);
        let delta = id - last;
        if (1..=15).contains(&delta) {
            self.out.push(((delta as u8) << 4) | kind);
        } else {
            self.out.push(kind);
            self.varint(((i64::from(id) << 1) ^ (i64::from(id) >> 63)) as u64);
        }
        if let Some(top) = self.last.last_mut() {
            *top = id;
        }
    }

    fn integer(&mut self, id: i16, kind: u8, value: i64) {
        self.field(id, kind);
        self.varint(((value << 1) ^ (value >> 63)) as u64);
    }

    fn binary(&mut self, id: i16, value: &str) {
        self.field(id, 8);
        self.varint(value.len() as u64);
        self.out.extend_from_slice(value.as_bytes());
    }

    fn list(&mut self, id: i16, size: usize, kind: u8) {
        self.field(id, LIST);
        self.out.push(((size as u8) << 4) | kind);
    }

    fn begin(&mut self) {
        self.last.push(0);
    }

    fn end(&mut self) {
        self.out.push(0);
        self.last.pop();
    }
}

/// The metadata of a small Parquet file: two columns `a` (INT64) and `b` (UTF8), five rows in one row group.
fn parquet_metadata() -> Vec<u8> {
    let mut writer = Compact::default();
    writer.begin();
    writer.integer(1, 5, 1);
    writer.list(2, 3, STRUCT);
    writer.begin();
    writer.binary(4, "schema");
    writer.integer(5, 5, 2);
    writer.end();
    writer.begin();
    writer.integer(1, 5, 2);
    writer.integer(3, 5, 0);
    writer.binary(4, "a");
    writer.end();
    writer.begin();
    writer.integer(1, 5, 6);
    writer.integer(3, 5, 1);
    writer.binary(4, " b ");
    writer.integer(6, 5, 0);
    writer.end();
    writer.integer(3, 6, 5);
    writer.list(4, 1, STRUCT);
    writer.begin();
    writer.list(1, 2, STRUCT);
    writer.begin();
    writer.end();
    writer.begin();
    writer.end();
    writer.integer(2, 6, 100);
    writer.integer(3, 6, 5);
    writer.end();
    writer.binary(6, "stowr test");
    writer.end();
    writer.out
}

fn parquet_file(metadata: &[u8]) -> Bytes {
    let mut file = b"PAR1".to_vec();
    file.extend_from_slice(&[0u8; 32]);
    file.extend_from_slice(metadata);
    file.extend_from_slice(&(metadata.len() as u32).to_le_bytes());
    file.extend_from_slice(b"PAR1");
    Bytes::from(file)
}

#[test]
fn the_schema_has_dotted_paths_and_a_flag_for_missing_fields() {
    let detail = parse_metadata_detail(&parquet_metadata()).unwrap();
    let (fields, truncated) = flatten_schema(&detail.schema);
    let fields = fields.unwrap();
    assert!(!truncated);
    assert_eq!(fields.len(), 2);
    assert_eq!(fields[1].path, "b");
    assert_eq!(fields[1].logical_type, "UTF8");
    let mut missing = detail.schema.clone();
    missing[0].children = 5;
    assert!(flatten_schema(&missing).1);
    assert_eq!(flatten_schema(&[]), (None, false));
}

#[tokio::test]
async fn the_parquet_route_gives_the_footer_metadata() {
    let (instance, backend) = memory_instance("data");
    let metadata = parquet_metadata();
    let file = parquet_file(&metadata);
    backend.insert("files/table.parquet", file.clone(), "application/octet-stream");
    let app = application(vec![instance]);
    let called = call(&app, "GET", "/api/parquet?instance=data&key=/files/table.parquet", None).await;
    assert_eq!(called.status, 200, "{}", called.text);
    let expected = serde_json::json!({
        "instance": "data",
        "key": "files/table.parquet",
        "version": 1,
        "rows": 5,
        "columns": 2,
        "createdBy": "stowr test",
        "schema": [
            {"path": "a", "name": "a", "physicalType": "INT64", "repetition": "REQUIRED"},
            {"path": "b", "name": "b", "physicalType": "BYTE_ARRAY", "logicalType": "UTF8", "repetition": "OPTIONAL"}
        ],
        "rowGroups": [{"index": 0, "rows": 5, "columns": 2, "uncompressedBytes": 100}],
        "rowGroupCount": 1,
        "metadataBytes": metadata.len(),
        "storageBytes": 8 + metadata.len(),
        "storageRequests": 2,
        "dataRowsDecoded": false
    });
    assert_eq!(called.json(), expected);
    assert!(
        backend
            .state()
            .get_ranges
            .iter()
            .all(|range| range.starts_with("bytes="))
    );

    let missing = call(&app, "GET", "/api/parquet?instance=data", None).await;
    assert_eq!((missing.status, missing.code()), (400, "missing_key".to_owned()));
    let size = call(&app, "GET", "/api/parquet?instance=data&key=x&size=-1", None).await;
    assert_eq!((size.status, size.code()), (400, "invalid_size".to_owned()));
    let method = call(&app, "POST", "/api/parquet?instance=data&key=x", None).await;
    assert_eq!(method.status, 405);
    assert_eq!(method.headers.get("allow").unwrap(), "GET");
    backend.insert("plain.parquet", Bytes::from_static(b"not a parquet file"), "");
    let invalid = call(&app, "GET", "/api/parquet?instance=data&key=plain.parquet", None).await;
    assert_eq!((invalid.status, invalid.code()), (422, "invalid_parquet".to_owned()));
    let mut broken = metadata.clone();
    broken.truncate(broken.len() - 4);
    backend.insert("broken.parquet", parquet_file(&broken), "");
    let broken = call(&app, "GET", "/api/parquet?instance=data&key=broken.parquet", None).await;
    assert_eq!(
        (broken.status, broken.code()),
        (422, "invalid_parquet_metadata".to_owned())
    );
    assert_eq!(broken.json()["error"]["message"], "unexpected EOF");
}

// --- Delimited text and lines ------------------------------------------------------------------------------------

#[tokio::test]
async fn the_details_of_delimited_text_wait_for_the_explicit_count() {
    let (instance, backend) = memory_instance("csv");
    let content = "first;second;empty\n1;2;\n3;4;\n";
    backend.insert("table.csv", content, "text/csv");
    let details = inspect_document_details(
        &OpCtx::default(),
        &instance,
        "table.csv",
        "csv",
        "text/csv",
        &listed(content.len()),
    )
    .await
    .unwrap();
    assert!(details.handled);
    assert_eq!(details.container, "CSV");
    assert!(details.properties.is_empty());
    let counts = {
        let state = backend.state();
        (state.get_count, state.head_count)
    };
    assert_eq!(counts, (0, 1), "the details read the object");
    let summary = inspect_delimited_summary(&OpCtx::default(), &instance, "table.csv", "csv")
        .await
        .unwrap();
    assert_eq!(
        (summary.rows, summary.columns, summary.total),
        (2, 3, content.len() as i64)
    );
}

#[tokio::test]
async fn the_details_of_tab_separated_text_accept_the_tab_extension_and_type() {
    let (instance, backend) = memory_instance("tsv");
    let content = "first\tsecond\n1\t2\n3\t4\n";
    backend.insert("table.tab", content, "text/tab-separated-values");
    let ctx = OpCtx::default();
    let details = inspect_document_details(
        &ctx,
        &instance,
        "table.tab",
        "tab",
        "text/tab-separated-values",
        &listed(content.len()),
    )
    .await
    .unwrap();
    assert!(details.handled);
    assert_eq!(details.container, "TSV");
    assert!(details.properties.is_empty());
    let counts = {
        let state = backend.state();
        (state.get_count, state.head_count)
    };
    assert_eq!(counts, (0, 1));
    backend.insert("noext", content, "text/tab-separated-values");
    let typed = inspect_document_details(
        &ctx,
        &instance,
        "noext",
        "",
        "text/tab-separated-values; charset=utf-8",
        &listed(0),
    )
    .await
    .unwrap();
    assert_eq!(typed.container, "TSV");
    let summary = inspect_delimited_summary(&ctx, &instance, "table.tab", "tab")
        .await
        .unwrap();
    assert_eq!((summary.rows, summary.columns), (2, 2));
}

#[tokio::test]
async fn the_line_count_counts_a_last_line_without_a_line_end() {
    let (instance, backend) = memory_instance("text");
    backend.insert("notes.txt", "one\ntwo\nthree", "text/plain");
    backend.insert("empty.txt", "", "text/plain");
    let ctx = OpCtx::default();
    let count = count_object_lines(&ctx, &instance, "notes.txt").await.unwrap();
    assert_eq!((count.lines, count.total), (3, 13));
    assert_eq!(count_object_lines(&ctx, &instance, "empty.txt").await.unwrap().lines, 0);
}

#[test]
fn the_text_labels_use_the_full_names_of_the_languages() {
    let cases = [
        ("js", "JavaScript"),
        ("mjs", "JavaScript module"),
        ("cjs", "CommonJS JavaScript"),
        ("jsx", "JavaScript XML"),
        ("ts", "TypeScript"),
        ("tsx", "TypeScript XML"),
        ("py", "Python"),
        ("rs", "Rust"),
        ("cpp", "C++"),
        ("cs", "C#"),
        ("fs", "F#"),
        ("hbs", "Handlebars"),
        ("vue", "Vue single-file component"),
        ("svg", "SVG"),
    ];
    for (extension, want) in cases {
        assert_eq!(
            text_container_label(&format!("example.{extension}"), extension, "text/plain"),
            want,
            "{extension}"
        );
    }
}

#[test]
fn the_text_labels_know_the_code_files_without_an_extension() {
    for (name, want) in [
        ("Dockerfile", "Dockerfile"),
        ("Makefile", "Makefile"),
        ("Jenkinsfile", "Jenkins pipeline"),
    ] {
        assert_eq!(text_container_label(name, "", "text/plain"), want, "{name}");
    }
    assert_eq!(
        text_container_label("dir/.env.local", "local", ""),
        "Environment configuration"
    );
    assert_eq!(
        text_container_label("unknown.bin", "bin", "application/octet-stream"),
        ""
    );
}

#[tokio::test]
async fn the_details_of_text_and_of_other_objects() {
    let (instance, backend) = memory_instance("text");
    backend.insert("src/main.rs", "fn main() {}\n", "text/x-rust");
    backend.insert("image.bin", "\u{0}", "application/octet-stream");
    let ctx = OpCtx::default();
    let details = inspect_document_details(&ctx, &instance, "src/main.rs", "rs", "", &listed(0))
        .await
        .unwrap();
    assert!(details.handled);
    assert_eq!(details.container, "Rust");
    assert_eq!(details.headers.get("content-type").unwrap(), "text/x-rust");
    let other = inspect_document_details(
        &ctx,
        &instance,
        "image.bin",
        "bin",
        "application/octet-stream",
        &listed(1),
    )
    .await
    .unwrap();
    assert!(!other.handled);
    let json = inspect_document_details(&ctx, &instance, "src/main.rs", "geojson", "", &listed(0))
        .await
        .unwrap();
    assert_eq!(json.container, "GEOJSON");
}

// --- SQLite and Parquet details -----------------------------------------------------------------------------------

#[tokio::test]
async fn the_details_of_a_sqlite_file_come_from_its_header() {
    let (instance, backend) = memory_instance("db");
    let image = {
        let mut header = vec![0u8; 1536];
        header[..16].copy_from_slice(b"SQLite format 3\0");
        header[16..18].copy_from_slice(&512u16.to_be_bytes());
        header[28..32].copy_from_slice(&3u32.to_be_bytes());
        header[44..48].copy_from_slice(&4u32.to_be_bytes());
        header[56..60].copy_from_slice(&1u32.to_be_bytes());
        header[68..72].copy_from_slice(&0x0f00_0001u32.to_be_bytes());
        header[96..100].copy_from_slice(&3_046_001u32.to_be_bytes());
        header
    };
    backend.insert("app.db", image.clone(), "application/vnd.sqlite3");
    let details = inspect_document_details(&OpCtx::default(), &instance, "app.db", "db", "", &listed(image.len()))
        .await
        .unwrap();
    assert_eq!(details.container, "SQLITE");
    let want: BTreeMap<String, String> = [
        ("Page size", "512 bytes"),
        ("Database pages", "3"),
        ("Schema format", "4"),
        ("Text encoding", "UTF-8"),
        ("User version", "0"),
        ("Declared database size", "1536 bytes"),
        ("Application ID", "0x0F000001"),
        ("SQLite version", "3.46.1"),
    ]
    .iter()
    .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
    .collect();
    assert_eq!(details.properties, want);
    assert_eq!(details.size, 1536);
    backend.insert("bad.sqlite", vec![0u8; 120], "");
    let error = inspect_document_details(&OpCtx::default(), &instance, "bad.sqlite", "sqlite", "", &listed(120))
        .await
        .err()
        .unwrap();
    assert!(error.has_code("invalid_sqlite"));
}

#[tokio::test]
async fn the_details_of_a_parquet_file_give_its_rows_and_columns() {
    let (instance, backend) = memory_instance("data");
    let file = parquet_file(&parquet_metadata());
    backend.insert("table.parquet", file.clone(), "");
    let details = inspect_document_details(&OpCtx::default(), &instance, "table.parquet", "parquet", "", &listed(0))
        .await
        .unwrap();
    assert_eq!(details.container, "PARQUET");
    assert_eq!(details.properties["Rows"], "5");
    assert_eq!(details.properties["Columns"], "2");
    assert_eq!(details.size, file.len() as i64);
}

// --- Workbooks ----------------------------------------------------------------------------------------------------

/// The row summary of the first row of a text: true when a cell has content, and the last column with content.
fn worksheet_row_summary(source: &str) -> (bool, i64) {
    let document = format!("<sheetData>{source}</sheetData>");
    count_worksheet_dimensions(&mut document.as_bytes())
        .map(|(rows, columns)| (rows > 0, columns))
        .unwrap()
}

#[test]
fn the_row_summary_ignores_empty_styled_cells() {
    assert_eq!(
        worksheet_row_summary(r#"<row r="1"><c r="A1" s="2"></c><c r="C1"><v>value</v></c></row>"#),
        (true, 3)
    );
    assert_eq!(
        worksheet_row_summary(r#"<row r="2"><c r="D2" s="4"></c></row>"#),
        (false, 0)
    );
    assert_eq!(
        worksheet_row_summary(r#"<row r="3"><c r="B3"><f>SUM(A1:A2)</f></c></row>"#),
        (true, 2)
    );
}

#[test]
fn the_dimension_count_tells_errors_in_and_out_of_rows() {
    // An error in a row keeps its cause: it is not an error of the request.
    let inside = count_worksheet_dimensions(&mut "<sheetData><row></sheetData>".as_bytes()).unwrap_err();
    assert!(inside.as_api().is_none(), "{inside:?}");
    assert_eq!(inside.status(), 502);
    let unclosed = count_worksheet_dimensions(&mut "<worksheet><sheetData>".as_bytes()).unwrap_err();
    assert!(unclosed.has_code("invalid_sheet"), "{unclosed:?}");
    assert_eq!(unclosed.status(), 422);
    let fallback = count_worksheet_dimensions(
        &mut "<x><row><c><v>1</v></c><c><v> </v></c><c><is><t>t</t></is></c></row><row/><row><c t=\"s\"><v>&#49;</v></c></row></x>"
            .as_bytes(),
    )
    .unwrap();
    assert_eq!(fallback, (3, 3));
}

/// A workbook with two sheets: `Data` (rows 2 to 5, two used columns) and the hidden sheet `Archive`.
fn test_workbook() -> Bytes {
    zip_of(&[
        (
            "[Content_Types].xml",
            r#"<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/worksheets/sheet2.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
</Types>"#,
        ),
        (
            "xl/workbook.xml",
            r#"<?xml version="1.0" encoding="UTF-8"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets>
    <sheet name="Data" sheetId="1" r:id="rId1"/>
    <sheet name="Archive" sheetId="2" state="hidden" r:id="rId2"/>
  </sheets>
</workbook>"#,
        ),
        (
            "xl/_rels/workbook.xml.rels",
            r#"<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet2.xml"/>
</Relationships>"#,
        ),
        (
            "xl/sharedStrings.xml",
            r#"<?xml version="1.0" encoding="UTF-8"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="4" uniqueCount="4">
  <si><t>alpha</t></si><si><t>beta</t></si><si><t>gamma</t></si><si><t>archived</t></si>
</sst>"#,
        ),
        (
            "xl/styles.xml",
            r#"<?xml version="1.0" encoding="UTF-8"?>
<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><cellXfs count="1"><xf numFmtId="0"/></cellXfs></styleSheet>"#,
        ),
        (
            "xl/worksheets/sheet1.xml",
            r#"<?xml version="1.0" encoding="UTF-8"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>
  <row r="2"><c r="A2" t="s"><v>0</v></c><c r="B2"><v>10</v></c></row>
  <row r="3"><c r="A3" t="inlineStr"><is><t></t></is></c></row>
  <row r="4"><c r="A4" t="s"><v>1</v></c><c r="B4"><v>20</v></c></row>
  <row r="5"><c r="A5" t="s"><v>2</v></c><c r="B5"><v>3</v></c><c r="D5"></c></row>
</sheetData></worksheet>"#,
        ),
        (
            "xl/worksheets/sheet2.xml",
            r#"<?xml version="1.0" encoding="UTF-8"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>
  <row r="1"><c r="A1" t="s"><v>3</v></c></row>
</sheetData></worksheet>"#,
        ),
    ])
}

#[tokio::test]
async fn the_spreadsheet_details_describe_the_active_sheet_only() {
    let (instance, backend) = memory_instance("xlsx");
    let workbook = test_workbook();
    backend.insert(
        "book.xlsx",
        workbook.clone(),
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    );
    let ctx = OpCtx::default();
    let (summary, _, size) = inspect_spreadsheet_summary(&ctx, &instance, "book.xlsx", workbook.len() as i64)
        .await
        .unwrap();
    assert_eq!((summary.sheets, summary.active_sheet.as_str()), (2, "Data"));
    assert_eq!((summary.rows, summary.columns), (0, 0), "the details count no cell");
    assert_eq!(size, workbook.len() as i64);
    let dimensions = inspect_spreadsheet_dimensions(&ctx, &instance, "book.xlsx", workbook.len() as i64)
        .await
        .unwrap();
    assert_eq!(dimensions.active_sheet, "Data");
    assert_eq!((dimensions.rows, dimensions.columns), (5, 2));
}

#[tokio::test]
async fn the_spreadsheet_counts_refuse_other_containers() {
    let (instance, backend) = memory_instance("xlsx");
    let mut xls = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
    xls.extend_from_slice(&[0u8; 64]);
    backend.insert("old.xlsx", xls, "");
    backend.insert("text.xlsx", "just text, not a package", "");
    let ctx = OpCtx::default();
    let old = inspect_spreadsheet_dimensions(&ctx, &instance, "old.xlsx", 0)
        .await
        .err()
        .unwrap();
    assert!(old.has_code("unsupported_xls_container"), "{old:?}");
    let text = inspect_spreadsheet_dimensions(&ctx, &instance, "text.xlsx", 0)
        .await
        .err()
        .unwrap();
    assert!(text.has_code("invalid_workbook_container"), "{text:?}");
    backend.insert("empty.xlsx", zip_of(&[("readme.txt", "no workbook")]), "");
    let empty = inspect_spreadsheet_dimensions(&ctx, &instance, "empty.xlsx", 0)
        .await
        .err()
        .unwrap();
    assert!(empty.has_code("invalid_workbook"), "{empty:?}");
}

// --- The readers of the other parts ---------------------------------------------------------------------------------

#[tokio::test]
async fn the_word_details_read_only_the_property_parts() {
    let (instance, backend) = memory_instance("docx");
    let archive = zip_of(&[
        (
            "docProps/core.xml",
            r#"<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/"><dc:title>Quarterly plan</dc:title><dc:creator>Ada Lovelace</dc:creator><cp:lastModifiedBy>Grace Hopper</cp:lastModifiedBy><cp:revision>7</cp:revision><dcterms:created>2026-07-25T08:00:00Z</dcterms:created></cp:coreProperties>"#,
        ),
        (
            "docProps/app.xml",
            r#"<?xml version="1.0"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>Microsoft Office Word</Application><AppVersion>16.0000</AppVersion><Company>Example</Company><Pages>12</Pages><Words>3456</Words><Lines>210</Lines><TotalTime>42</TotalTime></Properties>"#,
        ),
        ("word/document.xml", "x".repeat(3 << 20).as_str()),
    ]);
    backend.insert(
        "report.docx",
        archive.clone(),
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    );
    let details = inspect_document_details(
        &OpCtx::default(),
        &instance,
        "report.docx",
        "docx",
        "",
        &listed(archive.len()),
    )
    .await
    .unwrap();
    assert!(details.handled);
    assert_eq!(details.container, "Microsoft Word Open XML");
    for (label, want) in [
        ("Title", "Quarterly plan"),
        ("Author", "Ada Lovelace"),
        ("Last modified by", "Grace Hopper"),
        ("Revision", "7"),
        ("Application", "Microsoft Office Word"),
        ("Pages", "12"),
        ("Words", "3456"),
        ("Lines", "210"),
        ("Editing time (minutes)", "42"),
    ] {
        assert_eq!(details.properties.get(label).map(String::as_str), Some(want), "{label}");
    }
    assert!(
        backend.bytes_read() < archive.len() as i64,
        "the details read the complete package"
    );
    assert!(
        backend
            .state()
            .get_ranges
            .iter()
            .all(|range| range.starts_with("bytes=") && !range.ends_with('-'))
    );
}

#[tokio::test]
async fn the_presentation_details_use_only_the_package_metadata_and_the_central_directory() {
    let (instance, backend) = memory_instance("ppt");
    let archive = zip_of(&[
        (
            "docProps/core.xml",
            r#"<?xml version="1.0"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>Board review</dc:title><dc:creator>Ada Lovelace</dc:creator><cp:lastModifiedBy>Grace Hopper</cp:lastModifiedBy></cp:coreProperties>"#,
        ),
        (
            "docProps/app.xml",
            r#"<?xml version="1.0"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Application>Microsoft PowerPoint</Application><AppVersion>16.0000</AppVersion><Slides>2</Slides><HiddenSlides>1</HiddenSlides><Notes>1</Notes><PresentationFormat>Widescreen</PresentationFormat></Properties>"#,
        ),
        (
            "docProps/custom.xml",
            r#"<?xml version="1.0"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"><property name="Department"><vt:lpwstr>Research</vt:lpwstr></property></Properties>"#,
        ),
        ("ppt/slides/slide1.xml", "x".repeat(2 << 20).as_str()),
        ("ppt/slides/slide2.xml", "<p:sld/>"),
        ("ppt/notesSlides/notesSlide1.xml", "<p:notes/>"),
        ("ppt/media/image1.png", "png"),
        ("ppt/vbaProject.bin", "macro"),
    ]);
    backend.insert(
        "deck.pptm",
        archive.clone(),
        "application/vnd.ms-powerpoint.presentation.macroEnabled.12",
    );
    let details = inspect_document_details(
        &OpCtx::default(),
        &instance,
        "deck.pptm",
        "pptm",
        "",
        &listed(archive.len()),
    )
    .await
    .unwrap();
    assert!(details.handled);
    assert_eq!(details.container, "Microsoft PowerPoint macro-enabled presentation");
    for (label, want) in [
        ("Title", "Board review"),
        ("Author", "Ada Lovelace"),
        ("Last modified by", "Grace Hopper"),
        ("Application", "Microsoft PowerPoint"),
        ("Slides", "2"),
        ("Hidden slides", "1"),
        ("Notes slides", "1"),
        ("Presentation format", "Widescreen"),
        ("Media files", "1"),
        ("Macros", "Yes"),
        ("Custom - Department", "Research"),
    ] {
        assert_eq!(details.properties.get(label).map(String::as_str), Some(want), "{label}");
    }
    assert!(
        backend.bytes_read() < archive.len() as i64,
        "the details read the complete package"
    );
}

#[tokio::test]
async fn the_structured_details_of_small_text_formats() {
    let (instance, backend) = memory_instance("meta");
    let objects = [
        (
            "person.vcf",
            "BEGIN:VCARD\nVERSION:4.0\nFN:Ada Lovelace\nORG:Analytical Engines\nEMAIL:ada@example.test\nTEL:+33123456789\nEND:VCARD\n",
            "text/vcard",
        ),
        (
            "event.ics",
            "BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//Example//EN\nBEGIN:VEVENT\nSUMMARY:Review\nDTSTART:20260725T080000Z\nDTEND:20260725T090000Z\nEND:VEVENT\nEND:VCALENDAR\n",
            "text/calendar",
        ),
        (
            "message.eml",
            "From: Ada <ada@example.test>\r\nTo: Grace <grace@example.test>\r\nSubject: Metadata\r\nDate: Sat, 25 Jul 2026 08:00:00 +0000\r\nMessage-ID: <one@example.test>\r\n\r\nBody not inspected by metadata.",
            "message/rfc822",
        ),
        (
            "cert.pem",
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
            "application/x-pem-file",
        ),
    ];
    for (key, data, content_type) in objects {
        backend.insert(key, data, content_type);
    }
    let cases = [
        (
            "person.vcf",
            "vcf",
            "text/vcard",
            "vCard contact",
            "Name",
            "Ada Lovelace",
        ),
        ("event.ics", "ics", "text/calendar", "iCalendar", "Events", "1"),
        (
            "message.eml",
            "eml",
            "message/rfc822",
            "Email message",
            "Subject",
            "Metadata",
        ),
        (
            "cert.pem",
            "pem",
            "application/x-pem-file",
            "PEM certificate",
            "PEM blocks",
            "1",
        ),
    ];
    for (key, extension, content_type, container, property, want) in cases {
        let size = backend.object(key).unwrap().data.len();
        let details = inspect_document_details(
            &OpCtx::default(),
            &instance,
            key,
            extension,
            content_type,
            &listed(size),
        )
        .await
        .unwrap();
        assert!(details.handled, "{key}");
        assert_eq!(details.container, container, "{key}");
        assert_eq!(
            details.properties.get(property).map(String::as_str),
            Some(want),
            "{key}"
        );
    }
}
