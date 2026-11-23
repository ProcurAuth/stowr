// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tests of the SQLite reader and of its sessions.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use base64::Engine as _;
use bytes::Bytes;

use super::query::{PageAnswer, TableQuery, query_table, truncate_text};
use super::schema::{ColumnDefinition, ColumnInfo, TableDefinition, TableInfo, inspect_tables};
use super::sessions::{MAX_AGE_TTLS, MAX_SESSIONS, Session, SqliteSessions};
use super::{Database, DatabaseSource, Flow, MAX_RECORD_PAYLOAD, Value, local_payload_size, read_varint};
use crate::common::ctx::OpCtx;
use crate::common::error::Result;
use crate::pv_data::tests::{Called, application, call, memory_instance};

const FIXTURE_BASE64: &str = concat!(
    "U1FMaXRlIGZvcm1hdCAzAAIAAQEAQCAgAAAABAAAAAMAAAAAAAAAAAAAAAMAAAAEAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAC56cQ0AAAACAR4AAZEBHgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHEC",
    "BxcfHwGBMXRhYmxlY29tcG9zaXRlY29tcG9zaXRlA0NSRUFURSBUQUJMRSBjb21wb3NpdGUoYSBURVhULGIgSU5URUdFUix2",
    "YWx1ZSBURVhULFBSSU1BUlkgS0VZKGEsYikpIFdJVEhPVVQgUk9XSURtAQcXFxcBgTl0YWJsZWl0ZW1zaXRlbXMCQ1JFQVRF",
    "IFRBQkxFIGl0ZW1zKGlkIElOVEVHRVIgUFJJTUFSWSBLRVksbmFtZSBURVhULHNjb3JlIFJFQUwscGF5bG9hZCBCTE9CLG5v",
    "dGUgVEVYVCkNAAAAAwG9AAHiAc8BvQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAEAMGABcADBdnYW1tYXRoaXJkEQIGABUBABliZXRhAnNlY29uZBwBBgAXBxQXYWxwaGE/",
    "+AAAAAAAAAECAwRmaXJzdAoAAAADAeIAAfcB7QHiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACgQPCRd5",
    "dGhyZWUJBA8BE3gCdHdvCAQPCRN4b25l",
);

fn fixture() -> Bytes {
    Bytes::from(
        base64::engine::general_purpose::STANDARD
            .decode(FIXTURE_BASE64)
            .unwrap(),
    )
}

async fn open(image: Bytes) -> Database {
    let size = image.len() as i64;
    Database::open(DatabaseSource::Memory(image), size).await.unwrap()
}

async fn fixture_tables() -> (Database, Vec<TableInfo>, BTreeMap<String, TableDefinition>) {
    let database = open(fixture()).await;
    let (infos, definitions) = inspect_tables(&OpCtx::default(), &database).await.unwrap();
    (database, infos, definitions)
}

/// A page with the search, the filters and the sort of a test.
async fn page_of(
    database: &Database,
    definition: &TableDefinition,
    (page, page_size): (i64, i64),
    search: &str,
    filters: &[(&str, &str)],
    sort: (&str, &str),
    exact_totals: bool,
) -> Result<PageAnswer> {
    let filters: BTreeMap<String, String> = filters
        .iter()
        .map(|(column, filter)| ((*column).to_owned(), (*filter).to_owned()))
        .collect();
    let query = TableQuery {
        page,
        page_size,
        search,
        filters: &filters,
        sort_column: sort.0,
        sort_direction: sort.1,
        exact_totals,
    };
    query_table(&OpCtx::default(), database, definition, &query).await
}

/// A page with exact totals, without filter and sort.
async fn simple_page(
    database: &Database,
    definition: &TableDefinition,
    page: i64,
    size: i64,
    search: &str,
) -> PageAnswer {
    page_of(database, definition, (page, size), search, &[], ("", ""), true)
        .await
        .unwrap()
}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

#[tokio::test]
async fn the_reader_inspects_and_pages_the_tables() {
    let (database, infos, definitions) = fixture_tables().await;
    assert_eq!(infos.len(), 2, "{infos:?}");
    let items = definitions.get("items").expect("items definition");
    assert_eq!(items.info.columns.len(), 5);
    assert!(items.info.columns[0].primary_key);
    assert_eq!(items.info.columns[0].name, "id");
    let page = simple_page(&database, items, 0, 2, "a").await;
    assert_eq!(page.rows.len(), 2);
    assert!(page.has_more);
    assert_eq!(page.page_size, 2);
    assert_eq!(page.query, "a");
    assert_eq!((page.total_rows, page.source_total_rows), (3, 3));
    assert_eq!(page.rows[0]["id"], Value::Integer(1));
    assert_eq!(page.rows[0]["payload"], text("[BLOB 4 bytes]"));
    let empty = simple_page(&database, items, 0, 100, "nohit").await;
    assert!(empty.rows.is_empty());
    assert_eq!((empty.total_rows, empty.source_total_rows), (0, 3));
}

#[tokio::test]
async fn the_reader_reads_tables_without_row_ids() {
    let (database, _, definitions) = fixture_tables().await;
    let definition = definitions.get("composite").expect("composite definition");
    assert!(definition.without_row_id);
    let page = simple_page(&database, definition, 0, 100, "").await;
    assert_eq!((page.total_rows, page.rows.len()), (3, 3));
    assert_eq!(page.rows[0]["a"], text("x"));
    assert_eq!(page.rows[0]["b"], Value::Integer(1));
    assert_eq!(page.rows[0]["value"], text("one"));
}

#[tokio::test]
async fn the_reader_pages_without_exact_totals() {
    let (database, _, definitions) = fixture_tables().await;
    let items = &definitions["items"];
    let first = page_of(&database, items, (0, 2), "", &[], ("", ""), false)
        .await
        .unwrap();
    assert_eq!(first.rows.len(), 2);
    assert!(first.has_more);
    assert!(!first.total_known);
    assert_eq!(first.total_rows, -1);
    let second = page_of(&database, items, (1, 2), "", &[], ("", ""), false)
        .await
        .unwrap();
    assert_eq!(second.rows.len(), 1);
    assert!(!second.has_more);
    assert!(second.total_known);
    assert_eq!(second.total_rows, 3);
}

#[tokio::test]
async fn the_reader_uses_the_column_filters_and_the_sort() {
    let (database, _, definitions) = fixture_tables().await;
    let items = &definitions["items"];
    let filtered = page_of(&database, items, (0, 100), "", &[("name", "beta")], ("", ""), false)
        .await
        .unwrap();
    assert_eq!(filtered.rows.len(), 1);
    assert_eq!(filtered.rows[0]["name"], text("beta"));
    let sorted = page_of(&database, items, (0, 2), "", &[], ("name", "desc"), false)
        .await
        .unwrap();
    assert_eq!(sorted.rows.len(), 2);
    assert_eq!(sorted.rows[0]["name"], text("gamma"));
    assert_eq!(sorted.rows[1]["name"], text("beta"));
}

#[test]
fn varints_and_records_have_safety_limits() {
    assert_eq!(read_varint(&[0x81, 0x00], 0), Some((128, 2)));
    assert!(local_payload_size(MAX_RECORD_PAYLOAD + 1, 4096, true).is_err());
}

#[test]
fn a_full_session_table_removes_the_least_recently_used_session() {
    let sessions = SqliteSessions::new();
    let base = SystemTime::now();
    for index in 0..MAX_SESSIONS {
        let last = base + Duration::from_secs(index as u64);
        sessions
            .register(Session::bare(&format!("session-{index}"), last, last))
            .unwrap();
    }
    let later = base + Duration::from_secs(60);
    sessions.register(Session::bare("newcomer", later, later)).unwrap();
    assert_eq!(sessions.len(), MAX_SESSIONS);
    assert!(!sessions.contains("session-0"), "the least recently used session stays");
    assert!(sessions.contains("newcomer"));
}

#[test]
fn a_used_session_cannot_live_longer_than_its_maximum_age() {
    let sessions = SqliteSessions::new();
    let ttl = sessions.ttl();
    let now = SystemTime::now();
    sessions.insert_raw(Session::bare(
        "old",
        now - ttl * MAX_AGE_TTLS - Duration::from_secs(1),
        now,
    ));
    assert!(
        sessions.get("old").is_none(),
        "the table serves a session past its maximum age"
    );
    assert!(!sessions.contains("old"), "a session past its maximum age stays");

    sessions.insert_raw(Session::bare(
        "idle",
        now - ttl - Duration::from_secs(60),
        now - ttl - Duration::from_secs(1),
    ));
    assert!(sessions.get("idle").is_none(), "an idle session came back");

    sessions.insert_raw(Session::bare("swept", now - ttl * MAX_AGE_TTLS, now));
    sessions.insert_raw(Session::bare("fresh", now, now));
    sessions.cleanup_expired(now);
    assert!(
        !sessions.contains("swept"),
        "the sweep kept a session past its maximum age"
    );
    assert!(sessions.get("fresh").is_some(), "the sweep removed a fresh session");
}

/// The big-endian varint of a value below 2^21.
fn varint(value: usize) -> Vec<u8> {
    if value < 1 << 7 {
        vec![value as u8]
    } else if value < 1 << 14 {
        vec![(value >> 7) as u8 | 0x80, (value & 0x7f) as u8]
    } else {
        vec![
            (value >> 14) as u8 | 0x80,
            ((value >> 7) & 0x7f) as u8 | 0x80,
            (value & 0x7f) as u8,
        ]
    }
}

/// A table leaf page with the cells at its end and the pointers to the cells of `pointers`.
fn table_leaf_page(page_size: usize, cells: &[Vec<u8>], pointers: &[usize]) -> Vec<u8> {
    let mut page = vec![0u8; page_size];
    let mut end = page_size;
    let mut offsets = Vec::with_capacity(cells.len());
    for cell in cells {
        end -= cell.len();
        page[end..end + cell.len()].copy_from_slice(cell);
        offsets.push(end);
    }
    page[0] = 0x0d;
    page[3..5].copy_from_slice(&(pointers.len() as u16).to_be_bytes());
    page[5..7].copy_from_slice(&(end as u16).to_be_bytes());
    for (index, cell) in pointers.iter().enumerate() {
        page[8 + index * 2..10 + index * 2].copy_from_slice(&(offsets[*cell] as u16).to_be_bytes());
    }
    page
}

/// A table interior page with these children; the last one is the right-most child.
fn interior_page(page_size: usize, children: &[u32]) -> Vec<u8> {
    let mut page = vec![0u8; page_size];
    let mut end = page_size;
    page[0] = 0x05;
    let last = children.len() - 1;
    for (index, child) in children[..last].iter().enumerate() {
        let mut cell = child.to_be_bytes().to_vec();
        cell.extend(varint(index + 1));
        end -= cell.len();
        page[end..end + cell.len()].copy_from_slice(&cell);
        page[12 + index * 2..14 + index * 2].copy_from_slice(&(end as u16).to_be_bytes());
    }
    page[3..5].copy_from_slice(&(last as u16).to_be_bytes());
    page[5..7].copy_from_slice(&(end as u16).to_be_bytes());
    page[8..12].copy_from_slice(&children[last].to_be_bytes());
    page
}

/// A database image: page 1 has only the header, `pages[0]` is page 2.
fn image(page_size: usize, pages: &[Vec<u8>]) -> Bytes {
    let mut image = vec![0u8; page_size];
    image[..16].copy_from_slice(b"SQLite format 3\0");
    image[16..18].copy_from_slice(&(page_size as u16).to_be_bytes());
    for page in pages {
        image.extend_from_slice(page);
    }
    Bytes::from(image)
}

/// A table `t` with one column `v`.
fn single_column_table(root: u32) -> TableDefinition {
    TableDefinition {
        info: TableInfo {
            name: "t".to_owned(),
            columns: vec![ColumnInfo {
                name: "v".to_owned(),
                ..ColumnInfo::default()
            }],
            ..TableInfo::default()
        },
        root_page: root,
        columns: vec![ColumnDefinition {
            name: "v".to_owned(),
            ..ColumnDefinition::default()
        }],
        storage_order: vec![0],
        ..TableDefinition::default()
    }
}

async fn count_visits(database: &Database, root: u32) -> (Result<Flow>, usize) {
    let mut visited = 0;
    let result = database
        .walk_table(&OpCtx::default(), root, &mut |_: i64, _: Vec<Value>| {
            visited += 1;
            Ok(Flow::Continue)
        })
        .await;
    (result, visited)
}

#[tokio::test]
async fn the_reader_refuses_a_page_that_lists_a_cell_twice() {
    let mut cell = varint(2);
    cell.extend(varint(1));
    cell.extend([0x02, 0x08]);
    let leaf = table_leaf_page(4096, &[cell], &[0, 0, 0]);
    let database = open(image(4096, &[leaf])).await;
    let (result, visited) = count_visits(&database, 2).await;
    let error = result.expect_err("an error");
    assert!(error.has_code("invalid_sqlite_cell"), "{error:?}");
    assert_eq!(visited, 0);
}

#[tokio::test]
async fn the_reader_refuses_an_overflow_chain_that_two_cells_share() {
    const PAYLOAD: usize = 5000;
    let cell = |row_id: usize| {
        let mut out = varint(PAYLOAD);
        out.extend(varint(row_id));
        let mut local = vec![0u8; 908];
        let mut header = vec![3u8];
        header.extend(varint(2 * (PAYLOAD - 3) + 12));
        local[..header.len()].copy_from_slice(&header);
        out.extend(local);
        out.extend(3u32.to_be_bytes());
        out
    };
    let leaf = table_leaf_page(4096, &[cell(1), cell(2)], &[0, 1]);
    let overflow = vec![0u8; 4096];
    let database = open(image(4096, &[leaf, overflow])).await;
    let (result, visited) = count_visits(&database, 2).await;
    let error = result.expect_err("an error");
    assert!(error.has_code("sqlite_overflow_cycle"), "{error:?}");
    assert_eq!(visited, 1);
}

#[tokio::test]
async fn the_buffers_of_a_sort_have_a_limit_in_bytes() {
    const PAGE_SIZE: usize = 4096;
    const ROWS: usize = 17_000;
    const FANOUT: usize = 300;
    const TEXT_BYTES: usize = 4000;
    let mut record = vec![3u8];
    record.extend(varint(13 + 2 * TEXT_BYTES));
    record.extend(std::iter::repeat_n(b'a', TEXT_BYTES));
    let mut pages: Vec<Vec<u8>> = Vec::with_capacity(ROWS + ROWS / FANOUT + 2);
    let mut leaves: Vec<u32> = Vec::with_capacity(ROWS);
    for row in 1..=ROWS {
        let mut cell = varint(record.len());
        cell.extend(varint(row));
        cell.extend_from_slice(&record);
        pages.push(table_leaf_page(PAGE_SIZE, &[cell], &[0]));
        leaves.push(pages.len() as u32 + 1);
    }
    let mut interiors = Vec::new();
    for chunk in leaves.chunks(FANOUT) {
        pages.push(interior_page(PAGE_SIZE, chunk));
        interiors.push(pages.len() as u32 + 1);
    }
    pages.push(interior_page(PAGE_SIZE, &interiors));
    let database = open(image(PAGE_SIZE, &pages)).await;
    let definition = single_column_table(pages.len() as u32 + 1);
    let error = page_of(&database, &definition, (0, 10), "", &[], ("v", "asc"), true)
        .await
        .expect_err("a sort error");
    assert!(error.has_code("sort_result_too_large"), "{error:?}");
    let unsorted = page_of(&database, &definition, (0, 10), "", &[], ("", ""), true)
        .await
        .unwrap();
    assert_eq!(unsorted.total_rows, ROWS as i64);
}

#[tokio::test]
async fn a_sort_keeps_the_shown_values_of_the_smaller_rows() {
    let (database, _, definitions) = fixture_tables().await;
    let sorted = page_of(&database, &definitions["items"], (0, 3), "", &[], ("name", "asc"), true)
        .await
        .unwrap();
    assert_eq!(sorted.rows.len(), 3);
    assert_eq!(sorted.rows[0]["name"], text("alpha"));
    assert_eq!(sorted.rows[0]["payload"], text("[BLOB 4 bytes]"));
    let long = "é".repeat(4096 + 10);
    let cut = truncate_text(&long);
    assert_eq!(
        cut,
        format!("{}…", "é".repeat(4096)),
        "the cut text has {} bytes",
        cut.len()
    );
}

#[tokio::test]
async fn the_schema_reader_finds_keys_types_and_generated_columns() {
    use super::schema::{SchemaEntry, parse_create_table};
    let entry = |sql: &str| SchemaEntry {
        kind: "table".to_owned(),
        name: "t".to_owned(),
        table: "t".to_owned(),
        root_page: 2,
        sql: sql.to_owned(),
    };
    let definition = parse_create_table(&entry(
        "CREATE TABLE t(\"my id\" INTEGER, [weird, name] VARCHAR(10) NOT NULL, total REAL GENERATED ALWAYS AS (1) VIRTUAL, CONSTRAINT pk PRIMARY KEY(\"my id\"))",
    ))
    .unwrap();
    let names: Vec<&str> = definition.columns.iter().map(|column| column.name.as_str()).collect();
    assert_eq!(names, vec!["my id", "weird, name", "total"]);
    assert_eq!(definition.columns[1].declared_type, "VARCHAR(10)");
    assert!(definition.columns[0].primary_key);
    assert!(definition.columns[0].row_id_alias);
    assert!(definition.columns[2].virtual_generated);
    assert_eq!(definition.storage_order, vec![0, 1]);
    assert_eq!(definition.info.columns.len(), 2);
    let virtual_table = parse_create_table(&entry("CREATE VIRTUAL TABLE t USING fts5(a)"))
        .err()
        .unwrap();
    assert!(virtual_table.has_code("unsupported_sqlite_virtual_table"));
    let descending = parse_create_table(&entry("CREATE TABLE t(id INTEGER PRIMARY KEY DESC, v)")).unwrap();
    assert!(!descending.columns[0].row_id_alias);
    let without = parse_create_table(&entry("CREATE TABLE t(a TEXT, b INT, PRIMARY KEY(b, a)) WITHOUT ROWID")).unwrap();
    assert!(without.without_row_id);
    assert_eq!(without.storage_order, vec![1, 0]);
}

#[test]
fn values_have_the_texts_of_the_search_and_the_sort() {
    assert_eq!(Value::Null.text(), "");
    assert_eq!(Value::Integer(-7).text(), "-7");
    assert_eq!(Value::Real(1_234_567.0).text(), "1.234567e+06");
    assert_eq!(Value::Blob(vec![1, 2, 3]).text(), "[BLOB 3 bytes]");
    assert_eq!(Value::Text(" 42 ".to_owned()).integer(), 42);
    assert_eq!(Value::Real(9.9).integer(), 9);
}

// --- the routes ---------------------------------------------------------------------------------------------

fn sessions_app(objects: &[(&str, Bytes)]) -> Arc<crate::common::app::App> {
    let (instance, backend) = memory_instance("db");
    for (key, data) in objects {
        backend.insert(key, data.clone(), "application/vnd.sqlite3");
    }
    application(vec![instance])
}

async fn create(app: &Arc<crate::common::app::App>, body: serde_json::Value) -> Called {
    call(app, "POST", "/api/sqlite/sessions", Some(body)).await
}

#[tokio::test]
async fn a_session_lists_the_tables_and_gives_pages() {
    let app = sessions_app(&[("data/fixture.sqlite", fixture())]);
    let created = create(
        &app,
        serde_json::json!({"instance": "db", "key": "/data/fixture.sqlite"}),
    )
    .await;
    assert_eq!(created.status, 201, "{}", created.text);
    let body = created.json();
    let id = body["id"].as_str().unwrap().to_owned();
    assert_eq!(id.len(), 36);
    assert_eq!(body["key"], "data/fixture.sqlite");
    assert_eq!(body["size"], fixture().len());
    assert_eq!(body["tables"][0]["name"], "composite");
    assert_eq!(body["tables"][1]["name"], "items");
    assert_eq!(
        body["tables"][1]["columns"][0],
        serde_json::json!({"name": "id", "declaredType": "INTEGER", "primaryKey": true})
    );
    assert!(body.get("warning").is_none());

    let described = call(&app, "GET", &format!("/api/sqlite/sessions/{id}"), None).await;
    assert_eq!(described.status, 200);
    assert_eq!(described.json()["id"], id.as_str());

    let page = call(
        &app,
        "GET",
        &format!("/api/sqlite/sessions/{id}/table?table=items&pageSize=2&count=1&sortColumn=score&sortDirection=DESC"),
        None,
    )
    .await;
    assert_eq!(page.status, 200, "{}", page.text);
    let page = page.json();
    assert_eq!(page["id"], id.as_str());
    assert_eq!(page["totalRows"], 3);
    assert_eq!(page["hasMore"], true);
    assert_eq!(page["rows"].as_array().unwrap().len(), 2);
    assert_eq!(page["table"]["name"], "items");
    assert!(page.get("query").is_none());

    let filtered = call(
        &app,
        "GET",
        &format!(
            "/api/sqlite/sessions/{id}/table?table=items&filters=%7B%22name%22%3A%22beta%22%2C%22note%22%3A%22%20%22%7D"
        ),
        None,
    )
    .await;
    assert_eq!(filtered.status, 200, "{}", filtered.text);
    assert_eq!(filtered.json()["rows"][0]["name"], "beta");

    let deleted = call(&app, "DELETE", &format!("/api/sqlite/sessions/{id}"), None).await;
    assert_eq!(deleted.status, 204);
    let gone = call(&app, "GET", &format!("/api/sqlite/sessions/{id}"), None).await;
    assert_eq!(gone.status, 404);
    assert_eq!(gone.code(), "sqlite_session_not_found");
    assert_eq!(
        gone.json()["error"]["message"],
        "SQLite preview session was not found or expired"
    );
    let deleted_again = call(&app, "DELETE", &format!("/api/sqlite/sessions/{id}"), None).await;
    assert_eq!(deleted_again.status, 404);
    assert_eq!(
        deleted_again.json()["error"]["message"],
        "SQLite preview session was not found"
    );
}

#[tokio::test]
async fn the_session_routes_check_their_requests() {
    let mut wal = fixture().to_vec();
    wal[18] = 2;
    let app = sessions_app(&[
        ("fixture.sqlite", fixture()),
        ("wal.sqlite", Bytes::from(wal)),
        ("small.sqlite", Bytes::from_static(b"too small")),
    ]);
    let unknown = create(&app, serde_json::json!({"instance": "none", "key": "fixture.sqlite"})).await;
    assert_eq!((unknown.status, unknown.code()), (404, "unknown_instance".to_owned()));
    assert_eq!(unknown.json()["error"]["message"], "unknown storage instance");
    let empty = create(&app, serde_json::json!({"instance": "db", "key": "/"})).await;
    assert_eq!((empty.status, empty.code()), (400, "invalid_key".to_owned()));
    let large = create(
        &app,
        serde_json::json!({"instance": "db", "key": "x", "size": (16_i64 << 40) + 1}),
    )
    .await;
    assert_eq!((large.status, large.code()), (413, "sqlite_too_large".to_owned()));
    assert_eq!(
        large.json()["error"]["message"],
        "SQLite previews are limited to 16384 GiB"
    );
    let small = create(&app, serde_json::json!({"instance": "db", "key": "small.sqlite"})).await;
    assert_eq!((small.status, small.code()), (422, "invalid_sqlite".to_owned()));
    let invalid = call(&app, "POST", "/api/sqlite/sessions", Some(serde_json::json!("text"))).await;
    assert_eq!((invalid.status, invalid.code()), (400, "invalid_json".to_owned()));
    let method = call(&app, "GET", "/api/sqlite/sessions", None).await;
    assert_eq!(method.status, 405);
    let none = call(&app, "GET", "/api/sqlite/sessions/", None).await;
    assert_eq!((none.status, none.code()), (404, "sqlite_session_not_found".to_owned()));

    let wal_session = create(
        &app,
        serde_json::json!({"instance": "db", "key": "wal.sqlite", "other": [1]}),
    )
    .await;
    assert_eq!(wal_session.status, 201, "{}", wal_session.text);
    assert!(
        wal_session.json()["warning"]
            .as_str()
            .unwrap()
            .starts_with("This database uses WAL journaling.")
    );

    let created = create(&app, serde_json::json!({"instance": "db", "key": "fixture.sqlite"})).await;
    let id = created.json()["id"].as_str().unwrap().to_owned();
    let table = |query: &str| format!("/api/sqlite/sessions/{id}/table?{query}");
    let unknown_table = call(&app, "GET", &table("table=nothing"), None).await;
    assert_eq!(
        (unknown_table.status, unknown_table.code()),
        (400, "unknown_sqlite_table".to_owned())
    );
    let bad_column = call(
        &app,
        "GET",
        &table("table=items&filters=%7B%22a%5Cnb%22%3A%22x%22%7D"),
        None,
    )
    .await;
    assert_eq!(bad_column.code(), "invalid_filter_column");
    assert_eq!(
        bad_column.json()["error"]["message"],
        "unknown SQLite filter column \"a\\nb\""
    );
    let bad_filters = call(&app, "GET", &table("table=items&filters=%5B1%5D"), None).await;
    assert_eq!(bad_filters.code(), "invalid_filters");
    let bad_sort = call(&app, "GET", &table("table=items&sortColumn=nothing"), None).await;
    assert_eq!(bad_sort.code(), "invalid_sort_column");
    let bad_direction = call(
        &app,
        "GET",
        &table("table=items&sortColumn=name&sortDirection=up"),
        None,
    )
    .await;
    assert_eq!(bad_direction.code(), "invalid_sort_direction");
    let long = format!("table=items&filters=%7B%22name%22%3A%22{}%22%7D", "a".repeat(1025));
    let too_long = call(&app, "GET", &table(&long), None).await;
    assert_eq!(too_long.code(), "filter_too_long");
    let post = call(&app, "POST", &format!("/api/sqlite/sessions/{id}"), None).await;
    assert_eq!(post.status, 405);
}

#[test]
fn an_unencodable_float_gives_an_empty_answer() {
    let mut row = BTreeMap::new();
    row.insert("v".to_owned(), Value::Real(f64::INFINITY));
    let answer = PageAnswer {
        rows: vec![row],
        ..PageAnswer::default()
    };
    assert!(answer.has_unencodable_value());
}
