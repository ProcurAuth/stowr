//! The tests of the routes `/api/structured-preview` and `/api/archive-preview`.

use std::collections::BTreeMap;
use std::sync::{Arc, Weak};

use http::{HeaderMap, Method};
use serde_json::Value;

use super::routes::{handle_archive_preview, handle_structured_preview};
use super::testzip::{Entry, build};
use crate::access::AccessLayer;
use crate::archive::zip::is_zip_archive_extension;
use crate::common::app::App;
use crate::common::config::Config;
use crate::common::ctx::OpCtx;
use crate::common::http::{Req, empty, read_limited};
use crate::common::query::{Query, query_escape};
use crate::instance::Instance;
use crate::instance::ceiling::{ACTION_READ, Ceilings, MAX_OBJECT_SIZE};
use crate::testkit::{MemoryBackend, bucket_config, instance_over, read_only_backend, read_only_instance};

/// The application with the instances `readonly` and `rw`; the instance `rw` has the root prefix `tenant/`.
struct Rig {
    app: Arc<App>,
    backend: Arc<MemoryBackend>,
}

fn rig_with(configure: impl FnOnce(&mut Config)) -> Rig {
    let backend = crate::testkit::read_write_backend();
    let rw = crate::testkit::read_write_instance(backend.clone());
    let readonly = read_only_instance(read_only_backend());
    let write_only = Arc::new(instance_over(
        bucket_config("writeonly", "", &["write"]),
        Arc::new(MemoryBackend::new()),
    ));
    let mut config = Config::default();
    configure(&mut config);
    let access = AccessLayer::new(&config).unwrap();
    let instances: Vec<Arc<Instance>> = vec![readonly, rw, write_only];
    let app = Arc::new(App {
        config: Arc::new(config),
        instances,
        auths: BTreeMap::new(),
        jobs: crate::jobs::JobManager::new(Weak::new(), 10),
        uploads: crate::uploads::UploadManager::new(),
        sqlite: crate::pv_data::SqliteSessions::new(),
        access,
        resume_token_key: [0; 32],
    });
    Rig { app, backend }
}

fn rig() -> Rig {
    rig_with(|_| {})
}

struct Answer {
    status: u16,
    text: String,
}

impl Answer {
    fn json(&self) -> Value {
        serde_json::from_str(&self.text).unwrap_or(Value::Null)
    }
}

async fn get(app: &Arc<App>, archive: bool, target: &str, method: Method) -> Answer {
    get_with(app, archive, target, method, OpCtx::default()).await
}

async fn get_with(app: &Arc<App>, archive: bool, target: &str, method: Method, ctx: OpCtx) -> Answer {
    let (path, raw_query) = target.split_once('?').unwrap_or((target, ""));
    let request = Req {
        method,
        path: path.to_owned(),
        raw_query: raw_query.to_owned(),
        query: Query::parse(raw_query),
        headers: HeaderMap::new(),
        body: empty(),
        ctx,
        host: "localhost".to_owned(),
    };
    let response = if archive {
        handle_archive_preview(app.clone(), request).await
    } else {
        handle_structured_preview(app.clone(), request).await
    };
    let status = response.status().as_u16();
    let (bytes, _) = read_limited(response.into_body(), usize::MAX).await.unwrap();
    Answer {
        status,
        text: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

fn structured_target(key: &str) -> String {
    format!("/api/structured-preview?instance=rw&key={}", query_escape(key))
}

#[tokio::test]
async fn the_structured_preview_reads_contacts_calendars_e_mail_and_private_key_text() {
    let rig = rig();
    let private_key = "-----BEGIN PRIVATE KEY-----\nAQIDBA==\n-----END PRIVATE KEY-----\n";
    rig.backend.insert(
        "tenant/person.vcf",
        "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Ada Lovelace\r\nORG:Analytical Engines\r\nEMAIL:ada@example.test\r\nTEL:+33123456789\r\nEND:VCARD\r\n",
        "text/vcard",
    );
    rig.backend.insert(
        "tenant/event.ics",
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nX-WR-CALNAME:Reviews\r\nBEGIN:VEVENT\r\nUID:review@example.test\r\nSUMMARY:Architecture review\r\nDTSTART:20260725T080000Z\r\nDTEND:20260725T090000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
        "text/calendar",
    );
    rig.backend.insert(
        "tenant/message.eml",
        "From: Ada <ada@example.test>\r\nTo: Grace <grace@example.test>\r\nSubject: Review\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Hello <img src=\"https://external.invalid/pixel.png\"></p>",
        "message/rfc822",
    );
    rig.backend
        .insert("tenant/secret.key", private_key, "application/x-pem-file");

    let answer = get(&rig.app, false, &structured_target("person.vcf"), Method::GET).await;
    assert_eq!(answer.status, 200, "{}", answer.text);
    let payload = answer.json();
    assert_eq!(payload["kind"], "contact");
    assert_eq!(payload["instance"], "rw");
    assert_eq!(payload["key"], "person.vcf");
    assert_eq!(payload["container"], "vCard contact");
    assert_eq!(payload["contacts"][0]["name"], "Ada Lovelace");
    assert_eq!(payload["rawEncoding"], "text");
    assert_eq!(payload["properties"]["Contacts"], "1");

    let payload = get(&rig.app, false, &structured_target("event.ics"), Method::GET)
        .await
        .json();
    assert_eq!(payload["kind"], "calendar");
    assert_eq!(payload["calendar"]["events"][0]["summary"], "Architecture review");
    assert_eq!(payload["calendar"]["name"], "Reviews");

    let payload = get(&rig.app, false, &structured_target("message.eml"), Method::GET)
        .await
        .json();
    assert_eq!(payload["kind"], "email");
    assert_eq!(payload["email"]["headers"]["Subject"], "Review");
    assert_ne!(payload["email"]["bodyText"], "");

    let payload = get(&rig.app, false, &structured_target("secret.key"), Method::GET)
        .await
        .json();
    assert_eq!(payload["kind"], "certificate");
    assert_eq!(payload["raw"], private_key);
    assert_eq!(payload["rawEncoding"], "text");
    assert_eq!(payload["container"], "PEM private key");
    assert_eq!(payload["properties"]["PEM blocks"], "1");
}

#[tokio::test]
async fn a_binary_certificate_has_a_base64_raw_form() {
    let rig = rig();
    let data = vec![0x30, 0x03, 0x02, 0x01, 0x05, 0x00, 0x01, 0x02];
    rig.backend
        .insert("tenant/cert.der", data.clone(), "application/octet-stream");
    let payload = get(&rig.app, false, &structured_target("cert.der"), Method::GET)
        .await
        .json();
    assert_eq!(payload["rawEncoding"], "base64");
    assert_eq!(payload["container"], "DER certificate");
    let encoded = super::pem::encode_base64(&data);
    assert_eq!(payload["raw"], encoded.as_str());
}

#[tokio::test]
async fn the_structured_preview_refuses_what_it_cannot_show() {
    let rig = rig();
    rig.backend.insert("tenant/notes.txt", "plain", "text/plain");
    let answer = get(&rig.app, false, &structured_target("notes.txt"), Method::GET).await;
    assert_eq!(answer.status, 415);
    assert_eq!(answer.json()["error"]["code"], "unsupported_preview");
    assert_eq!(
        answer.json()["error"]["message"],
        "this object does not have a structured preview"
    );

    let answer = get(&rig.app, false, "/api/structured-preview?instance=rw&key=", Method::GET).await;
    assert_eq!(answer.status, 400);
    assert_eq!(answer.json()["error"]["code"], "invalid_key");
    assert_eq!(answer.json()["error"]["message"], "object key cannot be empty");

    let answer = get(
        &rig.app,
        false,
        "/api/structured-preview?instance=nope&key=a.vcf",
        Method::GET,
    )
    .await;
    assert_eq!(answer.status, 404);
    assert_eq!(answer.json()["error"]["code"], "unknown_instance");

    let answer = get(
        &rig.app,
        false,
        "/api/structured-preview?instance=writeonly&key=a.vcf",
        Method::GET,
    )
    .await;
    assert_eq!(answer.status, 403);

    let answer = get(&rig.app, false, &structured_target("person.vcf"), Method::POST).await;
    assert_eq!(answer.status, 405);

    let answer = get(&rig.app, false, &structured_target("absent.vcf"), Method::GET).await;
    assert!(answer.status >= 400, "{}", answer.text);
}

#[tokio::test]
async fn the_structured_preview_reads_only_small_objects() {
    let rig = rig();
    rig.backend
        .insert("tenant/big.vcf", "BEGIN:VCARD\nEND:VCARD\n", "text/vcard");
    let target = format!("{}&size={}", structured_target("big.vcf"), 33 << 20);
    let answer = get(&rig.app, false, &target, Method::GET).await;
    assert_eq!(answer.status, 413);
    assert_eq!(answer.json()["error"]["code"], "preview_too_large");
    assert_eq!(
        answer.json()["error"]["message"],
        "this structured preview reads the complete object and is limited to 32 MB"
    );
}

#[tokio::test]
async fn the_structured_preview_echoes_the_version() {
    let rig = rig();
    rig.backend
        .insert("tenant/v.vcf", "BEGIN:VCARD\nFN:V\nEND:VCARD\n", "text/vcard");
    let target = format!("{}&version=%20abc%20", structured_target("v.vcf"));
    let payload = get(&rig.app, false, &target, Method::GET).await.json();
    assert_eq!(payload["version"], "abc");
}

fn archive_target(key: &str, size: usize) -> String {
    format!("/api/archive-preview?instance=rw&key={}&size={size}", query_escape(key))
}

fn exact_ranges(ranges: &[String]) {
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

#[tokio::test]
async fn the_archive_preview_gives_the_complete_central_directory_of_a_package() {
    let rig = rig();
    let archive = build(&[
        Entry::file(
            "META-INF/MANIFEST.MF",
            "Manifest-Version: 1.0\nMain-Class: example.Main\n",
        ),
        Entry::file("example/Main.class", "bytecode"),
        Entry::file("assets/icon.png", "png"),
        Entry::folder("empty/"),
        Entry::symlink("main-link", "example/Main.class"),
    ]);
    rig.backend
        .insert("tenant/app.jar", archive.clone(), "application/java-archive");
    let answer = get(&rig.app, true, &archive_target("app.jar", archive.len()), Method::GET).await;
    assert_eq!(answer.status, 200, "{}", answer.text);
    let payload = answer.json();
    assert_eq!(payload["container"], "Java archive");
    let entries = payload["entries"].as_array().cloned().unwrap_or_default();
    assert_eq!(entries.len(), 3);
    for entry in &entries {
        assert_ne!(entry["name"], "empty/");
        assert_ne!(entry["name"], "main-link");
    }
    assert_eq!(payload["package"]["Main class"], "example.Main");
    assert_eq!(payload["properties"]["Entries"], "5");
    assert_eq!(payload["properties"]["Folders"], "1");
    assert_eq!(entries[0]["method"], "Deflate");
    assert_eq!(entries[0]["modified"], "2026-03-04T12:00:00Z");
    let ranges = rig.backend.state().get_ranges.clone();
    exact_ranges(&ranges);
}

#[tokio::test]
async fn the_archive_preview_follows_the_configured_entry_limit() {
    let rig = rig_with(|config| config.runtime.max_archive_entries = 1);
    let archive = build(&[Entry::file("one.txt", "one.txt"), Entry::file("two.txt", "two.txt")]);
    rig.backend.insert("tenant/two.zip", archive.clone(), "application/zip");
    let answer = get(&rig.app, true, &archive_target("two.zip", archive.len()), Method::GET).await;
    assert_eq!(answer.status, 413, "{}", answer.text);
    assert!(
        answer.text.contains("configured complete preview limit is 1"),
        "{}",
        answer.text
    );
    assert!(
        answer.text.contains("the archive contains 2 entries"),
        "{}",
        answer.text
    );
    assert_eq!(answer.json()["error"]["code"], "archive_too_many_entries");
}

#[tokio::test]
async fn archive_formats_without_a_central_directory_have_no_automatic_preview() {
    let rig = rig();
    for extension in ["tar", "rar", "7z", "gz", "xz", "zst"] {
        let key = format!("file.{extension}");
        rig.backend
            .insert(&format!("tenant/{key}"), "data", "application/octet-stream");
        let answer = get(&rig.app, true, &archive_target(&key, 4), Method::GET).await;
        assert_eq!(answer.status, 415, ".{extension}: {}", answer.text);
        assert_eq!(answer.json()["error"]["code"], "unsupported_preview");
    }
}

#[tokio::test]
async fn an_object_that_is_not_an_archive_is_refused_with_invalid_zip() {
    let rig = rig();
    rig.backend
        .insert("tenant/broken.zip", "this is not an archive at all", "application/zip");
    let answer = get(&rig.app, true, &archive_target("broken.zip", 29), Method::GET).await;
    assert_eq!(answer.status, 422);
    assert_eq!(answer.json()["error"]["code"], "invalid_zip");
    assert_eq!(
        answer.json()["error"]["message"],
        "the object does not contain a readable ZIP central directory"
    );
}

#[tokio::test]
async fn the_archive_preview_reads_the_book_data_of_an_epub() {
    let rig = rig();
    let container = r#"<?xml version="1.0"?><container><rootfiles><rootfile full-path="OEBPS/content.opf"/></rootfiles></container>"#;
    let opf = r#"<package><metadata xmlns:dc="http://purl.org/dc/elements/1.1/"><dc:title>The Book</dc:title><dc:creator>Ada</dc:creator></metadata><manifest><item id="nav" href="nav.xhtml" properties="nav"/></manifest></package>"#;
    let nav = r#"<html><body><nav><ol><li><a href="c1.xhtml">Chapter 1</a></li></ol></nav></body></html>"#;
    let archive = build(&[
        Entry::stored("mimetype", "application/epub+zip"),
        Entry::file("META-INF/container.xml", container),
        Entry::file("OEBPS/content.opf", opf),
        Entry::file("OEBPS/nav.xhtml", nav),
    ]);
    rig.backend
        .insert("tenant/book.epub", archive.clone(), "application/epub+zip");
    let payload = get(&rig.app, true, &archive_target("book.epub", archive.len()), Method::GET)
        .await
        .json();
    assert_eq!(payload["container"], "EPUB");
    assert_eq!(payload["epub"]["title"], "The Book");
    assert_eq!(payload["epub"]["creators"][0], "Ada");
    assert_eq!(payload["epub"]["toc"][0]["label"], "Chapter 1");
    assert_eq!(payload["epub"]["toc"][0]["href"], "c1.xhtml");
    assert!(payload.get("package").is_none());
}

#[tokio::test]
async fn a_refusal_for_a_ceiling_keeps_its_own_answer() {
    let rig = rig();
    let archive = build(&[Entry::file("one.txt", "one.txt"), Entry::file("two.txt", "two.txt")]);
    rig.backend.insert("tenant/two.zip", archive.clone(), "application/zip");
    let ceilings = Ceilings::default();
    ceilings.lower(ACTION_READ, MAX_OBJECT_SIZE, 10);
    let ctx = OpCtx {
        ceilings: Some(Arc::new(ceilings)),
        ..OpCtx::default()
    };
    let answer = get_with(
        &rig.app,
        true,
        &archive_target("two.zip", archive.len()),
        Method::GET,
        ctx.clone(),
    )
    .await;
    assert_eq!(answer.status, 403, "{}", answer.text);
    assert_eq!(answer.json()["error"]["code"], "ceiling_exceeded");
    rig.backend.insert(
        "tenant/card.vcf",
        "BEGIN:VCARD\nFN:Ada\nEND:VCARD\nplus some more text\n",
        "text/vcard",
    );
    let answer = get_with(&rig.app, false, &structured_target("card.vcf"), Method::GET, ctx).await;
    assert_eq!(answer.status, 403, "{}", answer.text);
    assert_eq!(answer.json()["error"]["code"], "ceiling_exceeded");
}

#[tokio::test]
async fn an_archive_with_zip64_end_records_gives_its_declared_count_in_the_refusal() {
    let rig = rig_with(|config| config.runtime.max_archive_entries = 1);
    let plain = build(&[Entry::file("one.txt", "one.txt"), Entry::file("two.txt", "two.txt")]);
    // Replace the end record with a ZIP64 end record, its locator and an end record with the marker counts.
    let end = plain.len() - 22;
    let mut archive = plain[..end].to_vec();
    let directory_size = u32::from_le_bytes([plain[end + 12], plain[end + 13], plain[end + 14], plain[end + 15]]);
    let directory_offset = u32::from_le_bytes([plain[end + 16], plain[end + 17], plain[end + 18], plain[end + 19]]);
    let zip64_offset = archive.len() as u64;
    archive.extend_from_slice(&0x0606_4b50u32.to_le_bytes());
    archive.extend_from_slice(&44u64.to_le_bytes());
    archive.extend_from_slice(&45u16.to_le_bytes());
    archive.extend_from_slice(&45u16.to_le_bytes());
    archive.extend_from_slice(&0u32.to_le_bytes());
    archive.extend_from_slice(&0u32.to_le_bytes());
    archive.extend_from_slice(&2u64.to_le_bytes());
    archive.extend_from_slice(&2u64.to_le_bytes());
    archive.extend_from_slice(&u64::from(directory_size).to_le_bytes());
    archive.extend_from_slice(&u64::from(directory_offset).to_le_bytes());
    archive.extend_from_slice(&0x0706_4b50u32.to_le_bytes());
    archive.extend_from_slice(&0u32.to_le_bytes());
    archive.extend_from_slice(&zip64_offset.to_le_bytes());
    archive.extend_from_slice(&1u32.to_le_bytes());
    archive.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    archive.extend_from_slice(&[0, 0, 0, 0]);
    archive.extend_from_slice(&0xffffu16.to_le_bytes());
    archive.extend_from_slice(&0xffffu16.to_le_bytes());
    archive.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    archive.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    rig.backend.insert("tenant/big.zip", archive.clone(), "application/zip");
    let answer = get(&rig.app, true, &archive_target("big.zip", archive.len()), Method::GET).await;
    assert_eq!(answer.status, 413, "{}", answer.text);
    assert!(
        answer.text.contains("the archive contains 2 entries"),
        "{}",
        answer.text
    );
}

#[test]
fn only_the_zip_compatible_extensions_have_an_archive_preview() {
    for extension in ["zip", "jar", "war", "ear", "apk", "aar", "xpi", "crx", "vsix", "epub"] {
        assert!(is_zip_archive_extension(extension), ".{extension}");
    }
    for extension in ["tar", "rar", "7z", "gz", "xz", "zst", "", "ZIP"] {
        assert!(!is_zip_archive_extension(extension), ".{extension}");
    }
}
