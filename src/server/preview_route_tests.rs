// SPDX-License-Identifier: MIT OR Apache-2.0
//! The route tests of the previews, of the details, of the version routes, of the jobs and of the uploads. Each
//! request goes through the whole dispatch: the middlewares, the router and the handler. Some tests also check the
//! idle limits of the request bodies and of the streamed answers, and the start probes of a real application.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, HOST};
use http::{HeaderMap, HeaderValue, Method, Uri, Version};
use http_body_util::BodyExt;
use serde_json::{Value, json};

use super::middleware::IdleBody;
use super::testing::{
    TestRequest, TestResponse, app_of, app_with, bucket_config, collect, get, instance, instance_with, memory_app,
    test_config,
};
use crate::access::AccessLayer;
use crate::archive::zip::writer::{EntryHeader, ZipWriter};
use crate::common::app::App;
use crate::common::config::{AuthConfig, BucketConfig, PERMISSION_DELETE, PERMISSION_READ, PERMISSION_WRITE, Provider};
use crate::common::ctx::OpCtx;
use crate::common::error::Error;
use crate::common::query::query_escape;
use crate::common::storage::{ListPage, ObjectInfo};
use crate::common::time::Timestamp;
use crate::provider::SharedAuth;
use crate::testkit::{MemoryBackend, MemoryVersion};
use crate::uploads::{RESUME_TOKEN_HEADER, RESUME_TOKEN_VERSION, upload_id_from_token};

const WORD_TYPE: &str = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
const PRESENTATION_TYPE: &str = "application/vnd.ms-powerpoint.presentation.macroEnabled.12";

// --- Helpers -----------------------------------------------------------------------------------------------------

/// The application of the tests: `readonly` (read only) and `rw` (read, write and delete, root prefix `tenant/`) over
/// `backend`.
fn rw_app(backend: Arc<MemoryBackend>) -> Arc<App> {
    app_of(vec![
        instance(
            bucket_config("readonly", "", &[PERMISSION_READ]),
            Arc::new(MemoryBackend::with_objects(&[("readonly.txt", "read")])),
        ),
        instance(
            bucket_config("rw", "tenant/", &[PERMISSION_READ, PERMISSION_WRITE, PERMISSION_DELETE]),
            backend,
        ),
    ])
}

/// Send a request with a JSON body.
async fn send_json(app: &Arc<App>, method: &str, target: &str, value: &Value) -> TestResponse {
    TestRequest::new(method, target)
        .header("content-type", "application/json")
        .body(serde_json::to_vec(value).unwrap())
        .send(app)
        .await
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

/// Each range is an exact range `bytes=<start>-<end>` with `0 <= start <= end`, and at least one range exists.
fn require_exact_byte_ranges(ranges: &[String]) {
    assert!(!ranges.is_empty(), "the reader sent no range request");
    for value in ranges {
        let rest = value
            .strip_prefix("bytes=")
            .unwrap_or_else(|| panic!("range {value:?} is not an exact byte range"));
        let (start, end) = rest
            .split_once('-')
            .unwrap_or_else(|| panic!("range {value:?} is open or malformed"));
        let start: i64 = start.parse().unwrap_or_else(|_| panic!("range {value:?} is not valid"));
        let end: i64 = end.parse().unwrap_or_else(|_| panic!("range {value:?} is not valid"));
        assert!(start >= 0 && end >= start, "range {value:?} is not valid");
    }
}

/// One page of a listing with one object.
fn page(key: &str, size: i64, next: &str) -> ListPage {
    ListPage {
        objects: vec![ObjectInfo {
            key: key.to_owned(),
            size,
            ..ObjectInfo::default()
        }],
        prefixes: Vec::new(),
        next_page_token: next.to_owned(),
    }
}

/// A body that gives `chunks` chunks of 16 bytes, with `delay` before each chunk.
fn slow_body(chunks: usize, delay: Duration) -> crate::common::http::Body {
    let (sender, body) = crate::common::http::channel(1);
    tokio::spawn(async move {
        for _ in 0..chunks {
            tokio::time::sleep(delay).await;
            if sender.send(Bytes::from(vec![b'x'; 16])).await.is_err() {
                return;
            }
        }
    });
    body
}

/// Read a body to its end. An error of the body stops the test.
async fn body_length(mut body: impl http_body::Body<Data = Bytes, Error = Error> + Unpin) -> usize {
    let mut total = 0;
    while let Some(frame) = body.frame().await {
        let frame = frame.unwrap_or_else(|error| panic!("the body stopped with an error: {error:?}"));
        if let Ok(data) = frame.into_data() {
            total += data.len();
        }
    }
    total
}

// --- The idle limits of the bodies ----------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stalled_put_body_gives_back_its_storage_slot() {
    let mut config = test_config();
    config.runtime.max_concurrent_requests_per_storage = 1;
    let backend = Arc::new(MemoryBackend::with_objects(&[("tenant/folder/direct.txt", "direct")]));
    let rw = instance_with(
        &config,
        bucket_config("rw", "tenant/", &[PERMISSION_READ, PERMISSION_WRITE, PERMISSION_DELETE]),
        backend.clone(),
    );
    let app = app_with(config, vec![rw]);

    // The client declares 1000 bytes, sends 10 bytes, then sends nothing more.
    let (sender, stalled) = crate::common::http::channel(1);
    sender.send(Bytes::from_static(b"abcdefghij")).await.unwrap();
    let mut headers = HeaderMap::new();
    headers.insert(HOST, HeaderValue::from_static("example.com"));
    headers.insert(CONTENT_LENGTH, HeaderValue::from_static("1000"));
    let body = IdleBody::new(stalled, Duration::from_millis(300)).boxed_unsync();
    let uri: Uri = "/s3?instance=rw&key=stalled.bin".parse().unwrap();
    let Ok((req, target)) = super::runtime::request_from_parts(Method::PUT, &uri, Version::HTTP_11, headers, body)
    else {
        panic!("the request of the test is not valid");
    };
    let put_app = app.clone();
    let put = tokio::spawn(async move {
        let response = super::handle(put_app, req, target).await;
        collect(super::runtime::finalize(&Method::PUT, response).await).await
    });
    // The stalled upload now holds the only storage slot of the instance.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let started = Instant::now();
    let answer = tokio::time::timeout(
        Duration::from_secs(3),
        get(&app, "/s3?instance=rw&key=folder/direct.txt"),
    )
    .await
    .unwrap_or_else(|_| panic!("the read waits behind the stalled upload"));
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert_eq!(answer.text(), "direct");
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "the slot became free only after {:?}",
        started.elapsed()
    );

    // The stalled request gets an error answer: it does not wait without end.
    let stalled_answer = tokio::time::timeout(Duration::from_secs(2), put)
        .await
        .unwrap_or_else(|_| panic!("the stalled upload got no answer"))
        .unwrap();
    assert_ne!(stalled_answer.status, 204, "{}", stalled_answer.text());
    assert!(!backend.contains("tenant/stalled.bin"));
    drop(sender);
}

#[tokio::test]
async fn an_idle_limit_lets_a_slow_body_go_on_while_each_chunk_comes_in_time() {
    // 8 chunks of 16 bytes, 80 ms apart: 640 ms in total, more than three idle periods of 200 ms.
    let body = IdleBody::new(slow_body(8, Duration::from_millis(80)), Duration::from_millis(200));
    assert_eq!(body_length(body).await, 8 * 16);
}

#[tokio::test]
async fn a_streamed_answer_lets_a_slow_source_go_on_while_the_client_reads() {
    let (sender, body) = crate::archive::stream::stream(Duration::from_millis(200));
    tokio::spawn(async move {
        for _ in 0..8 {
            tokio::time::sleep(Duration::from_millis(80)).await;
            if sender.send(Bytes::from(vec![b'x'; 16])).await.is_err() {
                return;
            }
        }
        sender.finish();
    });
    assert_eq!(body_length(body).await, 8 * 16);
}

#[tokio::test]
async fn an_idle_limit_stops_a_stalled_body_with_a_timeout() {
    let (sender, stalled) = crate::common::http::channel(1);
    let mut body = IdleBody::new(stalled, Duration::from_millis(300));
    let started = Instant::now();
    match body.frame().await {
        Some(Err(error)) => assert_eq!(error, Error::Timeout),
        other => panic!("a stalled body gave {other:?}"),
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(250) && elapsed < Duration::from_secs(2),
        "the idle limit fired after {elapsed:?}"
    );
    // After the timeout, the body keeps the error.
    assert!(matches!(body.frame().await, Some(Err(Error::Timeout))));
    drop(sender);
}

// --- The listing -------------------------------------------------------------------------------------------------

#[tokio::test]
async fn an_unlimited_scan_reads_each_page_and_gives_no_continuation_token() {
    let backend = Arc::new(MemoryBackend::new());
    backend.state().list_pages = vec![
        page("tenant/a.txt", 1, "page-1"),
        page("tenant/b.txt", 2, "page-2"),
        page("tenant/c.txt", 3, ""),
    ];
    let mut cfg = bucket_config("rw", "tenant/", &[PERMISSION_READ, PERMISSION_WRITE, PERMISSION_DELETE]);
    cfg.max_scan_pages = 0;
    let app = app_of(vec![instance(cfg, backend.clone())]);

    let answer = get(&app, "/api/list?instance=rw&delimiter=/").await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    let listing = answer.json();
    assert_eq!(listing["scanComplete"], true);
    assert_eq!(listing["sortAvailable"], true);
    assert!(listing.get("nextContinuationToken").is_none(), "{listing}");
    assert_eq!(listing["items"].as_array().unwrap().len(), 3);
    assert_eq!(backend.state().list_calls, 3);

    let continued = get(&app, "/api/list?instance=rw&delimiter=/&continuationToken=page-2")
        .await
        .json();
    assert_eq!(continued["scanComplete"], true);
    assert_eq!(continued["sortAvailable"], false);
    assert_eq!(continued["items"].as_array().unwrap().len(), 1);
}

// --- The details and the explicit counts ---------------------------------------------------------------------------

#[tokio::test]
async fn the_details_of_a_tsv_read_no_object_and_its_count_reads_it_one_time() {
    let backend = Arc::new(MemoryBackend::new());
    backend.insert(
        "tenant/table.tsv",
        "name\tvalue\nalpha\t1\nbeta\t2\n",
        "text/tab-separated-values",
    );
    let app = rw_app(backend.clone());

    let details = get(
        &app,
        "/api/media-info?instance=rw&key=table.tsv&size=30&mime=text%2Ftab-separated-values",
    )
    .await;
    assert_eq!(details.status, 200, "{}", details.text());
    {
        let state = backend.state();
        assert_eq!(
            (state.get_count, state.head_count),
            (0, 1),
            "the details read the object"
        );
    }

    let count = get(&app, "/api/document-count?instance=rw&key=table.tsv").await;
    assert_eq!(count.status, 200, "{}", count.text());
    let result = count.json();
    assert_eq!(
        (result["rows"].clone(), result["columns"].clone()),
        (json!(2), json!(2))
    );
    assert_eq!(backend.state().get_count, 1);
}

/// The details of an Office package through `/api/media-info`, with the size and the media type of the listing.
async fn office_details(app: &Arc<App>, key: &str, size: usize, media_type: &str) -> Value {
    let target = format!(
        "/api/media-info?instance=rw&key={key}&size={size}&mime={}",
        query_escape(media_type)
    );
    let answer = get(app, &target).await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    answer.json()
}

#[tokio::test]
async fn the_word_details_read_only_the_property_parts_with_exact_ranges() {
    let backend = Arc::new(MemoryBackend::new());
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
    backend.insert("tenant/report.docx", archive.clone(), WORD_TYPE);
    let app = rw_app(backend.clone());

    let details = office_details(&app, "report.docx", archive.len(), WORD_TYPE).await;
    assert_eq!(details["container"], "Microsoft Word Open XML", "{details}");
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
        assert_eq!(details["properties"][label], want, "{label}: {details}");
    }
    assert!(
        backend.bytes_read() < archive.len() as i64,
        "the details read the complete package"
    );
    require_exact_byte_ranges(&backend.state().get_ranges);
}

#[tokio::test]
async fn the_presentation_details_use_only_the_package_metadata_with_exact_ranges() {
    let backend = Arc::new(MemoryBackend::new());
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
    backend.insert("tenant/deck.pptm", archive.clone(), PRESENTATION_TYPE);
    let app = rw_app(backend.clone());

    let details = office_details(&app, "deck.pptm", archive.len(), PRESENTATION_TYPE).await;
    assert_eq!(
        details["container"], "Microsoft PowerPoint macro-enabled presentation",
        "{details}"
    );
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
        assert_eq!(details["properties"][label], want, "{label}: {details}");
    }
    assert!(
        backend.bytes_read() < archive.len() as i64,
        "the details read the complete package"
    );
    require_exact_byte_ranges(&backend.state().get_ranges);
}

// --- The structured preview -------------------------------------------------------------------------------------

#[tokio::test]
async fn the_structured_preview_gives_one_contact_one_event_the_text_of_an_email_and_the_raw_key() {
    let backend = Arc::new(MemoryBackend::new());
    let private_key = "-----BEGIN PRIVATE KEY-----\nAQIDBA==\n-----END PRIVATE KEY-----\n";
    backend.insert(
        "tenant/person.vcf",
        "BEGIN:VCARD\r\nVERSION:4.0\r\nFN:Ada Lovelace\r\nORG:Analytical Engines\r\nEMAIL:ada@example.test\r\nTEL:+33123456789\r\nEND:VCARD\r\n",
        "text/vcard",
    );
    backend.insert(
        "tenant/event.ics",
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nX-WR-CALNAME:Reviews\r\nBEGIN:VEVENT\r\nUID:review@example.test\r\nSUMMARY:Architecture review\r\nDTSTART:20260725T080000Z\r\nDTEND:20260725T090000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
        "text/calendar",
    );
    backend.insert(
        "tenant/message.eml",
        "From: Ada <ada@example.test>\r\nTo: Grace <grace@example.test>\r\nSubject: Review\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<p>Hello <img src=\"https://external.invalid/pixel.png\"></p>",
        "message/rfc822",
    );
    backend.insert("tenant/secret.key", private_key, "application/x-pem-file");
    let app = rw_app(backend);
    let preview = |key: &'static str| {
        let app = app.clone();
        async move {
            let answer = get(&app, &format!("/api/structured-preview?instance=rw&key={key}")).await;
            assert_eq!(answer.status, 200, "{key}: {}", answer.text());
            answer.json()
        }
    };

    let contact = preview("person.vcf").await;
    assert_eq!(contact["kind"], "contact");
    let contacts = contact["contacts"].as_array().unwrap();
    assert_eq!(contacts.len(), 1, "{contact}");
    assert_eq!(contacts[0]["name"], "Ada Lovelace");

    let calendar = preview("event.ics").await;
    assert_eq!(calendar["kind"], "calendar");
    let events = calendar["calendar"]["events"].as_array().unwrap();
    assert_eq!(events.len(), 1, "{calendar}");
    assert_eq!(events[0]["summary"], "Architecture review");

    let email = preview("message.eml").await;
    assert_eq!(email["kind"], "email");
    assert_eq!(email["email"]["headers"]["Subject"], "Review");
    assert!(
        email["email"]["bodyText"].as_str().is_some_and(|text| !text.is_empty()),
        "the text preview of the email is empty: {email}"
    );

    let key = preview("secret.key").await;
    assert_eq!(key["kind"], "certificate");
    assert_eq!(key["raw"], private_key);
    assert_eq!(key["rawEncoding"], "text");
}

// --- The versions ---------------------------------------------------------------------------------------------------

fn version(id: &str, data: &'static str, modified: Timestamp, current: bool, delete_marker: bool) -> MemoryVersion {
    MemoryVersion {
        id: id.to_owned(),
        data: Bytes::from_static(data.as_bytes()),
        content_type: "text/plain".to_owned(),
        modified: Some(modified),
        current,
        delete_marker,
    }
}

#[tokio::test]
async fn the_gateway_reads_the_version_that_the_request_names() {
    let backend = Arc::new(MemoryBackend::new().with_versions());
    let now = Timestamp::now();
    backend.add_version("tenant/versioned.txt", version("v2", "current", now, true, false));
    backend.add_version(
        "tenant/versioned.txt",
        version("v1", "previous", now.plus_secs(-3600), false, false),
    );
    backend.add_version(
        "tenant/versioned.txt",
        version("delete-marker", "", now.plus_secs(-7200), false, true),
    );
    let app = rw_app(backend);
    app.instance("rw").unwrap().set_versioning_available(true);

    let answer = get(&app, "/s3?instance=rw&key=versioned.txt&version=v1").await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert_eq!(answer.text(), "previous");
}

#[tokio::test]
async fn a_probe_that_gets_501_hides_the_versions_from_the_instances_and_the_routes() {
    let backend = Arc::new(MemoryBackend::with_objects(&[("tenant/folder/direct.txt", "direct")]).with_versions());
    backend.state().version_list_error = Some(Error::upstream(
        501,
        "NotImplemented",
        "version listing is not implemented",
    ));
    let app = rw_app(backend);
    let rw = app.instance("rw").unwrap().clone();
    assert!(!rw.probe_versioning(&OpCtx::default()).await);
    assert!(!rw.versioning_available());

    let instances = get(&app, "/api/instances").await;
    assert_eq!(instances.status, 200, "{}", instances.text());
    let listed = instances.json();
    let entry = listed["instances"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == "rw")
        .cloned()
        .unwrap_or_else(|| panic!("no instance rw: {listed}"));
    assert_eq!(entry["versioningSupported"], false, "{entry}");

    let versions = get(&app, "/api/versions?instance=rw&key=versioned.txt").await;
    assert_eq!(versions.status, 501, "{}", versions.text());
}

/// A provider that answers `501 Not Implemented` to each request with the parameter `versions` and counts them, and
/// `404` to each other request.
async fn versions_server(probes: Arc<AtomicUsize>) -> String {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let probes = probes.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut buffer = [0u8; 1024];
                while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(count) => head.extend_from_slice(&buffer[..count]),
                    }
                }
                let text = String::from_utf8_lossy(&head).into_owned();
                let target = text
                    .lines()
                    .next()
                    .and_then(|line| line.split(' ').nth(1))
                    .unwrap_or("")
                    .to_owned();
                let query = target.split_once('?').map_or("", |(_, query)| query);
                let versions = query.split('&').any(|pair| pair.split('=').next() == Some("versions"));
                let answer: &str = if versions {
                    probes.fetch_add(1, Ordering::SeqCst);
                    "HTTP/1.1 501 Not Implemented\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 16\r\nConnection: close\r\n\r\nNot Implemented\n"
                } else {
                    "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 19\r\nConnection: close\r\n\r\n404 page not found\n"
                };
                let _ = stream.write_all(answer.as_bytes()).await;
            });
        }
    });
    format!("http://{address}")
}

#[tokio::test]
async fn the_start_probe_hides_the_versions_of_a_provider_that_answers_501() {
    let probes = Arc::new(AtomicUsize::new(0));
    let endpoint = versions_server(probes.clone()).await;
    let mut config = test_config();
    config.auths = vec![AuthConfig {
        id: "garage".to_owned(),
        provider: Provider::S3,
        mode: "anonymous".to_owned(),
        endpoint,
        region: "garage".to_owned(),
        ..AuthConfig::default()
    }];
    config.buckets = vec![BucketConfig {
        id: "garage".to_owned(),
        name: "Garage".to_owned(),
        auth_id: "garage".to_owned(),
        provider: "s3".to_owned(),
        bucket: "objects".to_owned(),
        region: "garage".to_owned(),
        permissions: vec![PERMISSION_READ.to_owned()],
        permissions_defined: true,
        max_scan_pages: 1,
        ..BucketConfig::default()
    }];
    let app = super::start_app(config).await.unwrap();
    assert_eq!(probes.load(Ordering::SeqCst), 1, "the probes of the versions");
    assert!(!app.instance("garage").unwrap().versioning_available());

    let answer = get(&app, "/api/instances").await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    let listed = answer.json();
    let instances = listed["instances"].as_array().unwrap();
    assert_eq!(instances.len(), 1, "{listed}");
    assert_eq!(instances[0]["versioningSupported"], false, "{listed}");
    super::close_app(&app);
}

// --- The routes that do not exist --------------------------------------------------------------------------------

#[tokio::test]
async fn the_global_analysis_routes_do_not_exist() {
    let (app, _, _) = memory_app();
    for target in ["/api/compare", "/api/duplicates", "/api/checksum-manifest"] {
        let answer = get(&app, target).await;
        assert_eq!(answer.status, 404, "{target}: {}", answer.text());
    }
}

// --- The jobs ----------------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_copy_of_a_prefix_through_the_route_runs_as_a_job_in_memory() {
    let (app, _, rw) = memory_app();
    let answer = send_json(
        &app,
        "POST",
        "/api/copy",
        &json!({"instance": "rw", "src": "folder/", "dst": "copied/", "isPrefix": true}),
    )
    .await;
    assert_eq!(answer.status, 202, "{}", answer.text());
    let created = answer.json();
    let id = created["id"].as_str().unwrap().to_owned();
    assert_eq!(created["type"], "copy_prefix");
    let job = app
        .jobs
        .wait_for_terminal(&id, Duration::from_secs(10))
        .await
        .unwrap_or_else(|| panic!("the job {id} did not end"));
    assert_eq!(job.status, "completed", "{job:?}");
    assert_eq!(job.processed, 2);
    assert_eq!(rw.object("tenant/copied/direct.txt").unwrap().data, "direct");
    assert_eq!(rw.object("tenant/copied/nested/deep.txt").unwrap().data, "deep");
}

// --- The uploads ---------------------------------------------------------------------------------------------------

/// Create an upload of the instance `rw` through the route. The answer must be 201.
async fn create_upload(app: &Arc<App>, key: &str, size: i64) -> TestResponse {
    let answer = send_json(
        app,
        "POST",
        "/api/uploads",
        &json!({"instance": "rw", "key": key, "size": size, "contentType": "application/octet-stream"}),
    )
    .await;
    assert_eq!(answer.status, 201, "{}", answer.text());
    answer
}

/// The resume token of the answer of a creation.
fn resume_token(created: &TestResponse) -> String {
    created.json()["resumeToken"].as_str().unwrap_or("").to_owned()
}

/// Send a chunk of an upload through the route. The answer must be 200.
async fn put_chunk(app: &Arc<App>, token: &str, data: Vec<u8>, start: i64, end: i64, total: i64) -> Value {
    let answer = TestRequest::new("PUT", "/api/uploads")
        .header("content-type", "application/octet-stream")
        .header("content-range", &format!("bytes {start}-{end}/{total}"))
        .header(RESUME_TOKEN_HEADER, token)
        .body(data)
        .send(app)
        .await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    answer.json()
}

/// The id of the only incomplete multipart upload of a memory back end.
fn provider_upload_id(backend: &MemoryBackend) -> String {
    let state = backend.state();
    assert_eq!(state.multipart.len(), 1, "the incomplete uploads of the back end");
    state.multipart.keys().next().cloned().unwrap_or_default()
}

#[tokio::test]
async fn an_upload_through_the_routes_uses_an_opaque_token_and_frees_its_state_at_the_end() {
    const CHUNK: i64 = 16 << 20;
    const TOTAL: i64 = CHUNK + 17;
    let backend = Arc::new(MemoryBackend::new());
    let app = rw_app(backend.clone());

    let created = create_upload(&app, "large.bin", TOTAL).await;
    let text = created.text();
    assert!(
        !text.contains("provider_upload_id") && !text.contains("session_url"),
        "the answer shows the provider session: {text}"
    );
    let token = resume_token(&created);
    assert!(
        token.starts_with(&format!("{RESUME_TOKEN_VERSION}.")),
        "resume token {token:?}"
    );
    assert_eq!(created.json()["chunkSize"], CHUNK);

    let progress = put_chunk(&app, &token, vec![b'a'; CHUNK as usize], 0, CHUNK - 1, TOTAL).await;
    assert_eq!(progress["status"], "uploading", "{progress}");
    assert_eq!(progress["uploadedBytes"], CHUNK);

    let last = vec![b'b'; (TOTAL - CHUNK) as usize];
    let completed = put_chunk(&app, &token, last, CHUNK, TOTAL - 1, TOTAL).await;
    assert_eq!(completed["status"], "completed", "{completed}");
    assert_eq!(completed["verified"], true);
    assert_eq!(completed["uploadedBytes"], TOTAL);
    assert!(
        app.uploads.get(&upload_id_from_token(&token)).is_none(),
        "the completed upload stays in the memory of the server"
    );
    assert_eq!(backend.object("tenant/large.bin").unwrap().data.len() as i64, TOTAL);
}

/// The shared clients of the auth block `test-auth` of the instances of the tests, with S3 credentials. The key of
/// the resume tokens comes from these credentials.
fn credential_auths() -> BTreeMap<String, Arc<SharedAuth>> {
    let auth = AuthConfig {
        id: "test-auth".to_owned(),
        provider: Provider::S3,
        mode: "access_key".to_owned(),
        endpoint: "http://127.0.0.1:9".to_owned(),
        region: "test".to_owned(),
        access_key_id: "AKIDTEST".to_owned(),
        secret_access_key: "secret-of-the-test".to_owned(),
        ..AuthConfig::default()
    };
    BTreeMap::from([("test-auth".to_owned(), Arc::new(SharedAuth::new(&auth).unwrap()))])
}

/// A new application over the same instances and auth blocks: its upload manager is empty and its random key is
/// new.
fn fresh_app(instances: Vec<Arc<crate::instance::Instance>>, auths: BTreeMap<String, Arc<SharedAuth>>) -> Arc<App> {
    let config = test_config();
    let access = AccessLayer::new(&config).unwrap();
    super::assemble::assemble(Arc::new(config), auths, instances, access).unwrap()
}

#[tokio::test]
async fn a_resume_token_rebuilds_the_upload_through_the_route_without_the_memory_of_the_server() {
    const TOTAL: i64 = 20 << 20;
    let backend = Arc::new(MemoryBackend::new());
    let instances = vec![instance(
        bucket_config("rw", "tenant/", &[PERMISSION_READ, PERMISSION_WRITE, PERMISSION_DELETE]),
        backend.clone(),
    )];
    let auths = credential_auths();
    let first = fresh_app(instances.clone(), auths.clone());

    let created = create_upload(&first, "resume.bin", TOTAL).await;
    let token = resume_token(&created);
    // The first part goes to the provider directly: only the token and the provider session stay.
    let upload_id = provider_upload_id(&backend);
    backend
        .state()
        .multipart
        .get_mut(&upload_id)
        .unwrap()
        .parts
        .insert(1, Bytes::from(vec![b'r'; 5 << 20]));

    // A new process has an empty upload manager and a new random key; the credentials give the same token key.
    let second = fresh_app(instances, auths);
    let opened = crate::uploads::open_resume_token(&token, &*second, Timestamp::now());
    let Ok((descriptor, _)) = opened else {
        panic!("a new application cannot open the token of the client");
    };
    assert_eq!(descriptor.provider_upload_id, upload_id);

    let answer = send_json(&second, "POST", "/api/uploads/resume", &json!({"resumeToken": token})).await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    let resumed = answer.json();
    assert_eq!(resumed["uploadedBytes"], 5 << 20, "{resumed}");
    assert_eq!(resumed["partCount"], 1, "{resumed}");
    assert_eq!(resumed["status"], "uploading", "{resumed}");
}

#[tokio::test]
async fn a_cancel_through_the_route_aborts_the_provider_upload_and_frees_the_memory() {
    let backend = Arc::new(MemoryBackend::new());
    let app = rw_app(backend.clone());
    let created = create_upload(&app, "cancel.bin", 8 << 20).await;
    let token = resume_token(&created);
    let upload_id = provider_upload_id(&backend);

    let answer = TestRequest::new("DELETE", "/api/uploads")
        .header(RESUME_TOKEN_HEADER, &token)
        .send(&app)
        .await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert!(
        !backend.state().multipart.contains_key(&upload_id),
        "the provider upload stays open"
    );
    assert!(
        app.uploads.get(&upload_id_from_token(&token)).is_none(),
        "the canceled upload stays in the memory of the server"
    );
}
