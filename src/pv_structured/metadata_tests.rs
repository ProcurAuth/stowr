//! The tests of the structured details of the objects.

use std::sync::Arc;

use super::metadata::inspect_structured_metadata;
use super::testzip::{Entry, build};
use crate::common::ctx::OpCtx;
use crate::instance::Instance;
use crate::pv_media::MediaSourceMetadata;
use crate::testkit::{MemoryBackend, bucket_config, instance_over};

fn instance_with(backend: &Arc<MemoryBackend>) -> Arc<Instance> {
    Arc::new(instance_over(bucket_config("meta", "", &["read"]), backend.clone()))
}

fn listed(size: usize) -> MediaSourceMetadata {
    MediaSourceMetadata {
        size: size as i64,
        ..MediaSourceMetadata::default()
    }
}

#[tokio::test]
async fn the_details_of_small_text_formats_have_a_container_and_the_first_values() {
    let backend = Arc::new(MemoryBackend::new());
    backend.insert(
        "person.vcf",
        "BEGIN:VCARD\nVERSION:4.0\nFN:Ada Lovelace\nORG:Analytical Engines\nEMAIL:ada@example.test\nTEL:+33123456789\nEND:VCARD\n",
        "text/vcard",
    );
    backend.insert(
        "event.ics",
        "BEGIN:VCALENDAR\nVERSION:2.0\nPRODID:-//Example//EN\nBEGIN:VEVENT\nSUMMARY:Review\nDTSTART:20260725T080000Z\nDTEND:20260725T090000Z\nEND:VEVENT\nEND:VCALENDAR\n",
        "text/calendar",
    );
    backend.insert(
        "message.eml",
        "From: Ada <ada@example.test>\r\nTo: Grace <grace@example.test>\r\nSubject: Metadata\r\nDate: Sat, 25 Jul 2026 08:00:00 +0000\r\nMessage-ID: <one@example.test>\r\n\r\nBody not inspected by metadata.",
        "message/rfc822",
    );
    backend.insert(
        "cert.pem",
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
        "application/x-pem-file",
    );
    let instance = instance_with(&backend);
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
        let size = backend.object(key).map_or(0, |object| object.data.len());
        let summary = inspect_structured_metadata(
            &OpCtx::default(),
            &instance,
            key,
            extension,
            content_type,
            &listed(size),
        )
        .await
        .unwrap()
        .unwrap_or_else(|| panic!("{key} is not handled"));
        assert_eq!(summary.container, container, "{key}");
        assert_eq!(
            summary.properties.get(property).map(String::as_str),
            Some(want),
            "{key}"
        );
        assert_eq!(summary.size, size as i64, "{key}");
        assert!(!summary.headers.is_empty(), "{key}");
    }
}

#[tokio::test]
async fn the_details_of_other_objects_are_not_handled() {
    let backend = Arc::new(MemoryBackend::with_objects(&[("notes.txt", "plain")]));
    let instance = instance_with(&backend);
    let result = inspect_structured_metadata(
        &OpCtx::default(),
        &instance,
        "notes.txt",
        "txt",
        "text/plain",
        &listed(5),
    )
    .await
    .unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn the_details_of_a_pdf_come_from_its_first_and_last_bytes() {
    let backend = Arc::new(MemoryBackend::new());
    let mut data = b"%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n".to_vec();
    data.extend(std::iter::repeat_n(b' ', 600_000));
    data.extend_from_slice(b"5 0 obj << /Title (Report) /Author (Ada) >> endobj\n2 0 obj << /Type /Pages /Count 3 >> endobj\ntrailer << /Info 5 0 R /Root 1 0 R >>");
    backend.insert("report.pdf", data.clone(), "application/pdf");
    let instance = instance_with(&backend);
    let summary = inspect_structured_metadata(
        &OpCtx::default(),
        &instance,
        "report.pdf",
        "pdf",
        "application/pdf",
        &listed(data.len()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(summary.container, "PDF");
    assert_eq!(summary.properties.get("PDF version").map(String::as_str), Some("1.7"));
    assert_eq!(summary.properties.get("Pages").map(String::as_str), Some("3"));
    assert_eq!(summary.properties.get("Title").map(String::as_str), Some("Report"));
    assert_eq!(summary.properties.get("Author").map(String::as_str), Some("Ada"));
    assert_eq!(
        summary.properties.get("Object size").map(String::as_str),
        Some(data.len().to_string().as_str())
    );
    let ranges = backend.state().get_ranges.clone();
    assert!(
        ranges
            .iter()
            .all(|range| range.starts_with("bytes=") && !range.contains("bytes=-")),
        "{ranges:?}"
    );
}

#[tokio::test]
async fn the_details_of_a_package_come_from_its_central_directory() {
    let backend = Arc::new(MemoryBackend::new());
    let archive = build(&[
        Entry::file(
            "META-INF/MANIFEST.MF",
            "Manifest-Version: 1.0\nMain-Class: example.Main\n",
        ),
        Entry::file("example/Main.class", &"bytecode ".repeat(50)),
        Entry::folder("empty/"),
    ]);
    backend.insert("app.jar", archive.clone(), "application/java-archive");
    let instance = instance_with(&backend);
    let summary = inspect_structured_metadata(
        &OpCtx::default(),
        &instance,
        "app.jar",
        "jar",
        "application/java-archive",
        &listed(archive.len()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(summary.container, "Java archive");
    assert_eq!(summary.properties.get("Entries").map(String::as_str), Some("3"));
    assert_eq!(summary.properties.get("Folders").map(String::as_str), Some("1"));
    assert_eq!(
        summary.properties.get("Main class").map(String::as_str),
        Some("example.Main")
    );
    assert!(summary.properties.contains_key("Compression ratio"));
}

#[tokio::test]
async fn a_package_that_is_not_readable_has_a_container_and_no_property() {
    let backend = Arc::new(MemoryBackend::new());
    backend.insert("broken.zip", "this is not an archive", "application/zip");
    let instance = instance_with(&backend);
    let summary = inspect_structured_metadata(
        &OpCtx::default(),
        &instance,
        "broken.zip",
        "zip",
        "application/zip",
        &listed(22),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(summary.container, "ZIP archive");
    assert!(summary.properties.is_empty());
}

#[tokio::test]
async fn a_large_text_object_has_the_container_and_the_headers_of_a_head_request() {
    let backend = Arc::new(MemoryBackend::new());
    let big = "BEGIN:VCARD\nFN:Big\nEND:VCARD\n".to_owned() + &"x".repeat(1 << 20);
    backend.insert("big.vcf", big.clone(), "text/vcard");
    let instance = instance_with(&backend);
    let summary = inspect_structured_metadata(
        &OpCtx::default(),
        &instance,
        "big.vcf",
        "vcf",
        "text/vcard",
        &listed(big.len()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(summary.container, "vCard contact");
    assert!(summary.properties.is_empty());
    assert_eq!(summary.size, big.len() as i64);
    assert_eq!(backend.state().head_count, 1);
}

#[tokio::test]
async fn the_details_find_the_size_of_an_object_that_the_listing_did_not_give() {
    let backend = Arc::new(MemoryBackend::new());
    backend.insert("person.vcf", "BEGIN:VCARD\nFN:Ada\nEND:VCARD\n", "text/vcard");
    let instance = instance_with(&backend);
    let summary = inspect_structured_metadata(
        &OpCtx::default(),
        &instance,
        "person.vcf",
        "vcf",
        "text/vcard",
        &listed(0),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(summary.properties.get("Name").map(String::as_str), Some("Ada"));
    assert!(summary.size > 0);
}
