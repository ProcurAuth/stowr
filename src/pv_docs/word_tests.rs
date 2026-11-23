// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tests of the preview of Word documents.

use super::*;
use crate::pv_docs::test_support::{get, put, setup, zip_bytes};

const DOCUMENT: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>
<w:p><w:pPr><w:pStyle w:val="Heading2"/></w:pPr><w:r><w:t>Title here</w:t></w:r></w:p>
<w:p><w:r><w:t>Hello</w:t><w:tab/><w:t>world</w:t><w:br/><w:t xml:space="preserve"> next </w:t></w:r></w:p>
<w:p><w:pPr><w:numPr><w:ilvl w:val="1"/><w:numId w:val="3"/></w:numPr></w:pPr><w:r><w:t>item</w:t></w:r></w:p>
<w:p><w:pPr><w:outlineLvl w:val="0"/></w:pPr><w:r><w:t>Outline</w:t></w:r></w:p>
<w:p></w:p>
<w:p><w:r><w:delText>gone</w:delText></w:r><w:r><w:t>kept &amp; safe</w:t></w:r></w:p>
<w:tbl><w:tr><w:tc><w:p><w:r><w:t>a</w:t></w:r></w:p><w:p><w:r><w:t>b</w:t></w:r></w:p></w:tc><w:tc><w:p><w:r><w:t>c</w:t></w:r></w:p></w:tc></w:tr>
<w:tr><w:tc><w:p/></w:tc></w:tr></w:tbl>
<w:tbl><w:tr><w:tc><w:p/></w:tc></w:tr></w:tbl>
</w:body></w:document>"#;

fn docx() -> Vec<u8> {
    zip_bytes(
        &[("[Content_Types].xml", "<Types/>"), ("word/document.xml", DOCUMENT)],
        true,
    )
}

#[tokio::test]
async fn the_preview_gives_the_blocks_of_a_document() {
    let (app, backend) = setup();
    put(&backend, "doc.docx", docx(), "application/octet-stream");
    let response = get(&app, "/api/document/word?instance=rw&key=doc.docx")
        .await
        .decode::<WordPreview>();
    assert_eq!((response.instance.as_str(), response.key.as_str()), ("rw", "doc.docx"));
    let kinds: Vec<(&str, &str, i64)> = response
        .blocks
        .iter()
        .map(|block| (block.kind.as_str(), block.text.as_str(), block.level))
        .collect();
    assert_eq!(
        kinds,
        [
            ("heading", "Title here", 2),
            ("paragraph", "Hello\tworld\nnext", 0),
            ("list-item", "item", 2),
            ("heading", "Outline", 1),
            ("paragraph", "gonekept & safe", 0),
            ("table", "", 0),
            ("table", "", 0),
        ]
    );
    let table = &response.blocks[5];
    assert_eq!(
        table.rows,
        [vec!["a\nb".to_owned(), "c".to_owned()], vec![String::new()]]
    );
    assert!(!response.truncated && !response.macros_ignored);
    assert!(response.storage_bytes > 0 && response.storage_requests > 0);
}

#[tokio::test]
async fn a_docm_has_its_macros_ignored() {
    let (app, backend) = setup();
    put(&backend, "doc.docm", docx(), "application/octet-stream");
    let size = docx().len();
    let response = get(
        &app,
        &format!("/api/document/word?instance=rw&key=doc.docm&size={size}"),
    )
    .await
    .decode::<WordPreview>();
    assert!(response.macros_ignored);
}

#[tokio::test]
async fn the_route_explains_a_package_that_it_cannot_read() {
    let (app, backend) = setup();
    put(&backend, "text.docx", b"not a package at all".to_vec(), "text/plain");
    put(
        &backend,
        "nodoc.docx",
        zip_bytes(&[("a.txt", "x")], false),
        "application/octet-stream",
    );
    put(
        &backend,
        "badxml.docx",
        zip_bytes(&[("word/document.xml", "<w:p><w:t>x</w:p>")], false),
        "application/octet-stream",
    );
    for (target, status, code) in [
        ("/api/document/word?instance=rw&key=text.docx", 422, "invalid_docx"),
        ("/api/document/word?instance=rw&key=nodoc.docx", 422, "invalid_docx"),
        (
            "/api/document/word?instance=rw&key=badxml.docx",
            422,
            "invalid_docx_xml",
        ),
        (
            "/api/document/word?instance=rw&key=nodoc.docx&size=-1",
            400,
            "invalid_size",
        ),
        (
            "/api/document/word?instance=rw&key=nodoc.docx&size=x",
            400,
            "invalid_size",
        ),
        ("/api/document/word?instance=rw&key=", 400, "missing_key"),
        ("/api/document/word?instance=rw", 400, "missing_key"),
    ] {
        let called = get(&app, target).await;
        assert_eq!(
            (called.status, called.code().as_str()),
            (status, code),
            "{target}: {}",
            called.text()
        );
    }
    let called = get(&app, "/api/document/word?instance=rw&key=nodoc.docx").await;
    assert_eq!(called.message(), "the DOCX package is missing word/document.xml");
}

#[test]
fn a_limit_stops_the_read_of_the_text() {
    let mut limits = Limits::default();
    let text = "é".repeat(MAX_TEXT_BYTES);
    let xml = format!("<w:p><w:t>{text}</w:t></w:p><w:p><w:t>more</w:t></w:p>");
    let blocks = parse_document_xml(xml.as_bytes(), &mut limits).unwrap();
    assert!(limits.truncated);
    assert_eq!(blocks.len(), 1);
    assert!(blocks[0].text.len() <= MAX_TEXT_BYTES && blocks[0].text.is_char_boundary(blocks[0].text.len()));
}

#[test]
fn the_text_of_a_paragraph_is_normalized() {
    assert_eq!(normalize_text("  a \r\n\t b\u{a0}\rc  "), "a\nb\nc");
    assert_eq!(normalize_text(" \n "), "");
}

#[test]
fn the_level_of_a_heading_comes_from_the_style_or_the_outline() {
    assert_eq!(heading_level("Heading3", 0), 3);
    assert_eq!(heading_level("heading 9", 0), 6);
    assert_eq!(heading_level("Titre2", 0), 2);
    assert_eq!(heading_level("Heading", 0), 1);
    assert_eq!(heading_level("Heading0", 0), 1);
    assert_eq!(heading_level("Normal", 0), 0);
    assert_eq!(heading_level("Normal", 9), 6);
    assert_eq!(heading_level("", 2), 2);
}

#[test]
fn the_size_of_a_request_is_a_non_negative_number() {
    assert_eq!(optional_object_size("").unwrap(), 0);
    assert_eq!(optional_object_size(" 12 ").unwrap(), 12);
    assert!(optional_object_size("-1").is_err());
    assert!(optional_object_size("1.5").is_err());
}
