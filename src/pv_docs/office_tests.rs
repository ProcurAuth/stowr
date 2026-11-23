// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tests of the properties of Office packages.

use super::*;
use crate::pv_docs::test_support::{put, setup, zip_bytes};

const CORE: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<cp:coreProperties xmlns:cp="c" xmlns:dc="d" xmlns:dcterms="t"><dc:title> A title </dc:title><dc:creator>Ann</dc:creator>
<cp:revision>007</cp:revision><dcterms:created>2024-01-02T03:04:05Z</dcterms:created><dc:subject></dc:subject></cp:coreProperties>"#;
const APP: &str = r#"<Properties><Application>Word</Application><Pages>012</Pages><Words>x1</Words><TotalTime>+5</TotalTime></Properties>"#;
const CUSTOM: &str = r#"<Properties xmlns:vt="v"><property name=" Project "><vt:lpwstr> Atlas </vt:lpwstr></property>
<property name="Empty"><vt:lpwstr/></property><property name="Nested"><vt:variant><vt:i4>5</vt:i4></vt:variant></property>
<property name="Second"><vt:i4>1</vt:i4><vt:lpwstr>two</vt:lpwstr></property><property name="Project"><vt:lpwstr>again</vt:lpwstr></property></Properties>"#;

fn package() -> Vec<u8> {
    zip_bytes(
        &[
            ("docProps/core.xml", CORE),
            ("docProps/app.xml", APP),
            ("docProps/custom.xml", CUSTOM),
            ("word/document.xml", "<w:document/>"),
            ("word/media/image1.png", "x"),
            ("word/media/", ""),
            ("word/header1.xml", "<h/>"),
            ("word/header.xml", "<h/>"),
            ("word/_rels/header1.xml", "<h/>"),
            ("word/footer2.xml", "<f/>"),
            ("word/comments.xml", "<c/>"),
            ("word/vbaProject.bin", "x"),
            ("_xmlsignatures/sig1.xml", "<s/>"),
        ],
        true,
    )
}

#[tokio::test]
async fn the_properties_of_a_word_package_come_from_its_small_parts() {
    let (app, backend) = setup();
    put(&backend, "doc.docx", package(), "application/octet-stream");
    let instance = app.instance("rw").unwrap().clone();
    let listed = MediaSourceMetadata {
        size: -1,
        ..MediaSourceMetadata::default()
    };
    let ctx = OpCtx::default();
    let summary = inspect_word_properties(&ctx, &instance, "doc.docx", "DOCX", &listed)
        .await
        .unwrap();
    assert_eq!(summary.container, "Microsoft Word Open XML");
    let properties = &summary.properties;
    let get = |name: &str| properties.get(name).map(String::as_str);
    assert_eq!(get("Title"), Some("A title"));
    assert_eq!(get("Author"), Some("Ann"));
    // The name `revision` of the core part is not in the list of the counters: the value stays as it is.
    assert_eq!(get("Revision"), Some("007"));
    assert_eq!(get("Created"), Some("2024-01-02T03:04:05Z"));
    assert_eq!(get("Subject"), None);
    assert_eq!(get("Application"), Some("Word"));
    assert_eq!(get("Pages"), Some("12"));
    assert_eq!(get("Words"), Some("x1"));
    assert_eq!(get("Editing time (minutes)"), Some("5"));
    assert_eq!(get("Custom - Project"), Some("Atlas"));
    assert_eq!(get("Custom - Empty"), None);
    assert_eq!(get("Custom - Nested"), None);
    assert_eq!(get("Custom - Second"), Some("1"));
    assert_eq!(get("Images"), Some("1"));
    assert_eq!(get("Headers"), Some("1"));
    assert_eq!(get("Footers"), Some("1"));
    assert_eq!(get("Comments"), Some("1"));
    assert_eq!(get("Macros"), Some("Yes"));
    assert_eq!(get("Digital signatures"), Some("Yes"));
    assert!(summary.size > 0 && summary.bytes_read > 0 && summary.requests > 0);
    assert!(!summary.headers.is_empty());
    let by_extension = office_properties(&ctx, &instance, "doc.docx", "docx").await.unwrap();
    assert_eq!(by_extension, summary.properties);
}

#[tokio::test]
async fn a_package_that_is_not_valid_has_its_own_errors() {
    let (app, backend) = setup();
    put(&backend, "plain.docx", b"plain text".to_vec(), "text/plain");
    put(
        &backend,
        "bad.docx",
        zip_bytes(&[("docProps/core.xml", "<a><b></a>")], false),
        "text/plain",
    );
    let instance = app.instance("rw").unwrap().clone();
    let ctx = OpCtx::default();
    let listed = MediaSourceMetadata::default();
    for (key, status, code) in [
        ("plain.docx", 422, "invalid_office_package"),
        ("bad.docx", 422, "invalid_docx_properties"),
    ] {
        let error = inspect_word_properties(&ctx, &instance, key, "docx", &listed)
            .await
            .unwrap_err();
        let api = error.as_api().unwrap();
        assert_eq!((api.status, api.code.as_str()), (status, code), "{key}");
    }
    let error = office_properties(&ctx, &instance, "plain.docx", "txt")
        .await
        .unwrap_err();
    assert!(error.has_code("unsupported_office_package"));
}

#[test]
fn the_parts_of_each_family_are_counted_by_name() {
    let names: Vec<String> = [
        "xl/worksheets/sheet1.xml",
        "xl/worksheets/sheet2.xml",
        "xl/worksheets/_rels/sheet1.xml.rels",
        "xl/worksheets/sheetX.xml",
        "xl/charts/chart1.xml",
        "xl/comments1.xml",
        "xl/media/",
        "xl/media/a.png",
    ]
    .iter()
    .map(|name| (*name).to_owned())
    .collect();
    let mut properties = BTreeMap::new();
    add_package_structure_properties(&mut properties, &names, OfficeFamily::Spreadsheet);
    let expected: BTreeMap<String, String> = [
        ("Worksheets", "2"),
        ("Charts", "1"),
        ("Comment parts", "1"),
        ("Images", "1"),
    ]
    .iter()
    .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
    .collect();
    assert_eq!(properties, expected);
    let slides: Vec<String> = [
        "ppt/slides/slide1.xml",
        "ppt/slides/slide12.xml",
        "ppt/theme/theme1.xml",
    ]
    .iter()
    .map(|name| (*name).to_owned())
    .collect();
    let mut properties: BTreeMap<String, String> = BTreeMap::from([("Slides".to_owned(), "1,000".to_owned())]);
    add_package_structure_properties(&mut properties, &slides, OfficeFamily::Presentation);
    assert_eq!(properties["Slides"], "1,000", "a counter that the package states stays");
    assert_eq!(properties["Themes"], "1");
    let mut properties: BTreeMap<String, String> = BTreeMap::from([("Pages".to_owned(), "0".to_owned())]);
    add_package_structure_properties(
        &mut properties,
        &["visio/pages/page1.xml".to_owned()],
        OfficeFamily::Visio,
    );
    assert_eq!(properties["Pages"], "1");
}

#[test]
fn the_label_of_a_container_comes_from_the_extension() {
    assert_eq!(container_label("XLSM"), "Microsoft Excel macro-enabled workbook");
    assert_eq!(container_label(" vsdx "), "Microsoft Visio drawing");
    assert_eq!(container_label("odt"), "ODT");
    assert_eq!(family_of("PPTX"), Some(OfficeFamily::Presentation));
    assert_eq!(family_of("zip"), None);
    assert!(is_word_extension("dotm") && is_spreadsheet_extension("xlam") && is_visio_extension("vstm"));
}

#[test]
fn the_merge_keeps_the_first_value_and_skips_the_empty_ones() {
    let destination = BTreeMap::from([("A".to_owned(), "1".to_owned())]);
    let source = BTreeMap::from([
        ("A".to_owned(), "2".to_owned()),
        ("B".to_owned(), "3".to_owned()),
        ("C".to_owned(), "  ".to_owned()),
    ]);
    let merged = merge_office_properties(destination, &source);
    assert_eq!(
        merged,
        BTreeMap::from([("A".to_owned(), "1".to_owned()), ("B".to_owned(), "3".to_owned())])
    );
}

#[test]
fn the_values_of_the_counters_have_a_short_form() {
    assert_eq!(normalize_property_value("Pages", " 007 "), "7");
    assert_eq!(normalize_property_value("Pages", "x"), "x");
    assert_eq!(normalize_property_value("Company", "007"), "007");
    assert_eq!(normalize_property_value("Pages", "  "), "");
}
