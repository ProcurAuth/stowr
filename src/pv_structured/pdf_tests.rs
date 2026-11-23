//! The tests of the PDF details.

use std::collections::BTreeMap;

use super::fixtures::{bytes, cases, name};
use super::pdf::{page_count, parse_pdf_metadata};

#[test]
fn pdf_details_match_the_expected_answers_in_each_case() {
    let mut failures = Vec::new();
    for case in cases("pdfs") {
        let prefix = bytes(&case["prefix"]);
        let suffix = bytes(&case["suffix"]);
        let size = case["size"].as_i64().unwrap_or(0);
        let expected: BTreeMap<String, String> = case["properties"]
            .as_object()
            .map(|map| {
                map.iter()
                    .map(|(key, value)| (key.clone(), value.as_str().unwrap_or("").to_owned()))
                    .collect()
            })
            .unwrap_or_default();
        let got = parse_pdf_metadata(&prefix, &suffix, size);
        if got != expected {
            failures.push(format!("{}: got {got:?}, want {expected:?}", name(case)));
        }
        let mut combined = prefix.clone();
        combined.extend_from_slice(&suffix);
        let pages = page_count(&combined);
        let want_pages = case["pages"].as_i64().unwrap_or(0);
        if pages != want_pages {
            failures.push(format!("{} (pages): got {pages}, want {want_pages}", name(case)));
        }
    }
    assert!(failures.is_empty(), "{} failures:\n{}", failures.len(), failures.join("\n"));
}

#[test]
fn pdf_details_use_the_bounded_page_tree_counts() {
    let prefix = b"%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n";
    let suffix = b"2 0 obj << /Type /Pages /Kids [3 0 R 4 0 R] /Count 6 >> endobj\n4 0 obj << /Type /Pages /Count 1229 >> endobj\ntrailer << /Root 1 0 R >>";
    let props = parse_pdf_metadata(prefix, suffix, (prefix.len() + suffix.len()) as i64);
    assert_eq!(props.get("Pages").map(String::as_str), Some("1235"));
    assert_eq!(props.get("PDF version").map(String::as_str), Some("1.7"));
}

#[test]
fn the_page_count_scan_is_bounded() {
    // Without any "obj" text an unbounded backward search scans everything before each marker.
    let data = b"/Type/Pages".repeat(20_000);
    let started = std::time::Instant::now();
    page_count(&data);
    assert!(started.elapsed() < std::time::Duration::from_secs(2), "the scan took {:?}", started.elapsed());
    let legit = b"%PDF-1.7\n2 0 obj << /Type /Pages /Count 7 /Kids [3 0 R] >> endobj\n";
    assert_eq!(page_count(legit), 7);
}
