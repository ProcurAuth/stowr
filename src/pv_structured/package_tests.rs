// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tests of the package details: archives, manifests, APK, VSIX and EPUB.

use std::collections::BTreeMap;

use bytes::Bytes;
use serde_json::Value;

use super::fixtures::{bytes, cases, name};
use super::package::{
    archive_package_metadata, clean_entry_name, compression_method_label, epub_preview, zip_archive_properties,
    zip_details,
};
use crate::archive::zip::ZipReader;

fn expected_map(value: &Value) -> BTreeMap<String, String> {
    value
        .as_object()
        .map(|map| {
            map.iter()
                .map(|(key, value)| (key.clone(), value.as_str().unwrap_or("").to_owned()))
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn package_details_match_the_expected_answers_in_each_case() {
    let mut failures = Vec::new();
    for case in cases("packages") {
        let extension = case["extension"].as_str().unwrap_or("");
        let data = Bytes::from(bytes(&case["zip"]));
        let Ok(reader) = ZipReader::open(data, 0).await else {
            failures.push(format!("{}: the archive does not open", name(case)));
            continue;
        };
        let details = zip_details(&reader, extension).await;
        let expected = expected_map(&case["properties"]);
        if details != expected {
            failures.push(format!(
                "{} (properties): got {details:?}, want {expected:?}",
                name(case)
            ));
        }
        let package = archive_package_metadata(&reader, extension).await;
        let has_package = case["hasPackage"].as_bool().unwrap_or(false);
        if package.is_some() != has_package {
            failures.push(format!("{} (package present): got {}", name(case), package.is_some()));
        } else if let Some(package) = package {
            let want = expected_map(&case["package"]);
            if package != want {
                failures.push(format!("{} (package): got {package:?}, want {want:?}", name(case)));
            }
        }
        if extension == "epub" {
            let epub = epub_preview(&reader).await;
            let got = epub.map_or(Value::Null, |value| serde_json::to_value(value).unwrap_or(Value::Null));
            if got != case["epub"] {
                failures.push(format!("{} (epub): got {got}, want {}", name(case), case["epub"]));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn compression_methods_have_a_label() {
    assert_eq!(compression_method_label(0), "Stored");
    assert_eq!(compression_method_label(8), "Deflate");
    assert_eq!(compression_method_label(12), "BZIP2");
    assert_eq!(compression_method_label(14), "LZMA");
    assert_eq!(compression_method_label(93), "Zstandard");
    assert_eq!(compression_method_label(99), "AES");
    assert_eq!(compression_method_label(77), "Method 77");
}

#[test]
fn entry_names_are_cleaned_like_rooted_paths() {
    assert_eq!(clean_entry_name("META-INF/MANIFEST.MF"), "META-INF/MANIFEST.MF");
    assert_eq!(clean_entry_name("/a//b/./c/../d"), "a/b/d");
    assert_eq!(clean_entry_name("../x"), "x");
    assert_eq!(clean_entry_name(""), "");
}

#[tokio::test]
async fn an_archive_without_entries_has_the_counts_of_zero() {
    let Ok(reader) = ZipReader::open(Bytes::from_static(&EMPTY_ARCHIVE), 0).await else {
        panic!("the empty archive does not open");
    };
    let props = zip_archive_properties(&reader.entries);
    assert_eq!(props.get("Entries").map(String::as_str), Some("0"));
    assert_eq!(props.get("Files").map(String::as_str), Some("0"));
    assert_eq!(props.get("Folders").map(String::as_str), Some("0"));
    assert_eq!(props.get("Compressed size").map(String::as_str), Some("0"));
    assert!(!props.contains_key("Compression methods"));
}

/// The end record of an archive with no entry.
const EMPTY_ARCHIVE: [u8; 22] = [
    0x50, 0x4b, 0x05, 0x06, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];
