// SPDX-License-Identifier: MIT OR Apache-2.0
//! The content type of a file of a volume. A file has no metadata of S3: the type comes from the extension of the
//! name. The release image has no `/etc/mime.types`, so the tables of the program are the whole source.

use crate::common::mediatype::{path_ext, preview_content_type};

/// The content type of a folder key (`<folder>/`) in a HEAD answer.
pub const FOLDER_CONTENT_TYPE: &str = "application/x-directory";

/// The content types of common text and archive files.
const TEXT_TYPES: &[(&str, &str)] = &[
    (".txt", "text/plain; charset=utf-8"),
    (".log", "text/plain; charset=utf-8"),
    (".md", "text/markdown; charset=utf-8"),
    (".csv", "text/csv; charset=utf-8"),
    (".tsv", "text/tab-separated-values; charset=utf-8"),
    (".yaml", "application/yaml"),
    (".yml", "application/yaml"),
    (".toml", "application/toml"),
    (".zip", "application/zip"),
    (".gz", "application/gzip"),
    (".tar", "application/x-tar"),
];

fn lookup(table: &[(&'static str, &'static str)], extension: &str) -> Option<&'static str> {
    table
        .iter()
        .find(|(known, _)| *known == extension)
        .map(|(_, value)| *value)
}

/// The content type of a key from the extension of its name: the table of the text files, else the table of the
/// previews and the built-in table, else `application/octet-stream`.
pub fn content_type(key: &str) -> &'static str {
    let extension = path_ext(key).to_lowercase();
    if let Some(known) = lookup(TEXT_TYPES, &extension) {
        return known;
    }
    match preview_content_type(key) {
        "" => "application/octet-stream",
        known => known,
    }
}
