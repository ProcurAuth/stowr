//! The names of the archives: the safe name of an entry and the unique name of a member of the ZIP of a folder.
//! The module also gives the file name of the ZIP of a folder, the selection of an extraction and the quoted form of
//! a name in a message.

use std::collections::{BTreeSet, HashMap};

use crate::common::error::{Error, Result};

/// The limit of entries when the configuration gives none.
pub const DEFAULT_MAX_ARCHIVE_ENTRIES: usize = 10_000;

/// The extension of the last element of a path: from its last `.`, or an empty text.
pub fn path_ext(path: &str) -> &str {
    for (index, byte) in path.bytes().enumerate().rev() {
        match byte {
            b'/' => return "",
            b'.' => return &path[index..],
            _ => {}
        }
    }
    ""
}

/// The last element of a path, without the `/` at its end. An empty path gives `.`; a path of `/` only gives `/`.
pub fn path_base(path: &str) -> &str {
    if path.is_empty() {
        return ".";
    }
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/";
    }
    match trimmed.rfind('/') {
        Some(slash) => &trimmed[slash + 1..],
        None => trimmed,
    }
}

/// A prefix with one `/` at its end and none at its start, or an empty text.
pub fn normalize_prefix(value: &str) -> String {
    let value = value.trim_start_matches('/');
    if value.is_empty() {
        return String::new();
    }
    format!("{}/", value.trim_end_matches('/'))
}

/// The safe relative name of an archive entry. `\` becomes `/` and the name loses its empty elements. A control
/// character becomes `_`. A first element with `:` as its second byte (a drive letter) gets a `_` before it. A name
/// with a NUL byte, a `.` or `..` element, or no element gives `None`. A name that ends with `/` keeps it.
pub fn safe_archive_entry_name(value: &str) -> Option<String> {
    if value.is_empty() || value.contains('\0') {
        return None;
    }
    let value = value.replace('\\', "/");
    let directory = value.ends_with('/');
    let mut parts: Vec<String> = Vec::new();
    for part in value.split('/') {
        if part.is_empty() {
            continue;
        }
        if part == "." || part == ".." {
            return None;
        }
        let mut part: String = part.chars().map(|c| if c.is_control() { '_' } else { c }).collect();
        if parts.is_empty() && part.as_bytes().get(1) == Some(&b':') {
            part.insert(0, '_');
        }
        parts.push(part);
    }
    if parts.is_empty() {
        return None;
    }
    let mut name = parts.join("/");
    if directory {
        name.push('/');
    }
    Some(name)
}

/// A name that no other member of the archive has: the second `a.txt` becomes `a~2.txt`, a second `docs/` becomes
/// `docs~2/`.
pub fn unique_archive_entry_name(name: &str, seen: &mut HashMap<String, u64>) -> String {
    let current = seen.get(name).copied().unwrap_or(0);
    if current == 0 {
        seen.insert(name.to_owned(), 1);
        return name.to_owned();
    }
    let mut count = current + 1;
    seen.insert(name.to_owned(), count);
    let directory = name.ends_with('/');
    let base = name.strip_suffix('/').unwrap_or(name);
    let extension = path_ext(base);
    let stem = &base[..base.len() - extension.len()];
    let candidate = |count: u64| {
        let mut candidate = format!("{stem}~{count}{extension}");
        if directory {
            candidate.push('/');
        }
        candidate
    };
    let mut result = candidate(count);
    while seen.get(&result).copied().unwrap_or(0) != 0 {
        count += 1;
        result = candidate(count);
    }
    seen.insert(result.clone(), 1);
    result
}

/// The file name of the ZIP of a folder: the requested name, else the last folder of the prefix. Else the name of
/// the instance, else `archive`. A control character and `/\:*?"<>|` become `_`. The name loses the spaces and the
/// dots at its ends, and ends with `.zip`. A name of more than 180 bytes keeps its first 176 bytes and `.zip`.
pub fn archive_filename(requested: &str, prefix: &str, instance_name: &str) -> Vec<u8> {
    let mut name = requested.trim().to_owned();
    if name.is_empty() {
        let folder = prefix.strip_suffix('/').unwrap_or(prefix);
        name = match folder.rfind('/') {
            Some(slash) => folder[slash + 1..].to_owned(),
            None => folder.to_owned(),
        };
    }
    if name.is_empty() {
        name = instance_name.trim().to_owned();
    }
    if name.is_empty() {
        name = "archive".to_owned();
    }
    let name: String = name
        .chars()
        .map(|c| {
            if c.is_control() || "/\\:*?\"<>|".contains(c) {
                '_'
            } else {
                c
            }
        })
        .collect();
    let mut name = name.trim_matches(|c| c == ' ' || c == '.').to_owned();
    if name.is_empty() {
        name = "archive".to_owned();
    }
    if !name.to_lowercase().ends_with(".zip") {
        name.push_str(".zip");
    }
    let mut bytes = name.into_bytes();
    if bytes.len() > 180 {
        bytes.truncate(176);
        bytes.extend_from_slice(b".zip");
    }
    bytes
}

/// The selection of an extraction: the names without spaces at their ends, without the second copy of a name, in
/// byte order. An empty selection, a selection over the limit (0: the default limit) or an empty or NUL name gives an
/// error.
pub fn normalize_archive_entry_selection(entries: &[String], maximum: usize) -> Result<Vec<String>> {
    let maximum = if maximum == 0 {
        DEFAULT_MAX_ARCHIVE_ENTRIES
    } else {
        maximum
    };
    if entries.is_empty() {
        return Err(Error::api(
            400,
            "empty_archive_selection",
            "select at least one archive entry",
        ));
    }
    if entries.len() > maximum {
        return Err(Error::api(
            413,
            "archive_selection_limit",
            format!("the selection exceeds the configured limit of {maximum} entries"),
        ));
    }
    let mut result = BTreeSet::new();
    for raw in entries {
        let name = raw.trim();
        if name.is_empty() || name.contains('\0') {
            return Err(Error::api(
                400,
                "invalid_archive_entry",
                "the archive selection contains an invalid entry name",
            ));
        }
        result.insert(name.to_owned());
    }
    Ok(result.into_iter().collect())
}

/// True for a character that a quoted name shows as it is: a letter, a mark, a number, a punctuation, a symbol or
/// the ASCII space.
fn printable(c: char) -> bool {
    let code = u32::from(c);
    if code <= 0xff {
        return (0x20..=0x7e).contains(&code) || (code >= 0xa1 && code != 0xad);
    }
    !(c.is_control()
        || c.is_whitespace()
        || (0x200b..=0x200f).contains(&code)
        || (0x2028..=0x202e).contains(&code)
        || (0x2060..=0x206f).contains(&code)
        || (0xe000..=0xf8ff).contains(&code)
        || (0xfff9..=0xfffb).contains(&code)
        || code == 0xfeff
        || code >= 0xf_0000
        || (code & 0xfffe) == 0xfffe)
}

/// The name between double quotes, with the escapes of a text literal: `\"`, `\\`, `\n`, `\x01`, `\u200b`...
pub fn quote(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if printable(c) => out.push(c),
            '\u{7}' => out.push_str("\\a"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{b}' => out.push_str("\\v"),
            c if u32::from(c) < 0x20 || c == '\u{7f}' => out.push_str(&format!("\\x{:02x}", u32::from(c))),
            c if u32::from(c) < 0x1_0000 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push_str(&format!("\\U{:08x}", u32::from(c))),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_names_refuse_traversal_and_keep_folders() {
        assert_eq!(safe_archive_entry_name("a/b.txt").as_deref(), Some("a/b.txt"));
        assert_eq!(safe_archive_entry_name("a\\b//c/").as_deref(), Some("a/b/c/"));
        assert_eq!(safe_archive_entry_name("/abs/x").as_deref(), Some("abs/x"));
        assert_eq!(safe_archive_entry_name("C:/x").as_deref(), Some("_C:/x"));
        assert_eq!(safe_archive_entry_name("a\u{1}b").as_deref(), Some("a_b"));
        assert_eq!(safe_archive_entry_name("x/C:y").as_deref(), Some("x/C:y"));
        for refused in ["", "../x", "a/./b", "a/..", "a\0b", "/", "//"] {
            assert_eq!(safe_archive_entry_name(refused), None, "{refused:?}");
        }
    }

    #[test]
    fn unique_names_count_the_copies() {
        let mut seen = HashMap::new();
        assert_eq!(unique_archive_entry_name("a.txt", &mut seen), "a.txt");
        assert_eq!(unique_archive_entry_name("a.txt", &mut seen), "a~2.txt");
        assert_eq!(unique_archive_entry_name("a.txt", &mut seen), "a~3.txt");
        assert_eq!(unique_archive_entry_name("docs/", &mut seen), "docs/");
        assert_eq!(unique_archive_entry_name("docs/", &mut seen), "docs~2/");
        assert_eq!(unique_archive_entry_name("b~2.txt", &mut seen), "b~2.txt");
        assert_eq!(unique_archive_entry_name("b.txt", &mut seen), "b.txt");
        assert_eq!(unique_archive_entry_name("b.txt", &mut seen), "b~3.txt");
        assert_eq!(unique_archive_entry_name("v1.2/readme", &mut seen), "v1.2/readme");
        assert_eq!(unique_archive_entry_name("v1.2/readme", &mut seen), "v1.2/readme~2");
    }

    #[test]
    fn the_file_name_of_a_folder_archive() {
        assert_eq!(archive_filename("folder.zip", "folder/", "rw"), b"folder.zip");
        assert_eq!(archive_filename("", "a/b/", "rw"), b"b.zip");
        assert_eq!(archive_filename("  ", "", "Main bucket"), b"Main bucket.zip");
        assert_eq!(archive_filename("", "", " "), b"archive.zip");
        assert_eq!(archive_filename("a:b*c?.ZIP", "", ""), b"a_b_c_.ZIP");
        assert_eq!(archive_filename(" ..report.. ", "", ""), b"report.zip");
        assert_eq!(archive_filename("...", "", ""), b"archive.zip");
        let long = "x".repeat(200);
        let name = archive_filename(&long, "", "");
        assert_eq!(name.len(), 180);
        assert!(name.ends_with(b"x.zip"));
        let cut = archive_filename(&format!("{}é", "y".repeat(175)), "", "");
        assert_eq!(cut.len(), 180);
        assert_eq!(&cut[175..], b"\xc3.zip");
    }

    #[test]
    fn the_selection_is_sorted_and_without_copies() {
        let entries = vec![" b ".to_owned(), "a".to_owned(), "b".to_owned()];
        assert_eq!(normalize_archive_entry_selection(&entries, 10).unwrap(), vec!["a", "b"]);
        let error = normalize_archive_entry_selection(&[], 10).unwrap_err();
        assert!(error.has_code("empty_archive_selection"));
        let error = normalize_archive_entry_selection(&entries, 2).unwrap_err();
        assert_eq!(error.status(), 413);
        assert_eq!(
            error.public_message(),
            "the selection exceeds the configured limit of 2 entries"
        );
        for bad in [" ", "a\0"] {
            let error = normalize_archive_entry_selection(&[bad.to_owned()], 10).unwrap_err();
            assert!(error.has_code("invalid_archive_entry"));
        }
    }

    #[test]
    fn paths_give_their_extension_and_their_base() {
        assert_eq!(path_ext("a/b.tar.gz"), ".gz");
        assert_eq!(path_ext("a.b/c"), "");
        assert_eq!(path_ext(".bashrc"), ".bashrc");
        assert_eq!(path_base("a/b/"), "b");
        assert_eq!(path_base(""), ".");
        assert_eq!(path_base("///"), "/");
        assert_eq!(normalize_prefix("/a//"), "a/");
        assert_eq!(normalize_prefix("/"), "");
    }

    #[test]
    fn quoted_names_escape_what_a_reader_cannot_see() {
        assert_eq!(quote("a \"b\"\\c"), "\"a \\\"b\\\"\\\\c\"");
        assert_eq!(quote("tab\tnew\nnul\u{0}del\u{7f}"), "\"tab\\tnew\\nnul\\x00del\\x7f\"");
        assert_eq!(quote("café ✓"), "\"café ✓\"");
        assert_eq!(quote("\u{200b}\u{a0}\u{10ffff}"), "\"\\u200b\\u00a0\\U0010ffff\"");
    }
}
