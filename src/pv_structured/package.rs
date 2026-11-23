//! The details of the ZIP-compatible packages. They give the archive properties and the manifests of Java
//! archives, browser extensions and VSIX packages. They also give the contents of an APK and the book data of
//! an EPUB.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::html;
use super::text::unfold_lines;
use super::xml::{Token, Tokenizer, parse_document, read_element_text};
use crate::archive::zip::{ByteSource, ZipEntry, ZipReader};

/// The largest entry that the package readers read: 4 MiB.
pub const MAX_ENTRY_BYTES: u64 = 4 << 20;

/// The text of a path with the `.` and `..` parts and the repeated `/` removed (the path is rooted at `/`).
fn clean_rooted(path: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    parts.join("/")
}

/// The clean form of the name of an entry: no `/` at the start, no `.` or `..` part.
pub fn clean_entry_name(name: &str) -> String {
    clean_rooted(&format!("/{name}"))
}

/// The clean form of a path (relative paths stay relative): the form that a path join gives.
fn clean_relative(path: &str) -> String {
    if path.is_empty() {
        return ".".to_owned();
    }
    let rooted = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if matches!(parts.last(), Some(last) if *last != "..") {
                    parts.pop();
                } else if !rooted {
                    parts.push("..");
                }
            }
            other => parts.push(other),
        }
    }
    let joined = parts.join("/");
    match (rooted, joined.is_empty()) {
        (true, _) => format!("/{joined}"),
        (false, true) => ".".to_owned(),
        (false, false) => joined,
    }
}

/// The folder of a path: all but the last element, `.` when there is none.
fn directory_of(path: &str) -> String {
    match path.rfind('/') {
        Some(index) => clean_relative(&path[..=index]),
        None => ".".to_owned(),
    }
}

/// The path of a relative reference in the folder of a document.
fn resolve_relative(base_dir: &str, relative: &str) -> String {
    let joined = [base_dir, relative]
        .iter()
        .filter(|part| !part.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join("/");
    let joined = if joined.is_empty() {
        String::new()
    } else {
        clean_relative(&joined)
    };
    clean_entry_name(&joined)
}

/// The bytes of the first entry with this name (a difference of case does not count), at most `maximum` bytes.
/// `None` when no entry matches or when the entry cannot be read.
pub async fn read_zip_entry<S: ByteSource>(reader: &ZipReader<S>, name: &str, maximum: u64) -> Option<Vec<u8>> {
    let wanted = clean_entry_name(name);
    for entry in &reader.entries {
        let clean = clean_entry_name(&entry.name);
        if !clean.eq_ignore_ascii_case(&wanted) || entry.is_dir() || entry.size > maximum {
            continue;
        }
        return match reader.read_entry(entry, maximum).await {
            Ok(bytes) => Some(bytes.to_vec()),
            Err(_) => None,
        };
    }
    None
}

/// The label of a compression method.
pub fn compression_method_label(method: u16) -> String {
    match method {
        0 => "Stored".to_owned(),
        8 => "Deflate".to_owned(),
        12 => "BZIP2".to_owned(),
        14 => "LZMA".to_owned(),
        93 => "Zstandard".to_owned(),
        99 => "AES".to_owned(),
        other => format!("Method {other}"),
    }
}

/// The label of the container of an archive extension.
pub fn archive_container_label(extension: &str) -> &'static str {
    match extension {
        "jar" => "Java archive",
        "war" => "Java web archive",
        "ear" => "Java enterprise archive",
        "apk" => "Android package",
        "aar" => "Android library archive",
        "crx" => "Chrome extension",
        "epub" => "EPUB",
        "xpi" => "Firefox extension",
        "vsix" => "VSIX package",
        _ => "ZIP archive",
    }
}

/// The properties of the entries of an archive.
pub fn zip_archive_properties(entries: &[ZipEntry]) -> BTreeMap<String, String> {
    let mut props = BTreeMap::new();
    let mut files = 0i64;
    let mut folders = 0i64;
    let mut compressed = 0u64;
    let mut uncompressed = 0u64;
    let mut methods: BTreeMap<u16, i64> = BTreeMap::new();
    let mut encrypted = false;
    let mut zip64 = false;
    for entry in entries {
        if entry.name.trim().ends_with('/') {
            folders += 1;
        } else {
            files += 1;
        }
        compressed = compressed.wrapping_add(entry.compressed_size);
        uncompressed = uncompressed.wrapping_add(entry.size);
        *methods.entry(entry.method).or_insert(0) += 1;
        if entry.flags & 0x1 != 0 {
            encrypted = true;
        }
        if entry.compressed_size >= 0xffff_ffff || entry.size >= 0xffff_ffff {
            zip64 = true;
        }
    }
    props.insert("Entries".to_owned(), entries.len().to_string());
    props.insert("Files".to_owned(), files.to_string());
    props.insert("Folders".to_owned(), folders.to_string());
    props.insert("Compressed size".to_owned(), (compressed as i64).to_string());
    props.insert("Uncompressed size".to_owned(), (uncompressed as i64).to_string());
    if compressed > 0 && uncompressed > compressed {
        let ratio = (1.0 - compressed as f64 / uncompressed as f64) * 100.0;
        props.insert("Compression ratio".to_owned(), format!("{ratio:.1}%"));
    }
    if encrypted {
        props.insert("Encrypted entries".to_owned(), "Yes".to_owned());
    }
    if zip64 {
        props.insert("ZIP64".to_owned(), "Yes".to_owned());
    }
    let mut labels: Vec<String> = methods
        .iter()
        .map(|(method, count)| format!("{} ({count})", compression_method_label(*method)))
        .collect();
    labels.sort();
    if !labels.is_empty() {
        props.insert("Compression methods".to_owned(), labels.join(", "));
    }
    props
}

/// The details of a Java manifest: the main attributes that the details show.
fn manifest_metadata(data: &[u8]) -> Option<BTreeMap<String, String>> {
    if data.is_empty() {
        return None;
    }
    let allowed: [(&str, &str); 13] = [
        ("Manifest-Version", "Manifest version"),
        ("Main-Class", "Main class"),
        ("Automatic-Module-Name", "Module"),
        ("Implementation-Title", "Implementation"),
        ("Implementation-Version", "Version"),
        ("Implementation-Vendor", "Vendor"),
        ("Specification-Title", "Specification"),
        ("Specification-Version", "Specification version"),
        ("Specification-Vendor", "Specification vendor"),
        ("Bundle-Name", "Bundle"),
        ("Bundle-SymbolicName", "Bundle ID"),
        ("Bundle-Version", "Bundle version"),
        ("Created-By", "Created by"),
    ];
    let mut props = BTreeMap::new();
    for line in unfold_lines(data) {
        let Some(index) = line.find(':') else { continue };
        if index == 0 {
            continue;
        }
        let name = line[..index].trim();
        if let Some((_, label)) = allowed.iter().find(|(key, _)| *key == name) {
            props.insert((*label).to_owned(), line[index + 1..].trim().to_owned());
        }
    }
    Some(props)
}

/// The text of a JSON value for a detail. Strings stay as they are and numbers have the shortest form.
/// A list is in brackets. A map has its keys in order.
fn print_value(value: &serde_json::Value) -> String {
    use serde_json::Value;
    match value {
        Value::Null => "<nil>".to_owned(),
        Value::Bool(flag) => flag.to_string(),
        Value::Number(number) => print_float(number.as_f64().unwrap_or(0.0)),
        Value::String(text) => text.clone(),
        Value::Array(items) => {
            let parts: Vec<String> = items.iter().map(print_value).collect();
            format!("[{}]", parts.join(" "))
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let parts: Vec<String> = keys
                .iter()
                .map(|key| format!("{key}:{}", print_value(&map[key.as_str()])))
                .collect();
            format!("map[{}]", parts.join(" "))
        }
    }
}

/// The text of a number with the shortest digits: the exponent form when the exponent is below -4 or at least 6.
fn print_float(value: f64) -> String {
    if value == 0.0 {
        return "0".to_owned();
    }
    let scientific = format!("{value:e}");
    let (mantissa, exponent) = scientific.split_once('e').unwrap_or((&scientific, "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    if !(-4..6).contains(&exponent) {
        let sign = if exponent < 0 { '-' } else { '+' };
        return format!("{mantissa}e{sign}{:02}", exponent.abs());
    }
    format!("{value}")
}

/// The details of a manifest in JSON (browser extensions).
fn json_manifest_metadata(data: &[u8]) -> Option<BTreeMap<String, String>> {
    if data.is_empty() {
        return None;
    }
    let serde_json::Value::Object(manifest) = serde_json::from_slice::<serde_json::Value>(data).ok()? else {
        return None;
    };
    let labels: [(&str, &str); 10] = [
        ("name", "Name"),
        ("short_name", "Short name"),
        ("version", "Version"),
        ("version_name", "Version name"),
        ("description", "Description"),
        ("author", "Author"),
        ("homepage_url", "Homepage"),
        ("manifest_version", "Manifest version"),
        ("minimum_chrome_version", "Minimum browser version"),
        ("default_locale", "Default locale"),
    ];
    let mut props = BTreeMap::new();
    for (key, label) in labels {
        if let Some(value) = manifest.get(key) {
            props.insert(label.to_owned(), print_value(value));
        }
    }
    if let Some(serde_json::Value::Array(permissions)) = manifest.get("permissions") {
        let values: Vec<String> = permissions.iter().map(print_value).collect();
        if !values.is_empty() {
            props.insert("Permissions".to_owned(), values.join(", "));
        }
    }
    Some(props)
}

/// The details of a VSIX manifest.
fn vsix_metadata(data: &[u8]) -> Option<BTreeMap<String, String>> {
    if data.is_empty() {
        return None;
    }
    let root = parse_document(data)?;
    let metadata: Vec<&super::xml::Element> = root.children_named("Metadata").collect();
    let mut identity = [String::new(), String::new(), String::new(), String::new()];
    for element in root.at_path(&["Metadata", "Identity"]) {
        for (index, name) in ["Id", "Version", "Publisher", "Language"].iter().enumerate() {
            if element.attrs.iter().any(|(key, _)| key == name) {
                identity[index] = element.attr(name).to_owned();
            }
        }
    }
    let last_text = |name: &str| -> String {
        let mut value = String::new();
        for element in &metadata {
            for child in element.children_named(name) {
                value = child.text.clone();
            }
        }
        value
    };
    let mut props = BTreeMap::new();
    let pairs = [
        ("ID", identity[0].clone()),
        ("Version", identity[1].clone()),
        ("Publisher", identity[2].clone()),
        ("Language", identity[3].clone()),
        ("Name", last_text("DisplayName")),
        ("Description", last_text("Description")),
        ("More information", last_text("MoreInfo")),
        ("License", last_text("License")),
    ];
    for (label, value) in pairs {
        if !value.trim().is_empty() {
            props.insert(label.to_owned(), value.trim().to_owned());
        }
    }
    Some(props)
}

/// The details of an APK from the names of its entries.
fn apk_metadata(entries: &[ZipEntry]) -> BTreeMap<String, String> {
    let mut props = BTreeMap::new();
    let mut abis: BTreeSet<String> = BTreeSet::new();
    let mut dex_files = 0usize;
    let mut signatures = 0usize;
    let mut resources = false;
    let mut manifest = false;
    for entry in entries {
        let name = clean_entry_name(&entry.name);
        let lower = name.to_lowercase();
        if lower == "androidmanifest.xml" {
            manifest = true;
        }
        if lower == "resources.arsc" {
            resources = true;
        }
        if lower.starts_with("classes") && lower.ends_with(".dex") {
            dex_files += 1;
        }
        if lower.starts_with("lib/") {
            let parts: Vec<&str> = name.split('/').collect();
            if parts.len() > 2 && !parts[1].is_empty() {
                abis.insert(parts[1].to_owned());
            }
        }
        let upper = name.to_uppercase();
        if upper.starts_with("META-INF/")
            && (upper.ends_with(".RSA") || upper.ends_with(".DSA") || upper.ends_with(".EC"))
        {
            signatures += 1;
        }
    }
    if manifest {
        props.insert("Android manifest".to_owned(), "Present".to_owned());
    }
    if resources {
        props.insert("Compiled resources".to_owned(), "Present".to_owned());
    }
    if dex_files > 0 {
        props.insert("DEX files".to_owned(), dex_files.to_string());
    }
    if signatures > 0 {
        props.insert("Signature blocks".to_owned(), signatures.to_string());
    }
    if !abis.is_empty() {
        props.insert(
            "Native ABIs".to_owned(),
            abis.into_iter().collect::<Vec<_>>().join(", "),
        );
    }
    props
}

/// The details of the package of an archive of an extension that has a manifest, or `None`.
pub async fn archive_package_metadata<S: ByteSource>(
    reader: &ZipReader<S>,
    extension: &str,
) -> Option<BTreeMap<String, String>> {
    match extension {
        "jar" | "war" | "ear" | "aar" => manifest_metadata(
            &read_zip_entry(reader, "META-INF/MANIFEST.MF", MAX_ENTRY_BYTES)
                .await
                .unwrap_or_default(),
        ),
        "xpi" | "crx" => json_manifest_metadata(
            &read_zip_entry(reader, "manifest.json", MAX_ENTRY_BYTES)
                .await
                .unwrap_or_default(),
        ),
        "vsix" => vsix_metadata(
            &read_zip_entry(reader, "extension.vsixmanifest", MAX_ENTRY_BYTES)
                .await
                .unwrap_or_default(),
        ),
        "apk" => Some(apk_metadata(&reader.entries)),
        _ => None,
    }
}

/// One entry of the table of contents of an EPUB.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TocEntry {
    /// The label.
    pub label: String,
    /// The target.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub href: String,
    /// The level, from 0.
    #[serde(skip_serializing_if = "is_zero")]
    pub depth: usize,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

/// The book data of an EPUB.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct EpubPreview {
    /// The title.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub title: String,
    /// The creators.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub creators: Vec<String>,
    /// The language.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub language: String,
    /// The identifier.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub identifier: String,
    /// The publisher.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub publisher: String,
    /// The date.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub date: String,
    /// The rights.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub rights: String,
    /// The description.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// The subjects.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub subjects: Vec<String>,
    /// The path of the cover image.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub cover: String,
    /// The table of contents.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub toc: Vec<TocEntry>,
}

fn trim_non_empty(values: &[String]) -> Vec<String> {
    values
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect()
}

fn first_trimmed(values: &[String]) -> String {
    values.first().map(|value| value.trim().to_owned()).unwrap_or_default()
}

/// The texts of the children of the metadata with a name.
fn metadata_texts(metadata: &[&super::xml::Element], name: &str) -> Vec<String> {
    metadata
        .iter()
        .flat_map(|element| element.children_named(name))
        .map(|child| child.text.clone())
        .collect()
}

/// The table of contents of the navigation document: each link of each `nav` element.
fn parse_epub_nav(data: &[u8]) -> Vec<TocEntry> {
    let mut result = Vec::new();
    if data.is_empty() {
        return result;
    }
    let mut tokenizer = Tokenizer::new(data);
    let mut depth = 0usize;
    let mut in_nav = false;
    // The names of the end tokens come from the stack of the tokenizer: keep our own.
    let mut names: Vec<String> = Vec::new();
    loop {
        match tokenizer.next_token() {
            None | Some(Err(())) => break,
            Some(Ok(Token::Start { name, attrs })) => {
                let local = name.to_lowercase();
                if local == "nav" {
                    in_nav = true;
                }
                if in_nav && (local == "ol" || local == "ul") {
                    depth += 1;
                }
                if in_nav && local == "a" {
                    let mut href = String::new();
                    for (key, value) in &attrs {
                        if key.eq_ignore_ascii_case("href") {
                            href.clone_from(value);
                        }
                    }
                    if let Ok(label) = read_element_text(&mut tokenizer) {
                        let label = html::to_plain_text(&label)
                            .split_whitespace()
                            .collect::<Vec<_>>()
                            .join(" ");
                        if !label.is_empty() {
                            result.push(TocEntry {
                                label,
                                href,
                                depth: depth.saturating_sub(1),
                            });
                        }
                    }
                    continue;
                }
                names.push(local);
            }
            Some(Ok(Token::End)) => {
                let local = names.pop().unwrap_or_default();
                if in_nav && (local == "ol" || local == "ul") && depth > 0 {
                    depth -= 1;
                }
                if local == "nav" {
                    in_nav = false;
                }
            }
            Some(Ok(Token::Text(_))) => {}
        }
    }
    result
}

/// The book data of an EPUB, or `None` when the package has no readable container and package documents.
pub async fn epub_preview<S: ByteSource>(reader: &ZipReader<S>) -> Option<EpubPreview> {
    let container_data = read_zip_entry(reader, "META-INF/container.xml", MAX_ENTRY_BYTES).await?;
    if container_data.is_empty() {
        return None;
    }
    let container = parse_document(&container_data)?;
    let rootfiles = container.at_path(&["rootfiles", "rootfile"]);
    let first = rootfiles.first()?;
    let opf_path = clean_entry_name(first.attr("full-path"));
    let opf_data = read_zip_entry(reader, &opf_path, MAX_ENTRY_BYTES).await?;
    if opf_data.is_empty() {
        return None;
    }
    let package = parse_document(&opf_data)?;
    let metadata: Vec<&super::xml::Element> = package.children_named("metadata").collect();
    let mut result = EpubPreview {
        title: first_trimmed(&metadata_texts(&metadata, "title")),
        creators: trim_non_empty(&metadata_texts(&metadata, "creator")),
        language: first_trimmed(&metadata_texts(&metadata, "language")),
        identifier: first_trimmed(&metadata_texts(&metadata, "identifier")),
        publisher: first_trimmed(&metadata_texts(&metadata, "publisher")),
        date: first_trimmed(&metadata_texts(&metadata, "date")),
        rights: first_trimmed(&metadata_texts(&metadata, "rights")),
        description: first_trimmed(&metadata_texts(&metadata, "description")),
        subjects: trim_non_empty(&metadata_texts(&metadata, "subject")),
        ..EpubPreview::default()
    };
    let base_dir = directory_of(&opf_path);
    let mut manifest_by_id: BTreeMap<String, String> = BTreeMap::new();
    let mut nav_path = String::new();
    for item in package.at_path(&["manifest", "item"]) {
        manifest_by_id.insert(item.attr("id").to_owned(), item.attr("href").to_owned());
        for property in item.attr("properties").split_whitespace() {
            if property == "nav" {
                nav_path = resolve_relative(&base_dir, item.attr("href"));
            }
            if property == "cover-image" {
                result.cover = resolve_relative(&base_dir, item.attr("href"));
            }
        }
    }
    for meta in metadata.iter().flat_map(|element| element.children_named("meta")) {
        if meta.attr("name").eq_ignore_ascii_case("cover")
            && let Some(href) = manifest_by_id.get(meta.attr("content"))
        {
            result.cover = resolve_relative(&base_dir, href);
        }
    }
    if !nav_path.is_empty() {
        let data = read_zip_entry(reader, &nav_path, MAX_ENTRY_BYTES)
            .await
            .unwrap_or_default();
        result.toc = parse_epub_nav(&data);
    }
    // The navigation map of the old format (NCX) gives no entry.
    Some(result)
}

/// The details of a package: the properties of the archive, the details of its manifest and, for an EPUB, the
/// book data. A manifest value that is blank does not count.
pub async fn zip_details<S: ByteSource>(reader: &ZipReader<S>, extension: &str) -> BTreeMap<String, String> {
    let mut props = zip_archive_properties(&reader.entries);
    if let Some(package) = archive_package_metadata(reader, extension).await {
        for (name, value) in package {
            if !value.trim().is_empty() {
                props.insert(name, value);
            }
        }
    }
    if extension == "epub"
        && let Some(epub) = epub_preview(reader).await
    {
        let pairs = [
            ("Title", epub.title.clone()),
            ("Authors", epub.creators.join(", ")),
            ("Language", epub.language.clone()),
            ("Identifier", epub.identifier.clone()),
            ("Publisher", epub.publisher.clone()),
            ("Publication date", epub.date.clone()),
            ("Rights", epub.rights.clone()),
            ("Subjects", epub.subjects.join(", ")),
            ("Table of contents entries", epub.toc.len().to_string()),
        ];
        for (name, value) in pairs {
            if !value.trim().is_empty() && value != "0" {
                props.insert(name.to_owned(), value);
            }
        }
    }
    props
}
