//! The details of documents (`/api/media-info` for the formats that are not media): the container, the properties
//! that a bounded read gives, and the explicit counts (the dimensions of delimited text, the lines of a text, the
//! dimensions of a worksheet).
//!
//! A details request never reads a whole object. A delimited file, a JSON file or a text gives only its storage
//! headers; its count is a separate action of the interface, because it reads the complete object in order.

use std::collections::BTreeMap;
use std::sync::Arc;

use http::HeaderMap;
use http_body_util::BodyExt;

use super::DocumentDetails;
use super::bridge::{OfficeFamily, office_container_label, office_details, structured_details};
use super::parquet::{inspect_summary, read_exact_range};
use super::sqlite::SQLITE_MAGIC;
use super::text::{lower, upper};
use super::workbook::inspect_spreadsheet_summary;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::Body;
use crate::instance::Instance;
use crate::instance::range::RangeSource;
use crate::pv_media::MediaSourceMetadata;

/// The bytes that the delimiter detection reads at the start of a delimited file: 128 KiB.
const DELIMITER_SAMPLE_BYTES: usize = 128 << 10;

/// The rows (without the header record) and the non-empty columns of a delimited file.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DelimitedSummary {
    /// The records after the first non-empty record.
    pub rows: i64,
    /// The columns with at least one non-empty field.
    pub columns: i64,
}

/// The last part of a slash-separated key: `.` for an empty key, `/` for a key of slashes only.
fn base_name(key: &str) -> &str {
    if key.is_empty() {
        return ".";
    }
    let trimmed = key.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/";
    }
    match trimmed.rfind('/') {
        Some(index) => &trimmed[index + 1..],
        None => trimmed,
    }
}

/// The extension of a name with its dot (`.txt`), or an empty text.
fn extension_of(name: &str) -> &str {
    match name.rfind(['.', '/']) {
        Some(index) if name.as_bytes()[index] == b'.' => &name[index..],
        _ => "",
    }
}

/// The media type without its parameters, in lower case.
fn media_type(content_type: &str) -> String {
    lower(content_type.split(';').next().unwrap_or("").trim())
}

/// True for a delimited media type: `text/csv`, `text/tsv` or `text/tab-separated-values`.
pub(crate) fn is_delimited_content_type(content_type: &str) -> bool {
    matches!(
        media_type(content_type).as_str(),
        "text/csv" | "text/tsv" | "text/tab-separated-values"
    )
}

/// The container label of a text: the language or format of the extension, else a known name of a file without an
/// extension, else `Plain text` for a `text/` media type, else an empty text.
pub(crate) fn text_container_label(key: &str, extension: &str, content_type: &str) -> String {
    let extension = lower(extension.trim());
    let label = match extension.as_str() {
        "sh" | "bash" | "zsh" | "ksh" | "fish" | "envrc" => "Shell",
        "ps1" | "psm1" | "psd1" => "PowerShell",
        "js" => "JavaScript",
        "mjs" => "JavaScript module",
        "cjs" => "CommonJS JavaScript",
        "jsx" => "JavaScript XML",
        "ts" => "TypeScript",
        "mts" | "cts" => "TypeScript module",
        "tsx" => "TypeScript XML",
        "json" => "JSON",
        "json5" => "JSON5",
        "hjson" => "Hjson",
        "geojson" => "GeoJSON",
        "ipynb" => "Jupyter Notebook",
        "yaml" | "yml" => "YAML",
        "toml" => "TOML",
        "hcl" | "tf" => "Terraform HCL",
        "tfvars" => "Terraform variables",
        "html" | "htm" => "HTML",
        "xhtml" => "XHTML",
        "vue" => "Vue single-file component",
        "svelte" => "Svelte component",
        "xml" => "XML",
        "svg" => "SVG",
        "css" => "CSS",
        "scss" => "SCSS",
        "sass" => "Sass",
        "less" => "Less",
        "ini" => "INI",
        "conf" | "cfg" | "cnf" => "Configuration",
        "properties" => "Java properties",
        "md" | "markdown" | "mdown" | "mkd" => "Markdown",
        "rmd" => "R Markdown",
        "adoc" | "asciidoc" => "AsciiDoc",
        "txt" | "out" => "Plain text",
        "log" => "Log",
        "diff" => "Diff",
        "patch" => "Patch",
        "sql" => "SQL",
        "gql" | "graphql" => "GraphQL",
        "proto" => "Protocol Buffers",
        "thrift" => "Apache Thrift",
        "mk" => "Makefile",
        "nginx" => "Nginx configuration",
        "java" => "Java",
        "kt" | "kts" => "Kotlin",
        "groovy" => "Groovy",
        "scala" => "Scala",
        "c" | "h" => "C",
        "cpp" | "cxx" | "cc" | "hpp" | "hxx" | "inl" => "C++",
        "m" => "Objective-C",
        "mm" => "Objective-C++",
        "cs" => "C#",
        "go" => "Go",
        "mod" => "Go module",
        "sum" => "Go checksum list",
        "work" => "Go workspace",
        "rs" => "Rust",
        "swift" => "Swift",
        "py" | "pyw" => "Python",
        "pyi" => "Python type stub",
        "rb" => "Ruby",
        "php" | "phtml" => "PHP",
        "pl" | "pm" => "Perl",
        "lua" => "Lua",
        "r" => "R",
        "dart" => "Dart",
        "zig" => "Zig",
        "cue" => "CUE",
        "nix" => "Nix",
        "bat" | "cmd" => "DOS batch",
        "vb" => "Visual Basic .NET",
        "vbs" => "VBScript",
        "fs" | "fsx" => "F#",
        "hs" => "Haskell",
        "ml" | "mli" => "OCaml",
        "pas" | "pp" => "Pascal",
        "mustache" => "Mustache template",
        "hbs" | "handlebars" => "Handlebars",
        "ejs" => "Embedded JavaScript template",
        "njk" => "Nunjucks template",
        "twig" => "Twig template",
        "jinja" => "Jinja template",
        "lock" => "Lock file",
        _ => "",
    };
    if !label.is_empty() {
        return label.to_owned();
    }
    let name = lower(base_name(key));
    if name.starts_with("dockerfile") {
        return "Dockerfile".to_owned();
    }
    if name.starts_with("containerfile") {
        return "Containerfile".to_owned();
    }
    if name == "makefile" || name == "gnumakefile" {
        return "Makefile".to_owned();
    }
    if name.starts_with("jenkinsfile") {
        return "Jenkins pipeline".to_owned();
    }
    if name.starts_with(".env") {
        return "Environment configuration".to_owned();
    }
    if lower(content_type).starts_with("text/") {
        return "Plain text".to_owned();
    }
    String::new()
}

/// True for a text that a line count can read: a `text/` media type, a known name of a file without an extension,
/// or a text extension.
pub(crate) fn is_text_line_count_candidate(key: &str, content_type: &str) -> bool {
    let name = lower(base_name(key));
    let extension = lower(extension_of(&name).trim_start_matches('.'));
    if lower(content_type.trim()).starts_with("text/") || name.starts_with(".env") {
        return true;
    }
    const EXACT: [&str; 18] = [
        "dockerfile",
        "containerfile",
        "makefile",
        "gnumakefile",
        "jenkinsfile",
        "procfile",
        "gemfile",
        "rakefile",
        "vagrantfile",
        "caddyfile",
        "justfile",
        "taskfile",
        "earthfile",
        "brewfile",
        "podfile",
        "codeowners",
        "owners",
        "maintainers",
    ];
    if EXACT.contains(&name.as_str()) || name.starts_with(".git") || name.starts_with(".docker") {
        return true;
    }
    matches!(
        extension.as_str(),
        "txt"
            | "log"
            | "md"
            | "markdown"
            | "mdown"
            | "mkd"
            | "rmd"
            | "go"
            | "mod"
            | "sum"
            | "work"
            | "rs"
            | "c"
            | "h"
            | "cpp"
            | "cxx"
            | "cc"
            | "hpp"
            | "hxx"
            | "cs"
            | "java"
            | "kt"
            | "kts"
            | "swift"
            | "m"
            | "mm"
            | "py"
            | "pyw"
            | "pyi"
            | "rb"
            | "php"
            | "pl"
            | "pm"
            | "lua"
            | "r"
            | "js"
            | "mjs"
            | "cjs"
            | "jsx"
            | "ts"
            | "mts"
            | "cts"
            | "tsx"
            | "css"
            | "scss"
            | "sass"
            | "less"
            | "html"
            | "htm"
            | "xhtml"
            | "xml"
            | "svg"
            | "yaml"
            | "yml"
            | "toml"
            | "hcl"
            | "tf"
            | "tfvars"
            | "ini"
            | "conf"
            | "cfg"
            | "properties"
            | "sh"
            | "bash"
            | "zsh"
            | "fish"
            | "ps1"
            | "sql"
            | "proto"
            | "graphql"
            | "gql"
            | "diff"
            | "patch"
            | "json"
            | "json5"
            | "hjson"
            | "geojson"
            | "ipynb"
            | "jsonl"
            | "ndjson"
            | "csv"
            | "tsv"
            | "tab"
            | "psv"
            | "psm1"
            | "psd1"
            | "ksh"
            | "envrc"
            | "adoc"
            | "asciidoc"
            | "out"
            | "thrift"
            | "mk"
            | "nginx"
            | "groovy"
            | "scala"
            | "inl"
            | "dart"
            | "zig"
            | "cue"
            | "nix"
            | "bat"
            | "cmd"
            | "vb"
            | "vbs"
            | "fs"
            | "fsx"
            | "hs"
            | "ml"
            | "mli"
            | "pas"
            | "pp"
            | "mustache"
            | "hbs"
            | "handlebars"
            | "ejs"
            | "njk"
            | "twig"
            | "jinja"
            | "lock"
    )
}

/// The details of a document. A format that these readers do not handle gives details with `handled` false.
pub(crate) async fn inspect(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    extension: &str,
    content_type: &str,
    listed: &MediaSourceMetadata,
) -> Result<DocumentDetails> {
    let extension = lower(extension.trim());
    let head_details = |container: String| async move {
        let head = instance.head(ctx, &instance.full_key(key)).await?;
        Ok::<_, Error>(DocumentDetails {
            handled: true,
            container,
            properties: BTreeMap::new(),
            headers: head.headers,
            size: listed.size,
        })
    };
    let from_reader = |details: super::bridge::ReaderDetails| DocumentDetails {
        handled: true,
        container: details.container,
        properties: details.properties,
        headers: details.headers,
        size: details.size,
    };
    match extension.as_str() {
        "csv" | "tsv" | "tab" | "psv" => {
            let container = if extension == "tab" {
                "TSV".to_owned()
            } else {
                upper(&extension)
            };
            return head_details(container).await;
        }
        "json" | "geojson" => return head_details(upper(&extension)).await,
        "docx" | "docm" | "dotx" | "dotm" => {
            let details = office_details(ctx, instance, key, &extension, listed, OfficeFamily::Word).await?;
            return Ok(from_reader(details));
        }
        "xlsx" | "xlsm" | "xltx" | "xltm" | "xlam" => {
            let (summary, headers, size) = inspect_spreadsheet_summary(ctx, instance, key, listed.size).await?;
            let office = office_details(ctx, instance, key, &extension, listed, OfficeFamily::Spreadsheet).await?;
            let mut properties = office.properties;
            for (label, value) in [
                ("Worksheets", summary.sheets.to_string()),
                ("Active worksheet", summary.active_sheet),
            ] {
                if !value.trim().is_empty() {
                    properties.entry(label.to_owned()).or_insert(value);
                }
            }
            return Ok(DocumentDetails {
                handled: true,
                container: office_container_label(&extension),
                properties,
                headers,
                size,
            });
        }
        "pptx" | "pptm" | "potx" | "potm" | "ppsx" | "ppsm" | "ppam" | "sldx" | "sldm" => {
            let details = office_details(ctx, instance, key, &extension, listed, OfficeFamily::Presentation).await?;
            return Ok(from_reader(details));
        }
        "vsdx" | "vsdm" | "vssx" | "vssm" | "vstx" | "vstm" => {
            let details = office_details(ctx, instance, key, &extension, listed, OfficeFamily::Visio).await?;
            return Ok(from_reader(details));
        }
        "parquet" => {
            let (summary, headers, size) = inspect_summary(ctx, instance, key, listed.size).await?;
            let mut properties = BTreeMap::new();
            properties.insert("Rows".to_owned(), summary.rows.to_string());
            properties.insert("Columns".to_owned(), summary.columns.to_string());
            return Ok(DocumentDetails {
                handled: true,
                container: "PARQUET".to_owned(),
                properties,
                headers,
                size,
            });
        }
        "sqlite" | "sqlite3" | "db" | "db3" | "s3db" | "sl3" => {
            let (properties, headers, size) = inspect_sqlite_header(ctx, instance, key, listed.size).await?;
            return Ok(DocumentDetails {
                handled: true,
                container: "SQLITE".to_owned(),
                properties,
                headers,
                size,
            });
        }
        _ => {}
    }
    if let Some(details) = structured_details(ctx, instance, key, &extension, content_type, listed).await? {
        return Ok(from_reader(details));
    }
    if extension.is_empty() && is_delimited_content_type(content_type) {
        let tab = lower(content_type).contains("tab") || lower(content_type.trim()) == "text/tsv";
        return head_details(if tab { "TSV" } else { "CSV" }.to_owned()).await;
    }
    if !is_text_line_count_candidate(key, content_type) {
        return Ok(DocumentDetails::default());
    }
    head_details(text_container_label(key, &extension, content_type)).await
}

/// The properties of the header of a SQLite database: the page size, the pages, the schema format, the text
/// encoding, the user version, the declared size, the application id and the version of the writer.
pub(crate) async fn inspect_sqlite_header(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    known_size: i64,
) -> Result<(BTreeMap<String, String>, HeaderMap, i64)> {
    let mut source = RangeSource::open(ctx, instance, key).await?;
    source.set_known_size(known_size);
    let header = read_exact_range(&source, 0, 100).await?;
    if header.len() < 100 || &header[..16] != SQLITE_MAGIC {
        return Err(Error::api(
            422,
            "invalid_sqlite",
            "the object is not a SQLite 3 database",
        ));
    }
    let word = |offset: usize| {
        u32::from_be_bytes([
            header[offset],
            header[offset + 1],
            header[offset + 2],
            header[offset + 3],
        ])
    };
    let mut page_size = i64::from(u16::from_be_bytes([header[16], header[17]]));
    if page_size == 1 {
        page_size = 65_536;
    }
    let page_count = i64::from(word(28));
    let encoding = match word(56) {
        1 => "UTF-8",
        2 => "UTF-16 little-endian",
        3 => "UTF-16 big-endian",
        _ => "Unknown",
    };
    let mut properties = BTreeMap::new();
    properties.insert("Page size".to_owned(), format!("{page_size} bytes"));
    properties.insert("Database pages".to_owned(), page_count.to_string());
    properties.insert("Schema format".to_owned(), word(44).to_string());
    properties.insert("Text encoding".to_owned(), encoding.to_owned());
    properties.insert("User version".to_owned(), word(60).to_string());
    if page_size > 0 && page_count > 0 {
        properties.insert(
            "Declared database size".to_owned(),
            format!("{} bytes", page_size * page_count),
        );
    }
    let application = word(68);
    if application != 0 {
        properties.insert("Application ID".to_owned(), format!("0x{application:08X}"));
    }
    let version = word(96);
    if version != 0 {
        properties.insert(
            "SQLite version".to_owned(),
            format!(
                "{}.{}.{}",
                version / 1_000_000,
                (version / 1_000) % 1_000,
                version % 1_000
            ),
        );
    }
    Ok((properties, source.headers(), source.size_or_zero()))
}

/// The number of fields of the first records of a sample, for a delimiter. A record with one empty field does not
/// count.
fn sample_field_counts(sample: &[u8], delimiter: u8, limit: usize) -> Vec<usize> {
    let mut counts = Vec::with_capacity(limit);
    let mut fields = 1;
    let mut in_quotes = false;
    let mut after_quote = false;
    let mut row_has_content = false;
    let mut index = 0;
    while index < sample.len() && counts.len() < limit {
        let value = sample[index];
        if in_quotes {
            if value == b'"' {
                in_quotes = false;
                after_quote = true;
            } else if !matches!(value, b' ' | b'\t' | b'\r' | b'\n') {
                row_has_content = true;
            }
            index += 1;
            continue;
        }
        if after_quote {
            if value == b'"' {
                in_quotes = true;
                after_quote = false;
                row_has_content = true;
                index += 1;
                continue;
            }
            after_quote = false;
        }
        match value {
            b'"' => in_quotes = true,
            _ if value == delimiter => fields += 1,
            b'\r' | b'\n' => {
                if value == b'\r' && sample.get(index + 1) == Some(&b'\n') {
                    index += 1;
                }
                if row_has_content || fields > 1 {
                    counts.push(fields);
                }
                fields = 1;
                row_has_content = false;
            }
            _ => {
                if value != b' ' && value != b'\t' {
                    row_has_content = true;
                }
            }
        }
        index += 1;
    }
    if counts.len() < limit && (row_has_content || fields > 1) {
        counts.push(fields);
    }
    counts
}

/// The delimiter of a sample of delimited text: of `,`, `;`, tab and `|`, the one whose records most often have the
/// same number of fields (more than one), then the most fields.
pub fn detect_delimited_separator(sample: &[u8]) -> u8 {
    let mut best = b',';
    let mut best_score: i64 = -1;
    for candidate in *b",;\t|" {
        let counts = sample_field_counts(sample, candidate, 25);
        let mut frequencies: BTreeMap<usize, i64> = BTreeMap::new();
        let mut maximum = 0usize;
        for count in counts {
            if count <= 1 {
                continue;
            }
            *frequencies.entry(count).or_insert(0) += 1;
            maximum = maximum.max(count);
        }
        let mode = frequencies.values().copied().max().unwrap_or(0);
        let score = mode * 100 + maximum as i64;
        if score > best_score {
            best = candidate;
            best_score = score;
        }
    }
    best
}

/// The count of the records and of the non-empty columns of delimited text, one chunk after the other. It keeps only
/// one flag for each field of the current record and one flag for each column: a field and a file can be larger
/// than the memory.
#[derive(Debug)]
pub(crate) struct DelimitedCounter {
    delimiter: u8,
    row: Vec<bool>,
    non_empty_columns: Vec<bool>,
    field_non_empty: bool,
    field_started: bool,
    in_quotes: bool,
    after_quote: bool,
    skip_line_feed: bool,
    records: i64,
    total: i64,
}

impl DelimitedCounter {
    /// A counter for a delimiter.
    pub(crate) fn new(delimiter: u8) -> Self {
        Self {
            delimiter,
            row: Vec::with_capacity(32),
            non_empty_columns: Vec::with_capacity(32),
            field_non_empty: false,
            field_started: false,
            in_quotes: false,
            after_quote: false,
            skip_line_feed: false,
            records: 0,
            total: 0,
        }
    }

    fn finish_field(&mut self) {
        self.row.push(self.field_non_empty);
        self.field_non_empty = false;
        self.field_started = false;
    }

    fn finish_record(&mut self) {
        self.finish_field();
        if self.row.iter().any(|value| *value) {
            self.records += 1;
            if self.non_empty_columns.len() < self.row.len() {
                self.non_empty_columns.resize(self.row.len(), false);
            }
            for (index, value) in self.row.iter().enumerate() {
                if *value {
                    self.non_empty_columns[index] = true;
                }
            }
        }
        self.row.clear();
    }

    /// Count the bytes of a chunk.
    pub(crate) fn feed(&mut self, chunk: &[u8]) {
        self.total += chunk.len() as i64;
        for value in chunk.iter().copied() {
            if self.skip_line_feed {
                self.skip_line_feed = false;
                if value == b'\n' {
                    continue;
                }
            }
            if self.in_quotes {
                self.field_started = true;
                if value == b'"' {
                    self.in_quotes = false;
                    self.after_quote = true;
                } else if !matches!(value, b' ' | b'\t' | b'\r' | b'\n') {
                    self.field_non_empty = true;
                }
                continue;
            }
            if self.after_quote {
                if value == b'"' {
                    self.in_quotes = true;
                    self.after_quote = false;
                    self.field_non_empty = true;
                    continue;
                }
                self.after_quote = false;
            }
            match value {
                b'"' => {
                    if self.field_started {
                        self.field_non_empty = true;
                    } else {
                        self.field_started = true;
                        self.in_quotes = true;
                    }
                }
                _ if value == self.delimiter => self.finish_field(),
                b'\r' => {
                    self.finish_record();
                    self.skip_line_feed = true;
                }
                b'\n' => self.finish_record(),
                _ => {
                    self.field_started = true;
                    if value != b' ' && value != b'\t' {
                        self.field_non_empty = true;
                    }
                }
            }
        }
    }

    /// The summary at the end of the text, and the bytes that it read. A text that ends in a quoted field is an
    /// error.
    pub(crate) fn finish(mut self) -> Result<(DelimitedSummary, i64)> {
        if self.in_quotes {
            return Err(Error::api(
                422,
                "invalid_delimited_file",
                "the delimited file ends inside a quoted field",
            ));
        }
        if self.field_started || self.field_non_empty || !self.row.is_empty() {
            self.finish_record();
        }
        let columns = self.non_empty_columns.iter().filter(|value| **value).count() as i64;
        let rows = if self.records > 0 { self.records - 1 } else { 0 };
        Ok((DelimitedSummary { rows, columns }, self.total))
    }
}

/// Read the complete object in order with one request. Gives the headers and the body.
async fn read_complete(ctx: &OpCtx, instance: &Arc<Instance>, key: &str, what: &str) -> Result<(HeaderMap, Body)> {
    let response = instance.get(ctx, &instance.full_key(key), &HeaderMap::new()).await?;
    if !(200..300).contains(&response.status) {
        return Err(Error::internal(format!("read {what} object: HTTP {}", response.status)));
    }
    Ok((response.headers, response.body))
}

/// The next chunk of a body, or `None` at its end.
async fn next_chunk(body: &mut Body) -> Result<Option<bytes::Bytes>> {
    while let Some(frame) = body.frame().await {
        if let Ok(data) = frame?.into_data() {
            return Ok(Some(data));
        }
    }
    Ok(None)
}

/// The rows and the non-empty columns of a delimited object, with one read of the complete object in order. The
/// first non-empty record is the header. The delimiter comes from the extension (`tsv`, `tab`, `psv`) or from the
/// first 128 KiB. Gives the headers of the object and the bytes that the count read.
pub async fn inspect_delimited_summary(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    extension: &str,
) -> Result<(DelimitedSummary, HeaderMap, i64)> {
    let (headers, mut body) = read_complete(ctx, instance, key, "delimited").await?;
    let mut pending: Vec<bytes::Bytes> = Vec::new();
    let delimiter = match lower(extension).as_str() {
        "tsv" | "tab" => b'\t',
        "psv" => b'|',
        _ => {
            let mut sample = Vec::with_capacity(DELIMITER_SAMPLE_BYTES);
            while sample.len() < DELIMITER_SAMPLE_BYTES {
                let Some(chunk) = next_chunk(&mut body).await? else {
                    break;
                };
                let room = DELIMITER_SAMPLE_BYTES - sample.len();
                sample.extend_from_slice(&chunk[..chunk.len().min(room)]);
                pending.push(chunk);
            }
            detect_delimited_separator(&sample)
        }
    };
    let mut counter = DelimitedCounter::new(delimiter);
    for chunk in pending {
        counter.feed(&chunk);
    }
    while let Some(chunk) = next_chunk(&mut body).await? {
        counter.feed(&chunk);
    }
    let (summary, total) = counter.finish()?;
    Ok((summary, headers, total))
}

/// The lines of a text object, with one read of the complete object in order: the line ends, and one more line when
/// the last byte is not a line end. Gives the headers of the object and the bytes that the count read.
pub async fn count_object_lines(ctx: &OpCtx, instance: &Arc<Instance>, key: &str) -> Result<(i64, HeaderMap, i64)> {
    let (headers, mut body) = read_complete(ctx, instance, key, "text").await?;
    let mut lines: i64 = 0;
    let mut total: i64 = 0;
    let mut last = 0u8;
    while let Some(chunk) = next_chunk(&mut body).await? {
        if let Some(byte) = chunk.last() {
            total += chunk.len() as i64;
            lines += chunk.iter().filter(|byte| **byte == b'\n').count() as i64;
            last = *byte;
        }
    }
    if total > 0 && last != b'\n' {
        lines += 1;
    }
    Ok((lines, headers, total))
}
