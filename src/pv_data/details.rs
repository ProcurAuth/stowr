//! The details of documents (`/api/media-info` for the formats that are not media): the container and the properties
//! that a bounded read gives.
//!
//! A details request never reads a whole object. A delimited file, a JSON file or a text gives only its storage
//! headers; its count is a separate action of the interface (`crate::pv_docs::count`), because it reads the complete
//! object in order.

use std::collections::BTreeMap;
use std::sync::Arc;

use http::HeaderMap;

use super::DocumentDetails;
use super::parquet::{inspect_summary, read_exact_range};
use super::sqlite::SQLITE_MAGIC;
use super::text::upper;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::instance::Instance;
use crate::instance::range::RangeSource;
use crate::pv_docs::count::inspect_spreadsheet_summary;
use crate::pv_docs::office::{
    OfficeFamily, OfficeSummary, container_label, inspect_office_properties, merge_office_properties,
};
use crate::pv_docs::util::lower;
use crate::pv_media::MediaSourceMetadata;

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
    let from_office = |summary: OfficeSummary| DocumentDetails {
        handled: true,
        container: summary.container,
        properties: summary.properties,
        headers: summary.headers,
        size: summary.size,
    };
    let office = |family: OfficeFamily| inspect_office_properties(ctx, instance, key, &extension, listed, family);
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
        "docx" | "docm" | "dotx" | "dotm" => return Ok(from_office(office(OfficeFamily::Word).await?)),
        "xlsx" | "xlsm" | "xltx" | "xltm" | "xlam" => {
            let (summary, headers, size) = inspect_spreadsheet_summary(ctx, instance, key, listed.size).await?;
            let workbook = office(OfficeFamily::Spreadsheet).await?;
            let sheets = BTreeMap::from([
                ("Worksheets".to_owned(), summary.sheets.to_string()),
                ("Active worksheet".to_owned(), summary.active_sheet),
            ]);
            return Ok(DocumentDetails {
                handled: true,
                container: container_label(&extension),
                properties: merge_office_properties(workbook.properties, &sheets),
                headers,
                size,
            });
        }
        "pptx" | "pptm" | "potx" | "potm" | "ppsx" | "ppsm" | "ppam" | "sldx" | "sldm" => {
            return Ok(from_office(office(OfficeFamily::Presentation).await?));
        }
        "vsdx" | "vsdm" | "vssx" | "vssm" | "vstx" | "vstm" => {
            return Ok(from_office(office(OfficeFamily::Visio).await?));
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
    if let Some(summary) =
        crate::pv_structured::inspect_structured_metadata(ctx, instance, key, &extension, content_type, listed).await?
    {
        return Ok(DocumentDetails {
            handled: true,
            container: summary.container,
            properties: summary.properties,
            headers: summary.headers,
            size: summary.size,
        });
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
