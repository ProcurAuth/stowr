//! The kind of an object for Insights and the details, and the media types of the object routes: the type that a key
//! gives when the provider gives a generic type, and the types that a browser opens inline.

use super::mediatype::{base_media_type, type_by_extension};
use super::paths;

/// The kind of a key: `image`, `video`, `audio`, `pdf`, `markdown`, `document`, `spreadsheet`, `presentation`,
/// `database`, `contact`, `calendar`, `email`, `certificate`, `archive`, `code`, `text` or `other`. The media type
/// decides first, then the extension, then the name of the file.
pub fn detect_kind(key: &str, content_type: &str) -> &'static str {
    let media_type = base_media_type(content_type);
    if media_type.starts_with("image/") {
        return "image";
    }
    if media_type.starts_with("video/") {
        return "video";
    }
    if media_type.starts_with("audio/") {
        return "audio";
    }
    if media_type == "application/pdf" {
        return "pdf";
    }
    if media_type.contains("sqlite") {
        return "database";
    }
    let name = paths::base(key).to_lowercase();
    let extension = paths::ext(&name).trim_start_matches('.').to_owned();
    let by_extension = match extension.as_str() {
        "png" | "jpg" | "jpeg" | "jpe" | "gif" | "webp" | "bmp" | "dib" | "svg" | "avif" | "heif" | "heic" | "tif"
        | "tiff" | "qoi" | "ico" | "cur" | "raw" | "raf" | "dng" | "cr2" | "cr3" | "nef" | "nrw" | "arw" | "srf"
        | "sr2" | "orf" | "rw2" | "pef" | "rwl" | "x3f" | "iiq" | "3fr" | "fff" | "mef" | "mos" | "mrw" => "image",
        "mp4" | "mkv" | "webm" | "avi" | "mov" | "m4v" | "mpg" | "mpeg" | "flv" | "3gp" | "wmv" | "ogv" | "m2ts"
        | "vob" | "mxf" | "m2v" | "asf" | "rm" | "rmvb" => "video",
        "mp3" | "flac" | "wav" | "wave" | "m4a" | "aac" | "ogg" | "oga" | "opus" | "aiff" | "aif" | "alac" | "wma"
        | "amr" | "midi" | "mid" => "audio",
        "pdf" => "pdf",
        "md" | "markdown" | "mdown" | "mkd" | "rmd" => "markdown",
        "doc" | "docx" | "docm" | "dot" | "dotx" | "dotm" | "rtf" | "odt" | "pages" => "document",
        "xls" | "xlsx" | "xlsm" | "xlsb" | "xlt" | "xltx" | "xltm" | "ods" | "csv" | "tsv" | "tab" | "psv"
        | "numbers" | "parquet" | "arrow" | "feather" => "spreadsheet",
        "ppt" | "pptx" | "pptm" | "pps" | "ppsx" | "odp" => "presentation",
        "sqlite" | "sqlite3" | "db" | "db3" | "s3db" | "sl3" => "database",
        "vcf" | "vcard" => "contact",
        "ics" | "ifb" => "calendar",
        "eml" | "mime" | "mht" | "mhtml" => "email",
        "pem" | "crt" | "cer" | "cert" | "der" | "csr" | "req" | "p7b" | "p7c" | "spc" | "pfx" | "p12" | "key"
        | "pub" => "certificate",
        "zip" | "jar" | "war" | "ear" | "apk" | "aar" | "xpi" | "crx" | "vsix" | "epub" | "rar" | "7z" | "tar"
        | "gz" | "tgz" | "bz2" | "tbz" | "xz" | "txz" | "zst" => "archive",
        "js" | "mjs" | "cjs" | "jsx" | "ts" | "mts" | "cts" | "tsx" | "json" | "geojson" | "jsonl" | "ndjson"
        | "yaml" | "yml" | "toml" | "ini" | "hcl" | "tf" | "tfvars" | "sh" | "bash" | "zsh" | "fish" | "ps1" | "py"
        | "pyw" | "pyi" | "rb" | "php" | "java" | "kt" | "kts" | "go" | "mod" | "sum" | "work" | "rs" | "c" | "cc"
        | "cpp" | "cxx" | "h" | "hpp" | "hxx" | "cs" | "swift" | "sql" | "css" | "scss" | "sass" | "less" | "html"
        | "htm" | "xhtml" | "xml" | "proto" | "graphql" | "gql" | "diff" | "patch" => "code",
        "txt" | "log" | "conf" | "cfg" | "properties" => "text",
        _ => "",
    };
    if !by_extension.is_empty() {
        return by_extension;
    }
    match name.as_str() {
        "dockerfile" | "containerfile" | "makefile" | "gnumakefile" | "jenkinsfile" | "procfile" | "gemfile"
        | "rakefile" | "vagrantfile" | "caddyfile" | "justfile" | "taskfile" | "earthfile" | "brewfile" | "podfile" => {
            return "code";
        }
        _ => {}
    }
    if name.starts_with(".env") || name.starts_with(".git") || name.starts_with(".docker") {
        return "code";
    }
    "other"
}

/// True for a generic media type that says nothing about the bytes: empty, `application/octet-stream`,
/// `binary/octet-stream`, `application/binary`, `application/unknown`.
pub fn is_generic_object_content_type(value: &str) -> bool {
    matches!(
        base_media_type(value).as_str(),
        "" | "application/octet-stream" | "binary/octet-stream" | "application/binary" | "application/unknown"
    )
}

/// The media type of a key from its extension, for an object that the provider gives with a generic type.
pub fn preview_content_type(key: &str) -> &'static str {
    let extension = paths::ext(key).to_lowercase();
    let known = match extension.as_str() {
        ".mp4" => "video/mp4",
        ".m4v" => "video/x-m4v",
        ".mov" => "video/quicktime",
        ".webm" => "video/webm",
        ".mkv" => "video/x-matroska",
        ".mxf" => "application/mxf",
        ".avi" => "video/x-msvideo",
        ".ogv" => "video/ogg",
        ".mpg" | ".mpeg" => "video/mpeg",
        ".m2ts" | ".mts" | ".ts" => "video/mp2t",
        ".vob" => "video/dvd",
        ".mp3" => "audio/mpeg",
        ".m4a" => "audio/mp4",
        ".aac" => "audio/aac",
        ".flac" => "audio/flac",
        ".wav" => "audio/wav",
        ".ogg" => "audio/ogg",
        ".opus" => "audio/ogg; codecs=opus",
        ".aif" | ".aiff" => "audio/aiff",
        ".jpg" | ".jpeg" => "image/jpeg",
        ".png" => "image/png",
        ".gif" => "image/gif",
        ".webp" => "image/webp",
        ".avif" => "image/avif",
        ".svg" => "image/svg+xml",
        ".bmp" => "image/bmp",
        ".ico" => "image/x-icon",
        ".vcf" | ".vcard" => "text/vcard; charset=utf-8",
        ".ics" | ".ifb" => "text/calendar; charset=utf-8",
        ".eml" | ".mime" => "message/rfc822",
        ".pem" => "application/x-pem-file",
        ".crt" => "application/x-x509-ca-cert",
        ".cer" | ".der" => "application/pkix-cert",
        ".tif" | ".tiff" => "image/tiff",
        ".pdf" => "application/pdf",
        _ => "",
    };
    if !known.is_empty() {
        return known;
    }
    type_by_extension(&extension)
}

/// True when a browser opens the object inline without a plugin. A media type of the provider alone is not enough
/// for a codec that browsers do not play (MKV, AVI, WMA): such an object downloads with its own name.
pub fn browser_inline_content(key: &str, content_type: &str) -> bool {
    let extension = paths::ext(key).to_lowercase();
    if matches!(
        extension.as_str(),
        ".pdf"
            | ".txt"
            | ".log"
            | ".css"
            | ".json"
            | ".xml"
            | ".html"
            | ".htm"
            | ".png"
            | ".jpg"
            | ".jpeg"
            | ".gif"
            | ".webp"
            | ".avif"
            | ".bmp"
            | ".ico"
            | ".svg"
            | ".mp3"
            | ".m4a"
            | ".aac"
            | ".flac"
            | ".wav"
            | ".ogg"
            | ".oga"
            | ".opus"
            | ".mp4"
            | ".m4v"
            | ".mov"
            | ".webm"
            | ".ogv"
    ) {
        return true;
    }
    matches!(
        base_media_type(content_type).as_str(),
        "application/pdf"
            | "text/plain"
            | "text/css"
            | "text/html"
            | "application/json"
            | "application/xml"
            | "text/xml"
            | "image/png"
            | "image/jpeg"
            | "image/gif"
            | "image/webp"
            | "image/avif"
            | "image/bmp"
            | "image/x-icon"
            | "image/vnd.microsoft.icon"
            | "image/svg+xml"
            | "audio/mpeg"
            | "audio/mp4"
            | "audio/aac"
            | "audio/flac"
            | "audio/wav"
            | "audio/x-wav"
            | "audio/ogg"
            | "audio/opus"
            | "video/mp4"
            | "video/quicktime"
            | "video/webm"
            | "video/ogg"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_follow_the_media_type_then_the_name() {
        assert_eq!(detect_kind("a.bin", "image/png; x=y"), "image");
        assert_eq!(detect_kind("a.bin", "application/x-sqlite3"), "database");
        assert_eq!(detect_kind("dir/Report.PDF", ""), "pdf");
        assert_eq!(detect_kind("src/main.rs", "text/plain"), "code");
        assert_eq!(detect_kind("Dockerfile", ""), "code");
        assert_eq!(detect_kind(".env.local", ""), "code");
        assert_eq!(detect_kind("notes.txt", ""), "text");
        assert_eq!(detect_kind("data.unknown", ""), "other");
    }

    #[test]
    fn generic_types_and_inline_rules() {
        assert!(is_generic_object_content_type(" Application/Octet-Stream ; x=1"));
        assert!(!is_generic_object_content_type("video/mp4"));
        assert_eq!(preview_content_type("a/B.MP4"), "video/mp4");
        assert_eq!(preview_content_type("a.json"), "application/json");
        assert!(browser_inline_content("a.mp4", ""));
        assert!(!browser_inline_content("a.mkv", "video/x-matroska"));
        assert!(browser_inline_content("a.bin", "text/plain; charset=utf-8"));
    }
}
