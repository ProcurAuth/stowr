//! The content types and the headers of the bytes of an archive entry.
//!
//! The module gives the media type of a file name and the rules of inline display. It also gives the active types
//! that never display inline, the sandbox headers and the value of `Content-Disposition`.

use http::HeaderMap;
use http::header::{HeaderName, HeaderValue};

use super::names::path_ext;

/// The media types of the previews, by extension (lower case, with the dot).
const PREVIEW_TYPES: &[(&str, &str)] = &[
    (".mp4", "video/mp4"),
    (".m4v", "video/x-m4v"),
    (".mov", "video/quicktime"),
    (".webm", "video/webm"),
    (".mkv", "video/x-matroska"),
    (".mxf", "application/mxf"),
    (".avi", "video/x-msvideo"),
    (".ogv", "video/ogg"),
    (".mpg", "video/mpeg"),
    (".mpeg", "video/mpeg"),
    (".m2ts", "video/mp2t"),
    (".mts", "video/mp2t"),
    (".ts", "video/mp2t"),
    (".vob", "video/dvd"),
    (".mp3", "audio/mpeg"),
    (".m4a", "audio/mp4"),
    (".aac", "audio/aac"),
    (".flac", "audio/flac"),
    (".wav", "audio/wav"),
    (".ogg", "audio/ogg"),
    (".opus", "audio/ogg; codecs=opus"),
    (".aif", "audio/aiff"),
    (".aiff", "audio/aiff"),
    (".jpg", "image/jpeg"),
    (".jpeg", "image/jpeg"),
    (".png", "image/png"),
    (".gif", "image/gif"),
    (".webp", "image/webp"),
    (".avif", "image/avif"),
    (".svg", "image/svg+xml"),
    (".bmp", "image/bmp"),
    (".ico", "image/x-icon"),
    (".vcf", "text/vcard; charset=utf-8"),
    (".vcard", "text/vcard; charset=utf-8"),
    (".ics", "text/calendar; charset=utf-8"),
    (".ifb", "text/calendar; charset=utf-8"),
    (".eml", "message/rfc822"),
    (".mime", "message/rfc822"),
    (".pem", "application/x-pem-file"),
    (".crt", "application/x-x509-ca-cert"),
    (".cer", "application/pkix-cert"),
    (".der", "application/pkix-cert"),
    (".tif", "image/tiff"),
    (".tiff", "image/tiff"),
    (".pdf", "application/pdf"),
];

/// The built-in table of media types by extension.
const EXTENSION_TYPES: &[(&str, &str)] = &[
    (".avif", "image/avif"),
    (".css", "text/css; charset=utf-8"),
    (".gif", "image/gif"),
    (".htm", "text/html; charset=utf-8"),
    (".html", "text/html; charset=utf-8"),
    (".jpeg", "image/jpeg"),
    (".jpg", "image/jpeg"),
    (".js", "text/javascript; charset=utf-8"),
    (".json", "application/json"),
    (".mjs", "text/javascript; charset=utf-8"),
    (".pdf", "application/pdf"),
    (".png", "image/png"),
    (".svg", "image/svg+xml"),
    (".wasm", "application/wasm"),
    (".webp", "image/webp"),
    (".xml", "text/xml; charset=utf-8"),
];

/// The extensions that a browser displays inline.
const INLINE_EXTENSIONS: &[&str] = &[
    ".pdf", ".txt", ".log", ".css", ".json", ".xml", ".html", ".htm", ".png", ".jpg", ".jpeg", ".gif", ".webp",
    ".avif", ".bmp", ".ico", ".svg", ".mp3", ".m4a", ".aac", ".flac", ".wav", ".ogg", ".oga", ".opus", ".mp4", ".m4v",
    ".mov", ".webm", ".ogv",
];

/// The media types that a browser displays inline.
const INLINE_TYPES: &[&str] = &[
    "application/pdf",
    "text/plain",
    "text/css",
    "text/html",
    "application/json",
    "application/xml",
    "text/xml",
    "image/png",
    "image/jpeg",
    "image/gif",
    "image/webp",
    "image/avif",
    "image/bmp",
    "image/x-icon",
    "image/vnd.microsoft.icon",
    "image/svg+xml",
    "audio/mpeg",
    "audio/mp4",
    "audio/aac",
    "audio/flac",
    "audio/wav",
    "audio/x-wav",
    "audio/ogg",
    "audio/opus",
    "video/mp4",
    "video/quicktime",
    "video/webm",
    "video/ogg",
];

/// The extensions of the documents and scripts that a browser can run.
const ACTIVE_EXTENSIONS: &[&str] = &[
    ".html", ".htm", ".xhtml", ".xht", ".shtml", ".svg", ".svgz", ".xml", ".xsl", ".xslt", ".js", ".mjs", ".cjs",
    ".wasm", ".hta",
];

fn lookup(table: &[(&str, &'static str)], key: &str) -> Option<&'static str> {
    table
        .iter()
        .find(|(extension, _)| *extension == key)
        .map(|(_, value)| *value)
}

/// The media type of an extension in the built-in table (the case of the extension does not matter), or an empty
/// text.
pub fn type_by_extension(extension: &str) -> &'static str {
    lookup(EXTENSION_TYPES, &extension.to_ascii_lowercase()).unwrap_or("")
}

/// The media type of a key for the previews: the table of the previews, else the built-in table, else an empty
/// text.
pub fn preview_content_type(key: &str) -> &'static str {
    let extension = path_ext(key).to_lowercase();
    lookup(PREVIEW_TYPES, &extension).unwrap_or_else(|| type_by_extension(&extension))
}

/// The media type of a `Content-Type` value: the part before `;`, without spaces, in lower case.
fn media_type(content_type: &str) -> String {
    content_type.split(';').next().unwrap_or("").trim().to_lowercase()
}

/// True when a browser displays the content inline without a plug-in: by the extension, else by the media type.
pub fn browser_inline_content(key: &str, content_type: &str) -> bool {
    let extension = path_ext(key).to_lowercase();
    if INLINE_EXTENSIONS.contains(&extension.as_str()) {
        return true;
    }
    INLINE_TYPES.contains(&media_type(content_type).as_str())
}

/// True for an entry that a browser can run as a document or a script on the origin of the application: HTML, SVG,
/// XML, XSL, JavaScript, WebAssembly, HTA.
pub fn archive_entry_active_content(filename: &str, content_type: &str) -> bool {
    if ACTIVE_EXTENSIONS.contains(&path_ext(filename).to_lowercase().as_str()) {
        return true;
    }
    let media = media_type(content_type);
    matches!(
        media.as_str(),
        "text/html" | "image/svg+xml" | "text/xml" | "application/xml" | "application/wasm" | "text/xsl"
    ) || media.ends_with("+xml")
        || media.contains("javascript")
        || media.contains("ecmascript")
}

/// True for an SVG image: by the extension or by the media type.
pub fn is_svg_content(filename: &str, content_type: &str) -> bool {
    path_ext(filename).eq_ignore_ascii_case(".svg") || content_type.trim().to_lowercase().starts_with("image/svg+xml")
}

/// The sandbox headers of each answer that carries object bytes.
pub fn apply_object_safety_headers(headers: &mut HeaderMap) {
    headers.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(
            "sandbox; default-src 'none'; img-src data: blob:; media-src data: blob:; style-src 'unsafe-inline'",
        ),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
}

fn is_tspecial(byte: u8) -> bool {
    b"()<>@,;:\\\"/[]?=".contains(&byte)
}

fn is_token(value: &[u8]) -> bool {
    !value.is_empty()
        && value
            .iter()
            .all(|byte| *byte > 0x20 && *byte < 0x7f && !is_tspecial(*byte))
}

/// The value `disposition; filename=...` of a `Content-Disposition` header (RFC 2045, RFC 2231). A token name stays
/// as it is. Another printable ASCII name becomes a quoted string with `"` and `\` escaped. A name with a byte
/// outside the printable ASCII set becomes `filename*=utf-8''` with percent escapes. `None`: the disposition is not
/// a token.
pub fn format_disposition(disposition: &str, filename: &[u8]) -> Option<String> {
    if !is_token(disposition.as_bytes()) {
        return None;
    }
    let mut out = disposition.to_ascii_lowercase();
    out.push_str("; filename");
    let needs_encoding = filename
        .iter()
        .any(|byte| (*byte < b' ' || *byte > b'~') && *byte != b'\t');
    if needs_encoding {
        out.push_str("*=utf-8''");
        for &byte in filename {
            if byte <= b' ' || byte >= 0x7f || byte == b'*' || byte == b'\'' || byte == b'%' || is_tspecial(byte) {
                out.push_str(&format!("%{byte:02X}"));
            } else {
                out.push(char::from(byte));
            }
        }
        return Some(out);
    }
    out.push('=');
    if is_token(filename) {
        out.push_str(&String::from_utf8_lossy(filename));
        return Some(out);
    }
    out.push('"');
    for &byte in filename {
        if byte == b'"' || byte == b'\\' {
            out.push('\\');
        }
        out.push(char::from(byte));
    }
    out.push('"');
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_types_come_from_the_tables() {
        assert_eq!(preview_content_type("a/b.MP4"), "video/mp4");
        assert_eq!(preview_content_type("x.html"), "text/html; charset=utf-8");
        assert_eq!(preview_content_type("x.js"), "text/javascript; charset=utf-8");
        assert_eq!(preview_content_type("x.txt"), "");
        assert_eq!(preview_content_type("x"), "");
        assert_eq!(type_by_extension(".JSON"), "application/json");
    }

    #[test]
    fn active_content_and_inline_display() {
        assert!(archive_entry_active_content("page.HTML", ""));
        assert!(archive_entry_active_content(
            "data",
            "application/atom+xml; charset=utf-8"
        ));
        assert!(archive_entry_active_content("data", "text/ecmascript"));
        assert!(!archive_entry_active_content("note.txt", "text/plain"));
        assert!(browser_inline_content("note.txt", ""));
        assert!(browser_inline_content("x", " Image/PNG ; q=1"));
        assert!(!browser_inline_content("movie.mkv", "video/x-matroska"));
        assert!(is_svg_content("logo.SVG", ""));
        assert!(is_svg_content("logo", " image/svg+xml"));
    }

    #[test]
    fn dispositions_quote_or_encode_the_file_name() {
        assert_eq!(
            format_disposition("attachment", b"folder.zip").as_deref(),
            Some("attachment; filename=folder.zip")
        );
        assert_eq!(
            format_disposition("inline", b"board review.mp4").as_deref(),
            Some("inline; filename=\"board review.mp4\"")
        );
        assert_eq!(
            format_disposition("attachment", b"a\"b\\c d").as_deref(),
            Some("attachment; filename=\"a\\\"b\\\\c d\"")
        );
        assert_eq!(
            format_disposition("attachment", "café 1.txt".as_bytes()).as_deref(),
            Some("attachment; filename*=utf-8''caf%C3%A9%201.txt")
        );
        assert_eq!(format_disposition("not a token", b"x"), None);
    }
}
