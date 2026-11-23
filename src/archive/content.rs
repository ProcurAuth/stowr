//! The content types and the headers of the bytes of an archive entry.
//!
//! The module gives the media type of a file name and the rules of inline display. It also gives the active types
//! that never display inline, the sandbox headers and the value of `Content-Disposition`.

use crate::common::mediatype::base_media_type;
pub use crate::common::mediatype::{
    apply_object_safety_headers, browser_inline_content, path_ext, preview_content_type, type_by_extension,
};

/// The extensions of the documents and scripts that a browser can run.
const ACTIVE_EXTENSIONS: &[&str] = &[
    ".html", ".htm", ".xhtml", ".xht", ".shtml", ".svg", ".svgz", ".xml", ".xsl", ".xslt", ".js", ".mjs", ".cjs",
    ".wasm", ".hta",
];

/// True for an entry that a browser can run as a document or a script on the origin of the application: HTML, SVG,
/// XML, XSL, JavaScript, WebAssembly, HTA.
pub fn archive_entry_active_content(filename: &str, content_type: &str) -> bool {
    if ACTIVE_EXTENSIONS.contains(&path_ext(filename).to_lowercase().as_str()) {
        return true;
    }
    let media = base_media_type(content_type);
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
