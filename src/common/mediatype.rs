//! The media types of the object keys: the built-in table of the extensions, the table of the previews, the types
//! that a browser opens inline, and the safety headers of an answer with object bytes. The server, the volumes and
//! the archives use the same tables. The program reads no media type file of the system.

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

/// The media type of a `Content-Type` value without its parameters, in lower case and without spaces.
pub fn base_media_type(value: &str) -> String {
    value.split(';').next().unwrap_or("").trim().to_ascii_lowercase()
}

/// The media type of an extension (with its dot, in lower case), or an empty text. The table is the built-in table of
/// the server: the server reads no media type file of the system.
pub fn type_by_extension(extension: &str) -> &'static str {
    match extension.to_ascii_lowercase().as_str() {
        ".avif" => "image/avif",
        ".css" => "text/css; charset=utf-8",
        ".gif" => "image/gif",
        ".htm" | ".html" => "text/html; charset=utf-8",
        ".jpeg" | ".jpg" => "image/jpeg",
        ".js" | ".mjs" => "text/javascript; charset=utf-8",
        ".json" => "application/json",
        ".pdf" => "application/pdf",
        ".png" => "image/png",
        ".svg" => "image/svg+xml",
        ".wasm" => "application/wasm",
        ".webp" => "image/webp",
        ".xml" => "text/xml; charset=utf-8",
        _ => "",
    }
}

/// The media type of a key from its extension, for an object that the provider gives with a generic type.
pub fn preview_content_type(key: &str) -> &'static str {
    let extension = path_ext(key).to_lowercase();
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
    let extension = path_ext(key).to_lowercase();
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

/// The headers of each answer with object bytes: the objects share the origin of the application, so an object that
/// a browser can run (HTML, SVG) runs in a sandbox without access to the page.
pub fn apply_object_safety_headers(headers: &mut http::HeaderMap) {
    headers.insert(
        http::header::CONTENT_SECURITY_POLICY,
        http::HeaderValue::from_static(
            "sandbox; default-src 'none'; img-src data: blob:; media-src data: blob:; style-src 'unsafe-inline'",
        ),
    );
    headers.insert(
        http::HeaderName::from_static("cross-origin-resource-policy"),
        http::HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        http::header::X_CONTENT_TYPE_OPTIONS,
        http::HeaderValue::from_static("nosniff"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tables_give_the_media_type_of_a_key() {
        assert_eq!(path_ext("a/b.tar.GZ"), ".GZ");
        assert_eq!(path_ext("a.b/c"), "");
        assert_eq!(base_media_type(" Text/Plain ; charset=utf-8"), "text/plain");
        assert_eq!(type_by_extension(".MJS"), "text/javascript; charset=utf-8");
        assert_eq!(type_by_extension(".txt"), "");
        assert_eq!(preview_content_type("a/B.MP4"), "video/mp4");
        assert_eq!(preview_content_type("x.html"), "text/html; charset=utf-8");
        assert_eq!(preview_content_type("x.txt"), "");
        assert!(browser_inline_content("a.mp4", ""));
        assert!(!browser_inline_content("a.mkv", "video/x-matroska"));
        assert!(browser_inline_content("x", " Image/PNG ; q=1"));
    }
}
