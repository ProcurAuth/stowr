//! The media type of the first bytes of an object (the algorithm of <https://mimesniff.spec.whatwg.org/>), and the
//! built-in table of the media types of the extensions. The technical inspection uses them.
//!
//! The server reads no media type file of the system: the table is the whole source. The work package `server` has
//! the same two functions for its answers; the two give the same values.

/// The most bytes that the detection reads.
const SNIFF_LEN: usize = 512;

/// The media type of an extension (with its dot), or an empty text.
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

/// The extension of the last part of a key, with its dot, or an empty text.
pub fn extension(key: &str) -> &str {
    let name = key.rsplit('/').next().unwrap_or(key);
    name.rfind('.').map_or("", |index| &name[index..])
}

fn is_space(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\n' | 0x0c | b'\r' | b' ')
}

/// A tag of HTML: the case of the letters does not matter, and a space or `>` must follow.
fn html_match(data: &[u8], signature: &[u8]) -> bool {
    if data.len() < signature.len() + 1 {
        return false;
    }
    for (index, expected) in signature.iter().enumerate() {
        let mut byte = data[index];
        if expected.is_ascii_uppercase() {
            byte &= 0xdf;
        }
        if byte != *expected {
            return false;
        }
    }
    matches!(data[signature.len()], b' ' | b'>')
}

fn masked_match(data: &[u8], mask: &[u8], pattern: &[u8]) -> bool {
    if mask.len() != pattern.len() || data.len() < pattern.len() {
        return false;
    }
    data.iter()
        .zip(mask)
        .zip(pattern)
        .all(|((byte, mask), expected)| byte & mask == *expected)
}

fn mp4_match(data: &[u8]) -> bool {
    if data.len() < 12 {
        return false;
    }
    let box_size = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if data.len() < box_size || !box_size.is_multiple_of(4) || &data[4..8] != b"ftyp" {
        return false;
    }
    let mut start = 8;
    while start < box_size {
        // The four bytes at 12 are the version of the major brand.
        if start != 12 && data.get(start..start + 3) == Some(b"mp4".as_slice()) {
            return true;
        }
        start += 4;
    }
    false
}

const HTML_SIGNATURES: [&[u8]; 17] = [
    b"<!DOCTYPE HTML",
    b"<HTML",
    b"<HEAD",
    b"<SCRIPT",
    b"<IFRAME",
    b"<H1",
    b"<DIV",
    b"<FONT",
    b"<TABLE",
    b"<A",
    b"<STYLE",
    b"<TITLE",
    b"<B",
    b"<BODY",
    b"<BR",
    b"<P",
    b"<!--",
];

/// The media type of the first bytes of a body. It reads at most 512 bytes and gives `application/octet-stream`
/// when no rule matches.
pub fn detect_content_type(data: &[u8]) -> &'static str {
    let data = &data[..data.len().min(SNIFF_LEN)];
    let first = data.iter().position(|byte| !is_space(*byte)).unwrap_or(data.len());
    let trimmed = &data[first..];
    if HTML_SIGNATURES.iter().any(|signature| html_match(trimmed, signature)) {
        return "text/html; charset=utf-8";
    }
    if trimmed.starts_with(b"<?xml") {
        return "text/xml; charset=utf-8";
    }
    const EXACT_FIRST: [(&[u8], &str); 2] = [
        (b"%PDF-", "application/pdf"),
        (b"%!PS-Adobe-", "application/postscript"),
    ];
    for (signature, media_type) in EXACT_FIRST {
        if data.starts_with(signature) {
            return media_type;
        }
    }
    const MASKED_TEXT: [(&[u8], &[u8], &str); 3] = [
        (b"\xFF\xFF\x00\x00", b"\xFE\xFF\x00\x00", "text/plain; charset=utf-16be"),
        (b"\xFF\xFF\x00\x00", b"\xFF\xFE\x00\x00", "text/plain; charset=utf-16le"),
        (b"\xFF\xFF\xFF\x00", b"\xEF\xBB\xBF\x00", "text/plain; charset=utf-8"),
    ];
    for (mask, pattern, media_type) in MASKED_TEXT {
        if masked_match(data, mask, pattern) {
            return media_type;
        }
    }
    const EXACT_IMAGES: [(&[u8], &str); 5] = [
        (b"\x00\x00\x01\x00", "image/x-icon"),
        (b"\x00\x00\x02\x00", "image/x-icon"),
        (b"BM", "image/bmp"),
        (b"GIF87a", "image/gif"),
        (b"GIF89a", "image/gif"),
    ];
    for (signature, media_type) in EXACT_IMAGES {
        if data.starts_with(signature) {
            return media_type;
        }
    }
    if masked_match(
        data,
        b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF",
        b"RIFF\x00\x00\x00\x00WEBPVP",
    ) {
        return "image/webp";
    }
    if data.starts_with(b"\x89PNG\x0D\x0A\x1A\x0A") {
        return "image/png";
    }
    if data.starts_with(b"\xFF\xD8\xFF") {
        return "image/jpeg";
    }
    const MASKED_MEDIA: [(&[u8], &[u8], &str); 6] = [
        (
            b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
            b"FORM\x00\x00\x00\x00AIFF",
            "audio/aiff",
        ),
        (b"\xFF\xFF\xFF", b"ID3", "audio/mpeg"),
        (b"\xFF\xFF\xFF\xFF\xFF", b"OggS\x00", "application/ogg"),
        (
            b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF",
            b"MThd\x00\x00\x00\x06",
            "audio/midi",
        ),
        (
            b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
            b"RIFF\x00\x00\x00\x00AVI ",
            "video/avi",
        ),
        (
            b"\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF",
            b"RIFF\x00\x00\x00\x00WAVE",
            "audio/wave",
        ),
    ];
    for (mask, pattern, media_type) in MASKED_MEDIA {
        if masked_match(data, mask, pattern) {
            return media_type;
        }
    }
    if mp4_match(data) {
        return "video/mp4";
    }
    if data.starts_with(b"\x1A\x45\xDF\xA3") {
        return "video/webm";
    }
    // 34 bytes of any value, then `LP`.
    if data.len() >= 36 && &data[34..36] == b"LP" {
        return "application/vnd.ms-fontobject";
    }
    const EXACT_REST: [(&[u8], &str); 10] = [
        (b"\x00\x01\x00\x00", "font/ttf"),
        (b"OTTO", "font/otf"),
        (b"ttcf", "font/collection"),
        (b"wOFF", "font/woff"),
        (b"wOF2", "font/woff2"),
        (b"\x1F\x8B\x08", "application/x-gzip"),
        (b"PK\x03\x04", "application/zip"),
        (b"Rar!\x1A\x07\x00", "application/x-rar-compressed"),
        (b"Rar!\x1A\x07\x01\x00", "application/x-rar-compressed"),
        (b"\x00\x61\x73\x6D", "application/wasm"),
    ];
    for (signature, media_type) in EXACT_REST {
        if data.starts_with(signature) {
            return media_type;
        }
    }
    let binary = trimmed
        .iter()
        .any(|&byte| byte <= 0x08 || byte == 0x0b || (0x0e..=0x1a).contains(&byte) || (0x1c..=0x1f).contains(&byte));
    if binary {
        "application/octet-stream"
    } else {
        "text/plain; charset=utf-8"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_detection_follows_the_signatures() {
        assert_eq!(detect_content_type(b"  <html><body>"), "text/html; charset=utf-8");
        assert_eq!(detect_content_type(b"<!-- note -->"), "text/html; charset=utf-8");
        assert_eq!(detect_content_type(b"<?xml version"), "text/xml; charset=utf-8");
        assert_eq!(detect_content_type(b"%PDF-1.7"), "application/pdf");
        assert_eq!(detect_content_type(b"\x89PNG\r\n\x1a\nxxxx"), "image/png");
        assert_eq!(detect_content_type(b"\xff\xd8\xff\xe0"), "image/jpeg");
        assert_eq!(
            detect_content_type(b"\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom"),
            "video/mp4"
        );
        assert_eq!(detect_content_type(b"plain text"), "text/plain; charset=utf-8");
        assert_eq!(detect_content_type(b"\x00\x01binary"), "application/octet-stream");
        assert_eq!(detect_content_type(b"PK\x03\x04rest"), "application/zip");
        assert_eq!(detect_content_type(b""), "text/plain; charset=utf-8");
    }

    #[test]
    fn the_table_gives_the_media_type_of_an_extension() {
        assert_eq!(type_by_extension(".MJS"), "text/javascript; charset=utf-8");
        assert_eq!(type_by_extension(".txt"), "");
        assert_eq!(extension("a.b/c.PDF"), ".PDF");
        assert_eq!(extension("a.b/c"), "");
        assert_eq!(extension("name."), ".");
    }
}
