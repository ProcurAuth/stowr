//! Media types: the built-in table of the extensions, the text of a `Content-Disposition` value, and the detection of
//! the media type of the first bytes of a body (the algorithm of <https://mimesniff.spec.whatwg.org/>).

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

fn is_tspecial(byte: u8) -> bool {
    b"()<>@,;:\\\"/[]?=".contains(&byte)
}

fn is_token(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte > 0x20 && byte < 0x7f && !is_tspecial(byte))
}

fn needs_encoding(text: &str) -> bool {
    text.chars()
        .any(|character| !(' '..='~').contains(&character) && character != '\t')
}

/// The text of a media type with parameters (`inline; filename="a b.pdf"`), or an empty text when the type or a
/// parameter name is not a token. A value with a byte outside of printable ASCII has the form `name*=utf-8''...`.
pub fn format_media_type(media_type: &str, params: &[(&str, &str)]) -> String {
    let mut out = String::new();
    match media_type.split_once('/') {
        None => {
            if !is_token(media_type) {
                return String::new();
            }
            out.push_str(&media_type.to_ascii_lowercase());
        }
        Some((major, sub)) => {
            if !is_token(major) || !is_token(sub) {
                return String::new();
            }
            out.push_str(&major.to_ascii_lowercase());
            out.push('/');
            out.push_str(&sub.to_ascii_lowercase());
        }
    }
    let mut sorted: Vec<(&str, &str)> = params.to_vec();
    sorted.sort_by(|left, right| left.0.cmp(right.0));
    for (attribute, value) in sorted {
        out.push_str("; ");
        if !is_token(attribute) {
            return String::new();
        }
        out.push_str(&attribute.to_ascii_lowercase());
        if needs_encoding(value) {
            out.push_str("*=utf-8''");
            const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
            for &byte in value.as_bytes() {
                if byte <= b' ' || byte >= 0x7f || byte == b'*' || byte == b'\'' || byte == b'%' || is_tspecial(byte) {
                    out.push('%');
                    out.push(char::from(DIGITS[usize::from(byte >> 4)]));
                    out.push(char::from(DIGITS[usize::from(byte & 0xf)]));
                } else {
                    out.push(char::from(byte));
                }
            }
            continue;
        }
        out.push('=');
        if is_token(value) {
            out.push_str(value);
            continue;
        }
        out.push('"');
        for character in value.chars() {
            if character == '"' || character == '\\' {
                out.push('\\');
            }
            out.push(character);
        }
        out.push('"');
    }
    out
}

/// The media type of a `Content-Type` value without its parameters, in lower case and without spaces.
pub fn base_media_type(value: &str) -> String {
    value.split(';').next().unwrap_or("").trim().to_ascii_lowercase()
}

/// The largest number of bytes that the detection reads.
pub const SNIFF_LEN: usize = 512;

fn is_space(byte: u8) -> bool {
    matches!(byte, b'\t' | b'\n' | 0x0c | b'\r' | b' ')
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

fn html_match(data: &[u8], signature: &[u8]) -> bool {
    if data.len() < signature.len() + 1 {
        return false;
    }
    for (index, &expected) in signature.iter().enumerate() {
        let mut byte = data[index];
        if expected.is_ascii_uppercase() {
            byte &= 0xdf;
        }
        if byte != expected {
            return false;
        }
    }
    matches!(data[signature.len()], b' ' | b'>')
}

fn masked_match(data: &[u8], mask: &[u8], pattern: &[u8]) -> bool {
    data.len() >= pattern.len()
        && pattern
            .iter()
            .zip(mask)
            .zip(data)
            .all(|((expected, mask), byte)| byte & mask == *expected)
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
        if start != 12 && data.get(start..start + 3) == Some(b"mp4".as_slice()) {
            return true;
        }
        start += 4;
    }
    false
}

/// The media type of the first bytes of a body. It reads at most 512 bytes and gives `application/octet-stream` when no
/// rule matches.
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
    fn the_disposition_text_quotes_and_encodes_names() {
        assert_eq!(
            format_media_type("inline", &[("filename", "board review.mp4")]),
            "inline; filename=\"board review.mp4\""
        );
        assert_eq!(
            format_media_type("attachment", &[("filename", "a.mkv")]),
            "attachment; filename=a.mkv"
        );
        assert_eq!(
            format_media_type("attachment", &[("filename", "café.txt")]),
            "attachment; filename*=utf-8''caf%C3%A9.txt"
        );
        assert_eq!(format_media_type("a b", &[]), "");
    }

    #[test]
    fn detection_follows_the_signatures() {
        assert_eq!(detect_content_type(b"  <html><body>"), "text/html; charset=utf-8");
        assert_eq!(detect_content_type(b"%PDF-1.7"), "application/pdf");
        assert_eq!(detect_content_type(b"\x89PNG\r\n\x1a\nxxxx"), "image/png");
        assert_eq!(detect_content_type(b"plain text"), "text/plain; charset=utf-8");
        assert_eq!(detect_content_type(b"\x00\x01binary"), "application/octet-stream");
        assert_eq!(detect_content_type(b"PK\x03\x04rest"), "application/zip");
        assert_eq!(detect_content_type(b""), "text/plain; charset=utf-8");
        assert_eq!(type_by_extension(".MJS"), "text/javascript; charset=utf-8");
        assert_eq!(type_by_extension(".txt"), "");
    }
}
