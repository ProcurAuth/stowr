// SPDX-License-Identifier: MIT OR Apache-2.0
//! The e-mail previews and details: the message headers, the parts of a MIME message, the attachments and the text
//! of the body.

use std::collections::BTreeMap;

use serde::Serialize;

use super::html;
use super::mime::{
    HeaderMode, Headers, MultipartReader, canonical_key_str, decode_quoted_printable, first_header_value, header_get,
    parse_media_type, read_header_block,
};
use super::pem::decode_base64;
use super::text::lossy_runs;

/// The deepest level of multipart parts that the preview reads.
pub const MAX_MIME_DEPTH: usize = 8;
/// The most parts that the preview reads.
pub const MAX_MIME_PARTS: usize = 4096;

/// One attachment of a message.
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct Attachment {
    /// The file name.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub name: String,
    /// The media type.
    #[serde(rename = "contentType", skip_serializing_if = "String::is_empty")]
    pub content_type: String,
    /// The size of the decoded data.
    #[serde(skip_serializing_if = "is_zero")]
    pub size: i64,
    /// True for an inline part.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub inline: bool,
    /// The content identifier.
    #[serde(rename = "contentId", skip_serializing_if = "String::is_empty")]
    pub content_id: String,
}

fn is_zero(value: &i64) -> bool {
    *value == 0
}

/// The e-mail of the preview.
#[derive(Debug, Default, Serialize, PartialEq, Eq)]
pub struct EmailPreview {
    /// The main headers.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    /// The text of the message.
    #[serde(rename = "bodyText", skip_serializing_if = "String::is_empty")]
    pub body_text: String,
    /// The HTML source of the message.
    #[serde(rename = "htmlSource", skip_serializing_if = "String::is_empty")]
    pub html_source: String,
    /// The attachments.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<Attachment>,
}

/// The label of the container of an e-mail file.
pub fn email_container_label(extension: &str) -> &'static str {
    if extension == "mhtml" || extension == "mht" {
        "MHTML email archive"
    } else {
        "Email message"
    }
}

/// The headers of a message from the bytes up to the first blank line, with lowercase names. The first value of
/// a name stays; the continuation lines join the line before them. `None` when the data has no blank line.
pub fn parse_email_headers(data: &[u8]) -> Option<BTreeMap<String, String>> {
    let boundary = match find(data, b"\r\n\r\n") {
        Some(index) => index,
        None => find(data, b"\n\n")?,
    };
    let text = super::text::lossy(&data[..boundary]);
    let text = text.replace("\r\n", "\n");
    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    let mut current = String::new();
    for line in text.split('\n') {
        if line.starts_with(' ') || line.starts_with('\t') {
            if !current.is_empty() {
                let entry = headers.entry(current.clone()).or_default();
                entry.push(' ');
                entry.push_str(line.trim());
            }
            continue;
        }
        let Some(index) = line.find(':') else { continue };
        if index == 0 {
            continue;
        }
        current = line[..index].trim().to_lowercase();
        if !headers.contains_key(&current) {
            headers.insert(current.clone(), line[index + 1..].trim().to_owned());
        }
    }
    Some(headers)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|window| window == needle)
}

/// The details of a message from its headers.
pub fn email_properties(headers: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    let fields = [
        ("from", "From"),
        ("to", "To"),
        ("cc", "Cc"),
        ("bcc", "Bcc"),
        ("subject", "Subject"),
        ("date", "Date"),
        ("message-id", "Message ID"),
        ("reply-to", "Reply-To"),
        ("content-type", "MIME type"),
        ("mime-version", "MIME version"),
        ("user-agent", "User agent"),
        ("x-mailer", "Mailer"),
    ];
    let mut props = BTreeMap::new();
    for (key, label) in fields {
        if let Some(value) = headers.get(key) {
            let value = value.trim();
            if !value.is_empty() {
                props.insert(label.to_owned(), value.to_owned());
            }
        }
    }
    props
}

/// The headers with their names in the canonical form.
pub(super) fn display_headers(headers: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    headers
        .iter()
        .map(|(key, value)| (canonical_key_str(key), value.clone()))
        .collect()
}

/// Decode the body of a part from its transfer encoding. An encoding that fails leaves the data as it is.
fn decode_transfer_encoding(headers: &Headers, data: &[u8]) -> Vec<u8> {
    let encoding = first_header_value(headers, "Content-Transfer-Encoding")
        .trim()
        .to_lowercase();
    match encoding.as_str() {
        "base64" => {
            let cleaned: Vec<u8> = data
                .iter()
                .copied()
                .filter(|byte| !matches!(byte, b'\r' | b'\n' | b' ' | b'\t'))
                .collect();
            if let Some(decoded) = decode_base64(&cleaned) {
                return decoded;
            }
        }
        "quoted-printable" => {
            let decoded = decode_quoted_printable(data);
            if !decoded.failed {
                return decoded.bytes;
            }
        }
        _ => {}
    }
    data.to_vec()
}

struct Walker<'p> {
    preview: &'p mut EmailPreview,
    parts: usize,
}

impl Walker<'_> {
    /// Visit a part. `clean_end` is false when the data of the part ended without a boundary.
    fn walk(&mut self, headers: &Headers, data: &[u8], depth: usize, clean_end: bool) {
        let content_type = first_header_value(headers, "Content-Type").to_owned();
        let parsed = parse_media_type(&content_type);
        let mut media_type = parsed.media_type.clone();
        let params = if parsed.failed || media_type.is_empty() {
            media_type = "text/plain".to_owned();
            Default::default()
        } else {
            parsed.params.clone()
        };
        if media_type.to_lowercase().starts_with("multipart/") {
            let boundary = params.get("boundary").cloned().unwrap_or_default();
            if boundary.is_empty() || depth >= MAX_MIME_DEPTH {
                return;
            }
            let mut body: std::borrow::Cow<'_, [u8]> = std::borrow::Cow::Borrowed(data);
            let mut decoded = false;
            if depth > 0 {
                let encoding = first_header_value(headers, "Content-Transfer-Encoding")
                    .trim()
                    .to_lowercase();
                if encoding == "base64" || encoding == "quoted-printable" {
                    if !clean_end {
                        return;
                    }
                    body = std::borrow::Cow::Owned(decode_transfer_encoding(headers, data));
                    decoded = true;
                }
            }
            let mut reader = MultipartReader::new(&body, &boundary, decoded || clean_end);
            while self.parts < MAX_MIME_PARTS {
                let Some(part) = reader.next_part() else {
                    break;
                };
                self.parts += 1;
                let part_headers = part.headers.clone();
                self.walk(&part_headers, &part.body, depth + 1, !part.failed);
            }
            return;
        }
        if !clean_end {
            return;
        }
        let body = decode_transfer_encoding(headers, data);
        let disposition = parse_media_type(first_header_value(headers, "Content-Disposition"));
        let disposition_name = disposition.media_type.clone();
        let disposition_params = disposition.params;
        let mut filename = disposition_params
            .get("filename")
            .map(|value| value.trim().to_owned())
            .unwrap_or_default();
        if filename.is_empty() {
            filename = params
                .get("name")
                .map(|value| value.trim().to_owned())
                .unwrap_or_default();
        }
        let content_id = first_header_value(headers, "Content-ID")
            .trim()
            .trim_matches(|character| character == '<' || character == '>')
            .to_owned();
        let is_attachment = disposition_name.eq_ignore_ascii_case("attachment") || !filename.is_empty();
        let inline = disposition_name.eq_ignore_ascii_case("inline");
        if is_attachment {
            self.preview.attachments.push(Attachment {
                name: filename,
                content_type: media_type,
                size: body.len() as i64,
                inline,
                content_id,
            });
            return;
        }
        match media_type.to_lowercase().as_str() {
            "text/plain" => {
                if self.preview.body_text.is_empty() {
                    self.preview.body_text = lossy_runs(&body);
                }
            }
            "text/html" => {
                if self.preview.html_source.is_empty() {
                    self.preview.html_source = lossy_runs(&body);
                }
            }
            _ => {
                if !content_id.is_empty() || inline {
                    self.preview.attachments.push(Attachment {
                        name: filename,
                        content_type: media_type,
                        size: body.len() as i64,
                        inline: true,
                        content_id,
                    });
                }
            }
        }
    }
}

/// The preview of a message.
pub fn parse_email_preview(data: &[u8]) -> EmailPreview {
    let block = read_header_block(data, HeaderMode::Message, i64::MAX, i64::MAX);
    let failed = match block.error {
        Some(super::mime::HeaderError::EndOfData) => block.headers.is_empty(),
        Some(_) => true,
        None => false,
    };
    if failed {
        let headers = parse_email_headers(data).unwrap_or_default();
        return EmailPreview {
            headers: display_headers(&headers),
            ..EmailPreview::default()
        };
    }
    let mut preview = EmailPreview::default();
    for name in [
        "From",
        "To",
        "Cc",
        "Bcc",
        "Reply-To",
        "Subject",
        "Date",
        "Message-ID",
        "In-Reply-To",
        "References",
        "Content-Type",
        "MIME-Version",
        "User-Agent",
        "X-Mailer",
    ] {
        let value = header_get(&block.headers, name).trim();
        if !value.is_empty() {
            preview.headers.insert(name.to_owned(), value.to_owned());
        }
    }
    let body = &data[block.consumed.min(data.len())..];
    {
        let mut walker = Walker {
            preview: &mut preview,
            parts: 0,
        };
        walker.walk(&block.headers, body, 0, true);
    }
    preview.body_text = preview.body_text.trim().to_owned();
    preview.html_source = preview.html_source.trim().to_owned();
    if preview.body_text.is_empty() && !preview.html_source.is_empty() {
        preview.body_text = html::to_plain_text(&preview.html_source);
    }
    preview
}

#[cfg(test)]
pub(super) fn display_headers_for_tests(headers: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    display_headers(headers)
}
