// SPDX-License-Identifier: MIT OR Apache-2.0
//! The small helpers that the functions of this folder share. They are the S3 call seam, the XML tree of the provider
//! answers and the quoting of a text.

use quick_xml::Reader;
use quick_xml::events::Event;

use crate::common::BoxFuture;
use crate::common::config::BucketConfig;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::query::{path_escape, query_escape};
use crate::provider::S3Backend;
use crate::provider::s3::{S3Answer, S3Request};

/// The namespace of the S3 documents.
pub const S3_NAMESPACE: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

/// The largest answer of a provider that a function of this folder reads: 1 MiB.
pub const MAX_ANSWER_BYTES: usize = 1 << 20;

/// The seam between the S3 functions of this folder and the provider client. The S3 back end implements it with
/// `S3Backend::send`; the tests implement it with a fake provider.
pub trait S3Call: Send + Sync {
    /// Sign and send one request; read at most `limit` bytes of the answer.
    fn call<'a>(&'a self, ctx: &'a OpCtx, request: S3Request<'a>, limit: usize) -> BoxFuture<'a, Result<S3Answer>>;
    /// The provider error of an answer with a status of 300 or more.
    fn provider_error(&self, answer: &S3Answer) -> Error;
    /// The configuration of the bucket.
    fn bucket_config(&self) -> &BucketConfig;
}

impl S3Call for S3Backend {
    fn call<'a>(&'a self, ctx: &'a OpCtx, request: S3Request<'a>, limit: usize) -> BoxFuture<'a, Result<S3Answer>> {
        Box::pin(async move { self.send(ctx, request, limit).await })
    }

    fn provider_error(&self, answer: &S3Answer) -> Error {
        S3Backend::s3_error(answer)
    }

    fn bucket_config(&self) -> &BucketConfig {
        &self.cfg
    }
}

/// True for a provider answer 2xx.
pub fn is_success(status: u16) -> bool {
    (200..300).contains(&status)
}

pub use crate::provider::s3::provider_refused_feature;

/// The status and the S3 code of a provider answer, such as `HTTP 403 AccessDenied`.
pub fn upstream_status_text(status: u16, code: &str) -> String {
    let safe = crate::common::error::safe_provider_code(code);
    if safe.is_empty() {
        format!("HTTP {status}")
    } else {
        format!("HTTP {status} {safe}")
    }
}

/// The value of `x-amz-copy-source` for a key of the bucket, and for one version of it when `version` is not empty.
pub fn copy_source_header(bucket: &str, key: &str, version: &str) -> String {
    let mut value = format!("/{}/{}", aws_uri_encode(bucket, true), aws_uri_encode(key, false));
    if !version.is_empty() {
        value.push_str("?versionId=");
        value.push_str(&query_escape(version));
    }
    value
}

/// The URI encoding of the S3 signature: letters, digits and `-_.~` stay, and `/` stays when `encode_slash` is false.
pub fn aws_uri_encode(value: &str, encode_slash: bool) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(value.len());
    for &byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') || (byte == b'/' && !encode_slash)
        {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(DIGITS[usize::from(byte >> 4)]));
            out.push(char::from(DIGITS[usize::from(byte & 0xf)]));
        }
    }
    out
}

/// The text between double quotes with the escapes of a quoted text: `\n`, `\"`, `\\` and `\xNN` for a control
/// character. It is the form of the messages that show a value of the client.
pub fn quote(text: &str) -> String {
    crate::config::quote::quote(text)
}

/// True when the text has only the characters 0x20 to 0x7E, with no space at the start or the end. S3 sends the
/// metadata in HTTP headers: other characters do not come back unchanged.
pub fn printable_ascii(text: &str) -> bool {
    if text != text.trim() {
        return false;
    }
    text.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

// --- The XML tree of an answer ----------------------------------------------------------------------------------

/// An element of a provider document: its local name, the text that it holds directly, and its children.
#[derive(Debug, Default, Clone)]
pub struct XmlNode {
    /// The local name (without a prefix).
    pub name: String,
    /// The character data that the element holds directly.
    pub text: String,
    /// The child elements, in the order of the document.
    pub children: Vec<XmlNode>,
}

impl XmlNode {
    /// The first child with this name.
    pub fn child(&self, name: &str) -> Option<&XmlNode> {
        self.children.iter().find(|node| node.name == name)
    }

    /// Each child with this name.
    pub fn children_named<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a XmlNode> {
        self.children.iter().filter(move |node| node.name == name)
    }

    /// The first element at the path of names.
    pub fn path(&self, names: &[&str]) -> Option<&XmlNode> {
        let mut node = self;
        for name in names {
            node = node.child(name)?;
        }
        Some(node)
    }

    /// The text of the element at the path, or an empty text.
    pub fn text_at(&self, names: &[&str]) -> &str {
        self.path(names).map_or("", |node| node.text.as_str())
    }
}

fn resolve_entity(name: &str) -> Option<String> {
    match name {
        "amp" => Some("&".to_owned()),
        "lt" => Some("<".to_owned()),
        "gt" => Some(">".to_owned()),
        "quot" => Some("\"".to_owned()),
        "apos" => Some("'".to_owned()),
        _ => {
            let digits = name.strip_prefix('#')?;
            let code = match digits.strip_prefix('x') {
                Some(hex) => u32::from_str_radix(hex, 16).ok()?,
                None => digits.parse().ok()?,
            };
            char::from_u32(code).map(String::from)
        }
    }
}

/// Read a document into a tree. An empty document gives `None`. A malformed document gives the reason.
pub fn parse_xml(body: &[u8]) -> std::result::Result<Option<XmlNode>, String> {
    let text = std::str::from_utf8(body).map_err(|_| "the document is not UTF-8 text".to_owned())?;
    if text.trim().is_empty() {
        return Ok(None);
    }
    let mut reader = Reader::from_str(text);
    let mut stack: Vec<XmlNode> = Vec::new();
    let mut root: Option<XmlNode> = None;
    loop {
        let event = reader.read_event().map_err(|error| error.to_string())?;
        match event {
            Event::Start(start) => {
                let name = start.local_name().as_ref().to_owned();
                stack.push(XmlNode {
                    name,
                    ..XmlNode::default()
                });
            }
            Event::Empty(start) => {
                let name = start.local_name().as_ref().to_owned();
                let node = XmlNode {
                    name,
                    ..XmlNode::default()
                };
                match stack.last_mut() {
                    Some(parent) => parent.children.push(node),
                    None => {
                        if root.is_none() {
                            root = Some(node);
                        }
                    }
                }
            }
            Event::End(_) => {
                let Some(node) = stack.pop() else {
                    return Err("an end tag has no start tag".to_owned());
                };
                match stack.last_mut() {
                    Some(parent) => parent.children.push(node),
                    None => {
                        if root.is_none() {
                            root = Some(node);
                        }
                    }
                }
            }
            Event::Text(data) => {
                if let Some(node) = stack.last_mut() {
                    node.text.push_str(&data.xml10_content());
                }
            }
            Event::CData(data) => {
                if let Some(node) = stack.last_mut() {
                    node.text.push_str(&data.xml10_content());
                }
            }
            Event::GeneralRef(reference) => {
                let name: &str = &reference;
                let Some(value) = resolve_entity(name) else {
                    return Err(format!("the entity {name:?} is not known"));
                };
                if let Some(node) = stack.last_mut() {
                    node.text.push_str(&value);
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    if !stack.is_empty() {
        return Err("the document ends before its last end tag".to_owned());
    }
    Ok(root)
}

/// The tree of a provider answer, with the text of a decode error that names the document.
pub fn decode_document(body: &[u8], what: &str) -> Result<Option<XmlNode>> {
    parse_xml(body).map_err(|reason| Error::internal(format!("decode s3 {what} response: {reason}")))
}

/// The text of an integer element: an empty text is 0.
pub fn xml_integer(text: &str, what: &str) -> Result<i64> {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Ok(0);
    }
    trimmed
        .parse()
        .map_err(|_| Error::internal(format!("decode s3 {what} response: {trimmed:?} is not an integer")))
}

/// The error that a successful answer carries in its body: some providers answer 200 with an `<Error>` document.
pub fn embedded_error(body: &[u8]) -> Option<Error> {
    let node = parse_xml(body).ok().flatten()?;
    if node.name != "Error" {
        return None;
    }
    Some(Error::upstream(
        502,
        node.text_at(&["Code"]).to_owned(),
        node.text_at(&["Message"]).to_owned(),
    ))
}

// --- The URL of an admin API ---------------------------------------------------------------------------------------

/// The path of a URL in its escaped form: the characters that a path may hold stay, each other byte is `%XX`.
pub fn escape_url_path(path: &str) -> String {
    path.split('/').map(path_escape).collect::<Vec<_>>().join("/")
}
