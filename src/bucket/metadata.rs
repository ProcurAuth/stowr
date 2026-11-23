//! The edit of the metadata of an object: S3 `CopyObject` onto the same key with `x-amz-metadata-directive: REPLACE`.
//!
//! The request gives the complete state: the standard headers (`Content-Type`, `Cache-Control`,
//! `Content-Disposition`, `Content-Encoding`, `Content-Language`, `Expires`) and the user metadata (`x-amz-meta-*`).
//! A header that the request does not give is removed. The tags stay (`x-amz-tagging-directive: COPY`). The copy
//! names the ETag that the form read, so the provider refuses the copy of an object whose content changed in the
//! meantime. A change of the metadata only keeps the ETag on SeaweedFS, MinIO and Garage. Thus a HEAD request before
//! the copy also compares the modification date that the form read. From the threshold of the copy in parts up, the copy
//! goes in parts and `CreateMultipartUpload` gets the metadata. The copy of an older version makes that version the
//! current version, as a restore does. Only the S3 back end has the edit: the GCS back end answers 501.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, Method};
use serde::{Deserialize, Serialize};

use super::MetadataEditor;
use super::encryption::{kept_encryption_headers, write_encryption_headers};
use super::object_lock::null_default;
use super::support::{
    MAX_ANSWER_BYTES, S3Call, begin_request, copy_source_header, embedded_error, is_success, observe_permission,
    printable_ascii, provider_refused_feature, quote,
};
use crate::access;
use crate::common::BoxFuture;
use crate::common::app::App;
use crate::common::config::{PERMISSION_READ, PERMISSION_WRITE};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Req, Response, api_error, decode_json, json, method_not_allowed};
use crate::common::misc::clean_relative_key;
use crate::common::storage::{MultipartCopyOptions, ObjectResponse};
use crate::common::time::Timestamp;
use crate::instance::Instance;
use crate::instance::ceiling::{ACTION_WRITE, check_object_ceiling};
use crate::provider::S3Backend;
use crate::provider::s3::S3Request;

/// The S3 limit of the user metadata: the sum of the bytes of each key and each value.
pub const MAX_USER_METADATA_BYTES: usize = 2048;
/// The limit of the value of one standard header.
pub const MAX_STANDARD_HEADER_BYTES: usize = 1024;
/// The limit of the ETag of a request.
pub const MAX_ETAG_BYTES: usize = 128;
/// The object that the start probe names. The probe never writes it.
const METADATA_PROBE_KEY: &str = ".stowr-metadata-probe";
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// The standard headers that the edit sets. An empty field means no header.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ObjectHeaders {
    /// `Content-Type`.
    #[serde(default, skip_serializing_if = "String::is_empty", deserialize_with = "null_default")]
    pub content_type: String,
    /// `Cache-Control`.
    #[serde(default, skip_serializing_if = "String::is_empty", deserialize_with = "null_default")]
    pub cache_control: String,
    /// `Content-Disposition`.
    #[serde(default, skip_serializing_if = "String::is_empty", deserialize_with = "null_default")]
    pub content_disposition: String,
    /// `Content-Encoding`.
    #[serde(default, skip_serializing_if = "String::is_empty", deserialize_with = "null_default")]
    pub content_encoding: String,
    /// `Content-Language`.
    #[serde(default, skip_serializing_if = "String::is_empty", deserialize_with = "null_default")]
    pub content_language: String,
    /// `Expires`.
    #[serde(default, skip_serializing_if = "String::is_empty", deserialize_with = "null_default")]
    pub expires: String,
}

impl ObjectHeaders {
    /// Each header with its HTTP name, in the order of the copied headers.
    fn fields(&self) -> [(&'static str, &str); 6] {
        [
            ("Content-Type", self.content_type.as_str()),
            ("Cache-Control", self.cache_control.as_str()),
            ("Content-Disposition", self.content_disposition.as_str()),
            ("Content-Encoding", self.content_encoding.as_str()),
            ("Content-Language", self.content_language.as_str()),
            ("Expires", self.expires.as_str()),
        ]
    }

    fn set(&mut self, name: &str, value: String) {
        match name {
            "Content-Type" => self.content_type = value,
            "Cache-Control" => self.cache_control = value,
            "Content-Disposition" => self.content_disposition = value,
            "Content-Encoding" => self.content_encoding = value,
            "Content-Language" => self.content_language = value,
            "Expires" => self.expires = value,
            _ => {}
        }
    }
}

/// One user metadata: the name without the prefix `x-amz-meta-`, and its value.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataEntry {
    /// The name.
    #[serde(default, deserialize_with = "null_default")]
    pub key: String,
    /// The value.
    #[serde(default, deserialize_with = "null_default")]
    pub value: String,
}

impl MetadataEntry {
    /// An entry from two texts.
    pub fn new(key: &str, value: &str) -> Self {
        Self {
            key: key.to_owned(),
            value: value.to_owned(),
        }
    }
}

fn invalid_metadata(message: impl Into<String>) -> Error {
    Error::api(400, "invalid_metadata", message)
}

fn metadata_edit_unsupported() -> Error {
    Error::api(
        501,
        "metadata_unsupported",
        "this storage provider does not let Stowr change the metadata of an object",
    )
}

fn object_changed_error() -> Error {
    Error::api(
        412,
        "object_changed",
        "the object changed after the form read its metadata: read the metadata again and make the change again",
    )
}

// --- The syntax of the headers ------------------------------------------------------------------------------------

fn is_tspecial(character: char) -> bool {
    "()<>@,;:\\\"/[]?=".contains(character)
}

fn is_token_char(character: char) -> bool {
    let code = character as u32;
    code > 0x20 && code < 0x7f && !is_tspecial(character)
}

/// The leading token of a text and the rest.
fn consume_token(text: &str) -> (&str, &str) {
    let end = text
        .find(|character: char| !is_token_char(character))
        .unwrap_or(text.len());
    text.split_at(end)
}

/// The value of a media type parameter: a token or a quoted text. The value is empty and the rest is the whole text
/// when the value is not valid.
fn consume_value(text: &str) -> (String, &str) {
    if text.is_empty() {
        return (String::new(), text);
    }
    if !text.starts_with('"') {
        let (token, rest) = consume_token(text);
        return (token.to_owned(), rest);
    }
    let bytes = text.as_bytes();
    let mut value = Vec::new();
    let mut index = 1;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'"' {
            return (String::from_utf8_lossy(&value).into_owned(), &text[index + 1..]);
        }
        if byte == b'\\' && index + 1 < bytes.len() && is_tspecial(char::from(bytes[index + 1])) {
            value.push(bytes[index + 1]);
            index += 2;
            continue;
        }
        if byte == b'\r' || byte == b'\n' {
            return (String::new(), text);
        }
        value.push(byte);
        index += 1;
    }
    (String::new(), text)
}

/// One parameter of a media type: `; name=value`. `Err` gives the text that the function could not read.
fn consume_media_param(text: &str) -> std::result::Result<(String, String, &str), &str> {
    let rest = text.trim_start();
    let Some(rest) = rest.strip_prefix(';') else {
        return Err(text);
    };
    let rest = rest.trim_start();
    let (name, rest) = consume_token(rest);
    if name.is_empty() {
        return Err(text);
    }
    let name = name.to_lowercase();
    let rest = rest.trim_start();
    let Some(rest) = rest.strip_prefix('=') else {
        return Err(text);
    };
    let rest = rest.trim_start();
    let (value, after) = consume_value(rest);
    if value.is_empty() && after.len() == rest.len() {
        return Err(text);
    }
    Ok((name, value, after))
}

/// Check the media type of a `Content-Type` or of a `Content-Disposition`. It gives the lower-case type.
fn parse_media_type(value: &str) -> std::result::Result<String, ()> {
    let base = value.split(';').next().unwrap_or("");
    let media_type = base.trim().to_lowercase();
    let (kind, rest) = consume_token(&media_type);
    if kind.is_empty() {
        return Err(());
    }
    if !rest.is_empty() {
        let Some(after_slash) = rest.strip_prefix('/') else {
            return Err(());
        };
        let (subtype, tail) = consume_token(after_slash);
        if subtype.is_empty() || !tail.is_empty() {
            return Err(());
        }
    }
    let mut parameters: HashMap<String, String> = HashMap::new();
    let mut remaining = &value[base.len()..];
    while !remaining.is_empty() {
        remaining = remaining.trim_start();
        if remaining.is_empty() {
            break;
        }
        match consume_media_param(remaining) {
            Ok((name, parameter, rest)) => {
                if let Some(existing) = parameters.get(&name)
                    && *existing != parameter
                {
                    return Err(());
                }
                parameters.insert(name, parameter);
                remaining = rest;
            }
            Err(rest) => {
                if rest.trim() == ";" {
                    break;
                }
                return Err(());
            }
        }
    }
    Ok(media_type)
}

fn is_header_token(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+.^_`|~-".contains(&byte))
}

fn is_cache_directive_value(text: &str) -> bool {
    if let Some(inner) = text.strip_prefix('"').and_then(|rest| rest.strip_suffix('"')) {
        return inner
            .bytes()
            .all(|byte| byte == 0x20 || byte == 0x21 || (0x23..=0x7e).contains(&byte));
    }
    is_header_token(text)
}

fn is_content_encoding(text: &str) -> bool {
    let mut bytes = text.bytes();
    match bytes.next() {
        Some(first) if first.is_ascii_alphanumeric() => {}
        _ => return false,
    }
    bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-'))
}

fn is_content_language(text: &str) -> bool {
    if text == "*" {
        return true;
    }
    let mut parts = text.split('-');
    let Some(first) = parts.next() else {
        return false;
    };
    if first.is_empty() || first.len() > 8 || !first.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return false;
    }
    parts.all(|part| !part.is_empty() && part.len() <= 8 && part.bytes().all(|byte| byte.is_ascii_alphanumeric()))
}

/// The items of a list that a comma separates, or `None` when one item is empty.
fn split_list(value: &str) -> Option<Vec<&str>> {
    let items: Vec<&str> = value.split(',').map(str::trim).collect();
    if items.iter().any(|item| item.is_empty()) {
        return None;
    }
    Some(items)
}

/// Check each standard header against its HTTP syntax. An empty field means no header.
pub fn validate_object_headers(headers: &ObjectHeaders) -> Result<()> {
    for (name, value) in headers.fields() {
        if value.is_empty() {
            continue;
        }
        if value.len() > MAX_STANDARD_HEADER_BYTES {
            return Err(invalid_metadata(format!(
                "{name} has at most {MAX_STANDARD_HEADER_BYTES} characters, got {}",
                value.len()
            )));
        }
        if !printable_ascii(value) {
            return Err(invalid_metadata(format!(
                "{name} has ASCII letters, digits, spaces and punctuation only, with no space at the start or the end"
            )));
        }
        match name {
            "Content-Type" => match parse_media_type(value) {
                Ok(media_type) if media_type.contains('/') => {}
                _ => {
                    return Err(invalid_metadata(format!(
                        "Content-Type must be a media type such as text/plain or application/json; charset=utf-8, got {}",
                        quote(value)
                    )));
                }
            },
            "Content-Disposition" => match parse_media_type(value) {
                Ok(disposition) if disposition == "inline" || disposition == "attachment" => {}
                _ => {
                    return Err(invalid_metadata(format!(
                        "Content-Disposition must be inline or attachment, with optional parameters such as filename=\"report.pdf\", got {}",
                        quote(value)
                    )));
                }
            },
            "Content-Encoding" => {
                let valid = split_list(value).is_some_and(|items| {
                    items
                        .iter()
                        .all(|item| is_content_encoding(item) && !item.eq_ignore_ascii_case("aws-chunked"))
                });
                if !valid {
                    return Err(invalid_metadata(format!(
                        "Content-Encoding must be a list of codings such as gzip or br, separated by commas (aws-chunked is not stored), got {}",
                        quote(value)
                    )));
                }
            }
            "Content-Language" => {
                let valid = split_list(value).is_some_and(|items| items.iter().all(|item| is_content_language(item)));
                if !valid {
                    return Err(invalid_metadata(format!(
                        "Content-Language must be a list of language tags such as en or fr-CA, separated by commas, got {}",
                        quote(value)
                    )));
                }
            }
            "Cache-Control" => {
                let valid = split_list(value).is_some_and(|items| {
                    items.iter().all(|item| match item.split_once('=') {
                        Some((directive, argument)) => is_header_token(directive) && is_cache_directive_value(argument),
                        None => is_header_token(item),
                    })
                });
                if !valid {
                    return Err(invalid_metadata(format!(
                        "Cache-Control must be a list of directives such as max-age=3600 or no-cache, separated by commas, got {}",
                        quote(value)
                    )));
                }
            }
            "Expires" => {
                let canonical = Timestamp::parse_http_date(value).is_some_and(|parsed| parsed.http_date() == value);
                if !canonical {
                    return Err(invalid_metadata(format!(
                        "Expires must be an HTTP date such as Wed, 21 Oct 2026 07:28:00 GMT, got {}",
                        quote(value)
                    )));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn is_metadata_key(key: &str) -> bool {
    let mut bytes = key.bytes();
    match bytes.next() {
        Some(first) if first.is_ascii_lowercase() || first.is_ascii_digit() => {}
        _ => return false,
    }
    bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-'))
}

/// Check the user metadata. Each key is unique and has lowercase letters, digits, `.`, `_` and `-`. Each value is
/// printable ASCII. The sum of the keys and the values is at most 2 KiB, the S3 limit.
pub fn validate_user_metadata(entries: &[MetadataEntry]) -> Result<()> {
    let mut seen: Vec<&str> = Vec::with_capacity(entries.len());
    let mut total = 0usize;
    for entry in entries {
        if !is_metadata_key(&entry.key) {
            return Err(invalid_metadata(format!(
                "the metadata key {} must start with a lowercase letter or a digit, and have only lowercase letters, digits, '.', '_' and '-'",
                quote(&entry.key)
            )));
        }
        if seen.contains(&entry.key.as_str()) {
            return Err(invalid_metadata(format!(
                "the metadata key {} is twice in the request",
                quote(&entry.key)
            )));
        }
        if entry.value.is_empty() {
            return Err(invalid_metadata(format!(
                "the metadata {} has no value: remove it, or give a value",
                quote(&entry.key)
            )));
        }
        if !printable_ascii(&entry.value) {
            return Err(invalid_metadata(format!(
                "the value of the metadata {} has ASCII letters, digits, spaces and punctuation only, with no space at the start or the end",
                quote(&entry.key)
            )));
        }
        seen.push(entry.key.as_str());
        total += entry.key.len() + entry.value.len();
    }
    if total > MAX_USER_METADATA_BYTES {
        return Err(invalid_metadata(format!(
            "the user metadata has at most {MAX_USER_METADATA_BYTES} bytes (keys and values), got {total}"
        )));
    }
    Ok(())
}

/// Check the ETag of a request: 1 to 128 printable characters, with no quote, space or comma.
pub fn validate_etag(etag: &str) -> Result<()> {
    if etag.is_empty() {
        return Err(invalid_metadata("etag is required: give the ETag that the form read"));
    }
    if etag.len() > MAX_ETAG_BYTES || !printable_ascii(etag) || etag.contains(['"', ' ', ',']) {
        return Err(invalid_metadata(format!(
            "etag must be the ETag of the object without quotes, got {}",
            quote(etag)
        )));
    }
    Ok(())
}

/// The HTTP headers of the copy: the standard headers and the `x-amz-meta-*` headers.
pub fn metadata_request_headers(headers: &ObjectHeaders, entries: &[MetadataEntry]) -> HeaderMap {
    let mut out = HeaderMap::new();
    for (name, value) in headers.fields() {
        if value.is_empty() {
            continue;
        }
        if let (Ok(name), Ok(value)) = (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(value)) {
            out.insert(name, value);
        }
    }
    for entry in entries {
        let name = format!("x-amz-meta-{}", entry.key);
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&entry.value),
        ) {
            out.insert(name, value);
        }
    }
    out
}

fn joined_values(headers: &HeaderMap, name: &str) -> String {
    headers
        .get_all(name)
        .iter()
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Read the standard headers and the user metadata from the HEAD answer of the provider. The values are the stored
/// values: the gateway `/s3` changes some of them, for example `Cache-Control`.
pub fn stored_metadata(headers: &HeaderMap) -> (ObjectHeaders, Vec<MetadataEntry>) {
    let mut stored = ObjectHeaders::default();
    for (name, _) in ObjectHeaders::default().fields() {
        stored.set(name, joined_values(headers, name));
    }
    let mut entries: Vec<MetadataEntry> = Vec::new();
    for name in headers.keys() {
        let lower = name.as_str().to_lowercase();
        if let Some(key) = lower.strip_prefix("x-amz-meta-") {
            entries.push(MetadataEntry {
                key: key.to_owned(),
                value: joined_values(headers, name.as_str()),
            });
        }
    }
    entries.sort_by(|left, right| left.key.cmp(&right.key));
    (stored, entries)
}

/// The headers of the source that the copy must send again, or the provider changes them. These are the storage
/// class, the redirect of a website and the server-side encryption with a key of the provider.
pub fn kept_object_headers(headers: &HeaderMap) -> HeaderMap {
    let mut out = kept_encryption_headers(headers);
    for name in ["x-amz-storage-class", "x-amz-website-redirect-location"] {
        let value = headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty());
        if let Some(value) = value
            && let Ok(value) = HeaderValue::from_str(value)
        {
            out.insert(HeaderName::from_static(name), value);
        }
    }
    out
}

/// True for the 412 of a copy whose source does not have the ETag of `x-amz-copy-source-if-match`.
pub fn is_precondition_failed(error: &Error) -> bool {
    error
        .as_upstream()
        .is_some_and(|upstream| upstream.status == 412 || upstream.code == "PreconditionFailed")
}

// --- The S3 request -----------------------------------------------------------------------------------------------

/// Copy the object, or one version of it, onto its key with the headers (`CopyObject` with
/// `x-amz-metadata-directive: REPLACE`). The tags stay. The header `x-amz-copy-source-if-match` makes the provider
/// refuse a source with another ETag.
pub async fn replace_object_metadata(
    s3: &dyn S3Call,
    ctx: &OpCtx,
    key: &str,
    version: &str,
    etag: &str,
    headers: &HeaderMap,
) -> Result<()> {
    let mut request = headers.clone();
    let source = copy_source_header(&s3.bucket_config().bucket, key, version);
    let pairs = [
        ("x-amz-copy-source", source),
        ("x-amz-metadata-directive", "REPLACE".to_owned()),
        ("x-amz-tagging-directive", "COPY".to_owned()),
        ("x-amz-copy-source-if-match", format!("\"{etag}\"")),
    ];
    for (name, value) in pairs {
        let value = HeaderValue::from_str(&value).map_err(|_| Error::internal("the copy header is not valid"))?;
        request.insert(HeaderName::from_static(name), value);
    }
    write_encryption_headers(s3.bucket_config(), &mut request);
    let call = S3Request {
        method: Method::PUT,
        key,
        query: Vec::new(),
        headers: request,
        body: None,
    };
    let answer = s3.call(ctx, call, MAX_ANSWER_BYTES).await?;
    if !is_success(answer.status) {
        return Err(s3.provider_error(&answer));
    }
    // Some S3 implementations return HTTP 200 with an embedded Error document.
    match embedded_error(&answer.body) {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

impl MetadataEditor for S3Backend {
    fn replace_metadata<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        version: &'a str,
        etag: &'a str,
        headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { replace_object_metadata(self, ctx, key, version, etag, headers).await })
    }
}

// --- The instance -------------------------------------------------------------------------------------------------

fn versioning_unavailable() -> Error {
    Error::api(
        501,
        "versioning_unavailable",
        "object versioning is not available for this storage bucket",
    )
}

impl Instance {
    /// True when the instance can change the metadata of an object. Until the probe has run, and until the provider
    /// refuses an edit, the answer is yes for a back end with the edit.
    pub fn metadata_edit_available(&self) -> bool {
        self.backend.metadata_editor().is_some() && !self.metadata.off.load(Ordering::SeqCst)
    }

    /// Send the copy of the edit for an object that does not exist, with an ETag that no object has. A provider with
    /// `CopyObject` answers "no such key" and writes nothing. A provider without it answers 501 or 405. Any other
    /// failure (denied, timeout) leaves the answer at yes. An instance without the write permission is not probed.
    pub async fn probe_metadata_edit(&self, ctx: &OpCtx) {
        let Some(editor) = self.backend.metadata_editor() else {
            return;
        };
        if !self.permitted(PERMISSION_WRITE) {
            return;
        }
        let probe = ctx.with_timeout(PROBE_TIMEOUT);
        let key = self.full_key(METADATA_PROBE_KEY);
        let empty = HeaderMap::new();
        let result = probe
            .run(editor.replace_metadata(&probe, &key, "", "stowr-probe", &empty))
            .await;
        if let Err(error) = result
            && provider_refused_feature(&error)
        {
            self.metadata.off.store(true, Ordering::SeqCst);
        }
    }

    async fn head_for_metadata(&self, ctx: &OpCtx, key: &str, version: &str) -> Result<ObjectResponse> {
        if version.trim().is_empty() {
            self.head(ctx, key).await
        } else {
            self.head_version(ctx, key, version).await
        }
    }

    /// Give the object, or the version that `version` names, the headers of metadata. `etag` and `modified` are the
    /// ETag and the modification date that the caller read. A `None` date is not compared. A HEAD request compares
    /// both. The copy names the ETag again. Thus an object that changes between the two requests is not overwritten. An older version becomes the current version.
    pub async fn replace_metadata(
        &self,
        ctx: &OpCtx,
        key: &str,
        version: &str,
        etag: &str,
        modified: Option<Timestamp>,
        metadata: &HeaderMap,
    ) -> Result<()> {
        let editor = match self.backend.metadata_editor() {
            Some(editor) if !self.metadata.off.load(Ordering::SeqCst) => editor,
            _ => return Err(metadata_edit_unsupported()),
        };
        if !version.is_empty() {
            let (supported, checked) = self
                .versioning
                .probe
                .lock()
                .map(|state| *state)
                .unwrap_or((false, false));
            if self.backend.version_store().is_none() || (checked && !supported) {
                return Err(versioning_unavailable());
            }
        }
        let head = self.head_for_metadata(ctx, key, version).await?;
        let stored_etag = head
            .headers
            .get(http::header::ETAG)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .trim()
            .trim_matches('"')
            .to_owned();
        let headers = head.headers;
        drop(head.body);
        if stored_etag != etag {
            return Err(object_changed_error());
        }
        if let Some(modified) = modified {
            let stored = headers
                .get(http::header::LAST_MODIFIED)
                .and_then(|value| value.to_str().ok())
                .and_then(Timestamp::parse_http_date);
            if !stored.is_some_and(|value| value.secs == modified.secs && value.nanos == modified.nanos) {
                return Err(object_changed_error());
            }
        }
        if headers.contains_key(super::encryption::SSE_CUSTOMER_ALGORITHM_HEADER) {
            return Err(Error::api(
                400,
                "metadata_unsupported",
                "the object is encrypted with a key of the customer (SSE-C): Stowr cannot copy it",
            ));
        }
        let kept = kept_object_headers(&headers);
        let size = headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse::<i64>().ok());
        // The save writes the whole object again: the ceiling object.write applies to its size.
        check_object_ceiling(ctx, ACTION_WRITE, size.filter(|value| *value >= 0).unwrap_or(-1))?;
        let known = size.unwrap_or(0);
        let result = if self.copies_in_parts(known) {
            self.copy_multipart(
                ctx,
                key,
                key,
                MultipartCopyOptions {
                    source_version: version.to_owned(),
                    expected_etag: etag.to_owned(),
                    metadata: Some(metadata.clone()),
                    extra_headers: kept,
                    ..MultipartCopyOptions::default()
                },
            )
            .await
        } else {
            let mut merged = metadata.clone();
            for (name, value) in &kept {
                merged.insert(name.clone(), value.clone());
            }
            let slot = begin_request(self, ctx).await?;
            let result = editor.replace_metadata(ctx, key, version, etag, &merged).await;
            drop(slot);
            if let Err(error) = &result
                && provider_refused_feature(error)
            {
                self.metadata.off.store(true, Ordering::SeqCst);
                return Err(metadata_edit_unsupported());
            }
            observe_permission(self, PERMISSION_WRITE, result.as_ref().err());
            result
        };
        match result {
            Err(error) if is_precondition_failed(&error) => Err(object_changed_error()),
            other => other,
        }
    }
}

// --- HTTP ---------------------------------------------------------------------------------------------------------

/// The body of `PUT /api/metadata`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct MetadataRequest {
    /// The instance.
    #[serde(default, deserialize_with = "null_default")]
    pub instance: String,
    /// The key.
    #[serde(default, deserialize_with = "null_default")]
    pub key: String,
    /// The version.
    #[serde(default, deserialize_with = "null_default")]
    pub version: String,
    /// The ETag that the form read.
    #[serde(default, rename = "etag", deserialize_with = "null_default")]
    pub etag: String,
    /// The date of the metadata answer that the form read (RFC 3339). Empty means no comparison.
    #[serde(default, deserialize_with = "null_default")]
    pub last_modified: String,
    /// The standard headers.
    #[serde(default, deserialize_with = "null_default")]
    pub headers: ObjectHeaders,
    /// The user metadata.
    #[serde(default, deserialize_with = "null_default")]
    pub metadata: Vec<MetadataEntry>,
}

/// The answer of `/api/metadata`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MetadataResponse {
    /// The instance.
    pub instance: String,
    /// The key.
    pub key: String,
    /// The version.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version: String,
    /// The ETag without quotes.
    #[serde(rename = "etag")]
    pub etag: String,
    /// The date of the last change (RFC 3339).
    #[serde(rename = "lastModified", skip_serializing_if = "String::is_empty")]
    pub last_modified: String,
    /// The size.
    pub size: i64,
    /// The standard headers.
    pub headers: ObjectHeaders,
    /// The user metadata.
    pub metadata: Vec<MetadataEntry>,
    /// True when the ETag has the form `<digest>-<parts>`: the object was uploaded in parts.
    #[serde(rename = "multipartETag")]
    pub multipart_etag: bool,
    /// True when a save copies the object in parts.
    #[serde(rename = "copyInParts")]
    pub copy_in_parts: bool,
    /// The limit of the user metadata.
    #[serde(rename = "maxMetadataBytes")]
    pub max_metadata_bytes: usize,
}

fn is_multipart_etag(etag: &str) -> bool {
    let Some(index) = etag.rfind('-') else {
        return false;
    };
    let digits = &etag[index + 1..];
    !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
}

/// Read the stored metadata of the object, or of one version of it, with a HEAD request.
pub async fn metadata_state(ctx: &OpCtx, instance: &Instance, key: &str, version: &str) -> Result<MetadataResponse> {
    let head = instance
        .head_for_metadata(ctx, &instance.full_key(key), version)
        .await?;
    let headers = head.headers;
    drop(head.body);
    let (stored, entries) = stored_metadata(&headers);
    let etag = headers
        .get(http::header::ETAG)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .trim()
        .trim_matches('"')
        .to_owned();
    let size = headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<i64>().ok())
        .unwrap_or(0);
    let last_modified = headers
        .get(http::header::LAST_MODIFIED)
        .and_then(|value| value.to_str().ok())
        .and_then(Timestamp::parse_http_date)
        .map(|value| value.utc().rfc3339())
        .unwrap_or_default();
    Ok(MetadataResponse {
        instance: instance.cfg.id.clone(),
        key: key.to_owned(),
        version: headers
            .get("x-amz-version-id")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .trim()
            .to_owned(),
        multipart_etag: is_multipart_etag(&etag),
        etag,
        last_modified,
        size,
        headers: stored,
        metadata: entries,
        copy_in_parts: instance.copies_in_parts(size),
        max_metadata_bytes: MAX_USER_METADATA_BYTES,
    })
}

/// `GET` reads and `PUT` replaces the metadata of an object. The answer of a `PUT` is the new state.
pub fn handle_metadata(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        let result = match req.method {
            Method::GET => read_route(&app, req).await,
            Method::PUT => replace_route(&app, req).await,
            _ => return method_not_allowed(&["GET", "PUT"]),
        };
        match result {
            Ok(response) => response,
            Err(error) => api_error(&error),
        }
    })
}

async fn read_route(app: &App, req: Req) -> Result<Response> {
    let Req { query, ctx, .. } = req;
    let key = clean_relative_key(query.get("key"));
    let instance = app.instance_of("", query.get("instance"))?.clone();
    instance.require_permission(PERMISSION_READ)?;
    if key.is_empty() {
        return Err(Error::api(400, "invalid_key", "object key is required"));
    }
    access::authorize_read(app, &ctx, &instance, &key).await?;
    if !instance.metadata_edit_available() {
        return Err(metadata_edit_unsupported());
    }
    let state = metadata_state(&ctx, &instance, &key, query.get("version").trim()).await?;
    Ok(json(200, &state))
}

async fn replace_route(app: &App, req: Req) -> Result<Response> {
    let Req { query, body, ctx, .. } = req;
    let request: MetadataRequest = decode_json(body).await?;
    let key = clean_relative_key(&request.key);
    let instance = app.instance_of(&request.instance, query.get("instance"))?.clone();
    instance.require_permission(PERMISSION_WRITE)?;
    if key.is_empty() {
        return Err(Error::api(400, "invalid_key", "object key is required"));
    }
    validate_etag(&request.etag)?;
    validate_object_headers(&request.headers)?;
    validate_user_metadata(&request.metadata)?;
    let version = request.version.as_str();
    if !version.is_empty() && (version.len() > 1024 || !printable_ascii(version)) {
        return Err(invalid_metadata(format!(
            "version must be the id of a version of the object, got {}",
            quote(version)
        )));
    }
    let mut modified = None;
    if !request.last_modified.is_empty() {
        modified = Some(Timestamp::parse_rfc3339(&request.last_modified).ok_or_else(|| {
            invalid_metadata(format!(
                "lastModified must be the date that the metadata request gave (RFC 3339), got {}",
                quote(&request.last_modified)
            ))
        })?);
    }
    access::authorize_use(app, &ctx, access::ACTION_WRITE, &instance, &key).await?;
    let metadata = metadata_request_headers(&request.headers, &request.metadata);
    instance
        .replace_metadata(
            &ctx,
            &instance.full_key(&key),
            version,
            &request.etag,
            modified,
            &metadata,
        )
        .await?;
    let state = metadata_state(&ctx, &instance, &key, "").await?;
    Ok(json(200, &state))
}
