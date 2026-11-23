// SPDX-License-Identifier: MIT OR Apache-2.0
//! The routes `/api/structured-preview` and `/api/archive-preview`.

use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;
use http::Method;
use serde::Serialize;

use super::certificate::{
    certificate_container_label, is_mostly_text, parse_all_certificate_properties, parse_certificate_properties,
};
use super::email::{EmailPreview, email_container_label, email_properties, parse_email_headers, parse_email_preview};
use super::metadata::{
    ListedObject, is_calendar_extension, is_certificate_extension, is_contact_extension, is_email_extension,
    open_source,
};
use super::package::{
    EpubPreview, archive_container_label, archive_package_metadata, compression_method_label, epub_preview,
    zip_archive_properties,
};
use super::pem::encode_base64;
use super::text::{
    CalendarPreview, ContactRecord, calendar_container_label, calendar_metadata, calendar_preview,
    contact_container_label, lossy, vcard_metadata, vcard_preview,
};
use crate::access;
use crate::archive::zip::{ByteSource, ZipReader, invalid_zip, is_zip_archive_extension};
use crate::common::BoxFuture;
use crate::common::app::App;
use crate::common::config::{PERMISSION_READ, RuntimePolicy};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Req, Response, api_error, json, method_not_allowed};
use crate::common::misc::clean_relative_key;
use crate::common::query::Query;
use crate::instance::Instance;
use crate::instance::ceiling::ceiling_error_of;
use crate::instance::range::RangeSource;

/// The largest object that the structured preview reads: 32 MiB.
pub const MAX_STRUCTURED_PREVIEW_BYTES: i64 = 32 << 20;

/// The answer of `/api/structured-preview`.
#[derive(Debug, Default, Serialize)]
pub struct StructuredPreviewResponse {
    instance: String,
    key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    version: String,
    kind: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    container: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    properties: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    raw: String,
    #[serde(rename = "rawEncoding", skip_serializing_if = "String::is_empty")]
    raw_encoding: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    contacts: Vec<ContactRecord>,
    #[serde(skip_serializing_if = "Option::is_none")]
    calendar: Option<CalendarPreview>,
    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<EmailPreview>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    certificates: Vec<BTreeMap<String, String>>,
}

/// One file of an archive in the answer of `/api/archive-preview`.
#[derive(Debug, Serialize)]
pub struct ArchivePreviewEntry {
    name: String,
    #[serde(rename = "compressedSize")]
    compressed_size: u64,
    #[serde(rename = "uncompressedSize")]
    uncompressed_size: u64,
    method: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    modified: String,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    encrypted: bool,
}

/// The answer of `/api/archive-preview`.
#[derive(Debug, Serialize)]
pub struct ArchivePreviewResponse {
    instance: String,
    key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    version: String,
    container: String,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    properties: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    package: BTreeMap<String, String>,
    entries: Vec<ArchivePreviewEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    epub: Option<EpubPreview>,
}

fn invalid_key() -> Error {
    Error::api(400, "invalid_key", "object key cannot be empty")
}

/// The extension of a key in lowercase, without the dot. The extension of the last part of the path.
fn extension_of(key: &str) -> String {
    let name = key.rsplit('/').next().unwrap_or(key);
    match name.rfind('.') {
        Some(index) => name[index + 1..].to_lowercase(),
        None => String::new(),
    }
}

/// The text of a size for a message: `32 MB`.
fn format_byte_size(value: i64) -> String {
    const UNIT: i64 = 1024;
    if value < UNIT {
        return format!("{value} B");
    }
    let mut amount = value as f64;
    for label in ["KB", "MB", "GB", "TB"] {
        amount /= 1024.0;
        if amount < 1024.0 {
            return format!("{amount:.0} {label}");
        }
    }
    format!("{value} B")
}

fn parse_size(text: &str) -> i64 {
    text.trim().parse::<i64>().unwrap_or(0)
}

fn listed_of(query: &Query) -> ListedObject {
    ListedObject {
        size: parse_size(query.get("size")),
        etag: query.get("etag").trim().to_owned(),
        modified: query.get("lastModified").trim().to_owned(),
    }
}

/// The handler of `/api/structured-preview`: the preview of a contact, a calendar, an e-mail or a certificate.
pub fn handle_structured_preview(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        match structured_preview(app, req).await {
            Ok(response) => response,
            Err(error) => api_error(&error),
        }
    })
}

/// The handler of `/api/archive-preview`: the complete list of the files of a ZIP-compatible package.
pub fn handle_archive_preview(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        match archive_preview(app, req).await {
            Ok(response) => response,
            Err(error) => api_error(&error),
        }
    })
}

/// The instance, the key and the checks that both routes share.
async fn prepare(app: &Arc<App>, query: &Query, ctx: &OpCtx) -> Result<(Arc<Instance>, String)> {
    let instance = app.instance_of("", query.get("instance"))?.clone();
    instance.require_permission(PERMISSION_READ)?;
    let key = clean_relative_key(query.get("key"));
    if key.is_empty() {
        return Err(invalid_key());
    }
    access::authorize_read(app, ctx, &instance, &key).await?;
    Ok((instance, key))
}

async fn structured_preview(app: Arc<App>, req: Req) -> Result<Response> {
    let Req { method, query, ctx, .. } = req;
    if method != Method::GET {
        return Ok(method_not_allowed(&["GET"]));
    }
    let (instance, key) = prepare(&app, &query, &ctx).await?;
    let extension = extension_of(&key);
    let content_type = query.get("mime").trim().to_owned();
    let kind = if is_contact_extension(&extension, &content_type) {
        "contact"
    } else if is_calendar_extension(&extension, &content_type) {
        "calendar"
    } else if is_email_extension(&extension, &content_type) {
        "email"
    } else if is_certificate_extension(&extension, &content_type) {
        "certificate"
    } else {
        return Err(Error::api(
            415,
            "unsupported_preview",
            "this object does not have a structured preview",
        ));
    };
    let listed = listed_of(&query);
    let data = read_complete_object(&ctx, &instance, &key, &listed, MAX_STRUCTURED_PREVIEW_BYTES).await?;
    let response = StructuredPreviewResponse {
        instance: instance.cfg.id.clone(),
        key,
        version: query.get("version").trim().to_owned(),
        kind: kind.to_owned(),
        raw_encoding: "text".to_owned(),
        ..StructuredPreviewResponse::default()
    };
    tokio::task::spawn_blocking(move || json(200, &build_structured_response(response, kind, &extension, &data)))
        .await
        .map_err(|_| Error::internal("the structured reader stopped"))
}

/// The parts of the answer that depend on the kind of the object.
fn build_structured_response(
    mut response: StructuredPreviewResponse,
    kind: &str,
    extension: &str,
    data: &[u8],
) -> StructuredPreviewResponse {
    match kind {
        "contact" => {
            response.container = contact_container_label(extension).to_owned();
            response.properties = vcard_metadata(data);
            response.contacts = vcard_preview(data);
            response.raw = lossy(data);
        }
        "calendar" => {
            response.container = calendar_container_label(extension).to_owned();
            response.properties = calendar_metadata(data);
            response.calendar = Some(calendar_preview(data));
            response.raw = lossy(data);
        }
        "email" => {
            response.container = email_container_label(extension).to_owned();
            let headers = parse_email_headers(data).unwrap_or_default();
            response.properties = email_properties(&headers);
            response.email = Some(parse_email_preview(data));
            response.raw = lossy(data);
        }
        _ => {
            response.container = certificate_container_label(extension).to_owned();
            response.properties = parse_certificate_properties(data, extension);
            response.certificates = parse_all_certificate_properties(data, extension);
            if is_mostly_text(data) {
                response.raw = lossy(data);
            } else {
                response.raw_encoding = "base64".to_owned();
                response.raw = encode_base64(data);
            }
        }
    }
    response
}

/// Read a whole object of at most `maximum` bytes.
async fn read_complete_object(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    listed: &ListedObject,
    maximum: i64,
) -> Result<Bytes> {
    let source = open_source(ctx, instance, key, listed).await?;
    if source.size().is_none() {
        source.read_suffix(1).await?;
    }
    let size = source.size_or_zero();
    if size <= 0 {
        return Err(Error::api(
            422,
            "unknown_size",
            "the object size could not be determined safely",
        ));
    }
    if size > maximum {
        return Err(Error::api(
            413,
            "preview_too_large",
            format!(
                "this structured preview reads the complete object and is limited to {}",
                format_byte_size(maximum)
            ),
        ));
    }
    let data = source.read_range(0, size).await?;
    if data.len() as i64 != size {
        return Err(Error::api(
            502,
            "preview_truncated",
            "the storage provider returned a truncated object",
        ));
    }
    Ok(data)
}

async fn archive_preview(app: Arc<App>, req: Req) -> Result<Response> {
    let Req { method, query, ctx, .. } = req;
    if method != Method::GET {
        return Ok(method_not_allowed(&["GET"]));
    }
    let (instance, key) = prepare(&app, &query, &ctx).await?;
    let extension = extension_of(&key);
    if !is_zip_archive_extension(&extension) {
        return Err(Error::api(
            415,
            "unsupported_preview",
            "this archive format does not expose a deterministic central directory preview",
        ));
    }
    let listed = listed_of(&query);
    let source = open_source(&ctx, &instance, &key, &listed).await?;
    let limit = match app.config.runtime.max_archive_entries {
        0 => RuntimePolicy::default().max_archive_entries as usize,
        value => value as usize,
    };
    let reader = match ZipReader::open_package(source.with_context(&ctx), &extension, limit).await {
        Ok(reader) => reader,
        Err(error) => {
            // A refusal for a ceiling keeps its own answer: it is not a damaged archive.
            if ceiling_error_of(&error).is_some() {
                return Err(error);
            }
            if error.has_code("archive_too_many_entries") {
                let count = declared_entry_count(&source).await.unwrap_or(limit as u64 + 1);
                return Err(Error::api(
                    413,
                    "archive_too_many_entries",
                    format!("the archive contains {count} entries; the configured complete preview limit is {limit}"),
                ));
            }
            return Err(invalid_zip());
        }
    };
    let mut entries = Vec::with_capacity(reader.entries.len());
    for entry in &reader.entries {
        // The list has files only: a folder record and a link give nothing to open.
        if entry.is_dir() || entry.name.ends_with('/') || entry.is_symlink() || !entry.is_regular() {
            continue;
        }
        let modified = entry.modified.map(|time| time.utc().rfc3339()).unwrap_or_default();
        entries.push(ArchivePreviewEntry {
            name: entry.name.clone(),
            compressed_size: entry.compressed_size,
            uncompressed_size: entry.size,
            method: compression_method_label(entry.method),
            modified,
            encrypted: entry.flags & 0x1 != 0,
        });
    }
    let properties = zip_archive_properties(&reader.entries);
    let package = archive_package_metadata(&reader, &extension).await.unwrap_or_default();
    let epub = if extension == "epub" {
        epub_preview(&reader).await
    } else {
        None
    };
    let response = ArchivePreviewResponse {
        instance: instance.cfg.id.clone(),
        key,
        version: query.get("version").trim().to_owned(),
        container: archive_container_label(&extension).to_owned(),
        properties,
        package,
        entries,
        epub,
    };
    Ok(json(200, &response))
}

/// The number of entries that the end record of an archive declares. It is the number in the message of a
/// central directory that is too large. `None` when the end record is not readable.
async fn declared_entry_count(source: &RangeSource) -> Option<u64> {
    const END_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];
    const ZIP64_LOCATOR: [u8; 4] = [0x50, 0x4b, 0x06, 0x07];
    const ZIP64_END: [u8; 4] = [0x50, 0x4b, 0x06, 0x06];
    let size = source.size()?;
    let length = size.min(128 << 10);
    let tail = ByteSource::fetch(source, (size - length) as u64, length as u64)
        .await
        .ok()?;
    let position = tail.windows(4).rposition(|window| window == END_SIGNATURE)?;
    let record = &tail[position..];
    if record.len() < 22 {
        return None;
    }
    let count = u64::from(u16::from_le_bytes([record[10], record[11]]));
    if count != 0xffff {
        return Some(count);
    }
    if position >= 20 && tail[position - 20..position - 16] == ZIP64_LOCATOR {
        let locator = &tail[position - 20..position];
        let mut offset_bytes = [0u8; 8];
        offset_bytes.copy_from_slice(&locator[8..16]);
        let offset = u64::from_le_bytes(offset_bytes);
        let end = ByteSource::fetch(source, offset, 56).await.ok()?;
        if end.len() >= 56 && end[..4] == ZIP64_END {
            let mut count_bytes = [0u8; 8];
            count_bytes.copy_from_slice(&end[32..40]);
            return Some(u64::from_le_bytes(count_bytes));
        }
    }
    Some(count)
}
