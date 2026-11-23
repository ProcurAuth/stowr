//! The details of the structured objects for the details panel: PDF, ZIP-compatible packages, contacts,
//! calendars, e-mail and certificates. Each reader reads a bounded part of the object through a range source.

use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::Bytes;
use http::HeaderMap;

use super::certificate::{certificate_container_label, parse_certificate_properties};
use super::email::{email_container_label, email_properties, parse_email_headers};
use super::package::{archive_container_label, zip_details};
use super::pdf::parse_pdf_metadata;
use super::text::{calendar_container_label, calendar_metadata, contact_container_label, vcard_metadata};
use crate::archive::zip::{ZipReader, is_zip_archive_extension};
use crate::common::ctx::OpCtx;
use crate::common::error::Result;
use crate::instance::Instance;
use crate::instance::range::{ObjectVersion, RangeSource};
use crate::pv_media::MediaSourceMetadata;

/// The largest object that the small text readers read: 1 MiB.
const MAX_SMALL_METADATA_BYTES: i64 = 1 << 20;
/// The first bytes of a PDF file that the details read: 256 KiB.
const MAX_PDF_PREFIX_BYTES: i64 = 256 << 10;
/// The last bytes of a PDF file that the details read: 4 MiB.
const MAX_PDF_SUFFIX_BYTES: i64 = 4 << 20;
/// The suffix that finds the size of an object whose size is not known.
const SIZE_PROBE_BYTES: i64 = 64 << 10;

/// What the list told about an object: the size, the ETag and the date of the last change as a text.
#[derive(Clone, Debug, Default)]
pub struct ListedObject {
    /// The size, or 0 or less when it is not known.
    pub size: i64,
    /// The ETag.
    pub etag: String,
    /// The date of the last change, as the client gave it.
    pub modified: String,
}

impl From<&MediaSourceMetadata> for ListedObject {
    fn from(listed: &MediaSourceMetadata) -> Self {
        Self {
            size: listed.size,
            etag: listed.etag.clone(),
            modified: listed.last_modified.map(|time| time.rfc3339_nano()).unwrap_or_default(),
        }
    }
}

/// The structured details of an object: the container, the properties, the headers of the first answer and the size.
#[derive(Clone, Debug, Default)]
pub struct StructuredMetadata {
    /// The kind of the container: `PDF`, `ZIP archive`, `vCard contact`...
    pub container: String,
    /// The properties. An empty map means that the reader found none.
    pub properties: BTreeMap<String, String>,
    /// The headers of the first answer of the provider.
    pub headers: HeaderMap,
    /// The size of the object, or 0 when it is not known.
    pub size: i64,
}

/// True for a contact file.
pub fn is_contact_extension(extension: &str, content_type: &str) -> bool {
    extension == "vcf" || extension == "vcard" || content_type == "text/vcard" || content_type == "text/x-vcard"
}

/// True for a calendar file.
pub fn is_calendar_extension(extension: &str, content_type: &str) -> bool {
    extension == "ics" || extension == "ifb" || content_type == "text/calendar" || content_type == "application/ics"
}

/// True for an e-mail file.
pub fn is_email_extension(extension: &str, content_type: &str) -> bool {
    matches!(extension, "eml" | "mime" | "mht" | "mhtml")
        || content_type == "message/rfc822"
        || content_type == "multipart/related"
}

/// True for a certificate, a request or a key file.
pub fn is_certificate_extension(extension: &str, content_type: &str) -> bool {
    matches!(
        extension,
        "pem" | "crt" | "cer" | "cert" | "der" | "csr" | "req" | "p7b" | "p7c" | "spc" | "pfx" | "p12" | "key" | "pub"
    ) || content_type.contains("x-pem")
        || content_type.contains("x-x509")
        || content_type.contains("pkcs")
        || content_type.contains("certificate")
}

/// Open a range source for an object, with what the listing knows.
pub(super) async fn open_source(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    listed: &ListedObject,
) -> Result<RangeSource> {
    let mut source = RangeSource::open_version(ctx, instance, key, "").await?;
    source.set_known_size(listed.size);
    source.set_expected_version(&ObjectVersion {
        etag: listed.etag.clone(),
        version: String::new(),
        modified: listed.modified.clone(),
    });
    Ok(source)
}

/// The length of a read at `start`: the wish, or less near the end of an object of a known size.
fn range_length(source: &RangeSource, start: i64, desired: i64) -> i64 {
    if desired <= 0 {
        return 0;
    }
    let Some(size) = source.size() else {
        return desired;
    };
    if start >= size {
        return 0;
    }
    desired.min(size - start)
}

async fn read_bytes(source: &RangeSource, start: i64, length: i64) -> Result<Bytes> {
    if length <= 0 {
        return Ok(Bytes::new());
    }
    source.read_range(start, length).await
}

fn summary(container: &str, properties: BTreeMap<String, String>, source: &RangeSource) -> StructuredMetadata {
    StructuredMetadata {
        container: container.to_owned(),
        properties,
        headers: source.headers(),
        size: source.size_or_zero(),
    }
}

/// The summary of an object that the details do not read: the container and the headers of a HEAD request.
async fn head_only_summary(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    container: &str,
) -> Result<StructuredMetadata> {
    let response = instance.head(ctx, &instance.full_key(key)).await?;
    let size = response
        .headers
        .get(http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<i64>().ok())
        .unwrap_or(0);
    Ok(StructuredMetadata {
        container: container.to_owned(),
        properties: BTreeMap::new(),
        headers: response.headers,
        size,
    })
}

/// Read the last bytes of an object whose size is not known, so that the size becomes known.
async fn discover_size(source: &RangeSource) -> Result<()> {
    if source.size().is_none() {
        source.read_suffix(SIZE_PROBE_BYTES).await?;
    }
    Ok(())
}

/// The structured details of an object, or `None` when the object is not one of the structured formats.
pub async fn inspect_structured_metadata(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    extension: &str,
    content_type: &str,
    listed: &MediaSourceMetadata,
) -> Result<Option<StructuredMetadata>> {
    let extension = extension.trim().to_lowercase();
    let content_type = content_type.split(';').next().unwrap_or("").trim().to_lowercase();
    let listed = ListedObject::from(listed);
    let summary = if extension == "pdf" || content_type == "application/pdf" {
        inspect_pdf(ctx, instance, key, &listed).await?
    } else if is_zip_archive_extension(&extension) {
        inspect_zip_archive(ctx, instance, key, &extension, &listed).await?
    } else if is_contact_extension(&extension, &content_type) {
        inspect_small_text(
            ctx,
            instance,
            key,
            &listed,
            contact_container_label(&extension),
            vcard_metadata,
        )
        .await?
    } else if is_calendar_extension(&extension, &content_type) {
        inspect_small_text(
            ctx,
            instance,
            key,
            &listed,
            calendar_container_label(&extension),
            calendar_metadata,
        )
        .await?
    } else if is_email_extension(&extension, &content_type) {
        inspect_email_headers(ctx, instance, key, &listed, email_container_label(&extension)).await?
    } else if is_certificate_extension(&extension, &content_type) {
        inspect_certificate(ctx, instance, key, &extension, &listed).await?
    } else {
        return Ok(None);
    };
    Ok(Some(summary))
}

async fn inspect_pdf(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    listed: &ListedObject,
) -> Result<StructuredMetadata> {
    let source = open_source(ctx, instance, key, listed).await?;
    let prefix = read_bytes(&source, 0, range_length(&source, 0, MAX_PDF_PREFIX_BYTES)).await?;
    if source.size().is_none() {
        source.read_suffix(MAX_PDF_SUFFIX_BYTES).await?;
    }
    let mut suffix = Bytes::new();
    if let Some(size) = source.size() {
        let length = size.min(MAX_PDF_SUFFIX_BYTES);
        suffix = read_bytes(&source, size - length, length).await?;
    }
    let size = source.size_or_zero();
    let props = tokio::task::spawn_blocking(move || parse_pdf_metadata(&prefix, &suffix, size))
        .await
        .map_err(|_| crate::common::error::Error::internal("the PDF reader stopped"))?;
    Ok(summary("PDF", props, &source))
}

async fn inspect_zip_archive(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    extension: &str,
    listed: &ListedObject,
) -> Result<StructuredMetadata> {
    let source = open_source(ctx, instance, key, listed).await?;
    discover_size(&source).await?;
    let label = archive_container_label(extension);
    if source.size().is_none() {
        return head_only_summary(ctx, instance, key, label).await;
    }
    let Ok(reader) = ZipReader::open_package(source.with_context(ctx), extension, 0).await else {
        return Ok(summary(label, BTreeMap::new(), &source));
    };
    let props = zip_details(&reader, extension).await;
    Ok(summary(label, props, &source))
}

async fn inspect_small_text(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    listed: &ListedObject,
    container: &str,
    parser: fn(&[u8]) -> BTreeMap<String, String>,
) -> Result<StructuredMetadata> {
    let source = open_source(ctx, instance, key, listed).await?;
    discover_size(&source).await?;
    let Some(size) = source.size().filter(|size| *size <= MAX_SMALL_METADATA_BYTES) else {
        return head_only_summary(ctx, instance, key, container).await;
    };
    let data = read_bytes(&source, 0, size).await?;
    let props = tokio::task::spawn_blocking(move || parser(&data))
        .await
        .map_err(|_| crate::common::error::Error::internal("the structured reader stopped"))?;
    Ok(summary(container, props, &source))
}

async fn inspect_email_headers(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    listed: &ListedObject,
    container: &str,
) -> Result<StructuredMetadata> {
    let source = open_source(ctx, instance, key, listed).await?;
    let data = read_bytes(&source, 0, range_length(&source, 0, MAX_SMALL_METADATA_BYTES)).await?;
    let props = match parse_email_headers(&data) {
        Some(headers) => email_properties(&headers),
        None => BTreeMap::new(),
    };
    Ok(summary(container, props, &source))
}

async fn inspect_certificate(
    ctx: &OpCtx,
    instance: &Arc<Instance>,
    key: &str,
    extension: &str,
    listed: &ListedObject,
) -> Result<StructuredMetadata> {
    let source = open_source(ctx, instance, key, listed).await?;
    discover_size(&source).await?;
    let container = certificate_container_label(extension);
    let Some(size) = source.size().filter(|size| *size <= MAX_SMALL_METADATA_BYTES) else {
        return head_only_summary(ctx, instance, key, container).await;
    };
    let data = read_bytes(&source, 0, size).await?;
    let extension = extension.to_owned();
    let props = tokio::task::spawn_blocking(move || parse_certificate_properties(&data, &extension))
        .await
        .map_err(|_| crate::common::error::Error::internal("the certificate reader stopped"))?;
    Ok(summary(container, props, &source))
}
