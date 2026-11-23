// SPDX-License-Identifier: MIT OR Apache-2.0
//! The technical inspection of one object (docs/PREVIEWS.md, "Technical inspection"): the metadata of the provider,
//! the first 64 KiB and, when useful, the last 64 KiB, the detected media type, the structural markers, and the
//! exact provider requests and bytes of the inspection. The headers that carry a credential do not go to the client.

use std::collections::BTreeMap;
use std::sync::Arc;

use http::header::{ACCEPT_ENCODING, HeaderValue, IF_MATCH, RANGE};
use http::{HeaderMap, Method};
use serde::Serialize;

use crate::common::BoxFuture;
use crate::common::app::App;
use crate::common::config::PERMISSION_READ;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Req, Response, api_error, json, method_not_allowed, read_limited};
use crate::common::misc::{clean_relative_key, hex};
use crate::common::query::Query;
use crate::common::time::Timestamp;
use crate::instance::Instance;
use crate::instance::versions::provider_checksums;
use crate::server::mediatype::{detect_content_type, type_by_extension};

/// The size of each probe: 64 KiB.
const PROBE_SIZE: i64 = 64 << 10;
/// The most bytes of a probe that the answer shows.
const PROBE_PREVIEW: usize = 256;

/// One probe of the bytes of the object.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct InspectProbe {
    /// `Header` or `Trailer`.
    pub name: String,
    /// `bytes=<start>-<end>`, or `empty`.
    pub range: String,
    /// The bytes that the probe read.
    pub bytes: usize,
    /// The first 256 bytes in hexadecimal.
    pub hex: String,
    /// The first 256 bytes as ASCII, with `.` for each byte that is not printable.
    pub ascii: String,
}

/// The provider requests and bytes of the inspection.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct InspectResources {
    /// The provider calls.
    #[serde(rename = "storageRequests")]
    pub storage_requests: i64,
    /// The provider bytes.
    #[serde(rename = "storageBytes")]
    pub storage_bytes: i64,
    /// The start of the budget of the request.
    #[serde(rename = "startedAt", serialize_with = "crate::common::time::serialize_or_zero")]
    pub started_at: Option<Timestamp>,
    /// The time of the inspection, in milliseconds.
    #[serde(rename = "elapsedMs")]
    pub elapsed_ms: i64,
}

/// The answer of `/api/inspect`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct InspectResponse {
    /// The instance.
    pub instance: String,
    /// The relative key.
    pub key: String,
    /// The version.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version: String,
    /// The provider of the instance (`s3`, `gcs`, `fs`).
    pub provider: String,
    /// The kind of the object.
    #[serde(rename = "detectedKind")]
    pub detected_kind: String,
    /// The media type that the first bytes and the extension give.
    #[serde(rename = "detectedMime", skip_serializing_if = "String::is_empty")]
    pub detected_mime: String,
    /// The media type of the provider.
    #[serde(rename = "declaredMime", skip_serializing_if = "String::is_empty")]
    pub declared_mime: String,
    /// The size.
    pub size: i64,
    /// The ETag without quotes.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub etag: String,
    /// The generation of a GCS object.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub generation: String,
    /// The `Last-Modified` header of the provider.
    #[serde(rename = "lastModified", skip_serializing_if = "String::is_empty")]
    pub last_modified: String,
    /// The headers of the provider, without the headers that carry a credential.
    pub headers: BTreeMap<String, String>,
    /// The checksums of the provider.
    #[serde(rename = "providerChecksums", skip_serializing_if = "BTreeMap::is_empty")]
    pub provider_checksums: BTreeMap<String, String>,
    /// The probes.
    pub probes: Vec<InspectProbe>,
    /// The structural markers.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub structure: BTreeMap<String, String>,
    /// The provider requests and bytes of the inspection.
    pub resources: InspectResources,
}

/// The extension of the last part of a key, with its dot, or an empty text.
fn extension(key: &str) -> &str {
    let name = key.rsplit('/').next().unwrap_or(key);
    name.rfind('.').map_or("", |index| &name[index..])
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers.get(name).and_then(|value| value.to_str().ok()).unwrap_or("")
}

/// The handler of `GET /api/inspect?instance=&key=&version=`.
pub fn handle_inspect(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        if req.method != Method::GET {
            return method_not_allowed(&["GET"]);
        }
        let Req { query, ctx, .. } = req;
        inspect_route(&app, &query, &ctx)
            .await
            .unwrap_or_else(|error| api_error(&error))
    })
}

async fn inspect_route(app: &App, query: &Query, ctx: &OpCtx) -> Result<Response> {
    let instance = app.instance_of("", query.get("instance"))?.clone();
    instance.require_permission(PERMISSION_READ)?;
    let key = clean_relative_key(query.get("key"));
    let version = query.get("version").trim().to_owned();
    if key.is_empty() {
        return Err(Error::api(400, "invalid_key", "object key is required"));
    }
    crate::access::authorize_read(app, ctx, &instance, &key).await?;
    let before = ctx.budget.as_ref().map(|budget| budget.usage());
    let mut result = inspect_object(ctx, &instance, &key, &version).await?;
    if let (Some(budget), Some(before)) = (&ctx.budget, before) {
        let after = budget.usage();
        result.resources = InspectResources {
            storage_requests: after.storage_requests - before.storage_requests,
            storage_bytes: after.storage_bytes - before.storage_bytes,
            started_at: Some(before.started_at),
            elapsed_ms: after.elapsed_ms - before.elapsed_ms,
        };
    }
    Ok(json(200, &result))
}

/// Inspect one object (or one version): its metadata, its first and last bytes, and its markers.
pub async fn inspect_object(ctx: &OpCtx, instance: &Instance, key: &str, version: &str) -> Result<InspectResponse> {
    let full_key = instance.full_key(key);
    let head = instance.head_version(ctx, &full_key, version).await?;
    let raw_size = header(&head.headers, "content-length").trim();
    if raw_size.is_empty() {
        return Err(Error::api(
            502,
            "missing_content_length",
            "the storage provider did not return Content-Length for technical inspection",
        ));
    }
    let size = match raw_size.parse::<i64>() {
        Ok(size) if size >= 0 => size,
        _ => {
            return Err(Error::api(
                502,
                "invalid_content_length",
                "the storage provider returned an invalid Content-Length for technical inspection",
            ));
        }
    };
    let etag = header(&head.headers, "etag").trim().to_owned();
    let mut result = InspectResponse {
        instance: instance.cfg.id.clone(),
        key: key.to_owned(),
        version: version.to_owned(),
        provider: instance.cfg.provider.clone(),
        size,
        etag: etag.trim_matches('"').to_owned(),
        generation: header(&head.headers, "x-goog-generation").to_owned(),
        last_modified: header(&head.headers, "last-modified").to_owned(),
        declared_mime: header(&head.headers, "content-type").to_owned(),
        headers: safe_inspection_headers(&head.headers),
        provider_checksums: provider_checksums(&head.headers),
        ..InspectResponse::default()
    };
    let probe_size = if size > 0 { PROBE_SIZE.min(size) } else { PROBE_SIZE };
    let first = read_inspection_range(ctx, instance, &full_key, version, 0, probe_size, size, &etag).await?;
    result.probes.push(inspection_probe("Header", 0, &first));
    let mut suffix = Vec::new();
    if size > probe_size {
        let start = size - probe_size;
        suffix = read_inspection_range(ctx, instance, &full_key, version, start, probe_size, size, &etag).await?;
        result.probes.push(inspection_probe("Trailer", start, &suffix));
    }
    let mut detected = detect_content_type(&first);
    let inferred = type_by_extension(&extension(key).to_lowercase());
    if !inferred.is_empty() && (detected == "application/octet-stream" || detected == "text/plain; charset=utf-8") {
        detected = inferred;
    }
    result.detected_mime = detected.to_owned();
    result.detected_kind = crate::server::detect_kind(key, detected).to_owned();
    inspect_structure(&mut result.structure, &first, &suffix, size);
    Ok(result)
}

/// Read one exact range of the object for the inspection. The answer must be `206` with the same range, the same
/// total and the same length.
#[allow(clippy::too_many_arguments)]
async fn read_inspection_range(
    ctx: &OpCtx,
    instance: &Instance,
    full_key: &str,
    version: &str,
    start: i64,
    length: i64,
    expected_total: i64,
    etag: &str,
) -> Result<Vec<u8>> {
    if length <= 0 {
        return Ok(Vec::new());
    }
    let end = start + length - 1;
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(&format!("bytes={start}-{end}")) {
        headers.insert(RANGE, value);
    }
    headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
    if !etag.trim().is_empty()
        && let Ok(value) = HeaderValue::from_str(etag)
    {
        headers.insert(IF_MATCH, value);
    }
    let response = instance.get_version(ctx, full_key, version, &headers).await?;
    if response.status != 206 {
        return Err(Error::api(
            502,
            "range_not_honored",
            "the storage provider did not honor the inspection byte-range request",
        ));
    }
    match parse_content_range(header(&response.headers, "content-range")) {
        Some((first, last, total)) if first == start && last == end && total == expected_total => {}
        _ => {
            return Err(Error::api(
                502,
                "invalid_content_range",
                "the storage provider returned an unexpected Content-Range for technical inspection",
            ));
        }
    }
    let raw_length = header(&response.headers, "content-length").trim();
    if !raw_length.is_empty() && raw_length.parse::<i64>().ok() != Some(length) {
        return Err(Error::api(
            502,
            "invalid_content_length",
            "the storage provider returned an unexpected ranged Content-Length for technical inspection",
        ));
    }
    let limit = usize::try_from(length + 1).unwrap_or(usize::MAX);
    let (data, _) = ctx.run(read_limited(response.body, limit)).await?;
    if i64::try_from(data.len()).ok() != Some(length) {
        return Err(Error::api(
            502,
            "incomplete_range",
            "the storage provider returned an incomplete byte range for technical inspection",
        ));
    }
    Ok(data.to_vec())
}

/// Read `Content-Range: bytes <start>-<end>/<total>`: the start, the end and the total. A total `*`, a bad number or
/// an end after the total gives `None`.
pub(crate) fn parse_content_range(value: &str) -> Option<(i64, i64, i64)> {
    let value = value.trim();
    if !value.get(..6)?.eq_ignore_ascii_case("bytes ") {
        return None;
    }
    let (bounds, total) = value[6..].trim().split_once('/')?;
    if bounds == "*" || total == "*" {
        return None;
    }
    let total = total.trim().parse::<i64>().ok().filter(|total| *total >= 0)?;
    let (start, end) = bounds.trim().split_once('-')?;
    let start = start.trim().parse::<i64>().ok().filter(|start| *start >= 0)?;
    let end = end.trim().parse::<i64>().ok()?;
    if end < start || (total > 0 && end >= total) {
        return None;
    }
    Some((start, end, total))
}

fn inspection_probe(name: &str, start: i64, data: &[u8]) -> InspectProbe {
    let preview = &data[..data.len().min(PROBE_PREVIEW)];
    let ascii: String = preview
        .iter()
        .map(|byte| {
            if (32..=126).contains(byte) {
                char::from(*byte)
            } else {
                '.'
            }
        })
        .collect();
    let range = if data.is_empty() {
        "empty".to_owned()
    } else {
        format!("bytes={start}-{}", start + data.len() as i64 - 1)
    };
    InspectProbe {
        name: name.to_owned(),
        range,
        bytes: data.len(),
        hex: hex(preview),
        ascii,
    }
}

/// The canonical form of a header name: the first letter and each letter after `-` in upper case, the others in lower
/// case. A name with a character that a header name cannot have stays as it is.
fn canonical_header_name(name: &str) -> String {
    let valid = !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte));
    if !valid {
        return name.to_owned();
    }
    let mut upper = true;
    name.chars()
        .map(|c| {
            let out = if upper {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            };
            upper = c == '-';
            out
        })
        .collect()
}

/// The headers of the provider without `Authorization`, the cookies and each name with `credential` or `token`. The
/// values of one name are joined with `, `.
fn safe_inspection_headers(headers: &HeaderMap) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for name in headers.keys() {
        let lower = name.as_str().to_ascii_lowercase();
        if lower == "authorization"
            || lower == "cookie"
            || lower == "set-cookie"
            || lower.contains("credential")
            || lower.contains("token")
        {
            continue;
        }
        let values: Vec<String> = headers
            .get_all(name)
            .iter()
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
            .collect();
        out.insert(canonical_header_name(name.as_str()), values.join(", "));
    }
    out
}

fn find(data: &[u8], needle: &[u8]) -> bool {
    data.windows(needle.len()).any(|window| window == needle)
}

/// The structural markers of the first and the last bytes.
fn inspect_structure(output: &mut BTreeMap<String, String>, first: &[u8], suffix: &[u8], size: i64) {
    if first.starts_with(b"%PDF-") {
        let line = first.split(|byte| *byte == b'\n').next().unwrap_or(first);
        let line = String::from_utf8_lossy(line);
        output.insert("Format".to_owned(), "PDF".to_owned());
        output.insert(
            "PDF version".to_owned(),
            line.trim().strip_prefix("%PDF-").unwrap_or(line.trim()).to_owned(),
        );
        if let Some(index) = suffix.windows(9).rposition(|window| window == b"startxref") {
            let tail = String::from_utf8_lossy(&suffix[index..]);
            let mut fields = tail.split_whitespace();
            if let (Some(_), Some(value)) = (fields.next(), fields.next()) {
                output.insert("Start xref".to_owned(), value.to_owned());
            }
        }
        return;
    }
    if first.starts_with(b"PK\x03\x04") || find(suffix, b"PK\x05\x06") {
        output.insert("Format".to_owned(), "ZIP-compatible archive".to_owned());
        output.insert("Central directory".to_owned(), "Present".to_owned());
        return;
    }
    if first.starts_with(b"SQLite format 3\x00") {
        output.insert("Format".to_owned(), "SQLite 3".to_owned());
        if first.len() >= 18 {
            let mut page_size = (u32::from(first[16]) << 8) | u32::from(first[17]);
            if page_size == 1 {
                page_size = 65536;
            }
            output.insert("Page size".to_owned(), page_size.to_string());
        }
        return;
    }
    if first.starts_with(b"\x89PNG\r\n\x1a\n") {
        output.insert("Format".to_owned(), "PNG".to_owned());
        return;
    }
    if first.starts_with(b"\xff\xd8\xff") {
        output.insert("Format".to_owned(), "JPEG".to_owned());
        return;
    }
    if first.len() >= 12 && &first[4..8] == b"ftyp" {
        output.insert("Format".to_owned(), "ISO Base Media".to_owned());
        output.insert(
            "Major brand".to_owned(),
            String::from_utf8_lossy(&first[8..12]).into_owned(),
        );
        return;
    }
    if size >= 0 {
        output.insert("Object length".to_owned(), size.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_content_range_needs_a_known_total_and_an_end_inside_it() {
        assert_eq!(parse_content_range("bytes 0-9/100"), Some((0, 9, 100)));
        assert_eq!(parse_content_range("Bytes 5-5/6"), Some((5, 5, 6)));
        assert_eq!(parse_content_range("bytes 0-9/*"), None);
        assert_eq!(parse_content_range("bytes 9-0/100"), None);
        assert_eq!(parse_content_range("bytes 0-100/100"), None);
        assert_eq!(parse_content_range("items 0-9/100"), None);
        assert_eq!(parse_content_range(""), None);
    }

    #[test]
    fn the_header_names_have_their_canonical_form() {
        assert_eq!(canonical_header_name("x-amz-meta-test"), "X-Amz-Meta-Test");
        assert_eq!(canonical_header_name("etag"), "Etag");
        assert_eq!(canonical_header_name("bad name"), "bad name");
    }

    #[test]
    fn the_credential_headers_do_not_go_to_the_client() {
        let mut headers = HeaderMap::new();
        headers.insert("set-cookie", HeaderValue::from_static("a=1"));
        headers.insert("x-amz-security-token", HeaderValue::from_static("secret"));
        headers.insert("x-credential-hint", HeaderValue::from_static("secret"));
        headers.append("x-amz-meta-tag", HeaderValue::from_static("one"));
        headers.append("x-amz-meta-tag", HeaderValue::from_static("two"));
        let safe = safe_inspection_headers(&headers);
        assert_eq!(safe.len(), 1, "{safe:?}");
        assert_eq!(safe["X-Amz-Meta-Tag"], "one, two");
    }

    #[test]
    fn the_markers_of_common_formats_are_found() {
        let mut structure = BTreeMap::new();
        inspect_structure(&mut structure, b"%PDF-1.7\n%...", b"trailer startxref\n1234\n%%EOF", 99);
        assert_eq!(structure["PDF version"], "1.7");
        assert_eq!(structure["Start xref"], "1234");
        structure.clear();
        let mut sqlite = b"SQLite format 3\x00".to_vec();
        sqlite.extend_from_slice(&[0, 1]);
        inspect_structure(&mut structure, &sqlite, b"", 18);
        assert_eq!(structure["Page size"], "65536");
        structure.clear();
        inspect_structure(&mut structure, b"\x00\x00\x00\x18ftypisom", b"", 12);
        assert_eq!(structure["Major brand"], "isom");
        structure.clear();
        inspect_structure(&mut structure, b"plain", b"", 5);
        assert_eq!(structure["Object length"], "5");
    }

    #[test]
    fn the_extension_is_the_end_of_the_last_part_of_the_key() {
        assert_eq!(extension("a.b/c.PDF"), ".PDF");
        assert_eq!(extension("a.b/c"), "");
        assert_eq!(extension("name."), ".");
    }

    #[test]
    fn a_probe_shows_its_range_and_printable_bytes() {
        let probe = inspection_probe("Header", 10, b"AB\x00");
        assert_eq!(probe.range, "bytes=10-12");
        assert_eq!(probe.ascii, "AB.");
        assert_eq!(probe.hex, "414200");
        assert_eq!(inspection_probe("Header", 0, b"").range, "empty");
    }
}
