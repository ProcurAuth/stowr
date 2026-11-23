//! The object routes: the gateway `/s3` (read, write, delete, the bounded ranges of a preview, and the raw listing in
//! the XML form of S3) and `/open/` (an object with its own name, inline when a browser can show it).

use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use http::header::{
    ACCEPT_RANGES, ALLOW, CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE,
    CONTENT_TYPE, HeaderName, HeaderValue,
};
use http::{HeaderMap, Method};
use http_body::{Frame, SizeHint};
use http_body_util::BodyExt;
use serde::Serialize;

use super::RequestHead;
use super::kind::{browser_inline_content, is_generic_object_content_type, preview_content_type};
use super::mediatype::format_media_type;
use super::paths;
use crate::common::BoxFuture;
use crate::common::app::App;
use crate::common::config::{PERMISSION_DELETE, PERMISSION_READ, PERMISSION_WRITE};
use crate::common::error::{Error, Result};
use crate::common::http::{Body, Req, Response, answer, empty, full, gateway_error, json, method_not_allowed};
use crate::common::misc::{clean_relative_key, parse_bounded_int};
use crate::common::storage::{ListOptions, ObjectResponse};
use crate::instance::Instance;

/// The largest range of a preview that asks for ranges only: 16 MiB.
pub const MAX_PREVIEW_RANGE: i64 = 16 << 20;

/// The object headers that the routes copy from the provider: the standard headers, the version, the lock, the
/// encryption, and the `x-amz-meta-*` and `x-goog-meta-*` headers.
const COPIED_HEADERS: [&str; 22] = [
    "accept-ranges",
    "cache-control",
    "content-disposition",
    "content-encoding",
    "content-language",
    "content-length",
    "content-range",
    "content-type",
    "etag",
    "expires",
    "last-modified",
    "vary",
    "x-amz-version-id",
    "x-amz-object-lock-mode",
    "x-amz-object-lock-retain-until-date",
    "x-amz-object-lock-legal-hold",
    "x-goog-generation",
    "x-goog-hash",
    "x-amz-server-side-encryption",
    "x-amz-server-side-encryption-aws-kms-key-id",
    "x-amz-server-side-encryption-bucket-key-enabled",
    "x-amz-server-side-encryption-customer-algorithm",
];

/// Add the object headers of a provider answer to the headers of an answer. A header that the answer already has
/// keeps its value and gets the value of the provider after it.
pub fn copy_object_headers(destination: &mut HeaderMap, source: &HeaderMap) {
    for (name, value) in source {
        let lower = name.as_str();
        if COPIED_HEADERS.contains(&lower) || lower.starts_with("x-amz-meta-") || lower.starts_with("x-goog-meta-") {
            destination.append(name.clone(), value.clone());
        }
    }
}

fn header_text<'a>(headers: &'a HeaderMap, name: &HeaderName) -> &'a str {
    headers.get(name).and_then(|value| value.to_str().ok()).unwrap_or("")
}

fn set(headers: &mut HeaderMap, name: HeaderName, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(name, value);
    }
}

/// The headers of an object that a preview reads: ranges, the media type of the key for a generic type, and an
/// inline disposition with the name of the object.
pub fn apply_preview_object_headers(headers: &mut HeaderMap, key: &str) {
    headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    let existing = header_text(headers, &CONTENT_TYPE).trim().to_owned();
    if is_generic_object_content_type(&existing) {
        let inferred = preview_content_type(key);
        if !inferred.is_empty() {
            set(headers, CONTENT_TYPE, inferred);
        }
    }
    let filename = paths::base(key.trim());
    if matches!(filename, "." | "/" | "") {
        headers.insert(CONTENT_DISPOSITION, HeaderValue::from_static("inline"));
        return;
    }
    let value = format_media_type("inline", &[("filename", filename)]);
    if value.is_empty() {
        headers.insert(CONTENT_DISPOSITION, HeaderValue::from_static("inline"));
    } else {
        set(headers, CONTENT_DISPOSITION, &value);
    }
}

/// The headers of `/open/`: the media type of the key for a generic type, `inline` only for a type that a browser
/// shows, the name of the object, and ranges.
pub fn apply_open_original_headers(headers: &mut HeaderMap, key: &str, filename: &str) {
    let mut content_type = header_text(headers, &CONTENT_TYPE).trim().to_owned();
    if is_generic_object_content_type(&content_type) {
        let inferred = preview_content_type(key);
        if !inferred.is_empty() {
            content_type = inferred.to_owned();
            set(headers, CONTENT_TYPE, inferred);
        }
    }
    let disposition = if browser_inline_content(key, &content_type) {
        "inline"
    } else {
        "attachment"
    };
    let value = format_media_type(disposition, &[("filename", filename)]);
    if value.is_empty() {
        set(headers, CONTENT_DISPOSITION, disposition);
    } else {
        set(headers, CONTENT_DISPOSITION, &value);
    }
    headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
}

/// The headers of each answer with object bytes: the objects share the origin of the application, so an object that
/// a browser can run (HTML, SVG) runs in a sandbox without access to the page.
pub fn apply_object_safety_headers(headers: &mut HeaderMap) {
    headers.insert(
        http::header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "sandbox; default-src 'none'; img-src data: blob:; media-src data: blob:; style-src 'unsafe-inline'",
        ),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        http::header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
}

/// A decimal integer with an optional sign.
fn parse_i64(text: &str) -> Option<i64> {
    text.parse::<i64>().ok()
}

fn strip_prefix_ignore_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    let head = value.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then(|| &value[prefix.len()..])
}

/// True for one explicit range `bytes=a-b` of at most `maximum` bytes.
pub fn is_bounded_preview_range(value: &str, maximum: i64) -> bool {
    if maximum <= 0 {
        return false;
    }
    let value = value.trim();
    let Some(spec) = strip_prefix_ignore_case(value, "bytes=") else {
        return false;
    };
    if value.contains(',') {
        return false;
    }
    let Some((start, end)) = spec.trim().split_once('-') else {
        return false;
    };
    let (start, end) = (start.trim(), end.trim());
    if start.is_empty() || end.is_empty() {
        return false;
    }
    let Some(start) = parse_i64(start).filter(|value| *value >= 0) else {
        return false;
    };
    match parse_i64(end) {
        Some(end) => end >= start && end - start < maximum,
        None => false,
    }
}

/// One range of an object: the first and the last byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GatewayRange {
    /// The first byte.
    pub start: i64,
    /// The last byte.
    pub end: i64,
}

/// Read a `Content-Range` of a provider: the range and the total size.
pub fn parse_gateway_content_range(value: &str) -> Option<(GatewayRange, i64)> {
    let value = value.trim();
    let raw = strip_prefix_ignore_case(value, "bytes ")?.trim();
    let (bounds, total) = raw.split_once('/')?;
    if bounds == "*" || total == "*" {
        return None;
    }
    let total = parse_i64(total.trim()).filter(|total| *total >= 0)?;
    let (start, end) = bounds.trim().split_once('-')?;
    let start = parse_i64(start.trim()).filter(|start| *start >= 0)?;
    let end = parse_i64(end.trim())?;
    if end < start || (total > 0 && end >= total) {
        return None;
    }
    Some((GatewayRange { start, end }, total))
}

/// Read the `Range` of a preview for an object of `total` bytes: one range, a suffix range, or an open range.
pub fn parse_gateway_byte_range(value: &str, total: i64) -> Option<GatewayRange> {
    let value = value.trim();
    let raw = strip_prefix_ignore_case(value, "bytes=")?.trim();
    if total < 0 || raw.is_empty() || raw.contains(',') {
        return None;
    }
    let (left, right) = raw.split_once('-')?;
    let (left, right) = (left.trim(), right.trim());
    if left.is_empty() {
        let suffix = parse_i64(right).filter(|suffix| *suffix > 0 && total != 0)?.min(total);
        return Some(GatewayRange {
            start: total - suffix,
            end: total - 1,
        });
    }
    let start = parse_i64(left).filter(|start| *start >= 0 && *start < total)?;
    let mut end = total - 1;
    if !right.is_empty() {
        end = parse_i64(right).filter(|end| *end >= start)?;
        end = end.min(total - 1);
    }
    Some(GatewayRange { start, end })
}

/// A body that stops after a number of bytes.
struct LimitBody {
    inner: Option<Body>,
    remaining: u64,
}

impl http_body::Body for LimitBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>>>> {
        if self.remaining == 0 {
            self.inner = None;
            return Poll::Ready(None);
        }
        let Some(inner) = self.inner.as_mut() else {
            return Poll::Ready(None);
        };
        match Pin::new(inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(mut data) => {
                    if data.len() as u64 > self.remaining {
                        data.truncate(usize::try_from(self.remaining).unwrap_or(usize::MAX));
                    }
                    self.remaining -= data.len() as u64;
                    Poll::Ready(Some(Ok(Frame::data(data))))
                }
                Err(_) => Poll::Ready(None),
            },
            Poll::Ready(None) => {
                self.inner = None;
                Poll::Ready(None)
            }
            other => other,
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

fn gateway_api_error(status: u16, code: &str, message: &str) -> Response {
    gateway_error(&Error::api(status, code, message))
}

/// The answer of a preview that asks for a range: the exact range that the preview asked, or an error. A provider
/// that ignores the range is refused: the server never reads the complete object for it. `None` lets the caller
/// answer with the object as it is.
fn preview_range_response(
    req: &RequestHead,
    key: &str,
    preset: &HeaderMap,
    response: ObjectResponse,
) -> std::result::Result<Response, ObjectResponse> {
    if response.status != 206 && response.status != 200 {
        return Err(response);
    }
    let Some((upstream, total)) = parse_gateway_content_range(header_text(&response.headers, &CONTENT_RANGE)) else {
        return Ok(gateway_api_error(
            502,
            "preview_range_not_supported",
            "the storage provider ignored the byte-range request required for this preview; the server refused to scan or buffer the complete object",
        ));
    };
    let Some(requested) = parse_gateway_byte_range(header_text(&req.headers, &http::header::RANGE), total) else {
        let mut headers = preset.clone();
        copy_object_headers(&mut headers, &response.headers);
        headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
        set(&mut headers, CONTENT_RANGE, &format!("bytes */{total}"));
        headers.remove(CONTENT_LENGTH);
        apply_object_safety_headers(&mut headers);
        return Ok(answer(416, headers, empty()));
    };
    if upstream != requested {
        return Ok(gateway_api_error(
            502,
            "preview_range_mismatch",
            "the storage provider returned a different byte range than the preview requested",
        ));
    }
    let length = requested.end - requested.start + 1;
    let advertised = header_text(&response.headers, &CONTENT_LENGTH).trim().to_owned();
    if !advertised.is_empty() && parse_i64(&advertised) != Some(length) {
        return Ok(gateway_api_error(
            502,
            "preview_range_truncated",
            "the storage provider returned an invalid byte count for the requested preview range",
        ));
    }
    let mut headers = preset.clone();
    copy_object_headers(&mut headers, &response.headers);
    headers.insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    set(
        &mut headers,
        CONTENT_RANGE,
        &format!("bytes {}-{}/{}", requested.start, requested.end, total),
    );
    set(&mut headers, CONTENT_LENGTH, &length.to_string());
    headers.remove(CONTENT_ENCODING);
    apply_preview_object_headers(&mut headers, key);
    apply_object_safety_headers(&mut headers);
    let body = LimitBody {
        inner: Some(response.body),
        remaining: u64::try_from(length).unwrap_or(0),
    };
    Ok(answer(206, headers, body.boxed_unsync()))
}

/// The relative key of the gateway: no `key` parameter gives an empty key (the raw listing), two `key` parameters or
/// an empty key give `400 invalid_key`.
pub fn key_from_gateway_path(req: &RequestHead) -> Result<String> {
    if req.path != "/s3" {
        return Err(Error::api(400, "invalid_path", "invalid object gateway path"));
    }
    let values = req.query.values("key");
    if values.is_empty() {
        return Ok(String::new());
    }
    if values.len() != 1 {
        return Err(Error::api(
            400,
            "invalid_key",
            "exactly one key query parameter is required",
        ));
    }
    let key = clean_relative_key(values[0]);
    if key.is_empty() {
        return Err(Error::api(400, "invalid_key", "object key cannot be empty"));
    }
    Ok(key)
}

/// The tags of an upload need an instance that keeps the tags: a provider without tags would drop them.
fn require_tags(instance: &Instance, tags: &[crate::lifecycle::Tag]) -> Result<()> {
    let available = instance.backend.tagger().is_some() && !instance.tags.off.load(Ordering::SeqCst);
    if !tags.is_empty() && !available {
        return Err(Error::api(
            501,
            "tagging_unsupported",
            "this storage provider does not support object tags",
        ));
    }
    Ok(())
}

/// The size of a request body: `Content-Length`, -1 for a chunked body, 0 for no body.
fn request_body_size(headers: &HeaderMap) -> i64 {
    let length = header_text(headers, &CONTENT_LENGTH).trim();
    if let Ok(size) = length.parse::<i64>() {
        return size;
    }
    if headers.contains_key(http::header::TRANSFER_ENCODING) {
        return -1;
    }
    0
}

async fn read_object(instance: &Instance, req: &RequestHead, full_key: &str, version: &str) -> Result<ObjectResponse> {
    if version.is_empty() {
        instance.get(&req.ctx, full_key, &req.headers).await
    } else {
        instance.get_version(&req.ctx, full_key, version, &req.headers).await
    }
}

async fn head_object(instance: &Instance, req: &RequestHead, full_key: &str, version: &str) -> Result<ObjectResponse> {
    if version.is_empty() {
        instance.head(&req.ctx, full_key).await
    } else {
        instance.head_version(&req.ctx, full_key, version).await
    }
}

#[derive(Serialize)]
struct BoundedRangeRefusal {
    error: &'static str,
    message: &'static str,
}

/// The headers that the security middleware sets before the gateway handler: the provider headers come after them.
fn gateway_preset() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    headers
}

/// The handler of `/s3`.
pub fn handle_object_gateway(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        match object_gateway(&app, req).await {
            Ok(response) => response,
            Err(error) => gateway_error(&error),
        }
    })
}

async fn object_gateway(app: &Arc<App>, req: Req) -> Result<Response> {
    let (req, body) = super::split(req);
    let instance = app.instance_of("", req.query.get("instance"))?.clone();
    let key = key_from_gateway_path(&req)?;
    if key.is_empty() {
        return raw_list(app, &req, &instance).await;
    }
    let full_key = instance.full_key(&key);
    let version = req.query.get("version").trim().to_owned();
    let preview = req.query.get("preview") == "1";
    let range_only = preview && req.query.get("range_only") == "1";
    let method = req.method.clone();
    if method == Method::GET {
        instance.require_permission(PERMISSION_READ)?;
        crate::access::authorize_read(app, &req.ctx, &instance, &key).await?;
        let range = header_text(&req.headers, &http::header::RANGE).to_owned();
        if range_only && !is_bounded_preview_range(&range, MAX_PREVIEW_RANGE) {
            let mut response = json(
                416,
                &BoundedRangeRefusal {
                    error: "bounded_range_required",
                    message: "PDF preview requires one explicit byte range no larger than 16 MiB; the complete object was not downloaded",
                },
            );
            response
                .headers_mut()
                .insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
            return Ok(response);
        }
        let mut response = read_object(&instance, &req, &full_key, &version).await?;
        if preview && !range.trim().is_empty() {
            match preview_range_response(&req, &key, &gateway_preset(), response) {
                Ok(handled) => return Ok(handled),
                Err(unhandled) => response = unhandled,
            }
        }
        let mut headers = gateway_preset();
        copy_object_headers(&mut headers, &response.headers);
        if preview {
            apply_preview_object_headers(&mut headers, &key);
        }
        apply_object_safety_headers(&mut headers);
        return Ok(answer(response.status, headers, response.body));
    }
    if method == Method::HEAD {
        instance.require_permission(PERMISSION_READ)?;
        crate::access::authorize_read(app, &req.ctx, &instance, &key).await?;
        let response = head_object(&instance, &req, &full_key, &version).await?;
        let mut headers = gateway_preset();
        copy_object_headers(&mut headers, &response.headers);
        if preview {
            apply_preview_object_headers(&mut headers, &key);
        }
        apply_object_safety_headers(&mut headers);
        return Ok(answer(response.status, headers, empty()));
    }
    if method == Method::PUT {
        instance.require_permission(PERMISSION_WRITE)?;
        let digest = crate::uploads::parse_checksum_header(&req.headers)?;
        let tags = crate::lifecycle::parse_tagging_header(&req.headers)?;
        require_tags(&instance, &tags)?;
        // The decision comes before the read of the body.
        crate::access::authorize_use(app, &req.ctx, crate::access::ACTION_WRITE, &instance, &key).await?;
        let mut ctx = req.ctx.clone();
        if !tags.is_empty() {
            ctx.upload_tags = Some(Arc::from(tags));
        }
        let transfer = (!digest.is_empty()).then(|| {
            Arc::new(crate::provider::ChecksumTransfer {
                sha256: digest.clone(),
                echoed: Mutex::new(String::new()),
            })
        });
        ctx.checksum = transfer.clone();
        let size = request_body_size(&req.headers);
        let content_type = header_text(&req.headers, &CONTENT_TYPE).to_owned();
        instance.put(&ctx, &full_key, body, size, &content_type).await?;
        let mut headers = HeaderMap::new();
        if let Some(transfer) = transfer {
            let echoed = transfer.echoed.lock().map(|value| value.clone()).unwrap_or_default();
            if echoed == transfer.sha256 {
                // The provider answered with the digest that the client sent: it checked the bytes of the object.
                headers.insert(
                    HeaderName::from_static("x-checksum-sha256-verified"),
                    HeaderValue::from_static("true"),
                );
            }
        }
        return Ok(answer(204, headers, empty()));
    }
    if method == Method::DELETE {
        instance.require_permission(PERMISSION_DELETE)?;
        crate::access::authorize_use(app, &req.ctx, crate::access::ACTION_DELETE, &instance, &key).await?;
        if version.is_empty() {
            instance.delete(&req.ctx, &full_key).await?;
        } else {
            instance.delete_version(&req.ctx, &full_key, &version).await?;
        }
        return Ok(answer(204, HeaderMap::new(), empty()));
    }
    if method == Method::OPTIONS {
        let mut headers = HeaderMap::new();
        headers.insert(ALLOW, HeaderValue::from_static("GET, HEAD, PUT, DELETE, OPTIONS"));
        return Ok(answer(204, headers, empty()));
    }
    Ok(method_not_allowed(&["GET", "HEAD", "PUT", "DELETE", "OPTIONS"]))
}

/// Escape a text for XML: `"'&<>`, tab, line feed and carriage return as references, and a character that XML
/// cannot hold as U+FFFD.
pub fn xml_escape(text: &str, out: &mut String) {
    for character in text.chars() {
        match character {
            '"' => out.push_str("&#34;"),
            '\'' => out.push_str("&#39;"),
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\t' => out.push_str("&#x9;"),
            '\n' => out.push_str("&#xA;"),
            '\r' => out.push_str("&#xD;"),
            other => {
                let code = u32::from(other);
                let valid = code >= 0x20 && code != 0xFFFE && code != 0xFFFF;
                out.push(if valid { other } else { '\u{FFFD}' });
            }
        }
    }
}

fn xml_element(out: &mut String, name: &str, value: &str) {
    out.push('<');
    out.push_str(name);
    out.push('>');
    xml_escape(value, out);
    out.push_str("</");
    out.push_str(name);
    out.push('>');
}

/// The raw listing of the gateway, in the XML form of the S3 `ListObjectsV2` answer.
async fn raw_list(app: &Arc<App>, req: &RequestHead, instance: &Arc<Instance>) -> Result<Response> {
    if req.method != Method::GET && req.method != Method::HEAD {
        return Ok(method_not_allowed(&["GET", "HEAD"]));
    }
    instance.require_permission(PERMISSION_READ)?;
    let prefix = clean_relative_key(req.query.get("prefix"));
    crate::access::authorize_read(app, &req.ctx, instance, &prefix).await?;
    let max_results = parse_bounded_int(req.query.get("max-keys"), 1000, 1, 1000);
    let mut start_after = clean_relative_key(req.query.get("start-after"));
    if !start_after.is_empty() {
        start_after = instance.full_key(&start_after);
    }
    let delimiter = req.query.get("delimiter").to_owned();
    let page = instance
        .list(
            &req.ctx,
            &ListOptions {
                prefix: instance.full_key(&prefix),
                delimiter: delimiter.clone(),
                max_results: u32::try_from(max_results).unwrap_or(1000),
                page_token: req.query.get("continuation-token").to_owned(),
                start_after,
            },
        )
        .await?;
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/xml"));
    if req.method == Method::HEAD {
        return Ok(answer(200, headers, empty()));
    }
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str("<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">");
    xml_element(&mut out, "Name", &instance.cfg.bucket);
    xml_element(&mut out, "Prefix", &prefix);
    if !delimiter.is_empty() {
        xml_element(&mut out, "Delimiter", &delimiter);
    }
    xml_element(&mut out, "MaxKeys", &max_results.to_string());
    xml_element(
        &mut out,
        "IsTruncated",
        if page.next_page_token.is_empty() {
            "false"
        } else {
            "true"
        },
    );
    if !page.next_page_token.is_empty() {
        xml_element(&mut out, "NextContinuationToken", &page.next_page_token);
    }
    for full_prefix in &page.prefixes {
        if let Some(relative) = instance.relative_key(full_prefix) {
            out.push_str("<CommonPrefixes>");
            xml_element(&mut out, "Prefix", &relative);
            out.push_str("</CommonPrefixes>");
        }
    }
    for object in &page.objects {
        if let Some(relative) = instance.relative_key(&object.key) {
            let modified = object.last_modified.map_or_else(
                || crate::common::time::ZERO_TIME_TEXT.to_owned(),
                |time| time.utc().rfc3339(),
            );
            out.push_str("<Contents>");
            xml_element(&mut out, "Key", &relative);
            xml_element(&mut out, "LastModified", &modified);
            xml_element(&mut out, "ETag", &object.etag);
            xml_element(&mut out, "Size", &object.size.to_string());
            out.push_str("</Contents>");
        }
    }
    out.push_str("</ListBucketResult>");
    Ok(answer(200, headers, full(out)))
}

/// The handler of `/open/<name>`: the object of `key`, with its own name.
pub fn handle_open_original(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        if req.method != Method::GET && req.method != Method::HEAD {
            return method_not_allowed(&["GET", "HEAD"]);
        }
        match open_original(&app, req).await {
            Ok(response) => response,
            Err(error) => gateway_error(&error),
        }
    })
}

async fn open_original(app: &Arc<App>, req: Req) -> Result<Response> {
    let req = super::split(req).0;
    let instance = app.instance_of("", req.query.get("instance"))?.clone();
    let key = clean_relative_key(req.query.get("key"));
    instance.require_permission(PERMISSION_READ)?;
    if key.is_empty() {
        return Err(Error::api(400, "invalid_key", "object key cannot be empty"));
    }
    crate::access::authorize_read(app, &req.ctx, &instance, &key).await?;
    let full_key = instance.full_key(&key);
    let version = req.query.get("version").trim().to_owned();
    let mut filename = paths::base(&key).to_owned();
    if matches!(filename.as_str(), "." | "/" | "") {
        filename = "download".to_owned();
    }
    let (status, provider_headers, body) = if req.method == Method::HEAD {
        let response = head_object(&instance, &req, &full_key, &version).await?;
        (response.status, response.headers, empty())
    } else {
        let response = read_object(&instance, &req, &full_key, &version).await?;
        (response.status, response.headers, response.body)
    };
    let mut headers = HeaderMap::new();
    copy_object_headers(&mut headers, &provider_headers);
    apply_open_original_headers(&mut headers, &key, &filename);
    apply_object_safety_headers(&mut headers);
    Ok(answer(status, headers, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bounded_preview_range_is_one_explicit_finite_range() {
        for (input, want) in [
            ("bytes=2-5", true),
            ("bytes=0-16777215", true),
            ("", false),
            ("bytes=1048576-", false),
            ("bytes=0-16777216", false),
            ("bytes=-65536", false),
            ("bytes=0-1,4-5", false),
            ("bytes=nope", false),
        ] {
            assert_eq!(is_bounded_preview_range(input, 16 << 20), want, "{input:?}");
        }
    }

    #[test]
    fn content_ranges_and_preview_ranges() {
        assert_eq!(
            parse_gateway_content_range("bytes 3-6/10"),
            Some((GatewayRange { start: 3, end: 6 }, 10))
        );
        assert_eq!(parse_gateway_content_range("bytes */10"), None);
        assert_eq!(parse_gateway_content_range("bytes 3-10/10"), None);
        assert_eq!(
            parse_gateway_byte_range("bytes=-4", 10),
            Some(GatewayRange { start: 6, end: 9 })
        );
        assert_eq!(
            parse_gateway_byte_range("bytes=8-", 10),
            Some(GatewayRange { start: 8, end: 9 })
        );
        assert_eq!(
            parse_gateway_byte_range("bytes=8-20", 10),
            Some(GatewayRange { start: 8, end: 9 })
        );
        assert_eq!(parse_gateway_byte_range("bytes=10-", 10), None);
        assert_eq!(parse_gateway_byte_range("bytes=0-1,2-3", 10), None);
    }

    #[test]
    fn xml_text_escapes() {
        let mut out = String::new();
        xml_escape("a<b>&\"'\t\n\u{1}", &mut out);
        assert_eq!(out, "a&lt;b&gt;&amp;&#34;&#39;&#x9;&#xA;\u{FFFD}");
    }
}
