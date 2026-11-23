//! The S3 back end: the listing, the reads with ranges and conditions, the writes, the copy, the multipart upload,
//! the versions, the delete and the batch delete, and the permission probe. Each request has the SigV4 signature of
//! the credentials of the `auth` block in mode `access_key`, and no signature in mode `anonymous`.
//!
//! The path style of the URLs is `<endpoint>/<bucket>/<key>`. The answers are read with a limit: 32 MiB for a
//! listing, 8 MiB for a list of parts and a batch delete, 256 KiB for an error, 1 MiB for the other answers.

pub mod copy;
pub mod sigv4;

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use bytes::Bytes;
use http::header::{
    ACCEPT_ENCODING, CONTENT_TYPE, ETAG, HeaderName, HeaderValue, IF_MATCH, IF_MODIFIED_SINCE, IF_NONE_MATCH, IF_RANGE,
    IF_UNMODIFIED_SINCE, RANGE,
};
use http::{HeaderMap, Method, Response};
use serde::{Deserialize, Serialize};

use super::client::{Answer, build_request, header_text, parse_answer, status_text, with_context};
use super::xml::{self, Node, at};
use super::{SharedAuth, wrong_provider};
use crate::common::BoxFuture;
use crate::common::config::{BucketConfig, PERMISSION_DELETE, PERMISSION_READ, PERMISSION_WRITE, Provider};
use crate::common::ctx::OpCtx;
use crate::common::error::{BatchDeleteError, BatchDeleteFailure, Error, Result};
use crate::common::http::{Body, empty, read_limited};
use crate::common::storage::{
    Backend, BatchDeleter, CapabilityState, CapabilityStateName, CompletedPart, ConditionalWriter,
    DiscoveredCapabilities, ListOptions, ListPage, MultipartCopier, MultipartCopyOptions, MultipartPart,
    MultipartPartLister, MultipartUploadApi, ObjectInfo, ObjectResponse, ObjectVersionPage, StoredObjectVersion,
    VersionStore,
};
use crate::common::time::Timestamp;

/// The most keys of one `DeleteObjects` request.
pub const MAX_DELETE_BATCH: usize = 1000;

/// The limit of a listing answer.
const LIST_LIMIT: usize = 32 << 20;
/// The limit of a list of parts and of a batch delete answer.
const LARGE_LIMIT: usize = 8 << 20;
/// The limit of the other answers.
const SMALL_LIMIT: usize = 1 << 20;
/// The limit of an error answer.
const ERROR_LIMIT: usize = 256 << 10;

/// The headers of a read that the back end sends again to the provider.
pub(crate) const READ_HEADERS: [HeaderName; 6] = [
    RANGE,
    IF_MATCH,
    IF_NONE_MATCH,
    IF_MODIFIED_SINCE,
    IF_UNMODIFIED_SINCE,
    IF_RANGE,
];

/// One S3 request: the method, the key (empty for the bucket), the query pairs, the headers and the body.
pub struct S3Request<'a> {
    /// The method.
    pub method: Method,
    /// The full key, or an empty text for a request on the bucket.
    pub key: &'a str,
    /// The query pairs (for example `("lifecycle", "")`).
    pub query: Vec<(String, String)>,
    /// The headers.
    pub headers: HeaderMap,
    /// The body and its size, or `None`.
    pub body: Option<(Body, i64)>,
}

/// An answer of S3 with its body read to its end (at most the limit of the call).
pub type S3Answer = Answer;

/// The S3 back end of one bucket.
pub struct S3Backend {
    /// The configuration of the bucket.
    pub cfg: BucketConfig,
    /// The shared state of the auth block.
    pub auth: Arc<SharedAuth>,
}

impl std::fmt::Debug for S3Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("S3Backend")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

/// True for a status from 200 to 299.
fn success(status: u16) -> bool {
    (200..300).contains(&status)
}

/// Set a header. A value that a header cannot carry stops the request, as a transport error.
pub(crate) fn set_header(headers: &mut HeaderMap, name: &str, value: &str) -> Result<()> {
    let name = HeaderName::from_bytes(name.as_bytes())
        .map_err(|_| Error::Connect(format!("the header name {name:?} is not valid")))?;
    let value = HeaderValue::from_bytes(value.as_bytes())
        .map_err(|_| Error::Connect(format!("the value of the header {:?} is not valid", name.as_str())))?;
    headers.insert(name, value);
    Ok(())
}

/// Read at most `limit` bytes of a body. A read error ends the bytes without an error.
pub(crate) async fn read_some(body: Body, limit: usize) -> Bytes {
    use http_body_util::BodyExt as _;
    let mut body = body;
    let mut out = Vec::new();
    while out.len() < limit {
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Ok(data) = frame.into_data() {
                    let room = limit - out.len();
                    out.extend_from_slice(&data[..data.len().min(room)]);
                }
            }
            _ => break,
        }
    }
    Bytes::from(out)
}

/// Remove the `"` characters at the start and at the end of a text.
pub(crate) fn trim_quotes(text: &str) -> &str {
    text.trim_matches('"')
}

/// The time of a listing: RFC 3339, with or without a fraction. A text in another form gives no time.
fn parse_time(text: &str) -> Option<Timestamp> {
    Timestamp::parse_rfc3339(text)
}

/// The provider error of an answer: the `Code` and the `Message` of the XML body. Without a message, the message is
/// the body, else the status line.
fn error_of(status: u16, body: &[u8]) -> Error {
    let mut code = String::new();
    let mut message = String::new();
    let _ = xml::walk(body, |node| {
        if let Node::End(path, text) = node {
            if at(path, &["Code"]) {
                code = text;
            } else if at(path, &["Message"]) {
                message = text;
            }
        }
    });
    let mut message = message.trim().to_owned();
    if message.is_empty() {
        message = String::from_utf8_lossy(body).trim().to_owned();
    }
    if message.is_empty() {
        message = status_text(status);
    }
    Error::upstream(status, code, message)
}

/// The provider error of an answer that is not a success: the first 256 KiB of its body are read.
pub(crate) async fn response_error(response: Response<Body>) -> Error {
    let status = response.status().as_u16();
    let body = read_some(response.into_body(), ERROR_LIMIT).await;
    error_of(status, &body)
}

/// The error of an S3 document with the root `Error` in an answer with a success status: `502` with its code and
/// message.
fn embedded_error(body: &[u8]) -> Option<Error> {
    if body.is_empty() {
        return None;
    }
    match xml::error_document(body) {
        Some((root, code, message)) if root == "Error" => Some(Error::upstream(502, code, message)),
        _ => None,
    }
}

/// True for an explicit refusal of the credentials by the provider (HTTP 401 or 403).
pub fn is_authorization_denial(error: &Error) -> bool {
    error
        .as_upstream()
        .is_some_and(|upstream| upstream.status == 401 || upstream.status == 403)
}

/// True when the provider does not have a function: `501`, `405`, `NotImplemented` or `MethodNotAllowed`.
pub fn provider_refused_feature(error: &Error) -> bool {
    error.as_upstream().is_some_and(|upstream| {
        upstream.status == 501
            || upstream.status == 405
            || upstream.code == "NotImplemented"
            || upstream.code == "MethodNotAllowed"
    })
}

/// A permission state that the probe found, in the form that the instance keeps: a test that did not prove the
/// state gives `unknown`, which stays available.
pub(crate) fn probed_state(allowed: bool, verified: bool, source: &str, reason: &str) -> CapabilityState {
    let state = match (verified, allowed) {
        (true, true) => CapabilityStateName::Allowed,
        (true, false) => CapabilityStateName::Denied,
        _ => CapabilityStateName::Unknown,
    };
    CapabilityState {
        state,
        allowed: state != CapabilityStateName::Denied,
        verified: state != CapabilityStateName::Unknown,
        source: source.to_owned(),
        reason: reason.to_owned(),
        expires: None,
    }
}

/// Sort versions: the current version first, then the newest, then the larger version id.
pub(crate) fn sort_versions(versions: &mut [StoredObjectVersion]) {
    versions.sort_by(|left, right| {
        right
            .is_current
            .cmp(&left.is_current)
            .then_with(|| right.last_modified.cmp(&left.last_modified))
            .then_with(|| right.version.cmp(&left.version))
    });
}

/// The page token of the versions of one key: the key marker and the version marker of the provider.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct VersionCursor {
    #[serde(rename = "keyMarker", default, skip_serializing_if = "String::is_empty")]
    key_marker: String,
    #[serde(rename = "versionIdMarker", default, skip_serializing_if = "String::is_empty")]
    version_id_marker: String,
}

impl VersionCursor {
    fn encode(&self) -> String {
        let json = crate::common::json::to_vec(self).unwrap_or_default();
        URL_SAFE_NO_PAD.encode(json)
    }

    fn decode(token: &str) -> Option<Self> {
        if token.trim().is_empty() {
            return Some(Self::default());
        }
        let data = URL_SAFE_NO_PAD.decode(token).ok()?;
        serde_json::from_slice(&data).ok()
    }
}

/// One value of a header of a request of the caller: the first value when it is not empty.
pub(crate) fn first_value(headers: &HeaderMap, name: &HeaderName) -> Option<HeaderValue> {
    headers.get(name).filter(|value| !value.as_bytes().is_empty()).cloned()
}

/// The query of a request on one version: `versionId`, also when it is empty.
fn version_query(version: Option<&str>) -> Vec<(String, String)> {
    version.map_or_else(Vec::new, |version| vec![("versionId".to_owned(), version.to_owned())])
}

/// True when a ceiling `max_object_size` of `object.read` applies to the context.
pub(crate) fn read_ceiling_applies(ctx: &OpCtx) -> bool {
    ctx.ceilings.as_ref().is_some_and(|ceilings| {
        ceilings
            .get(
                crate::instance::ceiling::ACTION_READ,
                crate::instance::ceiling::MAX_OBJECT_SIZE,
            )
            .is_some()
    })
}

impl S3Backend {
    /// The back end of a bucket. The `auth` block must be an S3 block with complete credentials in mode
    /// `access_key`.
    pub fn new(cfg: BucketConfig, auth: Arc<SharedAuth>) -> Result<Self> {
        if auth.cfg.provider != Provider::S3 {
            return Err(wrong_provider(&cfg, "an S3"));
        }
        if auth.cfg.mode == "access_key" && (auth.cfg.access_key_id.is_empty() || auth.cfg.secret_access_key.is_empty())
        {
            return Err(Error::internal("S3 credentials are incomplete"));
        }
        Ok(Self { cfg, auth })
    }

    /// Sign and send one request; read at most `limit` bytes of the answer. A status of 300 or more is not an
    /// error here: the caller reads it (`s3_error` gives the provider error).
    pub async fn send(&self, ctx: &OpCtx, request: S3Request<'_>, limit: usize) -> Result<S3Answer> {
        let response = self
            .execute(
                ctx,
                request.method,
                request.key,
                &request.query,
                request.headers,
                request.body,
            )
            .await?;
        Answer::read(response, limit).await
    }

    /// Sign and send one request and give the answer with its body as a stream.
    pub async fn send_streaming(&self, ctx: &OpCtx, request: S3Request<'_>) -> Result<Response<Body>> {
        self.execute(
            ctx,
            request.method,
            request.key,
            &request.query,
            request.headers,
            request.body,
        )
        .await
    }

    /// The provider error of an answer: the `Code` and the `Message` of the XML body. Without a message, the message
    /// is the body, else the status line.
    pub fn s3_error(answer: &S3Answer) -> Error {
        let body = &answer.body[..answer.body.len().min(ERROR_LIMIT)];
        error_of(answer.status, body)
    }

    /// The URL of a key (or of the bucket for an empty key) with a query in its canonical form.
    pub fn object_url<N: AsRef<str>, V: AsRef<str>>(&self, key: &str, query: &[(N, V)]) -> String {
        let mut path = format!("/{}", sigv4::aws_uri_encode(&self.cfg.bucket, true));
        if !key.is_empty() {
            path.push('/');
            path.push_str(&sigv4::aws_uri_encode(key, false));
        }
        self.auth.endpoint().join(&path, &sigv4::canonical_query(query))
    }

    /// The value of `x-amz-copy-source` for a key of the bucket, and for one version when `version` is not empty.
    pub fn copy_source_header(&self, key: &str, version: &str) -> String {
        let mut value = format!(
            "/{}/{}",
            sigv4::aws_uri_encode(&self.cfg.bucket, true),
            sigv4::aws_uri_encode(key, false)
        );
        if !version.is_empty() {
            value.push_str("?versionId=");
            value.push_str(&crate::common::query::query_escape(version));
        }
        value
    }

    async fn execute(
        &self,
        ctx: &OpCtx,
        method: Method,
        key: &str,
        query: &[(String, String)],
        headers: HeaderMap,
        body: Option<(Body, i64)>,
    ) -> Result<Response<Body>> {
        let url = self.object_url(key, query);
        let has_body = body.is_some();
        let mut request =
            build_request(method, &url, headers, body).map_err(|error| with_context("create s3 request", error))?;
        if self.auth.cfg.mode == "access_key" {
            let method = request.method().clone();
            let uri = request.uri().clone();
            sigv4::sign(
                &method,
                &uri,
                request.headers_mut(),
                has_body,
                &self.auth.s3_credentials(),
                &self.auth.cfg.region,
                Timestamp::now(),
            )?;
        }
        self.auth
            .client
            .send(ctx, request)
            .await
            .map_err(|error| with_context("s3 request failed", error))
    }

    /// Send a request without a body; an answer that is not a success gives the provider error.
    async fn execute_ok(
        &self,
        ctx: &OpCtx,
        method: Method,
        key: &str,
        query: &[(String, String)],
        headers: HeaderMap,
    ) -> Result<Response<Body>> {
        let response = self.execute(ctx, method, key, query, headers, None).await?;
        if !success(response.status().as_u16()) {
            return Err(response_error(response).await);
        }
        Ok(response)
    }

    /// Read the body of an answer, or give the error with its context.
    async fn read_body(response: Response<Body>, limit: usize, what: &str) -> Result<Bytes> {
        read_limited(response.into_body(), limit)
            .await
            .map(|(body, _)| body)
            .map_err(|error| with_context(what, error))
    }

    fn put_checksum(ctx: &OpCtx, headers: &mut HeaderMap) -> Result<()> {
        if let Some(transfer) = &ctx.checksum
            && !transfer.sha256.is_empty()
        {
            set_header(headers, "x-amz-checksum-sha256", &transfer.sha256)?;
        }
        Ok(())
    }

    fn keep_echoed_checksum(ctx: &OpCtx, headers: &HeaderMap) {
        if let Some(transfer) = &ctx.checksum
            && let Ok(mut echoed) = transfer.echoed.lock()
        {
            *echoed = headers
                .get("x-amz-checksum-sha256")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .trim()
                .to_owned();
        }
    }

    fn put_upload_tags(ctx: &OpCtx, headers: &mut HeaderMap) -> Result<()> {
        if let Some(encoded) = crate::lifecycle::upload_tagging_header(ctx) {
            set_header(headers, "x-amz-tagging", &encoded)?;
        }
        Ok(())
    }

    async fn list_page(&self, ctx: &OpCtx, options: &ListOptions) -> Result<ListPage> {
        let mut query = vec![("list-type".to_owned(), "2".to_owned())];
        if !options.prefix.is_empty() {
            query.push(("prefix".to_owned(), options.prefix.clone()));
        }
        if !options.delimiter.is_empty() {
            query.push(("delimiter".to_owned(), options.delimiter.clone()));
        }
        if options.max_results > 0 {
            query.push(("max-keys".to_owned(), options.max_results.to_string()));
        }
        if !options.page_token.is_empty() {
            query.push(("continuation-token".to_owned(), options.page_token.clone()));
        }
        if !options.start_after.is_empty() {
            query.push(("start-after".to_owned(), options.start_after.clone()));
        }
        let response = self.execute_ok(ctx, Method::GET, "", &query, HeaderMap::new()).await?;
        let body = Self::read_body(response, LIST_LIMIT, "decode s3 list response").await?;
        parse_answer(body, parse_list_page)
            .await?
            .map_err(|error| Error::internal(format!("decode s3 list response: {error}")))
    }

    /// The headers of an object, or of one version (`Some`, also an empty one).
    async fn head_object(&self, ctx: &OpCtx, key: &str, version: Option<&str>) -> Result<ObjectResponse> {
        let query = version_query(version);
        let mut headers = HeaderMap::new();
        headers.insert("x-amz-checksum-mode", HeaderValue::from_static("ENABLED"));
        let mut response = self.execute(ctx, Method::HEAD, key, &query, headers, None).await?;
        // A number of S3-compatible providers do not know the checksum mode. The second request has no such header,
        // so the basic facts of the object stay available.
        if matches!(response.status().as_u16(), 400 | 403 | 501) {
            drop(response);
            response = self
                .execute(ctx, Method::HEAD, key, &query, HeaderMap::new(), None)
                .await?;
        }
        if !success(response.status().as_u16()) {
            return Err(response_error(response).await);
        }
        Ok(ObjectResponse {
            status: response.status().as_u16(),
            headers: response.headers().clone(),
            body: empty(),
        })
    }

    async fn get_object(
        &self,
        ctx: &OpCtx,
        key: &str,
        version: Option<&str>,
        request: &HeaderMap,
    ) -> Result<ObjectResponse> {
        let query = version_query(version);
        let mut headers = HeaderMap::new();
        for name in &READ_HEADERS {
            if let Some(value) = first_value(request, name) {
                headers.insert(name.clone(), value);
            }
        }
        // With a ceiling of object.read, the answer must tell the real size of the object: no decode of gzip.
        if headers.contains_key(RANGE) || read_ceiling_applies(ctx) {
            headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
        }
        let response = self.execute(ctx, Method::GET, key, &query, headers, None).await?;
        let status = response.status().as_u16();
        if !(success(status) || status == 304) {
            return Err(response_error(response).await);
        }
        let (parts, body) = response.into_parts();
        Ok(ObjectResponse {
            status,
            headers: parts.headers,
            body,
        })
    }

    async fn list_object_versions(
        &self,
        ctx: &OpCtx,
        key: &str,
        page_token: &str,
        maximum: u32,
    ) -> Result<ObjectVersionPage> {
        let Some(cursor) = VersionCursor::decode(page_token) else {
            return Err(Error::api(400, "invalid_page_token", "version page token is invalid"));
        };
        let maximum = if maximum == 0 || maximum > 1000 { 1000 } else { maximum };
        let mut query = vec![
            ("versions".to_owned(), String::new()),
            ("prefix".to_owned(), key.to_owned()),
            ("max-keys".to_owned(), maximum.to_string()),
        ];
        if !cursor.key_marker.is_empty() {
            query.push(("key-marker".to_owned(), cursor.key_marker.clone()));
        }
        if !cursor.version_id_marker.is_empty() {
            query.push(("version-id-marker".to_owned(), cursor.version_id_marker.clone()));
        }
        let response = self.execute_ok(ctx, Method::GET, "", &query, HeaderMap::new()).await?;
        let body = Self::read_body(response, LIST_LIMIT, "decode s3 version response").await?;
        let VersionListing {
            truncated,
            next_key,
            next_version,
            versions,
            markers,
        } = parse_answer(body, parse_version_listing)
            .await?
            .map_err(|error| Error::internal(format!("decode s3 version response: {error}")))?;
        let mut page = ObjectVersionPage {
            versions: versions
                .into_iter()
                .chain(markers)
                .filter(|(item_key, _)| item_key == key)
                .map(|(_, item)| item)
                .collect(),
            next_page_token: String::new(),
        };
        sort_versions(&mut page.versions);
        // A prefix listing can continue with another key. The cursor exists only while the provider still pages the
        // versions of the exact key.
        if truncated && next_key == key && !next_version.is_empty() {
            page.next_page_token = VersionCursor {
                key_marker: next_key,
                version_id_marker: next_version,
            }
            .encode();
        }
        Ok(page)
    }

    async fn put_object(
        &self,
        ctx: &OpCtx,
        key: &str,
        body: Body,
        size: i64,
        content_type: &str,
        if_absent: bool,
    ) -> Result<()> {
        let mut headers = HeaderMap::new();
        if !content_type.is_empty() {
            set_header(&mut headers, CONTENT_TYPE.as_str(), content_type)?;
        }
        if if_absent {
            headers.insert(IF_NONE_MATCH, HeaderValue::from_static("*"));
        }
        Self::put_checksum(ctx, &mut headers)?;
        Self::put_upload_tags(ctx, &mut headers)?;
        crate::bucket::write_encryption_headers(&self.cfg, &mut headers);
        let response = self
            .execute(ctx, Method::PUT, key, &[], headers, Some((body, size)))
            .await?;
        Self::keep_echoed_checksum(ctx, response.headers());
        let status = response.status().as_u16();
        if if_absent && (status == 409 || status == 412) {
            let _ = read_some(response.into_body(), SMALL_LIMIT).await;
            return Err(Error::api(
                409,
                "object_exists",
                "an object already exists at the extraction destination",
            ));
        }
        if !success(status) {
            return Err(response_error(response).await);
        }
        let _ = read_some(response.into_body(), SMALL_LIMIT).await;
        Ok(())
    }

    /// Start a multipart upload with the headers of the new object; gives the upload id. The encryption of the
    /// configuration of the bucket applies to the new object.
    pub async fn initiate_multipart_with(&self, ctx: &OpCtx, key: &str, headers: HeaderMap) -> Result<String> {
        let mut headers = headers;
        crate::bucket::write_encryption_headers(&self.cfg, &mut headers);
        let query = [("uploads".to_owned(), String::new())];
        let response = self.execute_ok(ctx, Method::POST, key, &query, headers).await?;
        let body = Self::read_body(response, SMALL_LIMIT, "decode s3 multipart initiation response").await?;
        let mut upload_id = String::new();
        xml::walk(&body, |node| {
            if let Node::End(path, text) = node
                && at(path, &["UploadId"])
            {
                upload_id = text;
            }
        })
        .map_err(|error| Error::internal(format!("decode s3 multipart initiation response: {error}")))?;
        if upload_id.trim().is_empty() {
            return Err(Error::internal("s3 multipart initiation did not return an upload id"));
        }
        Ok(upload_id)
    }

    async fn initiate_multipart(&self, ctx: &OpCtx, key: &str, content_type: &str) -> Result<String> {
        let mut headers = HeaderMap::new();
        if !content_type.is_empty() {
            set_header(&mut headers, CONTENT_TYPE.as_str(), content_type)?;
        }
        if ctx.checksum.is_some() {
            headers.insert("x-amz-checksum-algorithm", HeaderValue::from_static("SHA256"));
        }
        Self::put_upload_tags(ctx, &mut headers)?;
        self.initiate_multipart_with(ctx, key, headers).await
    }

    async fn upload_part(
        &self,
        ctx: &OpCtx,
        key: &str,
        upload_id: &str,
        number: u32,
        body: Body,
        size: i64,
    ) -> Result<String> {
        let query = [
            ("partNumber".to_owned(), number.to_string()),
            ("uploadId".to_owned(), upload_id.to_owned()),
        ];
        let mut headers = HeaderMap::new();
        Self::put_checksum(ctx, &mut headers)?;
        let response = self
            .execute(ctx, Method::PUT, key, &query, headers, Some((body, size)))
            .await?;
        Self::keep_echoed_checksum(ctx, response.headers());
        if !success(response.status().as_u16()) {
            return Err(response_error(response).await);
        }
        let etag = header_text(response.headers(), &ETAG).trim().to_owned();
        let _ = read_some(response.into_body(), SMALL_LIMIT).await;
        if etag.is_empty() {
            return Err(Error::internal("s3 multipart upload part did not return an ETag"));
        }
        Ok(trim_quotes(&etag).to_owned())
    }

    /// Complete a multipart upload with its parts.
    pub async fn complete_multipart(
        &self,
        ctx: &OpCtx,
        key: &str,
        upload_id: &str,
        parts: &[CompletedPart],
    ) -> Result<()> {
        if parts.is_empty() {
            return Err(Error::internal("cannot complete an s3 multipart upload without parts"));
        }
        let mut document = String::from("<CompleteMultipartUpload>");
        for part in parts {
            document.push_str("<Part>");
            document.push_str(&xml::element("PartNumber", &part.number.to_string()));
            document.push_str(&xml::element("ETag", &format!("\"{}\"", trim_quotes(&part.etag))));
            if !part.checksum_sha256.is_empty() {
                document.push_str(&xml::element("ChecksumSHA256", &part.checksum_sha256));
            }
            document.push_str("</Part>");
        }
        document.push_str("</CompleteMultipartUpload>");
        let query = [("uploadId".to_owned(), upload_id.to_owned())];
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/xml"));
        let size = document.len() as i64;
        let response = self
            .execute(
                ctx,
                Method::POST,
                key,
                &query,
                headers,
                Some((crate::common::http::full(document), size)),
            )
            .await?;
        if !success(response.status().as_u16()) {
            return Err(response_error(response).await);
        }
        let body = Self::read_body(response, SMALL_LIMIT, "read s3 multipart completion response").await?;
        // Some S3 implementations answer 200 with an Error document.
        match embedded_error(&body) {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Abort a multipart upload. An upload that does not exist (404) is not an error.
    pub async fn abort_multipart(&self, ctx: &OpCtx, key: &str, upload_id: &str) -> Result<()> {
        let query = [("uploadId".to_owned(), upload_id.to_owned())];
        let response = self
            .execute(ctx, Method::DELETE, key, &query, HeaderMap::new(), None)
            .await?;
        let status = response.status().as_u16();
        if status == 404 {
            return Ok(());
        }
        if !success(status) {
            return Err(response_error(response).await);
        }
        let _ = read_some(response.into_body(), SMALL_LIMIT).await;
        Ok(())
    }

    async fn list_multipart_parts(&self, ctx: &OpCtx, key: &str, upload_id: &str) -> Result<Vec<MultipartPart>> {
        if upload_id.trim().is_empty() {
            return Err(Error::internal("multipart upload id is required"));
        }
        let mut parts = Vec::new();
        let mut marker: i64 = 0;
        loop {
            let mut query = vec![
                ("uploadId".to_owned(), upload_id.to_owned()),
                ("max-parts".to_owned(), "1000".to_owned()),
            ];
            if marker > 0 {
                query.push(("part-number-marker".to_owned(), marker.to_string()));
            }
            let response = self.execute_ok(ctx, Method::GET, key, &query, HeaderMap::new()).await?;
            let body = Self::read_body(response, LARGE_LIMIT, "decode s3 multipart parts response").await?;
            let (page, truncated, next_marker) = parse_answer(body, parse_parts_page)
                .await?
                .map_err(|error| Error::internal(format!("decode s3 multipart parts response: {error}")))?;
            parts.extend(page);
            if !truncated {
                break;
            }
            if next_marker <= marker {
                return Err(Error::internal(
                    "s3 multipart parts response did not advance its marker",
                ));
            }
            marker = next_marker;
        }
        parts.sort_by_key(|part| part.number);
        Ok(parts)
    }

    async fn delete_object(&self, ctx: &OpCtx, key: &str, version: Option<&str>) -> Result<()> {
        let query = version_query(version);
        let response = self
            .execute_ok(ctx, Method::DELETE, key, &query, HeaderMap::new())
            .await?;
        let _ = read_some(response.into_body(), SMALL_LIMIT).await;
        Ok(())
    }

    /// Delete at most [`MAX_DELETE_BATCH`] keys with one `DeleteObjects` request. A key that the provider refuses
    /// makes the call fail with [`Error::BatchDelete`].
    async fn delete_keys(&self, ctx: &OpCtx, keys: &[String]) -> Result<()> {
        if keys.is_empty() {
            return Ok(());
        }
        if keys.len() > MAX_DELETE_BATCH {
            return Err(Error::internal(format!(
                "a batch delete takes at most {MAX_DELETE_BATCH} keys, got {}",
                keys.len()
            )));
        }
        let mut document = String::from("<Delete><Quiet>true</Quiet>");
        for key in keys {
            document.push_str("<Object>");
            document.push_str(&xml::element("Key", key));
            document.push_str("</Object>");
        }
        document.push_str("</Delete>");
        let digest = crate::common::md5::md5(document.as_bytes());
        let query = [("delete".to_owned(), String::new())];
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/xml"));
        set_header(&mut headers, "content-md5", &STANDARD.encode(digest))?;
        let size = document.len() as i64;
        let response = self
            .execute(
                ctx,
                Method::POST,
                "",
                &query,
                headers,
                Some((crate::common::http::full(document), size)),
            )
            .await?;
        if !success(response.status().as_u16()) {
            return Err(response_error(response).await);
        }
        let body = Self::read_body(response, LARGE_LIMIT, "read s3 batch delete response").await?;
        if body.is_empty() {
            return Ok(());
        }
        let Some((root, code, message, failures)) = parse_answer(body, parse_delete_result).await? else {
            return Ok(());
        };
        // Some S3 implementations answer 200 with an Error document, or with one Error for each refused key.
        if root == "Error" {
            return Err(Error::upstream(502, code, message));
        }
        if !failures.is_empty() {
            return Err(Error::BatchDelete(Box::new(BatchDeleteError {
                total: keys.len(),
                failures,
            })));
        }
        Ok(())
    }

    async fn restore_object_version(&self, ctx: &OpCtx, key: &str, version: &str, extra: &HeaderMap) -> Result<()> {
        let mut headers = extra.clone();
        set_header(
            &mut headers,
            "x-amz-copy-source",
            &self.copy_source_header(key, version),
        )?;
        crate::bucket::write_encryption_headers(&self.cfg, &mut headers);
        let response = self.execute_ok(ctx, Method::PUT, key, &[], headers).await?;
        let body = Self::read_body(response, SMALL_LIMIT, "read s3 restore response").await?;
        match embedded_error(&body) {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    async fn copy_object(&self, ctx: &OpCtx, source: &str, destination: &str) -> Result<()> {
        let mut headers = HeaderMap::new();
        set_header(&mut headers, "x-amz-copy-source", &self.copy_source_header(source, ""))?;
        crate::bucket::write_encryption_headers(&self.cfg, &mut headers);
        let response = self.execute_ok(ctx, Method::PUT, destination, &[], headers).await?;
        let body = Self::read_body(response, SMALL_LIMIT, "read s3 copy response").await?;
        match embedded_error(&body) {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    async fn discover(&self, ctx: &OpCtx) -> Result<DiscoveredCapabilities> {
        let mut found = DiscoveredCapabilities::default();
        found.states.insert(
            PERMISSION_WRITE.to_owned(),
            probed_state(
                false,
                false,
                "s3",
                "S3 does not provide a portable, non-destructive IAM test for PutObject",
            ),
        );
        found.states.insert(
            PERMISSION_DELETE.to_owned(),
            probed_state(
                false,
                false,
                "s3",
                "S3 does not provide a portable, non-destructive IAM test for DeleteObject",
            ),
        );
        let options = ListOptions {
            prefix: self.cfg.root_prefix.clone(),
            max_results: 1,
            ..ListOptions::default()
        };
        let page = match self.list_page(ctx, &options).await {
            Ok(page) => page,
            // Only an explicit refusal of the credentials is a verified denial. A canceled probe, a time limit or a
            // 5xx tells nothing about the credentials: the error goes back and the permission stays available.
            Err(error) if is_authorization_denial(&error) => {
                found.states.insert(
                    PERMISSION_READ.to_owned(),
                    probed_state(
                        false,
                        true,
                        "s3-list-probe",
                        &format!("ListObjectsV2 failed: {}", error.public_message()),
                    ),
                );
                return Ok(found);
            }
            Err(error) => return Err(error),
        };
        found.permissions.push("s3:ListBucket".to_owned());
        let Some(first) = page.objects.first() else {
            found.states.insert(
                PERMISSION_READ.to_owned(),
                probed_state(
                    true,
                    false,
                    "s3-list-probe",
                    "ListObjectsV2 succeeded; GetObject cannot be verified because the prefix is empty",
                ),
            );
            return Ok(found);
        };
        match self.head_object(ctx, &first.key, None).await {
            Ok(_) => {}
            Err(error) if is_authorization_denial(&error) => {
                found.states.insert(
                    PERMISSION_READ.to_owned(),
                    probed_state(
                        false,
                        true,
                        "s3-read-probe",
                        &format!(
                            "ListObjectsV2 succeeded but HeadObject failed: {}",
                            error.public_message()
                        ),
                    ),
                );
                return Ok(found);
            }
            Err(error) => return Err(error),
        }
        found.permissions.push("s3:GetObject".to_owned());
        found.states.insert(
            PERMISSION_READ.to_owned(),
            probed_state(true, true, "s3-read-probe", "ListObjectsV2 and HeadObject succeeded"),
        );
        Ok(found)
    }
}

impl Backend for S3Backend {
    fn list<'a>(&'a self, ctx: &'a OpCtx, options: &'a ListOptions) -> BoxFuture<'a, Result<ListPage>> {
        Box::pin(self.list_page(ctx, options))
    }
    fn head<'a>(&'a self, ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<ObjectResponse>> {
        Box::pin(self.head_object(ctx, key, None))
    }
    fn get<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        Box::pin(self.get_object(ctx, key, None, headers))
    }
    fn put<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        body: Body,
        size: i64,
        content_type: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.put_object(ctx, key, body, size, content_type, false))
    }
    fn delete<'a>(&'a self, ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.delete_object(ctx, key, None))
    }
    fn copy<'a>(&'a self, ctx: &'a OpCtx, source: &'a str, destination: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.copy_object(ctx, source, destination))
    }
    fn discover_capabilities<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<DiscoveredCapabilities>> {
        Box::pin(self.discover(ctx))
    }
    fn conditional_writer(&self) -> Option<&dyn ConditionalWriter> {
        Some(self)
    }
    fn batch_deleter(&self) -> Option<&dyn BatchDeleter> {
        Some(self)
    }
    fn multipart_copier(&self) -> Option<&dyn MultipartCopier> {
        Some(self)
    }
    fn version_store(&self) -> Option<&dyn VersionStore> {
        Some(self)
    }
    fn multipart_upload(&self) -> Option<&dyn MultipartUploadApi> {
        Some(self)
    }
    fn part_lister(&self) -> Option<&dyn MultipartPartLister> {
        Some(self)
    }
    fn multipart_lister(&self) -> Option<&dyn crate::uploads::MultipartUploadLister> {
        Some(self)
    }
    fn tagger(&self) -> Option<&dyn crate::lifecycle::ObjectTagger> {
        Some(self)
    }
    fn bucket_rules(&self) -> Option<&dyn crate::lifecycle::BucketRules> {
        Some(self)
    }
    fn object_lock(&self) -> Option<&dyn crate::bucket::ObjectLockManager> {
        Some(self)
    }
    fn encryption_reader(&self) -> Option<&dyn crate::bucket::EncryptionReader> {
        Some(self)
    }
    fn metadata_editor(&self) -> Option<&dyn crate::bucket::MetadataEditor> {
        Some(self)
    }
}

impl ConditionalWriter for S3Backend {
    /// Write with `If-None-Match: *`. A provider answer `409` or `412` gives `409 object_exists`.
    fn put_if_absent<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        body: Body,
        size: i64,
        content_type: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.put_object(ctx, key, body, size, content_type, true))
    }
}

impl BatchDeleter for S3Backend {
    fn delete_many<'a>(&'a self, ctx: &'a OpCtx, keys: &'a [String]) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.delete_keys(ctx, keys))
    }
}

impl MultipartCopier for S3Backend {
    fn copy_multipart<'a>(
        &'a self,
        ctx: &'a OpCtx,
        source: &'a str,
        destination: &'a str,
        options: MultipartCopyOptions,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.copy_in_parts(ctx, source, destination, options, copy::multipart_copy_part_size()))
    }
}

impl VersionStore for S3Backend {
    fn list_versions<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        page_token: &'a str,
        maximum: u32,
    ) -> BoxFuture<'a, Result<ObjectVersionPage>> {
        Box::pin(self.list_object_versions(ctx, key, page_token, maximum))
    }
    fn head_version<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        version: &'a str,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        Box::pin(self.head_object(ctx, key, Some(version)))
    }
    fn get_version<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        version: &'a str,
        headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        Box::pin(self.get_object(ctx, key, Some(version), headers))
    }
    fn delete_version<'a>(&'a self, ctx: &'a OpCtx, key: &'a str, version: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.delete_object(ctx, key, Some(version)))
    }
    fn restore_version<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        version: &'a str,
        extra: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.restore_object_version(ctx, key, version, extra))
    }
}

impl MultipartUploadApi for S3Backend {
    /// Start an upload. A context with a checksum transfer asks for the checksum algorithm `SHA256`.
    fn initiate<'a>(&'a self, ctx: &'a OpCtx, key: &'a str, content_type: &'a str) -> BoxFuture<'a, Result<String>> {
        Box::pin(self.initiate_multipart(ctx, key, content_type))
    }
    fn upload_part<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        upload_id: &'a str,
        number: u32,
        body: Body,
        size: i64,
    ) -> BoxFuture<'a, Result<String>> {
        Box::pin(S3Backend::upload_part(self, ctx, key, upload_id, number, body, size))
    }
    fn complete<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        upload_id: &'a str,
        parts: &'a [CompletedPart],
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.complete_multipart(ctx, key, upload_id, parts))
    }
    fn abort<'a>(&'a self, ctx: &'a OpCtx, key: &'a str, upload_id: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.abort_multipart(ctx, key, upload_id))
    }
}

impl MultipartPartLister for S3Backend {
    fn list_parts<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        upload_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<MultipartPart>>> {
        Box::pin(self.list_multipart_parts(ctx, key, upload_id))
    }
}

/// The values of a `ListObjectVersions` answer.
struct VersionListing {
    truncated: bool,
    next_key: String,
    next_version: String,
    /// The key and the version of each version, then of each delete marker, in the order of the answer.
    versions: Vec<(String, StoredObjectVersion)>,
    markers: Vec<(String, StoredObjectVersion)>,
}

/// Read a `ListObjectVersions` answer.
fn parse_version_listing(body: &[u8]) -> std::result::Result<VersionListing, String> {
    let mut truncated = false;
    let mut next_key = String::new();
    let mut next_version = String::new();
    let mut versions: Vec<(String, StoredObjectVersion)> = Vec::new();
    let mut markers: Vec<(String, StoredObjectVersion)> = Vec::new();
    let mut failure: Option<String> = None;
    let parsed = xml::walk(body, |node| match node {
        Node::Start(path) if at(path, &["Version"]) => versions.push(Default::default()),
        Node::Start(path) if at(path, &["DeleteMarker"]) => markers.push((
            String::new(),
            StoredObjectVersion {
                delete_marker: true,
                ..Default::default()
            },
        )),
        Node::Start(_) => {}
        Node::End(path, text) => {
            if at(path, &["IsTruncated"]) {
                match xml::parse_bool(&text) {
                    Ok(value) => truncated = value,
                    Err(error) => {
                        failure.get_or_insert(error);
                    }
                }
                return;
            }
            if at(path, &["NextKeyMarker"]) {
                next_key = text;
                return;
            }
            if at(path, &["NextVersionIdMarker"]) {
                next_version = text;
                return;
            }
            if path.len() != 2 {
                return;
            }
            let target = match path[0].as_str() {
                "Version" => versions.last_mut(),
                "DeleteMarker" => markers.last_mut(),
                _ => None,
            };
            let Some((item_key, item)) = target else {
                return;
            };
            match path[1].as_str() {
                "Key" => *item_key = text,
                "VersionId" => item.version = text,
                "IsLatest" => match xml::parse_bool(&text) {
                    Ok(value) => item.is_current = value,
                    Err(error) => {
                        failure.get_or_insert(error);
                    }
                },
                "LastModified" => item.last_modified = parse_time(&text),
                "ETag" if !item.delete_marker => item.etag = trim_quotes(&text).to_owned(),
                "Size" if !item.delete_marker => match xml::parse_int(&text) {
                    Ok(size) => item.size = size,
                    Err(error) => {
                        failure.get_or_insert(error);
                    }
                },
                _ => {}
            }
        }
    });
    if let Some(error) = parsed.err().or(failure) {
        return Err(error);
    }
    Ok(VersionListing {
        truncated,
        next_key,
        next_version,
        versions,
        markers,
    })
}

/// Read a `ListParts` answer: the parts, the truncation and the next marker.
fn parse_parts_page(body: &[u8]) -> std::result::Result<(Vec<MultipartPart>, bool, i64), String> {
    let mut truncated = false;
    let mut next_marker: i64 = 0;
    let mut page: Vec<MultipartPart> = Vec::new();
    let mut failure: Option<String> = None;
    let mut keep_error = |result: std::result::Result<(), String>| {
        if let Err(error) = result {
            failure.get_or_insert(error);
        }
    };
    let parsed = xml::walk(body, |node| match node {
        Node::Start(path) if at(path, &["Part"]) => page.push(MultipartPart::default()),
        Node::Start(_) => {}
        Node::End(path, text) => {
            if at(path, &["IsTruncated"]) {
                keep_error(xml::parse_bool(&text).map(|value| truncated = value));
            } else if at(path, &["NextPartNumberMarker"]) {
                keep_error(xml::parse_int(&text).map(|value| next_marker = value));
            } else if let Some(part) = page.last_mut()
                && path.len() == 2
                && path[0] == "Part"
            {
                match path[1].as_str() {
                    "PartNumber" => keep_error(xml::parse_int(&text).and_then(|value| {
                        u32::try_from(value)
                            .map(|number| part.number = number)
                            .map_err(|_| format!("invalid part number {value}"))
                    })),
                    "ETag" => part.etag = trim_quotes(&text).to_owned(),
                    "Size" => keep_error(xml::parse_int(&text).map(|size| part.size = size)),
                    "ChecksumSHA256" => part.checksum_sha256 = text,
                    _ => {}
                }
            }
        }
    });
    if let Some(error) = parsed.err().or(failure) {
        return Err(error);
    }
    Ok((page, truncated, next_marker))
}

/// Read a `DeleteObjects` answer: the root, the code and the message of the root, and the refused keys. A body that
/// does not read gives `None`.
fn parse_delete_result(body: &[u8]) -> Option<(String, String, String, Vec<BatchDeleteFailure>)> {
    let mut code = String::new();
    let mut message = String::new();
    let mut failures: Vec<BatchDeleteFailure> = Vec::new();
    let root = xml::walk(body, |node| match node {
        Node::Start(path) if at(path, &["Error"]) => failures.push(BatchDeleteFailure {
            key: String::new(),
            code: String::new(),
            message: String::new(),
        }),
        Node::Start(_) => {}
        Node::End(path, text) => {
            if at(path, &["Code"]) {
                code = text;
            } else if at(path, &["Message"]) {
                message = text;
            } else if let Some(failure) = failures.last_mut()
                && path.len() == 2
                && path[0] == "Error"
            {
                match path[1].as_str() {
                    "Key" => failure.key = text,
                    "Code" => failure.code = text,
                    "Message" => failure.message = text,
                    _ => {}
                }
            }
        }
    });
    let root = root.ok()?;
    Some((root, code, message, failures))
}

/// Read a `ListObjectsV2` answer.
fn parse_list_page(body: &[u8]) -> std::result::Result<ListPage, String> {
    let mut page = ListPage::default();
    let mut failure: Option<String> = None;
    let parsed = xml::walk(body, |node| match node {
        Node::Start(path) if at(path, &["Contents"]) => page.objects.push(ObjectInfo::default()),
        Node::Start(path) if at(path, &["CommonPrefixes"]) => page.prefixes.push(String::new()),
        Node::Start(_) => {}
        Node::End(path, text) => {
            if at(path, &["NextContinuationToken"]) {
                page.next_page_token = text;
            } else if at(path, &["IsTruncated"]) {
                if let Err(error) = xml::parse_bool(&text) {
                    failure.get_or_insert(error);
                }
            } else if at(path, &["CommonPrefixes", "Prefix"]) {
                if let Some(prefix) = page.prefixes.last_mut() {
                    *prefix = text;
                }
            } else if let Some(object) = page.objects.last_mut()
                && path.len() == 2
                && path[0] == "Contents"
            {
                match path[1].as_str() {
                    "Key" => object.key = text,
                    "LastModified" => object.last_modified = parse_time(&text),
                    "Size" => match xml::parse_int(&text) {
                        Ok(size) => object.size = size,
                        Err(error) => {
                            failure.get_or_insert(error);
                        }
                    },
                    "ETag" => object.etag = trim_quotes(&text).to_owned(),
                    _ => {}
                }
            }
        }
    });
    if let Some(error) = parsed.err().or(failure) {
        return Err(error);
    }
    Ok(page)
}

/// The access of the tests to the page token of the versions.
#[cfg(test)]
pub(crate) mod tests_support {
    /// The key marker and the version marker of a page token.
    pub fn decode_cursor(token: &str) -> Option<(String, String)> {
        super::VersionCursor::decode(token).map(|cursor| (cursor.key_marker, cursor.version_id_marker))
    }
}
