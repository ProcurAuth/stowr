// SPDX-License-Identifier: MIT OR Apache-2.0
//! The S3 requests of the tags and of the lifecycle rules, and the flavour of the provider.
//!
//! The functions of this file send their requests through [`S3Wire`]. The S3 back end is the wire of the program.
//! A test has a wire of its own.

use bytes::Bytes;
use http::header::{CONTENT_TYPE, HeaderValue};
use http::{HeaderMap, Method};

use super::rules::{
    FLAVOUR_AWS, FLAVOUR_GARAGE, FLAVOUR_MINIO, FLAVOUR_PROBE_KEY, FLAVOUR_SEAWEEDFS, MAX_LIFECYCLE_DOCUMENT_BYTES,
    parse_lifecycle_rules,
};
use super::xml::{self, XmlError};
use super::{BucketRules, LifecycleDocument, LifecycleRule, ObjectTagger, Tag};
use crate::common::BoxFuture;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::full;
use crate::common::md5::content_md5;
use crate::provider::S3Backend;
use crate::provider::s3::{S3Answer, S3Request};

/// The largest answer that these requests read, except the configuration.
const SMALL_ANSWER: usize = 1 << 20;
/// The largest answer of the probe of the provider.
const PROBE_ANSWER: usize = 64 << 10;

/// What these requests need from the S3 client.
pub(crate) trait S3Wire: Send + Sync {
    /// Sign and send one request; read at most `limit` bytes of the answer.
    fn send<'a>(&'a self, ctx: &'a OpCtx, request: S3Request<'a>, limit: usize) -> BoxFuture<'a, Result<S3Answer>>;
    /// The endpoint of the provider, as the configuration gives it.
    fn endpoint(&self) -> &str;
    /// The root prefix of the instance.
    fn root_prefix(&self) -> &str;
    /// The provider error of an answer outside of 2xx.
    fn failure(&self, answer: &S3Answer) -> Error;
}

impl S3Wire for S3Backend {
    fn send<'a>(&'a self, ctx: &'a OpCtx, request: S3Request<'a>, limit: usize) -> BoxFuture<'a, Result<S3Answer>> {
        Box::pin(S3Backend::send(self, ctx, request, limit))
    }

    fn endpoint(&self) -> &str {
        &self.auth.cfg.endpoint
    }

    fn root_prefix(&self) -> &str {
        &self.cfg.root_prefix
    }

    fn failure(&self, answer: &S3Answer) -> Error {
        S3Backend::s3_error(answer)
    }
}

fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
    items
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect()
}

fn xml_headers(body: &[u8]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/xml"));
    if let Ok(value) = HeaderValue::from_str(&content_md5(body)) {
        headers.insert("content-md5", value);
    }
    headers
}

fn is_success(answer: &S3Answer) -> bool {
    (200..300).contains(&answer.status)
}

// --- Tags --------------------------------------------------------------------------------------------------------

fn tagging_query(version: &str) -> Vec<(String, String)> {
    let mut query = pairs(&[("tagging", "")]);
    if !version.is_empty() {
        query.push(("versionId".to_owned(), version.to_owned()));
    }
    query
}

/// The XML of `PutObjectTagging` for a set of tags.
pub(crate) fn tagging_document(tags: &[Tag]) -> String {
    let mut out = String::from("<Tagging><TagSet>");
    for tag in tags {
        out.push_str("<Tag><Key>");
        out.push_str(&xml::escape_text(&tag.key));
        out.push_str("</Key><Value>");
        out.push_str(&xml::escape_text(&tag.value));
        out.push_str("</Value></Tag>");
    }
    out.push_str("</TagSet></Tagging>");
    out
}

/// The tags of an answer of `GetObjectTagging`, sorted by key.
pub(crate) fn parse_tagging(body: &[u8]) -> Result<Vec<Tag>> {
    let root =
        xml::parse_document(body).map_err(|error| Error::internal(format!("decode s3 tagging response: {error}")))?;
    let mut tags: Vec<Tag> = root
        .children_named("TagSet")
        .flat_map(|set| set.children_named("Tag"))
        .map(|tag| Tag {
            key: tag
                .last_child("Key")
                .map(|key| key.raw_text.clone())
                .unwrap_or_default(),
            value: tag
                .last_child("Value")
                .map(|value| value.raw_text.clone())
                .unwrap_or_default(),
        })
        .collect();
    tags.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(tags)
}

pub(crate) async fn get_tags<W: S3Wire + ?Sized>(wire: &W, ctx: &OpCtx, key: &str, version: &str) -> Result<Vec<Tag>> {
    let request = S3Request {
        method: Method::GET,
        key,
        query: tagging_query(version),
        headers: HeaderMap::new(),
        body: None,
    };
    let answer = wire.send(ctx, request, SMALL_ANSWER).await?;
    if !is_success(&answer) {
        return Err(wire.failure(&answer));
    }
    parse_tagging(&answer.body)
}

pub(crate) async fn put_tags<W: S3Wire + ?Sized>(
    wire: &W,
    ctx: &OpCtx,
    key: &str,
    version: &str,
    tags: &[Tag],
) -> Result<()> {
    let request = if tags.is_empty() {
        S3Request {
            method: Method::DELETE,
            key,
            query: tagging_query(version),
            headers: HeaderMap::new(),
            body: None,
        }
    } else {
        let body = tagging_document(tags).into_bytes();
        let headers = xml_headers(&body);
        let size = body.len() as i64;
        S3Request {
            method: Method::PUT,
            key,
            query: tagging_query(version),
            headers,
            body: Some((full(Bytes::from(body)), size)),
        }
    };
    let answer = wire.send(ctx, request, SMALL_ANSWER).await?;
    if !is_success(&answer) {
        return Err(wire.failure(&answer));
    }
    Ok(())
}

// --- Lifecycle ---------------------------------------------------------------------------------------------------

/// The code of the error document of a provider, or an empty text when the document has none.
fn error_code(body: &[u8]) -> String {
    xml::parse_document(body)
        .ok()
        .and_then(|root| root.last_child("Code").map(|code| code.raw_text.clone()))
        .unwrap_or_default()
}

pub(crate) async fn read_lifecycle<W: S3Wire + ?Sized>(wire: &W, ctx: &OpCtx) -> Result<LifecycleDocument> {
    let request = S3Request {
        method: Method::GET,
        key: "",
        query: pairs(&[("lifecycle", "")]),
        headers: HeaderMap::new(),
        body: None,
    };
    let answer = wire.send(ctx, request, MAX_LIFECYCLE_DOCUMENT_BYTES + 1).await?;
    if answer.status == 404 {
        let code = error_code(&answer.body);
        if code == "NoSuchLifecycleConfiguration" {
            return Ok(LifecycleDocument::default());
        }
        return Err(Error::upstream(404, code, ""));
    }
    if !is_success(&answer) {
        return Err(wire.failure(&answer));
    }
    if answer.body.len() > MAX_LIFECYCLE_DOCUMENT_BYTES {
        return Err(Error::internal(format!(
            "the s3 lifecycle configuration is larger than {MAX_LIFECYCLE_DOCUMENT_BYTES} bytes"
        )));
    }
    Ok(LifecycleDocument { body: answer.body })
}

pub(crate) async fn lifecycle_rules<W: S3Wire + ?Sized>(wire: &W, ctx: &OpCtx) -> Result<Vec<LifecycleRule>> {
    let document = read_lifecycle(wire, ctx).await?;
    parse_lifecycle_rules(&document.body)
}

pub(crate) async fn write_lifecycle<W: S3Wire + ?Sized>(wire: &W, ctx: &OpCtx, body: Bytes) -> Result<()> {
    let headers = xml_headers(&body);
    let size = body.len() as i64;
    let request = S3Request {
        method: Method::PUT,
        key: "",
        query: pairs(&[("lifecycle", "")]),
        headers,
        body: Some((full(body), size)),
    };
    let answer = wire.send(ctx, request, SMALL_ANSWER).await?;
    if !is_success(&answer) {
        return Err(wire.failure(&answer));
    }
    Ok(())
}

pub(crate) async fn delete_lifecycle<W: S3Wire + ?Sized>(wire: &W, ctx: &OpCtx) -> Result<()> {
    let request = S3Request {
        method: Method::DELETE,
        key: "",
        query: pairs(&[("lifecycle", "")]),
        headers: HeaderMap::new(),
        body: None,
    };
    let answer = wire.send(ctx, request, SMALL_ANSWER).await?;
    if !is_success(&answer) {
        return Err(wire.failure(&answer));
    }
    Ok(())
}

/// `GetBucketVersioning`. SeaweedFS, MinIO and Garage send no status for a bucket that never had versioning.
pub(crate) async fn versioning_status<W: S3Wire + ?Sized>(wire: &W, ctx: &OpCtx) -> Result<String> {
    let request = S3Request {
        method: Method::GET,
        key: "",
        query: pairs(&[("versioning", "")]),
        headers: HeaderMap::new(),
        body: None,
    };
    let answer = wire.send(ctx, request, SMALL_ANSWER).await?;
    if !is_success(&answer) {
        return Err(wire.failure(&answer));
    }
    match xml::parse_document(&answer.body) {
        Ok(root) => Ok(root
            .last_child("Status")
            .map(|status| status.raw_text.trim().to_owned())
            .unwrap_or_default()),
        Err(XmlError::NoRoot) => Ok(String::new()),
        Err(error) => Err(Error::internal(format!("decode s3 versioning response: {error}"))),
    }
}

/// Read an object that does not exist and tell the provider from the answer.
pub(crate) async fn provider_flavour<W: S3Wire + ?Sized>(wire: &W, ctx: &OpCtx) -> Result<String> {
    let key = format!("{}{FLAVOUR_PROBE_KEY}", wire.root_prefix());
    let request = S3Request {
        method: Method::GET,
        key: &key,
        query: Vec::new(),
        headers: HeaderMap::new(),
        body: None,
    };
    let answer = wire.send(ctx, request, PROBE_ANSWER).await?;
    Ok(s3_provider_flavour(wire.endpoint(), &answer.headers, &answer.body).to_owned())
}

/// The host of an endpoint URL, in lower case, without the number after the colon and the brackets of an IPv6 address.
fn endpoint_host(endpoint: &str) -> String {
    let rest = endpoint.split_once("://").map_or(endpoint, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit_once('@').map_or(authority, |(_, host)| host);
    let host = if let Some(inner) = authority.strip_prefix('[') {
        inner.split(']').next().unwrap_or("")
    } else {
        authority.split(':').next().unwrap_or("")
    };
    host.to_lowercase()
}

fn header_text(headers: &HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
        .unwrap_or_default()
}

/// The provider from the endpoint, the header `Server` and the error document of an answer. AWS S3 sends
/// `AmazonS3`, MinIO `MinIO` and SeaweedFS `SeaweedFS <size> <version>`. Garage v2.4.1 sends no `Server` header and
/// no request id, and its error document has a `Region` element and no `RequestId` element. Any other answer gives
/// an empty text: the provider is not known.
pub fn s3_provider_flavour(endpoint: &str, headers: &HeaderMap, body: &[u8]) -> &'static str {
    let host = endpoint_host(endpoint);
    let server = header_text(headers, "server").trim().to_lowercase();
    if host == "amazonaws.com" || host.ends_with(".amazonaws.com") || server == "amazons3" {
        FLAVOUR_AWS
    } else if server.starts_with("minio") {
        FLAVOUR_MINIO
    } else if server.starts_with("seaweedfs") {
        FLAVOUR_SEAWEEDFS
    } else if server.starts_with("garage")
        || (server.is_empty()
            && header_text(headers, "x-amz-request-id").is_empty()
            && header_text(headers, "x-amz-id-2").is_empty()
            && garage_error_document(body))
    {
        FLAVOUR_GARAGE
    } else {
        ""
    }
}

fn garage_error_document(body: &[u8]) -> bool {
    let Ok(root) = xml::parse_document(body) else {
        return false;
    };
    root.name == "Error"
        && root.last_child("Code").is_some_and(|code| !code.raw_text.is_empty())
        && root.child("Region").is_some()
        && root.child("RequestId").is_none()
}

// --- The S3 back end ---------------------------------------------------------------------------------------------

impl ObjectTagger for S3Backend {
    fn get_tags<'a>(&'a self, ctx: &'a OpCtx, key: &'a str, version: &'a str) -> BoxFuture<'a, Result<Vec<Tag>>> {
        Box::pin(get_tags(self, ctx, key, version))
    }

    fn put_tags<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        version: &'a str,
        tags: &'a [Tag],
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(put_tags(self, ctx, key, version, tags))
    }
}

impl BucketRules for S3Backend {
    fn lifecycle_rules<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<Vec<LifecycleRule>>> {
        Box::pin(lifecycle_rules(self, ctx))
    }

    fn read_lifecycle<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<LifecycleDocument>> {
        Box::pin(read_lifecycle(self, ctx))
    }

    fn write_lifecycle<'a>(&'a self, ctx: &'a OpCtx, body: Bytes) -> BoxFuture<'a, Result<()>> {
        Box::pin(write_lifecycle(self, ctx, body))
    }

    fn delete_lifecycle<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<()>> {
        Box::pin(delete_lifecycle(self, ctx))
    }

    fn versioning_status<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<String>> {
        Box::pin(versioning_status(self, ctx))
    }

    fn provider_flavour<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<String>> {
        Box::pin(provider_flavour(self, ctx))
    }
}
