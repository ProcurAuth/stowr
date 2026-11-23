//! The S3 back end.

use std::sync::Arc;

use bytes::Bytes;
use http::{HeaderMap, Method};

use super::SharedAuth;
use crate::common::BoxFuture;
use crate::common::config::BucketConfig;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::Body;
use crate::common::storage::{
    Backend, BatchDeleter, CompletedPart, ConditionalWriter, DiscoveredCapabilities, ListOptions, ListPage,
    MultipartCopier, MultipartCopyOptions, MultipartPart, MultipartPartLister, MultipartUploadApi, ObjectResponse,
    ObjectVersionPage, VersionStore,
};

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
pub struct S3Answer {
    /// The status.
    pub status: u16,
    /// The headers.
    pub headers: HeaderMap,
    /// The body.
    pub body: Bytes,
}

/// The S3 back end of one bucket.
pub struct S3Backend {
    /// The configuration of the bucket.
    pub cfg: BucketConfig,
    /// The shared state of the auth block.
    pub auth: Arc<SharedAuth>,
}

impl S3Backend {
    /// The back end of a bucket.
    pub fn new(cfg: BucketConfig, auth: Arc<SharedAuth>) -> Result<Self> {
        Ok(Self { cfg, auth })
    }

    /// Sign and send one request; read at most `limit` bytes of the answer. A status of 300 or more is not an
    /// error here: the caller reads it (`s3_error` gives the provider error).
    pub async fn send(&self, ctx: &OpCtx, request: S3Request<'_>, limit: usize) -> Result<S3Answer> {
        let _ = (ctx, request, limit);
        Err(Error::not_served("the S3 requests"))
    }

    /// The provider error of an answer: the `Code` and the `Message` of the XML body.
    pub fn s3_error(answer: &S3Answer) -> Error {
        Error::upstream(
            answer.status,
            "",
            String::from_utf8_lossy(&answer.body).trim().to_owned(),
        )
    }
}

macro_rules! not_served_future {
    ($what:expr) => {
        Box::pin(async move { Err(Error::not_served($what)) })
    };
}

impl Backend for S3Backend {
    fn list<'a>(&'a self, _ctx: &'a OpCtx, _options: &'a ListOptions) -> BoxFuture<'a, Result<ListPage>> {
        not_served_future!("the S3 listing")
    }
    fn head<'a>(&'a self, _ctx: &'a OpCtx, _key: &'a str) -> BoxFuture<'a, Result<ObjectResponse>> {
        not_served_future!("the S3 read")
    }
    fn get<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        not_served_future!("the S3 read")
    }
    fn put<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _body: Body,
        _size: i64,
        _content_type: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        not_served_future!("the S3 write")
    }
    fn delete<'a>(&'a self, _ctx: &'a OpCtx, _key: &'a str) -> BoxFuture<'a, Result<()>> {
        not_served_future!("the S3 delete")
    }
    fn copy<'a>(&'a self, _ctx: &'a OpCtx, _source: &'a str, _destination: &'a str) -> BoxFuture<'a, Result<()>> {
        not_served_future!("the S3 copy")
    }
    fn discover_capabilities<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<DiscoveredCapabilities>> {
        not_served_future!("the S3 permission discovery")
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
    fn put_if_absent<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _body: Body,
        _size: i64,
        _content_type: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        not_served_future!("the S3 write that creates only")
    }
}

impl BatchDeleter for S3Backend {
    fn delete_many<'a>(&'a self, _ctx: &'a OpCtx, _keys: &'a [String]) -> BoxFuture<'a, Result<()>> {
        not_served_future!("the S3 batch delete")
    }
}

impl MultipartCopier for S3Backend {
    fn copy_multipart<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _source: &'a str,
        _destination: &'a str,
        _options: MultipartCopyOptions,
    ) -> BoxFuture<'a, Result<()>> {
        not_served_future!("the S3 copy in parts")
    }
}

impl VersionStore for S3Backend {
    fn list_versions<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _page_token: &'a str,
        _maximum: u32,
    ) -> BoxFuture<'a, Result<ObjectVersionPage>> {
        not_served_future!("the S3 versions")
    }
    fn head_version<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _version: &'a str,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        not_served_future!("the S3 versions")
    }
    fn get_version<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _version: &'a str,
        _headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        not_served_future!("the S3 versions")
    }
    fn delete_version<'a>(&'a self, _ctx: &'a OpCtx, _key: &'a str, _version: &'a str) -> BoxFuture<'a, Result<()>> {
        not_served_future!("the S3 versions")
    }
    fn restore_version<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _version: &'a str,
        _extra: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<()>> {
        not_served_future!("the S3 versions")
    }
}

impl MultipartUploadApi for S3Backend {
    fn initiate<'a>(&'a self, _ctx: &'a OpCtx, _key: &'a str, _content_type: &'a str) -> BoxFuture<'a, Result<String>> {
        not_served_future!("the S3 multipart upload")
    }
    fn upload_part<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _upload_id: &'a str,
        _number: u32,
        _body: Body,
        _size: i64,
    ) -> BoxFuture<'a, Result<String>> {
        not_served_future!("the S3 multipart upload")
    }
    fn complete<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _upload_id: &'a str,
        _parts: &'a [CompletedPart],
    ) -> BoxFuture<'a, Result<()>> {
        not_served_future!("the S3 multipart upload")
    }
    fn abort<'a>(&'a self, _ctx: &'a OpCtx, _key: &'a str, _upload_id: &'a str) -> BoxFuture<'a, Result<()>> {
        not_served_future!("the S3 multipart upload")
    }
}

impl MultipartPartLister for S3Backend {
    fn list_parts<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _upload_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<MultipartPart>>> {
        not_served_future!("the S3 list of the parts")
    }
}

/// The AWS Signature Version 4 of a request (docs: the reference vector of AWS is a test of this module).
pub mod sigv4 {
    /// The lower-case hexadecimal SHA-256 of bytes.
    pub fn sha256_hex(data: &[u8]) -> String {
        crate::common::misc::hex(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data).as_ref())
    }
}
