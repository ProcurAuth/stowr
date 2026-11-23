//! The GCS back end: the JSON API, the OAuth token of a service account (an RS256 JWT), the generations and the
//! resumable upload.

use std::sync::Arc;

use http::HeaderMap;

use super::SharedAuth;
use crate::common::BoxFuture;
use crate::common::config::BucketConfig;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::Body;
use crate::common::storage::{
    Backend, ConditionalWriter, DiscoveredCapabilities, ListOptions, ListPage, ObjectResponse, ObjectVersionPage,
    ResumableApi, VersionStore,
};

/// The GCS back end of one bucket.
pub struct GcsBackend {
    /// The configuration of the bucket.
    pub cfg: BucketConfig,
    /// The shared state of the auth block.
    pub auth: Arc<SharedAuth>,
}

impl GcsBackend {
    /// The back end of a bucket.
    pub fn new(cfg: BucketConfig, auth: Arc<SharedAuth>) -> Result<Self> {
        Ok(Self { cfg, auth })
    }
}

macro_rules! not_served_future {
    ($what:expr) => {
        Box::pin(async move { Err(Error::not_served($what)) })
    };
}

impl Backend for GcsBackend {
    fn list<'a>(&'a self, _ctx: &'a OpCtx, _options: &'a ListOptions) -> BoxFuture<'a, Result<ListPage>> {
        not_served_future!("the GCS listing")
    }
    fn head<'a>(&'a self, _ctx: &'a OpCtx, _key: &'a str) -> BoxFuture<'a, Result<ObjectResponse>> {
        not_served_future!("the GCS read")
    }
    fn get<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        not_served_future!("the GCS read")
    }
    fn put<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _body: Body,
        _size: i64,
        _content_type: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        not_served_future!("the GCS write")
    }
    fn delete<'a>(&'a self, _ctx: &'a OpCtx, _key: &'a str) -> BoxFuture<'a, Result<()>> {
        not_served_future!("the GCS delete")
    }
    fn copy<'a>(&'a self, _ctx: &'a OpCtx, _source: &'a str, _destination: &'a str) -> BoxFuture<'a, Result<()>> {
        not_served_future!("the GCS copy")
    }
    fn discover_capabilities<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<DiscoveredCapabilities>> {
        not_served_future!("the GCS permission discovery")
    }
    fn conditional_writer(&self) -> Option<&dyn ConditionalWriter> {
        Some(self)
    }
    fn version_store(&self) -> Option<&dyn VersionStore> {
        Some(self)
    }
    fn resumable(&self) -> Option<&dyn ResumableApi> {
        Some(self)
    }
}

impl ConditionalWriter for GcsBackend {
    fn put_if_absent<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _body: Body,
        _size: i64,
        _content_type: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        not_served_future!("the GCS write that creates only")
    }
}

impl VersionStore for GcsBackend {
    fn list_versions<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _page_token: &'a str,
        _maximum: u32,
    ) -> BoxFuture<'a, Result<ObjectVersionPage>> {
        not_served_future!("the GCS generations")
    }
    fn head_version<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _version: &'a str,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        not_served_future!("the GCS generations")
    }
    fn get_version<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _version: &'a str,
        _headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        not_served_future!("the GCS generations")
    }
    fn delete_version<'a>(&'a self, _ctx: &'a OpCtx, _key: &'a str, _version: &'a str) -> BoxFuture<'a, Result<()>> {
        not_served_future!("the GCS generations")
    }
    fn restore_version<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _version: &'a str,
        _extra: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<()>> {
        not_served_future!("the GCS generations")
    }
}

impl ResumableApi for GcsBackend {
    fn initiate_resumable<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _total: i64,
        _content_type: &'a str,
    ) -> BoxFuture<'a, Result<String>> {
        not_served_future!("the GCS resumable upload")
    }
    fn upload_chunk<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _session: &'a str,
        _body: Body,
        _start: i64,
        _size: i64,
        _total: i64,
        _content_type: &'a str,
    ) -> BoxFuture<'a, Result<(i64, bool)>> {
        not_served_future!("the GCS resumable upload")
    }
    fn query_resumable<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _session: &'a str,
        _total: i64,
    ) -> BoxFuture<'a, Result<(i64, bool)>> {
        not_served_future!("the GCS resumable upload")
    }
    fn abort_resumable<'a>(&'a self, _ctx: &'a OpCtx, _session: &'a str) -> BoxFuture<'a, Result<()>> {
        not_served_future!("the GCS resumable upload")
    }
}
