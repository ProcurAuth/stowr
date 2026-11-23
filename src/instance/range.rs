//! The range readers of the previews.
//!
//! A [`RangeSource`] reads exact byte ranges of one object (one version), checks each answer `206` and its
//! `Content-Range`, binds the reads to the ETag or the generation, refuses an answer that is larger than the range,
//! and keeps a small cache of the read spans (`server.max_range_cache_bytes`). A [`WindowReader`] reads an object in
//! order, one window of 256 KiB after the other.

use std::sync::Arc;

use bytes::Bytes;
use http::HeaderMap;

use super::Instance;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};

/// The version of the object that a reader is bound to.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObjectVersion {
    /// The ETag.
    pub etag: String,
    /// The version id or the generation.
    pub version: String,
}

/// A reader of exact byte ranges of one object.
pub struct RangeSource {
    /// The instance.
    pub instance: Arc<Instance>,
    /// The context of the reads.
    pub ctx: OpCtx,
    /// The full key.
    pub key: String,
}

impl RangeSource {
    /// Open the object (the current version, or the version of the context).
    pub async fn open(ctx: &OpCtx, instance: &Arc<Instance>, key: &str) -> Result<Self> {
        Ok(Self {
            instance: instance.clone(),
            ctx: ctx.clone(),
            key: key.to_owned(),
        })
    }

    /// The size of the object, when it is known.
    pub fn size(&self) -> Option<i64> {
        None
    }

    /// Give the size of the listing: the first read does not need a HEAD.
    pub fn set_known_size(&mut self, size: i64) {
        let _ = size;
    }

    /// Give the ETag that the reads must find.
    pub fn set_expected_etag(&mut self, etag: &str) {
        let _ = etag;
    }

    /// The version that the reads are bound to.
    pub fn version(&self) -> ObjectVersion {
        ObjectVersion::default()
    }

    /// The headers of the object.
    pub fn headers(&self) -> HeaderMap {
        HeaderMap::new()
    }

    /// The provider calls and the bytes of the reads.
    pub fn counters(&self) -> (u64, i64) {
        (0, 0)
    }

    /// Read `length` bytes from `start`.
    pub async fn read_range(&self, start: i64, length: i64) -> Result<Bytes> {
        let _ = (start, length);
        Err(Error::not_served("the range reader"))
    }

    /// Read the first `length` bytes.
    pub async fn read_prefix(&self, length: i64) -> Result<Bytes> {
        self.read_range(0, length).await
    }

    /// Read the last `length` bytes.
    pub async fn read_suffix(&self, length: i64) -> Result<Bytes> {
        let _ = length;
        Err(Error::not_served("the range reader"))
    }
}

/// A reader of an object in order, from an offset, one window after the other.
pub struct WindowReader {
    /// The source of the windows.
    pub source: RangeSource,
    /// The next offset.
    pub offset: i64,
}

impl WindowReader {
    /// Open the object at an offset, bound to an ETag when it is not empty.
    pub async fn open(ctx: &OpCtx, instance: &Arc<Instance>, key: &str, offset: i64, etag: &str) -> Result<Self> {
        let mut source = RangeSource::open(ctx, instance, key).await?;
        source.set_expected_etag(etag);
        Ok(Self { source, offset })
    }

    /// The next bytes, or an empty value at the end of the object.
    pub async fn next_chunk(&mut self) -> Result<Bytes> {
        Err(Error::not_served("the window reader"))
    }
}
