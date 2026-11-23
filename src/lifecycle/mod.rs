//! The object tags and the lifecycle rules of a bucket (docs/ARCHITECTURE.md, "Object tags and lifecycle" and
//! "Edit of the lifecycle rules").
//!
//! This work package owns the tag routes (`/api/tags`, `/api/tags/bulk`), the lifecycle route (`/api/lifecycle`,
//! `GET` and `PUT`), the job `tag_prefix`, the start probes of the tags and of the lifecycle rules, the provider
//! flavour, the facts of the bucket in `/api/instances` (versioning state, number of rules), and the S3 requests
//! of these functions (`impl ObjectTagger for S3Backend`, `impl BucketRules for S3Backend`).

use std::sync::Mutex;
use std::sync::atomic::AtomicBool;

use bytes::Bytes;
use http::HeaderMap;
use serde::{Deserialize, Serialize};

use crate::common::BoxFuture;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Route, RouteAccess, route};
use crate::provider::S3Backend;

/// One object tag.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tag {
    /// The key.
    pub key: String,
    /// The value.
    pub value: String,
}

/// The change of the job `tag_prefix`: the tags to set and the keys to remove.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TagChange {
    /// The tags to set.
    pub add: Vec<Tag>,
    /// The keys to remove.
    pub remove: Vec<String>,
}

/// One lifecycle rule as `/api/lifecycle` gives it in `rules`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct LifecycleRule {
    /// The ID of the rule.
    pub id: String,
}

/// The raw lifecycle configuration of a bucket: the bytes that the provider sent.
#[derive(Clone, Debug, Default)]
pub struct LifecycleDocument {
    /// The XML bytes; empty for a bucket without rules.
    pub body: Bytes,
}

/// The object tags of a back end.
pub trait ObjectTagger: Send + Sync {
    /// The tags of an object (an empty version: the current object).
    fn get_tags<'a>(&'a self, ctx: &'a OpCtx, key: &'a str, version: &'a str) -> BoxFuture<'a, Result<Vec<Tag>>>;
    /// Replace the tags of an object.
    fn put_tags<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        version: &'a str,
        tags: &'a [Tag],
    ) -> BoxFuture<'a, Result<()>>;
}

/// The bucket functions of the lifecycle editor: the rules, the versioning status and the provider flavour.
pub trait BucketRules: Send + Sync {
    /// The rules of the bucket, parsed.
    fn lifecycle_rules<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<Vec<LifecycleRule>>>;
    /// The raw configuration of the bucket.
    fn read_lifecycle<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<LifecycleDocument>>;
    /// Write the whole configuration.
    fn write_lifecycle<'a>(&'a self, ctx: &'a OpCtx, body: Bytes) -> BoxFuture<'a, Result<()>>;
    /// Delete the configuration.
    fn delete_lifecycle<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<()>>;
    /// The status of `GetBucketVersioning`: `Enabled`, `Suspended` or empty.
    fn versioning_status<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<String>>;
    /// The provider that answers: `aws`, `minio`, `seaweedfs`, `garage`, or empty.
    fn provider_flavour<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<String>>;
}

/// The state of the tags of an instance.
#[derive(Debug, Default)]
pub struct TagsState {
    /// Set when the start probe found a provider without tags.
    pub off: AtomicBool,
}

/// The state of the lifecycle editor and of the bucket facts of an instance.
#[derive(Debug, Default)]
pub struct RulesState {
    /// The flavour, the refusals, the dropped fields and the count of the rules.
    pub inner: Mutex<RulesInner>,
}

/// The values of [`RulesState`].
#[derive(Debug, Default)]
pub struct RulesInner {
    /// The provider flavour that the probe found.
    pub flavour: String,
    /// True when the probe found the lifecycle rules.
    pub supported: bool,
    /// The number of rules at the last read.
    pub rule_count: Option<usize>,
}

/// Read the header `X-Amz-Tagging` of an upload (`a=b&c=d`).
pub fn parse_tagging_header(headers: &HeaderMap) -> Result<Vec<Tag>> {
    let _ = headers;
    Ok(Vec::new())
}

/// Run the job `tag_prefix`.
pub async fn run_tag_job(run: &crate::jobs::JobRun, job: &mut crate::jobs::JobState) -> Result<()> {
    let _ = (run, job);
    Err(Error::not_served("the job tag_prefix"))
}

crate::stub_handler!(handle_tags, "the route /api/tags");
crate::stub_handler!(handle_tags_bulk, "the route /api/tags/bulk");
crate::stub_handler!(handle_lifecycle, "the route /api/lifecycle");

/// The routes of this work package.
pub fn routes() -> Vec<Route> {
    vec![
        route("/api/tags", RouteAccess::HandlerAsks, handle_tags),
        route("/api/tags/bulk", RouteAccess::HandlerAsks, handle_tags_bulk),
        route("/api/lifecycle", RouteAccess::HandlerAsks, handle_lifecycle),
    ]
}

macro_rules! not_served_future {
    ($what:expr) => {
        Box::pin(async move { Err(Error::not_served($what)) })
    };
}

impl ObjectTagger for S3Backend {
    fn get_tags<'a>(&'a self, _ctx: &'a OpCtx, _key: &'a str, _version: &'a str) -> BoxFuture<'a, Result<Vec<Tag>>> {
        not_served_future!("the S3 tags")
    }
    fn put_tags<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _version: &'a str,
        _tags: &'a [Tag],
    ) -> BoxFuture<'a, Result<()>> {
        not_served_future!("the S3 tags")
    }
}

impl BucketRules for S3Backend {
    fn lifecycle_rules<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<Vec<LifecycleRule>>> {
        not_served_future!("the S3 lifecycle rules")
    }
    fn read_lifecycle<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<LifecycleDocument>> {
        not_served_future!("the S3 lifecycle rules")
    }
    fn write_lifecycle<'a>(&'a self, _ctx: &'a OpCtx, _body: Bytes) -> BoxFuture<'a, Result<()>> {
        not_served_future!("the S3 lifecycle rules")
    }
    fn delete_lifecycle<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<()>> {
        not_served_future!("the S3 lifecycle rules")
    }
    fn versioning_status<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<String>> {
        not_served_future!("the S3 versioning status")
    }
    fn provider_flavour<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<String>> {
        not_served_future!("the provider flavour")
    }
}
