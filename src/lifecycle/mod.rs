//! The object tags and the lifecycle rules of a bucket (docs/ARCHITECTURE.md, "Object tags and lifecycle" and
//! "Edit of the lifecycle rules").
//!
//! This folder has the tag routes (`/api/tags`, `/api/tags/bulk`) and the lifecycle route (`/api/lifecycle`, `GET`
//! and `PUT`). It has the job `tag_prefix` and the start probes of the tags and of the lifecycle rules. It finds the
//! provider flavour. It keeps the facts of the bucket for `/api/instances` (versioning state, number of rules). It
//! sends the S3 requests of these functions (`impl ObjectTagger for S3Backend`, `impl BucketRules for S3Backend`).
//!
//! The instance gets these methods in this folder: `tags_available`, `probe_tags`, `require_tags`, `get_tags`,
//! `put_tags`, `tag_version`, `lifecycle_available`, `probe_lifecycle`, `lifecycle_rule_count`, `known_flavour`,
//! `lifecycle_flavour`, `mark_bucket_facts_read`, `refresh_bucket_facts`, `read_lifecycle_state`,
//! `save_lifecycle`. The public facts of `/api/instances` use `tags_available`, `lifecycle_available`,
//! `lifecycle_rule_count` and `known_flavour`. The S3 back end of the upload sends the value of
//! `upload_tagging_header(ctx)` in the header `x-amz-tagging`.

mod editor;
mod routes;
mod rules;
mod s3;
mod seam;
mod tags;
pub mod xml;

#[cfg(test)]
pub(crate) mod fakes;
#[cfg(test)]
mod lifecycle_tests;
#[cfg(test)]
mod tags_tests;

use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::time::Instant;

use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize};

use crate::common::BoxFuture;
use crate::common::ctx::OpCtx;
use crate::common::error::Result;
use crate::common::http::{Route, RouteAccess, route};

pub use editor::{
    BUCKET_FACTS_TTL, EditorState, HiddenField, LifecycleEntry, LifecycleResponse, LifecycleState, lifecycle_deletes,
};
pub use routes::{handle_lifecycle, handle_tags, handle_tags_bulk};
pub use rules::{
    EditRule, FIELD_ABORT, FIELD_DELETE_MARKER, FIELD_NONCURRENT, FIELD_TAG, FIELDS, FLAVOUR_AWS, FLAVOUR_GARAGE,
    FLAVOUR_MINIO, FLAVOUR_SEAWEEDFS, LifecycleRule, LifecycleTransition, MAX_LIFECYCLE_DAYS, MAX_LIFECYCLE_RULES,
    flavour_name, lifecycle_hash, parse_lifecycle_rules,
};
pub use s3::s3_provider_flavour;
pub use tags::{
    MAX_OBJECT_TAGS, TagsResponse, apply_tag_change, encode_tagging, parse_tagging_header, run_tag_job, same_tags,
    upload_tagging_header, validate_tags, with_upload_tags,
};

/// One object tag.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tag {
    /// The key.
    #[serde(default, deserialize_with = "nullable")]
    pub key: String,
    /// The value.
    #[serde(default, deserialize_with = "nullable")]
    pub value: String,
}

impl Tag {
    /// A tag from two texts.
    pub fn new(key: &str, value: &str) -> Self {
        Self {
            key: key.to_owned(),
            value: value.to_owned(),
        }
    }
}

/// The change of the job `tag_prefix`: the tags to set and the keys to remove.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TagChange {
    /// The tags to set.
    #[serde(default, deserialize_with = "nullable", skip_serializing_if = "Vec::is_empty")]
    pub add: Vec<Tag>,
    /// The keys to remove.
    #[serde(default, deserialize_with = "nullable", skip_serializing_if = "Vec::is_empty")]
    pub remove: Vec<String>,
}

/// A value of a JSON request: `null` gives the default value, as an absent member does.
pub(crate) fn nullable<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// A text between double quotes, with the escapes of a quoted text: for a message that shows a value of the client.
pub fn quote_text(text: &str) -> String {
    crate::config::quote::quote(text)
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
    /// Replace the tags of an object. An empty set of tags removes them all.
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
    /// Set when the provider refused the read of the configuration (501 or 405).
    pub off: AtomicBool,
    /// Makes the read, the check of the hash, the write and the read back of one save one step in this process.
    pub write: tokio::sync::Mutex<()>,
    /// The flavour, the refusal, the dropped fields, the count of the rules and the time of the last read.
    pub inner: Mutex<RulesInner>,
}

/// The values of [`RulesState`].
#[derive(Debug, Default)]
pub struct RulesInner {
    /// The provider flavour that the probe found.
    pub flavour: String,
    /// True after the probe asked the provider one time.
    pub flavour_known: bool,
    /// The reason of the last refusal of a write (403, 501 or 405). A later write that works clears it.
    pub write_refusal: String,
    /// The fields that the provider dropped after a save in this process.
    pub dropped: Vec<&'static str>,
    /// The number of rules at the last read of the configuration.
    pub rule_count: Option<usize>,
    /// The time of the last read of the facts of the bucket.
    pub facts_at: Option<Instant>,
    /// True while a read of the facts runs in the background.
    pub facts_running: bool,
}

/// The routes of this work package.
pub fn routes() -> Vec<Route> {
    vec![
        route("/api/tags", RouteAccess::HandlerAsks, handle_tags),
        route("/api/tags/bulk", RouteAccess::HandlerAsks, handle_tags_bulk),
        route("/api/lifecycle", RouteAccess::HandlerAsks, handle_lifecycle),
    ]
}
