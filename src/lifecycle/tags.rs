//! The object tags: the limits and the checks of S3, the header `X-Amz-Tagging`, the tags of an upload, the tag
//! functions of the instance, and the job `tag_prefix`.
//!
//! Only the S3 back end has tags. A provider that does not know them answers 501 or 405. The instance then
//! answers `tagging_unsupported`.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::time::Duration;

use http::HeaderMap;
use serde::Serialize;

use super::{Tag, TagChange};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Interrupt, Result};
use crate::common::query::{encode_sorted, unescape};
use crate::common::storage::ListOptions;
use crate::common::time::Timestamp;
use crate::instance::Instance;
use crate::jobs::{JobRun, JobState, job_type};

/// The most tags of an object.
pub const MAX_OBJECT_TAGS: usize = 10;
const MAX_TAG_KEY_CHARS: usize = 128;
const MAX_TAG_VALUE_CHARS: usize = 256;
/// The key of the read that probes the tags. The object does not exist.
const TAGS_PROBE_KEY: &str = ".stowr-tags-probe";
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

fn invalid_tags(message: impl Into<String>) -> Error {
    Error::api(400, "invalid_tags", message)
}

/// The error of an instance without tags: `501 tagging_unsupported`.
pub fn tagging_unsupported() -> Error {
    Error::api(
        501,
        "tagging_unsupported",
        "this storage provider does not support object tags",
    )
}

pub use crate::provider::s3::provider_refused_feature;

/// The zero digits of the blocks of decimal digits (the category Nd). Each block has ten digits.
const DIGIT_BLOCKS: &[u32] = &[
    0x0030, 0x0660, 0x06F0, 0x07C0, 0x0966, 0x09E6, 0x0A66, 0x0AE6, 0x0B66, 0x0BE6, 0x0C66, 0x0CE6, 0x0D66, 0x0DE6,
    0x0E50, 0x0ED0, 0x0F20, 0x1040, 0x1090, 0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80, 0x1A90, 0x1B50, 0x1BB0, 0x1C40,
    0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50, 0xABF0, 0xFF10, 0x104A0, 0x10D30, 0x11066, 0x110F0,
    0x11136, 0x111D0, 0x112F0, 0x11450, 0x114D0, 0x11650, 0x116C0, 0x11730, 0x118E0, 0x11950, 0x11C50, 0x11D50,
    0x11DA0, 0x11DE0, 0x11F50, 0x16A60, 0x16AC0, 0x16B50, 0x16D70, 0x1CCF0, 0x1E140, 0x1E2F0, 0x1E4F0, 0x1E5F1,
    0x1E950, 0x1FBF0,
];

fn is_decimal_digit(c: char) -> bool {
    let code = c as u32;
    if (0x1D7CE..=0x1D7FF).contains(&code) {
        return true;
    }
    DIGIT_BLOCKS.iter().any(|zero| (*zero..*zero + 10).contains(&code))
}

/// True when the text has only the characters that S3 allows in a tag: letters, digits, spaces and `+ - = . _ : / @`.
fn valid_tag_text(text: &str) -> bool {
    text.chars().all(|c| {
        (c.is_alphabetic() && !c.is_numeric()) || is_decimal_digit(c) || c.is_whitespace() || "+-=._:/@".contains(c)
    })
}

/// Check a set of tags against the limits of S3: 10 tags, a key of 1 to 128 characters that is unique and does not
/// start with `aws:`, a value of 0 to 256 characters.
pub fn validate_tags(tags: &[Tag]) -> Result<()> {
    if tags.len() > MAX_OBJECT_TAGS {
        return Err(invalid_tags(format!(
            "an object has at most {MAX_OBJECT_TAGS} tags, got {}",
            tags.len()
        )));
    }
    let mut seen: Vec<&str> = Vec::with_capacity(tags.len());
    for tag in tags {
        let key_length = tag.key.chars().count();
        if key_length == 0 || key_length > MAX_TAG_KEY_CHARS {
            return Err(invalid_tags(format!(
                "a tag key has 1 to {MAX_TAG_KEY_CHARS} characters, got {key_length}"
            )));
        }
        if tag.value.chars().count() > MAX_TAG_VALUE_CHARS {
            return Err(invalid_tags(format!(
                "the value of the tag {} has at most {MAX_TAG_VALUE_CHARS} characters",
                super::quote_text(&tag.key)
            )));
        }
        if tag.key.to_lowercase().starts_with("aws:") {
            return Err(invalid_tags(format!(
                "the tag key {} starts with the reserved prefix aws:",
                super::quote_text(&tag.key)
            )));
        }
        if !valid_tag_text(&tag.key) || !valid_tag_text(&tag.value) {
            return Err(invalid_tags(format!(
                "the tag {} has a character that S3 does not allow: use letters, digits, spaces and + - = . _ : / @",
                super::quote_text(&tag.key)
            )));
        }
        if seen.contains(&tag.key.as_str()) {
            return Err(invalid_tags(format!(
                "the tag key {} is twice in the request",
                super::quote_text(&tag.key)
            )));
        }
        seen.push(&tag.key);
    }
    Ok(())
}

/// The tags of an object after the change. The result is sorted by key. A key that the change removes and adds
/// stays: the addition wins.
pub fn apply_tag_change(current: &[Tag], change: &TagChange) -> Vec<Tag> {
    let mut by_key: BTreeMap<&str, &str> = BTreeMap::new();
    for tag in current {
        by_key.insert(&tag.key, &tag.value);
    }
    for key in &change.remove {
        by_key.remove(key.as_str());
    }
    for tag in &change.add {
        by_key.insert(&tag.key, &tag.value);
    }
    by_key.into_iter().map(|(key, value)| Tag::new(key, value)).collect()
}

/// True when two lists have the same tags in the same order.
pub fn same_tags(left: &[Tag], right: &[Tag]) -> bool {
    left == right
}

/// The set of the tags of an upload by key: the last value of a key wins.
fn tags_by_key(tags: &[Tag]) -> BTreeMap<&str, &str> {
    tags.iter().map(|tag| (tag.key.as_str(), tag.value.as_str())).collect()
}

/// The value of the header `x-amz-tagging` for a set of tags: `a=1&b=2`, in the order of the keys.
pub fn encode_tagging(tags: &[Tag]) -> String {
    let pairs: Vec<(&str, &str)> = tags_by_key(tags).into_iter().collect();
    encode_sorted(&pairs)
}

/// The context of an upload that carries the tags. No tag gives the same context.
pub fn with_upload_tags(ctx: &OpCtx, tags: &[Tag]) -> OpCtx {
    if tags.is_empty() {
        return ctx.clone();
    }
    OpCtx {
        upload_tags: Some(tags.into()),
        ..ctx.clone()
    }
}

/// The value of the header `x-amz-tagging` that the upload of the context sends, or `None` without tags.
pub fn upload_tagging_header(ctx: &OpCtx) -> Option<String> {
    let tags = ctx.upload_tags.as_ref()?;
    if tags.is_empty() {
        return None;
    }
    Some(encode_tagging(tags))
}

/// Read a query text strictly: the parts split at `&`, each part at its first `=`, `+` is a space. A part with
/// `;` or with a bad escape is a fault. The values of one key join in order.
fn parse_query_strict(raw: &str) -> Option<BTreeMap<String, String>> {
    let mut values: BTreeMap<String, String> = BTreeMap::new();
    for part in raw.split('&') {
        if part.contains(';') {
            return None;
        }
        if part.is_empty() {
            continue;
        }
        let (key, value) = part.split_once('=').unwrap_or((part, ""));
        let key = unescape(key, true)?;
        let value = unescape(value, true)?;
        values.entry(key).or_default().push_str(&value);
    }
    Some(values)
}

/// Read the header `X-Amz-Tagging` of an upload: the tags as a query text (`a=b&c=d`).
pub fn parse_tagging_header(headers: &HeaderMap) -> Result<Vec<Tag>> {
    let raw = headers
        .get("x-amz-tagging")
        .map(|value| String::from_utf8_lossy(value.as_bytes()).trim().to_owned())
        .unwrap_or_default();
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    let Some(values) = parse_query_strict(&raw) else {
        return Err(invalid_tags("X-Amz-Tagging must be a query string such as a=b&c=d"));
    };
    let tags: Vec<Tag> = values.into_iter().map(|(key, value)| Tag { key, value }).collect();
    validate_tags(&tags)?;
    Ok(tags)
}

// --- Instance ----------------------------------------------------------------------------------------------------

impl Instance {
    /// True when the instance keeps object tags. A provider that does not know the tag requests answers 501, or
    /// accepts the header `x-amz-tagging` and drops the tags without a word. The page must know it before an upload.
    /// Until the probe has run, the answer is yes.
    pub fn tags_available(&self) -> bool {
        self.backend.tagger().is_some() && !self.tags.off.load(Ordering::SeqCst)
    }

    /// Read the tags of an object that does not exist. A provider with tags answers "no such key". A provider
    /// without tags answers 501 or 405. Any other failure (denied, timeout) leaves the answer at yes.
    pub async fn probe_tags(&self, ctx: &OpCtx) {
        let Some(tagger) = self.backend.tagger() else {
            return;
        };
        let probe = ctx.with_timeout(PROBE_TIMEOUT);
        let key = self.full_key(TAGS_PROBE_KEY);
        let result = probe.run(tagger.get_tags(&probe, &key, "")).await;
        if let Err(error) = result
            && provider_refused_feature(&error)
        {
            self.tags.off.store(true, Ordering::SeqCst);
        }
    }

    /// Refuse tags for an instance that does not keep them: the provider would drop them without a word.
    pub fn require_tags(&self, tags: &[Tag]) -> Result<()> {
        if !tags.is_empty() && !self.tags_available() {
            return Err(tagging_unsupported());
        }
        Ok(())
    }

    /// The version that a tag request names. A bucket with versioning gets the version of the object that a HEAD
    /// request reports, `null` for an object made before the versioning. A provider such as SeaweedFS takes more
    /// than ten seconds to read the tags of such an object when no version is named. Other buckets get an empty text.
    pub async fn tag_version(&self, ctx: &OpCtx, key: &str, version: &str) -> Result<String> {
        if !version.is_empty() || !self.versions_found() {
            return Ok(version.to_owned());
        }
        let response = self.head(ctx, key).await?;
        let reported = response
            .headers
            .get("x-amz-version-id")
            .map(|value| String::from_utf8_lossy(value.as_bytes()).trim().to_owned())
            .unwrap_or_default();
        Ok(reported)
    }

    /// The tags of an object (an empty version: the current object).
    pub async fn get_tags(&self, ctx: &OpCtx, key: &str, version: &str) -> Result<Vec<Tag>> {
        let tagger = match self.backend.tagger() {
            Some(tagger) if !self.tags.off.load(Ordering::SeqCst) => tagger,
            _ => return Err(tagging_unsupported()),
        };
        let version = self.tag_version(ctx, key, version).await?;
        let slot = self.begin_lifecycle_call(ctx).await?;
        let result = tagger.get_tags(ctx, key, &version).await;
        drop(slot);
        if let Err(error) = &result
            && provider_refused_feature(error)
        {
            return Err(tagging_unsupported());
        }
        self.observe_lifecycle_call(crate::common::config::PERMISSION_READ, result.as_ref().err());
        result
    }

    /// Replace the tags of an object. An empty list removes them all.
    pub async fn put_tags(&self, ctx: &OpCtx, key: &str, version: &str, tags: &[Tag]) -> Result<()> {
        let tagger = match self.backend.tagger() {
            Some(tagger) if !self.tags.off.load(Ordering::SeqCst) => tagger,
            _ => return Err(tagging_unsupported()),
        };
        let version = self.tag_version(ctx, key, version).await?;
        let slot = self.begin_lifecycle_call(ctx).await?;
        let result = tagger.put_tags(ctx, key, &version, tags).await;
        drop(slot);
        if let Err(error) = &result
            && provider_refused_feature(error)
        {
            return Err(tagging_unsupported());
        }
        self.observe_lifecycle_call(crate::common::config::PERMISSION_WRITE, result.as_ref().err());
        result
    }
}

// --- HTTP answers ------------------------------------------------------------------------------------------------

/// The answer of `/api/tags`.
#[derive(Clone, Debug, Serialize)]
pub struct TagsResponse {
    /// The instance.
    pub instance: String,
    /// The key, relative to the root prefix.
    pub key: String,
    /// The version.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version: String,
    /// The tags.
    pub tags: Vec<Tag>,
    /// The most tags of an object.
    #[serde(rename = "maxTags")]
    pub max_tags: usize,
}

// --- Job ---------------------------------------------------------------------------------------------------------

const STATUS_QUEUED: &str = "queued";
const STATUS_RUNNING: &str = "running";
const STATUS_PAUSED: &str = "paused";
const STATUS_CANCELED: &str = "canceled";
/// The most objects of one page of the walk.
const WALK_PAGE: usize = 1000;

/// What the walk of a job needs from the job manager.
pub(crate) trait JobHost: Sync {
    /// `Err(Error::Interrupted)` when a person paused or canceled the job.
    fn control(&self) -> Result<()>;
    /// The job as the manager has it now.
    fn latest(&self) -> Option<JobState>;
    /// Save the progress.
    fn save(&self, job: &JobState) -> Result<()>;
}

impl JobHost for JobRun {
    fn control(&self) -> Result<()> {
        self.check_control()
    }

    fn latest(&self) -> Option<JobState> {
        self.app.jobs.get(&self.id)
    }

    fn save(&self, job: &JobState) -> Result<()> {
        JobRun::save(self, job)
    }
}

/// Run the job `tag_prefix`: change the tags of each object under the prefix of the job. An object that already
/// has the result is not written again.
pub async fn run_tag_job(run: &JobRun, job: &mut JobState) -> Result<()> {
    let instance = run.app.instance(&job.instance)?.clone();
    walk_tag_job(run, &instance, &run.ctx, job).await
}

pub(crate) async fn walk_tag_job(
    host: &dyn JobHost,
    instance: &Instance,
    ctx: &OpCtx,
    job: &mut JobState,
) -> Result<()> {
    instance.require_permission(crate::common::config::PERMISSION_READ)?;
    instance.require_permission(crate::common::config::PERMISSION_WRITE)?;
    let Some(change) = job.tag_change.clone() else {
        return Err(invalid_tags("the tag job has no change"));
    };
    let prefix = if job.prefix.is_empty() {
        job.source.clone()
    } else {
        job.prefix.clone()
    };
    let full_prefix = instance.full_key(&prefix);
    let mut last_key = job.last_key.clone();
    let mut processed_this_run = 0i64;
    loop {
        let options = ListOptions {
            prefix: full_prefix.clone(),
            delimiter: String::new(),
            max_results: WALK_PAGE as u32,
            page_token: String::new(),
            start_after: if last_key.is_empty() {
                String::new()
            } else {
                instance.full_key(&last_key)
            },
        };
        let mut page = instance.list(ctx, &options).await?;
        page.objects.sort_by(|left, right| left.key.cmp(&right.key));
        let mut progressed = false;
        for object in &page.objects {
            let Some(relative) = instance.relative_key(&object.key) else {
                continue;
            };
            if relative.is_empty() || !relative.starts_with(&prefix) || (!last_key.is_empty() && relative <= last_key) {
                continue;
            }
            host.control()?;
            change_tags_of(instance, ctx, &relative, &change).await?;
            job.processed += 1;
            processed_this_run += 1;
            job.last_key.clone_from(&relative);
            job.updated_at = Timestamp::now();
            if let Some(latest) = host.latest() {
                job.status = latest.status;
                job.ended_at = latest.ended_at;
                if job.status == STATUS_QUEUED {
                    job.status = STATUS_RUNNING.to_owned();
                }
            }
            host.save(job)?;
            match job.status.as_str() {
                STATUS_PAUSED => return Err(Error::Interrupted(Interrupt::Paused)),
                STATUS_CANCELED => return Err(Error::Interrupted(Interrupt::Canceled)),
                _ => {}
            }
            last_key = relative;
            progressed = true;
        }
        if !progressed || (page.next_page_token.is_empty() && page.objects.len() < WALK_PAGE) {
            break;
        }
    }
    if job.processed == 0 && processed_this_run == 0 {
        return Err(Error::api(404, "empty_prefix", "source prefix contains no objects"));
    }
    Ok(())
}

/// Change the tags of one object. An object that already has the result is not written.
async fn change_tags_of(instance: &Instance, ctx: &OpCtx, relative: &str, change: &TagChange) -> Result<()> {
    let full_key = instance.full_key(relative);
    let version = instance.tag_version(ctx, &full_key, "").await?;
    let current = instance.get_tags(ctx, &full_key, &version).await?;
    let next = apply_tag_change(&current, change);
    if same_tags(&current, &next) {
        return Ok(());
    }
    if let Err(error) = validate_tags(&next) {
        let message = error.as_api().map(|api| api.message.clone()).unwrap_or_default();
        return Err(invalid_tags(format!("{relative}: {message}")));
    }
    instance.put_tags(ctx, &full_key, &version, &next).await
}

/// The job that a request of `/api/tags/bulk` creates.
pub(crate) fn tag_job(instance: &str, prefix: &str, change: TagChange) -> JobState {
    JobState {
        job_type: job_type::TAG_PREFIX.to_owned(),
        instance: instance.to_owned(),
        prefix: prefix.to_owned(),
        tag_change: Some(change),
        ..JobState::default()
    }
}
