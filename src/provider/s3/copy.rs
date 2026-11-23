// SPDX-License-Identifier: MIT OR Apache-2.0
//! The copy of an object in parts on the provider (S3 `UploadPartCopy`).
//!
//! `CopyObject` refuses a source above 5 GiB. From [`multipart_copy_threshold`] up, a copy, a move or a rename starts
//! a multipart upload, lets the provider copy each byte range of the source into one part, and completes the upload.
//! No byte of the object goes through this process (docs/ARCHITECTURE.md, "Copy in parts").

use std::future::Future as _;
use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

use http::HeaderMap;
use http::Method;
use http::header::{
    CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_ENCODING, CONTENT_LANGUAGE, CONTENT_LENGTH, CONTENT_TYPE, ETAG,
    EXPIRES, HeaderName,
};

use super::{S3Backend, embedded_error, provider_refused_feature, response_error, set_header, trim_quotes};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::misc::CancelToken;
use crate::common::storage::{CompletedPart, CopyProgress, MultipartCopyOptions, RequestGate};
use crate::instance::gate::Slot;
use crate::lifecycle::Tag;
use crate::provider::client::header_text;
use crate::provider::xml::{self, Node, at};

/// The number of parts that the provider copies at the same time. The gates of the instance can lower it.
pub const MULTIPART_COPY_PARALLEL: usize = 4;
/// The S3 limit of parts in one multipart upload.
pub const MAX_MULTIPART_PARTS: i64 = 10_000;
/// The S3 limit of the size of a part, the last part excepted: at least 5 MiB.
pub const MIN_COPY_PART_SIZE: i64 = 5 << 20;
/// The S3 limit of the size of a part: at most 5 GiB.
pub const MAX_COPY_PART_SIZE: i64 = 5 << 30;
/// The time that the abort of a failed or canceled copy can take.
pub const MULTIPART_ABORT_TIMEOUT: Duration = Duration::from_secs(30);
/// The source size from which a copy goes in parts: 5 GiB minus a margin of 256 MiB.
pub const DEFAULT_MULTIPART_COPY_THRESHOLD: i64 = (5 << 30) - (256 << 20);
/// The size of each part, the last part excepted.
pub const DEFAULT_MULTIPART_COPY_PART_SIZE: i64 = 256 << 20;

static THRESHOLD: AtomicI64 = AtomicI64::new(DEFAULT_MULTIPART_COPY_THRESHOLD);
static PART_SIZE: AtomicI64 = AtomicI64::new(DEFAULT_MULTIPART_COPY_PART_SIZE);

/// The standard headers that a copy keeps from the source, as `CopyObject` does.
pub const COPIED_OBJECT_HEADERS: [HeaderName; 6] = [
    CONTENT_TYPE,
    CACHE_CONTROL,
    CONTENT_DISPOSITION,
    CONTENT_ENCODING,
    CONTENT_LANGUAGE,
    EXPIRES,
];

/// The source size from which a copy goes in parts.
pub fn multipart_copy_threshold() -> i64 {
    THRESHOLD.load(Ordering::Relaxed)
}

/// The size of each part of a copy in parts, the last part excepted.
pub fn multipart_copy_part_size() -> i64 {
    PART_SIZE.load(Ordering::Relaxed)
}

/// Set the threshold and the part size of the copy in parts. The test image and the tests use smaller values.
pub fn set_multipart_copy_settings(threshold: i64, part_size: i64) {
    THRESHOLD.store(threshold, Ordering::Relaxed);
    PART_SIZE.store(part_size, Ordering::Relaxed);
}

/// Check the values of the build: the threshold from 1 byte to 5 GiB, the part size from 5 MiB to 5 GiB. The result
/// is the threshold, the part size (each when the build gives it) and one log line for each value.
pub fn check_build_settings(
    threshold: Option<&str>,
    part_size: Option<&str>,
) -> Result<(Option<i64>, Option<i64>, Vec<String>)> {
    let mut notes = Vec::new();
    let mut checked_threshold = None;
    let mut checked_part_size = None;
    if let Some(raw) = threshold.map(str::trim).filter(|raw| !raw.is_empty()) {
        match raw.parse::<i64>() {
            Ok(value) if (1..=MAX_COPY_PART_SIZE).contains(&value) => {
                checked_threshold = Some(value);
                notes.push(format!(
                    "build.multipart_copy_threshold = {value}  # set at build time, for tests"
                ));
            }
            _ => {
                return Err(Error::internal(format!(
                    "build value STOWR_MULTIPART_COPY_THRESHOLD must be an integer from 1 to {MAX_COPY_PART_SIZE} bytes, got {raw:?}"
                )));
            }
        }
    }
    if let Some(raw) = part_size.map(str::trim).filter(|raw| !raw.is_empty()) {
        match raw.parse::<i64>() {
            Ok(value) if (MIN_COPY_PART_SIZE..=MAX_COPY_PART_SIZE).contains(&value) => {
                checked_part_size = Some(value);
                notes.push(format!(
                    "build.multipart_copy_part_size = {value}  # set at build time, for tests"
                ));
            }
            _ => {
                return Err(Error::internal(format!(
                    "build value STOWR_MULTIPART_COPY_PART_SIZE must be an integer from {MIN_COPY_PART_SIZE} to {MAX_COPY_PART_SIZE} bytes, got {raw:?}"
                )));
            }
        }
    }
    Ok((checked_threshold, checked_part_size, notes))
}

/// Apply the values that the build gave (`STOWR_MULTIPART_COPY_THRESHOLD` and `STOWR_MULTIPART_COPY_PART_SIZE` at
/// compile time). Call it one time at start: a value that is not an integer in its range stops the start. The result
/// has one log line for each value that the build changed.
pub fn apply_multipart_copy_build_settings() -> Result<Vec<String>> {
    let (threshold, part_size, notes) = check_build_settings(
        option_env!("STOWR_MULTIPART_COPY_THRESHOLD"),
        option_env!("STOWR_MULTIPART_COPY_PART_SIZE"),
    )?;
    if let Some(value) = threshold {
        THRESHOLD.store(value, Ordering::Relaxed);
    }
    if let Some(value) = part_size {
        PART_SIZE.store(value, Ordering::Relaxed);
    }
    Ok(notes)
}

/// The byte range of the source that one part copies. `first` and `last` are included.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CopyPartRange {
    /// The part number, from 1.
    pub number: u32,
    /// The first byte.
    pub first: i64,
    /// The last byte.
    pub last: i64,
}

impl CopyPartRange {
    /// The size of the part.
    pub fn size(&self) -> i64 {
        self.last - self.first + 1
    }
}

/// Divide `size` bytes into parts of `part_size` bytes; the last part has the remainder. When more than 10000 parts
/// are necessary, the parts become larger, in steps of 1 MiB.
pub fn copy_part_ranges(size: i64, part_size: i64) -> Result<Vec<CopyPartRange>> {
    if size <= 0 {
        return Err(Error::internal(format!(
            "a copy in parts needs a source of 1 byte or more, got {size}"
        )));
    }
    if part_size <= 0 {
        return Err(Error::internal(format!(
            "the part size must be positive, got {part_size}"
        )));
    }
    let mut part_size = part_size;
    let ceil_div = |value: i64, divisor: i64| (value + divisor - 1) / divisor;
    if ceil_div(size, part_size) > MAX_MULTIPART_PARTS {
        const STEP: i64 = 1 << 20;
        part_size = ceil_div(ceil_div(size, MAX_MULTIPART_PARTS), STEP) * STEP;
    }
    if part_size > MAX_COPY_PART_SIZE {
        return Err(Error::internal(format!(
            "a source of {size} bytes needs parts larger than the S3 limit of {MAX_COPY_PART_SIZE} bytes"
        )));
    }
    let mut ranges = Vec::new();
    let mut first = 0;
    while first < size {
        let last = (first + part_size).min(size) - 1;
        let number = u32::try_from(ranges.len() + 1).unwrap_or(u32::MAX);
        ranges.push(CopyPartRange { number, first, last });
        first += part_size;
    }
    Ok(ranges)
}

/// The headers of [`COPIED_OBJECT_HEADERS`] and the `x-amz-meta-*` headers of an answer or of a request.
pub fn copy_metadata_headers(source: &HeaderMap) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for name in &COPIED_OBJECT_HEADERS {
        if let Some(value) = source.get(name).filter(|value| !value.as_bytes().is_empty()) {
            headers.insert(name.clone(), value.clone());
        }
    }
    for name in source.keys() {
        if name.as_str().starts_with("x-amz-meta-") {
            for value in source.get_all(name) {
                headers.append(name.clone(), value.clone());
            }
        }
    }
    headers
}

/// Take a slot of the gate of a copy, or no slot without a gate.
async fn take_slot(gate: &Option<RequestGate>, ctx: &OpCtx) -> Result<Option<Slot>> {
    match gate {
        Some(gate) => gate(ctx.clone()).await.map(Some),
        None => Ok(None),
    }
}

/// Add a note to the text of an error that has a text. The other errors stay as they are.
fn with_note(error: Error, note: &str) -> Error {
    match error {
        Error::Upstream(mut upstream) => {
            upstream.message = format!("{}{note}", upstream.message);
            Error::Upstream(upstream)
        }
        Error::Connect(text) => Error::Connect(format!("{text}{note}")),
        Error::Internal(text) => Error::Internal(format!("{text}{note}")),
        other => other,
    }
}

impl S3Backend {
    /// The tags of an object (an empty version: the current object), in the order of the keys.
    pub async fn object_tags(&self, ctx: &OpCtx, key: &str, version: &str) -> Result<Vec<Tag>> {
        let mut query = vec![("tagging".to_owned(), String::new())];
        if !version.is_empty() {
            query.push(("versionId".to_owned(), version.to_owned()));
        }
        let response = self.execute_ok(ctx, Method::GET, key, &query, HeaderMap::new()).await?;
        let body = Self::read_body(response, super::SMALL_LIMIT, "decode s3 tagging response").await?;
        let mut tags: Vec<Tag> = Vec::new();
        xml::walk(&body, |node| match node {
            Node::Start(path) if at(path, &["TagSet", "Tag"]) => tags.push(Tag::default()),
            Node::Start(_) => {}
            Node::End(path, text) => {
                if let Some(tag) = tags.last_mut() {
                    if at(path, &["TagSet", "Tag", "Key"]) {
                        tag.key = text;
                    } else if at(path, &["TagSet", "Tag", "Value"]) {
                        tag.value = text;
                    }
                }
            }
        })
        .map_err(|error| Error::internal(format!("decode s3 tagging response: {error}")))?;
        tags.sort_by(|left, right| left.key.cmp(&right.key));
        Ok(tags)
    }

    /// Copy the source to the destination in parts: `CreateMultipartUpload` with the metadata and the tags,
    /// `UploadPartCopy` for each byte range, `CompleteMultipartUpload`. Each part names the ETag of the source, so a
    /// source that changes during the copy makes it fail. On any error, and on a cancel, the upload is aborted.
    pub async fn copy_in_parts(
        &self,
        ctx: &OpCtx,
        source: &str,
        destination: &str,
        options: MultipartCopyOptions,
        part_size: i64,
    ) -> Result<()> {
        let head = {
            let _slot = take_slot(&options.gate, ctx).await?;
            let version = Some(options.source_version.as_str()).filter(|version| !version.is_empty());
            self.head_object(ctx, source, version).await?
        };
        let source_etag = header_text(&head.headers, &ETAG).trim().to_owned();
        if !options.expected_etag.is_empty() && trim_quotes(&source_etag) != options.expected_etag {
            return Err(Error::upstream(
                412,
                "PreconditionFailed",
                "the ETag of the source is not the ETag that the caller read",
            ));
        }
        let size = header_text(&head.headers, &CONTENT_LENGTH)
            .trim()
            .parse::<i64>()
            .map_err(|_| Error::internal("the provider gave no size for the source of the copy"))?;
        let ranges = copy_part_ranges(size, part_size)?;
        let mut headers = match &options.metadata {
            Some(metadata) => copy_metadata_headers(metadata),
            None => copy_metadata_headers(&head.headers),
        };
        let tags = match &options.tags {
            Some(tags) => tags.clone(),
            None => crate::lifecycle::encode_tagging(&self.source_tags(ctx, &options, source, &head.headers).await?),
        };
        if !tags.is_empty() {
            set_header(&mut headers, "x-amz-tagging", &tags)?;
        }
        for name in options.extra_headers.keys() {
            headers.remove(name);
            for value in options.extra_headers.get_all(name) {
                headers.append(name.clone(), value.clone());
            }
        }
        let upload_id = {
            let _slot = take_slot(&options.gate, ctx).await?;
            self.initiate_multipart_with(ctx, destination, headers).await?
        };
        let result = async {
            let parts = self
                .copy_parts(ctx, &options, source, &source_etag, destination, &upload_id, &ranges)
                .await?;
            let _slot = take_slot(&options.gate, ctx).await?;
            self.complete_multipart(ctx, destination, &upload_id, &parts).await
        }
        .await;
        let Err(error) = result else {
            return Ok(());
        };
        // The context of the copy can be canceled: the abort gets its own time and no slot of the gate.
        let mut abort_ctx = ctx.detached();
        abort_ctx.deadline = None;
        let abort_ctx = abort_ctx.with_timeout(MULTIPART_ABORT_TIMEOUT);
        match self.abort_multipart(&abort_ctx, destination, &upload_id).await {
            Ok(()) => Err(error),
            Err(abort_error) => Err(with_note(
                error,
                &format!(" (the abort of the multipart upload {upload_id} also failed: {abort_error})"),
            )),
        }
    }

    /// The tags of the source. A source with `x-amz-tagging-count: 0` needs no request. A provider without tags
    /// (`501` or `405`) gives no tag.
    async fn source_tags(
        &self,
        ctx: &OpCtx,
        options: &MultipartCopyOptions,
        source: &str,
        head: &HeaderMap,
    ) -> Result<Vec<Tag>> {
        if header_text(head, &HeaderName::from_static("x-amz-tagging-count")).trim() == "0" {
            return Ok(Vec::new());
        }
        let _slot = take_slot(&options.gate, ctx).await?;
        match self.object_tags(ctx, source, &options.source_version).await {
            Err(error) if provider_refused_feature(&error) => Ok(Vec::new()),
            other => other,
        }
    }

    /// Let the provider copy the ranges, [`MULTIPART_COPY_PARALLEL`] at the same time. The first error stops the parts
    /// that run and the parts that did not start.
    #[allow(clippy::too_many_arguments)]
    async fn copy_parts(
        &self,
        ctx: &OpCtx,
        options: &MultipartCopyOptions,
        source: &str,
        source_etag: &str,
        destination: &str,
        upload_id: &str,
        ranges: &[CopyPartRange],
    ) -> Result<Vec<CompletedPart>> {
        let stop = CancelToken::new();
        let part_ctx = OpCtx {
            cancel: stop.clone(),
            ..ctx.clone()
        };
        let next = AtomicUsize::new(0);
        let state_cell: Mutex<(Vec<Option<CompletedPart>>, Option<Error>)> =
            Mutex::new((vec![None; ranges.len()], None));
        let progress: Option<&CopyProgress> = options.progress.as_ref();
        let (stop, next, state, part_ctx) = (&stop, &next, &state_cell, &part_ctx);
        let worker = || async move {
            loop {
                if stop.is_canceled() {
                    break;
                }
                let index = next.fetch_add(1, Ordering::SeqCst);
                let Some(part) = ranges.get(index) else {
                    break;
                };
                let result = self
                    .upload_part_copy_gated(part_ctx, options, source, source_etag, destination, upload_id, part)
                    .await;
                let Ok(mut state) = state.lock() else {
                    break;
                };
                match result {
                    Err(error) => {
                        if state.1.is_none() {
                            state.1 = Some(error);
                            stop.cancel();
                        }
                    }
                    Ok(etag) => {
                        state.0[index] = Some(CompletedPart {
                            number: part.number,
                            etag,
                            checksum_sha256: String::new(),
                        });
                        if let Some(progress) = progress {
                            progress(part.size());
                        }
                    }
                }
            }
        };
        let count = MULTIPART_COPY_PARALLEL.min(ranges.len());
        let mut workers: Vec<_> = (0..count).map(|_| Some(Box::pin(worker()))).collect();
        let all = std::future::poll_fn(|cx| {
            let mut pending = false;
            for slot in &mut workers {
                if let Some(future) = slot {
                    if future.as_mut().poll(cx).is_ready() {
                        *slot = None;
                    } else {
                        pending = true;
                    }
                }
            }
            if pending { Poll::Pending } else { Poll::Ready(()) }
        });
        ctx.run(async {
            all.await;
            Ok(())
        })
        .await?;
        drop(workers);
        let (parts, failure) = state_cell
            .into_inner()
            .map_err(|_| Error::internal("the state of the copy in parts is not readable"))?;
        if let Some(error) = failure {
            return Err(error);
        }
        ctx.check()?;
        parts
            .into_iter()
            .map(|part| part.ok_or_else(|| Error::internal("a part of the copy in parts is missing")))
            .collect()
    }

    #[allow(clippy::too_many_arguments)]
    async fn upload_part_copy_gated(
        &self,
        ctx: &OpCtx,
        options: &MultipartCopyOptions,
        source: &str,
        source_etag: &str,
        destination: &str,
        upload_id: &str,
        part: &CopyPartRange,
    ) -> Result<String> {
        ctx.check()?;
        let _slot = take_slot(&options.gate, ctx).await?;
        ctx.run(self.upload_part_copy(
            ctx,
            source,
            &options.source_version,
            source_etag,
            destination,
            upload_id,
            part,
        ))
        .await
    }

    /// Let the provider copy one byte range of the source into one part of the multipart upload. An ETag that is not
    /// empty makes the provider refuse a source that changed.
    #[allow(clippy::too_many_arguments)]
    pub async fn upload_part_copy(
        &self,
        ctx: &OpCtx,
        source: &str,
        version: &str,
        source_etag: &str,
        destination: &str,
        upload_id: &str,
        part: &CopyPartRange,
    ) -> Result<String> {
        let query = [
            ("partNumber".to_owned(), part.number.to_string()),
            ("uploadId".to_owned(), upload_id.to_owned()),
        ];
        let mut headers = HeaderMap::new();
        set_header(
            &mut headers,
            "x-amz-copy-source",
            &self.copy_source_header(source, version),
        )?;
        set_header(
            &mut headers,
            "x-amz-copy-source-range",
            &format!("bytes={}-{}", part.first, part.last),
        )?;
        if !source_etag.is_empty() {
            set_header(&mut headers, "x-amz-copy-source-if-match", source_etag)?;
        }
        let response = self
            .execute(ctx, Method::PUT, destination, &query, headers, None)
            .await?;
        if !super::success(response.status().as_u16()) {
            return Err(response_error(response).await);
        }
        let body = Self::read_body(response, super::SMALL_LIMIT, "read s3 upload part copy response").await?;
        // Some S3 implementations answer 200 with an Error document.
        if let Some(error) = embedded_error(&body) {
            return Err(error);
        }
        let mut etag = String::new();
        xml::walk(&body, |node| {
            if let Node::End(path, text) = node
                && at(path, &["ETag"])
            {
                etag = text;
            }
        })
        .map_err(|error| Error::internal(format!("decode s3 upload part copy response: {error}")))?;
        let etag = trim_quotes(etag.trim()).to_owned();
        if etag.is_empty() {
            return Err(Error::internal("s3 upload part copy did not return an ETag"));
        }
        Ok(etag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_part_ranges_cover_the_source_once() {
        let ranges = copy_part_ranges(12, 5).unwrap();
        let want = vec![
            CopyPartRange {
                number: 1,
                first: 0,
                last: 4,
            },
            CopyPartRange {
                number: 2,
                first: 5,
                last: 9,
            },
            CopyPartRange {
                number: 3,
                first: 10,
                last: 11,
            },
        ];
        assert_eq!(ranges, want);
        let ranges = copy_part_ranges(10, 5).unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[1].last, 9);
        let ranges = copy_part_ranges(1, 5).unwrap();
        assert_eq!(
            ranges,
            vec![CopyPartRange {
                number: 1,
                first: 0,
                last: 0
            }]
        );
    }

    #[test]
    fn copy_part_ranges_grow_the_parts_above_ten_thousand_parts() {
        let size: i64 = 5 << 40;
        let ranges = copy_part_ranges(size, 256 << 20).unwrap();
        assert!(ranges.len() as i64 <= MAX_MULTIPART_PARTS, "{} parts", ranges.len());
        let part_size = ranges[0].size();
        assert!(
            part_size % (1 << 20) == 0 && part_size <= MAX_COPY_PART_SIZE,
            "part size {part_size}"
        );
        let mut total = 0;
        for (index, part) in ranges.iter().enumerate() {
            assert_eq!(part.number as usize, index + 1);
            if index > 0 {
                assert_eq!(part.first, ranges[index - 1].last + 1);
            }
            total += part.size();
        }
        assert_eq!(total, size);
    }

    #[test]
    fn copy_part_ranges_refuse_an_empty_source() {
        assert!(copy_part_ranges(0, 5).is_err());
        assert!(copy_part_ranges(5, 0).is_err());
    }

    #[test]
    fn the_build_settings_of_the_copy_in_parts() {
        let (threshold, part_size, notes) = check_build_settings(None, None).unwrap();
        assert!(threshold.is_none() && part_size.is_none() && notes.is_empty());
        let (threshold, part_size, notes) = check_build_settings(Some("8192"), Some("5242880")).unwrap();
        assert_eq!((threshold, part_size), (Some(8192), Some(5 << 20)));
        assert_eq!(
            notes,
            vec![
                "build.multipart_copy_threshold = 8192  # set at build time, for tests",
                "build.multipart_copy_part_size = 5242880  # set at build time, for tests",
            ]
        );
        for (threshold, part_size) in [
            (Some("0"), None),
            (Some("8k"), None),
            (None, Some("1024")),
            (None, Some("6442450944")),
        ] {
            assert!(
                check_build_settings(threshold, part_size).is_err(),
                "{threshold:?} and {part_size:?}: want an error"
            );
        }
        let error = check_build_settings(Some("8k"), None).err().unwrap();
        assert_eq!(
            error.to_string(),
            "build value STOWR_MULTIPART_COPY_THRESHOLD must be an integer from 1 to 5368709120 bytes, got \"8k\""
        );
    }

    #[test]
    fn the_copied_headers_are_the_standard_set_and_the_user_metadata() {
        let mut source = HeaderMap::new();
        source.insert(CONTENT_TYPE, "text/csv".parse().unwrap());
        source.insert("x-amz-meta-owner", "ops".parse().unwrap());
        source.insert("authorization", "ignored".parse().unwrap());
        source.insert(CACHE_CONTROL, "".parse().unwrap());
        let copied = copy_metadata_headers(&source);
        assert_eq!(copied.len(), 2);
        assert_eq!(copied.get(CONTENT_TYPE).unwrap(), "text/csv");
        assert_eq!(copied.get("x-amz-meta-owner").unwrap(), "ops");
    }
}
