//! The storage calls of an instance: the listing, the reads, the writes, the deletes, the copies, the moves, the
//! multipart uploads and the resumable uploads.
//!
//! Each call counts one provider request in the budget of the context and takes a slot of the gates. A read holds
//! its slot until its body ends or the caller drops it, and counts the bytes of the body in the budget. The ceilings
//! of the access policy apply before the first byte goes to the caller or to the provider.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};

use bytes::Bytes;
use http::HeaderMap;
use http_body::Frame;
use http_body_util::BodyExt;

use super::Instance;
use super::budget::Budget;
use super::ceiling::{
    ACTION_READ, ACTION_WRITE, ceiling_applies, check_copy_ceilings, check_read_answer, check_write_ceiling,
    header_text,
};
use super::gate::Slot;
use crate::bucket::is_object_locked;
use crate::common::config::{PERMISSION_DELETE, PERMISSION_READ, PERMISSION_WRITE};
use crate::common::ctx::{GateMode, OpCtx};
use crate::common::error::{BatchDeleteError, Error, Result};
use crate::common::http::Body;
use crate::common::storage::{
    CompletedPart, CopyProgress, ListOptions, ListPage, MultipartCopyOptions, MultipartPart, ObjectResponse,
};

/// The most keys of one batch delete.
pub const MAX_DELETE_BATCH: usize = 1000;

/// The most refused keys of one batch delete for which the instance reads the lock.
pub const MAX_LOCK_CHECKS: usize = 100;

/// The most requests that one page of a listing adds to look for empty folders.
pub const MAX_PREFIX_PROBES: usize = 200;

/// The most folder probes of one page at the same time.
const PREFIX_PROBE_PARALLEL: usize = 4;

/// The body of a read: it counts its bytes in the budget, and holds the slots of the gates until its end.
struct GuardedBody {
    inner: Body,
    budget: Option<Arc<Budget>>,
    slot: Option<Slot>,
}

impl http_body::Body for GuardedBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>>>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let (Some(data), Some(budget)) = (frame.data_ref(), &this.budget) {
                    let count = i64::try_from(data.len()).unwrap_or(i64::MAX);
                    if let Err(error) = budget.consume_bytes(count) {
                        this.slot = None;
                        return Poll::Ready(Some(Err(error)));
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                this.slot = None;
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                this.slot = None;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

/// An error for an answer 401 or 403 of a read: the provider denied the read.
fn access_denied(status: u16) -> Error {
    Error::upstream(status, "AccessDenied", "")
}

/// True for a provider that does not know the batch delete request.
pub fn batch_delete_unsupported(error: &Error) -> bool {
    error.as_upstream().is_some_and(|upstream| {
        upstream.status == 501
            || upstream.status == 405
            || upstream.code == "NotImplemented"
            || upstream.code == "MethodNotAllowed"
    })
}

/// True when the key goes through an XML document unchanged: no control character that XML 1.0 forbids.
pub fn xml_safe_key(key: &str) -> bool {
    key.chars().all(|c| {
        let code = u32::from(c);
        !((code < 0x20 && c != '\t' && c != '\n' && c != '\r') || code == 0xFFFE || code == 0xFFFF)
    })
}

/// Run futures with at most `limit` of them at the same time. The outputs keep the order of the futures.
pub(crate) async fn run_bounded<T, F>(futures: Vec<F>, limit: usize) -> Vec<T>
where
    F: Future<Output = T>,
{
    let total = futures.len();
    let mut waiting = futures.into_iter().enumerate();
    let mut running: Vec<(usize, Pin<Box<F>>)> = Vec::with_capacity(limit.max(1));
    let mut outputs: Vec<Option<T>> = (0..total).map(|_| None).collect();
    std::future::poll_fn(|cx| {
        loop {
            while running.len() < limit.max(1) {
                match waiting.next() {
                    Some((index, future)) => running.push((index, Box::pin(future))),
                    None => break,
                }
            }
            if running.is_empty() {
                return Poll::Ready(());
            }
            let mut finished = false;
            let mut position = 0;
            while position < running.len() {
                if let Poll::Ready(output) = running[position].1.as_mut().poll(cx) {
                    let (index, _) = running.swap_remove(position);
                    outputs[index] = Some(output);
                    finished = true;
                } else {
                    position += 1;
                }
            }
            if !finished {
                return Poll::Pending;
            }
        }
    })
    .await;
    outputs.into_iter().flatten().collect()
}

impl Instance {
    /// One page of a listing. With a delimiter, a folder that holds no object leaves the page (see
    /// [`Instance::without_empty_prefixes`]).
    pub async fn list(&self, ctx: &OpCtx, options: &ListOptions) -> Result<ListPage> {
        let slot = self.begin_storage_request(ctx).await?;
        let result = self.backend.list(ctx, options).await;
        drop(slot);
        self.observe_permission(PERMISSION_READ, result.as_ref().err());
        let mut page = result?;
        if !options.delimiter.is_empty() && !page.prefixes.is_empty() {
            page.prefixes = self
                .without_empty_prefixes(ctx, std::mem::take(&mut page.prefixes))
                .await;
        }
        Ok(page)
    }

    /// Remove the folders that hold no object. In a bucket with versions, MinIO keeps the folder of an object whose
    /// current version is a delete marker in the listing with a delimiter, and shows no key for it in the listing
    /// without a delimiter. The person then sees an empty folder, and a delete of that folder finds nothing. A
    /// provider that does not do this (AWS, SeaweedFS, Garage) costs no request. A probe that fails keeps its folder.
    pub async fn without_empty_prefixes(&self, ctx: &OpCtx, prefixes: Vec<String>) -> Vec<String> {
        if !self.versioning_available() {
            return prefixes;
        }
        let flavour = super::info::provider_flavour(self, ctx).await;
        if matches!(flavour.as_str(), "aws" | "seaweedfs" | "garage") {
            return prefixes;
        }
        let checked = prefixes.len().min(MAX_PREFIX_PROBES);
        let probes = prefixes[..checked]
            .iter()
            .map(|prefix| async move {
                let Ok(_slot) = self.begin_storage_request(ctx).await else {
                    return false;
                };
                let options = ListOptions {
                    prefix: prefix.clone(),
                    max_results: 1,
                    ..ListOptions::default()
                };
                matches!(self.backend.list(ctx, &options).await, Ok(page) if page.objects.is_empty())
            })
            .collect::<Vec<_>>();
        let empty = run_bounded(probes, PREFIX_PROBE_PARALLEL).await;
        prefixes
            .into_iter()
            .enumerate()
            .filter(|(index, _)| !empty.get(*index).copied().unwrap_or(false))
            .map(|(_, prefix)| prefix)
            .collect()
    }

    /// The headers of an object, or of the version of the context.
    pub async fn head(&self, ctx: &OpCtx, key: &str) -> Result<ObjectResponse> {
        let version = ctx.version().trim();
        if !version.is_empty() {
            return self.head_stored_version(ctx, key, version).await;
        }
        self.head_current(ctx, key).await
    }

    async fn head_current(&self, ctx: &OpCtx, key: &str) -> Result<ObjectResponse> {
        let _slot = self.begin_storage_request(ctx).await?;
        let result = match self.backend.head(ctx, key).await {
            Ok(response) if response.status == 401 || response.status == 403 => Err(access_denied(response.status)),
            other => other,
        };
        self.observe_permission(PERMISSION_READ, result.as_ref().err());
        result
    }

    /// The bytes of an object, or of the version of the context. The ceiling `object.read` applies to the size of
    /// the object before any byte goes to the caller.
    pub async fn get(&self, ctx: &OpCtx, key: &str, headers: &HeaderMap) -> Result<ObjectResponse> {
        let version = ctx.version().trim();
        if !version.is_empty() {
            return self.get_stored_version(ctx, key, version, headers).await;
        }
        let slot = self.begin_storage_request(ctx).await?;
        let result = self.backend.get(ctx, key, headers).await;
        self.finish_read(ctx, slot, result)
    }

    /// The common end of a read of an object or of a version: the denial, the ceiling, the budget of the bytes and
    /// the slot of the body.
    pub(crate) fn finish_read(
        &self,
        ctx: &OpCtx,
        slot: Slot,
        result: Result<ObjectResponse>,
    ) -> Result<ObjectResponse> {
        let response = match result {
            Ok(response) => response,
            Err(error) => {
                drop(slot);
                self.observe_permission(PERMISSION_READ, Some(&error));
                return Err(error);
            }
        };
        if response.status == 401 || response.status == 403 {
            drop(slot);
            let error = access_denied(response.status);
            self.observe_permission(PERMISSION_READ, Some(&error));
            return Err(error);
        }
        check_read_answer(ctx, response.status, &response.headers)?;
        let ObjectResponse { status, headers, body } = response;
        let body = GuardedBody {
            inner: body,
            budget: ctx.budget.clone(),
            slot: Some(slot),
        }
        .boxed_unsync();
        self.observe_permission(PERMISSION_READ, None);
        Ok(ObjectResponse { status, headers, body })
    }

    /// Write an object. The ceiling `object.write` applies before the first byte. A size below 0 is an unknown size.
    pub async fn put(&self, ctx: &OpCtx, key: &str, body: Body, size: i64, content_type: &str) -> Result<()> {
        check_write_ceiling(ctx, size)?;
        let _slot = self.begin_storage_request(ctx).await?;
        if let Some(budget) = &ctx.budget
            && size > 0
        {
            budget.consume_bytes(size)?;
        }
        let result = self.backend.put(ctx, key, body, size, content_type).await;
        self.observe_permission(PERMISSION_WRITE, result.as_ref().err());
        result
    }

    /// Write an object only when no current object exists at the key. S3 and GCS do it in one request with a
    /// precondition. A back end without the conditional write gets a HEAD, then the write.
    pub async fn put_if_absent(&self, ctx: &OpCtx, key: &str, body: Body, size: i64, content_type: &str) -> Result<()> {
        check_write_ceiling(ctx, size)?;
        if let Some(conditional) = self.backend.conditional_writer() {
            let _slot = self.begin_storage_request(ctx).await?;
            if let Some(budget) = &ctx.budget
                && size > 0
            {
                budget.consume_bytes(size)?;
            }
            let result = conditional.put_if_absent(ctx, key, body, size, content_type).await;
            self.observe_permission(PERMISSION_WRITE, result.as_ref().err());
            return result;
        }
        match self.head(ctx, key).await {
            Ok(_) => Err(Error::api(
                409,
                "object_exists",
                "an object already exists at the extraction destination",
            )),
            Err(error) if !error.is_not_found() => Err(error),
            Err(_) => self.put(ctx, key, body, size, content_type).await,
        }
    }

    /// Delete an object. A refusal that an active Object Lock explains gives `409 object_locked`.
    pub async fn delete(&self, ctx: &OpCtx, key: &str) -> Result<()> {
        let slot = self.begin_storage_request(ctx).await?;
        let result = self.backend.delete(ctx, key).await;
        drop(slot);
        match result {
            Ok(()) => {
                self.observe_permission(PERMISSION_DELETE, None);
                Ok(())
            }
            Err(error) => {
                let error = self.explain_lock_refusal(ctx, key, "", error).await;
                if !is_object_locked(&error) {
                    self.observe_permission(PERMISSION_DELETE, Some(&error));
                }
                Err(error)
            }
        }
    }

    /// Delete keys, in batches of 1000 when the back end can. A key that XML cannot carry, a back end without a
    /// batch delete, and a provider that refuses the batch request all get the delete of one key. A key that an
    /// active Object Lock keeps does not stop the delete: the result gives it, with its full key. The error is the
    /// first other failure.
    pub async fn delete_many(&self, ctx: &OpCtx, keys: &[String]) -> Result<Vec<String>> {
        let (locked, result) = self.delete_many_with_locks(ctx, keys).await;
        result.map(|()| locked)
    }

    async fn delete_many_with_locks(&self, ctx: &OpCtx, keys: &[String]) -> (Vec<String>, Result<()>) {
        let mut locked = Vec::new();
        if self.backend.batch_deleter().is_none() || self.batch_delete_off.load(Ordering::SeqCst) {
            return self.delete_each(ctx, keys).await;
        }
        let mut batch: Vec<String> = Vec::with_capacity(keys.len().min(MAX_DELETE_BATCH));
        for key in keys {
            if !xml_safe_key(key) {
                let (kept, result) = self.delete_each(ctx, std::slice::from_ref(key)).await;
                locked.extend(kept);
                if result.is_err() {
                    return (locked, result);
                }
                continue;
            }
            batch.push(key.clone());
            if batch.len() == MAX_DELETE_BATCH {
                let result = self.flush_delete_batch(ctx, &batch, &mut locked).await;
                batch.clear();
                if result.is_err() {
                    return (locked, result);
                }
            }
        }
        let result = self.flush_delete_batch(ctx, &batch, &mut locked).await;
        (locked, result)
    }

    async fn flush_delete_batch(&self, ctx: &OpCtx, batch: &[String], locked: &mut Vec<String>) -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        let Some(batcher) = self.backend.batch_deleter() else {
            let (kept, result) = self.delete_each(ctx, batch).await;
            locked.extend(kept);
            return result;
        };
        let slot = self.begin_storage_request(ctx).await?;
        let result = batcher.delete_many(ctx, batch).await;
        drop(slot);
        let mut error = result.err();
        if let Some(refusal) = &error
            && batch_delete_unsupported(refusal)
        {
            self.batch_delete_off.store(true, Ordering::SeqCst);
            let (kept, result) = self.delete_each(ctx, batch).await;
            locked.extend(kept);
            return result;
        }
        if let Some(Error::BatchDelete(refused)) = &error {
            let (kept, others) = self.locked_keys(ctx, refused).await;
            let every_key_kept = others.is_none() && kept.len() == batch.len();
            locked.extend(kept);
            if every_key_kept {
                // The lock kept each key: the batch says nothing about the delete permission.
                return Ok(());
            }
            error = others;
        }
        self.observe_permission(PERMISSION_DELETE, error.as_ref());
        match error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Read the lock of the refused keys of a batch delete, for up to [`MAX_LOCK_CHECKS`] keys. Gives the keys that
    /// an active lock keeps, and a batch error with the other refused keys, or `None` when the lock explains each
    /// refusal.
    async fn locked_keys(&self, ctx: &OpCtx, refused: &BatchDeleteError) -> (Vec<String>, Option<Error>) {
        let mut locked = Vec::new();
        let mut others = BatchDeleteError {
            total: refused.total,
            failures: Vec::new(),
        };
        for (index, failure) in refused.failures.iter().enumerate() {
            if index < MAX_LOCK_CHECKS {
                let candidate = Error::upstream(502, failure.code.clone(), failure.message.clone());
                let explained = self.explain_lock_refusal(ctx, &failure.key, "", candidate).await;
                if is_object_locked(&explained) {
                    locked.push(failure.key.clone());
                    continue;
                }
            }
            others.failures.push(failure.clone());
        }
        if others.failures.is_empty() {
            return (locked, None);
        }
        (locked, Some(Error::BatchDelete(Box::new(others))))
    }

    /// Delete the keys one by one. A key that an active Object Lock keeps goes to the result, and the delete goes on.
    async fn delete_each(&self, ctx: &OpCtx, keys: &[String]) -> (Vec<String>, Result<()>) {
        let mut locked = Vec::new();
        for key in keys {
            if let Err(error) = self.delete(ctx, key).await {
                if is_object_locked(&error) {
                    locked.push(key.clone());
                    continue;
                }
                return (locked, Err(error));
            }
        }
        (locked, Ok(()))
    }

    /// Copy one object. The ceilings of read and write apply to the size of the source: a HEAD gives it before the
    /// copy, when a ceiling applies.
    pub async fn copy(&self, ctx: &OpCtx, source: &str, destination: &str) -> Result<()> {
        self.check_copy_source(ctx, source, "").await?;
        self.copy_object(ctx, source, destination).await
    }

    /// Copy one object with one request. The caller checks the ceilings.
    async fn copy_object(&self, ctx: &OpCtx, source: &str, destination: &str) -> Result<()> {
        let _slot = self.begin_storage_request(ctx).await?;
        let result = self.backend.copy(ctx, source, destination).await;
        match &result {
            Ok(()) => {
                self.observe_permission(PERMISSION_READ, None);
                self.observe_permission(PERMISSION_WRITE, None);
            }
            // A provider does not tell if a copy denial comes from the read of the source or from the write of the
            // destination: the read stays available, and the instance learns the denial of the write only.
            Err(error) => self.observe_permission(PERMISSION_WRITE, Some(error)),
        }
        result
    }

    /// Copy one object of a known size. From the copy threshold up, a back end that copies in parts gets a copy in
    /// parts; the other copies are one request. The progress function gets the size of each copied part. The check
    /// of the ceilings uses the size of the caller and makes no HEAD request.
    pub async fn copy_sized(
        &self,
        ctx: &OpCtx,
        source: &str,
        destination: &str,
        size: i64,
        progress: Option<CopyProgress>,
    ) -> Result<()> {
        if ceiling_applies(ctx, &[ACTION_READ, ACTION_WRITE]) {
            check_copy_ceilings(ctx, size)?;
        }
        if self.copies_in_parts(size) {
            let options = MultipartCopyOptions {
                progress,
                ..MultipartCopyOptions::default()
            };
            return self.copy_multipart_object(ctx, source, destination, options).await;
        }
        self.copy_object(ctx, source, destination).await
    }

    /// True when a copy of this size goes in parts.
    pub fn copies_in_parts(&self, size: i64) -> bool {
        self.backend.multipart_copier().is_some() && size >= self.multipart_copy_threshold()
    }

    /// Copy an object in parts. Each provider request of the copy takes a slot of the gates, and waits for it
    /// without a time limit: a copy in parts is long. The ceilings of read and write apply to the size of the
    /// source before the copy.
    pub async fn copy_multipart(
        &self,
        ctx: &OpCtx,
        source: &str,
        destination: &str,
        options: MultipartCopyOptions,
    ) -> Result<()> {
        if self.backend.multipart_copier().is_some() {
            self.check_copy_source(ctx, source, &options.source_version).await?;
        }
        self.copy_multipart_object(ctx, source, destination, options).await
    }

    /// Copy an object in parts. The caller checks the ceilings.
    pub(crate) async fn copy_multipart_object(
        &self,
        ctx: &OpCtx,
        source: &str,
        destination: &str,
        mut options: MultipartCopyOptions,
    ) -> Result<()> {
        let Some(copier) = self.backend.multipart_copier() else {
            return Err(Error::api(
                501,
                "multipart_copy_unsupported",
                "this storage provider does not copy objects in parts",
            ));
        };
        options.gate = Some(self.request_gate());
        let unbounded = if ctx.gate == GateMode::Exempt {
            ctx.clone()
        } else {
            ctx.gated(GateMode::Unbounded)
        };
        let result = copier.copy_multipart(&unbounded, source, destination, options).await;
        match &result {
            Ok(()) => {
                self.observe_permission(PERMISSION_READ, None);
                self.observe_permission(PERMISSION_WRITE, None);
            }
            Err(error) => self.observe_permission(PERMISSION_WRITE, Some(error)),
        }
        result
    }

    /// The size of the source of a copy, with a HEAD request of the version (the current object for an empty
    /// version; the version of the context does not apply). -1 when the answer has no size.
    async fn copy_source_size(&self, ctx: &OpCtx, key: &str, version: &str) -> Result<i64> {
        let current = ctx.with_version(None);
        let response = self.head_version(&current, key, version).await?;
        match header_text(&response.headers, "content-length").parse::<i64>() {
            Ok(size) if size >= 0 => Ok(size),
            _ => Ok(-1),
        }
    }

    /// Check a copy of one object: the source size comes from a HEAD request. Without a ceiling of read or write,
    /// it makes no request.
    pub async fn check_copy_source(&self, ctx: &OpCtx, key: &str, version: &str) -> Result<()> {
        if !ceiling_applies(ctx, &[ACTION_READ, ACTION_WRITE]) {
            return Ok(());
        }
        let size = self.copy_source_size(ctx, key, version).await?;
        check_copy_ceilings(ctx, size)
    }

    /// True when the back end moves an object with one rename (a volume).
    pub fn moves_objects(&self) -> bool {
        self.backend.mover().is_some()
    }

    /// Move one object with one rename. The caller checks [`Instance::moves_objects`] first.
    pub async fn move_object(&self, ctx: &OpCtx, source: &str, destination: &str) -> Result<()> {
        let Some(mover) = self.backend.mover() else {
            return Err(Error::api(
                501,
                "move_unsupported",
                "this storage provider does not move objects with a rename",
            ));
        };
        self.check_copy_source(ctx, source, "").await?;
        let _slot = self.begin_storage_request(ctx).await?;
        let result = mover.move_object(ctx, source, destination).await;
        match &result {
            Ok(()) => {
                for permission in [PERMISSION_READ, PERMISSION_WRITE, PERMISSION_DELETE] {
                    self.observe_permission(permission, None);
                }
            }
            Err(error) => self.observe_permission(PERMISSION_WRITE, Some(error)),
        }
        result
    }

    /// Remove the empty folders under a full prefix, for a back end with real folders (a volume). The other back
    /// ends have no folders: nothing happens.
    pub async fn remove_empty_folders(&self, ctx: &OpCtx, prefix: &str) -> Result<()> {
        let Some(remover) = self.backend.folder_remover() else {
            return Ok(());
        };
        let _slot = self.begin_storage_request(ctx).await?;
        remover.remove_empty_folders(ctx, prefix).await
    }

    /// Start an S3 multipart upload; gives the upload id.
    pub async fn initiate_multipart(&self, ctx: &OpCtx, key: &str, content_type: &str) -> Result<String> {
        let api = self.backend.multipart_upload().ok_or_else(no_multipart)?;
        let _slot = self.begin_storage_request(ctx).await?;
        let result = api.initiate(ctx, key, content_type).await;
        self.observe_permission(PERMISSION_WRITE, result.as_ref().err());
        result
    }

    /// Send one part of an S3 multipart upload; gives its ETag. A part is not larger than its object: a part over
    /// the ceiling `object.write` is refused.
    pub async fn upload_part(
        &self,
        ctx: &OpCtx,
        key: &str,
        upload_id: &str,
        number: u32,
        body: Body,
        size: i64,
    ) -> Result<String> {
        check_write_ceiling(ctx, size)?;
        let api = self.backend.multipart_upload().ok_or_else(no_multipart)?;
        let _slot = self.begin_storage_request(ctx).await?;
        if let Some(budget) = &ctx.budget
            && size > 0
        {
            budget.consume_bytes(size)?;
        }
        let result = api.upload_part(ctx, key, upload_id, number, body, size).await;
        self.observe_permission(PERMISSION_WRITE, result.as_ref().err());
        result
    }

    /// Complete an S3 multipart upload.
    pub async fn complete_multipart(
        &self,
        ctx: &OpCtx,
        key: &str,
        upload_id: &str,
        parts: &[CompletedPart],
    ) -> Result<()> {
        let api = self.backend.multipart_upload().ok_or_else(no_multipart)?;
        let _slot = self.begin_storage_request(ctx).await?;
        let result = api.complete(ctx, key, upload_id, parts).await;
        self.observe_permission(PERMISSION_WRITE, result.as_ref().err());
        result
    }

    /// Abort a multipart upload, or remove the temporary file of a volume upload.
    pub async fn abort_multipart(&self, ctx: &OpCtx, key: &str, upload_id: &str) -> Result<()> {
        if let Some(remover) = self.backend.incomplete_upload_remover() {
            let _slot = self.begin_storage_request(ctx).await?;
            let result = remover.remove_incomplete_upload(ctx, key, upload_id).await;
            self.observe_permission(PERMISSION_WRITE, result.as_ref().err());
            return result;
        }
        let api = self.backend.multipart_upload().ok_or_else(no_multipart)?;
        let _slot = self.begin_storage_request(ctx).await?;
        let result = api.abort(ctx, key, upload_id).await;
        self.observe_permission(PERMISSION_WRITE, result.as_ref().err());
        result
    }

    /// The parts of an S3 multipart upload, in the order of the numbers.
    pub async fn list_multipart_parts(&self, ctx: &OpCtx, key: &str, upload_id: &str) -> Result<Vec<MultipartPart>> {
        let lister = self
            .backend
            .part_lister()
            .ok_or_else(|| Error::internal("storage backend does not support multipart part reconciliation"))?;
        let _slot = self.begin_storage_request(ctx).await?;
        let result = lister.list_parts(ctx, key, upload_id).await;
        self.observe_permission(PERMISSION_WRITE, result.as_ref().err());
        result
    }

    /// Start a resumable upload (GCS, a volume); gives the session. The ceiling `object.write` applies to the total.
    pub async fn initiate_resumable(&self, ctx: &OpCtx, key: &str, total: i64, content_type: &str) -> Result<String> {
        check_write_ceiling(ctx, total)?;
        let api = self.backend.resumable().ok_or_else(no_resumable)?;
        let _slot = self.begin_storage_request(ctx).await?;
        let result = api.initiate_resumable(ctx, key, total, content_type).await;
        self.observe_permission(PERMISSION_WRITE, result.as_ref().err());
        result
    }

    /// Send one chunk of a resumable upload; gives the next offset and true at the end. The ceiling `object.write`
    /// applies to the total: the size of the object that the upload writes.
    #[allow(clippy::too_many_arguments)]
    pub async fn upload_resumable_chunk(
        &self,
        ctx: &OpCtx,
        session: &str,
        body: Body,
        start: i64,
        size: i64,
        total: i64,
        content_type: &str,
    ) -> Result<(i64, bool)> {
        check_write_ceiling(ctx, total)?;
        let api = self.backend.resumable().ok_or_else(no_resumable)?;
        let _slot = self.begin_storage_request(ctx).await?;
        if let Some(budget) = &ctx.budget
            && size > 0
        {
            budget.consume_bytes(size)?;
        }
        let result = api
            .upload_chunk(ctx, session, body, start, size, total, content_type)
            .await;
        self.observe_permission(PERMISSION_WRITE, result.as_ref().err());
        result
    }

    /// The next offset of a resumable upload, and true at the end.
    pub async fn query_resumable(&self, ctx: &OpCtx, session: &str, total: i64) -> Result<(i64, bool)> {
        let api = self.backend.resumable().ok_or_else(no_resumable)?;
        let _slot = self.begin_storage_request(ctx).await?;
        let result = api.query_resumable(ctx, session, total).await;
        self.observe_permission(PERMISSION_WRITE, result.as_ref().err());
        result
    }

    /// Abort a resumable upload.
    pub async fn abort_resumable(&self, ctx: &OpCtx, session: &str) -> Result<()> {
        let api = self.backend.resumable().ok_or_else(no_resumable)?;
        let _slot = self.begin_storage_request(ctx).await?;
        let result = api.abort_resumable(ctx, session).await;
        self.observe_permission(PERMISSION_WRITE, result.as_ref().err());
        result
    }
}

fn no_multipart() -> Error {
    Error::internal("s3 backend does not support multipart uploads")
}

fn no_resumable() -> Error {
    Error::internal("gcs backend does not support resumable uploads")
}
