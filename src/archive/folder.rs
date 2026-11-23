//! The ZIP of a folder: `GET /api/archive?instance=&prefix=&name=`.
//!
//! The route lists the prefix in pages of 1000 keys and streams one stored member for each object, in the order of
//! the listing. A member gets the safe relative name of its key; a second member with the same name gets `~2`,
//! `~3`... A folder marker (a key that ends with `/` and has no bytes) gives a folder entry. The trailers
//! `X-Stowr-Archive-Status` (`complete` or `incomplete`), `X-Stowr-Archive-Entries` and `X-Stowr-Archive-Bytes`
//! end the answer. A failure after the first byte adds the member `__STOWR_ARCHIVE_INCOMPLETE.txt` with the reason,
//! then the central directory.
//!
//! While a member of at most 4 MiB streams, the route asks for the next member of at most 4 MiB in advance. That
//! request never waits for a storage slot: without a free slot, the member comes in line as usual.

use std::collections::HashMap;
use std::sync::Arc;

use bytes::Bytes;
use http::header::{CACHE_CONTROL, CONTENT_DISPOSITION, CONTENT_TYPE, HeaderName, HeaderValue, TRAILER};
use http::{HeaderMap, Method};
use http_body_util::BodyExt;
use tokio::sync::oneshot;

use super::content::format_disposition;
use super::names::{archive_filename, normalize_prefix, safe_archive_entry_name, unique_archive_entry_name};
use super::stream::{STREAM_IDLE_TIMEOUT, StreamSender, stream};
use super::zip::writer::{EntryHeader, ZipWriter};
use crate::access::{ACTION_READ, authorize_read};
use crate::common::BoxFuture;
use crate::common::app::App;
use crate::common::config::PERMISSION_READ;
use crate::common::ctx::{GateMode, OpCtx};
use crate::common::error::{Error, Result};
use crate::common::http::{Req, Response, answer, api_error, method_not_allowed};
use crate::common::misc::clean_relative_key;
use crate::common::storage::{ListOptions, ListPage, ObjectInfo, ObjectResponse};
use crate::common::time::Timestamp;
use crate::instance::Instance;
use crate::instance::ceiling::{MAX_OBJECT_SIZE, check_object_ceiling};

/// The trailer of the state of the archive: `complete` or `incomplete`.
pub const ARCHIVE_STATUS_TRAILER: &str = "X-Stowr-Archive-Status";
/// The trailer of the count of the members.
pub const ARCHIVE_ENTRIES_TRAILER: &str = "X-Stowr-Archive-Entries";
/// The trailer of the object bytes in the archive.
pub const ARCHIVE_BYTES_TRAILER: &str = "X-Stowr-Archive-Bytes";
/// The name of the member that tells why an archive is incomplete.
pub const INCOMPLETE_ENTRY_NAME: &str = "__STOWR_ARCHIVE_INCOMPLETE.txt";
/// The largest member (the current one and the next one) for which the next request starts in advance.
pub const ARCHIVE_PREFETCH_MAX_BYTES: i64 = 4 << 20;

const PAGE_SIZE: u32 = 1000;

/// True when a ceiling `max_object_size` applies to the action in the context.
pub(crate) fn ceiling_applies(ctx: &OpCtx, action: &str) -> bool {
    ctx.ceilings
        .as_ref()
        .is_some_and(|ceilings| ceilings.get(action, MAX_OBJECT_SIZE).is_some())
        || ctx
            .access
            .as_ref()
            .is_some_and(|access| access.ceilings.get(action, MAX_OBJECT_SIZE).is_some())
}

/// The handler of `/api/archive`.
pub fn handle_archive(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        if req.method != Method::GET {
            return method_not_allowed(&["GET"]);
        }
        match start_archive(app, req).await {
            Ok(response) => response,
            Err(error) => api_error(&error),
        }
    })
}

async fn start_archive(app: Arc<App>, req: Req) -> Result<Response> {
    let instance = app.instance_of("", req.query.get("instance"))?.clone();
    instance.require_permission(PERMISSION_READ)?;
    let prefix = normalize_prefix(&clean_relative_key(req.query.get("prefix")));
    authorize_read(&app, &req.ctx, &instance, &prefix).await?;
    let ctx = req.ctx.clone();
    let options = ListOptions {
        prefix: instance.full_key(&prefix),
        max_results: PAGE_SIZE,
        ..ListOptions::default()
    };
    let page = instance.list(&ctx, &options).await?;
    if page.objects.is_empty() && page.next_page_token.is_empty() {
        return Err(Error::api(
            404,
            "empty_prefix",
            "the selected prefix contains no objects",
        ));
    }
    // The ceiling object.read: the check of each listed size comes before the first byte of the ZIP.
    check_archive_sizes(&ctx, &instance, &prefix).await?;

    let filename = archive_filename(req.query.get("name"), &prefix, &instance.cfg.name);
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/zip"));
    if let Some(value) = format_disposition("attachment", &filename)
        && let Ok(value) = HeaderValue::from_str(&value)
    {
        headers.insert(CONTENT_DISPOSITION, value);
    }
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("private, no-store"));
    for trailer in [ARCHIVE_STATUS_TRAILER, ARCHIVE_ENTRIES_TRAILER, ARCHIVE_BYTES_TRAILER] {
        headers.append(TRAILER, HeaderValue::from_static(trailer));
    }
    let (sender, body) = stream(STREAM_IDLE_TIMEOUT);
    let max_entries = u64::from(app.config.runtime.max_archive_entries);
    tokio::spawn(write_archive(sender, instance, ctx, prefix, page, max_entries));
    Ok(answer(200, headers, body))
}

/// The ceiling `object.read`: the check of the size of each object of the prefix, in key order, before the first
/// byte of the ZIP. A folder marker needs no check. No request when no ceiling applies.
async fn check_archive_sizes(ctx: &OpCtx, instance: &Instance, prefix: &str) -> Result<()> {
    if !ceiling_applies(ctx, ACTION_READ) {
        return Ok(());
    }
    let full_prefix = instance.full_key(prefix);
    let mut last_key = String::new();
    loop {
        let mut options = ListOptions {
            prefix: full_prefix.clone(),
            max_results: PAGE_SIZE,
            ..ListOptions::default()
        };
        if !last_key.is_empty() {
            options.start_after = instance.full_key(&last_key);
        }
        let mut page = instance.list(ctx, &options).await?;
        page.objects.sort_by(|a, b| a.key.cmp(&b.key));
        let mut progressed = false;
        for object in &page.objects {
            let Some(relative) = instance.relative_key(&object.key) else {
                continue;
            };
            if relative.is_empty() || !relative.starts_with(prefix) || (!last_key.is_empty() && relative <= last_key) {
                continue;
            }
            if let Some(name) = safe_archive_entry_name(&relative[prefix.len()..])
                && !(name.ends_with('/') && object.size == 0)
            {
                check_object_ceiling(ctx, ACTION_READ, object.size)?;
            }
            last_key = relative;
            progressed = true;
        }
        if !progressed || (page.next_page_token.is_empty() && page.objects.len() < PAGE_SIZE as usize) {
            return Ok(());
        }
    }
}

/// The read of the next member, asked in advance.
struct Prefetch {
    key: String,
    plan: Option<(Arc<Instance>, OpCtx)>,
    receiver: Option<oneshot::Receiver<Result<ObjectResponse>>>,
}

impl Prefetch {
    /// The read in advance of `next` while `current` streams, when both are small and `next` is a member.
    fn plan(
        instance: &Arc<Instance>,
        ctx: &OpCtx,
        prefix: &str,
        current: &ObjectInfo,
        next: &ObjectInfo,
    ) -> Option<Self> {
        let relative = instance.relative_key(&next.key)?;
        if !relative.starts_with(prefix) || relative.ends_with('/') {
            return None;
        }
        safe_archive_entry_name(&relative[prefix.len()..])?;
        if current.size < 0
            || current.size > ARCHIVE_PREFETCH_MAX_BYTES
            || next.size <= 0
            || next.size > ARCHIVE_PREFETCH_MAX_BYTES
        {
            return None;
        }
        Some(Self {
            key: next.key.clone(),
            plan: Some((instance.clone(), ctx.gated(GateMode::NoWait))),
            receiver: None,
        })
    }

    /// Start the read. It never waits for a storage slot.
    fn start(&mut self) {
        let Some((instance, ctx)) = self.plan.take() else {
            return;
        };
        let (sender, receiver) = oneshot::channel();
        let key = self.key.clone();
        tokio::spawn(async move {
            let result = instance.get(&ctx, &key, &HeaderMap::new()).await;
            // A dropped receiver drops the answer: the body closes and frees its slot.
            let _ = sender.send(result);
        });
        self.receiver = Some(receiver);
    }

    /// The answer for `key`, or `None` when the member comes in line: no read started, another key, or a failure.
    async fn take(self, key: &str) -> Option<ObjectResponse> {
        let receiver = self.receiver?;
        if self.key != key {
            return None;
        }
        match receiver.await {
            Ok(Ok(response)) => Some(response),
            _ => None,
        }
    }
}

/// Why the archive stopped.
struct Failure {
    error: Error,
    /// True for an error of the write of a member: its message is not public.
    wrapped: bool,
    /// True when the client is gone.
    client: bool,
}

impl Failure {
    fn direct(error: Error) -> Self {
        Self {
            error,
            wrapped: false,
            client: false,
        }
    }

    fn wrapped(error: Error) -> Self {
        Self {
            error,
            wrapped: true,
            client: false,
        }
    }

    fn client(error: Error) -> Self {
        Self {
            error,
            wrapped: true,
            client: true,
        }
    }

    /// The reason in the member `__STOWR_ARCHIVE_INCOMPLETE.txt`.
    fn public_text(&self) -> String {
        if !self.wrapped
            && let Error::Api(api) = &self.error
        {
            return api.message.clone();
        }
        match &self.error {
            Error::Upstream(_) | Error::BatchDelete(_) | Error::Timeout | Error::Canceled | Error::Connect(_) => {
                self.error.public_message()
            }
            _ => "the storage provider operation failed".to_owned(),
        }
    }
}

/// Send the bytes that the writer gave.
async fn flush(sender: &StreamSender, writer: &mut ZipWriter) -> Result<(), Failure> {
    for part in writer.take_output() {
        sender.send(part).await.map_err(Failure::client)?;
    }
    Ok(())
}

fn successful_read(status: u16) -> bool {
    (200..300).contains(&status) || status == 304
}

/// Write one member: its header, then the bytes of the object.
#[allow(clippy::too_many_arguments)]
async fn write_member(
    sender: &StreamSender,
    writer: &mut ZipWriter,
    instance: &Instance,
    ctx: &OpCtx,
    object: &ObjectInfo,
    name: String,
    written: &mut i64,
    ready: Option<ObjectResponse>,
    next: Option<&mut Prefetch>,
) -> Result<(), Failure> {
    let folder = name.ends_with('/');
    let header = EntryHeader {
        name,
        modified: object.last_modified.map(Timestamp::utc),
        permissions: if folder { 0o755 } else { 0o600 },
    };
    writer.create(&header).map_err(Failure::wrapped)?;
    flush(sender, writer).await?;
    if folder && object.size == 0 {
        return Ok(());
    }
    let response = match ready {
        Some(response) => response,
        None => instance
            .get(ctx, &object.key, &HeaderMap::new())
            .await
            .map_err(Failure::direct)?,
    };
    if !successful_read(response.status) {
        return Err(Failure::direct(Error::upstream(
            response.status,
            "ArchiveObjectReadFailed",
            "",
        )));
    }
    if let Some(next) = next {
        // The slot of this member is held: the request of the next member overlaps with this transfer.
        next.start();
    }
    let mut body = response.body;
    let mut count = 0i64;
    let outcome = loop {
        let data = match body.frame().await {
            None => break Ok(()),
            Some(Err(error)) => break Err(Failure::wrapped(error)),
            Some(Ok(frame)) => match frame.into_data() {
                Ok(data) => data,
                Err(_) => continue,
            },
        };
        if data.is_empty() {
            continue;
        }
        let length = data.len() as i64;
        if let Err(error) = writer.write(data) {
            break Err(Failure::wrapped(error));
        }
        count += length;
        if let Err(failure) = flush(sender, writer).await {
            break Err(failure);
        }
    };
    *written += count;
    outcome?;
    if object.size >= 0 && count != object.size {
        return Err(Failure::direct(Error::api(
            502,
            "object_size_changed",
            "an object changed size while the archive was being streamed",
        )));
    }
    Ok(())
}

/// The member that tells why the archive is incomplete.
fn write_incomplete_entry(writer: &mut ZipWriter, failure: &Failure, entries: u64, bytes: i64) -> Result<()> {
    writer.create(&EntryHeader {
        name: INCOMPLETE_ENTRY_NAME.to_owned(),
        modified: Some(Timestamp::now()),
        permissions: 0o600,
    })?;
    let message = format!(
        "This archive is incomplete.\n\nCompleted entries: {entries}\nObject bytes streamed: {bytes}\nReason: {}\n",
        failure.public_text()
    );
    writer.write(Bytes::from(message))
}

/// Stream the archive: each page of the listing, each member, then the central directory and the trailers.
async fn write_archive(
    sender: StreamSender,
    instance: Arc<Instance>,
    ctx: OpCtx,
    prefix: String,
    first: ListPage,
    max_entries: u64,
) {
    let mut writer = ZipWriter::new();
    let mut seen = HashMap::new();
    let mut entries = 0u64;
    let mut written = 0i64;
    let mut failure: Option<Failure> = None;
    let mut prefetch: Option<Prefetch> = None;
    let mut page_token = String::new();
    let mut current = first;
    loop {
        let objects = std::mem::take(&mut current.objects);
        for (position, object) in objects.iter().enumerate() {
            if let Err(error) = ctx.check() {
                failure = Some(Failure::direct(error));
                break;
            }
            let Some(relative) = instance.relative_key(&object.key) else {
                continue;
            };
            if !relative.starts_with(&prefix) {
                continue;
            }
            let Some(name) = safe_archive_entry_name(&relative[prefix.len()..]) else {
                continue;
            };
            let name = unique_archive_entry_name(&name, &mut seen);
            entries += 1;
            if entries > max_entries {
                failure = Some(Failure::direct(Error::api(
                    413,
                    "archive_entry_limit",
                    format!("the archive exceeds the configured limit of {max_entries} entries"),
                )));
                break;
            }
            let ready = match prefetch.take() {
                Some(previous) => previous.take(&object.key).await,
                None => None,
            };
            prefetch = objects
                .get(position + 1)
                .and_then(|next| Prefetch::plan(&instance, &ctx, &prefix, object, next));
            let result = write_member(
                &sender,
                &mut writer,
                &instance,
                &ctx,
                object,
                name,
                &mut written,
                ready,
                prefetch.as_mut(),
            )
            .await;
            if let Err(stop) = result {
                failure = Some(stop);
                break;
            }
        }
        if failure.is_some() || current.next_page_token.is_empty() {
            break;
        }
        if current.next_page_token == page_token {
            failure = Some(Failure::direct(Error::api(
                502,
                "invalid_continuation_token",
                "the storage provider returned the same continuation token twice",
            )));
            break;
        }
        page_token = current.next_page_token.clone();
        let options = ListOptions {
            prefix: instance.full_key(&prefix),
            max_results: PAGE_SIZE,
            page_token: page_token.clone(),
            ..ListOptions::default()
        };
        match instance.list(&ctx, &options).await {
            Ok(page) => current = page,
            Err(error) => {
                failure = Some(Failure::direct(error));
                break;
            }
        }
    }
    drop(prefetch);
    if failure.as_ref().is_some_and(|failure| failure.client) {
        // The client stopped: the task drops the sender and the body stops with an error.
        return;
    }
    if let Some(failure) = &failure
        && ctx.check().is_ok()
    {
        let _ = write_incomplete_entry(&mut writer, failure, entries, written);
    }
    let closed = writer.finish();
    if flush(&sender, &mut writer).await.is_err() {
        return;
    }
    let complete = failure.is_none() && closed.is_ok();
    let mut trailers = HeaderMap::new();
    let values = [
        (
            ARCHIVE_STATUS_TRAILER,
            if complete { "complete" } else { "incomplete" }.to_owned(),
        ),
        (ARCHIVE_ENTRIES_TRAILER, entries.to_string()),
        (ARCHIVE_BYTES_TRAILER, written.to_string()),
    ];
    for (name, value) in values {
        if let (Ok(name), Ok(value)) = (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(&value)) {
            trailers.insert(name, value);
        }
    }
    if sender.send_trailers(trailers).await.is_ok() {
        sender.finish();
    }
}
