//! The upload sessions in the memory of the process, and the operations on them.
//!
//! The state of a session is in memory only. At most four sessions exist at the same time, so abandoned browser tabs
//! cannot grow the process. The resume token that the client keeps can make a session again. A session that makes no
//! progress for 30 minutes is abandoned: the manager aborts its provider session and frees its slot
//! (docs/ARCHITECTURE.md, "Upload resume protocol").

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use http::HeaderMap;
use serde::{Deserialize, Deserializer};

use super::checksum::{
    UPLOAD_CHECKSUM_SHA256, parse_checksum_header, verify_upload_checksum, with_checksum_transfer, with_upload_tags,
};
use super::limit::limit_body;
use super::session::{
    MAX_IN_MEMORY_UPLOAD_SESSIONS, MAXIMUM_S3_PART_SIZE, MAXIMUM_S3_PARTS, MINIMUM_S3_PART_SIZE, STATUS_CANCELED,
    STATUS_COMPLETED, STATUS_UPLOADING, UploadPartState, UploadSession, nanos_between, parse_content_range,
    upload_chunk_size,
};
use super::target::{AccessCheck, Targets, UploadTarget, initiation_context, validate_upload_tags};
use super::token::{open_resume_token, seal_resume_token, upload_id_from_token};
use crate::common::config::{PERMISSION_READ, PERMISSION_WRITE, PROVIDER_VOLUME};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::Body;
use crate::common::misc::{CancelToken, clean_relative_key, new_state_id};
use crate::common::storage::CompletedPart;
use crate::common::time::Timestamp;
use crate::instance::ceiling::{ACTION_WRITE, check_object_ceiling};
use crate::lifecycle::Tag;

/// An upload session that makes no progress for this long is abandoned.
pub const UPLOAD_IDLE_TTL: Duration = Duration::from_secs(30 * 60);
/// The time between two looks of the reaper.
pub const UPLOAD_REAP_INTERVAL: Duration = Duration::from_secs(60);
/// The time that the reaper gives to the abort of one provider session.
pub const UPLOAD_REAP_ABORT_LIMIT: Duration = Duration::from_secs(30);

/// A value that is `null` in the JSON text has the default value, as a missing member has.
fn null_as_default<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// The request `POST /api/uploads`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateUploadRequest {
    /// The id of the instance.
    #[serde(default, deserialize_with = "null_as_default")]
    pub instance: String,
    /// The relative key of the object.
    #[serde(default, deserialize_with = "null_as_default")]
    pub key: String,
    /// The size of the object.
    #[serde(default, deserialize_with = "null_as_default")]
    pub size: i64,
    /// The media type.
    #[serde(default, rename = "contentType", deserialize_with = "null_as_default")]
    pub content_type: String,
    /// `""` or `sha256`. With `sha256` the client sends the SHA-256 digest of each chunk in `X-Checksum-Sha256`.
    #[serde(default, deserialize_with = "null_as_default")]
    pub checksum: String,
    /// The tags of the new object. Only an S3 provider that keeps tags keeps them.
    #[serde(default, deserialize_with = "null_as_default")]
    pub tags: Vec<Tag>,
}

/// One chunk of an upload: the request headers, the length that the client declared (`-1` when the length is not
/// known) and the body.
pub struct ChunkInput {
    /// The request headers (`Content-Range`, `X-Checksum-Sha256`).
    pub headers: HeaderMap,
    /// The declared length of the body, or `-1`.
    pub content_length: i64,
    /// The body.
    pub body: Body,
}

fn capacity_error() -> Error {
    Error::api(
        429,
        "upload_session_limit_reached",
        format!("the server is already tracking {MAX_IN_MEMORY_UPLOAD_SESSIONS} active upload sessions"),
    )
}

fn not_found() -> Error {
    Error::api(404, "upload_not_found", "upload session was not found")
}

fn unknown_instance() -> Error {
    Error::api(404, "unknown_instance", "storage instance was not found")
}

struct Inner {
    sessions: Mutex<HashMap<String, UploadSession>>,
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    stop: CancelToken,
    reaper_started: AtomicBool,
    idle_ttl: Duration,
    reap_interval: Duration,
    reap_abort_limit: Duration,
}

/// The upload sessions in the memory of the process (at most four).
#[derive(Clone)]
pub struct UploadManager {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for UploadManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UploadManager")
            .field("sessions", &self.sessions().len())
            .finish_non_exhaustive()
    }
}

impl Default for UploadManager {
    fn default() -> Self {
        Self::new()
    }
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl UploadManager {
    /// A manager with no session.
    pub fn new() -> Self {
        Self::with_timings(UPLOAD_IDLE_TTL, UPLOAD_REAP_INTERVAL, UPLOAD_REAP_ABORT_LIMIT)
    }

    /// A manager with its own idle time, reap interval and abort limit.
    pub fn with_timings(idle_ttl: Duration, reap_interval: Duration, reap_abort_limit: Duration) -> Self {
        Self {
            inner: Arc::new(Inner {
                sessions: Mutex::new(HashMap::new()),
                locks: Mutex::new(HashMap::new()),
                stop: CancelToken::new(),
                reaper_started: AtomicBool::new(false),
                idle_ttl,
                reap_interval,
                reap_abort_limit,
            }),
        }
    }

    fn sessions(&self) -> MutexGuard<'_, HashMap<String, UploadSession>> {
        locked(&self.inner.sessions)
    }

    /// The idle time after which a session is abandoned.
    pub fn idle_ttl(&self) -> Duration {
        self.inner.idle_ttl
    }

    /// Start the task that aborts the sessions that stay idle. The call does nothing after the first one. The task
    /// stops with [`UploadManager::close`] or when the manager or the registry is gone.
    pub fn ensure_reaper(&self, targets: Weak<dyn Targets>) {
        if self.inner.reaper_started.swap(true, Ordering::SeqCst) {
            return;
        }
        let inner = Arc::downgrade(&self.inner);
        let stop = self.inner.stop.clone();
        let interval = self.inner.reap_interval;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            ticker.tick().await;
            loop {
                tokio::select! {
                    () = stop.canceled() => return,
                    _ = ticker.tick() => {}
                }
                let (Some(inner), Some(targets)) = (inner.upgrade(), targets.upgrade()) else {
                    return;
                };
                Self { inner }.reap_idle(&*targets, Timestamp::now()).await;
            }
        });
    }

    /// The provider upload ids that this process sends now, for an instance. The list of the incomplete uploads
    /// shows these uploads with `active`, and no abort touches them.
    pub fn active_provider_uploads(&self, instance: &str) -> BTreeSet<String> {
        let mut active = BTreeSet::new();
        for upload in self.sessions().values() {
            if upload.instance != instance || upload.status != STATUS_UPLOADING {
                continue;
            }
            if !upload.provider_upload_id.is_empty() {
                active.insert(upload.provider_upload_id.clone());
            } else if upload.provider == PROVIDER_VOLUME && !upload.session_url.is_empty() {
                // The list of a volume gives the name of the temporary file as the upload id.
                active.insert(volume_session_upload_id(&upload.session_url));
            }
        }
        active
    }

    /// Stop the reaper of the idle sessions.
    pub fn close(&self) {
        self.inner.stop.cancel();
    }

    /// A copy of a session.
    pub fn get(&self, id: &str) -> Option<UploadSession> {
        self.sessions().get(id).cloned()
    }

    /// Keep a session. A new session needs a free slot (`429 upload_session_limit_reached`). The time of the last
    /// progress moves when the session is new or when its offset or its status changed.
    pub fn put(&self, mut upload: UploadSession) -> Result<()> {
        if upload.id.trim().is_empty() {
            return Err(Error::internal("upload id is empty"));
        }
        let mut sessions = self.sessions();
        let existing = sessions.get(&upload.id);
        if existing.is_none() && sessions.len() >= MAX_IN_MEMORY_UPLOAD_SESSIONS {
            return Err(capacity_error());
        }
        upload.last_activity = match existing {
            Some(old) if old.uploaded_bytes == upload.uploaded_bytes && old.status == upload.status => {
                old.last_activity
            }
            _ => Timestamp::now(),
        };
        sessions.insert(upload.id.clone(), upload);
        Ok(())
    }

    /// True when a session with this id can be kept: it exists, or a slot is free.
    pub fn has_capacity_for(&self, id: &str) -> bool {
        let sessions = self.sessions();
        sessions.contains_key(id) || sessions.len() < MAX_IN_MEMORY_UPLOAD_SESSIONS
    }

    /// Forget a session.
    pub fn remove(&self, id: &str) {
        let id = id.trim();
        if id.is_empty() {
            return;
        }
        self.sessions().remove(id);
        locked(&self.inner.locks).remove(id);
    }

    /// Forget a session that ended: a completed or a canceled upload does not stay in memory.
    pub fn release_terminal(&self, upload: &UploadSession) {
        if upload.status == STATUS_COMPLETED || upload.status == STATUS_CANCELED {
            self.remove(&upload.id);
        }
    }

    /// The lock of one session. A request that holds it is never reaped.
    pub fn upload_lock(&self, id: &str) -> Arc<tokio::sync::Mutex<()>> {
        locked(&self.inner.locks)
            .entry(id.to_owned())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Abort and forget each session with no progress for the idle time. A session that handles a request holds its
    /// lock and stays, so a slow chunk is never reaped. Gives the number of reaped sessions.
    pub async fn reap_idle(&self, targets: &dyn Targets, now: Timestamp) -> usize {
        let limit = i128::try_from(self.inner.idle_ttl.as_nanos()).unwrap_or(i128::MAX);
        let idle: Vec<String> = self
            .sessions()
            .iter()
            .filter(|(_, upload)| nanos_between(now, upload.last_activity) > limit)
            .map(|(id, _)| id.clone())
            .collect();
        let mut reaped = 0;
        for id in idle {
            let lock = self.upload_lock(&id);
            let Ok(_guard) = lock.try_lock() else {
                continue;
            };
            let Some(upload) = self.get(&id) else {
                continue;
            };
            if nanos_between(now, upload.last_activity) <= limit {
                continue;
            }
            if upload.status == STATUS_UPLOADING
                && let Some(target) = targets.target(&upload.instance)
            {
                let ctx = OpCtx::default();
                let abort = self.abort_provider(&ctx, &*target, &upload);
                let _ = tokio::time::timeout(self.inner.reap_abort_limit, abort).await;
            }
            self.remove(&id);
            reaped += 1;
        }
        reaped
    }

    /// Make an upload session. The function calls `check` after the validation of the request and before the first
    /// call to the storage.
    pub async fn create_checked(
        &self,
        targets: &dyn Targets,
        ctx: &OpCtx,
        request: CreateUploadRequest,
        check: &dyn AccessCheck,
    ) -> Result<UploadSession> {
        if !self.has_capacity_for("") {
            return Err(capacity_error());
        }
        let target = targets.target(request.instance.trim()).ok_or_else(unknown_instance)?;
        target.require_permission(PERMISSION_WRITE)?;
        let key = clean_relative_key(&request.key);
        if key.is_empty() {
            return Err(Error::api(400, "invalid_key", "object key is required"));
        }
        let chunk_size = upload_chunk_size(target.provider(), request.size)
            .map_err(|message| Error::api(400, "invalid_size", message))?;
        let content_type = match request.content_type.trim() {
            "" => "application/octet-stream".to_owned(),
            value => value.to_owned(),
        };
        validate_upload_tags(&request.tags)?;
        target.require_tags(&request.tags)?;
        let ctx = with_upload_tags(ctx, &request.tags);
        if !request.checksum.is_empty() && request.checksum != UPLOAD_CHECKSUM_SHA256 {
            return Err(Error::api(
                400,
                "invalid_checksum",
                r#"checksum must be "" or "sha256""#,
            ));
        }
        check.check(&*target, &key).await?;
        // The ceiling object.write: the declared total size of the upload is the size of the object that it writes.
        check_object_ceiling(&ctx, ACTION_WRITE, request.size)?;
        let now = Timestamp::now();
        let mut upload = UploadSession {
            instance: target.id().to_owned(),
            key: key.clone(),
            provider: target.provider().to_owned(),
            status: STATUS_UPLOADING.to_owned(),
            content_type: content_type.clone(),
            total_size: request.size,
            chunk_size,
            created_at: now,
            updated_at: now,
            ..UploadSession::default()
        };
        let full_key = target.full_key(&key);
        if request.size == 0 {
            target.put_empty(&ctx, &full_key, &content_type).await?;
            upload.id = new_state_id("upl")?;
            upload.status = STATUS_COMPLETED.to_owned();
            upload.completed_at = Some(now);
            upload.verified = true;
            return Ok(upload);
        }
        match target.provider() {
            "s3" => {
                let initiate = if request.checksum == UPLOAD_CHECKSUM_SHA256 {
                    upload.checksum = UPLOAD_CHECKSUM_SHA256.to_owned();
                    initiation_context(&ctx, UPLOAD_CHECKSUM_SHA256)
                } else {
                    ctx.clone()
                };
                upload.provider_upload_id = target.initiate_multipart(&initiate, &full_key, &content_type).await?;
            }
            "gcs" | PROVIDER_VOLUME => {
                upload.session_url = target
                    .initiate_resumable(&ctx, &full_key, request.size, &content_type)
                    .await?;
            }
            other => {
                return Err(Error::internal(format!(
                    "provider {other:?} does not support resumable uploads"
                )));
            }
        }
        let token = match seal_resume_token(&*target, &upload, now) {
            Ok(token) => token,
            Err(error) => {
                let _ = self.abort_provider(&OpCtx::default(), &*target, &upload).await;
                return Err(error);
            }
        };
        upload.id = upload_id_from_token(&token);
        upload.resume_token = token;
        if let Err(error) = self.put(upload.clone()) {
            // The cleanup is a best effort when the session cannot be kept in memory.
            let _ = self.abort_provider(&OpCtx::default(), &*target, &upload).await;
            return Err(error);
        }
        Ok(upload)
    }

    /// The state of an upload from its resume token. The function calls `check` before the first read of the session
    /// and of the storage. The instance and the key come from the sealed token, never from the client.
    pub async fn resume_checked(
        &self,
        targets: &dyn Targets,
        ctx: &OpCtx,
        token: &str,
        check: &dyn AccessCheck,
    ) -> Result<UploadSession> {
        let now = Timestamp::now();
        let (descriptor, target) = open_resume_token(token, targets, now)?;
        target.require_permission(PERMISSION_WRITE)?;
        check.check(&*target, &descriptor.key).await?;
        let id = upload_id_from_token(token);
        if let Some(existing) = self.get(&id) {
            return self.status(targets, ctx, &existing.id).await;
        }
        if !self.has_capacity_for(&id) {
            return Err(capacity_error());
        }
        let mut upload = UploadSession {
            id: id.clone(),
            instance: descriptor.instance,
            key: descriptor.key,
            provider: descriptor.provider,
            status: STATUS_UPLOADING.to_owned(),
            content_type: descriptor.content_type,
            total_size: descriptor.total_size,
            chunk_size: descriptor.chunk_size,
            provider_upload_id: descriptor.provider_upload_id,
            session_url: descriptor.session_url,
            checksum: descriptor.checksum,
            created_at: Timestamp::from_unix(descriptor.issued_at, 0),
            updated_at: now,
            resume_token: token.to_owned(),
            ..UploadSession::default()
        };
        if upload.chunk_size <= 0 {
            upload.chunk_size = upload_chunk_size(&upload.provider, upload.total_size).map_err(Error::internal)?;
        }
        self.put(upload)?;
        self.status(targets, ctx, &id).await
    }

    async fn abort_provider(&self, ctx: &OpCtx, target: &dyn UploadTarget, upload: &UploadSession) -> Result<()> {
        match upload.provider.as_str() {
            "s3" => {
                if upload.provider_upload_id.is_empty() {
                    return Ok(());
                }
                target
                    .abort_multipart(ctx, &target.full_key(&upload.key), &upload.provider_upload_id)
                    .await
            }
            "gcs" | PROVIDER_VOLUME => {
                if upload.session_url.is_empty() {
                    return Ok(());
                }
                target.abort_resumable(ctx, &upload.session_url).await
            }
            _ => Ok(()),
        }
    }

    /// Send one chunk of an upload.
    pub async fn upload_chunk(
        &self,
        targets: &dyn Targets,
        ctx: &OpCtx,
        id: &str,
        input: ChunkInput,
    ) -> Result<UploadSession> {
        let lock = self.upload_lock(id);
        let _guard = lock.lock().await;
        let mut upload = self.get(id).ok_or_else(not_found)?;
        if upload.status != STATUS_UPLOADING {
            return Err(Error::api(409, "upload_not_active", "upload session is not active"));
        }
        let target = targets.target(&upload.instance).ok_or_else(unknown_instance)?;
        target.require_permission(PERMISSION_WRITE)?;
        let range = input
            .headers
            .get("Content-Range")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        let (start, end, total) =
            parse_content_range(range).map_err(|message| Error::api(400, "invalid_content_range", message))?;
        if total != upload.total_size {
            return Err(Error::api(
                409,
                "size_mismatch",
                "Content-Range total does not match the upload session",
            ));
        }
        let size = end - start + 1;
        if input.content_length < 0 {
            return Err(Error::api(
                411,
                "content_length_required",
                "Content-Length is required for upload chunks",
            ));
        }
        if input.content_length != size {
            return Err(Error::api(
                400,
                "content_length_mismatch",
                "Content-Length does not match Content-Range",
            ));
        }
        // The ceiling object.write of this request: the continuation answer has its own ceilings.
        check_object_ceiling(ctx, ACTION_WRITE, upload.total_size)?;

        if start != upload.uploaded_bytes {
            match upload.provider.as_str() {
                "gcs" | PROVIDER_VOLUME => self.synchronize_gcs_offset(ctx, &*target, &mut upload).await?,
                "s3" => self.synchronize_s3_parts(ctx, &*target, &mut upload).await?,
                _ => {}
            }
        }
        if start != upload.uploaded_bytes {
            return Err(Error::api(
                409,
                "offset_mismatch",
                format!("upload must resume at byte {}", upload.uploaded_bytes),
            ));
        }

        let body = limit_body(input.body, size);
        upload.error.clear();
        match upload.provider.clone().as_str() {
            "s3" => {
                if size > MAXIMUM_S3_PART_SIZE {
                    return Err(Error::api(400, "part_too_large", "S3 upload parts cannot exceed 5 GiB"));
                }
                if end + 1 < total && size < MINIMUM_S3_PART_SIZE {
                    return Err(Error::api(
                        400,
                        "part_too_small",
                        "non-final S3 upload parts must be at least 5 MiB",
                    ));
                }
                let part_number = upload.parts.len() as i64 + 1;
                if part_number > MAXIMUM_S3_PARTS {
                    return Err(Error::api(
                        400,
                        "too_many_parts",
                        "S3 multipart uploads cannot exceed 10000 parts",
                    ));
                }
                let (part_ctx, transfer) = if upload.checksum == UPLOAD_CHECKSUM_SHA256 {
                    let digest = parse_checksum_header(&input.headers)?;
                    if digest.is_empty() {
                        return Err(Error::api(
                            400,
                            "checksum_required",
                            "X-Checksum-Sha256 is required for each chunk of this upload",
                        ));
                    }
                    with_checksum_transfer(ctx, &digest)
                } else {
                    (ctx.clone(), None)
                };
                let full_key = target.full_key(&upload.key);
                let number = u32::try_from(part_number).unwrap_or(u32::MAX);
                let etag = match target
                    .upload_part(&part_ctx, &full_key, &upload.provider_upload_id, number, body, size)
                    .await
                {
                    Ok(etag) => etag,
                    Err(error) => {
                        upload.error = error.public_message();
                        upload.updated_at = Timestamp::now();
                        let _ = self.put(upload);
                        return Err(error);
                    }
                };
                let mut part = UploadPartState {
                    part_number: number,
                    etag,
                    size,
                    ..UploadPartState::default()
                };
                if let Some(transfer) = &transfer {
                    part.checksum_sha256.clone_from(&transfer.sha256);
                    part.checksum_stored = transfer
                        .echoed
                        .lock()
                        .map(|echoed| *echoed == transfer.sha256)
                        .unwrap_or(false);
                }
                upload.parts.push(part);
                upload.uploaded_bytes = end + 1;
                upload.updated_at = Timestamp::now();
                self.put(upload.clone())?;
                if upload.uploaded_bytes == upload.total_size {
                    self.complete_s3(ctx, &*target, &mut upload).await?;
                }
            }
            "gcs" | PROVIDER_VOLUME => {
                let result = target
                    .upload_resumable_chunk(ctx, &upload.session_url, body, start, size, total, &upload.content_type)
                    .await;
                let (next, complete) = match result {
                    Ok(value) => value,
                    Err(error) => {
                        upload.error = error.public_message();
                        upload.updated_at = Timestamp::now();
                        let _ = self.put(upload);
                        return Err(error);
                    }
                };
                if next < start || next > total {
                    return Err(Error::internal("gcs resumable upload returned an invalid offset"));
                }
                upload.uploaded_bytes = next;
                upload.updated_at = Timestamp::now();
                if complete {
                    let now = upload.updated_at;
                    upload.status = STATUS_COMPLETED.to_owned();
                    upload.completed_at = Some(now);
                    self.verify_completed_object(ctx, &*target, &mut upload).await?;
                }
                self.put(upload.clone())?;
            }
            other => return Err(Error::internal(format!("unsupported upload provider {other:?}"))),
        }
        Ok(upload)
    }

    async fn complete_s3(&self, ctx: &OpCtx, target: &dyn UploadTarget, upload: &mut UploadSession) -> Result<()> {
        let parts: Vec<CompletedPart> = upload
            .parts
            .iter()
            .map(|part| CompletedPart {
                number: part.part_number,
                etag: part.etag.clone(),
                checksum_sha256: part.checksum_sha256.clone(),
            })
            .collect();
        let full_key = target.full_key(&upload.key);
        if let Err(error) = target
            .complete_multipart(ctx, &full_key, &upload.provider_upload_id, &parts)
            .await
        {
            upload.error = error.public_message();
            upload.updated_at = Timestamp::now();
            let _ = self.put(upload.clone());
            return Err(error);
        }
        let now = Timestamp::now();
        upload.status = STATUS_COMPLETED.to_owned();
        upload.error.clear();
        upload.updated_at = now;
        upload.completed_at = Some(now);
        self.verify_completed_object(ctx, target, upload).await?;
        self.put(upload.clone())
    }

    async fn synchronize_s3_parts(
        &self,
        ctx: &OpCtx,
        target: &dyn UploadTarget,
        upload: &mut UploadSession,
    ) -> Result<()> {
        if upload.provider_upload_id.is_empty() {
            return Ok(());
        }
        let parts = target
            .list_multipart_parts(ctx, &target.full_key(&upload.key), &upload.provider_upload_id)
            .await?;
        let known: HashMap<u32, &UploadPartState> = upload.parts.iter().map(|part| (part.part_number, part)).collect();
        let mut state = Vec::with_capacity(parts.len());
        let mut uploaded: i64 = 0;
        for (index, part) in parts.iter().enumerate() {
            if part.number as usize != index + 1 || part.size <= 0 || part.etag.trim().is_empty() {
                return Err(Error::internal(
                    "s3 multipart upload contains a non-contiguous or invalid part sequence",
                ));
            }
            let mut item = UploadPartState {
                part_number: part.number,
                etag: part.etag.clone(),
                size: part.size,
                ..UploadPartState::default()
            };
            if upload.checksum == UPLOAD_CHECKSUM_SHA256 {
                match known.get(&part.number) {
                    Some(local) if local.etag == part.etag && !local.checksum_sha256.is_empty() => {
                        // The server sends this part and the provider confirms its digest: keep what the server knows.
                        item.checksum_sha256.clone_from(&local.checksum_sha256);
                        item.checksum_stored = local.checksum_stored;
                    }
                    _ => {
                        // A provider such as Garage lists the digest of each stored part: it is the digest that the provider checks.
                        item.checksum_sha256.clone_from(&part.checksum_sha256);
                        item.checksum_stored = !part.checksum_sha256.is_empty();
                    }
                }
            }
            state.push(item);
            uploaded += part.size;
        }
        if uploaded > upload.total_size {
            return Err(Error::internal(
                "s3 multipart upload contains more bytes than the local upload session",
            ));
        }
        upload.parts = state;
        upload.uploaded_bytes = uploaded;
        upload.updated_at = Timestamp::now();
        self.put(upload.clone())
    }

    async fn verify_completed_object(
        &self,
        ctx: &OpCtx,
        target: &dyn UploadTarget,
        upload: &mut UploadSession,
    ) -> Result<()> {
        if target.require_permission(PERMISSION_READ).is_err() {
            // The check reads the object back. On an instance without the read permission it would show whether and
            // how large a key is, so the session stays unverified.
            upload.verified = false;
            return Ok(());
        }
        let response = match target.head(ctx, &target.full_key(&upload.key)).await {
            Ok(response) => response,
            Err(error) => {
                upload.error = "the upload completed but the final object could not be verified".to_owned();
                upload.verified = false;
                upload.updated_at = Timestamp::now();
                let _ = self.put(upload.clone());
                return Err(error);
            }
        };
        let size: i64 = response
            .headers
            .get(http::header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().parse().ok())
            .unwrap_or(0);
        if size != upload.total_size {
            upload.error = format!(
                "the upload completed but the provider reports {size} bytes instead of {}",
                upload.total_size
            );
            upload.verified = false;
            upload.updated_at = Timestamp::now();
            let _ = self.put(upload.clone());
            return Err(Error::internal("completed upload size verification failed"));
        }
        if upload.checksum == UPLOAD_CHECKSUM_SHA256
            && let Err(error) = verify_upload_checksum(&response.headers, upload)
        {
            upload.error = error.to_string();
            upload.verified = false;
            upload.checksum_verified = false;
            upload.updated_at = Timestamp::now();
            let _ = self.put(upload.clone());
            return Err(error);
        }
        upload.verified = true;
        upload.error.clear();
        Ok(())
    }

    async fn synchronize_gcs_offset(
        &self,
        ctx: &OpCtx,
        target: &dyn UploadTarget,
        upload: &mut UploadSession,
    ) -> Result<()> {
        let (next, complete) = target
            .query_resumable(ctx, &upload.session_url, upload.total_size)
            .await?;
        upload.uploaded_bytes = next;
        upload.updated_at = Timestamp::now();
        if complete {
            let now = upload.updated_at;
            upload.status = STATUS_COMPLETED.to_owned();
            upload.completed_at = Some(now);
            self.verify_completed_object(ctx, target, upload).await?;
        }
        self.put(upload.clone())
    }

    /// The state of a session. The function reads the provider again for a session that sends chunks.
    pub async fn status(&self, targets: &dyn Targets, ctx: &OpCtx, id: &str) -> Result<UploadSession> {
        let lock = self.upload_lock(id);
        let _guard = lock.lock().await;
        let mut upload = self.get(id).ok_or_else(not_found)?;
        let target = targets.target(&upload.instance).ok_or_else(unknown_instance)?;
        if upload.status == STATUS_UPLOADING {
            match upload.provider.as_str() {
                "gcs" | PROVIDER_VOLUME => {
                    if let Err(error) = self.synchronize_gcs_offset(ctx, &*target, &mut upload).await {
                        // The last offset in memory stays when the provider is not available.
                        upload.error = error.public_message();
                        upload.updated_at = Timestamp::now();
                        let _ = self.put(upload.clone());
                    }
                }
                "s3" => self.status_of_s3(ctx, &*target, &mut upload).await,
                _ => {}
            }
        }
        if upload.status == STATUS_COMPLETED && !upload.verified {
            match self.verify_completed_object(ctx, &*target, &mut upload).await {
                Ok(()) => upload.error.clear(),
                Err(error) => upload.error = error.public_message(),
            }
            upload.updated_at = Timestamp::now();
            let _ = self.put(upload.clone());
        }
        Ok(upload)
    }

    async fn status_of_s3(&self, ctx: &OpCtx, target: &dyn UploadTarget, upload: &mut UploadSession) {
        match self.synchronize_s3_parts(ctx, target, upload).await {
            Err(error) => {
                // The provider may remove the multipart session at once after the completion. The final object
                // must be verified before the session counts as complete.
                if error.is_not_found() && target.require_permission(PERMISSION_READ).is_err() {
                    // A vanished multipart session proves the completion only when the object can be checked.
                    // Without the read permission the answer is the same whether the key exists or not.
                    upload.error = "the upload session is no longer available".to_owned();
                    upload.updated_at = Timestamp::now();
                    let _ = self.put(upload.clone());
                } else if error.is_not_found() {
                    let now = Timestamp::now();
                    upload.status = STATUS_COMPLETED.to_owned();
                    upload.uploaded_bytes = upload.total_size;
                    upload.completed_at = Some(now);
                    upload.updated_at = now;
                    match self.verify_completed_object(ctx, target, upload).await {
                        Ok(()) => {
                            let _ = self.put(upload.clone());
                        }
                        Err(verify_error) => {
                            upload.status = STATUS_UPLOADING.to_owned();
                            upload.uploaded_bytes = 0;
                            upload.completed_at = None;
                            upload.error = verify_error.public_message();
                            let _ = self.put(upload.clone());
                        }
                    }
                } else {
                    upload.error = error.public_message();
                    upload.updated_at = Timestamp::now();
                    let _ = self.put(upload.clone());
                }
            }
            Ok(()) => {
                if upload.uploaded_bytes == upload.total_size
                    && !upload.parts.is_empty()
                    && let Err(error) = self.complete_s3(ctx, target, upload).await
                {
                    upload.error = error.public_message();
                    let _ = self.put(upload.clone());
                }
            }
        }
    }

    /// Cancel an upload: abort the provider session and keep the canceled state.
    pub async fn cancel(&self, targets: &dyn Targets, ctx: &OpCtx, id: &str) -> Result<UploadSession> {
        let lock = self.upload_lock(id);
        let _guard = lock.lock().await;
        let mut upload = self.get(id).ok_or_else(not_found)?;
        if upload.status == STATUS_COMPLETED || upload.status == STATUS_CANCELED {
            return Ok(upload);
        }
        let target = targets.target(&upload.instance).ok_or_else(unknown_instance)?;
        target.require_permission(PERMISSION_WRITE)?;
        self.abort_provider(ctx, &*target, &upload).await?;
        upload.status = STATUS_CANCELED.to_owned();
        upload.error.clear();
        upload.updated_at = Timestamp::now();
        self.put(upload.clone())?;
        Ok(upload)
    }
}

/// The id that the list of the incomplete uploads gives to the temporary file of a volume session: its name.
pub fn volume_session_upload_id(session: &str) -> String {
    let temporary = session.split('\0').next().unwrap_or("");
    if temporary.is_empty() {
        return ".".to_owned();
    }
    let trimmed = temporary.trim_end_matches('/');
    if trimmed.is_empty() {
        return "/".to_owned();
    }
    trimmed.rsplit('/').next().unwrap_or(trimmed).to_owned()
}
