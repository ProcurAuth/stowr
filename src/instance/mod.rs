//! The storage instance: one bucket block or one volume block, over its back end.
//!
//! An [`Instance`] wraps a [`Backend`]. Each call takes a slot of the gate of the process and of the gate of the
//! instance, counts the resource budget of the context, checks the ceilings of the access policy, and learns the
//! permissions of the provider from the result (docs/ARCHITECTURE.md, "Storage interfaces"; docs/SECURITY.md,
//! "Permission enforcement"). The instance also gives the version functions, the multipart functions, the start
//! probes of the versioning, and the public facts of `/api/instances`.
//!
//! The feature work packages add their methods to `Instance` in their own folders (`impl Instance` blocks), and
//! keep their state in the fields that this structure gives them.

pub mod budget;
pub mod ceiling;
pub mod cursor;
pub mod gate;
pub mod range;

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

use http::HeaderMap;
use serde::Serialize;

use crate::common::config::{BucketConfig, PERMISSION_DELETE, PERMISSION_READ, PERMISSION_WRITE, RuntimePolicy};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::Body;
use crate::common::storage::{
    Backend, Capabilities, CapabilityState, CompletedPart, ListOptions, ListPage, MultipartCopyOptions, MultipartPart,
    ObjectResponse, ObjectVersionPage,
};

/// The state of the versioning of an instance: the result of the start probe and the last status of the bucket.
#[derive(Debug, Default)]
pub struct VersioningState {
    /// `(supported, checked)`.
    pub probe: Mutex<(bool, bool)>,
    /// The last status of `GetBucketVersioning`: `Enabled`, `Suspended` or empty, when a read worked.
    pub status: Mutex<Option<String>>,
}

/// One storage instance.
pub struct Instance {
    /// The configuration of the block.
    pub cfg: BucketConfig,
    /// The back end.
    pub backend: Arc<dyn Backend>,
    /// The limits of the process.
    pub policy: Arc<RuntimePolicy>,
    /// The gate of the process.
    pub global_gate: gate::Gate,
    /// The gate of the instance.
    pub gate: gate::Gate,
    /// The permissions that the process knows.
    pub caps: Mutex<Capabilities>,
    /// The versioning.
    pub versioning: VersioningState,
    /// Set when the provider refused the batch delete one time.
    pub batch_delete_off: AtomicBool,
    /// The state of the tags (work package `lifecycle`).
    pub tags: crate::lifecycle::TagsState,
    /// The state of the lifecycle editor and of the bucket facts (work package `lifecycle`).
    pub rules: crate::lifecycle::RulesState,
    /// The state of the list of the incomplete uploads (work package `uploads`).
    pub multiparts: crate::uploads::MultipartsState,
    /// The state of Object Lock (work package `bucket`).
    pub object_lock: crate::bucket::ObjectLockCapability,
    /// The state of the default encryption (work package `bucket`).
    pub encryption: crate::bucket::EncryptionCapability,
    /// The state of the edit of the metadata (work package `bucket`).
    pub metadata: crate::bucket::MetadataCapability,
    /// The reader and the cache of the usage (work package `bucket`).
    pub usage: crate::bucket::UsageCapability,
}

/// The public facts of an instance in `/api/instances` (docs/ARCHITECTURE.md).
#[derive(Clone, Debug, Default, Serialize)]
pub struct InstanceInfo {
    /// The id.
    pub id: String,
    /// The host: the label of the auth block, or `volume`.
    pub host: String,
    /// The name.
    pub name: String,
    /// `s3`, `gcs` or `fs`.
    pub provider: String,
}

impl Instance {
    /// An instance over a back end, with the gates of the process.
    pub fn new(
        cfg: BucketConfig,
        backend: Arc<dyn Backend>,
        policy: Arc<RuntimePolicy>,
        global_gate: gate::Gate,
    ) -> Self {
        let gate = gate::Gate::new(policy.max_concurrent_requests_per_storage);
        Self {
            cfg,
            backend,
            policy,
            global_gate,
            gate,
            caps: Mutex::new(Capabilities::default()),
            versioning: VersioningState::default(),
            batch_delete_off: AtomicBool::new(false),
            tags: Default::default(),
            rules: Default::default(),
            multiparts: Default::default(),
            object_lock: Default::default(),
            encryption: Default::default(),
            metadata: Default::default(),
            usage: Default::default(),
        }
    }

    /// The full key of a relative key: the root prefix and the key, without the `/` at the start of the key.
    pub fn full_key(&self, relative: &str) -> String {
        format!("{}{}", self.cfg.root_prefix, relative.trim_start_matches('/'))
    }

    /// The relative key of a full key, or `None` for a key outside of the root prefix.
    pub fn relative_key(&self, full: &str) -> Option<String> {
        if self.cfg.root_prefix.is_empty() {
            return Some(full.trim_start_matches('/').to_owned());
        }
        full.strip_prefix(self.cfg.root_prefix.as_str()).map(str::to_owned)
    }

    /// True when a request may reach the back end with this permission. Only the configuration, `force_read_only`
    /// and a denial of a probe stop it; a denial that one provider call taught does not.
    pub fn permitted(&self, permission: &str) -> bool {
        if self.policy.force_read_only() && permission != PERMISSION_READ {
            return false;
        }
        self.cfg.allows(permission)
    }

    /// `403 permission_denied` when the permission is not permitted.
    pub fn require_permission(&self, permission: &str) -> Result<()> {
        if self.permitted(permission) {
            return Ok(());
        }
        Err(Error::api(
            403,
            "permission_denied",
            format!("instance {:?} does not expose {permission} permission", self.cfg.id),
        ))
    }

    /// The permissions that the process knows now.
    pub fn capabilities(&self) -> Capabilities {
        self.caps.lock().map(|caps| caps.clone()).unwrap_or_default()
    }

    /// The state of one permission (`read`, `write` or `delete`).
    pub fn capability(&self, permission: &str) -> CapabilityState {
        let caps = self.capabilities();
        match permission {
            PERMISSION_READ => caps.read,
            PERMISSION_WRITE => caps.write,
            PERMISSION_DELETE => caps.delete,
            _ => CapabilityState::default(),
        }
    }

    /// One page of a listing.
    pub async fn list(&self, ctx: &OpCtx, options: &ListOptions) -> Result<ListPage> {
        self.backend.list(ctx, options).await
    }

    /// The headers of an object, or of the version of the context.
    pub async fn head(&self, ctx: &OpCtx, key: &str) -> Result<ObjectResponse> {
        self.backend.head(ctx, key).await
    }

    /// The bytes of an object, or of the version of the context.
    pub async fn get(&self, ctx: &OpCtx, key: &str, headers: &HeaderMap) -> Result<ObjectResponse> {
        self.backend.get(ctx, key, headers).await
    }

    /// Write an object. The ceiling `object.write` applies before the first byte.
    pub async fn put(&self, ctx: &OpCtx, key: &str, body: Body, size: i64, content_type: &str) -> Result<()> {
        self.backend.put(ctx, key, body, size, content_type).await
    }

    /// Write an object only when no object exists at the key.
    pub async fn put_if_absent(&self, ctx: &OpCtx, key: &str, body: Body, size: i64, content_type: &str) -> Result<()> {
        let _ = (ctx, key, body, size, content_type);
        Err(Error::not_served("the write that creates only"))
    }

    /// Delete an object. A refusal that an active Object Lock explains gives `409 object_locked`.
    pub async fn delete(&self, ctx: &OpCtx, key: &str) -> Result<()> {
        self.backend.delete(ctx, key).await
    }

    /// Delete keys, in batches of 1000 when the back end can. Gives the keys that an active Object Lock keeps.
    pub async fn delete_many(&self, ctx: &OpCtx, keys: &[String]) -> Result<Vec<String>> {
        let _ = (ctx, keys);
        Err(Error::not_served("the delete of many keys"))
    }

    /// Copy one object. The ceilings of read and write apply to the size of the source.
    pub async fn copy(&self, ctx: &OpCtx, source: &str, destination: &str) -> Result<()> {
        self.backend.copy(ctx, source, destination).await
    }

    /// Copy one object of a known size: in parts from the threshold of the copy in parts up.
    pub async fn copy_sized(
        &self,
        ctx: &OpCtx,
        source: &str,
        destination: &str,
        size: i64,
        progress: Option<crate::common::storage::CopyProgress>,
    ) -> Result<()> {
        let _ = (ctx, source, destination, size, progress);
        Err(Error::not_served("the copy of a known size"))
    }

    /// One page of the versions of one key.
    pub async fn list_versions(
        &self,
        ctx: &OpCtx,
        key: &str,
        page_token: &str,
        maximum: u32,
    ) -> Result<ObjectVersionPage> {
        let _ = (ctx, key, page_token, maximum);
        Err(Error::not_served("the versions"))
    }

    /// The headers of one version (an empty version: the current object).
    pub async fn head_version(&self, ctx: &OpCtx, key: &str, version: &str) -> Result<ObjectResponse> {
        let _ = (ctx, key, version);
        Err(Error::not_served("the read of a version"))
    }

    /// The bytes of one version (an empty version: the current object).
    pub async fn get_version(
        &self,
        ctx: &OpCtx,
        key: &str,
        version: &str,
        headers: &HeaderMap,
    ) -> Result<ObjectResponse> {
        let _ = (ctx, key, version, headers);
        Err(Error::not_served("the read of a version"))
    }

    /// Delete one version for ever.
    pub async fn delete_version(&self, ctx: &OpCtx, key: &str, version: &str) -> Result<()> {
        let _ = (ctx, key, version);
        Err(Error::not_served("the delete of a version"))
    }

    /// Copy one version onto its key (in parts from the threshold up).
    pub async fn restore_version(&self, ctx: &OpCtx, key: &str, version: &str) -> Result<()> {
        let _ = (ctx, key, version);
        Err(Error::not_served("the restore of a version"))
    }

    /// Copy an object in parts on the provider.
    pub async fn copy_multipart(
        &self,
        ctx: &OpCtx,
        source: &str,
        destination: &str,
        options: MultipartCopyOptions,
    ) -> Result<()> {
        let _ = (ctx, source, destination, options);
        Err(Error::not_served("the copy in parts"))
    }

    /// True when a copy of this size goes in parts.
    pub fn copies_in_parts(&self, size: i64) -> bool {
        let _ = size;
        false
    }

    /// True when the back end moves an object with one rename (a volume).
    pub fn moves_objects(&self) -> bool {
        self.backend.mover().is_some()
    }

    /// Move one object with one rename.
    pub async fn move_object(&self, ctx: &OpCtx, source: &str, destination: &str) -> Result<()> {
        let _ = (ctx, source, destination);
        Err(Error::not_served("the move of an object"))
    }

    /// Remove the empty folders under a full prefix (a volume; nothing for the other back ends).
    pub async fn remove_empty_folders(&self, ctx: &OpCtx, prefix: &str) -> Result<()> {
        let _ = (ctx, prefix);
        Ok(())
    }

    /// Start an S3 multipart upload.
    pub async fn initiate_multipart(&self, ctx: &OpCtx, key: &str, content_type: &str) -> Result<String> {
        let _ = (ctx, key, content_type);
        Err(Error::not_served("the multipart upload"))
    }

    /// Send one part of an S3 multipart upload; gives its ETag.
    pub async fn upload_part(
        &self,
        ctx: &OpCtx,
        key: &str,
        upload_id: &str,
        number: u32,
        body: Body,
        size: i64,
    ) -> Result<String> {
        let _ = (ctx, key, upload_id, number, body, size);
        Err(Error::not_served("the multipart upload"))
    }

    /// Complete an S3 multipart upload.
    pub async fn complete_multipart(
        &self,
        ctx: &OpCtx,
        key: &str,
        upload_id: &str,
        parts: &[CompletedPart],
    ) -> Result<()> {
        let _ = (ctx, key, upload_id, parts);
        Err(Error::not_served("the multipart upload"))
    }

    /// Abort a multipart upload, or remove the temporary file of a volume upload.
    pub async fn abort_multipart(&self, ctx: &OpCtx, key: &str, upload_id: &str) -> Result<()> {
        let _ = (ctx, key, upload_id);
        Err(Error::not_served("the multipart upload"))
    }

    /// The parts of an S3 multipart upload.
    pub async fn list_multipart_parts(&self, ctx: &OpCtx, key: &str, upload_id: &str) -> Result<Vec<MultipartPart>> {
        let _ = (ctx, key, upload_id);
        Err(Error::not_served("the multipart upload"))
    }

    /// Start a resumable upload (GCS, a volume); gives the session.
    pub async fn initiate_resumable(&self, ctx: &OpCtx, key: &str, total: i64, content_type: &str) -> Result<String> {
        let _ = (ctx, key, total, content_type);
        Err(Error::not_served("the resumable upload"))
    }

    /// Send one chunk of a resumable upload; gives the next offset and true at the end.
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
        let _ = (ctx, session, body, start, size, total, content_type);
        Err(Error::not_served("the resumable upload"))
    }

    /// The next offset of a resumable upload, and true at the end.
    pub async fn query_resumable(&self, ctx: &OpCtx, session: &str, total: i64) -> Result<(i64, bool)> {
        let _ = (ctx, session, total);
        Err(Error::not_served("the resumable upload"))
    }

    /// Abort a resumable upload.
    pub async fn abort_resumable(&self, ctx: &OpCtx, session: &str) -> Result<()> {
        let _ = (ctx, session);
        Err(Error::not_served("the resumable upload"))
    }

    /// Learn the permissions again (`POST /api/permissions/refresh`).
    pub async fn refresh_capabilities(&self, ctx: &OpCtx) -> Capabilities {
        let _ = ctx;
        self.capabilities()
    }

    /// The start probe of the versioning: one bounded list of versions.
    pub async fn probe_versioning(&self, ctx: &OpCtx) -> bool {
        let _ = ctx;
        false
    }

    /// True when the probe found the versions.
    pub fn versioning_available(&self) -> bool {
        false
    }

    /// `enabled`, `suspended`, `off`, or `None` when the server could not read the status.
    pub fn versioning_state(&self) -> Option<&'static str> {
        None
    }

    /// The public facts of the instance.
    pub fn public_info(&self) -> InstanceInfo {
        InstanceInfo {
            id: self.cfg.id.clone(),
            host: self.cfg.auth_id.clone(),
            name: self.cfg.name.clone(),
            provider: self.cfg.provider.clone(),
        }
    }
}
