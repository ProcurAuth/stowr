// SPDX-License-Identifier: MIT OR Apache-2.0
//! The volume back end: a folder of the server that the browser shows as a bucket (docs/ARCHITECTURE.md,
//! "Volumes").
//!
//! This folder holds the only code of the program that writes to the local file system: the files of a `volume`
//! block (scripts/check-invariants.sh checks it). The temporary files of the writes are `.stowr-tmp-<random>` in the
//! folder of the target; a write ends with `fsync` and one rename.
//!
//! The functions of the file system block, so each one runs on a thread of the blocking pool. A read of a file
//! streams its blocks to the answer, and a write takes its body through a small queue: the memory of an operation has
//! a fixed bound.

pub mod content_type;
mod http_time;
pub mod path;
mod read;
pub mod size;
pub mod statfs;
pub mod uploads;
pub mod usage;
mod write;

#[cfg(test)]
mod links_tests;
#[cfg(test)]
mod size_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod write_tests;

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use http::HeaderMap;

use self::path::resolve_inside;
use self::size::VolumeSizer;
use self::usage::VolumeUsageReader;
use crate::common::BoxFuture;
use crate::common::config::{
    BucketConfig, PERMISSION_DELETE, PERMISSION_READ, PERMISSION_WRITE, RuntimePolicy, VolumeConfig,
};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::Body;
use crate::common::storage::{
    Backend, Capabilities, CapabilityState, CapabilityStateName, ConditionalWriter, DiscoveredCapabilities,
    FolderRemover, ListOptions, ListPage, Mover, MultipartCopier, MultipartCopyOptions, ObjectResponse, ResumableApi,
};
use crate::common::time::Timestamp;
use crate::instance::Instance;
use crate::instance::gate::Gate;

/// The back end of one volume.
#[derive(Clone)]
pub struct VolumeBackend {
    /// The configuration of the block.
    pub cfg: VolumeConfig,
    /// The root: `path` and `root_prefix`, with the symbolic links resolved at start.
    pub root: PathBuf,
    /// True when the volume follows no symbolic link (mode `authzen`).
    pub refuse_links: bool,
    /// The `root_prefix` of the block. Each key of the storage instance starts with it.
    pub(crate) prefix: String,
    /// True when the start checked that the process can write in the root.
    pub(crate) writes: bool,
    /// The sizer that counts the files of the root in the background. A write marks its count old.
    pub(crate) sizer: VolumeSizer,
}

/// Run a task of the file system on the blocking pool.
pub(crate) async fn blocking<T, F>(task: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    match tokio::task::spawn_blocking(task).await {
        Ok(result) => result,
        Err(_) => Err(Error::internal("the task of the volume failed")),
    }
}

impl VolumeBackend {
    /// Open the folder of a volume block. When the server can write in the volume (the permissions include write or
    /// delete, and `server.access_mode` is not `force_read_only`), it writes and removes a temporary file in the
    /// root: a folder that the process cannot write stops the start.
    pub fn open(cfg: &VolumeConfig, force_read_only: bool) -> Result<Self> {
        let mut root = fs::canonicalize(&cfg.path).map_err(|error| {
            Error::internal(format!(
                "volume {:?}: path {:?}: cannot resolve the symbolic links: {}",
                cfg.id,
                cfg.path.display().to_string(),
                path::os_error_text(&error)
            ))
        })?;
        if !cfg.root_prefix.is_empty() {
            let prefix = cfg.root_prefix.strip_suffix('/').unwrap_or(&cfg.root_prefix);
            root = resolve_inside(&root, prefix).map_err(|error| {
                Error::internal(format!(
                    "volume {:?}: root_prefix {:?}: {error}",
                    cfg.id, cfg.root_prefix
                ))
            })?;
        }
        let sizer = VolumeSizer::new(root.clone());
        let mut backend = Self {
            cfg: cfg.clone(),
            root,
            refuse_links: cfg.refuse_links,
            prefix: cfg.root_prefix.clone(),
            writes: false,
            sizer,
        };
        if cfg.writes() && !force_read_only {
            if let Err(error) = backend.probe_write() {
                return Err(Error::internal(format!(
                    "volume {:?}: the process cannot write in path {:?}, and the permissions include write or delete \
                     (a block without permissions has all three): {}; give permissions = [\"read\"] for a volume that is read only",
                    cfg.id,
                    cfg.path.display().to_string(),
                    path::os_error_text(&error)
                )));
            }
            backend.writes = true;
        }
        Ok(backend)
    }

    /// The reader of the usage of this volume: the count of its sizer and the capacity of its file system.
    pub fn usage_reader(&self) -> VolumeUsageReader {
        VolumeUsageReader::new(self.root.clone(), self.sizer.clone())
    }

    /// The count of the files of the volume in the background.
    pub fn sizer(&self) -> &VolumeSizer {
        &self.sizer
    }
}

/// The permissions of an instance from the configuration, the policy of the process and what the back end learned.
/// A volume gives a verified state for each permission that its probes tested.
fn merge_capabilities(cfg: &BucketConfig, force_read_only: bool, discovered: &DiscoveredCapabilities) -> Capabilities {
    let state = |name: &str| -> CapabilityState {
        let denied = |source: &str, reason: &str| CapabilityState {
            state: CapabilityStateName::Denied,
            allowed: false,
            verified: true,
            source: source.to_owned(),
            reason: reason.to_owned(),
            expires: None,
        };
        if force_read_only && name != PERMISSION_READ {
            return denied(
                "runtime",
                "mutations are disabled by the administrative force_read_only policy",
            );
        }
        if cfg.permissions_defined && !cfg.permissions.iter().any(|value| value == name) {
            return denied("configuration", "action is disabled by the storage permission ceiling");
        }
        match discovered.states.get(name) {
            Some(known) if known.verified => known.clone(),
            Some(known) => CapabilityState {
                state: CapabilityStateName::Unknown,
                allowed: true,
                verified: false,
                source: known.source.clone(),
                reason: if known.reason.is_empty() {
                    "the provider cannot verify this permission without executing the real operation".to_owned()
                } else {
                    known.reason.clone()
                },
                expires: None,
            },
            None => CapabilityState {
                state: CapabilityStateName::Unknown,
                allowed: true,
                verified: false,
                source: "credentials".to_owned(),
                reason: "the provider permission has not been tested; the action remains available and will be verified when used"
                    .to_owned(),
                expires: None,
            },
        }
    };
    Capabilities {
        read: state(PERMISSION_READ),
        write: state(PERMISSION_WRITE),
        delete: state(PERMISSION_DELETE),
        permissions: discovered.permissions.clone(),
        checked_at: Some(Timestamp::now()),
        error: String::new(),
    }
}

/// The instance of a volume block. With write permissions, the start writes and removes a test file.
pub fn new_volume_instance(cfg: &VolumeConfig, policy: Arc<RuntimePolicy>, global_gate: Gate) -> Result<Instance> {
    let force_read_only = policy.force_read_only();
    let backend = VolumeBackend::open(cfg, force_read_only)?;
    // The checks at start read and wrote the folder: the permissions of the process are known.
    let discovered = backend.discover();
    let reader = backend.usage_reader();
    let bucket = cfg.bucket_config();
    let capabilities = merge_capabilities(&bucket, force_read_only, &discovered);
    let instance = Instance::new(bucket, Arc::new(backend), policy, global_gate);
    if let Ok(mut caps) = instance.caps.lock() {
        *caps = capabilities;
    }
    if let Ok(mut slot) = instance.usage.reader.lock() {
        *slot = Some(Arc::new(reader));
    }
    Ok(instance)
}

impl Backend for VolumeBackend {
    fn list<'a>(&'a self, ctx: &'a OpCtx, options: &'a ListOptions) -> BoxFuture<'a, Result<ListPage>> {
        Box::pin(async move {
            let backend = self.clone();
            let ctx = ctx.clone();
            let options = options.clone();
            blocking(move || backend.list_blocking(&ctx, &options)).await
        })
    }

    fn head<'a>(&'a self, _ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<ObjectResponse>> {
        Box::pin(async move {
            let backend = self.clone();
            let key = key.to_owned();
            blocking(move || backend.head_blocking(&key)).await
        })
    }

    fn get<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        key: &'a str,
        headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        Box::pin(async move { self.get_object(key, headers).await })
    }

    fn put<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        body: Body,
        size: i64,
        _content_type: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { self.put_object(ctx, key, body, size, false).await })
    }

    fn delete<'a>(&'a self, _ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let backend = self.clone();
            let key = key.to_owned();
            blocking(move || backend.delete_blocking(&key)).await
        })
    }

    fn copy<'a>(&'a self, ctx: &'a OpCtx, source: &'a str, destination: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let backend = self.clone();
            let ctx = ctx.clone();
            let (source, destination) = (source.to_owned(), destination.to_owned());
            blocking(move || backend.copy_blocking(&ctx, &source, &destination, None)).await
        })
    }

    fn discover_capabilities<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<DiscoveredCapabilities>> {
        Box::pin(async move {
            let backend = self.clone();
            blocking(move || Ok(backend.discover())).await
        })
    }

    fn conditional_writer(&self) -> Option<&dyn ConditionalWriter> {
        Some(self)
    }

    fn multipart_copier(&self) -> Option<&dyn MultipartCopier> {
        Some(self)
    }

    fn mover(&self) -> Option<&dyn Mover> {
        Some(self)
    }

    fn folder_remover(&self) -> Option<&dyn FolderRemover> {
        Some(self)
    }

    fn resumable(&self) -> Option<&dyn ResumableApi> {
        Some(self)
    }

    fn multipart_lister(&self) -> Option<&dyn crate::uploads::MultipartUploadLister> {
        Some(self)
    }

    fn incomplete_upload_remover(&self) -> Option<&dyn crate::uploads::IncompleteUploadRemover> {
        Some(self)
    }
}

impl ConditionalWriter for VolumeBackend {
    /// Write a file only when no file has its name.
    fn put_if_absent<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        body: Body,
        size: i64,
        _content_type: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { self.put_object(ctx, key, body, size, true).await })
    }
}

impl MultipartCopier for VolumeBackend {
    /// Copy a large file with the same stream as `copy`, and give the progress of the copy. A volume has no
    /// versions, no metadata and no tags: an option that names them is refused. It lets the jobs copy a large file
    /// with progress and cancel.
    fn copy_multipart<'a>(
        &'a self,
        ctx: &'a OpCtx,
        source: &'a str,
        destination: &'a str,
        options: MultipartCopyOptions,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            Self::check_copy_options(&options)?;
            let backend = self.clone();
            let ctx = ctx.clone();
            let (source, destination) = (source.to_owned(), destination.to_owned());
            blocking(move || backend.copy_blocking(&ctx, &source, &destination, options.progress)).await
        })
    }
}

impl Mover for VolumeBackend {
    fn move_object<'a>(&'a self, ctx: &'a OpCtx, source: &'a str, destination: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let backend = self.clone();
            let ctx = ctx.clone();
            let (source, destination) = (source.to_owned(), destination.to_owned());
            blocking(move || backend.move_blocking(&ctx, &source, &destination)).await
        })
    }
}

impl FolderRemover for VolumeBackend {
    fn remove_empty_folders<'a>(&'a self, ctx: &'a OpCtx, prefix: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let backend = self.clone();
            let ctx = ctx.clone();
            let prefix = prefix.to_owned();
            blocking(move || backend.remove_empty_folders_blocking(&ctx, &prefix)).await
        })
    }
}
