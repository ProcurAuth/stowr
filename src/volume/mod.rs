//! The volume back end: a folder of the server that the browser shows as a bucket (docs/ARCHITECTURE.md,
//! "Volumes").
//!
//! This folder holds the only code of the program that writes to the local file system: the files of a `volume`
//! block (scripts/check-invariants.sh checks it). The temporary files of the writes are `.stowr-tmp-<random>` in the
//! folder of the target; a write ends with `fsync` and one rename.

pub mod path;
pub mod statfs;

use std::path::PathBuf;
use std::sync::Arc;

use http::HeaderMap;

use crate::common::BoxFuture;
use crate::common::config::{RuntimePolicy, VolumeConfig};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::Body;
use crate::common::storage::{Backend, DiscoveredCapabilities, ListOptions, ListPage, ObjectResponse};
use crate::instance::Instance;
use crate::instance::gate::Gate;

/// The back end of one volume.
pub struct VolumeBackend {
    /// The configuration of the block.
    pub cfg: VolumeConfig,
    /// The root: `path` and `root_prefix`, with the symbolic links resolved at start.
    pub root: PathBuf,
    /// True when the volume follows no symbolic link (mode `authzen`).
    pub refuse_links: bool,
}

/// The instance of a volume block. With write permissions, the start writes and removes a test file.
pub fn new_volume_instance(cfg: &VolumeConfig, policy: Arc<RuntimePolicy>, global_gate: Gate) -> Result<Instance> {
    let _ = (cfg, policy, global_gate);
    Err(Error::not_served("the volumes"))
}

macro_rules! not_served_future {
    ($what:expr) => {
        Box::pin(async move { Err(Error::not_served($what)) })
    };
}

impl Backend for VolumeBackend {
    fn list<'a>(&'a self, _ctx: &'a OpCtx, _options: &'a ListOptions) -> BoxFuture<'a, Result<ListPage>> {
        not_served_future!("the volume listing")
    }
    fn head<'a>(&'a self, _ctx: &'a OpCtx, _key: &'a str) -> BoxFuture<'a, Result<ObjectResponse>> {
        not_served_future!("the volume read")
    }
    fn get<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        not_served_future!("the volume read")
    }
    fn put<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _body: Body,
        _size: i64,
        _content_type: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        not_served_future!("the volume write")
    }
    fn delete<'a>(&'a self, _ctx: &'a OpCtx, _key: &'a str) -> BoxFuture<'a, Result<()>> {
        not_served_future!("the volume delete")
    }
    fn copy<'a>(&'a self, _ctx: &'a OpCtx, _source: &'a str, _destination: &'a str) -> BoxFuture<'a, Result<()>> {
        not_served_future!("the volume copy")
    }
    fn discover_capabilities<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<DiscoveredCapabilities>> {
        not_served_future!("the volume permissions")
    }
}
