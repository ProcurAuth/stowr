//! The usage of a volume. The part of the bucket is the size of the files of the folder, from the count of its sizer
//! (`size.rs`): the read never walks the tree. The part of the storage is the file system of the folder (`statfs`):
//! used = size - available, total = size, free = available. These numbers are for the whole file system. They are
//! exact at the time of the read, except on a FUSE or network file system, which can count with a delay: they are
//! then approximate.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use super::path::os_error_text;
use super::size::{SizeState, VolumeSizer};
use super::statfs::{FileSystemSize, statfs};
use crate::bucket::{BucketUsage, BucketUsageReader, StorageCapacity};
use crate::common::BoxFuture;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::time::Timestamp;

/// The source of the usage of a volume: the size of its file system.
pub const USAGE_SOURCE_STATFS: &str = "statfs";

/// The scope of the capacity of a volume: the file system of its folder.
pub const SCOPE_FILESYSTEM: &str = "filesystem";

/// The reason of an approximate capacity of a FUSE or network file system.
pub const DELAYED_REASON: &str =
    "The volume is on a FUSE or network file system: it can count the used bytes with a delay.";

/// True: this system gives the size of the file system of a volume.
pub const USAGE_SUPPORTED: bool = true;

/// The function that gives the capacity of a file system. A test sets its own.
pub type StatfsFunction = Arc<dyn Fn(&Path) -> io::Result<FileSystemSize> + Send + Sync>;

/// The count of the files of a volume, with its state and its time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VolumeUsage {
    /// The sum of the sizes of the files.
    pub used_bytes: i64,
    /// The number of files.
    pub used_objects: i64,
    /// The state of the count: `computing`, `partial` or `ready`.
    pub state: SizeState,
    /// The time of the count.
    pub as_of: Timestamp,
}

/// The reader of the usage of a volume. A read costs no request: the server reads it at each request.
#[derive(Clone)]
pub struct VolumeUsageReader {
    root: PathBuf,
    sizer: VolumeSizer,
    statfs: Option<StatfsFunction>,
}

impl std::fmt::Debug for VolumeUsageReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VolumeUsageReader")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl VolumeUsageReader {
    /// A reader for the folder `root`, with the count of `sizer`.
    pub fn new(root: PathBuf, sizer: VolumeSizer) -> Self {
        Self {
            root,
            sizer,
            statfs: None,
        }
    }

    /// The same reader with another function for `statfs`. The tests use it.
    pub fn with_statfs(mut self, function: StatfsFunction) -> Self {
        self.statfs = Some(function);
        self
    }

    /// True: a read of a volume costs no request.
    pub fn is_live(&self) -> bool {
        true
    }

    /// The count of the files of the folder. It starts a walk in the background when the count is old.
    pub fn volume_usage(&self) -> VolumeUsage {
        let count = self.sizer.snapshot();
        VolumeUsage {
            used_bytes: count.bytes,
            used_objects: count.files,
            state: count.state,
            as_of: count.at.unwrap_or_else(Timestamp::now),
        }
    }

    /// The capacity of the file system of the folder.
    pub fn capacity(&self) -> Result<StorageCapacity> {
        let measured = match &self.statfs {
            Some(function) => function(&self.root),
            None => statfs(&self.root),
        };
        let size = measured.map_err(|error| match error.raw_os_error() {
            Some(_) => Error::internal(format!(
                "statfs: the file system of the volume does not give its size: {}",
                os_error_text(&error)
            )),
            None => Error::internal("statfs: the file system of the volume does not give its size"),
        })?;
        if size.total == 0 {
            // A FUSE mount can give a size of 0 for a short time, for example after a delete.
            return Err(Error::internal(
                "statfs: the file system of the volume gives a size of 0",
            ));
        }
        let used = size.total.saturating_sub(size.available);
        let mut capacity = StorageCapacity {
            scope: SCOPE_FILESYSTEM.to_owned(),
            used_bytes: clamp_to_i64(used),
            total_bytes: clamp_to_i64(size.total),
            free_bytes: clamp_to_i64(size.available),
            note: "the file system of the folder of the volume".to_owned(),
            ..StorageCapacity::default()
        };
        if size.delayed {
            capacity.approximate = true;
            capacity.approximate_reason = DELAYED_REASON.to_owned();
        }
        Ok(capacity)
    }
}

/// The value, or the largest `i64` for a larger value (a file system of more than 8 EiB).
fn clamp_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

impl BucketUsageReader for VolumeUsageReader {
    fn bucket_usage<'a>(&'a self, _ctx: &'a OpCtx, _bucket: &'a str) -> BoxFuture<'a, Result<BucketUsage>> {
        Box::pin(async move {
            let usage = self.volume_usage();
            Ok(BucketUsage {
                used_bytes: usage.used_bytes,
                used_objects: usage.used_objects,
                ..BucketUsage::default()
            })
        })
    }

    fn storage_capacity<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<Option<StorageCapacity>>> {
        Box::pin(async move {
            let reader = self.clone();
            let capacity = tokio::task::spawn_blocking(move || reader.capacity())
                .await
                .map_err(|_| Error::internal("the task of the capacity of the volume failed"))??;
            Ok(Some(capacity))
        })
    }
}
