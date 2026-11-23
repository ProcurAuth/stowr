//! The writes of a volume. Each write of a file goes to a temporary file in the folder of the target, is
//! synchronized to the disk, and replaces the target with one rename. A reader sees the old file or the new file,
//! never a part.
//!
//! The body of a request goes through a small queue to a task of the blocking pool: the task owns the temporary
//! file. A write that stops before its end (a short body, an error, a cancel) removes its temporary file.

use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use aws_lc_rs::digest::{Context, SHA256};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;
use http_body_util::BodyExt as _;
use tokio::sync::mpsc;

use super::path::{invalid_key, resolve_part, temporary_name, volume_error};
use super::{VolumeBackend, blocking};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::Body;
use crate::common::storage::{CopyProgress, MultipartCopyOptions};
use crate::provider::ChecksumTransfer;

/// The number of copied bytes between two reports of the progress of a large copy.
pub const COPY_PROGRESS_STEP: i64 = 8 << 20;

/// The largest file that a write of an unknown size accepts: 5 TiB.
pub const MAX_OBJECT_SIZE: i64 = 5 << 40;

/// The size of the blocks of a copy.
const COPY_BLOCK: usize = 256 * 1024;

/// The number of blocks of a body that wait for the task of the file.
const QUEUE_DEPTH: usize = 4;

/// Write the entries of a folder to the disk. A file system that cannot do it (some FUSE file systems) keeps the
/// rename in its own way: the error is ignored.
pub(crate) fn sync_folder(real: &Path) {
    if let Ok(folder) = fs::File::open(real) {
        let _ = folder.sync_all();
    }
}

/// The error `409 object_exists`.
fn object_exists() -> Error {
    Error::api(
        409,
        "object_exists",
        "an object already exists at the extraction destination",
    )
}

/// Give the temporary file the name of `target`. Without `exclusive`, a rename replaces `target`. With
/// `exclusive`, a hard link makes `target` only when it does not exist, and the temporary name is removed. A file
/// system without hard links gets a check and a rename.
pub(crate) fn commit_temporary(temporary: &Path, target: &Path, exclusive: bool) -> Result<()> {
    if !exclusive {
        return fs::rename(temporary, target).map_err(|error| volume_error(&error));
    }
    match fs::hard_link(temporary, target) {
        Ok(()) => {
            let _ = fs::remove_file(temporary);
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists || error.raw_os_error() == Some(libc::ENOTEMPTY) => {
            Err(object_exists())
        }
        Err(_) => {
            if fs::symlink_metadata(target).is_ok() {
                return Err(object_exists());
            }
            fs::rename(temporary, target).map_err(|error| volume_error(&error))
        }
    }
}

/// A temporary file of a write. The file is removed when the value is dropped before `commit`.
struct StagedWrite {
    file: Option<fs::File>,
    path: PathBuf,
    digest: Option<Context>,
}

impl StagedWrite {
    /// Make a new temporary file in `folder`. With `checksum`, the bytes also feed a SHA-256 context.
    fn create(folder: &Path, checksum: bool) -> Result<Self> {
        let path = folder.join(temporary_name("")?);
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o666)
            .open(&path)
            .map_err(|error| volume_error(&error))?;
        Ok(Self {
            file: Some(file),
            path,
            digest: checksum.then(|| Context::new(&SHA256)),
        })
    }

    fn push(&mut self, data: &[u8]) -> Result<()> {
        if let Some(digest) = self.digest.as_mut() {
            digest.update(data);
        }
        match self.file.as_mut() {
            Some(file) => file.write_all(data).map_err(|error| volume_error(&error)),
            None => Err(Error::internal("the temporary file is closed")),
        }
    }

    /// Check the checksum, synchronize the file, and give it the name of the target. With a checksum transfer, the
    /// SHA-256 of the bytes must be the digest of the client.
    fn commit(mut self, target: &Path, exclusive: bool, transfer: Option<&ChecksumTransfer>) -> Result<()> {
        if let (Some(digest), Some(transfer)) = (self.digest.take(), transfer) {
            let sum = STANDARD.encode(digest.finish().as_ref());
            if sum != transfer.sha256 {
                return Err(Error::api(
                    400,
                    "bad_digest",
                    "the SHA-256 of the received bytes is not the checksum of the client: the file is not written",
                ));
            }
            if let Ok(mut echoed) = transfer.echoed.lock() {
                *echoed = sum;
            }
        }
        let file = self
            .file
            .take()
            .ok_or_else(|| Error::internal("the temporary file is closed"))?;
        file.sync_all().map_err(|error| volume_error(&error))?;
        drop(file);
        commit_temporary(&self.path, target, exclusive)?;
        // The rename or the link made the name of the target: the temporary name is gone, so nothing is left to
        // remove.
        self.path = PathBuf::new();
        if let Some(folder) = target.parent() {
            sync_folder(folder);
        }
        Ok(())
    }
}

impl Drop for StagedWrite {
    fn drop(&mut self) {
        self.file.take();
        if !self.path.as_os_str().is_empty() {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// A message to the task of the file.
pub(crate) enum Message {
    Data(Bytes),
    Finish,
}

/// How the feed of a body ended.
pub(crate) enum Fed {
    Complete,
    Short,
    TooLarge,
    WriterGone,
}

/// Send the bytes of a body to the task of the file. `size` is the number of bytes to read, or -1 for all the bytes
/// up to `MAX_OBJECT_SIZE`.
pub(crate) async fn feed(ctx: &OpCtx, mut body: Body, size: i64, queue: &mpsc::Sender<Message>) -> Result<Fed> {
    let mut total = 0i64;
    loop {
        if size >= 0 && total >= size {
            return Ok(Fed::Complete);
        }
        let frame = ctx.run(async { Ok(body.frame().await) }).await?;
        let Some(frame) = frame else {
            return Ok(if size >= 0 { Fed::Short } else { Fed::Complete });
        };
        let Ok(mut data) = frame?.into_data() else {
            continue;
        };
        let length = i64::try_from(data.len()).unwrap_or(i64::MAX);
        if size >= 0 {
            let room = usize::try_from(size - total).unwrap_or(0);
            data.truncate(room);
        } else if total.saturating_add(length) > MAX_OBJECT_SIZE {
            return Ok(Fed::TooLarge);
        }
        total += i64::try_from(data.len()).unwrap_or(0);
        if queue.send(Message::Data(data)).await.is_err() {
            return Ok(Fed::WriterGone);
        }
    }
}

/// The task of the file: it writes each block of the queue to a temporary file, and commits it at the end. A queue
/// that closes with no `Finish` is a write that stopped: the temporary file is removed.
fn stream_to_target(
    mut queue: mpsc::Receiver<Message>,
    target: &Path,
    exclusive: bool,
    transfer: Option<&ChecksumTransfer>,
) -> Result<()> {
    let folder = target
        .parent()
        .ok_or_else(|| Error::internal("the target has no folder"))?;
    let mut staged = StagedWrite::create(folder, transfer.is_some())?;
    loop {
        match queue.blocking_recv() {
            Some(Message::Data(data)) => staged.push(&data)?,
            Some(Message::Finish) => return staged.commit(target, exclusive, transfer),
            None => return Ok(()),
        }
    }
}

fn incomplete_body() -> Error {
    Error::api(
        400,
        "incomplete_body",
        "the request has fewer bytes than its Content-Length",
    )
}

impl VolumeBackend {
    /// Make the folder of the key and its parents.
    fn make_folder(&self, parts: &[String]) -> Result<()> {
        if parts.is_empty() {
            return Err(invalid_key("the root of the volume exists already"));
        }
        self.resolve_folder(parts, true).map(|_| ())
    }

    /// Write a file from a body. A key that ends with `/` makes a folder: it takes no content. With `exclusive`, an
    /// existing file stops the write (`object_exists`).
    pub(crate) async fn put_object(
        &self,
        ctx: &OpCtx,
        full: &str,
        body: Body,
        size: i64,
        exclusive: bool,
    ) -> Result<()> {
        self.sizer.invalidate();
        let key = self.parse(full, true)?;
        if key.folder {
            if size > 0 {
                return Err(invalid_key(
                    "a key that ends with \"/\" makes a folder: it takes no content",
                ));
            }
            let backend = self.clone();
            return blocking(move || backend.make_folder(&key.parts)).await;
        }
        if key.parts.is_empty() {
            return Err(invalid_key("a key of a file is required"));
        }
        let backend = self.clone();
        let target = blocking(move || backend.write_target(&key)).await?;
        let (queue, receiver) = mpsc::channel::<Message>(QUEUE_DEPTH);
        let transfer = ctx.checksum.clone();
        let task_target = target.clone();
        let writer = tokio::task::spawn_blocking(move || {
            stream_to_target(receiver, &task_target, exclusive, transfer.as_deref())
        });
        let fed = feed(ctx, body, size, &queue).await;
        if matches!(fed, Ok(Fed::Complete)) {
            // A closed queue here means the task already failed: its result has the error.
            let _ = queue.send(Message::Finish).await;
        }
        drop(queue);
        let written = writer
            .await
            .map_err(|_| Error::internal("the task of the write failed"))?;
        match fed? {
            Fed::Complete | Fed::WriterGone => written,
            Fed::Short => Err(incomplete_body()),
            Fed::TooLarge => Err(Error::api(
                413,
                "object_too_large",
                format!("a file must have {MAX_OBJECT_SIZE} bytes or less"),
            )),
        }
    }

    /// Delete a file, or an empty folder for a key that ends with `/`. A key that does not exist, and a folder that
    /// is not empty, are not errors: a delete of S3 does the same. A symbolic link is removed, not its target.
    pub(crate) fn delete_blocking(&self, full: &str) -> Result<()> {
        self.sizer.invalidate();
        let key = self.parse(full, false)?;
        if key.parts.is_empty() {
            return Err(invalid_key("Stowr does not delete the root of the volume"));
        }
        let folder = match self.resolve_folder(key.parent(), false) {
            Ok(folder) => folder,
            Err(error) if error.is_not_found() || error.has_code("volume_not_folder") => return Ok(()),
            Err(error) => return Err(error),
        };
        let entry = folder.join(key.name());
        let info = match fs::symlink_metadata(&entry) {
            Ok(info) => info,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(volume_error(&error)),
        };
        if key.folder {
            if !info.is_dir() {
                return Ok(());
            }
            if let Err(error) = fs::remove_dir(&entry) {
                let mapped = volume_error(&error);
                if mapped.has_code("volume_folder_not_empty") || mapped.is_not_found() {
                    return Ok(());
                }
                return Err(mapped);
            }
        } else if info.is_dir() {
            return Ok(());
        } else {
            if info.file_type().is_symlink() {
                resolve_part(&self.root, &folder, key.name(), self.refuse_links)
                    .map_err(|error| volume_error(&error))?;
            }
            if let Err(error) = fs::remove_file(&entry)
                && error.kind() != io::ErrorKind::NotFound
            {
                return Err(volume_error(&error));
            }
        }
        sync_folder(&folder);
        Ok(())
    }

    /// Copy a file to a temporary file, then give it the name of the destination. A folder key copies to a new
    /// empty folder.
    pub(crate) fn copy_blocking(
        &self,
        ctx: &OpCtx,
        source: &str,
        destination: &str,
        progress: Option<CopyProgress>,
    ) -> Result<()> {
        self.sizer.invalidate();
        let from = self.parse(source, false)?;
        let to = self.parse(destination, true)?;
        if from.folder != to.folder {
            return Err(invalid_key(
                "a copy goes from a folder to a folder, or from a file to a file",
            ));
        }
        let (real, object) = self.stat(source)?;
        if from.folder {
            return self.make_folder(&to.parts);
        }
        let file = self.open_read(&real).map_err(|error| volume_error(&error))?;
        let target = self.write_target(&to)?;
        if target == real {
            return Ok(());
        }
        let mut reader = file;
        let folder = target
            .parent()
            .ok_or_else(|| Error::internal("the target has no folder"))?;
        let mut staged = StagedWrite::create(folder, false)?;
        let mut left = object.size;
        let mut pending = 0i64;
        let mut block = vec![0u8; COPY_BLOCK];
        while left > 0 {
            ctx.check()?;
            let want = usize::try_from(left).unwrap_or(COPY_BLOCK).min(COPY_BLOCK);
            let count = reader.read(&mut block[..want]).map_err(|error| volume_error(&error))?;
            if count == 0 {
                return Err(incomplete_body());
            }
            staged.push(&block[..count])?;
            let count = i64::try_from(count).unwrap_or(0);
            left -= count;
            pending += count;
            if let Some(report) = &progress
                && pending >= COPY_PROGRESS_STEP
            {
                report(pending);
                pending = 0;
            }
        }
        staged.commit(&target, false, None)?;
        if let Some(report) = &progress
            && pending > 0
        {
            report(pending);
        }
        Ok(())
    }

    /// Give a file the name of the destination with one rename. A rename to another file system (`EXDEV`), and the
    /// move of a symbolic link, copy the content and remove the source. A folder key makes the destination folder
    /// and removes the source folder when it is empty.
    pub(crate) fn move_blocking(&self, ctx: &OpCtx, source: &str, destination: &str) -> Result<()> {
        self.sizer.invalidate();
        let from = self.parse(source, true)?;
        let to = self.parse(destination, true)?;
        if from.folder != to.folder || from.parts.is_empty() {
            return Err(invalid_key(
                "a move goes from a folder to a folder, or from a file to a file",
            ));
        }
        if from.folder {
            self.stat(source)?;
            self.make_folder(&to.parts)?;
            return self.delete_blocking(source);
        }
        let folder = self.resolve_folder(from.parent(), false)?;
        let entry = folder.join(from.name());
        let info = fs::symlink_metadata(&entry).map_err(|error| volume_error(&error))?;
        if !info.is_file() {
            self.copy_blocking(ctx, source, destination, None)?;
            return self.delete_blocking(source);
        }
        let target = self.write_target(&to)?;
        if target == entry {
            return Ok(());
        }
        if let Err(error) = fs::rename(&entry, &target) {
            if error.raw_os_error() == Some(libc::EXDEV) {
                self.copy_blocking(ctx, source, destination, None)?;
                return self.delete_blocking(source);
            }
            return Err(volume_error(&error));
        }
        sync_folder(&folder);
        if let Some(parent) = target.parent() {
            sync_folder(parent);
        }
        Ok(())
    }

    /// Remove the folder of the prefix and each folder below it that has no file, from the bottom. A folder with a
    /// file stays: a delete of the folders never removes a file. The root of the volume stays.
    pub(crate) fn remove_empty_folders_blocking(&self, ctx: &OpCtx, full: &str) -> Result<()> {
        self.sizer.invalidate();
        let key = self.parse(full, false)?;
        if !key.folder || key.parts.is_empty() {
            return Ok(());
        }
        let folder = match self.resolve_folder(key.parent(), false) {
            Ok(folder) => folder,
            Err(error) if error.is_not_found() || error.has_code("volume_not_folder") => return Ok(()),
            Err(error) => return Err(error),
        };
        let real = folder.join(key.name());
        match fs::symlink_metadata(&real) {
            Ok(info) if info.is_dir() => remove_empty_tree(ctx, &real),
            _ => Ok(()),
        }
    }

    /// The options of a copy in parts that a volume cannot keep: a volume has no versions, no metadata and no tags.
    pub(crate) fn check_copy_options(options: &MultipartCopyOptions) -> Result<()> {
        if !options.source_version.is_empty()
            || !options.expected_etag.is_empty()
            || options.metadata.is_some()
            || options.tags.is_some()
            || !options.extra_headers.is_empty()
        {
            return Err(Error::api(
                501,
                "volume_unsupported",
                "a volume has no versions, no metadata and no tags",
            ));
        }
        Ok(())
    }

    /// Make and remove a temporary file in the root.
    pub(crate) fn probe_write(&self) -> io::Result<()> {
        let name = temporary_name("").map_err(|error| io::Error::other(error.to_string()))?;
        let probe = self.root.join(name);
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o666)
            .open(&probe)?;
        drop(file);
        fs::remove_file(&probe)
    }
}

fn remove_empty_tree(ctx: &OpCtx, real: &Path) -> Result<()> {
    ctx.check()?;
    let reader = match fs::read_dir(real) {
        Ok(reader) => reader,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(volume_error(&error)),
    };
    for entry in reader {
        let entry = entry.map_err(|error| volume_error(&error))?;
        if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            remove_empty_tree(ctx, &entry.path())?;
        }
    }
    if let Err(error) = fs::remove_dir(real) {
        let mapped = volume_error(&error);
        if mapped.has_code("volume_folder_not_empty")
            || mapped.is_not_found()
            || error.kind() == io::ErrorKind::AlreadyExists
        {
            return Ok(());
        }
        return Err(mapped);
    }
    if let Some(parent) = real.parent() {
        sync_folder(parent);
    }
    Ok(())
}
