// SPDX-License-Identifier: MIT OR Apache-2.0
//! The resumable uploads of a volume. An upload writes its chunks to a temporary file in the folder of the target:
//! the name is the temporary prefix, a random part and, when it fits, the name of the target. The next chunk starts
//! at the size of the temporary file, so a client can resume after a lost connection. The last chunk synchronizes
//! the file and gives it the name of the target with one rename. The session of the upload (inside the sealed resume
//! token) holds the temporary file and the key of the target.
//!
//! A temporary file that stays (a closed tab, a stopped server) is an incomplete upload: the window "Incomplete
//! uploads" lists it with the date of its last write, and its abort removes it. The abort by age keeps a file
//! younger than 24 hours, and no abort touches a file that an upload of this process writes.

use std::fs;
use std::io;
use std::os::unix::fs::{FileExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};

use tokio::sync::mpsc;

use super::path::{inside_root, invalid_key, parse_temporary_name, temporary_name, volume_error};
use super::read::{MAX_FOLDER_ENTRIES, modified};
use super::write::{Fed, Message, commit_temporary, feed, sync_folder};
use super::{VolumeBackend, blocking};
use crate::common::BoxFuture;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::Body;
use crate::common::storage::ResumableApi;
use crate::uploads::{
    IncompleteUploadRemover, MultipartCursor, MultipartPartsSummary, MultipartUpload, MultipartUploadLister,
    MultipartUploadPage,
};

/// The largest number of entries that one page of the list of the incomplete uploads reads.
pub const TEMPORARY_SCAN_ENTRIES: usize = 20_000;

/// The size of a page of the list of the incomplete uploads when the caller gives none.
const DEFAULT_PAGE_SIZE: usize = 1000;

/// The session of a resumable upload: the path of the temporary file relative to the root, and the full key of the
/// target. A NUL byte, which no key has, separates them in the text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VolumeSession {
    /// The path of the temporary file, relative to the root.
    pub temporary: String,
    /// The full key of the target.
    pub key: String,
}

impl VolumeSession {
    /// The text of the session.
    pub fn text(&self) -> String {
        format!("{}\0{}", self.temporary, self.key)
    }
}

/// The id that the list of the incomplete uploads gives to the temporary file of a session: the last element of its
/// path. A path without a name gives `.`, and a path of `/` characters only gives `/`.
pub fn session_upload_id(session: &str) -> String {
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

fn invalid_token() -> Error {
    Error::api(
        400,
        "invalid_resume_token",
        "upload resume token does not match the configured storage",
    )
}

fn no_such_upload() -> Error {
    Error::upstream(404, "NoSuchUpload", "the temporary file of the upload does not exist")
}

/// The path `relative` in `root`, with the `.` and `..` parts resolved by the text of the path only.
fn join_clean(root: &Path, relative: &str) -> PathBuf {
    let mut path = root.to_path_buf();
    for component in Path::new(relative).components() {
        match component {
            Component::Normal(name) => path.push(name),
            Component::ParentDir => {
                path.pop();
            }
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
        }
    }
    path
}

/// Open a temporary file of an upload for a write. It must be a regular file, not a symbolic link.
fn open_temporary(real: &Path) -> Result<fs::File> {
    let info = match fs::symlink_metadata(real) {
        Ok(info) => info,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Err(no_such_upload()),
        Err(error) => return Err(volume_error(&error)),
    };
    if !info.is_file() {
        return Err(Error::api(
            409,
            "volume_not_file",
            "the temporary file of the upload is not a regular file",
        ));
    }
    fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(real)
        .map_err(|error| volume_error(&error))
}

/// The task of the file of a chunk: it writes each block of the queue at its offset, and synchronizes the file at
/// the end. A queue that closes with no `Finish` is a chunk that stopped: the bytes stay, and the next chunk cuts
/// the file back to its start.
fn write_chunk(mut queue: mpsc::Receiver<Message>, file: &fs::File, start: u64) -> Result<()> {
    let mut offset = start;
    loop {
        match queue.blocking_recv() {
            Some(Message::Data(data)) => {
                file.write_all_at(&data, offset).map_err(|error| volume_error(&error))?;
                offset += data.len() as u64;
            }
            Some(Message::Finish) => return file.sync_all().map_err(|error| volume_error(&error)),
            None => return Ok(()),
        }
    }
}

impl VolumeBackend {
    /// Read a session text: the session and the real path of its temporary file.
    fn parse_session(&self, value: &str) -> Result<(VolumeSession, PathBuf)> {
        let Some((temporary, key)) = value.split_once('\0') else {
            return Err(invalid_token());
        };
        if temporary.is_empty() || temporary.starts_with('/') {
            return Err(invalid_token());
        }
        let name = Path::new(temporary)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if parse_temporary_name(name).is_none() {
            return Err(invalid_token());
        }
        let real = join_clean(&self.root, temporary);
        if !inside_root(&real, &self.root) {
            return Err(invalid_token());
        }
        Ok((
            VolumeSession {
                temporary: temporary.to_owned(),
                key: key.to_owned(),
            },
            real,
        ))
    }

    /// Make the folders of the target and an empty temporary file in the folder of the target.
    fn initiate_blocking(&self, full: &str) -> Result<String> {
        let key = self.parse(full, true)?;
        if key.folder || key.parts.is_empty() {
            return Err(invalid_key("an upload needs the key of a file"));
        }
        let target = self.write_target(&key)?;
        let name = temporary_name(target.file_name().and_then(|name| name.to_str()).unwrap_or(""))?;
        let folder = target
            .parent()
            .ok_or_else(|| Error::internal("the target has no folder"))?;
        let real = folder.join(name);
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o666)
            .open(&real)
            .map_err(|error| volume_error(&error))?;
        drop(file);
        let relative = real
            .strip_prefix(&self.root)
            .ok()
            .and_then(|path| path.to_str())
            .map(str::to_owned);
        match relative {
            Some(relative) => Ok(VolumeSession {
                temporary: relative,
                key: full.to_owned(),
            }
            .text()),
            None => {
                let _ = fs::remove_file(&real);
                Err(Error::internal("the temporary file is not in the root"))
            }
        }
    }

    /// Give the complete temporary file the name of the target.
    fn finish_upload(&self, session: &VolumeSession, real: &Path) -> Result<()> {
        self.sizer.invalidate();
        let key = self.parse(&session.key, true)?;
        let target = self.write_target(&key)?;
        commit_temporary(real, &target, false)?;
        if let Some(folder) = target.parent() {
            sync_folder(folder);
        }
        Ok(())
    }

    /// Write one chunk at `start`. A temporary file longer than `start` (a chunk that a lost connection cut) is cut
    /// back to `start`. The last chunk gives the file the name of the target.
    async fn upload_chunk_object(
        &self,
        ctx: &OpCtx,
        value: &str,
        body: Body,
        start: i64,
        size: i64,
        total: i64,
    ) -> Result<(i64, bool)> {
        if size <= 0 || start < 0 || total <= 0 || start + size > total {
            return Err(Error::internal("invalid volume upload range"));
        }
        let backend = self.clone();
        let text = value.to_owned();
        let (session, real, file) = blocking(move || {
            let (session, real) = backend.parse_session(&text)?;
            let file = open_temporary(&real)?;
            let length = file.metadata().map_err(|error| volume_error(&error))?.len();
            let from = u64::try_from(start).unwrap_or(0);
            if length < from {
                return Err(Error::api(
                    409,
                    "offset_mismatch",
                    format!("upload must resume at byte {length}"),
                ));
            }
            if length > from {
                file.set_len(from).map_err(|error| volume_error(&error))?;
            }
            Ok((session, real, file))
        })
        .await?;
        let (queue, receiver) = mpsc::channel::<Message>(4);
        let offset = u64::try_from(start).unwrap_or(0);
        let writer = tokio::task::spawn_blocking(move || write_chunk(receiver, &file, offset));
        let fed = feed(ctx, body, size, &queue).await;
        if matches!(fed, Ok(Fed::Complete)) {
            // A closed queue here means the task already failed: its result has the error.
            let _ = queue.send(Message::Finish).await;
        }
        drop(queue);
        let written = writer
            .await
            .map_err(|_| Error::internal("the task of the upload failed"))?;
        match fed? {
            Fed::Complete | Fed::WriterGone => written?,
            Fed::Short => {
                return Err(Error::api(
                    400,
                    "incomplete_body",
                    "the request has fewer bytes than its Content-Range",
                ));
            }
            Fed::TooLarge => return Err(Error::internal("invalid volume upload range")),
        }
        let next = start + size;
        if next < total {
            return Ok((next, false));
        }
        let backend = self.clone();
        blocking(move || backend.finish_upload(&session, &real)).await?;
        Ok((total, true))
    }

    /// The size of the temporary file. When the file is gone and the target has the size of the upload, the upload
    /// is complete.
    fn query_blocking(&self, value: &str, total: i64) -> Result<(i64, bool)> {
        let (session, real) = self.parse_session(value)?;
        match fs::symlink_metadata(&real) {
            Ok(info) => return Ok((i64::try_from(info.len()).unwrap_or(i64::MAX), false)),
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(volume_error(&error)),
            Err(_) => {}
        }
        if let Ok((_, object)) = self.stat(&session.key)
            && object.size == total
        {
            return Ok((total, true));
        }
        Err(no_such_upload())
    }

    /// Remove the temporary file. A file that is gone is not an error.
    fn abort_blocking(&self, value: &str) -> Result<()> {
        let (_, real) = self.parse_session(value)?;
        match fs::remove_file(&real) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => Err(volume_error(&error)),
            _ => Ok(()),
        }
    }

    /// The real path of the temporary file `upload_id` in the folder of the key of an upload of the list.
    fn temporary_of_upload(&self, full: &str, upload_id: &str) -> Result<PathBuf> {
        if parse_temporary_name(upload_id).is_none() || upload_id.contains('/') {
            return Err(Error::api(
                400,
                "invalid_multipart_request",
                "the upload id of a volume is the name of a temporary file of Stowr",
            ));
        }
        let key = self.parse(full, false)?;
        match self.resolve_folder(key.parent(), false) {
            Ok(folder) => Ok(folder.join(upload_id)),
            Err(error) if error.is_not_found() || error.has_code("volume_not_folder") => Err(no_such_upload()),
            Err(error) => Err(error),
        }
    }

    /// List the temporary files of the tree, in the order of the keys, after the key of the cursor. The key of an
    /// upload is the key of its target when the temporary name has it, else the key of the temporary file. The id is
    /// the temporary name. The date is the last write. One page reads at most `TEMPORARY_SCAN_ENTRIES` entries: the
    /// next cursor then starts after the last entry that the page read.
    fn list_uploads_blocking(
        &self,
        ctx: &OpCtx,
        cursor: &MultipartCursor,
        maximum: u32,
    ) -> Result<MultipartUploadPage> {
        let marker = if cursor.key_marker.is_empty() {
            ""
        } else {
            self.relative(&cursor.key_marker)?
        };
        let maximum = match usize::try_from(maximum).unwrap_or(0) {
            0 => DEFAULT_PAGE_SIZE,
            asked => asked,
        };
        let mut uploads = Vec::new();
        let mut truncated = false;
        let mut visited = 0usize;
        let mut last = String::new();
        let mut visit = |key: &str, info: &fs::Metadata| {
            if visited == TEMPORARY_SCAN_ENTRIES || uploads.len() == maximum {
                truncated = true;
                return false;
            }
            visited += 1;
            key.clone_into(&mut last);
            let (folder_key, name) = match key.rfind('/') {
                Some(slash) => key.split_at(slash + 1),
                None => ("", key),
            };
            let Some(target) = parse_temporary_name(name) else {
                return true;
            };
            let shown = if target.is_empty() {
                key.to_owned()
            } else {
                format!("{folder_key}{target}")
            };
            uploads.push(MultipartUpload {
                key: format!("{}{shown}", self.prefix),
                upload_id: name.to_owned(),
                initiated: Some(modified(info)),
            });
            true
        };
        walk_temporary(ctx, &self.root, "", marker, &mut visit)?;
        let next = truncated.then(|| MultipartCursor {
            key_marker: format!("{}{last}", self.prefix),
            ..MultipartCursor::default()
        });
        Ok(MultipartUploadPage { uploads, next })
    }

    /// One part with the size of the temporary file.
    fn upload_parts_blocking(&self, full: &str, upload_id: &str) -> Result<MultipartPartsSummary> {
        let real = self.temporary_of_upload(full, upload_id)?;
        match fs::symlink_metadata(&real) {
            Ok(info) => Ok(MultipartPartsSummary {
                parts: 1,
                bytes: i64::try_from(info.len()).unwrap_or(i64::MAX),
                ..MultipartPartsSummary::default()
            }),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Err(no_such_upload()),
            Err(error) => Err(volume_error(&error)),
        }
    }

    /// Remove the temporary file `upload_id` in the folder of the key of the list. A file that is gone is not an
    /// error.
    fn remove_incomplete_blocking(&self, full: &str, upload_id: &str) -> Result<()> {
        let real = self.temporary_of_upload(full, upload_id)?;
        match fs::symlink_metadata(&real) {
            Ok(info) if !info.is_file() => {
                return Err(Error::api(
                    409,
                    "volume_not_file",
                    "the temporary file of the upload is not a regular file",
                ));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(volume_error(&error)),
        }
        if let Err(error) = fs::remove_file(&real)
            && error.kind() != io::ErrorKind::NotFound
        {
            return Err(volume_error(&error));
        }
        if let Some(folder) = real.parent() {
            sync_folder(folder);
        }
        Ok(())
    }
}

/// Give each file of the tree after `marker`, in the order of the keys. A symbolic link is not followed. The walk
/// stops when `visit` gives false.
fn walk_temporary(
    ctx: &OpCtx,
    real: &Path,
    folder_key: &str,
    marker: &str,
    visit: &mut dyn FnMut(&str, &fs::Metadata) -> bool,
) -> Result<bool> {
    ctx.check()?;
    let reader = match fs::read_dir(real) {
        Ok(reader) => reader,
        Err(error) if error.kind() == io::ErrorKind::NotFound || error.kind() == io::ErrorKind::PermissionDenied => {
            return Ok(true);
        }
        Err(error) => return Err(volume_error(&error)),
    };
    let mut items = Vec::new();
    for item in reader {
        items.push(item.map_err(|error| volume_error(&error))?);
        if items.len() > MAX_FOLDER_ENTRIES {
            return Err(Error::api(
                422,
                "volume_folder_too_large",
                format!("a folder has more than {MAX_FOLDER_ENTRIES} entries: Stowr does not list it"),
            ));
        }
    }
    let mut entries: Vec<(String, fs::DirEntry)> = items
        .into_iter()
        .map(|item| {
            let mut sort_key = item.file_name().to_string_lossy().into_owned();
            if item.file_type().is_ok_and(|kind| kind.is_dir()) {
                sort_key.push('/');
            }
            (sort_key, item)
        })
        .collect();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    for (sort_key, item) in &entries {
        let key = format!("{folder_key}{sort_key}");
        let Ok(kind) = item.file_type() else {
            continue;
        };
        if kind.is_dir() {
            if !marker.is_empty() && key.as_str() < marker && !marker.starts_with(key.as_str()) {
                continue;
            }
            if !walk_temporary(ctx, &item.path(), &key, marker, visit)? {
                return Ok(false);
            }
            continue;
        }
        if !kind.is_file() || key.as_str() <= marker {
            continue;
        }
        let Ok(info) = item.metadata() else {
            continue;
        };
        if !visit(&key, &info) {
            return Ok(false);
        }
    }
    Ok(true)
}

impl ResumableApi for VolumeBackend {
    fn initiate_resumable<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        key: &'a str,
        _total: i64,
        _content_type: &'a str,
    ) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move {
            let backend = self.clone();
            let key = key.to_owned();
            blocking(move || backend.initiate_blocking(&key)).await
        })
    }

    fn upload_chunk<'a>(
        &'a self,
        ctx: &'a OpCtx,
        session: &'a str,
        body: Body,
        start: i64,
        size: i64,
        total: i64,
        _content_type: &'a str,
    ) -> BoxFuture<'a, Result<(i64, bool)>> {
        Box::pin(async move { self.upload_chunk_object(ctx, session, body, start, size, total).await })
    }

    fn query_resumable<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        session: &'a str,
        total: i64,
    ) -> BoxFuture<'a, Result<(i64, bool)>> {
        Box::pin(async move {
            let backend = self.clone();
            let session = session.to_owned();
            blocking(move || backend.query_blocking(&session, total)).await
        })
    }

    fn abort_resumable<'a>(&'a self, _ctx: &'a OpCtx, session: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let backend = self.clone();
            let session = session.to_owned();
            blocking(move || backend.abort_blocking(&session)).await
        })
    }
}

impl MultipartUploadLister for VolumeBackend {
    fn list_uploads<'a>(
        &'a self,
        ctx: &'a OpCtx,
        cursor: &'a MultipartCursor,
        maximum: u32,
    ) -> BoxFuture<'a, Result<MultipartUploadPage>> {
        Box::pin(async move {
            let backend = self.clone();
            let ctx = ctx.clone();
            let cursor = cursor.clone();
            blocking(move || backend.list_uploads_blocking(&ctx, &cursor, maximum)).await
        })
    }

    fn upload_parts<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        key: &'a str,
        upload_id: &'a str,
        _maximum: u32,
    ) -> BoxFuture<'a, Result<MultipartPartsSummary>> {
        Box::pin(async move {
            let backend = self.clone();
            let (key, upload_id) = (key.to_owned(), upload_id.to_owned());
            blocking(move || backend.upload_parts_blocking(&key, &upload_id)).await
        })
    }
}

impl IncompleteUploadRemover for VolumeBackend {
    fn remove_incomplete_upload<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        key: &'a str,
        upload_id: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let backend = self.clone();
            let (key, upload_id) = (key.to_owned(), upload_id.to_owned());
            blocking(move || backend.remove_incomplete_blocking(&key, &upload_id)).await
        })
    }
}
