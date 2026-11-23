//! The reads of a volume: the listing, the tree walk, HEAD, GET with the conditions and the ranges of S3, and the
//! probe of the permissions.
//!
//! Folders are real: a listing with the delimiter `/` gives the subfolders, and an empty folder exists. A listing
//! without a delimiter gives the files and the empty folders (as `<folder>/` with size 0, as the folder objects of
//! S3) in the order of the keys of S3, so that the jobs (delete, copy, move, Insights, archive, search) work as on a
//! bucket. The page token of a listing is the last key of the page: it stays valid when the folder changes.
//!
//! A file has no metadata of S3: the content type comes from the extension of the name, and the ETag is the weak
//! validator `W/"<size>-<modification time in nanoseconds>"`.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bytes::Bytes;
use http::HeaderMap;
use http::header::{
    ACCEPT_RANGES, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, ETAG, HeaderName, HeaderValue, LAST_MODIFIED,
};

use super::content_type::{FOLDER_CONTENT_TYPE, content_type};
use super::http_time::parse_http_seconds;
use super::path::{inside_root, not_found, parse_key, parse_temporary_name, volume_error};
use super::{VolumeBackend, blocking};
use crate::common::config::{PERMISSION_DELETE, PERMISSION_READ, PERMISSION_WRITE};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Body, channel, empty};
use crate::common::storage::{
    CapabilityState, CapabilityStateName, DiscoveredCapabilities, ListOptions, ListPage, ObjectInfo, ObjectResponse,
};
use crate::common::time::Timestamp;

/// The largest folder that a listing reads. A larger folder gives an error.
pub const MAX_FOLDER_ENTRIES: usize = 250_000;

/// The largest page of a listing: the page size of S3.
pub const LIST_PAGE_SIZE: u32 = 1000;

/// The number of bytes that one read of a file gives to the body of an answer.
const READ_CHUNK: u64 = 256 * 1024;

/// The number of entries between two checks of the cancellation while a folder is read.
const CANCEL_STEP: usize = 1024;

/// The kind of an entry of a folder.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EntryKind {
    File,
    Folder,
    /// A symbolic link that leaves the root or that does not resolve (each symbolic link with `refuse_links`), or a
    /// file that is not a regular file (device, socket, pipe). The listing with a delimiter shows it. No operation
    /// reads it.
    Unreadable,
}

/// One entry of a folder.
#[derive(Debug)]
struct Entry {
    /// The name as the file system gives it.
    os_name: OsString,
    /// The name, with `/` after the name of a folder: the entries then have the order of the keys of S3.
    sort_key: String,
    kind: EntryKind,
    /// True for a symbolic link. `real` is then its target, in the root.
    link: bool,
    real: PathBuf,
}

/// The modification time of a file.
pub(crate) fn modified(info: &fs::Metadata) -> Timestamp {
    Timestamp::from_unix(info.mtime(), u32::try_from(info.mtime_nsec()).unwrap_or(0))
}

/// The weak validator of a file: its size and its modification time in nanoseconds.
fn etag_of(info: &fs::Metadata) -> String {
    let nanos = info
        .mtime()
        .saturating_mul(1_000_000_000)
        .saturating_add(info.mtime_nsec());
    format!("W/\"{}-{}\"", info.size(), nanos)
}

fn size_of(info: &fs::Metadata) -> i64 {
    i64::try_from(info.size()).unwrap_or(i64::MAX)
}

fn set_header(headers: &mut HeaderMap, name: HeaderName, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(name, value);
    }
}

/// The headers of the answer of a read.
fn object_headers(object: &ObjectInfo) -> HeaderMap {
    let mut headers = HeaderMap::new();
    set_header(&mut headers, CONTENT_LENGTH, &object.size.to_string());
    set_header(&mut headers, CONTENT_TYPE, &object.content_type);
    set_header(&mut headers, ETAG, &object.etag);
    if let Some(time) = object.last_modified {
        set_header(&mut headers, LAST_MODIFIED, &time.utc().http_date());
    }
    set_header(&mut headers, ACCEPT_RANGES, "bytes");
    headers
}

fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers.get(name).and_then(|value| value.to_str().ok()).unwrap_or("")
}

/// Compare two ETags without their weak mark (`W/`).
fn same_weak_etag(left: &str, right: &str) -> bool {
    fn strong(value: &str) -> &str {
        let value = value.trim();
        value.strip_prefix("W/").unwrap_or(value)
    }
    strong(left) == strong(right)
}

/// True when the value of `If-Match` or `If-None-Match` (`*`, or ETags separated by commas) matches `etag`.
fn etag_list_matches(value: &str, etag: &str) -> bool {
    value.split(',').any(|item| {
        let item = item.trim();
        item == "*" || (!item.is_empty() && same_weak_etag(item, etag))
    })
}

/// The conditions of a read in the order of RFC 9110. The result is 412, 304, or 0 when the read goes on. The dates
/// compare to the second, as the HTTP date has seconds only.
fn precondition(headers: &HeaderMap, object: &ObjectInfo) -> u16 {
    let modified = object.last_modified.map_or(0, |time| time.secs);
    let value = header_text(headers, "If-Match");
    if !value.is_empty() {
        if !etag_list_matches(value, &object.etag) {
            return 412;
        }
    } else {
        let value = header_text(headers, "If-Unmodified-Since");
        if !value.is_empty() && parse_http_seconds(value).is_some_and(|since| modified > since) {
            return 412;
        }
    }
    let value = header_text(headers, "If-None-Match");
    if !value.is_empty() {
        if etag_list_matches(value, &object.etag) {
            return 304;
        }
    } else {
        let value = header_text(headers, "If-Modified-Since");
        if !value.is_empty() && parse_http_seconds(value).is_some_and(|since| modified <= since) {
            return 304;
        }
    }
    0
}

/// The part of the file that a read sends: the start, the length and the status (200, 206 or 416). A `Range` header
/// that is not one valid byte range is ignored, as RFC 9110 lets a server do: the answer is the whole file. An empty
/// file has no range: the answer is the whole (empty) file.
fn read_range(headers: &HeaderMap, object: &ObjectInfo) -> (i64, i64, u16) {
    let whole = (0, object.size, 200);
    let value = header_text(headers, "Range").trim();
    if value.is_empty() || object.size == 0 {
        return whole;
    }
    let condition = header_text(headers, "If-Range").trim();
    if !condition.is_empty() {
        if condition.starts_with('"') || condition.starts_with("W/") {
            return whole;
        }
        let modified = object.last_modified.map_or(0, |time| time.secs);
        if parse_http_seconds(condition) != Some(modified) {
            return whole;
        }
    }
    let has_bytes = value.get(..6).is_some_and(|start| start.eq_ignore_ascii_case("bytes="));
    if !has_bytes || value.contains(',') {
        return whole;
    }
    let Some((left, right)) = value[6..].trim().split_once('-') else {
        return whole;
    };
    let (left, right) = (left.trim(), right.trim());
    if left.is_empty() {
        return match right.parse::<i64>() {
            Ok(suffix) if suffix > 0 => {
                let suffix = suffix.min(object.size);
                (object.size - suffix, suffix, 206)
            }
            _ => whole,
        };
    }
    let Ok(start) = left.parse::<i64>() else {
        return whole;
    };
    if start < 0 {
        return whole;
    }
    let mut end = object.size - 1;
    if !right.is_empty() {
        match right.parse::<i64>() {
            Ok(last) if last >= start => end = last.min(object.size - 1),
            _ => return whole,
        }
    }
    if start >= object.size {
        return (0, 0, 416);
    }
    (start, end - start + 1, 206)
}

/// The plan of the body of a GET: nothing, or a part of an open file.
enum BodyPlan {
    Empty,
    File { file: fs::File, start: u64, length: u64 },
}

/// The result of the check of a GET, before the body streams.
struct GetPlan {
    status: u16,
    headers: HeaderMap,
    body: BodyPlan,
}

/// A body that reads a part of an open file in blocks. The file closes when the body is dropped.
fn file_body(file: fs::File, start: u64, length: u64) -> Body {
    let (sender, body) = channel(2);
    tokio::spawn(async move {
        let file = Arc::new(file);
        let mut offset = start;
        let mut left = length;
        while left > 0 {
            let want = usize::try_from(left.min(READ_CHUNK)).unwrap_or(READ_CHUNK as usize);
            let source = Arc::clone(&file);
            let read = tokio::task::spawn_blocking(move || {
                let mut buffer = vec![0u8; want];
                let count = source.read_at(&mut buffer, offset)?;
                buffer.truncate(count);
                io::Result::Ok(buffer)
            })
            .await;
            match read {
                Ok(Ok(buffer)) if !buffer.is_empty() => {
                    let count = buffer.len() as u64;
                    offset += count;
                    left = left.saturating_sub(count);
                    if sender.send(Bytes::from(buffer)).await.is_err() {
                        return;
                    }
                }
                Ok(Ok(_)) => {
                    sender.abort(Error::internal("the file is shorter than its size")).await;
                    return;
                }
                Ok(Err(error)) => {
                    sender.abort(volume_error(&error)).await;
                    return;
                }
                Err(_) => {
                    sender.abort(Error::internal("the task of the read failed")).await;
                    return;
                }
            }
        }
    });
    body
}

impl VolumeBackend {
    /// The key relative to the root of the volume. A key of the instance always starts with the root prefix.
    pub(crate) fn relative<'a>(&self, full: &'a str) -> Result<&'a str> {
        full.strip_prefix(self.prefix.as_str()).ok_or_else(|| {
            Error::api(
                403,
                "volume_outside_root",
                "the key is outside the root_prefix of the volume",
            )
        })
    }

    /// Cut a full key into the parts of its path.
    pub(crate) fn parse(&self, full: &str, write: bool) -> Result<super::path::VolumeKey> {
        parse_key(self.relative(full)?, write)
    }

    /// The listing information of a file from its relative key.
    pub(crate) fn object(&self, key: &str, info: &fs::Metadata) -> ObjectInfo {
        ObjectInfo {
            key: format!("{}{key}", self.prefix),
            size: size_of(info),
            last_modified: Some(modified(info)),
            etag: etag_of(info),
            content_type: content_type(key).to_owned(),
            unreadable: false,
        }
    }

    /// The information of a folder from its relative key: size 0 and the type of a folder.
    fn folder_object(&self, key: &str, info: &fs::Metadata) -> ObjectInfo {
        let mut object = self.object(key, info);
        object.size = 0;
        object.content_type = FOLDER_CONTENT_TYPE.to_owned();
        object
    }

    fn unreadable(&self, key: &str) -> ObjectInfo {
        ObjectInfo {
            key: format!("{}{key}", self.prefix),
            unreadable: true,
            ..ObjectInfo::default()
        }
    }

    /// Read the entries of the real folder whose names start with `name_prefix`, in the order of their keys. The
    /// temporary files of the server are left out.
    fn read_folder(&self, ctx: &OpCtx, real: &Path, name_prefix: &str) -> Result<Vec<Entry>> {
        let reader = fs::read_dir(real).map_err(|error| volume_error(&error))?;
        let mut entries = Vec::with_capacity(64);
        for (index, item) in reader.enumerate() {
            if index % CANCEL_STEP == CANCEL_STEP - 1 {
                ctx.check()?;
            }
            let item = item.map_err(|error| volume_error(&error))?;
            let os_name = item.file_name();
            let name = os_name.to_string_lossy().into_owned();
            if !name.starts_with(name_prefix) || parse_temporary_name(&name).is_some() {
                continue;
            }
            let mut entry = Entry {
                sort_key: name,
                os_name,
                kind: EntryKind::Unreadable,
                link: false,
                real: PathBuf::new(),
            };
            if let Ok(kind) = item.file_type() {
                if kind.is_dir() {
                    entry.kind = EntryKind::Folder;
                } else if kind.is_file() {
                    entry.kind = EntryKind::File;
                } else if kind.is_symlink() {
                    entry.link = true;
                    // With `refuse_links` the entry stays unreadable: the volume follows no link.
                    if !self.refuse_links {
                        self.follow_link(&real.join(&entry.os_name), &mut entry);
                    }
                }
            }
            if entry.kind == EntryKind::Folder {
                entry.sort_key.push('/');
            }
            entries.push(entry);
            if entries.len() > MAX_FOLDER_ENTRIES {
                return Err(Error::api(
                    422,
                    "volume_folder_too_large",
                    format!("the folder has more than {MAX_FOLDER_ENTRIES} entries: Stowr does not list it"),
                ));
            }
        }
        entries.sort_by(|left, right| left.sort_key.cmp(&right.sort_key));
        Ok(entries)
    }

    /// Set the kind of an entry that is a symbolic link: a link to a folder or to a file in the root is that folder
    /// or that file.
    fn follow_link(&self, link: &Path, entry: &mut Entry) {
        let Ok(target) = fs::canonicalize(link) else {
            return;
        };
        if !inside_root(&target, &self.root) {
            return;
        }
        let Ok(info) = fs::metadata(&target) else {
            return;
        };
        if info.is_dir() {
            entry.kind = EntryKind::Folder;
            entry.real = target;
        } else if info.is_file() {
            entry.kind = EntryKind::File;
            entry.real = target;
        }
    }

    /// The information of a file entry: of its target for a symbolic link.
    fn entry_info(real: &Path, entry: &Entry) -> io::Result<fs::Metadata> {
        if entry.link {
            fs::metadata(&entry.real)
        } else {
            fs::symlink_metadata(real.join(&entry.os_name))
        }
    }

    /// One page of the keys under the prefix, after the page token and after `start_after`. With the delimiter `/`,
    /// it reads one folder. Without a delimiter, it reads the tree. A prefix that does not exist gives an empty page.
    pub(crate) fn list_blocking(&self, ctx: &OpCtx, options: &ListOptions) -> Result<ListPage> {
        if !options.delimiter.is_empty() && options.delimiter != "/" {
            return Err(Error::api(
                400,
                "invalid_delimiter",
                "a volume lists with the delimiter \"/\" or without a delimiter",
            ));
        }
        let prefix = self.relative(&options.prefix)?;
        let mut marker = "";
        for value in [options.start_after.as_str(), options.page_token.as_str()] {
            if value.is_empty() {
                continue;
            }
            let relative = self.relative(value).map_err(|_| {
                Error::api(
                    400,
                    "invalid_page_token",
                    "the page token of the listing is not valid: open the folder again",
                )
            })?;
            if relative > marker {
                marker = relative;
            }
        }
        let limit = match options.max_results {
            0 => LIST_PAGE_SIZE,
            asked => asked.min(LIST_PAGE_SIZE),
        } as usize;
        let (folder_key, name_prefix) = match prefix.rfind('/') {
            Some(slash) => prefix.split_at(slash + 1),
            None => ("", prefix),
        };
        let parsed = parse_key(folder_key, false)?;
        let real = match self.resolve_folder(&parsed.parts, false) {
            Ok(real) => real,
            Err(error) if error.is_not_found() || error.has_code("volume_not_folder") => {
                return Ok(ListPage::default());
            }
            Err(error) => return Err(error),
        };
        let mut page = ListPage::default();
        let mut count = 0usize;
        if options.delimiter == "/" {
            for entry in self.read_folder(ctx, &real, name_prefix)? {
                let key = format!("{folder_key}{}", entry.sort_key);
                if key.as_str() <= marker {
                    continue;
                }
                count += 1;
                if count > limit {
                    page.next_page_token = last_key(&page);
                    break;
                }
                match entry.kind {
                    EntryKind::Folder => page.prefixes.push(format!("{}{key}", self.prefix)),
                    EntryKind::File => match Self::entry_info(&real, &entry) {
                        Ok(info) => page.objects.push(self.object(&key, &info)),
                        Err(_) => page.objects.push(self.unreadable(&key)),
                    },
                    EntryKind::Unreadable => page.objects.push(self.unreadable(&key)),
                }
            }
            return Ok(page);
        }
        let mut emit = |object: ObjectInfo| {
            count += 1;
            if count > limit {
                page.next_page_token = last_key(&page);
                return false;
            }
            page.objects.push(object);
            true
        };
        self.walk_folder(ctx, &real, folder_key, name_prefix, marker, &mut emit)?;
        Ok(page)
    }

    /// Give each key of the tree of the real folder (with the key `folder_key`) whose name starts with `name_prefix`,
    /// after `marker`, in the order of the keys. A file gives its key. An empty folder gives `<folder>/` with size 0.
    /// A symbolic link to a folder is not followed (a link can make a loop), and an unreadable entry is left out. The
    /// walk stops when `emit` gives false: the result is then false.
    fn walk_folder(
        &self,
        ctx: &OpCtx,
        real: &Path,
        folder_key: &str,
        name_prefix: &str,
        marker: &str,
        emit: &mut dyn FnMut(ObjectInfo) -> bool,
    ) -> Result<bool> {
        ctx.check()?;
        let entries = self.read_folder(ctx, real, name_prefix)?;
        if entries.is_empty() && name_prefix.is_empty() && !folder_key.is_empty() && folder_key > marker {
            let info = fs::metadata(real).map_err(|error| volume_error(&error))?;
            return Ok(emit(self.folder_object(folder_key, &info)));
        }
        for entry in &entries {
            let key = format!("{folder_key}{}", entry.sort_key);
            if entry.kind == EntryKind::Folder && !entry.link {
                if !marker.is_empty() && key.as_str() < marker && !marker.starts_with(key.as_str()) {
                    continue;
                }
                let next = real.join(&entry.os_name);
                if !self.walk_folder(ctx, &next, &key, "", marker, emit)? {
                    return Ok(false);
                }
            } else if entry.kind == EntryKind::File {
                if key.as_str() <= marker {
                    continue;
                }
                let Ok(info) = Self::entry_info(real, entry) else {
                    continue;
                };
                if !emit(self.object(&key, &info)) {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// The information of a key: a regular file, or a folder for a key that ends with `/`.
    pub(crate) fn stat(&self, full: &str) -> Result<(PathBuf, ObjectInfo)> {
        let key = self.parse(full, false)?;
        let (real, info) = self.resolve_existing(&key)?;
        let relative = self.relative(full)?;
        if key.folder && info.is_dir() {
            return Ok((real, self.folder_object(relative, &info)));
        }
        if key.folder || info.is_dir() {
            return Err(not_found());
        }
        if !info.is_file() {
            return Err(Error::api(
                403,
                "volume_not_file",
                "the path is not a regular file: Stowr does not read it",
            ));
        }
        Ok((real, self.object(relative, &info)))
    }

    /// The headers of an object (HEAD).
    pub(crate) fn head_blocking(&self, full: &str) -> Result<ObjectResponse> {
        let (_, object) = self.stat(full)?;
        Ok(ObjectResponse {
            status: 200,
            headers: object_headers(&object),
            body: empty(),
        })
    }

    /// Check a GET: the conditions and the range of the request headers, as an S3 provider does. `If-Match` and
    /// `If-Unmodified-Since` give 412, `If-None-Match` and `If-Modified-Since` give 304, one byte range gives 206,
    /// and a range after the end gives 416. The comparison of an ETag is weak. An `If-Range` with an ETag never
    /// matches (the ETag is weak): the answer is then the whole file.
    fn get_plan(&self, full: &str, request: &HeaderMap) -> Result<GetPlan> {
        let (real, object) = self.stat(full)?;
        if full.ends_with('/') {
            return Ok(GetPlan {
                status: 200,
                headers: object_headers(&object),
                body: BodyPlan::Empty,
            });
        }
        let file = self.open_read(&real).map_err(|error| volume_error(&error))?;
        let info = file.metadata().map_err(|error| volume_error(&error))?;
        if !info.is_file() {
            return Err(Error::api(
                403,
                "volume_not_file",
                "the path is not a regular file: Stowr does not read it",
            ));
        }
        let object = self.object(self.relative(full)?, &info);
        let mut headers = object_headers(&object);
        match precondition(request, &object) {
            0 => {}
            304 => {
                headers.remove(CONTENT_LENGTH);
                return Ok(GetPlan {
                    status: 304,
                    headers,
                    body: BodyPlan::Empty,
                });
            }
            status => {
                return Err(Error::upstream(
                    status,
                    "PreconditionFailed",
                    "the file does not match the condition of the request",
                ));
            }
        }
        let (start, length, status) = read_range(request, &object);
        if status == 416 {
            return Err(Error::upstream(
                416,
                "InvalidRange",
                "the range starts after the end of the file",
            ));
        }
        if status == 206 {
            set_header(
                &mut headers,
                CONTENT_RANGE,
                &format!("bytes {start}-{}/{}", start + length - 1, object.size),
            );
            set_header(&mut headers, CONTENT_LENGTH, &length.to_string());
        }
        let body = if length == 0 {
            BodyPlan::Empty
        } else {
            BodyPlan::File {
                file,
                start: u64::try_from(start).unwrap_or(0),
                length: u64::try_from(length).unwrap_or(0),
            }
        };
        Ok(GetPlan { status, headers, body })
    }

    /// The bytes of an object (GET).
    pub(crate) async fn get_object(&self, full: &str, request: &HeaderMap) -> Result<ObjectResponse> {
        let backend = self.clone();
        let full = full.to_owned();
        let request = request.clone();
        let plan = blocking(move || backend.get_plan(&full, &request)).await?;
        let body = match plan.body {
            BodyPlan::Empty => empty(),
            BodyPlan::File { file, start, length } => file_body(file, start, length),
        };
        Ok(ObjectResponse {
            status: plan.status,
            headers: plan.headers,
            body,
        })
    }

    /// Check the permissions of the process: read the root and, when the server can write in the volume, write and
    /// remove a temporary file.
    pub fn discover(&self) -> DiscoveredCapabilities {
        let state = |allowed: bool, source: &str, reason: &str| CapabilityState {
            state: if allowed {
                CapabilityStateName::Allowed
            } else {
                CapabilityStateName::Denied
            },
            allowed,
            verified: true,
            source: source.to_owned(),
            reason: reason.to_owned(),
            expires: None,
        };
        let mut states = BTreeMap::new();
        let readable = match fs::read_dir(&self.root) {
            Ok(mut reader) => !matches!(reader.next(), Some(Err(_))),
            Err(_) => false,
        };
        let read = if readable {
            state(
                true,
                "volume-read-probe",
                "the process can read the folder of the volume",
            )
        } else {
            state(
                false,
                "volume-read-probe",
                "the process cannot read the folder of the volume",
            )
        };
        states.insert(PERMISSION_READ.to_owned(), read);
        if self.writes {
            let write = if self.probe_write().is_ok() {
                state(
                    true,
                    "volume-write-probe",
                    "the process can write and remove a file in the folder of the volume",
                )
            } else {
                state(
                    false,
                    "volume-write-probe",
                    "the process cannot write a file in the folder of the volume",
                )
            };
            states.insert(PERMISSION_WRITE.to_owned(), write.clone());
            states.insert(PERMISSION_DELETE.to_owned(), write);
        }
        DiscoveredCapabilities {
            states,
            permissions: Vec::new(),
        }
    }
}

/// The largest key of a page.
fn last_key(page: &ListPage) -> String {
    let mut last = page.objects.last().map(|object| object.key.clone()).unwrap_or_default();
    if let Some(prefix) = page.prefixes.last()
        && *prefix > last
    {
        last.clone_from(prefix);
    }
    last
}
