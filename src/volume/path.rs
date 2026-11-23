// SPDX-License-Identifier: MIT OR Apache-2.0
//! The keys and the paths of a volume: the check of a key, the resolution of each part of a path inside the root,
//! the refusal of the symbolic links, and the names of the temporary files.
//!
//! A key is a path relative to the root of the volume: `path`, then `root_prefix`, with no symbolic link. The server
//! refuses a key with an empty, `.` or `..` part, a NUL byte, or a part longer than 255 bytes. It resolves each part
//! of a path, one after the other. With `access.mode = "open"`, a symbolic link to a place inside the root is
//! followed. A symbolic link that leaves the root, or that does not resolve, stops the operation with
//! `volume_link_refused`.
//!
//! With `access.mode = "authzen"`, the server follows no symbolic link: `VolumeConfig::refuse_links` is true. The
//! access policy gives a grant on a folder by the key of the object, not by the real path. A link from one folder to
//! another folder would let a person read the other folder. Each symbolic link in the path of a key then stops the
//! operation with `volume_link_refused`. The listing shows such a link as an unreadable entry, and a walk leaves it
//! out. The function `resolve_part` and the folder reader of the listing are the only places that follow a link
//! in a path. Both read the refusal from the same field. The last part of a file that the server opens for a read or
//! a copy is opened with `O_NOFOLLOW`. The part of the path that `root_prefix` gives is resolved at the start, and a
//! link there is not a link of a key.
//!
//! The server never makes a symbolic link. A key of a write must not name a temporary file of the server.
//!
//! Limit: a process outside the server that changes a symbolic link between the check and the use of a path can race
//! the check, for each folder of the path. The API of the server cannot make a symbolic link.

use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use super::VolumeBackend;
use crate::common::error::{Error, Result};
use crate::common::misc::{hex, random_bytes};

/// The prefix of the names of the temporary files of the server.
pub const TEMPORARY_PREFIX: &str = ".stowr-tmp-";

/// The length of the random hexadecimal part of a temporary name.
pub const TEMPORARY_ID_LENGTH: usize = 32;

/// The longest name of one part of a path (the limit of the file systems of Linux).
pub const MAX_NAME_BYTES: usize = 255;

/// The refusal of a path with a symbolic link that leaves the root of the volume or that does not resolve. With
/// `refuse_links`, it is also the refusal of each symbolic link.
pub fn link_refused() -> Error {
    Error::api(
        403,
        "volume_link_refused",
        "the path has a symbolic link that Stowr does not follow: it leaves the volume, it does not resolve, or the access mode refuses each link",
    )
}

/// The file system error that stands for the refusal of a link. `volume_error` turns it into `link_refused`.
fn link_error() -> io::Error {
    io::Error::from_raw_os_error(libc::ELOOP)
}

/// The error `400 invalid_key`.
pub fn invalid_key(text: impl Into<String>) -> Error {
    Error::api(400, "invalid_key", text)
}

/// A key of a volume, cut into the parts of its path.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VolumeKey {
    /// The names of the path. The root of the volume has no part.
    pub parts: Vec<String>,
    /// True for a key that ends with `/`: the key names a folder.
    pub folder: bool,
}

impl VolumeKey {
    /// The last name, or an empty text for the root.
    pub fn name(&self) -> &str {
        self.parts.last().map_or("", String::as_str)
    }

    /// The names of the folder that holds the last name.
    pub fn parent(&self) -> &[String] {
        match self.parts.split_last() {
            Some((_, parent)) => parent,
            None => &[],
        }
    }
}

/// Cut a key that is relative to the root of the volume. A key for a write must also not name a temporary file. A
/// key is always valid UTF-8 here, so the check of the encoding of a write has nothing to refuse.
pub fn parse_key(key: &str, write: bool) -> Result<VolumeKey> {
    let folder = key.ends_with('/');
    let trimmed = key.strip_suffix('/').unwrap_or(key);
    let mut parsed = VolumeKey {
        parts: Vec::new(),
        folder,
    };
    if trimmed.is_empty() {
        return Ok(parsed);
    }
    if trimmed.contains('\0') {
        return Err(invalid_key("a key of a volume must not contain a NUL byte"));
    }
    parsed.parts = trimmed.split('/').map(str::to_owned).collect();
    for part in &parsed.parts {
        if part.is_empty() || part == "." || part == ".." {
            return Err(invalid_key(
                "a key of a volume must not have an empty, \".\" or \"..\" part",
            ));
        }
        if part.len() > MAX_NAME_BYTES {
            return Err(invalid_key(format!(
                "a name of a key of a volume must have {MAX_NAME_BYTES} bytes or less"
            )));
        }
        if write && part.starts_with(TEMPORARY_PREFIX) {
            return Err(invalid_key(format!(
                "the names that start with {TEMPORARY_PREFIX:?} are for the temporary files of Stowr"
            )));
        }
    }
    Ok(parsed)
}

/// True when the real path `target` is `root` or is in `root`.
pub fn inside_root(target: &Path, root: &Path) -> bool {
    target == root || target.starts_with(root)
}

/// The real path of the relative path `relative` in the folder `root`. `root` is a real path. Each part must exist.
/// A symbolic link is followed when its target is in `root`.
pub fn resolve_inside(root: &Path, relative: &str) -> Result<PathBuf> {
    let mut current = root.to_path_buf();
    for part in relative.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(Error::internal("the path must not have an empty, \".\" or \"..\" part"));
        }
        match resolve_part(root, &current, part, false) {
            Ok(next) => current = next,
            Err(error) if error.raw_os_error() == Some(libc::ELOOP) => return Err(link_refused()),
            Err(error) => {
                return Err(Error::internal(format!(
                    "lstat {}: {}",
                    current.join(part).display(),
                    os_error_text(&error)
                )));
            }
        }
    }
    Ok(current)
}

/// The real path of the name `part` in the real folder `current`. A symbolic link is followed when its target is in
/// `root`, except with `refuse_links`: each symbolic link then gives the link error. This is the one place that
/// follows a link in a path. The error of a part that does not exist is `NotFound`.
pub fn resolve_part(root: &Path, current: &Path, part: &str, refuse_links: bool) -> io::Result<PathBuf> {
    let next = current.join(part);
    let info = fs::symlink_metadata(&next)?;
    if !info.file_type().is_symlink() {
        return Ok(next);
    }
    if refuse_links {
        return Err(link_error());
    }
    match fs::canonicalize(&next) {
        Ok(target) if inside_root(&target, root) => Ok(target),
        _ => Err(link_error()),
    }
}

/// The text of an error of the file system as the system gives it, in lower case and without the number.
pub fn os_error_text(error: &io::Error) -> String {
    let text = error.to_string();
    let text = text.split(" (os error").next().unwrap_or(&text);
    let mut characters = text.chars();
    match characters.next() {
        Some(first) => first.to_lowercase().chain(characters).collect(),
        None => String::new(),
    }
}

/// The error of the API for an error of the file system. The message never shows a path of the server.
pub fn volume_error(error: &io::Error) -> Error {
    let errno = error.raw_os_error();
    if error.kind() == io::ErrorKind::NotFound || errno == Some(libc::ENOTDIR) {
        return Error::upstream(404, "NoSuchKey", "the file does not exist");
    }
    if error.kind() == io::ErrorKind::PermissionDenied {
        return Error::upstream(
            403,
            "AccessDenied",
            "the file system refused the access to the process of Stowr",
        );
    }
    match errno {
        Some(libc::ELOOP) => link_refused(),
        Some(libc::ENOSPC | libc::EDQUOT) => Error::api(507, "volume_full", "the volume has no free space"),
        Some(libc::EROFS) => Error::api(403, "volume_read_only", "the file system of the volume is read only"),
        Some(libc::ENOTEMPTY) => Error::api(409, "volume_folder_not_empty", "the folder is not empty"),
        Some(libc::EISDIR) => Error::api(409, "volume_folder_exists", "a folder has this name"),
        Some(libc::ENAMETOOLONG) => invalid_key("a name of the path is too long for the file system of the volume"),
        Some(_) => Error::api(
            502,
            "volume_error",
            format!(
                "the file system of the volume refused the operation: {}",
                os_error_text(error)
            ),
        ),
        None => Error::api(
            502,
            "volume_error",
            "the file system of the volume refused the operation",
        ),
    }
}

/// A new name of a temporary file. The name of the target follows the random part when the whole name has 255 bytes
/// or less, so that the window "Incomplete uploads" can show it. An empty target gives no target in the name.
pub fn temporary_name(target: &str) -> Result<String> {
    let mut random = [0u8; TEMPORARY_ID_LENGTH / 2];
    random_bytes(&mut random)?;
    let mut name = format!("{TEMPORARY_PREFIX}{}", hex(&random));
    if !target.is_empty() && name.len() + 1 + target.len() <= MAX_NAME_BYTES {
        name.push('-');
        name.push_str(target);
    }
    Ok(name)
}

/// The name of the target of a temporary name: `Some("")` when the name has no target, `None` when the name is not
/// the name of a temporary file of the server.
pub fn parse_temporary_name(name: &str) -> Option<&str> {
    let bytes = name.as_bytes();
    let start = TEMPORARY_PREFIX.len();
    if !name.starts_with(TEMPORARY_PREFIX) || bytes.len() < start + TEMPORARY_ID_LENGTH {
        return None;
    }
    let random = bytes.get(start..start + TEMPORARY_ID_LENGTH)?;
    if !random
        .iter()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return None;
    }
    // The random part is ASCII, so the end of it is a boundary of a character.
    let rest = name.get(start + TEMPORARY_ID_LENGTH..)?;
    if rest.is_empty() {
        return Some("");
    }
    match rest.strip_prefix('-') {
        Some(target) if !target.is_empty() => Some(target),
        _ => None,
    }
}

impl VolumeBackend {
    /// Open a real file for a read. With `refuse_links`, a symbolic link at the end of the path gives an error, also
    /// when a process outside the server made the link after the check of `resolve_part`.
    pub(crate) fn open_read(&self, real: &Path) -> io::Result<fs::File> {
        let mut options = fs::OpenOptions::new();
        options.read(true);
        if self.refuse_links {
            options.custom_flags(libc::O_NOFOLLOW);
        }
        options.open(real)
    }

    /// The real path of the folder of `parts`. With `create`, a folder that does not exist is made, with the
    /// permissions 0777 and the umask of the process, and a part that is a file gives `volume_not_folder`. Without
    /// `create`, a part that does not exist or that is a file gives the 404 of S3.
    pub(crate) fn resolve_folder(&self, parts: &[String], create: bool) -> Result<PathBuf> {
        let mut current = self.root.clone();
        for part in parts {
            let mut resolved = resolve_part(&self.root, &current, part, self.refuse_links);
            if create && matches!(&resolved, Err(error) if error.kind() == io::ErrorKind::NotFound) {
                let next = current.join(part);
                resolved = match fs::DirBuilder::new().mode(0o777).create(&next) {
                    Ok(()) => Ok(next),
                    // Another request made the folder at the same time.
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                        resolve_part(&self.root, &current, part, self.refuse_links)
                    }
                    Err(error) => Err(error),
                };
            }
            let next = resolved.map_err(|error| volume_error(&error))?;
            let info = fs::metadata(&next).map_err(|error| volume_error(&error))?;
            if !info.is_dir() && !create {
                return Err(not_found());
            }
            if !info.is_dir() {
                return Err(Error::api(
                    409,
                    "volume_not_folder",
                    "a part of the path is a file, not a folder",
                ));
            }
            current = next;
        }
        Ok(current)
    }

    /// The real path of a key that exists, and its information. A symbolic link at the end is followed when its
    /// target is in the root.
    pub(crate) fn resolve_existing(&self, key: &VolumeKey) -> Result<(PathBuf, fs::Metadata)> {
        let folder = self.resolve_folder(key.parent(), false)?;
        let mut target = folder.clone();
        if !key.name().is_empty() {
            target = resolve_part(&self.root, &folder, key.name(), self.refuse_links)
                .map_err(|error| volume_error(&error))?;
        }
        let info = fs::metadata(&target).map_err(|error| volume_error(&error))?;
        Ok((target, info))
    }

    /// The real path that a write of the file `key` replaces or makes. The folders of the path are made when they
    /// do not exist. A symbolic link at the end is followed when its target is a file in the root. A folder at the
    /// path stops the write.
    pub(crate) fn write_target(&self, key: &VolumeKey) -> Result<PathBuf> {
        let folder = self.resolve_folder(key.parent(), true)?;
        let mut target = folder.join(key.name());
        let mut info = match fs::symlink_metadata(&target) {
            Ok(info) => info,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(target),
            Err(error) => return Err(volume_error(&error)),
        };
        if info.file_type().is_symlink() {
            let resolved = resolve_part(&self.root, &folder, key.name(), self.refuse_links)
                .map_err(|error| volume_error(&error))?;
            info = fs::metadata(&resolved).map_err(|error| volume_error(&error))?;
            target = resolved;
        }
        if info.is_dir() {
            return Err(Error::api(
                409,
                "volume_folder_exists",
                "a folder has this name: Stowr does not replace a folder with a file",
            ));
        }
        if !info.is_file() {
            return Err(Error::api(
                409,
                "volume_not_file",
                "the path is not a regular file: Stowr does not replace it",
            ));
        }
        Ok(target)
    }
}

/// The 404 of S3 for a file that does not exist.
pub fn not_found() -> Error {
    Error::upstream(404, "NoSuchKey", "the file does not exist")
}
