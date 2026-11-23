// SPDX-License-Identifier: MIT OR Apache-2.0
//! The capacity of the file system of a volume (`statfs`). This is the only module of the program with `unsafe`
//! code: one call to the C library, with a buffer that this module owns.
#![allow(unsafe_code)]

use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// The type numbers of the file systems that can count the used bytes with a delay: FUSE, NFS, CephFS, SMB 2, CIFS.
const DELAYED_FILE_SYSTEMS: [i64; 5] = [0x6573_5546, 0x6969, 0x00c3_6400, 0xfe53_4d42, 0xff53_4d42];

/// The capacity of a file system.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileSystemSize {
    /// The size in bytes.
    pub total: u64,
    /// The bytes that the process can use.
    pub available: u64,
    /// True for a file system that can count the used bytes with a delay.
    pub delayed: bool,
}

/// `statfs` of a path. The size is in bytes: the number of blocks times the fragment size, or the block size when
/// the file system gives no fragment size. The available bytes are the bytes that the process can use: the blocks
/// that the file system keeps for the superuser are not in them.
// The types of the fields change with the C library (glibc, musl): the casts are the same on each.
#[allow(clippy::unnecessary_cast)]
pub fn statfs(path: &Path) -> io::Result<FileSystemSize> {
    let name = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "the path has a NUL byte"))?;
    let mut buffer = std::mem::MaybeUninit::<libc::statfs>::zeroed();
    // SAFETY: `name` is a valid C text that lives during the call, and `buffer` is a writable `statfs` value that
    // this function owns. The value is read only after the call returned 0.
    let status = unsafe { libc::statfs(name.as_ptr(), buffer.as_mut_ptr()) };
    if status != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the call returned 0, so it wrote the whole value.
    let value = unsafe { buffer.assume_init() };
    let block = match value.f_frsize as u64 {
        0 => value.f_bsize as u64,
        fragment => fragment,
    };
    let total = (value.f_blocks as u64).saturating_mul(block);
    let available = (value.f_bavail as u64).saturating_mul(block);
    let kind = value.f_type as i64;
    Ok(FileSystemSize {
        total,
        available,
        delayed: DELAYED_FILE_SYSTEMS.contains(&kind),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statfs_of_the_root_gives_a_size() {
        let size = statfs(Path::new("/")).unwrap();
        assert!(size.total >= size.available);
    }
}
