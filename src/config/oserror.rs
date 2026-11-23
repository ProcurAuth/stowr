// SPDX-License-Identifier: MIT OR Apache-2.0
//! The text of an error of the operating system in the messages of the start: `<operation> <path>: <cause>`, with the
//! cause in lower case, for example `open /etc/stowr/token: no such file or directory`. The text is the same with each
//! C library.

use std::io;

/// The cause of an error of the operating system, in lower case.
pub fn cause(error: &io::Error) -> String {
    if let Some(text) = error.raw_os_error().and_then(errno_text) {
        return text.to_owned();
    }
    let text = error.to_string();
    let text = match text.rfind(" (os error ") {
        Some(index) if text.ends_with(')') => text.get(..index).unwrap_or(&text).to_owned(),
        _ => text,
    };
    let mut chars = text.chars();
    match chars.next() {
        Some(first) => first.to_lowercase().chain(chars).collect(),
        None => text,
    }
}

/// The text of an operation on a path that failed: `<operation> <path>: <cause>`.
pub fn path_error(operation: &str, path: &std::path::Path, error: &io::Error) -> String {
    format!("{operation} {}: {}", path.display(), cause(error))
}

/// The text of the common error numbers.
fn errno_text(code: i32) -> Option<&'static str> {
    let text = match code {
        libc::EPERM => "operation not permitted",
        libc::ENOENT => "no such file or directory",
        libc::EINTR => "interrupted system call",
        libc::EIO => "input/output error",
        libc::ENXIO => "no such device or address",
        libc::EBADF => "bad file descriptor",
        libc::EAGAIN => "resource temporarily unavailable",
        libc::ENOMEM => "cannot allocate memory",
        libc::EACCES => "permission denied",
        libc::EFAULT => "bad address",
        libc::EBUSY => "device or resource busy",
        libc::EEXIST => "file exists",
        libc::EXDEV => "invalid cross-device link",
        libc::ENODEV => "no such device",
        libc::ENOTDIR => "not a directory",
        libc::EISDIR => "is a directory",
        libc::EINVAL => "invalid argument",
        libc::ENFILE => "too many open files in system",
        libc::EMFILE => "too many open files",
        libc::ETXTBSY => "text file busy",
        libc::EFBIG => "file too large",
        libc::ENOSPC => "no space left on device",
        libc::EROFS => "read-only file system",
        libc::EMLINK => "too many links",
        libc::ENAMETOOLONG => "file name too long",
        libc::ENOTEMPTY => "directory not empty",
        libc::ELOOP => "too many levels of symbolic links",
        libc::EOVERFLOW => "value too large for defined data type",
        libc::EADDRINUSE => "address already in use",
        libc::EADDRNOTAVAIL => "cannot assign requested address",
        libc::ENETUNREACH => "network is unreachable",
        libc::ECONNABORTED => "software caused connection abort",
        libc::ECONNRESET => "connection reset by peer",
        libc::ENOTCONN => "transport endpoint is not connected",
        libc::ETIMEDOUT => "connection timed out",
        libc::ECONNREFUSED => "connection refused",
        libc::EHOSTUNREACH => "no route to host",
        libc::ESTALE => "stale NFS file handle",
        libc::EDQUOT => "disk quota exceeded",
        _ => return None,
    };
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_cause_is_in_lower_case_without_the_number() {
        assert_eq!(
            cause(&io::Error::from_raw_os_error(libc::ENOENT)),
            "no such file or directory"
        );
        assert_eq!(
            cause(&io::Error::from_raw_os_error(libc::ELOOP)),
            "too many levels of symbolic links"
        );
        assert_eq!(cause(&io::Error::other("Other text")), "other text");
        assert_eq!(
            path_error(
                "open",
                std::path::Path::new("/x"),
                &io::Error::from_raw_os_error(libc::EACCES)
            ),
            "open /x: permission denied"
        );
    }
}
