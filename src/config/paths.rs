//! The paths of the configuration: the clean form of a path, the start of a relative path at the folder of the
//! configuration file, and the bounded read of a file.

use std::io::Read as _;
use std::path::Path;

use super::oserror::path_error;

/// The shortest form of a path to the same file: one `/` between the parts, no `.` part, no `..` part after a
/// name, no `/` at the end. An empty path gives `.`.
pub fn clean(path: &str) -> String {
    if path.is_empty() {
        return ".".to_owned();
    }
    let bytes = path.as_bytes();
    let rooted = bytes.first() == Some(&b'/');
    let n = bytes.len();
    let mut out: Vec<u8> = Vec::with_capacity(n);
    let (mut r, mut dotdot) = (0, 0);
    if rooted {
        out.push(b'/');
        r = 1;
        dotdot = 1;
    }
    while r < n {
        let at = |index: usize| bytes.get(index).copied();
        if bytes[r] == b'/' || (bytes[r] == b'.' && (r + 1 == n || at(r + 1) == Some(b'/'))) {
            r += 1;
        } else if bytes[r] == b'.' && at(r + 1) == Some(b'.') && (r + 2 == n || at(r + 2) == Some(b'/')) {
            r += 2;
            if out.len() > dotdot {
                out.pop();
                while out.len() > dotdot && out.last() != Some(&b'/') {
                    out.pop();
                }
                if out.len() > dotdot && out.last() == Some(&b'/') {
                    out.pop();
                }
            } else if !rooted {
                if !out.is_empty() {
                    out.push(b'/');
                }
                out.extend_from_slice(b"..");
                dotdot = out.len();
            }
        } else {
            if (rooted && out.len() != 1) || (!rooted && !out.is_empty()) {
                out.push(b'/');
            }
            while r < n && bytes[r] != b'/' {
                out.push(bytes[r]);
                r += 1;
            }
        }
    }
    if out.is_empty() {
        out.push(b'.');
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The clean join of a folder and a name.
pub fn join(folder: &str, name: &str) -> String {
    match (folder.is_empty(), name.is_empty()) {
        (true, true) => String::new(),
        (true, false) => clean(name),
        (false, true) => clean(folder),
        (false, false) => clean(&format!("{folder}/{name}")),
    }
}

/// True for an absolute path.
pub fn is_absolute(path: &str) -> bool {
    path.starts_with('/')
}

/// A path of the configuration: a relative path starts at the folder of the configuration file. The result is
/// clean.
pub fn resolve_config_path(name: &str, base_dir: &str) -> String {
    if is_absolute(name) {
        clean(name)
    } else {
        join(base_dir, name)
    }
}

/// The absolute and clean form of a path. A relative path starts at the current folder of the process.
pub fn absolute(path: &str) -> Result<String, String> {
    if is_absolute(path) {
        return Ok(clean(path));
    }
    let current = super::env::current_folder().map_err(|error| format!("getwd: {}", super::oserror::cause(&error)))?;
    Ok(join(&current.to_string_lossy(), path))
}

/// Read a file of at most `maximum` bytes. A larger file is an error.
pub fn read_bounded_file(path: &str, maximum: u64) -> Result<Vec<u8>, String> {
    if maximum < 1 {
        return Err("file size limit must be positive".to_owned());
    }
    let file = std::fs::File::open(path).map_err(|error| path_error("open", Path::new(path), &error))?;
    let mut data = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut data)
        .map_err(|error| path_error("read", Path::new(path), &error))?;
    if data.len() as u64 > maximum {
        return Err(format!("file exceeds the {maximum}-byte limit"));
    }
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_gives_the_shortest_form() {
        for (path, want) in [
            ("", "."),
            ("/", "/"),
            ("abc", "abc"),
            ("abc/def", "abc/def"),
            ("a/b/c", "a/b/c"),
            (".", "."),
            ("..", ".."),
            ("../..", "../.."),
            ("../../abc", "../../abc"),
            ("/abc", "/abc"),
            ("/../abc", "/abc"),
            ("abc/", "abc"),
            ("abc/def/", "abc/def"),
            ("a/b/c/", "a/b/c"),
            ("./", "."),
            ("../", ".."),
            ("../../", "../.."),
            ("/abc/", "/abc"),
            ("abc//def//ghi", "abc/def/ghi"),
            ("//abc", "/abc"),
            ("///abc", "/abc"),
            ("//abc//", "/abc"),
            ("abc//", "abc"),
            ("abc/./def", "abc/def"),
            ("/./abc/def", "/abc/def"),
            ("abc/.", "abc"),
            ("abc/def/ghi/../jkl", "abc/def/jkl"),
            ("abc/def/../ghi/../jkl", "abc/jkl"),
            ("abc/def/..", "abc"),
            ("abc/def/../..", "."),
            ("/abc/def/../..", "/"),
            ("abc/def/../../..", ".."),
            ("/abc/def/../../..", "/"),
            ("abc/def/../../../ghi/jkl/../../../mno", "../../mno"),
            ("/../../", "/"),
            ("abc/./../def", "def"),
            ("abc//./../def", "def"),
            ("abc/../../././../def", "../../def"),
        ] {
            assert_eq!(clean(path), want, "{path}");
        }
    }

    #[test]
    fn a_relative_path_starts_at_the_folder_of_the_file() {
        assert_eq!(resolve_config_path("./secret", "/etc/stowr"), "/etc/stowr/secret");
        assert_eq!(resolve_config_path("../x", "/etc/stowr"), "/etc/x");
        assert_eq!(
            resolve_config_path("/run/secrets//token", "/etc/stowr"),
            "/run/secrets/token"
        );
    }
}
