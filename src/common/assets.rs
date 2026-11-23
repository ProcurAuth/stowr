// SPDX-License-Identifier: MIT OR Apache-2.0
//! The browser interface, embedded in the binary at build time (build.rs). The server never reads the interface
//! from the file system.

mod table {
    include!(concat!(env!("OUT_DIR"), "/public_files.rs"));
}

pub use table::FILES;

/// The bytes of one file of the interface: a path below `src/public` without `/` at the start, for example
/// `assets/css/stowr.css`.
pub fn file(path: &str) -> Option<&'static [u8]> {
    FILES
        .binary_search_by(|(name, _)| (*name).cmp(path))
        .ok()
        .and_then(|index| FILES.get(index))
        .map(|(_, bytes)| *bytes)
}

/// True when the path is a folder of the interface (`assets`, `assets/js`...).
pub fn is_folder(path: &str) -> bool {
    let prefix = format!("{}/", path.trim_end_matches('/'));
    !path.is_empty() && FILES.iter().any(|(name, _)| name.starts_with(&prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pages_are_embedded_in_the_order_of_their_paths() {
        assert!(file("index.html").is_some());
        assert!(file("preview.html").is_some());
        assert!(file("info.html").is_some());
        assert!(file("404.html").is_some());
        assert!(file("missing.html").is_none());
        assert!(is_folder("assets"));
        assert!(FILES.windows(2).all(|pair| pair[0].0 < pair[1].0));
    }
}
