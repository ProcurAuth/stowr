//! The keys and the paths of a volume: the check of a key, the resolution of each part of a path inside the root,
//! the refusal of the symbolic links, and the names of the temporary files.

use std::path::{Path, PathBuf};

use crate::common::error::{Error, Result};

/// The prefix of the names of the temporary files of the server.
pub const TEMPORARY_PREFIX: &str = ".stowr-tmp-";

/// Resolve a relative folder path inside a root, part after part, after the symbolic links. A path that leaves the
/// root, or that does not resolve, is an error.
pub fn resolve_inside(root: &Path, relative: &str) -> Result<PathBuf> {
    let _ = (root, relative);
    Err(Error::not_served("the resolution of the paths of a volume"))
}
