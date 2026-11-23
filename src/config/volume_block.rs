// SPDX-License-Identifier: MIT OR Apache-2.0
//! The `volume` block: one folder of the file system of the server that the browser shows as it shows a bucket
//! (docs/ARCHITECTURE.md, "Volumes"). The start checks that the folder exists, that it is a folder, and that the
//! process can read it. The volume back end checks the write permission at start: it writes a file.

use std::path::{Path, PathBuf};

use crate::common::config::VolumeConfig;

use super::Hooks;
use super::decode::{ID_PATTERN, decode_permissions, reject_unknown_attrs, require_attr_kinds, text_attr, valid_id};
use super::hcl::{Block, Kind};
use super::keys::attribute_names;
use super::oserror::path_error;
use super::paths::{clean, is_absolute};
use super::quote::{quote, quote_bytes};

/// True when the value is a relative folder path that ends with `/`, with parts that are not empty, `.` or `..`, and
/// without a NUL byte.
fn valid_volume_root_prefix(value: &str) -> bool {
    if value.starts_with('/') || !value.ends_with('/') || value.contains('\0') {
        return false;
    }
    value
        .strip_suffix('/')
        .unwrap_or(value)
        .split('/')
        .all(|part| !part.is_empty() && part != "." && part != "..")
}

/// Read one `volume` block, and check its folder.
pub(super) fn decode(block: &Block, hooks: &Hooks<'_>) -> Result<VolumeConfig, String> {
    let [label] = block.labels.as_slice() else {
        return Err(block.error("volume block requires exactly one quoted identifier"));
    };
    reject_unknown_attrs(block, &attribute_names("volume"))?;
    require_attr_kinds(block, |name| match name {
        b"name" | b"path" | b"root_prefix" => Some(Kind::String),
        b"permissions" => Some(Kind::List),
        b"max_scan_pages" => Some(Kind::Number),
        _ => None,
    })?;
    if !block.blocks.is_empty() {
        return Err(block.error("nested blocks are not supported inside volume"));
    }
    if !valid_id(label) {
        return Err(block.error(format!(
            "volume label must match {ID_PATTERN}, got {}",
            quote_bytes(label)
        )));
    }
    let id = String::from_utf8_lossy(label).into_owned();
    let path = format!("volume {}", quote(&id));
    let name = text_attr(block, &path, "name")?.unwrap_or_else(|| id.clone());
    let Some(folder) = text_attr(block, &path, "path")? else {
        return Err(block.error(format!(
            "{path}.path is required: the absolute path of the folder (for example \"/data/volume\")"
        )));
    };
    // The value applies as it is: the server does not clean it.
    if !is_absolute(&folder) || clean(&folder) != folder {
        return Err(block.error(format!(
            "{path}.path must be an absolute path without \"/\" at the end and without an empty, \".\" or \"..\" part (for example \"/data/volume\"), got {}",
            quote(&folder)
        )));
    }
    let mut root_prefix = String::new();
    if let Some(value) = block.string("root_prefix") {
        if !value.is_empty() && !valid_volume_root_prefix(value) {
            return Err(block.error(format!(
                "{path}.root_prefix must be \"\" or a relative folder path that ends with \"/\", without an empty, \".\" or \"..\" part (for example \"published/\"), got {}",
                quote(value)
            )));
        }
        value.clone_into(&mut root_prefix);
    }
    let mut max_scan_pages = 1;
    if let Some(value) = block.integer("max_scan_pages") {
        if !(0..=1_000_000).contains(&value) {
            return Err(block.error(format!(
                "{path}.max_scan_pages must be between 0 and 1000000, got {value}"
            )));
        }
        max_scan_pages = u32::try_from(value).unwrap_or(1);
    }
    let permissions = decode_permissions(block, &path)?;
    let volume = VolumeConfig {
        id,
        name,
        path: PathBuf::from(folder),
        permissions_defined: permissions.is_some(),
        permissions: permissions.unwrap_or_default(),
        root_prefix,
        max_scan_pages,
        refuse_links: false,
    };
    check_volume_folder(&volume, hooks).map_err(|error| block.error(format!("{path}: {error}")))?;
    Ok(volume)
}

/// Check the folder of a volume at start: the path and the root prefix exist, are folders, stay inside the path after
/// the symbolic links, and the process can read them.
fn check_volume_folder(volume: &VolumeConfig, hooks: &Hooks<'_>) -> Result<(), String> {
    let shown = quote(&volume.path.to_string_lossy());
    let info = std::fs::metadata(&volume.path).map_err(|error| {
        format!(
            "path {shown} must be a folder that exists at start: {}",
            path_error("stat", &volume.path, &error)
        )
    })?;
    if !info.is_dir() {
        return Err(format!("path {shown} must be a folder, got a file"));
    }
    let root = std::fs::canonicalize(&volume.path).map_err(|error| {
        format!(
            "path {shown}: cannot resolve the symbolic links: {}",
            path_error("lstat", &volume.path, &error)
        )
    })?;
    let mut top = root.clone();
    if !volume.root_prefix.is_empty() {
        let prefix = quote(&volume.root_prefix);
        let relative = volume.root_prefix.strip_suffix('/').unwrap_or(&volume.root_prefix);
        top = (hooks.resolve_inside)(&root, relative).map_err(|error| format!("root_prefix {prefix}: {error}"))?;
        let info = std::fs::metadata(&top).map_err(|error| {
            format!(
                "root_prefix {prefix} must be a folder that exists at start in path {shown}: {}",
                path_error("stat", &top, &error)
            )
        })?;
        if !info.is_dir() {
            return Err(format!(
                "root_prefix {prefix} must be a folder in path {shown}, got a file"
            ));
        }
    }
    read_first_entry(&top)
}

/// Read the first entry of a folder: the process can read it.
fn read_first_entry(folder: &Path) -> Result<(), String> {
    let shown = quote(&folder.to_string_lossy());
    let mut entries = std::fs::read_dir(folder).map_err(|error| {
        format!(
            "the process cannot read the folder {shown}: {}",
            path_error("open", folder, &error)
        )
    })?;
    if let Some(Err(error)) = entries.next() {
        return Err(format!(
            "the process cannot read the folder {shown}: {}",
            path_error("readdir", folder, &error)
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_root_prefix_is_a_relative_folder_path_that_ends_with_a_slash() {
        assert!(valid_volume_root_prefix("published/"));
        assert!(valid_volume_root_prefix("a/b/"));
        for value in ["/published/", "published", "a/../b/", "a//b/", "./", "a/./", "a\0/"] {
            assert!(!valid_volume_root_prefix(value), "{value:?}");
        }
    }
}
