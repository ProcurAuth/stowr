// SPDX-License-Identifier: MIT OR Apache-2.0
//! Embed the browser interface (`src/public`) in the binary.
//!
//! The build script writes a table of each file of `src/public`, in the order of the paths, with the bytes of the
//! file. The server reads the table only: it never reads the interface from the file system at run time.

// A build script talks to cargo on its standard output.
#![allow(clippy::print_stdout)]

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

fn main() -> Result<(), String> {
    let manifest = std::env::var_os("CARGO_MANIFEST_DIR")
        .map(PathBuf::from)
        .unwrap_or_default();
    let out_dir = std::env::var_os("OUT_DIR").map(PathBuf::from).unwrap_or_default();
    let public = manifest.join("src").join("public");
    println!("cargo:rerun-if-changed=src/public");
    println!("cargo:rerun-if-env-changed=STOWR_BUILD_VERSION");
    println!("cargo:rerun-if-env-changed=STOWR_BUILD_COMMIT");
    println!("cargo:rerun-if-env-changed=STOWR_BUILD_DATE");
    println!("cargo:rerun-if-env-changed=STOWR_MULTIPART_COPY_THRESHOLD");
    println!("cargo:rerun-if-env-changed=STOWR_MULTIPART_COPY_PART_SIZE");

    let mut files = Vec::new();
    collect(&public, &public, &mut files)?;
    files.sort();

    let mut table = String::from("/// Each file of the interface: the path below `src/public` and the bytes.\n");
    table.push_str("pub static FILES: &[(&str, &[u8])] = &[\n");
    for (relative, absolute) in &files {
        println!("cargo:rerun-if-changed={}", absolute.display());
        let _ = writeln!(
            table,
            "    ({relative:?}, include_bytes!({:?})),",
            absolute.display().to_string()
        );
    }
    table.push_str("];\n");
    std::fs::write(out_dir.join("public_files.rs"), table)
        .map_err(|error| format!("cannot write the table of the interface: {error}"))
}

fn collect(root: &Path, folder: &Path, files: &mut Vec<(String, PathBuf)>) -> Result<(), String> {
    let entries = std::fs::read_dir(folder).map_err(|error| format!("cannot read {}: {error}", folder.display()))?;
    for entry in entries.flatten() {
        let path = entry.path();
        // A name that starts with "." or "_" is not part of the interface.
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') || name.starts_with('_') {
            continue;
        }
        if path.is_dir() {
            collect(root, &path, files)?;
        } else if let Ok(relative) = path.strip_prefix(root) {
            let name = relative
                .components()
                .map(|part| part.as_os_str().to_string_lossy())
                .collect::<Vec<_>>()
                .join("/");
            files.push((name, path));
        }
    }
    Ok(())
}
