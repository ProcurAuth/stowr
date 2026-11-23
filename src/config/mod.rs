//! The configuration: the strict reader of the HCL file, the table of the keys, the reference that the table
//! makes (docs/configuration-reference.md), the effective configuration (`print-config` and the log at start), the
//! warnings of the start, the command line and the identity of the build (docs/CONFIGURATION.md).
//!
//! The rules: a closed schema (an unknown block, an unknown attribute or a duplicate attribute stops the start), no
//! change of a value, one parse at start into `crate::common::config::Config`, the forms `_env` and `_file`, the
//! secrets only by `_env` or `_file`, each error with the key, the expected form and the value.

mod access_block;
pub mod build_info;
pub mod cli;
mod decode;
mod effective;
pub mod env;
mod flags;
mod hcl;
mod health;
pub mod keys;
pub mod oserror;
mod paths;
mod printable;
pub mod quote;
pub mod url;
mod volume_block;

#[cfg(test)]
mod access_tests;
#[cfg(test)]
mod cli_tests;
#[cfg(test)]
mod fixture_tests;
#[cfg(test)]
mod support_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod usage_tests;
#[cfg(test)]
mod volume_tests;

use std::path::{Path, PathBuf};

use crate::common::config::Config;
use crate::common::error::{Error, Result};

pub use access_block::{
    DEFAULT_IDENTITY_CLOCK_SKEW, DEFAULT_IDENTITY_HEADER, DEFAULT_IDENTITY_MAX_AGE, DEFAULT_PDP_CACHE_TTL,
    DEFAULT_PDP_MAX_EVALUATIONS, DEFAULT_PDP_TIMEOUT, DEFAULT_PDP_USAGE_TIMEOUT, MAX_ACCESS_ID_BYTES,
    MAX_ACCESS_RESOURCES, duration_text, parse_duration_text,
};

/// The largest configuration file: 4 MiB.
pub const MAX_CONFIGURATION_BYTES: u64 = 4 << 20;
/// The largest file of a `_file` form: 1 MiB.
pub const MAX_SECRET_FILE_BYTES: u64 = 1 << 20;

/// One line of the effective configuration: the path of the key, the value and the source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectiveSetting {
    /// The path of the key, for example `bucket "archive".max_scan_pages`.
    pub name: String,
    /// The value, quoted for a text; `<hidden>` for a secret; `<none>` for no value.
    pub value: String,
    /// `file`, `env:VAR`, `file:/path` or `default`.
    pub source: String,
}

/// The services of the system that the reader of the configuration uses: the environment, the reader of the public
/// keys of the issuer, and the resolution of a path inside a volume. The tests give other services.
#[derive(Clone, Copy)]
pub struct Hooks<'a> {
    /// Read one environment variable that the file names.
    pub environment: &'a dyn Fn(&str) -> env::Variable,
    /// Read the text of `access.identity.public_keys` and give the short name of each key.
    pub public_keys: &'a dyn Fn(&str) -> Result<Vec<String>>,
    /// Resolve a relative folder path inside the real root of a volume.
    pub resolve_inside: &'a dyn Fn(&Path, &str) -> Result<PathBuf>,
}

impl Hooks<'static> {
    /// The services of the process.
    pub fn system() -> Self {
        Self {
            environment: &env::read,
            public_keys: &crate::access::parse_public_keys,
            resolve_inside: &crate::volume::path::resolve_inside,
        }
    }
}

/// Read and check the configuration file. A relative path starts at the current folder.
pub fn load(path: &Path) -> Result<Config> {
    load_with(path, &Hooks::system())
}

/// Read and check the configuration file with the services of `hooks`.
pub fn load_with(path: &Path, hooks: &Hooks<'_>) -> Result<Config> {
    let text = path.to_string_lossy();
    let name = text.trim();
    if name.is_empty() {
        return Err(Error::internal("configuration path cannot be empty"));
    }
    let absolute =
        paths::absolute(name).map_err(|error| Error::internal(format!("resolve configuration path: {error}")))?;
    let data = paths::read_bounded_file(&absolute, MAX_CONFIGURATION_BYTES)
        .map_err(|error| Error::internal(format!("read configuration {}: {error}", quote::quote(&absolute))))?;
    let folder = match absolute.rfind('/') {
        Some(0) => "/".to_owned(),
        Some(index) => absolute[..index].to_owned(),
        None => ".".to_owned(),
    };
    decode::decode(&data, &absolute, &folder, hooks).map_err(Error::internal)
}

/// Read the configuration of the command line: a path is required.
pub fn load_runtime(path: &str) -> Result<Config> {
    load_runtime_with(path, &Hooks::system())
}

/// Read the configuration of the command line with the services of `hooks`.
pub fn load_runtime_with(path: &str, hooks: &Hooks<'_>) -> Result<Config> {
    let path = path.trim();
    if path.is_empty() {
        return Err(Error::internal(
            "configuration path is required; use -c <path> or --config <path>",
        ));
    }
    load_with(Path::new(path), hooks)
}

/// Read the configuration from a text, as [`load`] reads a file. `source_name` names the file in the messages, and
/// a relative path of the text starts at `source_dir`.
pub fn decode(text: &str, source_name: &Path, source_dir: &Path) -> Result<Config> {
    decode_with(text.as_bytes(), source_name, source_dir, &Hooks::system())
}

/// Read the configuration from bytes with the services of `hooks`.
pub fn decode_with(data: &[u8], source_name: &Path, source_dir: &Path, hooks: &Hooks<'_>) -> Result<Config> {
    decode::decode(
        data,
        &source_name.to_string_lossy(),
        &source_dir.to_string_lossy(),
        hooks,
    )
    .map_err(Error::internal)
}

/// The effective configuration: one line for each key, in the order of the table of the keys.
pub fn effective(config: &Config) -> Vec<EffectiveSetting> {
    effective::effective(config)
}

/// The text of `print-config`: `name = value  # source` for each key.
pub fn format_effective(config: &Config) -> String {
    effective(config)
        .iter()
        .map(|setting| format!("{} = {}  # {}\n", setting.name, setting.value, setting.source))
        .collect()
}

/// The warnings of the start (`config.warning`).
pub fn warnings(config: &Config) -> Vec<String> {
    access_block::warnings(config)
}

/// Write the effective configuration and the warnings in the log, as the start does.
pub fn log_start(config: &Config) {
    for setting in effective(config) {
        crate::log!(
            "config.effective {} = {}  # {}",
            setting.name,
            setting.value,
            setting.source
        );
    }
    for warning in warnings(config) {
        crate::log!("config.warning {warning}");
    }
}

/// The text of docs/configuration-reference.md, from the table of the keys.
pub fn reference() -> String {
    keys::reference()
}
