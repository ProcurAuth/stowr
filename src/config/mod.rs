//! The configuration: the strict reader of the HCL file, the table of the keys, the reference that the table
//! makes (docs/configuration-reference.md), the effective configuration (`print-config` and the log at start), the
//! warnings of the start, the command line and the identity of the build (docs/CONFIGURATION.md).
//!
//! The rules: a closed schema (an unknown block, an unknown attribute or a duplicate attribute stops the start), no
//! change of a value, one parse at start into `crate::common::config::Config`, the forms `_env` and `_file`, the
//! secrets only by `_env` or `_file`, each error with the key, the expected form and the value.

pub mod build_info;
pub mod cli;
pub mod env;
pub mod url;

use std::path::Path;

use crate::common::config::Config;
use crate::common::error::{Error, Result};

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

/// Read and check the configuration file.
pub fn load(path: &Path) -> Result<Config> {
    let _ = path;
    Err(Error::not_served("the reader of the configuration"))
}

/// The effective configuration: one line for each key, in the order of the table of the keys.
pub fn effective(config: &Config) -> Vec<EffectiveSetting> {
    let _ = config;
    Vec::new()
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
    let _ = config;
    Vec::new()
}

/// The text of docs/configuration-reference.md, from the table of the keys.
pub fn reference() -> String {
    String::new()
}
