// SPDX-License-Identifier: MIT OR Apache-2.0
//! The only reader of the process environment, and the forms `<name>`, `<name>_env` and `<name>_file` of a key.
//!
//! The configuration names each variable with an attribute `<name>_env`. The program reads no other variable
//! (scripts/check-invariants.sh checks it). This module also gives the arguments of the command line and the current
//! folder of the process.

use super::hcl::Block;
use super::keys::{FORM_ENV, FORM_FILE, FORM_VALUE};
use super::paths::{read_bounded_file, resolve_config_path};
use super::quote::quote;
use super::{Hooks, MAX_SECRET_FILE_BYTES};

/// The state of an environment variable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Variable {
    /// The variable does not exist.
    Missing,
    /// The value is not valid UTF-8.
    NotUnicode,
    /// The value.
    Value(String),
}

/// Read one environment variable that the configuration names. A name that is empty or that has `=` or a NUL
/// character names no variable.
pub fn read(name: &str) -> Variable {
    if name.is_empty() || name.contains('=') || name.contains('\0') {
        return Variable::Missing;
    }
    match std::env::var_os(name) {
        None => Variable::Missing,
        Some(value) => match value.into_string() {
            Ok(text) => Variable::Value(text),
            Err(_) => Variable::NotUnicode,
        },
    }
}

/// The value of an environment variable that the configuration names, or `None` when it does not exist (or is not
/// valid Unicode).
pub fn lookup(name: &str) -> Option<String> {
    match read(name) {
        Variable::Value(text) => Some(text),
        Variable::Missing | Variable::NotUnicode => None,
    }
}

/// The arguments of the command line, without the name of the program. An argument that is not valid UTF-8 gets
/// U+FFFD for each bad byte.
pub fn arguments() -> Vec<String> {
    std::env::args_os()
        .skip(1)
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect()
}

/// The current folder of the process: a relative path of the command line starts there.
pub fn current_folder() -> std::io::Result<std::path::PathBuf> {
    std::env::current_dir()
}

/// Read the value of a key that can have the forms `<name>`, `<name>_env` and `<name>_file`. `forms` gives the forms
/// that the key accepts. The block can have one form only. A variable that does not exist, an empty value, or a file
/// that the server cannot read is an error. The value of a file has no last line end. The function does not change
/// the value in other ways. `None`: the block has no form of the key.
pub(super) fn resolve_value_source(
    block: &Block,
    path: &str,
    name: &str,
    base_dir: &str,
    forms: u8,
    hooks: &Hooks<'_>,
) -> Result<Option<String>, String> {
    let env_attribute = format!("{name}_env");
    let file_attribute = format!("{name}_file");
    let direct = block.string(name);
    let env_name = block.string(&env_attribute);
    let file_name = block.string(&file_attribute);
    let count = [direct.is_some(), env_name.is_some(), file_name.is_some()]
        .iter()
        .filter(|present| **present)
        .count();
    if count == 0 {
        return Ok(None);
    }
    if count > 1 {
        return Err(block.error(format!(
            "{path}.{name}: give only one of {name}, {name}_env and {name}_file"
        )));
    }
    if let Some(direct) = direct {
        if forms & FORM_VALUE == 0 {
            return Err(block.error(format!(
                "{path}.{name} is a secret: use {name}_env or {name}_file, not the value in clear text"
            )));
        }
        if direct.is_empty() {
            return Err(block.error(format!("{path}.{name} is empty")));
        }
        return Ok(Some(direct.to_owned()));
    }
    if let Some(env_name) = env_name {
        if forms & FORM_ENV == 0 {
            return Err(block.error(format!("{path}.{name}_env is not a form of the key")));
        }
        if env_name.is_empty() {
            return Err(block.error(format!("{path}.{name}_env is empty")));
        }
        return match (hooks.environment)(env_name) {
            Variable::Missing => Err(block.error(format!(
                "{path}.{name}_env: the environment variable {} does not exist",
                quote(env_name)
            ))),
            Variable::NotUnicode => Err(block.error(format!(
                "{path}.{name}_env: the environment variable {} is not valid UTF-8",
                quote(env_name)
            ))),
            Variable::Value(value) if value.is_empty() => Err(block.error(format!(
                "{path}.{name}_env: the environment variable {} is empty",
                quote(env_name)
            ))),
            Variable::Value(value) => Ok(Some(value)),
        };
    }
    let file_name = file_name.unwrap_or_default();
    if forms & FORM_FILE == 0 {
        return Err(block.error(format!("{path}.{name}_file is not a form of the key")));
    }
    if file_name.is_empty() {
        return Err(block.error(format!("{path}.{name}_file is empty")));
    }
    let cleaned = resolve_config_path(file_name, base_dir);
    let data = read_bounded_file(&cleaned, MAX_SECRET_FILE_BYTES)
        .map_err(|error| block.error(format!("{path}.{name}_file: cannot read {}: {error}", quote(&cleaned))))?;
    let Ok(text) = String::from_utf8(data) else {
        return Err(block.error(format!(
            "{path}.{name}_file: the file {} is not valid UTF-8",
            quote(&cleaned)
        )));
    };
    let value = strip_last_line_end(&text);
    if value.is_empty() {
        return Err(block.error(format!("{path}.{name}_file: the file {} is empty", quote(&cleaned))));
    }
    Ok(Some(value.to_owned()))
}

/// The text of a `_file` form without its last line end: one `\n`, or one `\r\n`. A `\r` without a `\n` after it
/// is part of the value.
fn strip_last_line_end(text: &str) -> &str {
    match text.strip_suffix('\n') {
        Some(value) => value.strip_suffix('\r').unwrap_or(value),
        None => text,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_value_loses_only_its_last_line_end() {
        assert_eq!(strip_last_line_end("abc\n"), "abc");
        assert_eq!(strip_last_line_end("abc\r\n"), "abc");
        assert_eq!(strip_last_line_end("abc\r"), "abc\r");
        assert_eq!(strip_last_line_end("abc"), "abc");
        assert_eq!(strip_last_line_end("abc\n\n"), "abc\n");
        assert_eq!(strip_last_line_end("abc\r\n\r\n"), "abc\r\n");
        assert_eq!(strip_last_line_end("abc\n\r"), "abc\n\r");
        assert_eq!(strip_last_line_end("\n"), "");
        assert_eq!(strip_last_line_end("\r"), "\r");
    }

    #[test]
    fn a_name_with_an_equal_sign_or_a_nul_names_no_variable() {
        assert_eq!(read(""), Variable::Missing);
        assert_eq!(read("PATH=x"), Variable::Missing);
        assert_eq!(read("PA\0TH"), Variable::Missing);
        assert_eq!(read("STOWR_TEST_NO_SUCH_VARIABLE"), Variable::Missing);
        assert_eq!(lookup("STOWR_TEST_NO_SUCH_VARIABLE"), None);
    }
}
