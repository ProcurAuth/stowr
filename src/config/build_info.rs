//! The identity of the build: the version, the commit and the date that the release build gives
//! (`STOWR_BUILD_VERSION`, `STOWR_BUILD_COMMIT`, `STOWR_BUILD_DATE` at compile time).

use serde::Serialize;

/// The identity of the build, as `/api/build` gives it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BuildInfo {
    /// The version, or `dev`.
    pub version: String,
    /// The commit, or `unknown`.
    pub commit: String,
    /// The first 9 characters of the commit.
    pub short_commit: String,
    /// The date of the build, when the build gives it.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub date: String,
    /// `version · short commit`, or the version alone.
    pub display: String,
}

fn value(compiled: Option<&'static str>, fallback: &str) -> String {
    match compiled.map(str::trim) {
        Some(text) if !text.is_empty() => text.to_owned(),
        _ => fallback.to_owned(),
    }
}

/// The identity of this build.
pub fn current() -> BuildInfo {
    let version = value(option_env!("STOWR_BUILD_VERSION"), "dev");
    let commit = value(option_env!("STOWR_BUILD_COMMIT"), "unknown");
    let date = value(option_env!("STOWR_BUILD_DATE"), "");
    let short_commit: String = commit.chars().take(9).collect();
    let display = if short_commit.is_empty() || short_commit == "unknown" {
        version.clone()
    } else {
        format!("{version} · {short_commit}")
    };
    BuildInfo {
        version,
        commit,
        short_commit,
        date,
        display,
    }
}
