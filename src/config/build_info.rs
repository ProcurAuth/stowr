// SPDX-License-Identifier: MIT OR Apache-2.0
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

fn value(given: Option<&str>, fallback: &str) -> String {
    match given.map(str::trim) {
        Some(text) if !text.is_empty() => text.to_owned(),
        _ => fallback.to_owned(),
    }
}

/// The identity of a build from its version, its commit and its date. No value, or an empty value, gives `dev`,
/// `unknown` and no date.
pub fn from_parts(version: Option<&str>, commit: Option<&str>, date: Option<&str>) -> BuildInfo {
    let version = value(version, "dev");
    let commit = value(commit, "unknown");
    let date = value(date, "");
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

/// The identity of this build.
pub fn current() -> BuildInfo {
    from_parts(
        option_env!("STOWR_BUILD_VERSION"),
        option_env!("STOWR_BUILD_COMMIT"),
        option_env!("STOWR_BUILD_DATE"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_given_identity_gives_the_short_commit_and_the_display() {
        let info = from_parts(Some("v1.2.3"), Some("0123456789abcdef"), Some("2026-07-24T12:00:00Z"));
        assert_eq!(info.short_commit, "012345678");
        assert_eq!(info.display, "v1.2.3 · 012345678");
        assert_eq!(info.date, "2026-07-24T12:00:00Z");
        let json = serde_json::to_string(&info).unwrap();
        assert_eq!(
            json,
            "{\"version\":\"v1.2.3\",\"commit\":\"0123456789abcdef\",\"shortCommit\":\"012345678\",\"date\":\"2026-07-24T12:00:00Z\",\"display\":\"v1.2.3 · 012345678\"}"
        );
    }

    #[test]
    fn a_build_without_identity_is_dev() {
        let info = from_parts(None, Some("  "), None);
        assert_eq!(info.version, "dev");
        assert_eq!(info.commit, "unknown");
        assert_eq!(info.short_commit, "unknown");
        assert_eq!(info.display, "dev");
        assert_eq!(
            serde_json::to_string(&info).unwrap(),
            "{\"version\":\"dev\",\"commit\":\"unknown\",\"shortCommit\":\"unknown\",\"display\":\"dev\"}"
        );
        let short = from_parts(Some("v9.8.7"), Some("abcdef1234567890"), None);
        assert_eq!(short.short_commit, "abcdef123");
    }
}
