// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tests of the `usage` block of an `auth` block and of `bucket.quota_bytes`.

use crate::common::config::{Config, UsageSource};
use crate::common::error::Result;

use super::support_tests::{TEST_OPEN_ACCESS, TempDir, decode_in, decode_in_with, load_in, message, with_environment};
use super::{format_effective, reference};

/// The body of an auth block with the mode `access_key`. The lines of the usage block follow it.
const USAGE_AUTH_LINES: &str = "
  provider               = \"s3\"
  mode                   = \"access_key\"
  endpoint               = \"http://minio.local:9000\"
  region                 = \"test\"
  access_key_id          = \"key\"
  secret_access_key_file = \"./s3-secret\"
";

/// A configuration with the auth block `x` and the bucket `b`. `auth_lines` is the body of the auth block, with the
/// usage block. `bucket_lines` are more lines of the bucket block.
fn usage_config_text(auth_lines: &str, bucket_lines: &str) -> String {
    format!(
        "auth \"x\" {{{auth_lines}}}\nbucket \"b\" {{\n  auth   = \"x\"\n  bucket = \"bucket\"\n{bucket_lines}\n}}\n"
    )
}

/// An access_key auth body with a usage block that has these lines.
fn usage_block(lines: &str) -> String {
    format!("{USAGE_AUTH_LINES}  usage {{\n{lines}\n  }}\n")
}

fn usage_dir() -> TempDir {
    let dir = TempDir::new();
    dir.write("s3-secret", "s3-secret-value\n");
    dir.write("token", "admin-token-value\n");
    dir.write("gcs.json", "{\"type\":\"service_account\"}");
    dir
}

/// Write the files that the configuration needs and load it. It gives the folder too.
fn load_usage(content: &str) -> (Result<Config>, TempDir) {
    let dir = usage_dir();
    let result = load_in(&dir, &format!("{content}{TEST_OPEN_ACCESS}"));
    (result, dir)
}

#[test]
fn usage_of_garage() {
    let (result, _dir) = load_usage(&usage_config_text(
        &usage_block(
            "\n    source     = \"garage\"\n    endpoint   = \"http://garage.local:3903\"\n    token_file = \"./token\"",
        ),
        "",
    ));
    let config = result.unwrap();
    let usage = config.auths[0].usage.clone().unwrap();
    assert_eq!(usage.source, UsageSource::Garage);
    assert_eq!(usage.endpoint, "http://garage.local:3903");
    assert_eq!(usage.filer_endpoint, "");
    assert_eq!(usage.token, "admin-token-value");
    assert!(!format!("{usage:?}").contains("admin-token-value"));
    assert_eq!(config.buckets[0].quota_bytes, 0);
}

#[test]
fn the_garage_token_from_the_environment() {
    with_environment(&[("USAGE_TEST_GARAGE_TOKEN", "token-from-the-environment")], |hooks| {
        let dir = usage_dir();
        let text = usage_config_text(
            &usage_block(
                "\n    source    = \"garage\"\n    endpoint  = \"http://garage.local:3903\"\n    token_env = \"USAGE_TEST_GARAGE_TOKEN\"",
            ),
            "",
        );
        let config = decode_in_with(&dir, &format!("{text}{TEST_OPEN_ACCESS}"), hooks).unwrap();
        assert_eq!(
            config.auths[0].usage.as_ref().unwrap().token,
            "token-from-the-environment"
        );
        let printed = format_effective(&config);
        assert!(printed.contains("auth \"x\".usage.token = <hidden>  # env:USAGE_TEST_GARAGE_TOKEN"));
        assert!(!printed.contains("token-from-the-environment"));
    });
}

#[test]
fn usage_of_seaweedfs() {
    let (result, _dir) = load_usage(&usage_config_text(
        &usage_block(
            "\n    source         = \"seaweedfs\"\n    endpoint       = \"http://master.local:9333\"\n    filer_endpoint = \"https://filer.local:8888\"",
        ),
        "",
    ));
    let usage = result.unwrap().auths[0].usage.clone().unwrap();
    assert_eq!(usage.source, UsageSource::SeaweedFs);
    assert_eq!(usage.endpoint, "http://master.local:9333");
    assert_eq!(usage.filer_endpoint, "https://filer.local:8888");
    assert_eq!(usage.token, "");
}

/// The endpoint of the MinIO source is the endpoint of the auth block, unless the block sets it.
#[test]
fn usage_of_minio() {
    let (result, _dir) = load_usage(&usage_config_text(&usage_block("    source = \"minio\""), ""));
    let usage = result.unwrap().auths[0].usage.clone().unwrap();
    assert_eq!(usage.source, UsageSource::MinIo);
    assert_eq!(usage.endpoint, "http://minio.local:9000");
    let (result, _dir) = load_usage(&usage_config_text(
        &usage_block("\n    source   = \"minio\"\n    endpoint = \"https://console.local:9001\""),
        "",
    ));
    assert_eq!(
        result.unwrap().auths[0].usage.clone().unwrap().endpoint,
        "https://console.local:9001"
    );
}

#[test]
fn no_block_means_no_usage() {
    let (result, _dir) = load_usage(&usage_config_text(USAGE_AUTH_LINES, ""));
    let config = result.unwrap();
    assert!(config.auths[0].usage.is_none());
    assert!(!format_effective(&config).contains(".usage."));
}

/// Each error stops the start. The message names the key and the value. A secret never shows.
#[test]
fn usage_errors() {
    let garage = "    source = \"garage\"\n    endpoint = \"http://garage.local:3903\"\n    token_file = \"./token\"\n";
    let gcs = "\n  provider = \"gcs\"\n  mode = \"service_account\"\n  credentials_file = \"./gcs.json\"\n  usage {\n    source = \"garage\"\n    endpoint = \"http://g:3903\"\n    token_file = \"./token\"\n  }\n";
    let anonymous = "\n  provider = \"s3\"\n  mode = \"anonymous\"\n  endpoint = \"http://minio.local:9000\"\n  region = \"test\"\n  usage {\n    source = \"minio\"\n  }\n";
    let block = |lines: &str| usage_config_text(&usage_block(lines), "");
    let with_bucket = |bucket: &str| usage_config_text(&usage_block(garage), bucket);
    let cases: Vec<(&str, String, Vec<&str>, &str)> = vec![
        (
            "missing source",
            block("    endpoint = \"http://g:3903\""),
            vec![
                "auth \"x\".usage.source is required",
                "\"garage\"",
                "\"seaweedfs\"",
                "\"minio\"",
            ],
            "",
        ),
        (
            "unknown source",
            block("    source = \"ceph\""),
            vec!["auth \"x\".usage.source must be", "got \"ceph\""],
            "",
        ),
        (
            "upper-case source",
            block("    source = \"Garage\""),
            vec!["auth \"x\".usage.source must be", "lower case", "got \"Garage\""],
            "",
        ),
        (
            "source with a space",
            block("    source = \"garage \""),
            vec!["auth \"x\".usage.source"],
            "",
        ),
        (
            "unknown attribute",
            block(&format!("{garage}    timeout = \"5s\"")),
            vec!["unknown attribute \"timeout\" in usage block"],
            "",
        ),
        (
            "duplicate attribute",
            block(&format!("{garage}    endpoint = \"http://other:3903\"")),
            vec!["endpoint"],
            "",
        ),
        (
            "duplicate usage block",
            usage_config_text(
                &format!("{}  usage {{\n    source = \"minio\"\n  }}\n", usage_block(garage)),
                "",
            ),
            vec!["only one usage block is allowed in auth \"x\""],
            "",
        ),
        (
            "unknown nested block",
            usage_config_text(&format!("{USAGE_AUTH_LINES}  other {{\n    a = \"b\"\n  }}\n"), ""),
            vec!["unknown block \"other\" in auth; the only block is usage"],
            "",
        ),
        (
            "nested block in usage",
            block(&format!("{garage}    sub {{\n      a = \"b\"\n    }}")),
            vec!["nested blocks are not supported inside auth \"x\".usage"],
            "",
        ),
        (
            "label on usage",
            usage_config_text(
                &format!("{USAGE_AUTH_LINES}  usage \"y\" {{\n    source = \"minio\"\n  }}\n"),
                "",
            ),
            vec!["auth \"x\".usage block does not accept labels"],
            "",
        ),
        (
            "token in clear text",
            block("    source = \"garage\"\n    endpoint = \"http://g:3903\"\n    token = \"x-clear-token\""),
            vec!["auth \"x\".usage.token is a secret", "token_env", "token_file"],
            "x-clear-token",
        ),
        (
            "token env variable is missing",
            block(
                "    source = \"garage\"\n    endpoint = \"http://g:3903\"\n    token_env = \"USAGE_TEST_NO_SUCH_VARIABLE\"",
            ),
            vec!["token", "USAGE_TEST_NO_SUCH_VARIABLE"],
            "",
        ),
        (
            "token file is missing",
            block("    source = \"garage\"\n    endpoint = \"http://g:3903\"\n    token_file = \"./no-such-file\""),
            vec!["token", "no-such-file"],
            "",
        ),
        (
            "two token forms",
            block(&format!("{garage}    token_env = \"X\"")),
            vec!["token"],
            "admin-token-value",
        ),
        (
            "garage without token",
            block("    source = \"garage\"\n    endpoint = \"http://g:3903\""),
            vec![
                "auth \"x\".usage.token is required with source \"garage\"",
                "token_env",
                "token_file",
            ],
            "",
        ),
        (
            "garage without endpoint",
            block("    source = \"garage\"\n    token_file = \"./token\""),
            vec!["auth \"x\".usage.endpoint is required with source \"garage\""],
            "",
        ),
        (
            "garage with filer",
            block(&format!("{garage}    filer_endpoint = \"http://f:8888\"")),
            vec!["auth \"x\".usage.filer_endpoint is only for source \"seaweedfs\""],
            "",
        ),
        (
            "seaweedfs without endpoint",
            block("    source = \"seaweedfs\"\n    filer_endpoint = \"http://f:8888\""),
            vec!["auth \"x\".usage.endpoint is required with source \"seaweedfs\""],
            "",
        ),
        (
            "seaweedfs without filer",
            block("    source = \"seaweedfs\"\n    endpoint = \"http://m:9333\""),
            vec!["auth \"x\".usage.filer_endpoint is required with source \"seaweedfs\""],
            "",
        ),
        (
            "seaweedfs with token",
            block(
                "    source = \"seaweedfs\"\n    endpoint = \"http://m:9333\"\n    filer_endpoint = \"http://f:8888\"\n    token_file = \"./token\"",
            ),
            vec!["auth \"x\".usage.token is only for source \"garage\""],
            "admin-token-value",
        ),
        (
            "minio with token",
            block("    source = \"minio\"\n    token_file = \"./token\""),
            vec!["auth \"x\".usage.token is only for source \"garage\""],
            "admin-token-value",
        ),
        (
            "minio with filer",
            block("    source = \"minio\"\n    filer_endpoint = \"http://f:8888\""),
            vec!["auth \"x\".usage.filer_endpoint is only for source \"seaweedfs\""],
            "",
        ),
        (
            "minio with anonymous mode",
            usage_config_text(anonymous, ""),
            vec![
                "source \"minio\" needs auth \"x\" with mode \"access_key\"",
                "got mode \"anonymous\"",
            ],
            "",
        ),
        (
            "usage on a gcs auth",
            usage_config_text(gcs, ""),
            vec!["a usage block needs provider \"s3\"", "auth \"x\" has provider \"gcs\""],
            "",
        ),
        (
            "endpoint with a slash at the end",
            block("    source = \"garage\"\n    endpoint = \"http://g:3903/\"\n    token_file = \"./token\""),
            vec![
                "auth \"x\".usage.endpoint",
                "must not end with \"/\"",
                "got \"http://g:3903/\"",
            ],
            "",
        ),
        (
            "endpoint with a query",
            block("    source = \"garage\"\n    endpoint = \"http://g:3903?a=b\"\n    token_file = \"./token\""),
            vec![
                "auth \"x\".usage.endpoint",
                "query string or fragment",
                "got \"http://g:3903?a=b\"",
            ],
            "",
        ),
        (
            "endpoint with a fragment",
            block("    source = \"garage\"\n    endpoint = \"http://g:3903#a\"\n    token_file = \"./token\""),
            vec!["auth \"x\".usage.endpoint", "query string or fragment"],
            "",
        ),
        (
            "endpoint with a user",
            block("    source = \"garage\"\n    endpoint = \"http://user:pass@g:3903\"\n    token_file = \"./token\""),
            vec!["auth \"x\".usage.endpoint", "user information"],
            "pass@",
        ),
        (
            "endpoint with a wrong scheme",
            block("    source = \"garage\"\n    endpoint = \"ftp://g:3903\"\n    token_file = \"./token\""),
            vec!["auth \"x\".usage.endpoint", "http or https"],
            "",
        ),
        (
            "filer endpoint with a slash at the end",
            block(
                "    source = \"seaweedfs\"\n    endpoint = \"http://m:9333\"\n    filer_endpoint = \"http://f:8888/\"",
            ),
            vec!["auth \"x\".usage.filer_endpoint", "must not end with \"/\""],
            "",
        ),
        (
            "wrong type",
            block("    source = \"garage\"\n    endpoint = 3903"),
            vec!["endpoint"],
            "",
        ),
        (
            "quota 0",
            with_bucket("quota_bytes = 0"),
            vec!["bucket \"b\".quota_bytes must be between 1 and 1152921504606846976, got 0"],
            "",
        ),
        (
            "quota negative",
            with_bucket("quota_bytes = -5"),
            vec!["unexpected character '-'"],
            "",
        ),
        (
            "quota too large",
            with_bucket("quota_bytes = 1152921504606846977"),
            vec!["bucket \"b\".quota_bytes must be between 1 and 1152921504606846976"],
            "",
        ),
        (
            "quota is text",
            with_bucket("quota_bytes = \"10\""),
            vec!["quota_bytes"],
            "",
        ),
        (
            "quota without a usage block",
            usage_config_text(USAGE_AUTH_LINES, "quota_bytes = 1000"),
            vec!["bucket \"b\".quota_bytes needs a usage block in auth \"x\""],
            "",
        ),
    ];
    for (name, config, wants, hidden) in cases {
        let dir = usage_dir();
        let result = decode_in(&dir, &format!("{config}{TEST_OPEN_ACCESS}"));
        let error = message(&result);
        assert!(result.is_err(), "{name}: the start must stop");
        for want in wants {
            assert!(error.contains(want), "{name}: error = {error:?}, want {want:?}");
        }
        if !hidden.is_empty() {
            assert!(!error.contains(hidden), "{name}: the error shows the secret: {error}");
        }
    }
}

#[test]
fn quota_bytes() {
    let garage = "    source = \"garage\"\n    endpoint = \"http://g:3903\"\n    token_file = \"./token\"";
    for (name, line, want) in [
        ("smallest", "quota_bytes = 1", 1),
        ("ten GiB", "quota_bytes = 10737418240", 10_737_418_240),
        ("largest", "quota_bytes = 1152921504606846976", 1 << 60),
        ("not in use", "", 0),
    ] {
        let (result, _dir) = load_usage(&usage_config_text(&usage_block(garage), line));
        let config = result.unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(config.buckets[0].quota_bytes, want, "{name}");
    }
}

/// print-config shows the block, the source of each value and the key of the bucket. It hides the token.
#[test]
fn usage_in_print_config() {
    let (result, dir) = load_usage(&usage_config_text(
        &usage_block(
            "\n    source     = \"garage\"\n    endpoint   = \"http://garage.local:3903\"\n    token_file = \"./token\"",
        ),
        "quota_bytes = 1048576",
    ));
    let text = format_effective(&result.unwrap());
    let usage: Vec<&str> = text
        .lines()
        .filter(|line| line.starts_with("auth \"x\".usage."))
        .collect();
    assert_eq!(
        usage,
        vec![
            "auth \"x\".usage.source = \"garage\"  # file".to_owned(),
            "auth \"x\".usage.endpoint = \"http://garage.local:3903\"  # file".to_owned(),
            "auth \"x\".usage.filer_endpoint = <none>  # default".to_owned(),
            format!("auth \"x\".usage.token = <hidden>  # file:{}", dir.join("token")),
        ]
    );
    assert!(text.contains("bucket \"b\".quota_bytes = 1048576  # file"));
    assert!(!text.contains("admin-token-value"));

    // Without the key, the bucket shows the default.
    let (result, _dir) = load_usage(&usage_config_text(&usage_block("    source = \"minio\""), ""));
    let text = format_effective(&result.unwrap());
    for want in [
        "auth \"x\".usage.source = \"minio\"  # file",
        "auth \"x\".usage.endpoint = \"http://minio.local:9000\"  # default",
        "auth \"x\".usage.token = <none>  # default",
        "bucket \"b\".quota_bytes = <none>  # default",
    ] {
        assert!(text.contains(want), "print-config does not show {want:?}:\n{text}");
    }
}

/// The reference documents the keys of the block, and it tells which key takes `_env` and `_file`.
#[test]
fn usage_is_in_the_key_table() {
    let text = reference();
    for want in ["auth.usage", "`source`", "`filer_endpoint`", "`token`", "`quota_bytes`"] {
        assert!(
            text.contains(want),
            "the configuration reference does not contain {want:?}"
        );
    }
    let token = super::keys::KEYS
        .iter()
        .find(|key| key.block == "auth.usage" && key.name == "token")
        .unwrap();
    assert!(token.secret);
    assert_eq!(token.forms, super::keys::FORM_ENV | super::keys::FORM_FILE);
}

/// The folder of the configuration file is not needed when the token comes from a file with an absolute path.
#[test]
fn a_token_file_with_an_absolute_path() {
    let token_dir = TempDir::new();
    token_dir.write("t", "absolute-token\n");
    let (result, _dir) = load_usage(&usage_config_text(
        &usage_block(&format!(
            "\n    source     = \"garage\"\n    endpoint   = \"http://garage.local:3903\"\n    token_file = \"{}\"",
            token_dir.join("t")
        )),
        "",
    ));
    assert_eq!(result.unwrap().auths[0].usage.clone().unwrap().token, "absolute-token");
}

#[test]
fn usage_errors_give_the_line_of_the_usage_block() {
    let dir = usage_dir();
    let text = usage_config_text(&usage_block("    source = \"Garage\""), "");
    assert_eq!(
        message(&decode_in(&dir, &format!("{text}{TEST_OPEN_ACCESS}"))),
        "line 8:3: auth \"x\".usage.source must be \"garage\", \"seaweedfs\" or \"minio\" (lower case), got \"Garage\""
    );
    let text = usage_config_text(
        &usage_block(
            "    source = \"garage\"\n    endpoint = \"http://user:pass@g:3903\"\n    token_file = \"./token\"",
        ),
        "",
    );
    assert_eq!(
        message(&decode_in(&dir, &format!("{text}{TEST_OPEN_ACCESS}"))),
        "line 8:3: auth \"x\".usage.endpoint: usage endpoint must not contain user information"
    );
}
