// SPDX-License-Identifier: MIT OR Apache-2.0
//! The configuration files of real deployments, and a file with each kind of key: they parse, and print-config gives
//! the text of the `.print` file next to them. The secrets are test values in a temporary folder.

use super::format_effective;
use super::support_tests::{TempDir, decode_in_with, rfc8037_pem, test_hooks, with_environment};

/// The secret files of the deployment fixtures, with test values.
fn write_secrets(dir: &TempDir) {
    dir.mkdir("secrets");
    dir.write("secrets/storage_s3_access_key", "dummy-access-key\n");
    dir.write("secrets/storage_s3_secret_key", "dummy-secret-key\n");
    dir.write("secrets/stowr_pdp_token", "dummy-pdp-token-0123456789\n");
    dir.write("secrets/stowr_identity_keys", rfc8037_pem());
}

/// The text of a fixture with its paths in the temporary folder: `/run/secrets/` becomes `<dir>/secrets/`, and
/// `@DIR@` becomes `<dir>`.
fn localize(text: &str, dir: &TempDir) -> String {
    text.replace("/run/secrets/", "@DIR@/secrets/")
        .replace("@DIR@", &dir.text())
}

fn check_fixture(config: &str, expected: &str) {
    let dir = TempDir::new();
    write_secrets(&dir);
    let config = decode_in_with(&dir, &localize(config, &dir), &test_hooks()).unwrap();
    assert_eq!(format_effective(&config), localize(expected, &dir));
}

#[test]
fn the_compose_deployment_prints_as_expected() {
    check_fixture(
        include_str!("fixtures/compose.hcl"),
        include_str!("fixtures/compose.print"),
    );
}

#[test]
fn the_cluster_deployment_prints_as_expected() {
    check_fixture(
        include_str!("fixtures/kubernetes.hcl"),
        include_str!("fixtures/kubernetes.print"),
    );
}

#[test]
fn a_file_with_each_kind_of_key_prints_as_expected() {
    let variables = [
        ("FIXTURE_ACCESS_KEY", "AKIA-FIXTURE"),
        ("FIXTURE_SESSION_TOKEN", "session-token-value"),
        ("FIXTURE_GARAGE_SECRET", "garage-secret-value"),
    ];
    with_environment(&variables, |hooks| {
        let dir = TempDir::new();
        dir.mkdir("secrets");
        dir.mkdir("volume/shared");
        dir.write("secrets/s3-secret", "s3-secret-value\n");
        dir.write("secrets/garage-token", "garage-token-value\n");
        let text = localize(include_str!("fixtures/full.hcl"), &dir);
        let config = decode_in_with(&dir, &text, hooks).unwrap();
        let printed = format_effective(&config);
        assert_eq!(printed, localize(include_str!("fixtures/full.print"), &dir));
        for secret in [
            "s3-secret-value",
            "garage-token-value",
            "session-token-value",
            "garage-secret-value",
        ] {
            assert!(!printed.contains(secret));
        }
        let storage = &config.auths[0];
        assert_eq!(storage.access_key_id, "AKIA-FIXTURE");
        assert_eq!(storage.secret_access_key, "s3-secret-value");
        assert_eq!(storage.session_token, "session-token-value");
        assert_eq!(
            config.auths[1].usage.as_ref().map(|usage| usage.token.as_str()),
            Some("garage-token-value")
        );
        assert_eq!(config.buckets[0].name, "Documents \"main\"\u{a0}é\t日本");
        assert!(config.runtime.force_read_only());
        assert_eq!(config.volumes[1].id, "-");
    });
}
