// SPDX-License-Identifier: MIT OR Apache-2.0
//! The configuration files of real deployments and a file with each kind of key parse. For each of them, print-config
//! gives the text of the `.print` file next to it. config.example.hcl at the root of the repository parses too. The
//! secrets are test values in a temporary folder.

use super::format_effective;
use super::support_tests::{TempDir, decode_in_with, ed_jwk, key_set, rfc8037_pem, test_hooks, with_environment};

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

/// The text of config.example.hcl with its paths in the temporary folder. The folder also gets the files that the
/// text names. `/run/keys/` and `/run/secrets/` become `<dir>/keys/` and `<dir>/secrets/`. With `volume`, the
/// commented volume block is active, and `/data/shared` becomes `<dir>/shared`.
fn example_in(dir: &TempDir, volume: bool) -> String {
    dir.mkdir("keys");
    dir.mkdir("secrets");
    dir.write("keys/edge-jwks.json", key_set(&[ed_jwk(",\"kid\":\"edge-1\"")]));
    dir.write("secrets/pdp-token", "dummy-pdp-token-0123456789\n");
    dir.write("secrets/s3-access-key-id", "dummy-access-key\n");
    dir.write("secrets/s3-secret-access-key", "dummy-secret-key\n");
    dir.write("secrets/gcs-service-account.json", "{\"type\":\"service_account\"}");
    let mut text = include_str!("../../config.example.hcl").replace("/run/keys/", "@DIR@/keys/");
    if volume {
        dir.mkdir("shared/published");
        let start = text.find("# volume \"shared\" {").unwrap();
        let block: String = text[start..]
            .lines()
            .map(|line| line.strip_prefix("# ").unwrap_or(line))
            .map(|line| format!("{line}\n"))
            .collect();
        text = format!("{}{}", &text[..start], block.replace("/data/shared", "@DIR@/shared"));
    }
    localize(&text, dir)
}

/// config.example.hcl at the root of the repository is a valid configuration. It names its files with `_file`.
/// Print-config does not show the secrets of these files.
#[test]
fn the_example_configuration_parses() {
    let dir = TempDir::new();
    let config = decode_in_with(&dir, &example_in(&dir, false), &test_hooks()).unwrap();
    assert!(config.access.enforced());
    let identity = config.access.identity.clone().unwrap();
    assert_eq!(identity.key_names, vec!["Ed25519 kid=edge-1"]);
    assert_eq!(config.access.pdp.clone().unwrap().token, "dummy-pdp-token-0123456789");
    assert_eq!(config.auths.len(), 2);
    assert_eq!(config.auths[0].access_key_id, "dummy-access-key");
    assert_eq!(config.auths[0].secret_access_key, "dummy-secret-key");
    assert!(config.auths[0].usage.is_none());
    let ids: Vec<&str> = config.buckets.iter().map(|bucket| bucket.id.as_str()).collect();
    assert_eq!(ids, vec!["documents", "archive", "gcs-backups"]);
    assert!(config.volumes.is_empty());
    let printed = format_effective(&config);
    assert!(!printed.contains("dummy-secret-key") && !printed.contains("dummy-pdp-token"));
}

/// The commented volume block of config.example.hcl is valid too.
#[test]
fn the_volume_block_of_the_example_configuration_parses() {
    let dir = TempDir::new();
    let config = decode_in_with(&dir, &example_in(&dir, true), &test_hooks()).unwrap();
    assert_eq!(config.volumes.len(), 1);
    let volume = &config.volumes[0];
    assert_eq!((volume.id.as_str(), volume.name.as_str()), ("shared", "Shared files"));
    assert_eq!(volume.path, dir.path().join("shared"));
    assert_eq!(volume.root_prefix, "published/");
    assert_eq!(volume.max_scan_pages, 15);
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
