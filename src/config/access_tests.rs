//! The tests of the `access` block: the values and the defaults, the refusals, the secrets, the environment, the
//! limits of the resources, print-config and the warnings.

use std::time::Duration;

use crate::common::config::{AccessConfig, AccessPolicy, Config, IdentityConfig, PdpConfig};

use super::support_tests::{
    RFC8037_THUMBPRINT, TempDir, decode_in, decode_in_with, ec_jwk, ed_jwk, key_set, load_in, message,
    minimal_test_config, rfc7515_pem, rfc7515_thumbprint, rfc8037_pem, with_environment,
};
use super::{format_effective, reference, warnings};

const TEST_PDP_TOKEN: &str = "pdp-test-token-0123456789abcdef0123456789";

const ACCESS_TEST_STORAGE: &str = "
auth \"public\" {
  provider = \"s3\"
  mode     = \"anonymous\"
  endpoint = \"http://localhost:9000\"
  region   = \"test\"
}

bucket \"logs\" {
  auth   = \"public\"
  bucket = \"logs\"
}
";

const GOOD_IDENTITY: &str = "
    issuer           = \"https://edge.example\"
    audience         = \"infra-s3\"
    public_keys_file = \"jwks.json\"
";

const GOOD_PDP: &str = "
    url        = \"https://pdp.example:4182\"
    token_file = \"pdp-token\"
";

/// An access block with mode `authzen`. `identity` and `pdp` are the bodies of the two blocks.
fn authzen_text(identity: &str, pdp: &str) -> String {
    format!("access {{\n  mode = \"authzen\"\n  identity {{{identity}\n  }}\n  pdp {{{pdp}\n  }}\n}}\n")
}

/// A folder with the key set and the token file of the tests, and more files.
fn access_dir(files: &[(&str, &str)]) -> TempDir {
    let dir = TempDir::new();
    dir.write(
        "jwks.json",
        key_set(&[ed_jwk(",\"kid\":\"edge-1\""), ec_jwk(",\"kid\":\"edge-2\"")]),
    );
    dir.write("pdp-token", format!("{TEST_PDP_TOKEN}\n"));
    for (name, content) in files {
        dir.write(name, content);
    }
    dir
}

/// Decode the storage blocks of the tests with the text, in a folder with the key set and the token file.
fn decode_access(text: &str, files: &[(&str, &str)]) -> (Result<Config, crate::common::error::Error>, TempDir) {
    let dir = access_dir(files);
    let result = decode_in(&dir, &format!("{ACCESS_TEST_STORAGE}{text}"));
    (result, dir)
}

fn identity_of(config: &Config) -> IdentityConfig {
    config.access.identity.clone().unwrap()
}

fn pdp_of(config: &Config) -> PdpConfig {
    config.access.pdp.clone().unwrap()
}

#[test]
fn authzen_values_and_defaults() {
    let (result, _dir) = decode_access(&authzen_text(GOOD_IDENTITY, GOOD_PDP), &[]);
    let config = result.unwrap();
    assert!(config.access.enforced());
    assert_eq!(config.access.mode, AccessPolicy::AuthZen);
    let identity = identity_of(&config);
    assert_eq!(identity.header, "X-Identity-Token");
    assert_eq!(identity.issuer, "https://edge.example");
    assert_eq!(identity.audience, "infra-s3");
    assert_eq!(config.access.audience(), "infra-s3");
    assert_eq!(identity.key_names, vec!["Ed25519 kid=edge-1", "P-256 kid=edge-2"]);
    assert_eq!(identity.max_age, Duration::from_secs(300));
    assert_eq!(identity.clock_skew, Duration::from_secs(60));
    let pdp = pdp_of(&config);
    assert_eq!(pdp.url, "https://pdp.example:4182");
    assert!(!pdp.plain_http);
    assert_eq!(pdp.token, TEST_PDP_TOKEN);
    assert_eq!(pdp.timeout, Duration::from_millis(500));
    assert_eq!(pdp.usage_timeout, Duration::from_secs(6));
    assert_eq!(pdp.cache_ttl, Duration::from_secs(30));
    assert_eq!(pdp.max_evaluations, 64);
    assert!(!format!("{pdp:?}").contains(TEST_PDP_TOKEN));
}

#[test]
fn authzen_explicit_values() {
    let identity = format!(
        "{GOOD_IDENTITY}\n    header     = \"X-Edge-Token\"\n    max_age    = \"1h\"\n    clock_skew = \"2m\"\n"
    );
    let pdp = "
    url             = \"http://pdp.internal:4182/base\"
    plain_http      = true
    token_file      = \"pdp-token\"
    timeout         = \"1s\"
    usage_timeout   = \"1m\"
    cache_ttl       = \"0s\"
    max_evaluations = 1024
";
    let (result, _dir) = decode_access(&authzen_text(&identity, pdp), &[]);
    let config = result.unwrap();
    let identity = identity_of(&config);
    assert_eq!(identity.header, "X-Edge-Token");
    assert_eq!(identity.max_age, Duration::from_secs(3600));
    assert_eq!(identity.clock_skew, Duration::from_secs(120));
    let pdp = pdp_of(&config);
    assert_eq!(pdp.url, "http://pdp.internal:4182/base");
    assert!(pdp.plain_http);
    assert_eq!(pdp.timeout, Duration::from_secs(1));
    assert_eq!(pdp.usage_timeout, Duration::from_secs(60));
    assert_eq!(pdp.cache_ttl, Duration::ZERO);
    assert_eq!(pdp.max_evaluations, 1024);
}

#[test]
fn volumes_follow_no_link_with_mode_authzen() {
    let folder = TempDir::new();
    let text = format!(
        "{}volume \"v\" {{\n  path = \"{}\"\n}}\n",
        authzen_text(GOOD_IDENTITY, GOOD_PDP),
        folder.text()
    );
    let (result, _dir) = decode_access(&text, &[]);
    let config = result.unwrap();
    assert!(config.volumes[0].refuse_links);
}

#[test]
fn bounds_are_accepted() {
    let cases = [
        (
            "lower bounds",
            format!("{GOOD_IDENTITY}max_age = \"1s\"\nclock_skew = \"0s\"\nheader = \"A\""),
            format!("{GOOD_PDP}timeout = \"10ms\"\nusage_timeout = \"100ms\"\ncache_ttl = \"0s\"\nmax_evaluations = 1"),
        ),
        (
            "upper bounds",
            format!("{GOOD_IDENTITY}max_age = \"24h\"\nclock_skew = \"5m\""),
            format!("{GOOD_PDP}timeout = \"1m\"\nusage_timeout = \"1m\"\ncache_ttl = \"1h\""),
        ),
        (
            "clock_skew in whole seconds with ms",
            format!("{GOOD_IDENTITY}clock_skew = \"2000ms\""),
            GOOD_PDP.to_owned(),
        ),
        (
            "usage_timeout equal to timeout",
            GOOD_IDENTITY.to_owned(),
            format!("{GOOD_PDP}timeout = \"2s\""),
        ),
    ];
    for (name, identity, pdp) in cases {
        let (result, _dir) = decode_access(&authzen_text(&identity, &pdp), &[]);
        assert!(result.is_ok(), "{name}: {}", message(&result));
    }
}

#[test]
fn open_mode() {
    let (result, _dir) = decode_access("access {\n  mode = \"open\"\n}\n", &[]);
    let config = result.unwrap();
    assert!(!config.access.enforced());
    assert_eq!(config.access.mode, AccessPolicy::Open);
    assert!(config.access.identity.is_none() && config.access.pdp.is_none());
    assert_eq!(config.access.audience(), "");
}

#[test]
fn refusals() {
    let ident = |old: &str, new: &str| GOOD_IDENTITY.replacen(old, new, 1);
    let pdp_with = |old: &str, new: &str| GOOD_PDP.replacen(old, new, 1);
    let long = |count: usize| "a".repeat(count);
    let with_identity = |extra: &str| authzen_text(&format!("{GOOD_IDENTITY}{extra}"), GOOD_PDP);
    let with_pdp = |extra: &str| authzen_text(GOOD_IDENTITY, &format!("{GOOD_PDP}{extra}"));
    let cases: Vec<(&str, String, String)> = vec![
        // The blocks.
        (
            "no access block",
            String::new(),
            "the access block is required".to_owned(),
        ),
        (
            "two access blocks",
            "access { mode = \"open\" }\naccess { mode = \"open\" }\n".to_owned(),
            "only one access block is allowed".to_owned(),
        ),
        (
            "access with a label",
            "access \"x\" { mode = \"open\" }\n".to_owned(),
            "access block does not accept labels".to_owned(),
        ),
        (
            "no mode",
            "access {\n}\n".to_owned(),
            "access.mode is required".to_owned(),
        ),
        (
            "mode AuthZEN",
            "access { mode = \"AuthZEN\" }\n".to_owned(),
            "access.mode must be \"authzen\" or \"open\" (lower case), got \"AuthZEN\"".to_owned(),
        ),
        (
            "mode none",
            "access { mode = \"none\" }\n".to_owned(),
            "got \"none\"".to_owned(),
        ),
        (
            "mode empty",
            "access { mode = \"\" }\n".to_owned(),
            "got \"\"".to_owned(),
        ),
        (
            "mode is a number",
            "access { mode = 1 }\n".to_owned(),
            "attribute \"mode\" must be a quoted string".to_owned(),
        ),
        (
            "unknown attribute",
            "access {\n  mode = \"open\"\n  modes = \"x\"\n}\n".to_owned(),
            "unknown attribute \"modes\" in access block".to_owned(),
        ),
        (
            "unknown nested block",
            "access {\n  mode = \"open\"\n  policy {}\n}\n".to_owned(),
            "unknown block \"policy\" in access".to_owned(),
        ),
        (
            "two identity blocks",
            "access {\n  mode = \"authzen\"\n  identity {}\n  identity {}\n}\n".to_owned(),
            "only one access.identity block is allowed".to_owned(),
        ),
        (
            "two pdp blocks",
            "access {\n  mode = \"authzen\"\n  pdp {}\n  pdp {}\n}\n".to_owned(),
            "only one access.pdp block is allowed".to_owned(),
        ),
        (
            "identity with label",
            "access {\n  mode = \"authzen\"\n  identity \"x\" {}\n}\n".to_owned(),
            "access.identity block does not accept labels".to_owned(),
        ),
        (
            "pdp with label",
            "access {\n  mode = \"authzen\"\n  pdp \"x\" {}\n}\n".to_owned(),
            "access.pdp block does not accept labels".to_owned(),
        ),
        (
            "block inside identity",
            with_identity("\n    keys {}"),
            "nested blocks are not supported inside access.identity".to_owned(),
        ),
        (
            "block inside pdp",
            with_pdp("\n    cache {}"),
            "nested blocks are not supported inside access.pdp".to_owned(),
        ),
        (
            "unknown identity attribute",
            with_identity("\n    leeway = \"1s\""),
            "unknown attribute \"leeway\" in identity block".to_owned(),
        ),
        (
            "unknown pdp attribute",
            with_pdp("\n    retries = 3"),
            "unknown attribute \"retries\" in pdp block".to_owned(),
        ),
        // The contradictions between the mode and the blocks.
        (
            "open with identity",
            format!("access {{\n  mode = \"open\"\n  identity {{{GOOD_IDENTITY}}}\n}}\n"),
            "access.mode = \"open\" contradicts the access.identity block".to_owned(),
        ),
        (
            "open with pdp",
            format!("access {{\n  mode = \"open\"\n  pdp {{{GOOD_PDP}}}\n}}\n"),
            "access.mode = \"open\" contradicts the access.pdp block".to_owned(),
        ),
        (
            "authzen no blocks",
            "access { mode = \"authzen\" }\n".to_owned(),
            "access.mode = \"authzen\" needs the access.identity block".to_owned(),
        ),
        (
            "authzen no pdp",
            format!("access {{\n  mode = \"authzen\"\n  identity {{{GOOD_IDENTITY}}}\n}}\n"),
            "access.mode = \"authzen\" needs the access.pdp block".to_owned(),
        ),
        (
            "authzen no identity",
            format!("access {{\n  mode = \"authzen\"\n  pdp {{{GOOD_PDP}}}\n}}\n"),
            "access.mode = \"authzen\" needs the access.identity block".to_owned(),
        ),
        // access.identity.
        (
            "header Cookie",
            with_identity("\n    header = \"Cookie\""),
            "access.identity.header: must not be Cookie, Authorization".to_owned(),
        ),
        (
            "header authorization",
            with_identity("\n    header = \"authorization\""),
            "got \"authorization\"".to_owned(),
        ),
        (
            "header Host",
            with_identity("\n    header = \"HOST\""),
            "access.identity.header".to_owned(),
        ),
        (
            "header Content-Type",
            with_identity("\n    header = \"content-type\""),
            "access.identity.header".to_owned(),
        ),
        (
            "header Content-Length",
            with_identity("\n    header = \"Content-Length\""),
            "access.identity.header".to_owned(),
        ),
        (
            "header with underscore",
            with_identity("\n    header = \"X_Identity\""),
            "must have only letters, digits".to_owned(),
        ),
        (
            "header with a space",
            with_identity("\n    header = \"X Identity\""),
            "must have only letters, digits".to_owned(),
        ),
        (
            "header empty",
            with_identity("\n    header = \"\""),
            "must have 1 to 64 characters".to_owned(),
        ),
        (
            "header 65 characters",
            with_identity(&format!("\n    header = \"{}\"", long(65))),
            "must have 1 to 64 characters".to_owned(),
        ),
        (
            "no issuer",
            authzen_text(&ident("issuer           = \"https://edge.example\"", ""), GOOD_PDP),
            "access.identity.issuer is required".to_owned(),
        ),
        (
            "issuer empty",
            authzen_text(&ident("\"https://edge.example\"", "\"\""), GOOD_PDP),
            "access.identity.issuer must have 1 to 1024 bytes".to_owned(),
        ),
        (
            "issuer 1025 bytes",
            authzen_text(
                &ident("\"https://edge.example\"", &format!("\"{}\"", long(1025))),
                GOOD_PDP,
            ),
            "access.identity.issuer must have 1 to 1024 bytes".to_owned(),
        ),
        (
            "issuer with control",
            authzen_text(&ident("\"https://edge.example\"", "\"edge\\u0001\""), GOOD_PDP),
            "access.identity.issuer must have 1 to 1024 bytes".to_owned(),
        ),
        (
            "no audience",
            authzen_text(&ident("audience         = \"infra-s3\"", ""), GOOD_PDP),
            "access.identity.audience is required".to_owned(),
        ),
        (
            "audience empty",
            authzen_text(&ident("\"infra-s3\"", "\"\""), GOOD_PDP),
            "access.identity.audience must have 1 to 256 bytes".to_owned(),
        ),
        (
            "audience 257 bytes",
            authzen_text(&ident("\"infra-s3\"", &format!("\"{}\"", long(257))), GOOD_PDP),
            "access.identity.audience must have 1 to 256 bytes".to_owned(),
        ),
        (
            "audience with control",
            authzen_text(&ident("\"infra-s3\"", "\"a\\u0007b\""), GOOD_PDP),
            "access.identity.audience must have 1 to 256 bytes".to_owned(),
        ),
        (
            "no public keys",
            authzen_text(&ident("public_keys_file = \"jwks.json\"", ""), GOOD_PDP),
            "access.identity.public_keys is required".to_owned(),
        ),
        (
            "public keys not a key",
            authzen_text(
                &ident("public_keys_file = \"jwks.json\"", "public_keys = \"not a key\""),
                GOOD_PDP,
            ),
            "access.identity.public_keys: line 1 is not -----BEGIN PUBLIC KEY-----".to_owned(),
        ),
        (
            "public keys bad JWK",
            authzen_text(
                &ident("public_keys_file = \"jwks.json\"", "public_keys = \"{\\\"keys\\\":\""),
                GOOD_PDP,
            ),
            "access.identity.public_keys: the JWK Set is not valid JSON".to_owned(),
        ),
        (
            "public keys file",
            authzen_text(&ident("\"jwks.json\"", "\"missing.json\""), GOOD_PDP),
            "public_keys_file: cannot read".to_owned(),
        ),
        (
            "public keys two forms",
            authzen_text(
                &ident(
                    "public_keys_file = \"jwks.json\"",
                    "public_keys_file = \"jwks.json\"\n    public_keys_env = \"X\"",
                ),
                GOOD_PDP,
            ),
            "give only one of public_keys, public_keys_env and public_keys_file".to_owned(),
        ),
        (
            "public keys bad key",
            authzen_text(
                &ident(
                    "public_keys_file = \"jwks.json\"",
                    "public_keys = \"{\\\"keys\\\":[{\\\"kty\\\":\\\"RSA\\\"}]}\"",
                ),
                GOOD_PDP,
            ),
            "access.identity.public_keys: key 1: kty".to_owned(),
        ),
        (
            "issuer is a number",
            authzen_text(&ident("\"https://edge.example\"", "5"), GOOD_PDP),
            "attribute \"issuer\" must be a quoted string".to_owned(),
        ),
        // The durations: the form.
        (
            "max_age 1.5s",
            with_identity("\n    max_age = \"1.5s\""),
            "access.identity.max_age is not a duration".to_owned(),
        ),
        (
            "max_age +5s",
            with_identity("\n    max_age = \"+5s\""),
            "got \"+5s\"".to_owned(),
        ),
        (
            "max_age -5s",
            with_identity("\n    max_age = \"-5s\""),
            "got \"-5s\"".to_owned(),
        ),
        (
            "max_age 1m30s",
            with_identity("\n    max_age = \"1m30s\""),
            "got \"1m30s\"".to_owned(),
        ),
        (
            "max_age no unit",
            with_identity("\n    max_age = \"5\""),
            "got \"5\"".to_owned(),
        ),
        (
            "max_age empty",
            with_identity("\n    max_age = \"\""),
            "got \"\"".to_owned(),
        ),
        (
            "max_age leading 0",
            with_identity("\n    max_age = \"05s\""),
            "got \"05s\"".to_owned(),
        ),
        (
            "max_age with space",
            with_identity("\n    max_age = \"5 s\""),
            "got \"5 s\"".to_owned(),
        ),
        (
            "max_age upper case",
            with_identity("\n    max_age = \"5M\""),
            "got \"5M\"".to_owned(),
        ),
        (
            "max_age day unit",
            with_identity("\n    max_age = \"1d\""),
            "got \"1d\"".to_owned(),
        ),
        (
            "max_age huge",
            with_identity("\n    max_age = \"99999999999999999999s\""),
            "is too large".to_owned(),
        ),
        (
            "max_age overflow",
            with_identity("\n    max_age = \"9223372036854775807h\""),
            "is too large".to_owned(),
        ),
        (
            "max_age a number",
            with_identity("\n    max_age = 300"),
            "attribute \"max_age\" must be a quoted string".to_owned(),
        ),
        // The durations: the ranges.
        (
            "max_age 0s",
            with_identity("\n    max_age = \"0s\""),
            "access.identity.max_age must be from 1s to 24h, got \"0s\"".to_owned(),
        ),
        (
            "max_age 999ms",
            with_identity("\n    max_age = \"999ms\""),
            "access.identity.max_age must be from 1s to 24h".to_owned(),
        ),
        (
            "max_age 25h",
            with_identity("\n    max_age = \"25h\""),
            "access.identity.max_age must be from 1s to 24h, got \"25h\"".to_owned(),
        ),
        (
            "clock_skew 6m",
            with_identity("\n    clock_skew = \"6m\""),
            "access.identity.clock_skew must be from 0s to 5m, got \"6m\"".to_owned(),
        ),
        (
            "clock_skew 1500ms",
            with_identity("\n    clock_skew = \"1500ms\""),
            "access.identity.clock_skew must be a whole number of seconds, got \"1500ms\"".to_owned(),
        ),
        (
            "timeout 9ms",
            with_pdp("\n    timeout = \"9ms\""),
            "access.pdp.timeout must be from 10ms to 1m, got \"9ms\"".to_owned(),
        ),
        (
            "timeout 61s",
            with_pdp("\n    timeout = \"61s\""),
            "access.pdp.timeout must be from 10ms to 1m, got \"61s\"".to_owned(),
        ),
        (
            "timeout 0s",
            with_pdp("\n    timeout = \"0s\""),
            "access.pdp.timeout must be from 10ms to 1m".to_owned(),
        ),
        (
            "usage_timeout 99ms",
            with_pdp("\n    usage_timeout = \"99ms\""),
            "access.pdp.usage_timeout must be from 100ms to 1m, got \"99ms\"".to_owned(),
        ),
        (
            "usage_timeout 61s",
            with_pdp("\n    usage_timeout = \"61s\""),
            "access.pdp.usage_timeout must be from 100ms to 1m, got \"61s\"".to_owned(),
        ),
        (
            "cache_ttl 2h",
            with_pdp("\n    cache_ttl = \"2h\""),
            "access.pdp.cache_ttl must be from 0s to 1h, got \"2h\"".to_owned(),
        ),
        (
            "cache_ttl 1.5s",
            with_pdp("\n    cache_ttl = \"1.5s\""),
            "access.pdp.cache_ttl is not a duration".to_owned(),
        ),
        (
            "max_evaluations 0",
            with_pdp("\n    max_evaluations = 0"),
            "access.pdp.max_evaluations must be between 1 and 1024, got 0".to_owned(),
        ),
        (
            "max_evaluations 1025",
            with_pdp("\n    max_evaluations = 1025"),
            "access.pdp.max_evaluations must be between 1 and 1024, got 1025".to_owned(),
        ),
        (
            "max_evaluations a string",
            with_pdp("\n    max_evaluations = \"64\""),
            "attribute \"max_evaluations\" must be an integer".to_owned(),
        ),
        (
            "plain_http a string",
            with_pdp("\n    plain_http = \"false\""),
            "attribute \"plain_http\" must be a boolean".to_owned(),
        ),
        // access.pdp.url.
        (
            "no url",
            authzen_text(
                GOOD_IDENTITY,
                &pdp_with("url        = \"https://pdp.example:4182\"", ""),
            ),
            "access.pdp.url is required".to_owned(),
        ),
        (
            "url without scheme",
            authzen_text(
                GOOD_IDENTITY,
                &pdp_with("\"https://pdp.example:4182\"", "\"pdp.example:4182\""),
            ),
            "access.pdp.url: must start with http:// or https://".to_owned(),
        ),
        (
            "url ftp",
            authzen_text(
                GOOD_IDENTITY,
                &pdp_with("\"https://pdp.example:4182\"", "\"ftp://pdp.example\""),
            ),
            "must start with http:// or https://".to_owned(),
        ),
        (
            "url upper case HTTP",
            authzen_text(
                GOOD_IDENTITY,
                &pdp_with("\"https://pdp.example:4182\"", "\"HTTPS://pdp.example\""),
            ),
            "must start with http:// or https://".to_owned(),
        ),
        (
            "url no host",
            authzen_text(GOOD_IDENTITY, &pdp_with("\"https://pdp.example:4182\"", "\"https://\"")),
            "must have a host".to_owned(),
        ),
        (
            "url no host, port",
            authzen_text(
                GOOD_IDENTITY,
                &pdp_with("\"https://pdp.example:4182\"", "\"https://:4182\""),
            ),
            "must have a host".to_owned(),
        ),
        (
            "url with user info",
            authzen_text(
                GOOD_IDENTITY,
                &pdp_with(
                    "\"https://pdp.example:4182\"",
                    "\"https://user:secret-pass@pdp.example\"",
                ),
            ),
            "must not have credentials".to_owned(),
        ),
        (
            "url with query",
            authzen_text(
                GOOD_IDENTITY,
                &pdp_with(
                    "\"https://pdp.example:4182\"",
                    "\"https://pdp.example?key=secret-value\"",
                ),
            ),
            "must not have a query".to_owned(),
        ),
        (
            "url with empty query",
            authzen_text(
                GOOD_IDENTITY,
                &pdp_with("\"https://pdp.example:4182\"", "\"https://pdp.example?\""),
            ),
            "must not have a query".to_owned(),
        ),
        (
            "url with fragment",
            authzen_text(
                GOOD_IDENTITY,
                &pdp_with("\"https://pdp.example:4182\"", "\"https://pdp.example#top\""),
            ),
            "must not have a fragment".to_owned(),
        ),
        (
            "url with empty fragment",
            authzen_text(
                GOOD_IDENTITY,
                &pdp_with("\"https://pdp.example:4182\"", "\"https://pdp.example#\""),
            ),
            "must not have a fragment".to_owned(),
        ),
        (
            "url trailing slash",
            authzen_text(
                GOOD_IDENTITY,
                &pdp_with("\"https://pdp.example:4182\"", "\"https://pdp.example:4182/\""),
            ),
            "must not end with \"/\"".to_owned(),
        ),
        (
            "url path trailing slash",
            authzen_text(
                GOOD_IDENTITY,
                &pdp_with("\"https://pdp.example:4182\"", "\"https://pdp.example/base/\""),
            ),
            "must not end with \"/\"".to_owned(),
        ),
        (
            "url with a bad port",
            authzen_text(
                GOOD_IDENTITY,
                &pdp_with("\"https://pdp.example:4182\"", "\"https://pdp.example:port\""),
            ),
            "is not a valid URL".to_owned(),
        ),
        (
            "url file missing",
            authzen_text(
                GOOD_IDENTITY,
                &pdp_with("url        = \"https://pdp.example:4182\"", "url_file = \"no-url\""),
            ),
            "url_file: cannot read".to_owned(),
        ),
        // access.pdp.plain_http.
        (
            "http url, plain_http false",
            authzen_text(
                GOOD_IDENTITY,
                &pdp_with("\"https://pdp.example:4182\"", "\"http://pdp.example:4182\""),
            ),
            "access.pdp.url is an http URL, but access.pdp.plain_http = false".to_owned(),
        ),
        (
            "http url, plain_http set false",
            authzen_text(
                GOOD_IDENTITY,
                &format!(
                    "{}\n    plain_http = false",
                    pdp_with("\"https://pdp.example:4182\"", "\"http://pdp.example:4182\"")
                ),
            ),
            "plain_http = false".to_owned(),
        ),
        (
            "https url, plain_http true",
            with_pdp("\n    plain_http = true"),
            "access.pdp.url is an https URL, but access.pdp.plain_http = true".to_owned(),
        ),
        // access.pdp.token.
        (
            "clear text token",
            authzen_text(
                GOOD_IDENTITY,
                &pdp_with("token_file = \"pdp-token\"", "token = \"clear-text-token-value\""),
            ),
            "access.pdp.token is a secret: use token_env or token_file".to_owned(),
        ),
        (
            "no token",
            authzen_text(GOOD_IDENTITY, &pdp_with("token_file = \"pdp-token\"", "")),
            "access.pdp.token is required".to_owned(),
        ),
        (
            "token two forms",
            with_pdp("\n    token_env = \"X\""),
            "give only one of token, token_env and token_file".to_owned(),
        ),
        (
            "token file missing",
            authzen_text(GOOD_IDENTITY, &pdp_with("\"pdp-token\"", "\"no-token\"")),
            "token_file: cannot read".to_owned(),
        ),
        (
            "token env missing",
            authzen_text(
                GOOD_IDENTITY,
                &pdp_with(
                    "token_file = \"pdp-token\"",
                    "token_env = \"STOWR_TEST_NO_SUCH_VARIABLE\"",
                ),
            ),
            "the environment variable \"STOWR_TEST_NO_SUCH_VARIABLE\" does not exist".to_owned(),
        ),
        (
            "token_file is a number",
            authzen_text(GOOD_IDENTITY, &pdp_with("\"pdp-token\"", "5")),
            "attribute \"token_file\" must be a quoted string".to_owned(),
        ),
        // The resources of the service.
        (
            "label of 257 bytes",
            format!(
                "access {{\n  mode = \"authzen\"\n  identity {{{GOOD_IDENTITY}}}\n  pdp {{{GOOD_PDP}}}\n}}\nbucket \"{}\" {{\n  auth = \"public\"\n  bucket = \"b\"\n}}\n",
                long(257)
            ),
            "access.mode = \"authzen\" contradicts the bucket or volume label".to_owned(),
        ),
    ];
    for (name, text, want) in cases {
        let (result, _dir) = decode_access(&text, &[]);
        let error = message(&result);
        assert!(result.is_err(), "{name}: the start goes on");
        assert!(
            error.contains(&want),
            "{name}: error {error:?} does not contain {want:?}"
        );
        for secret in [TEST_PDP_TOKEN, "clear-text-token-value", "secret-pass", "secret-value"] {
            assert!(!error.contains(secret), "{name}: the error shows a secret: {error:?}");
        }
    }
}

#[test]
fn a_token_with_a_space_never_appears_in_the_error() {
    let cases = [
        ("space", "zzqx1 zzqx2\n".to_owned()),
        ("tab", "zzqx1\tzzqx2\n".to_owned()),
        ("line end", "zzqx1\nzzqx2\n".to_owned()),
        ("control", "zzqx1\u{1}zzqx2\n".to_owned()),
        ("DEL", "zzqx1\u{7f}zzqx2\n".to_owned()),
        ("4097 bytes", format!("{}\n", "zzqx".repeat(1025))),
        ("only a space", " \n".to_owned()),
    ];
    for (name, content) in cases {
        let (result, _dir) = decode_access(
            &authzen_text(GOOD_IDENTITY, &GOOD_PDP.replacen("\"pdp-token\"", "\"bad-token\"", 1)),
            &[("bad-token", &content)],
        );
        let error = message(&result);
        assert!(
            error.contains("access.pdp.token must have 1 to 4096 bytes without a space or a control character"),
            "{name}: {error}"
        );
        assert!(
            !error.contains("zzqx"),
            "{name}: the error shows a part of the token: {error}"
        );
    }
}

#[test]
fn a_token_file_loses_only_its_last_line_end() {
    let long = "a".repeat(4096);
    for (name, content, want) in [
        ("line end", "abc\n", "abc"),
        ("CRLF", "abc\r\n", "abc"),
        ("no line end", "abc", "abc"),
        ("4096 bytes", long.as_str(), long.as_str()),
    ] {
        let (result, _dir) = decode_access(
            &authzen_text(GOOD_IDENTITY, &GOOD_PDP.replacen("\"pdp-token\"", "\"other-token\"", 1)),
            &[("other-token", content)],
        );
        let config = result.unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!(pdp_of(&config).token, want, "{name}");
    }
}

#[test]
fn contradictions_name_both_keys() {
    let cases = [
        (
            "usage_timeout below an explicit timeout",
            format!("{GOOD_PDP}\n    timeout = \"500ms\"\n    usage_timeout = \"400ms\""),
            vec!["access.pdp.usage_timeout = \"400ms\"", "access.pdp.timeout = \"500ms\""],
        ),
        (
            "timeout above the default usage_timeout",
            format!("{GOOD_PDP}\n    timeout = \"10s\""),
            vec!["access.pdp.usage_timeout = \"6s\"", "access.pdp.timeout = \"10s\""],
        ),
        (
            "http url without plain_http",
            GOOD_PDP.replacen("https://", "http://", 1),
            vec!["access.pdp.url is an http URL", "access.pdp.plain_http = false"],
        ),
        (
            "https url with plain_http",
            format!("{GOOD_PDP}\n    plain_http = true"),
            vec!["access.pdp.url is an https URL", "access.pdp.plain_http = true"],
        ),
    ];
    for (name, pdp, wants) in cases {
        let (result, _dir) = decode_access(&authzen_text(GOOD_IDENTITY, &pdp), &[]);
        let error = message(&result);
        for want in wants {
            assert!(error.contains(want), "{name}: error {error:?} does not name {want:?}");
        }
    }
}

/// `count` bucket blocks with the labels of `label`.
fn bucket_blocks(count: usize, label: impl Fn(usize) -> String) -> String {
    (0..count)
        .map(|index| {
            format!(
                "bucket \"{}\" {{\n  auth = \"public\"\n  bucket = \"b{index}\"\n}}\n",
                label(index)
            )
        })
        .collect()
}

#[test]
fn limits_of_the_resources() {
    let storage = "auth \"public\" {\n  provider = \"s3\"\n  mode = \"anonymous\"\n  endpoint = \"http://localhost:9000\"\n  region = \"test\"\n}\n";
    let authzen = authzen_text(GOOD_IDENTITY, GOOD_PDP);
    let decode = |access: &str, blocks: &str| {
        let dir = TempDir::new();
        dir.write("jwks.json", key_set(&[ed_jwk("")]));
        dir.write("pdp-token", TEST_PDP_TOKEN);
        message(&decode_in(&dir, &format!("{access}{storage}{blocks}")))
    };
    let number = |index: usize| format!("bucket-{index:03}");
    assert_eq!(decode(&authzen, &bucket_blocks(256, number)), "");
    let error = decode(&authzen, &bucket_blocks(257, number));
    assert!(
        error.contains("access.mode = \"authzen\"") && error.contains("(257)"),
        "{error}"
    );
    assert_eq!(decode(&authzen, &bucket_blocks(1, |_| "a".repeat(256))), "");
    let error = decode(&authzen, &bucket_blocks(1, |_| "a".repeat(257)));
    assert_eq!(
        error,
        format!(
            "access.mode = \"authzen\" contradicts the bucket or volume label \"{}...\" (257 bytes): a label is the id of a node and has at most 256 bytes",
            "a".repeat(32)
        )
    );

    // The buckets and the volumes count together, and a volume label has the same limit.
    let folder = TempDir::new();
    let volumes = |count: usize| -> String {
        (0..count)
            .map(|index| {
                format!(
                    "volume \"volume-{index:03}\" {{\n  path = \"{}\"\n  permissions = [\"read\"]\n}}\n",
                    folder.text()
                )
            })
            .collect()
    };
    assert_eq!(
        decode(&authzen, &format!("{}{}", bucket_blocks(200, number), volumes(56))),
        ""
    );
    let error = decode(&authzen, &format!("{}{}", bucket_blocks(200, number), volumes(57)));
    assert_eq!(
        error,
        "access.mode = \"authzen\" contradicts the number of bucket and volume blocks (257): the action document lists one resource for each, and the most is 256"
    );
    let long_volume = format!(
        "volume \"{}\" {{\n  path = \"{}\"\n  permissions = [\"read\"]\n}}\n",
        "v".repeat(257),
        folder.text()
    );
    assert!(decode(&authzen, &long_volume).contains("(257 bytes)"));

    // With mode open, the labels are not node ids: no limit applies.
    let open = "access { mode = \"open\" }\n";
    assert_eq!(decode(open, &bucket_blocks(300, number)), "");
    assert_eq!(decode(open, &bucket_blocks(1, |_| "a".repeat(257))), "");
}

#[test]
fn the_environment_is_read_only_when_the_file_names_it() {
    let jwks = key_set(&[ed_jwk(",\"kid\":\"env-key\"")]);
    let variables = [
        ("STOWR_TEST_PDP_TOKEN", "token-from-env"),
        ("STOWR_TEST_PDP_URL", "http://pdp.internal:4182/base"),
        ("STOWR_TEST_JWKS", jwks.as_str()),
        ("STOWR_TEST_EMPTY", ""),
    ];
    let identity = GOOD_IDENTITY.replacen(
        "public_keys_file = \"jwks.json\"",
        "public_keys_env = \"STOWR_TEST_JWKS\"",
        1,
    );
    let pdp = "
    url_env    = \"STOWR_TEST_PDP_URL\"
    plain_http = true
    token_env  = \"STOWR_TEST_PDP_TOKEN\"
";
    with_environment(&variables, |hooks| {
        let dir = access_dir(&[]);
        let text = format!("{ACCESS_TEST_STORAGE}{}", authzen_text(&identity, pdp));
        let config = decode_in_with(&dir, &text, hooks).unwrap();
        assert_eq!(pdp_of(&config).token, "token-from-env");
        assert_eq!(pdp_of(&config).url, "http://pdp.internal:4182/base");
        assert_eq!(identity_of(&config).key_names, vec!["Ed25519 kid=env-key"]);
        let printed = format_effective(&config);
        for want in [
            "access.pdp.token = <hidden>  # env:STOWR_TEST_PDP_TOKEN",
            "access.pdp.url = \"http://pdp.internal:4182/base\"  # env:STOWR_TEST_PDP_URL",
            "access.identity.public_keys = [\"Ed25519 kid=env-key\"]  # env:STOWR_TEST_JWKS",
        ] {
            assert!(printed.contains(want), "print-config misses {want:?}:\n{printed}");
        }
        assert!(!printed.contains("token-from-env"));

        // An empty variable and a variable that does not exist stop the start.
        for (name, pdp, want) in [
            (
                "empty variable",
                pdp.replacen("STOWR_TEST_PDP_TOKEN", "STOWR_TEST_EMPTY", 1),
                "the environment variable \"STOWR_TEST_EMPTY\" is empty",
            ),
            (
                "missing variable",
                pdp.replacen("STOWR_TEST_PDP_URL", "STOWR_TEST_NO_SUCH_VARIABLE", 1),
                "the environment variable \"STOWR_TEST_NO_SUCH_VARIABLE\" does not exist",
            ),
        ] {
            let text = format!("{ACCESS_TEST_STORAGE}{}", authzen_text(&identity, &pdp));
            let error = message(&decode_in_with(&dir, &text, hooks));
            assert!(error.contains(want), "{name}: {error}");
        }
    });
}

/// A PEM file in `public_keys_file` gives the same keys and the same print-config form as a JWK Set: the type and the
/// RFC 7638 thumbprint.
#[test]
fn pem_public_keys() {
    let identity = GOOD_IDENTITY.replacen("public_keys_file = \"jwks.json\"", "public_keys_file = \"edge.pem\"", 1);
    let pem = format!("{}{}", rfc8037_pem(), rfc7515_pem());
    let (result, dir) = decode_access(&authzen_text(&identity, GOOD_PDP), &[("edge.pem", &pem)]);
    let config = result.unwrap();
    let identity = identity_of(&config);
    assert_eq!(identity.public_keys_text, pem.strip_suffix('\n').unwrap());
    let want = format!(
        "access.identity.public_keys = [\"Ed25519 kid={RFC8037_THUMBPRINT}\", \"P-256 kid={}\"]  # file:{}\n",
        rfc7515_thumbprint(),
        dir.join("edge.pem")
    );
    let printed = format_effective(&config);
    assert!(printed.contains(&want), "{want}\n{printed}");
}

#[test]
fn print_config_in_authzen_mode() {
    let identity = format!("{GOOD_IDENTITY}\n    max_age = \"300s\"\n");
    let pdp = format!("{GOOD_PDP}\n    timeout = \"1s\"\n    plain_http = false\n");
    let (result, dir) = decode_access(&authzen_text(&identity, &pdp), &[]);
    let config = result.unwrap();
    let printed = format_effective(&config);
    let access: Vec<&str> = printed.lines().filter(|line| line.starts_with("access.")).collect();
    assert_eq!(
        access,
        vec![
            "access.mode = \"authzen\"  # file".to_owned(),
            "access.identity.header = \"X-Identity-Token\"  # default".to_owned(),
            "access.identity.issuer = \"https://edge.example\"  # file".to_owned(),
            "access.identity.audience = \"infra-s3\"  # file".to_owned(),
            format!(
                "access.identity.public_keys = [\"Ed25519 kid=edge-1\", \"P-256 kid=edge-2\"]  # file:{}",
                dir.join("jwks.json")
            ),
            "access.identity.max_age = \"300s\"  # file".to_owned(),
            "access.identity.clock_skew = \"60s\"  # default".to_owned(),
            "access.pdp.url = \"https://pdp.example:4182\"  # file".to_owned(),
            "access.pdp.plain_http = false  # file".to_owned(),
            format!("access.pdp.token = <hidden>  # file:{}", dir.join("pdp-token")),
            "access.pdp.timeout = \"1s\"  # file".to_owned(),
            "access.pdp.usage_timeout = \"6s\"  # default".to_owned(),
            "access.pdp.cache_ttl = \"30s\"  # default".to_owned(),
            "access.pdp.max_evaluations = 64  # default".to_owned(),
        ]
    );
    assert!(!printed.contains(TEST_PDP_TOKEN));
}

#[test]
fn print_config_in_open_mode() {
    let (result, _dir) = decode_access("access { mode = \"open\" }\n", &[]);
    let printed = format_effective(&result.unwrap());
    assert!(printed.contains("access.mode = \"open\"  # file\n"));
    assert!(!printed.contains("access.identity") && !printed.contains("access.pdp"));
}

/// A configuration that no file made has no written text: print-config then gives the shortest strict text.
#[test]
fn print_config_of_a_duration_without_text() {
    let config = Config {
        listen: ":8080".to_owned(),
        access: AccessConfig {
            mode: AccessPolicy::AuthZen,
            identity: Some(IdentityConfig {
                header: "X-Identity-Token".to_owned(),
                issuer: "i".to_owned(),
                audience: "a".to_owned(),
                max_age: Duration::from_secs(90),
                ..IdentityConfig::default()
            }),
            pdp: Some(PdpConfig {
                url: "https://p".to_owned(),
                timeout: Duration::from_millis(1500),
                cache_ttl: Duration::from_secs(3600),
                ..PdpConfig::default()
            }),
        },
        ..Config::default()
    };
    let printed = format_effective(&config);
    for want in [
        "access.identity.max_age = \"90s\"",
        "access.pdp.timeout = \"1500ms\"",
        "access.pdp.cache_ttl = \"1h\"",
        "access.identity.clock_skew = \"0s\"",
    ] {
        assert!(printed.contains(want), "print-config misses {want:?}:\n{printed}");
    }
}

#[test]
fn warnings_of_a_decoded_file() {
    let (result, _dir) = decode_access("access { mode = \"open\" }\n", &[]);
    let got = warnings(&result.unwrap());
    assert_eq!(got.len(), 1);
    assert!(got[0].contains("access.mode = \"open\""));
    let (result, _dir) = decode_access(
        &authzen_text(
            GOOD_IDENTITY,
            &format!("{}\n    plain_http = true", GOOD_PDP.replacen("https://", "http://", 1)),
        ),
        &[],
    );
    let config = result.unwrap();
    let got = warnings(&config);
    assert_eq!(got.len(), 2, "{got:?}");
    assert!(got[0].contains("plain_http") && got[1].contains("only through the edge"));
    // print-config does not print the warnings.
    assert!(!format_effective(&config).contains("warning"));
}

/// The reference shows the access block.
#[test]
fn access_is_in_the_reference() {
    let text = reference();
    for want in [
        "## `access`",
        "## `access.identity`",
        "## `access.pdp`",
        "| `mode` |",
        "| `public_keys` |",
        "| `max_evaluations` |",
        "| `token` | text | (required) |",
        "Exactly one block. Required.",
        "One block with mode authzen. No block with mode open.",
    ] {
        assert!(text.contains(want), "the configuration reference misses {want:?}");
    }
}

/// A file without an access block gives an error that tells how to fix it.
#[test]
fn a_missing_access_block_tells_how_to_fix_it() {
    let dir = TempDir::new();
    let text = minimal_test_config("bucket").replacen("access {\n  mode = \"open\"\n}\n", "", 1);
    let error = message(&load_in(&dir, &text));
    for want in [
        "the access block is required",
        "access { mode = \"open\" }",
        "mode = \"authzen\"",
    ] {
        assert!(error.contains(want), "error {error:?} does not contain {want:?}");
    }
}

#[test]
fn errors_of_the_access_block_give_the_line() {
    let (result, _dir) = decode_access("access {\n  mode = \"AuthZEN\"\n}\n", &[]);
    assert_eq!(
        message(&result),
        "line 13:1: access.mode must be \"authzen\" or \"open\" (lower case), got \"AuthZEN\""
    );
    let (result, _dir) = decode_access(
        &authzen_text(GOOD_IDENTITY, &format!("{GOOD_PDP}\n    timeout = \"9ms\"")),
        &[],
    );
    assert_eq!(
        message(&result),
        "line 21:3: access.pdp.timeout must be from 10ms to 1m, got \"9ms\""
    );
    let (result, _dir) = decode_access(
        &authzen_text(
            GOOD_IDENTITY,
            &GOOD_PDP.replacen(
                "\"https://pdp.example:4182\"",
                "\"https://user:secret-pass@pdp.example\"",
                1,
            ),
        ),
        &[],
    );
    assert_eq!(message(&result), "line 21:3: access.pdp.url: must not have credentials");
    let (result, _dir) = decode_access(
        &authzen_text(
            GOOD_IDENTITY,
            &GOOD_PDP.replacen("\"https://pdp.example:4182\"", "\"https://pdp.example:4182/\"", 1),
        ),
        &[],
    );
    assert_eq!(
        message(&result),
        "line 21:3: access.pdp.url: must not end with \"/\", got \"https://pdp.example:4182/\""
    );
}
