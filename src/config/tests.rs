// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tests of the reader of the configuration: the `server`, `auth` and `bucket` blocks, the strict values, the
//! sizes of the files, the reference and the encryption key.

use crate::common::config::{AccessMode, Encryption, PERMISSION_DELETE, PERMISSION_READ, PERMISSION_WRITE, Provider};

use super::support_tests::{TEST_OPEN_ACCESS, TempDir, decode_in, load_in, message, minimal_test_config, test_hooks};
use super::{MAX_CONFIGURATION_BYTES, MAX_SECRET_FILE_BYTES, format_effective, load_runtime_with, reference};

/// docs/configuration-reference.md is the output of `stowr config-reference`: the program makes it from the table of
/// the keys.
#[test]
fn the_configuration_reference_is_current() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/docs/configuration-reference.md");
    let committed = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => panic!("read the reference: {error}"),
    };
    assert!(
        committed == reference(),
        "docs/configuration-reference.md is not the output of the table: run scripts/cargo.sh run --quiet -- config-reference > docs/configuration-reference.md"
    );
}

#[test]
fn the_reference_names_its_generator_and_each_block() {
    let text = reference();
    assert!(text.contains("`src/config/keys.rs`"));
    assert!(text.contains("scripts/cargo.sh run --quiet -- config-reference > docs/configuration-reference.md"));
    for block in super::keys::BLOCKS {
        assert!(text.contains(&format!("\n## `{}`\n", block.path)), "{}", block.path);
    }
    for key in super::keys::KEYS {
        assert!(
            text.contains(&format!("| `{}` | {} |", key.name, key.kind)),
            "{}.{}",
            key.block,
            key.name
        );
    }
}

#[test]
fn omitted_permissions_let_each_permission() {
    let dir = TempDir::new();
    dir.write("secret", "secret\n");
    let config = load_in(
        &dir,
        &format!(
            "\nauth \"shared\" {{\n  provider          = \"s3\"\n  mode              = \"access_key\"\n  endpoint          = \"http://localhost:9000\"\n  region            = \"test\"\n  access_key_id          = \"key\"\n  secret_access_key_file = \"secret\"\n}}\n\nbucket \"inherited\" {{\n  auth   = \"shared\"\n  bucket = \"bucket\"\n}}\n{TEST_OPEN_ACCESS}"
        ),
    )
    .unwrap();
    let bucket = &config.buckets[0];
    assert!(
        !bucket.permissions_defined && bucket.permissions.is_empty(),
        "{bucket:?}"
    );
    for permission in [PERMISSION_READ, PERMISSION_WRITE, PERMISSION_DELETE] {
        assert!(bucket.allows(permission));
    }
}

#[test]
fn buckets_share_one_auth_block() {
    let dir = TempDir::new();
    dir.write("s3-secret.txt", "shared-secret\n");
    let config = load_in(
        &dir,
        &format!(
            "\nserver {{\n  listen            = \":9090\"\n  job_history_limit = 17\n}}\n\nauth \"production\" {{\n  provider               = \"s3\"\n  mode                   = \"access_key\"\n  endpoint               = \"http://127.0.0.1:9000\"\n  region                 = \"us-east-1\"\n  access_key_id          = \"shared-key\"\n  secret_access_key_file = \"./s3-secret.txt\"\n}}\n\nbucket \"documents\" {{\n  name           = \"Documents\"\n  auth           = \"production\"\n  bucket         = \"documents\"\n  permissions    = [\"read\", \"write\", \"delete\"]\n  root_prefix    = \"tenant-a/\"\n  max_scan_pages = 15\n}}\n\nbucket \"archive\" {{\n  name        = \"Archive\"\n  auth        = \"production\"\n  bucket      = \"archive\"\n  permissions = [\"read\"]\n}}\n{TEST_OPEN_ACCESS}"
        ),
    )
    .unwrap();
    assert_eq!(config.listen, ":9090");
    assert_eq!(config.job_history_limit, 17);
    assert_eq!((config.auths.len(), config.buckets.len()), (1, 2));
    for bucket in &config.buckets {
        assert_eq!(
            (
                bucket.auth_id.as_str(),
                bucket.provider.as_str(),
                bucket.region.as_str()
            ),
            ("production", "s3", "us-east-1")
        );
    }
    let auth = &config.auths[0];
    assert_eq!(auth.access_key_id, "shared-key");
    assert_eq!(auth.secret_access_key, "shared-secret");
    assert_eq!(config.buckets[0].root_prefix, "tenant-a/");
    assert_eq!(
        (config.buckets[0].max_scan_pages, config.buckets[1].max_scan_pages),
        (15, 1)
    );
    assert_eq!(config.buckets[0].permissions.join(","), "read,write,delete");
    assert_eq!(config.source_dir, dir.path());
    assert_eq!(config.source_name, dir.path().join("config.hcl"));
}

#[test]
fn a_dash_is_a_valid_instance_id() {
    let dir = TempDir::new();
    let config = load_in(&dir, &minimal_test_config("-")).unwrap();
    assert_eq!(config.buckets.len(), 1);
    assert_eq!(config.buckets[0].id, "-");
}

#[test]
fn background_budgets_are_read() {
    let dir = TempDir::new();
    let config = load_in(
        &dir,
        &format!(
            "\nserver {{\n  max_background_storage_bytes    = 274877906944\n  max_background_storage_requests = 12345\n}}\n\n{}",
            minimal_test_config("primary")
        ),
    )
    .unwrap();
    assert_eq!(config.runtime.max_background_storage_bytes, 274_877_906_944);
    assert_eq!(config.runtime.max_background_storage_requests, 12345);
}

#[test]
fn background_budgets_out_of_range_stop_the_start() {
    for (attribute, value) in [
        ("max_background_storage_bytes", "1024"),
        ("max_background_storage_requests", "0"),
    ] {
        let dir = TempDir::new();
        let result = load_in(
            &dir,
            &format!("server {{ {attribute} = {value} }}\n{}", minimal_test_config("primary")),
        );
        assert!(message(&result).contains(attribute), "{}", message(&result));
    }
}

#[test]
fn defaults_keep_the_memory_low() {
    let dir = TempDir::new();
    let config = load_in(&dir, &minimal_test_config("primary")).unwrap();
    assert_eq!(config.job_history_limit, 10);
    assert_eq!(config.runtime.max_range_cache_bytes, 8 << 20);
    assert_eq!(config.runtime.max_concurrent_storage_requests, 4);
    assert_eq!(config.runtime.max_concurrent_requests_per_storage, 2);
    assert!(config.runtime.max_storage_bytes_per_request >= 100 << 30);
    assert!(config.runtime.max_background_storage_bytes >= 100 << 30);
}

#[test]
fn the_default_runtime_is_stateless_and_bounded() {
    let dir = TempDir::new();
    let config = decode_in(&dir, &minimal_test_config("stateless")).unwrap();
    assert_eq!(config.runtime.access_mode, AccessMode::InheritCredentials);
    assert_eq!(config.job_history_limit, 10);
    assert_eq!(config.runtime.max_range_cache_bytes, 8 << 20);
    assert_eq!(
        (
            config.runtime.max_concurrent_storage_requests,
            config.runtime.max_concurrent_requests_per_storage
        ),
        (4, 2)
    );
    assert_eq!(config.runtime, crate::common::config::RuntimePolicy::default());
}

#[test]
fn a_gcs_auth_block_is_read() {
    let dir = TempDir::new();
    dir.write("gcs.json", "{\"type\":\"service_account\"}");
    let config = load_in(
        &dir,
        &format!(
            "\nauth \"gcs\" {{\n  provider         = \"gcs\"\n  mode             = \"service_account\"\n  credentials_file = \"./gcs.json\"\n}}\n\nbucket \"archive\" {{\n  auth   = \"gcs\"\n  bucket = \"archive-bucket\"\n}}\n{TEST_OPEN_ACCESS}"
        ),
    )
    .unwrap();
    let bucket = &config.buckets[0];
    assert_eq!((bucket.provider.as_str(), bucket.auth_id.as_str()), ("gcs", "gcs"));
    let auth = &config.auths[0];
    assert_eq!(auth.provider, Provider::Gcs);
    assert_eq!(auth.endpoint, "https://storage.googleapis.com");
    assert_eq!(auth.credentials_file, Some(dir.path().join("gcs.json")));
    let printed = format_effective(&config);
    assert!(printed.contains(&format!(
        "auth \"gcs\".credentials_file = \"{}\"  # file\n",
        dir.join("gcs.json")
    )));
    assert!(printed.contains("auth \"gcs\".region = <none>  # default\n"));
}

#[test]
fn an_unknown_auth_attribute_stops_the_start() {
    let dir = TempDir::new();
    let result = load_in(
        &dir,
        &format!(
            "\nauth \"broken\" {{\n  provider           = \"s3\"\n  endpoint           = \"http://localhost:9000\"\n  region             = \"test\"\n  unsupported_option = \"value\"\n}}\n\nbucket \"bucket\" {{ auth = \"broken\" bucket = \"bucket\" }}\n{TEST_OPEN_ACCESS}"
        ),
    );
    assert_eq!(
        message(&result),
        "line 6:3: unknown attribute \"unsupported_option\" in auth block"
    );
}

#[test]
fn a_bucket_with_an_unknown_auth_stops_the_start() {
    let dir = TempDir::new();
    let result = load_in(
        &dir,
        &format!(
            "{}\nbucket \"broken\" {{ auth = \"missing\" bucket = \"bucket\" }}\n",
            minimal_test_config("known")
        ),
    );
    assert!(
        message(&result).contains("bucket \"broken\".auth: no auth block has the label \"missing\""),
        "{}",
        message(&result)
    );
}

#[test]
fn an_unknown_server_attribute_stops_the_start() {
    let dir = TempDir::new();
    let result = load_in(
        &dir,
        &format!(
            "server {{ public_prefix = \"/browser/\" }}\n{}",
            minimal_test_config("bucket")
        ),
    );
    assert_eq!(
        message(&result),
        "line 1:10: unknown attribute \"public_prefix\" in server block"
    );
}

#[test]
fn max_scan_pages_out_of_range_stops_the_start() {
    let dir = TempDir::new();
    let result = load_in(
        &dir,
        &format!(
            "\nauth \"public\" {{\n  provider = \"s3\"\n  mode     = \"anonymous\"\n  endpoint = \"http://localhost:9000\"\n  region   = \"test\"\n}}\n\nbucket \"bucket\" {{\n  auth           = \"public\"\n  bucket         = \"bucket\"\n  max_scan_pages = 1000001\n}}\n{TEST_OPEN_ACCESS}"
        ),
    );
    assert_eq!(
        message(&result),
        "line 9:1: bucket \"bucket\".max_scan_pages must be between 0 and 1000000, got 1000001"
    );
}

#[test]
fn an_oversized_configuration_stops_the_start() {
    let dir = TempDir::new();
    let mut data = "# padding\n".repeat(usize::try_from(MAX_CONFIGURATION_BYTES / 10).unwrap() + 2);
    while data.len() as u64 <= MAX_CONFIGURATION_BYTES {
        data.push('x');
    }
    let result = load_in(&dir, &data);
    assert!(
        message(&result).contains("exceeds the 4194304-byte limit"),
        "{}",
        message(&result)
    );
}

#[test]
fn an_oversized_secret_file_stops_the_start() {
    let dir = TempDir::new();
    dir.write(
        "secret.txt",
        vec![b'x'; usize::try_from(MAX_SECRET_FILE_BYTES).unwrap() + 1],
    );
    let result = load_in(
        &dir,
        &format!(
            "\nauth \"shared\" {{\n  provider               = \"s3\"\n  mode                   = \"access_key\"\n  endpoint               = \"http://localhost:9000\"\n  region                 = \"test\"\n  access_key_id          = \"key\"\n  secret_access_key_file = \"./secret.txt\"\n}}\n\nbucket \"bucket\" {{ auth = \"shared\" bucket = \"bucket\" }}\n{TEST_OPEN_ACCESS}"
        ),
    );
    assert_eq!(
        message(&result),
        format!(
            "line 2:1: auth \"shared\".secret_access_key_file: cannot read \"{}\": file exceeds the 1048576-byte limit",
            dir.join("secret.txt")
        )
    );
}

#[test]
fn the_command_line_needs_a_path() {
    let result = load_runtime_with("", &test_hooks());
    assert_eq!(
        message(&result),
        "configuration path is required; use -c <path> or --config <path>"
    );
    let result = load_runtime_with("  ", &test_hooks());
    assert!(message(&result).contains("configuration path is required"));
}

#[test]
fn a_missing_file_names_the_absolute_path() {
    let dir = TempDir::new();
    let path = dir.join("missing.hcl");
    let result = load_runtime_with(&path, &test_hooks());
    assert_eq!(
        message(&result),
        format!("read configuration \"{path}\": open {path}: no such file or directory")
    );
}

#[test]
fn an_attribute_of_a_wrong_kind_stops_the_start() {
    let dir = TempDir::new();
    let result = load_in(
        &dir,
        &format!(
            "\nauth \"public\" {{\n  provider = \"s3\"\n  mode     = \"anonymous\"\n  endpoint = \"http://localhost:9000\"\n  region   = \"test\"\n}}\n\nbucket \"broken\" {{\n  auth        = \"public\"\n  bucket      = \"bucket\"\n  permissions = true\n}}\n{TEST_OPEN_ACCESS}"
        ),
    );
    assert_eq!(
        message(&result),
        "line 12:3: attribute \"permissions\" must be a string list"
    );
}

#[test]
fn a_parse_error_names_the_file() {
    let dir = TempDir::new();
    let result = load_in(&dir, "server {\n  listen = :8080\n}\n");
    assert_eq!(
        message(&result),
        format!(
            "parse configuration \"{}\": line 2:12: unexpected character ':'",
            dir.join("config.hcl")
        )
    );
}

#[test]
fn the_job_history_limit_is_read() {
    let dir = TempDir::new();
    let config = load_in(
        &dir,
        &format!(
            "server {{ job_history_limit = 12 }}\n{}",
            minimal_test_config("primary")
        ),
    )
    .unwrap();
    assert_eq!(config.job_history_limit, 12);
}

#[test]
fn a_job_history_limit_out_of_range_stops_the_start() {
    for value in ["0", "21", "\"100\""] {
        let dir = TempDir::new();
        let result = load_in(
            &dir,
            &format!(
                "server {{ job_history_limit = {value} }}\n{}",
                minimal_test_config("primary")
            ),
        );
        assert!(result.is_err(), "{value}");
    }
    let dir = TempDir::new();
    let result = load_in(
        &dir,
        &format!(
            "server {{ job_history_limit = 21 }}\n{}",
            minimal_test_config("primary")
        ),
    );
    assert_eq!(
        message(&result),
        "line 1:1: server.job_history_limit must be between 1 and 20, got 21"
    );
}

/// The server never changes a value to make it fit. A value that does not fit stops the start, and the error names
/// the key and the value (but never the value of a secret).
#[test]
fn strict_values_stop_the_start() {
    let dir = TempDir::new();
    dir.write("spaced", " secret-with-space\n");
    dir.write("good", "good-secret\n");
    let auth =
        |lines: &str| format!("auth \"s3\" {{\n{lines}\n}}\nbucket \"b\" {{\n  auth = \"s3\"\n  bucket = \"b\"\n}}\n");
    let base = "provider = \"s3\"\nendpoint = \"http://localhost:9000\"\nregion = \"test\"\n";
    let with_bucket =
        |lines: &str| format!("auth \"s3\" {{\n{base}}}\nbucket \"b\" {{\n  auth = \"s3\"\n{lines}\n}}\n");
    let cases: Vec<(&str, String, &str, &str)> = vec![
        (
            "upper-case provider",
            auth(&base.replacen("\"s3\"", "\"S3\"", 1)),
            "auth \"s3\".provider must be \"s3\" or \"gcs\", got \"S3\"",
            "",
        ),
        (
            "space in mode",
            auth(&format!("{base}mode = \" anonymous\"")),
            "auth \"s3\".mode must not have a space at the start or at the end, got \" anonymous\"",
            "",
        ),
        (
            "endpoint slash",
            auth(&base.replacen("9000\"", "9000/\"", 1)),
            "auth \"s3\".endpoint must not end with \"/\", got \"http://localhost:9000/\"",
            "",
        ),
        (
            "region space",
            auth(&base.replacen("\"test\"", "\"test \"", 1)),
            "auth \"s3\".region must not have a space",
            "",
        ),
        (
            "clear secret",
            auth(&format!(
                "{base}access_key_id = \"k\"\nsecret_access_key = \"top-secret-value\""
            )),
            "auth \"s3\".secret_access_key is a secret: use secret_access_key_env or secret_access_key_file",
            "top-secret-value",
        ),
        (
            "clear session token",
            auth(&format!("{base}session_token = \"top-secret-value\"")),
            "auth \"s3\".session_token is a secret",
            "top-secret-value",
        ),
        (
            "secret with space",
            auth(&format!(
                "{base}access_key_id = \"k\"\nsecret_access_key_file = \"spaced\""
            )),
            "auth \"s3\".secret_access_key must not contain a space or a control character",
            "secret-with-space",
        ),
        (
            "two secret forms",
            auth(&format!(
                "{base}access_key_id = \"k\"\nsecret_access_key_file = \"good\"\nsecret_access_key_env = \"X\""
            )),
            "give only one of secret_access_key, secret_access_key_env and secret_access_key_file",
            "good-secret",
        ),
        (
            "root prefix slash",
            with_bucket("  bucket = \"b\"\n  root_prefix = \"/tenant\""),
            "bucket \"b\".root_prefix must be \"\" or a prefix that ends with \"/\"",
            "",
        ),
        (
            "root prefix no end",
            with_bucket("  bucket = \"b\"\n  root_prefix = \"tenant\""),
            "got \"tenant\"",
            "",
        ),
        (
            "upper-case permission",
            with_bucket("  bucket = \"b\"\n  permissions = [\"Read\"]"),
            "bucket \"b\".permissions must contain only \"read\", \"write\" and \"delete\", got \"Read\"",
            "",
        ),
        (
            "duplicate permission",
            with_bucket("  bucket = \"b\"\n  permissions = [\"read\", \"read\"]"),
            "bucket \"b\".permissions contains \"read\" two times",
            "",
        ),
        (
            "empty name",
            with_bucket("  bucket = \"b\"\n  name = \"\""),
            "bucket \"b\".name must not be empty",
            "",
        ),
        (
            "bucket name space",
            with_bucket("  bucket = \" b\""),
            "bucket \"b\".bucket must not have a space at the start or at the end, got \" b\"",
            "",
        ),
        (
            "upper-case log mode",
            format!(
                "server {{ log_mode = \"Detailed\" }}\n{}",
                with_bucket("  bucket = \"b\"")
            ),
            "server.log_mode must be \"anonymous\" or \"detailed\", got \"Detailed\"",
            "",
        ),
        (
            "listen space",
            format!("server {{ listen = \" :8080\" }}\n{}", with_bucket("  bucket = \"b\"")),
            "server.listen",
            "",
        ),
    ];
    for (name, config, want, hidden) in cases {
        let result = decode_in(&dir, &config);
        let text = message(&result);
        assert!(text.contains(want), "{name}: error = {text:?}, want {want:?}");
        if !hidden.is_empty() {
            assert!(!text.contains(hidden), "{name}: the error shows the secret: {text}");
        }
    }
}

#[test]
fn listen_addresses_are_checked_without_a_change() {
    let dir = TempDir::new();
    let listen = |value: &str| {
        let result = decode_in(
            &dir,
            &format!("server {{ listen = \"{value}\" }}\n{}", minimal_test_config("b")),
        );
        match result {
            Ok(config) => Ok(config.listen),
            Err(error) => Err(error.to_string()),
        }
    };
    assert_eq!(listen("127.0.0.1:8081"), Ok("127.0.0.1:8081".to_owned()));
    assert_eq!(listen("[::1]:80"), Ok("[::1]:80".to_owned()));
    assert_eq!(listen("localhost:0080"), Ok("localhost:0080".to_owned()));
    assert_eq!(
        listen("http://h:80"),
        Err("line 1:1: server.listen: must be a host:port address, not a URL, got \"http://h:80\"".to_owned())
    );
    assert_eq!(
        listen("8080"),
        Err("line 1:1: server.listen: must be a valid host:port address: address 8080: no port in the address, got \"8080\"".to_owned())
    );
    assert_eq!(
        listen(":0"),
        Err("line 1:1: server.listen: port must be an integer between 1 and 65535, got \":0\"".to_owned())
    );
    assert_eq!(
        listen(":65536"),
        Err("line 1:1: server.listen: port must be an integer between 1 and 65535, got \":65536\"".to_owned())
    );
    assert_eq!(
        listen(""),
        Err("line 1:1: server.listen: cannot be empty, got \"\"".to_owned())
    );
    assert_eq!(
        listen("a b:80"),
        Err("line 1:1: server.listen: must not contain a space or a control character, got \"a b:80\"".to_owned())
    );
}

#[test]
fn runtime_limits_stop_the_start_without_a_line() {
    let dir = TempDir::new();
    let run = |lines: &str| {
        message(&decode_in(
            &dir,
            &format!("server {{\n{lines}\n}}\n{}", minimal_test_config("b")),
        ))
    };
    assert_eq!(
        run("access_mode = \"read_only\""),
        "server.access_mode must be \"inherit_credentials\" or \"force_read_only\", got \"read_only\""
    );
    assert_eq!(
        run("memory_limit_bytes = 1024"),
        "server.memory_limit_bytes must be between 33554432 and 1125899906842624, got 1024"
    );
    assert_eq!(
        run("max_concurrent_storage_requests = 99999999999"),
        "server.max_concurrent_storage_requests must be between 1 and 1024, got 99999999999"
    );
    assert_eq!(
        run("max_concurrent_storage_requests = 2\nmax_concurrent_requests_per_storage = 3"),
        "server.max_concurrent_requests_per_storage (3) cannot exceed max_concurrent_storage_requests (2)"
    );
    assert_eq!(
        run("session_ttl_seconds = 29"),
        "server.session_ttl_seconds must be between 30 and 604800, got 29"
    );
    assert_eq!(
        run("max_stats_folders = 99"),
        "server.max_stats_folders must be between 100 and 1000000, got 99"
    );
    assert_eq!(
        run("max_archive_entries = 0"),
        "server.max_archive_entries must be between 1 and 1000000, got 0"
    );
    assert_eq!(
        run("max_range_cache_bytes = 4294967297"),
        "server.max_range_cache_bytes must be between 1048576 and 4294967296, got 4294967297"
    );
}

#[test]
fn each_server_key_is_read_and_printed() {
    let dir = TempDir::new();
    let config = decode_in(
        &dir,
        &format!(
            "server {{\n  listen = \"127.0.0.1:9000\"\n  access_mode = \"force_read_only\"\n  log_mode = \"detailed\"\n  allow_full_object_fallback = true\n  memory_limit_bytes = 33554432\n  max_storage_bytes_per_request = 1048576\n  max_storage_requests_per_request = 7\n  max_range_cache_bytes = 2097152\n  max_concurrent_storage_requests = 8\n  max_concurrent_requests_per_storage = 8\n  session_ttl_seconds = 30\n  max_stats_folders = 100\n  max_archive_entries = 5\n  max_background_storage_bytes = 3145728\n  max_background_storage_requests = 9\n}}\n{}",
            minimal_test_config("b")
        ),
    )
    .unwrap();
    assert!(config.runtime.force_read_only());
    let printed = format_effective(&config);
    let server: Vec<&str> = printed.lines().filter(|line| line.starts_with("server.")).collect();
    assert_eq!(
        server,
        vec![
            "server.listen = \"127.0.0.1:9000\"  # file",
            "server.job_history_limit = 10  # default",
            "server.access_mode = \"force_read_only\"  # file",
            "server.log_mode = \"detailed\"  # file",
            "server.allow_full_object_fallback = true  # file",
            "server.memory_limit_bytes = 33554432  # file",
            "server.max_storage_bytes_per_request = 1048576  # file",
            "server.max_storage_requests_per_request = 7  # file",
            "server.max_range_cache_bytes = 2097152  # file",
            "server.max_concurrent_storage_requests = 8  # file",
            "server.max_concurrent_requests_per_storage = 8  # file",
            "server.session_ttl_seconds = 30  # file",
            "server.max_stats_folders = 100  # file",
            "server.max_archive_entries = 5  # file",
            "server.max_background_storage_bytes = 3145728  # file",
            "server.max_background_storage_requests = 9  # file",
        ]
    );
}

#[test]
fn structural_errors_of_the_file() {
    let dir = TempDir::new();
    let run = |text: &str| message(&decode_in(&dir, text));
    assert_eq!(
        run("listen = \":8080\"\n"),
        "line 1:1: root attribute \"listen\" is not supported; use a block"
    );
    assert_eq!(
        run(&format!("server {{}}\nserver {{}}\n{}", minimal_test_config("b"))),
        "only one server block is allowed"
    );
    assert_eq!(
        run(&format!("server \"x\" {{}}\n{}", minimal_test_config("b"))),
        "line 1:1: server block does not accept labels"
    );
    assert_eq!(
        run(&format!("server {{\n  x {{}}\n}}\n{}", minimal_test_config("b"))),
        "line 1:1: nested blocks are not supported inside server"
    );
    assert_eq!(
        run(&format!("buckets \"x\" {{}}\n{}", minimal_test_config("b"))),
        "line 1:1: unknown block type \"buckets\"; supported blocks are server, access, auth, bucket and volume"
    );
    assert_eq!(
        run(TEST_OPEN_ACCESS),
        "at least one bucket block or one volume block is required"
    );
    assert_eq!(
        run(&format!(
            "bucket \"b\" {{\n  auth = \"x\"\n  bucket = \"b\"\n}}\n{TEST_OPEN_ACCESS}"
        )),
        "at least one auth block is required"
    );
    assert_eq!(
        run(&format!(
            "{}bucket \"b\" {{ auth = \"public\" bucket = \"c\" }}\n",
            minimal_test_config("b")
        )),
        "line 17:1: duplicate bucket id \"b\""
    );
    assert_eq!(
        run(&format!(
            "{}bucket {{ auth = \"public\" bucket = \"c\" }}\n",
            minimal_test_config("b")
        )),
        "line 17:1: bucket block requires exactly one quoted identifier"
    );
    assert_eq!(
        run(&format!(
            "{}bucket \"a b\" {{ auth = \"public\" bucket = \"c\" }}\n",
            minimal_test_config("b")
        )),
        "line 17:1: bucket label must match ^(?:[A-Za-z0-9][A-Za-z0-9._-]*|-)$, got \"a b\""
    );
    assert_eq!(
        run(&format!(
            "{}auth \"public\" {{\n  provider = \"s3\"\n  endpoint = \"http://h\"\n  region = \"r\"\n}}\n",
            minimal_test_config("b")
        )),
        "line 17:1: duplicate auth id \"public\""
    );
    assert_eq!(
        run(&format!(
            "{}auth \".x\" {{\n  provider = \"s3\"\n}}\n",
            minimal_test_config("b")
        )),
        "line 17:1: auth label must match ^(?:[A-Za-z0-9][A-Za-z0-9._-]*|-)$, got \".x\""
    );
}

#[test]
fn auth_rules_of_each_provider() {
    let dir = TempDir::new();
    dir.write("key", "k\n");
    dir.write("gcs.json", "{}");
    let run = |lines: &str| {
        message(&decode_in(
            &dir,
            &format!(
                "auth \"a\" {{\n{lines}\n}}\nbucket \"b\" {{\n  auth = \"a\"\n  bucket = \"b\"\n}}\n{TEST_OPEN_ACCESS}"
            ),
        ))
    };
    let s3 = "provider = \"s3\"\nendpoint = \"http://h:9000\"\nregion = \"r\"\n";
    assert_eq!(
        run("endpoint = \"http://h\""),
        "line 1:1: auth \"a\".provider is required: \"s3\" or \"gcs\""
    );
    assert_eq!(
        run(&format!("{s3}credentials_file = \"gcs.json\"")),
        "line 1:1: auth \"a\".credentials_file is only supported for provider \"gcs\""
    );
    assert_eq!(
        run("provider = \"s3\"\nregion = \"r\""),
        "line 1:1: auth \"a\".endpoint is required for provider \"s3\""
    );
    assert_eq!(
        run("provider = \"s3\"\nendpoint = \"http://h\""),
        "line 1:1: auth \"a\".region is required for provider \"s3\""
    );
    assert_eq!(
        run(&format!("{s3}mode = \"access_key\"\naccess_key_id = \"k\"")),
        "line 1:1: auth \"a\": mode \"access_key\" requires access_key_id and secret_access_key (_env or _file)"
    );
    assert_eq!(
        run(&format!("{s3}mode = \"anonymous\"\naccess_key_id = \"k\"")),
        "line 1:1: auth \"a\": mode \"anonymous\" cannot define access credentials"
    );
    assert_eq!(
        run(&format!("{s3}mode = \"service_account\"")),
        "line 1:1: auth \"a\".mode must be \"access_key\" or \"anonymous\" for provider \"s3\", got \"service_account\""
    );
    assert_eq!(
        run("provider = \"gcs\"\naccess_key_id_file = \"key\""),
        "line 1:1: auth \"a\": the S3 credential attributes are only supported for provider \"s3\""
    );
    assert_eq!(
        run("provider = \"gcs\"\nmode = \"service_account\""),
        "line 1:1: auth \"a\": mode \"service_account\" requires credentials_file"
    );
    assert_eq!(
        run("provider = \"gcs\"\nmode = \"anonymous\"\ncredentials_file = \"gcs.json\""),
        "line 1:1: auth \"a\": mode \"anonymous\" cannot define credentials_file"
    );
    assert_eq!(
        run("provider = \"gcs\"\nmode = \"access_key\""),
        "line 1:1: auth \"a\".mode must be \"service_account\" or \"anonymous\" for provider \"gcs\", got \"access_key\""
    );
    assert_eq!(
        run("provider = \"s3\"\nendpoint = \"localhost:9000\"\nregion = \"r\""),
        "line 1:1: auth \"a\".endpoint: s3 endpoint scheme must be http or https, got \"localhost:9000\""
    );
    assert_eq!(
        run("provider = \"s3\"\nendpoint = \"http://h:port\"\nregion = \"r\""),
        "line 1:1: auth \"a\".endpoint: invalid s3 endpoint: invalid URL \"http://h:port\": invalid port \":port\", got \"http://h:port\""
    );
    assert_eq!(
        run("provider = \"s3\"\nendpoint = \"ftp://h\"\nregion = \"r\""),
        "line 1:1: auth \"a\".endpoint: s3 endpoint scheme must be http or https, got \"ftp://h\""
    );
    assert_eq!(
        run(&format!("{s3}access_key_id = \" k\"")),
        "line 1:1: auth \"a\".access_key_id must not have a space at the start or at the end or a control character, got \" k\""
    );
    assert_eq!(
        run(&format!("{s3}insecure_skip_verify = \"true\"")),
        "line 5:1: attribute \"insecure_skip_verify\" must be a boolean"
    );
    assert_eq!(
        run(&format!("{s3}access_key_id = \"k\"\naccess_key_id_file = \"key\"")),
        "line 1:1: auth \"a\".access_key_id: give only one of access_key_id, access_key_id_env and access_key_id_file"
    );
    assert_eq!(
        run(&format!("{s3}secret_access_key_env = \"\"\naccess_key_id = \"k\"")),
        "line 1:1: auth \"a\".secret_access_key_env is empty"
    );
    assert_eq!(
        run(&format!(
            "{s3}secret_access_key_file = \"missing\"\naccess_key_id = \"k\""
        )),
        format!(
            "line 1:1: auth \"a\".secret_access_key_file: cannot read \"{}\": open {}: no such file or directory",
            dir.join("missing"),
            dir.join("missing")
        )
    );
}

#[test]
fn an_auth_block_takes_its_mode_from_its_credentials() {
    let dir = TempDir::new();
    dir.write("secret", "s\n");
    let config = decode_in(
        &dir,
        &format!(
            "auth \"a\" {{\n  provider = \"s3\"\n  endpoint = \"http://h:9000/base\"\n  region = \"r\"\n  access_key_id = \"k\"\n  secret_access_key_file = \"secret\"\n}}\nauth \"g\" {{\n  provider = \"gcs\"\n}}\nbucket \"b\" {{\n  auth = \"a\"\n  bucket = \"b\"\n}}\n{TEST_OPEN_ACCESS}"
        ),
    )
    .unwrap();
    assert_eq!(config.auths[0].mode, "access_key");
    assert_eq!(config.auths[1].mode, "anonymous");
    assert_eq!(config.auths[1].endpoint, "https://storage.googleapis.com");
    let printed = format_effective(&config);
    for line in [
        "auth \"a\".mode = \"access_key\"  # default",
        "auth \"a\".access_key_id = \"k\"  # file",
        &format!("auth \"a\".secret_access_key = <hidden>  # file:{}", dir.join("secret")),
        "auth \"a\".session_token = <none>  # default",
        "auth \"g\".endpoint = \"https://storage.googleapis.com\"  # default",
        "auth \"g\".access_key_id = <none>  # default",
    ] {
        assert!(printed.contains(&format!("{line}\n")), "{line}\n{printed}");
    }
}

/// The two valid values of `bucket.encryption` are `sse-s3` and `""`. A bucket without the key has `""`.
#[test]
fn bucket_encryption_accepts_two_values() {
    for (lines, want) in [
        ("encryption = \"sse-s3\"", Encryption::SseS3),
        ("encryption = \"\"", Encryption::None),
        ("", Encryption::None),
        ("root_prefix = \"tenant/\"\nencryption = \"sse-s3\"", Encryption::SseS3),
    ] {
        let dir = TempDir::new();
        let config = load_in(&dir, &encryption_config(lines)).unwrap();
        assert_eq!(config.buckets[0].encryption, want, "{lines}");
    }
}

fn encryption_config(lines: &str) -> String {
    format!(
        "\nauth \"public\" {{\n  provider = \"s3\"\n  mode     = \"anonymous\"\n  endpoint = \"http://localhost:9000\"\n  region   = \"test\"\n}}\nbucket \"b\" {{\n  auth   = \"public\"\n  bucket = \"bucket\"\n{lines}\n}}\n{TEST_OPEN_ACCESS}"
    )
}

fn encryption_gcs_config(lines: &str) -> String {
    format!(
        "\nauth \"gcs\" {{\n  provider         = \"gcs\"\n  mode             = \"service_account\"\n  credentials_file = \"./gcs.json\"\n}}\nbucket \"b\" {{\n  auth   = \"gcs\"\n  bucket = \"bucket\"\n{lines}\n}}\n{TEST_OPEN_ACCESS}"
    )
}

/// Any other value stops the start. The server does not change the case and does not remove a space.
#[test]
fn bucket_encryption_refuses_other_values() {
    for value in [
        "SSE-S3", "sse-s3 ", " sse-s3", "aes256", "AES256", "sse-kms", "aws:kms", "sse-c",
    ] {
        let dir = TempDir::new();
        let result = load_in(&dir, &encryption_config(&format!("encryption = \"{value}\"")));
        let text = message(&result);
        for want in [
            "bucket \"b\".encryption",
            "\"sse-s3\"",
            &format!("got \"{value}\""),
            "SSE-C and SSE-KMS are not supported",
        ] {
            assert!(text.contains(want), "{value}: {text}");
        }
    }
}

/// A value that is not a string stops the start.
#[test]
fn bucket_encryption_refuses_a_wrong_kind() {
    for line in ["encryption = true", "encryption = 1", "encryption = [\"sse-s3\"]"] {
        let dir = TempDir::new();
        let result = load_in(&dir, &encryption_config(line));
        assert!(
            message(&result).contains("\"encryption\""),
            "{line}: {}",
            message(&result)
        );
    }
}

/// The GCS API has no SSE header: a gcs bucket with `encryption = "sse-s3"` stops the start.
#[test]
fn bucket_encryption_refuses_a_gcs_bucket() {
    let dir = TempDir::new();
    dir.write("gcs.json", "{\"type\":\"service_account\"}");
    let result = load_in(&dir, &encryption_gcs_config("encryption = \"sse-s3\""));
    let text = message(&result);
    for want in [
        "bucket \"b\".encryption = \"sse-s3\"",
        "needs an auth block with provider \"s3\"",
        "auth \"gcs\" has provider \"gcs\"",
    ] {
        assert!(text.contains(want), "{text}");
    }
    for line in ["", "encryption = \"\""] {
        let config = load_in(&dir, &encryption_gcs_config(line)).unwrap();
        assert_eq!(config.buckets[0].provider, "gcs");
        assert_eq!(config.buckets[0].encryption, Encryption::None);
    }
}

/// print-config shows the source of the key, and the reference documents it.
#[test]
fn bucket_encryption_is_in_the_key_table() {
    assert!(reference().contains("| `encryption` | text | \"\" |"));
    let dir = TempDir::new();
    let config = load_in(&dir, &encryption_config("encryption = \"sse-s3\"")).unwrap();
    assert!(format_effective(&config).contains("bucket \"b\".encryption = \"sse-s3\"  # file"));
    let config = load_in(&dir, &encryption_config("")).unwrap();
    assert!(format_effective(&config).contains("bucket \"b\".encryption = \"\"  # default"));
}

/// The key `server.frontend` does not exist: the schema is closed, so a configuration with it stops at start with
/// the error of an unknown attribute. The error names the key and its line.
#[test]
fn the_frontend_key_stops_the_start() {
    for value in ["default", "stowr"] {
        let dir = TempDir::new();
        let result = load_in(
            &dir,
            &format!(
                "server {{\n  frontend = \"{value}\"\n}}\n{}",
                minimal_test_config("bucket")
            ),
        );
        let text = message(&result);
        assert!(
            text.contains("unknown attribute \"frontend\" in server block"),
            "{text}"
        );
        assert!(text.contains("line 2:"), "{text}");
    }
}

/// The reference and print-config do not show the key `frontend`.
#[test]
fn the_frontend_key_is_not_in_the_key_table() {
    assert!(!reference().contains("`frontend`"));
    let dir = TempDir::new();
    let config = load_in(&dir, &minimal_test_config("bucket")).unwrap();
    assert!(!format_effective(&config).contains("frontend"));
}

#[test]
fn the_key_table_is_complete_and_has_no_duplicate() {
    use super::keys::{BLOCKS, FORM_ENV, FORM_FILE, FORM_VALUE, KEYS, attribute_names, key_of_attribute};
    let mut seen = std::collections::BTreeSet::new();
    for key in KEYS {
        assert!(
            seen.insert(format!("{}.{}", key.block, key.name)),
            "duplicate {}.{}",
            key.block,
            key.name
        );
        assert!(
            !key.description.is_empty() && !key.kind.is_empty() && key.forms != 0 && !key.default.is_empty(),
            "{}.{} is not complete",
            key.block,
            key.name
        );
        assert!(
            !(key.secret && key.forms & FORM_VALUE != 0),
            "the secret {}.{}",
            key.block,
            key.name
        );
        assert!(
            BLOCKS.iter().any(|block| block.path == key.block),
            "{}.{} has no block",
            key.block,
            key.name
        );
    }
    for block in ["access", "access.identity", "access.pdp"] {
        assert!(BLOCKS.iter().any(|known| known.path == block) && KEYS.iter().any(|key| key.block == block));
    }
    let (token, form) = key_of_attribute("access.pdp", b"token_env").unwrap();
    assert!(token.secret && token.forms == FORM_ENV | FORM_FILE && form == FORM_ENV);
    let names = attribute_names("access.pdp");
    assert!(!names.contains(&"token".to_owned()));
    assert!(names.contains(&"token_env".to_owned()) && names.contains(&"token_file".to_owned()));
    for (path, text) in [
        ("access.identity.max_age", super::DEFAULT_IDENTITY_MAX_AGE),
        ("access.identity.clock_skew", super::DEFAULT_IDENTITY_CLOCK_SKEW),
        ("access.pdp.timeout", super::DEFAULT_PDP_TIMEOUT),
        ("access.pdp.usage_timeout", super::DEFAULT_PDP_USAGE_TIMEOUT),
        ("access.pdp.cache_ttl", super::DEFAULT_PDP_CACHE_TTL),
    ] {
        let (block, name) = path.rsplit_once('.').unwrap();
        let key = KEYS.iter().find(|key| key.block == block && key.name == name).unwrap();
        assert_eq!(key.default, format!("\"{text}\""), "{path}");
        assert_eq!(key.kind, "duration", "{path}");
        assert!(super::parse_duration_text(text).is_ok(), "{path}");
    }
}

#[test]
fn identifiers_of_a_text_without_utf8_are_quoted_byte_by_byte() {
    let dir = TempDir::new();
    let mut text = b"server {\n  \xc3\xaa\xc3 = 1\n}\n".to_vec();
    text.extend_from_slice(minimal_test_config("b").as_bytes());
    let result = super::decode_with(&text, &dir.path().join("config.hcl"), dir.path(), &test_hooks());
    assert_eq!(
        message(&result),
        "line 2:3: unknown attribute \"ê\\xc3\" in server block"
    );
}
