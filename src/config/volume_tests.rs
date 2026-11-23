//! The tests of the `volume` block: the values, the defaults, the refusals and the folders of the start.

use crate::common::config::{PROVIDER_VOLUME, VOLUME_HOST_ID};

use super::format_effective;
use super::support_tests::{TEST_OPEN_ACCESS, TempDir, decode_in, message};

/// A configuration with one volume block whose attributes are the lines.
fn volume_config_text(lines: &str) -> String {
    format!("volume \"vol\" {{\n{lines}\n}}\n")
}

fn decode_volume(text: &str) -> crate::common::error::Result<crate::common::config::Config> {
    let dir = TempDir::new();
    decode_in(&dir, &format!("{text}{TEST_OPEN_ACCESS}"))
}

#[test]
fn a_volume_block_decodes_and_prints_its_keys() {
    let root = TempDir::new();
    root.mkdir("published");
    let config = decode_volume(&volume_config_text(&format!(
        "path = \"{}\"\nname = \"Shared files\"\npermissions = [\"read\", \"write\"]\nroot_prefix = \"published/\"\nmax_scan_pages = 3",
        root.text()
    )))
    .unwrap();
    assert_eq!(
        (config.volumes.len(), config.buckets.len(), config.auths.len()),
        (1, 0, 0)
    );
    let volume = &config.volumes[0];
    assert_eq!(volume.id, "vol");
    assert_eq!(volume.name, "Shared files");
    assert_eq!(volume.path, root.path());
    assert_eq!(volume.root_prefix, "published/");
    assert_eq!(volume.max_scan_pages, 3);
    assert!(volume.permissions_defined);
    assert_eq!(volume.permissions.join(","), "read,write");
    assert!(!volume.refuse_links);
    let bucket = volume.bucket_config();
    assert_eq!(bucket.provider, PROVIDER_VOLUME);
    assert_eq!(bucket.auth_id, VOLUME_HOST_ID);
    assert_eq!(bucket.root_prefix, "published/");
    let printed = format_effective(&config);
    for line in [
        "volume \"vol\".name = \"Shared files\"  # file".to_owned(),
        format!("volume \"vol\".path = \"{}\"  # file", root.text()),
        "volume \"vol\".permissions = [\"read\", \"write\"]  # file".to_owned(),
        "volume \"vol\".root_prefix = \"published/\"  # file".to_owned(),
        "volume \"vol\".max_scan_pages = 3  # file".to_owned(),
    ] {
        assert!(
            printed.contains(&format!("{line}\n")),
            "print-config has no line {line:?}:\n{printed}"
        );
    }
}

#[test]
fn volume_block_defaults() {
    let root = TempDir::new();
    let config = decode_volume(&volume_config_text(&format!("path = \"{}\"", root.text()))).unwrap();
    let volume = &config.volumes[0];
    assert_eq!(volume.name, "vol");
    assert_eq!(volume.root_prefix, "");
    assert_eq!(volume.max_scan_pages, 1);
    assert!(!volume.permissions_defined);
    assert!(volume.writes());
    let printed = format_effective(&config);
    for line in [
        "volume \"vol\".name = \"vol\"  # default",
        "volume \"vol\".permissions = <none>  # default",
        "volume \"vol\".root_prefix = \"\"  # default",
        "volume \"vol\".max_scan_pages = 1  # default",
    ] {
        assert!(
            printed.contains(&format!("{line}\n")),
            "print-config has no line {line:?}:\n{printed}"
        );
    }
}

/// A value that does not fit stops the start. The error names the key and the value.
#[test]
fn volume_values_stop_the_start() {
    let root = TempDir::new();
    root.write("a-file", "x");
    let file = root.join("a-file");
    let base = root.text();
    let path = format!("path = \"{base}\"\n");
    let bucket = "auth \"s3\" {\n  provider = \"s3\"\n  endpoint = \"http://localhost:9000\"\n  region = \"test\"\n}\n";
    let cases: Vec<(&str, String, String)> = vec![
        ("no path", volume_config_text("name = \"x\""), "volume \"vol\".path is required".to_owned()),
        ("relative path", volume_config_text("path = \"data/volume\""), "volume \"vol\".path must be an absolute path without \"/\" at the end and without an empty, \".\" or \"..\" part (for example \"/data/volume\"), got \"data/volume\"".to_owned()),
        ("path slash", volume_config_text(&format!("path = \"{base}/\"")), format!("got \"{base}/\"")),
        ("path dot dot", volume_config_text(&format!("path = \"{base}/../x\"")), format!("got \"{base}/../x\"")),
        ("path missing", volume_config_text(&format!("path = \"{base}/missing\"")), format!("volume \"vol\": path \"{base}/missing\" must be a folder that exists at start: stat {base}/missing: no such file or directory")),
        ("path file", volume_config_text(&format!("path = \"{file}\"")), format!("volume \"vol\": path \"{file}\" must be a folder, got a file")),
        ("path empty", volume_config_text("path = \"\""), "volume \"vol\".path must not be empty".to_owned()),
        ("path type", volume_config_text("path = 3"), "attribute \"path\" must be a quoted string".to_owned()),
        ("unknown attribute", volume_config_text(&format!("{path}bucket = \"x\"")), "unknown attribute \"bucket\" in volume block".to_owned()),
        ("duplicate key", volume_config_text(&format!("{path}{path}")), "duplicate attribute \"path\"".to_owned()),
        ("nested block", volume_config_text(&format!("{path}usage {{ source = \"garage\" }}")), "nested blocks are not supported inside volume".to_owned()),
        ("no label", format!("volume {{\n{path}}}\n"), "volume block requires exactly one quoted identifier".to_owned()),
        ("root prefix slash", volume_config_text(&format!("{path}root_prefix = \"/published/\"")), "volume \"vol\".root_prefix must be \"\" or a relative folder path that ends with \"/\"".to_owned()),
        ("root prefix no end", volume_config_text(&format!("{path}root_prefix = \"published\"")), "got \"published\"".to_owned()),
        ("root prefix dots", volume_config_text(&format!("{path}root_prefix = \"a/../b/\"")), "got \"a/../b/\"".to_owned()),
        ("root prefix gone", volume_config_text(&format!("{path}root_prefix = \"missing/\"")), format!("volume \"vol\": root_prefix \"missing/\": lstat {base}/missing: no such file or directory")),
        ("root prefix file", volume_config_text(&format!("{path}root_prefix = \"a-file/\"")), format!("volume \"vol\": root_prefix \"a-file/\" must be a folder in path \"{base}\", got a file")),
        ("permission case", volume_config_text(&format!("{path}permissions = [\"Read\"]")), "volume \"vol\".permissions must contain only \"read\", \"write\" and \"delete\", got \"Read\"".to_owned()),
        ("permission twice", volume_config_text(&format!("{path}permissions = [\"read\", \"read\"]")), "volume \"vol\".permissions contains \"read\" two times".to_owned()),
        ("scan pages", volume_config_text(&format!("{path}max_scan_pages = 1000001")), "volume \"vol\".max_scan_pages must be between 0 and 1000000, got 1000001".to_owned()),
        ("same label", format!("{bucket}bucket \"vol\" {{\n  auth = \"s3\"\n  bucket = \"b\"\n}}\n{}", volume_config_text(&path)), "duplicate bucket or volume id \"vol\"".to_owned()),
        ("label of a bucket after a volume", format!("{bucket}{}bucket \"vol\" {{\n  auth = \"s3\"\n  bucket = \"b\"\n}}\n", volume_config_text(&path)), "duplicate bucket id \"vol\"".to_owned()),
        ("auth label volume", format!("{}{}", bucket.replacen("auth \"s3\"", "auth \"volume\"", 1), volume_config_text(&path)), "auth \"volume\": the label \"volume\" is the address word of the volumes".to_owned()),
        ("nothing to show", String::new(), "at least one bucket block or one volume block is required".to_owned()),
        ("bucket without auth", format!("bucket \"b\" {{\n  auth = \"s3\"\n  bucket = \"b\"\n}}\n{}", volume_config_text(&path)), "at least one auth block is required".to_owned()),
        ("bad label", format!("volume \"a/b\" {{\n{path}}}\n"), "line 1:1: volume label must match ^(?:[A-Za-z0-9][A-Za-z0-9._-]*|-)$, got \"a/b\"".to_owned()),
    ];
    for (name, config, want) in cases {
        let result = decode_volume(&config);
        let error = message(&result);
        assert!(error.contains(&want), "{name}: error = {error:?}, want {want:?}");
    }
}

#[test]
fn a_volume_block_with_buckets() {
    let root = TempDir::new();
    let auth = "auth \"s3\" {\n  provider = \"s3\"\n  endpoint = \"http://localhost:9000\"\n  region = \"test\"\n}\n";
    let bucket = "bucket \"b\" {\n  auth = \"s3\"\n  bucket = \"b\"\n}\n";
    let volume = format!("volume \"vol\" {{\n  path = \"{}\"\n}}\n", root.text());
    let config = decode_volume(&format!("{auth}{bucket}{volume}")).unwrap();
    assert_eq!((config.buckets.len(), config.volumes.len()), (1, 1));
    // The label "volume" of an auth block is valid in a file without a volume block.
    let renamed = format!("{auth}{bucket}").replace("\"s3\"", "\"volume\"").replacen(
        "provider = \"volume\"",
        "provider = \"s3\"",
        1,
    );
    assert!(decode_volume(&renamed).is_ok(), "{}", message(&decode_volume(&renamed)));
}

#[test]
fn a_symbolic_link_of_the_root_prefix_must_stay_in_the_volume() {
    let root = TempDir::new();
    let outside = TempDir::new();
    root.mkdir("inside");
    std::os::unix::fs::symlink(root.path().join("inside"), root.path().join("near")).unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join("far")).unwrap();
    let block = |prefix: &str| volume_config_text(&format!("path = \"{}\"\nroot_prefix = \"{prefix}\"", root.text()));
    assert!(decode_volume(&block("near/")).is_ok());
    assert!(
        message(&decode_volume(&block("far/")))
            .contains("volume \"vol\": root_prefix \"far/\": the path has a symbolic link"),
        "{}",
        message(&decode_volume(&block("far/")))
    );
}

#[test]
fn a_folder_that_the_process_cannot_read_stops_the_start() {
    use std::os::unix::fs::PermissionsExt as _;
    let root = TempDir::new();
    root.mkdir("closed");
    let closed = root.path().join("closed");
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).unwrap();
    let readable = std::fs::read_dir(&closed).is_ok();
    let result = decode_volume(&volume_config_text(&format!("path = \"{}\"", closed.display())));
    std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o755)).unwrap();
    if readable {
        // The process runs as root: it reads each folder.
        assert!(result.is_ok());
        return;
    }
    assert_eq!(
        message(&result),
        format!(
            "line 1:1: volume \"vol\": the process cannot read the folder \"{0}\": open {0}: permission denied",
            closed.display()
        )
    );
}
