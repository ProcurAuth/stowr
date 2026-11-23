// SPDX-License-Identifier: MIT OR Apache-2.0
//! The helpers of the tests of the configuration: temporary folders, the services of the tests (an environment of
//! the test, a reader of the public keys of the tests, a resolution of the paths of a volume), and the texts that the
//! tests share.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

use crate::common::config::Config;
use crate::common::error::{Error, Result};

use super::Hooks;
use super::env::Variable;

/// The access block of a test configuration that checks no identity token. A test adds it at the end of its text:
/// the line numbers of the other blocks do not change.
pub(super) const TEST_OPEN_ACCESS: &str = "\naccess {\n  mode = \"open\"\n}\n";

/// A configuration with an open access block, one anonymous S3 auth block and one bucket with the label `id`.
pub(super) fn minimal_test_config(id: &str) -> String {
    format!(
        "\naccess {{\n  mode = \"open\"\n}}\n\nauth \"public\" {{\n  provider = \"s3\"\n  mode     = \"anonymous\"\n  endpoint = \"http://localhost:9000\"\n  region   = \"test\"\n}}\n\nbucket \"{id}\" {{\n  auth   = \"public\"\n  bucket = \"bucket\"\n}}\n"
    )
}

/// A new empty folder. The drop removes it.
pub(super) struct TempDir {
    path: PathBuf,
}

impl TempDir {
    pub(super) fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default();
        let name = format!(
            "stowr-config-test-{}-{}-{nanos}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(name);
        std::fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    /// The path of a name in the folder, as text.
    pub(super) fn join(&self, name: &str) -> String {
        self.path.join(name).to_string_lossy().into_owned()
    }

    /// Write a file in the folder.
    pub(super) fn write(&self, name: &str, content: impl AsRef<[u8]>) {
        std::fs::write(self.path.join(name), content).unwrap();
    }

    /// Make a folder in the folder.
    pub(super) fn mkdir(&self, name: &str) {
        std::fs::create_dir_all(self.path.join(name)).unwrap();
    }

    /// The text of the path.
    pub(super) fn text(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn no_environment(_: &str) -> Variable {
    Variable::Missing
}

/// The services of the tests, with an empty environment.
pub(super) fn test_hooks() -> Hooks<'static> {
    Hooks {
        environment: &no_environment,
        public_keys: &fake_public_keys,
        resolve_inside: &fake_resolve_inside,
    }
}

/// Run `body` with the services of the tests and an environment with these variables.
pub(super) fn with_environment<T>(variables: &[(&str, &str)], body: impl FnOnce(&Hooks<'_>) -> T) -> T {
    let map: BTreeMap<String, String> = variables
        .iter()
        .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
        .collect();
    let read = move |name: &str| {
        map.get(name)
            .map_or(Variable::Missing, |value| Variable::Value(value.clone()))
    };
    let hooks = Hooks {
        environment: &read,
        ..test_hooks()
    };
    body(&hooks)
}

/// Decode a text as the file `config.hcl` of the folder, with the services of the tests.
pub(super) fn decode_in(dir: &TempDir, text: &str) -> Result<Config> {
    decode_in_with(dir, text, &test_hooks())
}

/// Decode a text as the file `config.hcl` of the folder.
pub(super) fn decode_in_with(dir: &TempDir, text: &str, hooks: &Hooks<'_>) -> Result<Config> {
    super::decode_with(text.as_bytes(), &dir.path().join("config.hcl"), dir.path(), hooks)
}

/// Write a text as the file `config.hcl` of the folder and load it, with the services of the tests.
pub(super) fn load_in(dir: &TempDir, text: &str) -> Result<Config> {
    dir.write("config.hcl", text);
    super::load_with(&dir.path().join("config.hcl"), &test_hooks())
}

/// The message of an error, or an empty text.
pub(super) fn message<T>(result: &Result<T>) -> String {
    match result {
        Ok(_) => String::new(),
        Err(error) => error.to_string(),
    }
}

// The keys of the tests: the Ed25519 key of RFC 8037, appendix A.3, and the P-256 key of RFC 7515, appendix A.3.

/// The `x` of the Ed25519 key of RFC 8037.
pub(super) const RFC8037_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
/// The RFC 7638 thumbprint of the Ed25519 key of RFC 8037.
pub(super) const RFC8037_THUMBPRINT: &str = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";
/// The `x` of the P-256 key of RFC 7515.
pub(super) const RFC7515_X: &str = "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU";
/// The `y` of the P-256 key of RFC 7515.
pub(super) const RFC7515_Y: &str = "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0";

const ED25519_PREFIX: &str = "302a300506032b6570032100";
const P256_PREFIX: &str = "3059301306072a8648ce3d020106082a8648ce3d03010703420004";

fn hex_bytes(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).unwrap())
        .collect()
}

/// An Ed25519 JWK. `extra` is more members, with a comma at the start.
pub(super) fn ed_jwk(extra: &str) -> String {
    format!("{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"{RFC8037_X}\"{extra}}}")
}

/// A P-256 JWK. `extra` is more members, with a comma at the start.
pub(super) fn ec_jwk(extra: &str) -> String {
    format!("{{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"{RFC7515_X}\",\"y\":\"{RFC7515_Y}\"{extra}}}")
}

/// A JWK Set with these keys.
pub(super) fn key_set(keys: &[String]) -> String {
    format!("{{\"keys\":[{}]}}", keys.join(","))
}

fn pem_block(der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect();
    format!(
        "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
        lines.join("\n")
    )
}

/// The Ed25519 key of RFC 8037 as PEM.
pub(super) fn rfc8037_pem() -> String {
    let mut der = hex_bytes(ED25519_PREFIX);
    der.extend(URL_SAFE_NO_PAD.decode(RFC8037_X).unwrap());
    pem_block(&der)
}

/// The P-256 key of RFC 7515 as PEM.
pub(super) fn rfc7515_pem() -> String {
    let mut der = hex_bytes(P256_PREFIX);
    der.extend(URL_SAFE_NO_PAD.decode(RFC7515_X).unwrap());
    der.extend(URL_SAFE_NO_PAD.decode(RFC7515_Y).unwrap());
    pem_block(&der)
}

fn thumbprint(canonical: &str) -> String {
    URL_SAFE_NO_PAD.encode(aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, canonical.as_bytes()).as_ref())
}

fn ed_thumbprint(x: &str) -> String {
    thumbprint(&format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{x}\"}}"))
}

fn ec_thumbprint(x: &str, y: &str) -> String {
    thumbprint(&format!(
        "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{x}\",\"y\":\"{y}\"}}"
    ))
}

/// The P-256 thumbprint of the key of RFC 7515.
pub(super) fn rfc7515_thumbprint() -> String {
    ec_thumbprint(RFC7515_X, RFC7515_Y)
}

/// A reader of the public keys for the tests. It gives the names that the reader of the access policy gives
/// (`Ed25519 kid=...`, `P-256 kid=...`) for the keys and the errors of these tests.
pub(super) fn fake_public_keys(text: &str) -> Result<Vec<String>> {
    if text.trim_start_matches([' ', '\t', '\r', '\n']).starts_with('{') {
        let set: serde_json::Value = serde_json::from_str(text)
            .map_err(|error| Error::internal(format!("the JWK Set is not valid JSON: {error}")))?;
        let keys = set
            .get("keys")
            .and_then(serde_json::Value::as_array)
            .ok_or_else(|| Error::internal("the JWK Set must have the member \"keys\""))?;
        let mut names = Vec::new();
        for (index, key) in keys.iter().enumerate() {
            let member = |name: &str| key.get(name).and_then(serde_json::Value::as_str).unwrap_or_default();
            let (kty, crv, x, y) = (member("kty"), member("crv"), member("x"), member("y"));
            let (kind, computed) = match (kty, crv) {
                ("OKP", "Ed25519") => ("Ed25519", ed_thumbprint(x)),
                ("EC", "P-256") => ("P-256", ec_thumbprint(x, y)),
                _ => {
                    return Err(Error::internal(format!(
                        "key {}: kty {kty:?} with crv {crv:?} is not supported; use kty \"OKP\" with crv \"Ed25519\", or kty \"EC\" with crv \"P-256\"",
                        index + 1
                    )));
                }
            };
            let kid = match member("kid") {
                "" => computed,
                kid => kid.to_owned(),
            };
            names.push(format!("{kind} kid={kid}"));
        }
        return Ok(names);
    }
    let mut names = Vec::new();
    let mut body: Option<String> = None;
    for (index, line) in text.split('\n').enumerate() {
        let line = line.trim_matches([' ', '\t', '\r']);
        match (&mut body, line) {
            (None, "") => {}
            (None, "-----BEGIN PUBLIC KEY-----") => body = Some(String::new()),
            (None, _) => {
                return Err(Error::internal(format!(
                    "line {} is not -----BEGIN PUBLIC KEY-----: give PEM public keys or a JWK Set",
                    index + 1
                )));
            }
            (Some(collected), "-----END PUBLIC KEY-----") => {
                let der = STANDARD
                    .decode(collected.as_bytes())
                    .map_err(|_| Error::internal(format!("key {} is not valid base64", names.len() + 1)))?;
                let hex: String = der.iter().map(|byte| format!("{byte:02x}")).collect();
                if let Some(x) = hex.strip_prefix(ED25519_PREFIX) {
                    names.push(format!(
                        "Ed25519 kid={}",
                        ed_thumbprint(&URL_SAFE_NO_PAD.encode(hex_bytes(x)))
                    ));
                } else if let Some(point) = hex.strip_prefix(P256_PREFIX) {
                    let bytes = hex_bytes(point);
                    let (x, y) = bytes.split_at(32);
                    names.push(format!(
                        "P-256 kid={}",
                        ec_thumbprint(&URL_SAFE_NO_PAD.encode(x), &URL_SAFE_NO_PAD.encode(y))
                    ));
                } else {
                    return Err(Error::internal(format!(
                        "key {} is not an Ed25519 public key or a P-256 public key with an uncompressed point (SubjectPublicKeyInfo)",
                        names.len() + 1
                    )));
                }
                body = None;
            }
            (Some(collected), _) => collected.push_str(line),
        }
    }
    if body.is_some() {
        return Err(Error::internal("-----END PUBLIC KEY----- is missing"));
    }
    if names.is_empty() {
        return Err(Error::internal(
            "no key: give at least one -----BEGIN PUBLIC KEY----- block, or a JWK Set",
        ));
    }
    Ok(names)
}

/// A resolution of a relative folder path inside the real root of a volume for the tests: each part must exist,
/// and a symbolic link must stay in the root.
pub(super) fn fake_resolve_inside(root: &Path, relative: &str) -> Result<PathBuf> {
    let mut current = root.to_path_buf();
    for part in relative.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(Error::internal("the path must not have an empty, \".\" or \"..\" part"));
        }
        let next = current.join(part);
        let info = std::fs::symlink_metadata(&next)
            .map_err(|error| Error::internal(super::oserror::path_error("lstat", &next, &error)))?;
        if info.file_type().is_symlink() {
            let target = std::fs::canonicalize(&next).map_err(|error| Error::internal(error.to_string()))?;
            if !target.starts_with(root) {
                return Err(Error::internal(
                    "the path has a symbolic link that Stowr does not follow: it leaves the volume, it does not resolve, or the access mode refuses each link",
                ));
            }
            current = target;
        } else {
            current = next;
        }
    }
    Ok(current)
}

#[test]
fn the_reader_of_the_tests_gives_the_names_of_the_keys() {
    assert_eq!(
        fake_public_keys(&rfc8037_pem()).unwrap(),
        vec![format!("Ed25519 kid={RFC8037_THUMBPRINT}")]
    );
    assert_eq!(
        fake_public_keys(&key_set(&[ed_jwk(""), ec_jwk(",\"kid\":\"edge-2\"")])).unwrap(),
        vec![
            format!("Ed25519 kid={RFC8037_THUMBPRINT}"),
            "P-256 kid=edge-2".to_owned()
        ]
    );
    assert_eq!(
        fake_public_keys(&rfc7515_pem()).unwrap(),
        vec![format!("P-256 kid={}", rfc7515_thumbprint())]
    );
}
