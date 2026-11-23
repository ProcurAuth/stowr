//! The tests of the resume token: the form, the key, the limits of its life and the tokens of other versions.

use std::sync::Arc;

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use base64::Engine as _;

use super::session::UploadSession;
use super::target::{Targets, resume_material};
use super::test_fakes::{FakeTarget, FakeTargets, test_cipher_key};
use super::token::{
    RESUME_TOKEN_LIFETIME_SECONDS, ResumeDescriptor, derive_cipher_key, open_resume_token, seal_descriptor,
    seal_resume_token, upload_id_from_token,
};
use crate::common::config::{AuthConfig, Provider};
use crate::common::json;
use crate::common::time::Timestamp;

fn targets() -> FakeTargets {
    FakeTargets::new(vec![
        Arc::new(FakeTarget::new("rw", "s3", "tenant/")),
        Arc::new(FakeTarget::new("vol", "fs", "")),
    ])
}

fn at(text: &str) -> Timestamp {
    Timestamp::parse_rfc3339(text).unwrap()
}

fn descriptor(issued_at: i64) -> ResumeDescriptor {
    ResumeDescriptor {
        instance: "rw".to_owned(),
        key: "large.bin".to_owned(),
        provider: "s3".to_owned(),
        content_type: "application/octet-stream".to_owned(),
        total_size: 100,
        chunk_size: 50,
        provider_upload_id: "u-1".to_owned(),
        issued_at,
        expires_at: issued_at + RESUME_TOKEN_LIFETIME_SECONDS,
        ..ResumeDescriptor::default()
    }
}

fn sealed(descriptor: &ResumeDescriptor) -> String {
    seal_descriptor(&test_cipher_key(), &descriptor.instance, descriptor).unwrap()
}

/// Decrypt a token with a key. The function gives the JSON text of the descriptor.
fn decrypt(key: &[u8; 32], token: &str) -> String {
    let parts: Vec<&str> = token.split('.').collect();
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[2])
        .unwrap();
    let (nonce, cipher_text) = raw.split_at(NONCE_LEN);
    let cipher = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, key).unwrap());
    let mut buffer = cipher_text.to_vec();
    let plain = cipher
        .open_in_place(
            Nonce::try_assume_unique_for_key(nonce).unwrap(),
            Aad::from(format!("{}.{}", parts[0], parts[1]).as_bytes()),
            &mut buffer,
        )
        .unwrap();
    String::from_utf8(plain.to_vec()).unwrap()
}

/// A fixed token for the instance `rw` and the credentials `test-auth`. A change of the token format makes the test
/// fail.
const FIXED_TOKEN: &str = "stowr1.cnc.d-4Tf2XhubVF2RmA2A0W5eF1QWyHpOdX_DlQLY7a5NKbt6aXKeOiuggWxwO3hMHkc5CXJ1ZIwT2BGarXho1DoJ-CJ5XWC-ri6NlJvxjA6sdegE8XfXINzmL_oUj5_CP6gGs-MGoE1Z_-4F7oy_Urf5NxxDL8TV8ds6uAtSnMHLoK9VjY6pASOyFnKGgNNnlvn9uAzTc_ySTbPcEqQsSEFy6qVgI0ep1lnXfDdnLYYYtcHXL50Zpp-HI";

/// A fixed token whose descriptor has characters that the JSON form escapes, and a NUL in the session.
const FIXED_ESCAPED_TOKEN: &str = "stowr1.cnc.0JE-pS-XtHWFbk7OYg0IBm3XheBUOijw5LCFuh7rvihWV7GoIT1Xomp0pP0sSp_7c3U4d9yamqNrFv8MZeTdqhxoj9ILy_TXzJ8SC4LkbSwmFuvJcXx_BxaHni4FED1BkMhPDN3__ak6gGPZ9j7LHKleA25W7oDLn6zi5AE4muiAkaGHH-pW1yml4342T62PprM0gJptzO8-n93CxV3OmqcORZEaow";

#[test]
fn the_key_comes_from_the_domain_the_auth_label_and_the_secret_material() {
    assert_eq!(
        crate::common::misc::hex(&derive_cipher_key("test-auth", b"stable-test-secret\0")),
        "e1d943c734e601b1d7b1dcab52f76ea80a33206ecae52d868690ef626b584b84"
    );
    assert_ne!(derive_cipher_key("a", b"x"), derive_cipher_key("b", b"x"));
    assert_ne!(derive_cipher_key("a", b"x"), derive_cipher_key("a", b"y"));
}

#[test]
fn a_fixed_token_opens() {
    let (descriptor, target) = open_resume_token(FIXED_TOKEN, &targets(), at("2026-11-21T00:00:00Z")).unwrap();
    assert_eq!(target.id(), "rw");
    assert_eq!(
        descriptor,
        ResumeDescriptor {
            instance: "rw".to_owned(),
            key: "large.bin".to_owned(),
            provider: "s3".to_owned(),
            content_type: "application/octet-stream".to_owned(),
            total_size: 16_777_233,
            chunk_size: 16_777_216,
            provider_upload_id: "upload-1".to_owned(),
            session_url: String::new(),
            checksum: "sha256".to_owned(),
            issued_at: at("2026-11-20T10:00:00Z").secs,
            expires_at: at("2026-12-20T10:00:00Z").secs,
        }
    );
    assert_eq!(
        upload_id_from_token(FIXED_TOKEN),
        "upl_553565f583214b9b9baa6f795cc31dd9"
    );
}

#[test]
fn a_fixed_token_with_escaped_characters_opens() {
    let (descriptor, _) = open_resume_token(FIXED_ESCAPED_TOKEN, &targets(), at("2026-11-21T00:00:00Z")).unwrap();
    assert_eq!(descriptor.key, "a<b>&c.bin");
    assert_eq!(descriptor.session_url, "x\0y");
    assert_eq!(descriptor.content_type, "text/plain");
    assert_eq!(descriptor.chunk_size, 5 << 20);
    assert!(descriptor.provider_upload_id.is_empty() && descriptor.checksum.is_empty());
}

#[test]
fn the_descriptor_has_a_fixed_json_form() {
    let text = json::to_vec(&ResumeDescriptor {
        instance: "rw".to_owned(),
        key: "a<b>&c.bin".to_owned(),
        provider: "s3".to_owned(),
        content_type: "text/plain".to_owned(),
        total_size: 10,
        chunk_size: 5 << 20,
        session_url: "x\0y".to_owned(),
        issued_at: 1_795_168_800,
        expires_at: 1_797_760_800,
        ..ResumeDescriptor::default()
    })
    .unwrap();
    assert_eq!(
        String::from_utf8(text).unwrap(),
        r#"{"i":"rw","k":"a\u003cb\u003e\u0026c.bin","p":"s3","ct":"text/plain","s":10,"cs":5242880,"r":"x\u0000y","iat":1795168800,"exp":1797760800}"#
    );
}

#[test]
fn a_new_token_has_the_form_version_instance_sealed_and_a_fresh_nonce() {
    let first = sealed(&descriptor(1_795_168_800));
    let second = sealed(&descriptor(1_795_168_800));
    assert_ne!(first, second);
    let parts: Vec<&str> = first.split('.').collect();
    assert_eq!(parts.len(), 3);
    assert_eq!(parts[0], "stowr1");
    assert_eq!(
        base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap(),
        b"rw"
    );
    assert!(!first.contains('=') && !first.contains('+') && !first.contains('/'));
    let plain = decrypt(&test_cipher_key(), &first);
    assert!(plain.starts_with(
        r#"{"i":"rw","k":"large.bin","p":"s3","ct":"application/octet-stream","s":100,"cs":50,"u":"u-1","#
    ));
}

#[test]
fn a_session_makes_a_token_that_opens_with_the_same_coordinates() {
    let target = FakeTarget::new("rw", "s3", "tenant/");
    let created = at("2026-11-20T10:00:00Z");
    let upload = UploadSession {
        key: "dir/file.bin".to_owned(),
        provider: "s3".to_owned(),
        content_type: "text/plain".to_owned(),
        total_size: 7,
        chunk_size: 5 << 20,
        provider_upload_id: "abc".to_owned(),
        checksum: "sha256".to_owned(),
        created_at: created,
        ..UploadSession::default()
    };
    let token = seal_resume_token(&target, &upload, Timestamp::now()).unwrap();
    let (opened, _) = open_resume_token(&token, &targets(), created.plus_secs(60)).unwrap();
    assert_eq!(opened.key, "dir/file.bin");
    assert_eq!(opened.provider_upload_id, "abc");
    assert_eq!(opened.checksum, "sha256");
    assert_eq!(opened.issued_at, created.secs);
    assert_eq!(opened.expires_at, created.secs + RESUME_TOKEN_LIFETIME_SECONDS);
}

#[test]
fn a_token_that_is_not_valid_is_refused_with_its_own_code() {
    let registry = targets();
    let now = at("2026-11-21T00:00:00Z");
    let good = sealed(&descriptor(now.secs - 100));
    let mut flipped = good.clone().into_bytes();
    let last = flipped.len() - 2;
    flipped[last] = if flipped[last] == b'A' { b'B' } else { b'A' };
    let cases = [
        ("", 400, "invalid_resume_token"),
        ("stowr1", 400, "invalid_resume_token"),
        ("stowr2.cnc.AAAA", 400, "invalid_resume_token"),
        ("stowr1.cnc.AAAA.extra", 400, "invalid_resume_token"),
        ("stowr1.!!!.AAAA", 400, "invalid_resume_token"),
        ("stowr1.cnc.!!!", 400, "invalid_resume_token"),
        ("stowr1.cnc.AAAA", 400, "invalid_resume_token"),
        ("stowr1.bm9wZQ.AAAA", 404, "unknown_instance"),
        (std::str::from_utf8(&flipped).unwrap(), 400, "invalid_resume_token"),
    ];
    for (token, status, code) in cases {
        let error = open_resume_token(token, &registry, now).map(|_| ()).unwrap_err();
        assert_eq!((error.status(), error.code().as_str()), (status, code), "{token:?}");
    }
    let error = open_resume_token(std::str::from_utf8(&flipped).unwrap(), &registry, now)
        .map(|_| ())
        .unwrap_err();
    assert_eq!(error.public_message(), "upload resume token could not be verified");
    assert!(open_resume_token(&format!("  {good}  "), &registry, now).is_ok());
}

#[test]
fn a_token_of_another_key_or_another_instance_does_not_open() {
    let registry = targets();
    let now = at("2026-11-21T00:00:00Z");
    let foreign = seal_descriptor(&[1; 32], "rw", &descriptor(now.secs)).unwrap();
    assert_eq!(
        open_resume_token(&foreign, &registry, now)
            .map(|_| ())
            .unwrap_err()
            .code(),
        "invalid_resume_token"
    );
    // A token sealed for the instance `rw` but with the name of `vol` in its text.
    let good = sealed(&descriptor(now.secs));
    let parts: Vec<&str> = good.split('.').collect();
    let moved = format!(
        "stowr1.{}.{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode("vol"),
        parts[2]
    );
    assert_eq!(
        open_resume_token(&moved, &registry, now)
            .map(|_| ())
            .unwrap_err()
            .code(),
        "invalid_resume_token"
    );
}

#[test]
fn a_descriptor_that_does_not_match_the_storage_is_refused() {
    let registry = targets();
    let now = at("2026-11-21T00:00:00Z");
    type Change = Box<dyn Fn(&mut ResumeDescriptor)>;
    let changes: Vec<Change> = vec![
        Box::new(|value| value.provider = "gcs".to_owned()),
        Box::new(|value| value.key = "/".to_owned()),
        Box::new(|value| value.key.clear()),
        Box::new(|value| value.total_size = -1),
        Box::new(|value| value.instance = "vol".to_owned()),
    ];
    for change in changes {
        let mut value = descriptor(now.secs);
        change(&mut value);
        let token = seal_descriptor(&test_cipher_key(), "rw", &value).unwrap();
        let error = open_resume_token(&token, &registry, now).map(|_| ()).unwrap_err();
        assert_eq!(error.code(), "invalid_resume_token");
        assert_eq!(
            error.public_message(),
            "upload resume token does not match the configured storage"
        );
    }
}

#[test]
fn the_life_of_a_token_is_30_days_with_a_skew_of_5_minutes() {
    let registry = targets();
    let now = at("2026-11-21T00:00:00Z");
    let open = |value: ResumeDescriptor| {
        let token = seal_descriptor(&test_cipher_key(), "rw", &value).unwrap();
        open_resume_token(&token, &registry, now).map(|_| ())
    };
    let issued = now.secs - 1000;
    assert!(open(descriptor(issued)).is_ok());
    // The end of the life is the second of `exp`: the token is valid until then.
    assert!(
        open(ResumeDescriptor {
            expires_at: now.secs,
            ..descriptor(issued)
        })
        .is_ok()
    );
    let expired = [
        ResumeDescriptor {
            expires_at: now.secs - 1,
            ..descriptor(issued)
        },
        descriptor(now.secs - RESUME_TOKEN_LIFETIME_SECONDS - 10),
        descriptor(now.secs + 301),
        ResumeDescriptor {
            expires_at: issued - 1,
            ..descriptor(issued)
        },
        ResumeDescriptor {
            expires_at: issued + RESUME_TOKEN_LIFETIME_SECONDS + 1,
            ..descriptor(issued)
        },
        ResumeDescriptor {
            issued_at: 0,
            ..descriptor(issued)
        },
        ResumeDescriptor {
            expires_at: 0,
            ..descriptor(issued)
        },
    ];
    for value in expired {
        let error = open(value.clone()).unwrap_err();
        assert_eq!(
            (error.status(), error.code().as_str()),
            (410, "resume_token_expired"),
            "{value:?}"
        );
        assert_eq!(error.public_message(), "upload resume token has expired");
    }
    assert!(open(descriptor(now.secs + 299)).is_ok());
}

#[test]
fn a_token_that_uses_every_character_of_the_alphabet_keeps_the_instance_name() {
    let registry = FakeTargets::new(vec![Arc::new(FakeTarget::new("wé/ird id", "s3", ""))]);
    let value = ResumeDescriptor {
        instance: "wé/ird id".to_owned(),
        ..descriptor(Timestamp::now().secs)
    };
    let token = seal_descriptor(&test_cipher_key(), "wé/ird id", &value).unwrap();
    let (opened, target) = open_resume_token(&token, &registry, Timestamp::now()).unwrap();
    assert_eq!(opened.instance, "wé/ird id");
    assert_eq!(target.id(), "wé/ird id");
    assert!(registry.target("rw").is_none());
}

fn auth(provider: Provider, secret: &str, session: &str) -> AuthConfig {
    AuthConfig {
        id: "a".to_owned(),
        provider,
        secret_access_key: secret.to_owned(),
        session_token: session.to_owned(),
        ..AuthConfig::default()
    }
}

#[test]
fn the_material_of_an_s3_block_is_the_secret_and_the_session_token() {
    let process = [9u8; 32];
    assert_eq!(
        resume_material(Some(&auth(Provider::S3, "secret", "session")), &process),
        b"secret\0session"
    );
    // An anonymous S3 block has the material `\0`, not the key of the process.
    assert_eq!(resume_material(Some(&auth(Provider::S3, "", "")), &process), b"\0");
    assert_eq!(resume_material(None, &process), process.to_vec());
    // A GCS block without a readable service account falls back to the key of the process.
    assert_eq!(
        resume_material(Some(&auth(Provider::Gcs, "", "")), &process),
        process.to_vec()
    );
}

#[test]
fn the_material_of_a_gcs_block_is_the_e_mail_and_the_private_key_of_its_service_account() {
    let process = [9u8; 32];
    let path = std::env::temp_dir().join(format!("stowr-uploads-account-{}.json", std::process::id()));
    std::fs::write(
        &path,
        r#"{"type":"service_account","client_email":"robot@example.test","private_key":"KEY TEXT","token_uri":"x"}"#,
    )
    .unwrap();
    let mut config = auth(Provider::Gcs, "", "");
    config.credentials_file = Some(path.clone());
    assert_eq!(
        resume_material(Some(&config), &process),
        b"robot@example.test\0KEY TEXT"
    );
    std::fs::remove_file(&path).unwrap();
    // The process reads the file one time, as the token source of the provider does at start.
    assert_eq!(
        resume_material(Some(&config), &process),
        b"robot@example.test\0KEY TEXT"
    );
    let mut missing = auth(Provider::Gcs, "", "");
    missing.credentials_file = Some(path.with_extension("missing"));
    assert_eq!(resume_material(Some(&missing), &process), process.to_vec());
}

#[test]
fn the_application_derives_the_key_of_a_target_from_its_auth_label() {
    let app = super::test_fakes::test_app(None);
    let target = app.target("rw").unwrap();
    // The instances of this application have no credentials: the key of the process gives the key of the cipher.
    assert_eq!(target.cipher_key(), derive_cipher_key("test-auth", &[7; 32]));
    assert_eq!(target.provider(), "s3");
    assert_eq!(target.full_key("a/b"), "tenant/a/b");
    assert_eq!(target.relative_key("tenant/a/b").as_deref(), Some("a/b"));
    assert_eq!(target.relative_key("other/a"), None);
    assert!(app.target("none").is_none());
}
