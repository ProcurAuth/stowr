//! The tests of the provider clients that write a key file in a temporary folder: the shared state of an `auth`
//! block and the service account of GCS.

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use aws_lc_rs::encoding::AsDer as _;
use aws_lc_rs::rsa::{KeyPair, KeySize};
use aws_lc_rs::signature::KeyPair as _;
use aws_lc_rs::signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};

use super::gcs::OAUTH_SCOPE;
use super::test_server::{Problems, TestResponse, TestServer};
use super::testing::{auth_config, bucket_config, shared_auth};
use super::{GcsBackend, S3Backend, SharedAuth, StorageClient};
use crate::common::config::Provider;
use crate::common::ctx::OpCtx;
use crate::common::query::Query;
use crate::common::storage::{Backend, ListOptions};

/// A file in the temporary folder of the system, removed at the end of the test.
struct TempFile(PathBuf);

impl TempFile {
    fn new(name: &str, data: &[u8]) -> Self {
        let mut random = [0u8; 8];
        crate::common::misc::random_bytes(&mut random).unwrap();
        let path = std::env::temp_dir().join(format!("{}-{name}", crate::common::misc::hex(&random)));
        std::fs::write(&path, data).unwrap();
        Self(path)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn pem(label: &str, der: &[u8]) -> String {
    let encoded = STANDARD.encode(der);
    let lines: Vec<&str> = encoded
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect();
    format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", lines.join("\n"))
}

fn service_account(key: &KeyPair, token_uri: &str) -> Vec<u8> {
    let der = key.as_der().unwrap();
    serde_json::to_vec(&serde_json::json!({
        "type": "service_account",
        "project_id": "test-project",
        "private_key_id": "test-key",
        "private_key": pem("PRIVATE KEY", der.as_ref()),
        "client_email": "browser@test-project.iam.gserviceaccount.com",
        "token_uri": token_uri,
    }))
    .unwrap()
}

/// Check the JWT of a token request: the header, the claims and the RS256 signature.
fn check_assertion(assertion: &str, public_key: &[u8], audience: &str) -> Result<(), String> {
    let parts: Vec<&str> = assertion.split('.').collect();
    if parts.len() != 3 {
        return Err(format!("JWT parts = {}", parts.len()));
    }
    let decode = |value: &str| URL_SAFE_NO_PAD.decode(value).map_err(|error| error.to_string());
    let header: serde_json::Value = serde_json::from_slice(&decode(parts[0])?).map_err(|error| error.to_string())?;
    if header["alg"] != "RS256" || header["kid"] != "test-key" || header["typ"] != "JWT" {
        return Err(format!("JWT header = {header}"));
    }
    let claims: serde_json::Value = serde_json::from_slice(&decode(parts[1])?).map_err(|error| error.to_string())?;
    if claims["aud"] != audience
        || claims["scope"] != OAUTH_SCOPE
        || claims["iss"] != "browser@test-project.iam.gserviceaccount.com"
        || claims["exp"].as_i64().unwrap_or(0) - claims["iat"].as_i64().unwrap_or(0) != 3600
    {
        return Err(format!("JWT claims = {claims}"));
    }
    let unsigned = format!("{}.{}", parts[0], parts[1]);
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public_key)
        .verify(unsigned.as_bytes(), &decode(parts[2])?)
        .map_err(|_| "the JWT signature does not verify".to_owned())
}

#[tokio::test]
async fn a_service_account_signs_its_token_request_and_the_permission_probe_uses_the_token() {
    let key = KeyPair::generate(KeySize::Rsa2048).unwrap();
    let public_key = key.public_key().as_ref().to_vec();
    let problems = Arc::new(Problems::default());
    let token_calls = Arc::new(AtomicUsize::new(0));
    let address: Arc<OnceLock<String>> = Arc::new(OnceLock::new());
    let (seen, calls, base) = (problems.clone(), token_calls.clone(), address.clone());
    let server = TestServer::start(move |request| match request.path.as_str() {
        "/token" => {
            calls.fetch_add(1, Ordering::SeqCst);
            let form = Query::parse(&request.text());
            if form.get("grant_type") != "urn:ietf:params:oauth:grant-type:jwt-bearer" {
                seen.report(format!("grant_type = {:?}", form.get("grant_type")));
            }
            let audience = format!("{}/token", base.get().unwrap());
            if let Err(problem) = check_assertion(form.get("assertion"), &public_key, &audience) {
                seen.report(problem);
            }
            TestResponse::body(200, r#"{"access_token":"test-token","expires_in":3600,"token_type":"Bearer"}"#)
                .header("content-type", "application/json")
        }
        "/storage/v1/b/test-bucket/iam/testPermissions" => {
            if request.header("authorization") != "Bearer test-token" {
                seen.report(format!("Authorization = {:?}", request.header("authorization")));
            }
            let mut permissions = request.query.values("permissions");
            permissions.sort_unstable();
            if permissions.join(",")
                != "storage.objects.create,storage.objects.delete,storage.objects.get,storage.objects.list"
            {
                seen.report(format!("permissions = {permissions:?}"));
            }
            TestResponse::body(
                200,
                r#"{"permissions":["storage.objects.list","storage.objects.get","storage.objects.create"]}"#,
            )
        }
        "/storage/v1/b/test-bucket/o" => {
            if request.header("authorization") != "Bearer test-token" {
                seen.report(format!("Authorization = {:?}", request.header("authorization")));
            }
            TestResponse::body(
                200,
                r#"{"items":[{"name":"folder/file.txt","size":"12","updated":"2026-01-02T03:04:05Z","etag":"etag","contentType":"text/plain"}]}"#,
            )
        }
        other => {
            seen.report(format!("unexpected request: {} {other}", request.method));
            TestResponse::status(404)
        }
    })
    .await;
    address.set(server.url.clone()).unwrap();
    let file = TempFile::new(
        "service-account.json",
        &service_account(&key, &format!("{}/token", server.url)),
    );
    let mut cfg = auth_config(Provider::Gcs, "service_account", &server.url);
    cfg.credentials_file = Some(file.0.clone());
    let auth = shared_auth(&cfg);
    let backend = GcsBackend::new(bucket_config(&cfg, "test-bucket"), auth).unwrap();
    let ctx = OpCtx::default();
    let found = backend.discover_capabilities(&ctx).await.unwrap();
    assert!(found.states["read"].allowed && found.states["read"].verified);
    assert!(found.states["write"].allowed);
    assert!(!found.states["delete"].allowed && found.states["delete"].verified);
    assert_eq!(
        found.permissions,
        vec![
            "storage.objects.create".to_owned(),
            "storage.objects.get".to_owned(),
            "storage.objects.list".to_owned(),
        ]
    );
    let options = ListOptions {
        prefix: "folder/".to_owned(),
        max_results: 10,
        ..ListOptions::default()
    };
    let page = backend.list(&ctx, &options).await.unwrap();
    assert_eq!(page.objects.len(), 1);
    assert_eq!(page.objects[0].key, "folder/file.txt");
    assert_eq!(page.objects[0].size, 12);
    assert_eq!(token_calls.load(Ordering::SeqCst), 1);
    problems.check();
}

#[tokio::test]
async fn a_token_endpoint_error_stops_the_request() {
    let key = KeyPair::generate(KeySize::Rsa2048).unwrap();
    let server = TestServer::start(|request| match request.path.as_str() {
        "/token" => TestResponse::body(401, " invalid_grant "),
        _ => TestResponse::status(500),
    })
    .await;
    let file = TempFile::new("account.json", &service_account(&key, &format!("{}/token", server.url)));
    let mut cfg = auth_config(Provider::Gcs, "service_account", &server.url);
    cfg.credentials_file = Some(file.0.clone());
    let backend = GcsBackend::new(bucket_config(&cfg, "bucket"), shared_auth(&cfg)).unwrap();
    let error = backend
        .list(&OpCtx::default(), &ListOptions::default())
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "gcs token endpoint returned HTTP 401: invalid_grant");
    assert_eq!(error.public_message(), "the storage provider operation failed");
}

fn load_error(data: &[u8]) -> String {
    let file = TempFile::new("account.json", data);
    let mut cfg = auth_config(Provider::Gcs, "service_account", "https://storage.googleapis.com");
    cfg.credentials_file = Some(file.0.clone());
    let endpoint = super::url::BaseUrl::from_url(&cfg.endpoint).unwrap();
    let client = StorageClient::new(false).unwrap();
    SharedAuth::with_endpoint(&cfg, endpoint, client)
        .unwrap_err()
        .to_string()
}

#[test]
fn a_bad_key_file_stops_the_start() {
    assert!(load_error(b"not json").starts_with("decode gcs credentials file "));
    assert!(load_error(br#"{"type":"user"}"#).ends_with("is not a service_account key"));
    assert!(
        load_error(br#"{"type":"service_account","client_email":"a"}"#)
            .ends_with("is missing client_email, private_key or token_uri")
    );
    let no_pem = br#"{"type":"service_account","client_email":"a","private_key":"nothing","token_uri":"https://t"}"#;
    assert!(load_error(no_pem).ends_with("contains an invalid PEM private key"));
    let ec_key =
        aws_lc_rs::signature::EcdsaKeyPair::generate(&aws_lc_rs::signature::ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
    let ec_der = ec_key.to_pkcs8v1().unwrap();
    let ec_file = serde_json::to_vec(&serde_json::json!({
        "type": "service_account",
        "client_email": "a",
        "private_key": pem("PRIVATE KEY", ec_der.as_ref()),
        "token_uri": "https://t",
    }))
    .unwrap();
    assert_eq!(load_error(&ec_file), "gcs private key is not RSA");
    let junk = serde_json::to_vec(&serde_json::json!({
        "type": "service_account",
        "client_email": "a",
        "private_key": pem("RSA PRIVATE KEY", b"junk"),
        "token_uri": "https://t",
    }))
    .unwrap();
    assert_eq!(load_error(&junk), "parse gcs RSA private key: unsupported key encoding");
    let missing = std::env::temp_dir().join("a-key-file-that-does-not-exist.json");
    let mut cfg = auth_config(Provider::Gcs, "service_account", "https://storage.googleapis.com");
    cfg.credentials_file = Some(missing.clone());
    let error = SharedAuth::with_endpoint(
        &cfg,
        super::url::BaseUrl::from_url(&cfg.endpoint).unwrap(),
        StorageClient::new(false).unwrap(),
    )
    .unwrap_err();
    assert_eq!(
        error.to_string(),
        format!(
            "open gcs credentials file {:?}: open {}: no such file or directory",
            missing.display().to_string(),
            missing.display()
        )
    );
    let large = vec![b' '; (4 << 20) + 1];
    assert!(load_error(&large).ends_with("exceeds the 4194304-byte limit"));
}

#[test]
fn a_bucket_needs_an_auth_block_of_its_provider_and_complete_credentials() {
    let s3 = auth_config(Provider::S3, "anonymous", "http://127.0.0.1:9000");
    let gcs = auth_config(Provider::Gcs, "anonymous", "http://127.0.0.1:4443");
    let error = GcsBackend::new(bucket_config(&s3, "b"), shared_auth(&s3)).unwrap_err();
    assert_eq!(
        error.to_string(),
        "bucket \"test-bucket\" requires a GCS authentication"
    );
    let error = S3Backend::new(bucket_config(&gcs, "b"), shared_auth(&gcs)).unwrap_err();
    assert_eq!(
        error.to_string(),
        "bucket \"test-bucket\" requires an S3 authentication"
    );
    let mut incomplete = auth_config(Provider::S3, "access_key", "http://127.0.0.1:9000");
    incomplete.access_key_id = "id".to_owned();
    let error = SharedAuth::with_endpoint(
        &incomplete,
        super::url::BaseUrl::from_url(&incomplete.endpoint).unwrap(),
        StorageClient::new(false).unwrap(),
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "auth \"test-s3\" contains incomplete S3 credentials");
    let auth = shared_auth(&s3);
    assert_eq!(auth.endpoint().authority, "127.0.0.1:9000");
    assert!(!auth.signs_requests());
}
