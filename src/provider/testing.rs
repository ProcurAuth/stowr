//! The helpers of the tests that use a provider back end: the configuration of an `auth` block and of a bucket, and a
//! back end over a local test server (refer to [`super::test_server`]).

use std::sync::Arc;

use super::client::StorageClient;
use super::url::BaseUrl;
use super::{GcsBackend, S3Backend, SharedAuth};
use crate::common::config::{AuthConfig, BucketConfig, Provider};

/// The configuration of an `auth` block of a test: id `test-s3` or `test-gcs`, region `test` for S3.
pub fn auth_config(provider: Provider, mode: &str, endpoint: &str) -> AuthConfig {
    AuthConfig {
        id: format!("test-{}", provider.as_str()),
        provider,
        mode: mode.to_owned(),
        endpoint: endpoint.to_owned(),
        region: if provider == Provider::S3 {
            "test".to_owned()
        } else {
            String::new()
        },
        ..AuthConfig::default()
    }
}

/// The configuration of the bucket `test-bucket` of an `auth` block.
pub fn bucket_config(auth: &AuthConfig, bucket: &str) -> BucketConfig {
    BucketConfig {
        id: "test-bucket".to_owned(),
        auth_id: auth.id.clone(),
        provider: auth.provider.as_str().to_owned(),
        region: auth.region.clone(),
        bucket: bucket.to_owned(),
        ..BucketConfig::default()
    }
}

/// The shared state of an `auth` block of a test, with the client of the module and the roots of the image.
pub fn shared_auth(cfg: &AuthConfig) -> Arc<SharedAuth> {
    let endpoint = BaseUrl::from_url(&cfg.endpoint).unwrap();
    let client = StorageClient::new(cfg.insecure_skip_verify).unwrap();
    Arc::new(SharedAuth::with_endpoint(cfg, endpoint, client).unwrap())
}

/// An S3 back end in mode `anonymous` (region `test`) on an endpoint.
pub fn anonymous_s3(endpoint: &str, bucket: &str) -> S3Backend {
    let cfg = auth_config(Provider::S3, "anonymous", endpoint);
    let auth = shared_auth(&cfg);
    S3Backend::new(bucket_config(&cfg, bucket), auth).unwrap()
}

/// An S3 back end in mode `access_key` (key `test-id`, secret `test-secret`, region `test`) on an endpoint.
pub fn signed_s3(endpoint: &str, bucket: &str) -> S3Backend {
    let mut cfg = auth_config(Provider::S3, "access_key", endpoint);
    cfg.access_key_id = "test-id".to_owned();
    cfg.secret_access_key = "test-secret".to_owned();
    let auth = shared_auth(&cfg);
    S3Backend::new(bucket_config(&cfg, bucket), auth).unwrap()
}

/// A GCS back end in mode `anonymous` on an endpoint.
pub fn anonymous_gcs(endpoint: &str, bucket: &str) -> GcsBackend {
    let cfg = auth_config(Provider::Gcs, "anonymous", endpoint);
    let auth = shared_auth(&cfg);
    GcsBackend::new(bucket_config(&cfg, bucket), auth).unwrap()
}
