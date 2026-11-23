//! The clients of the providers: S3 (SigV4, listing, ranges, multipart, versions, batch delete, copy in parts) and
//! GCS (service account, JSON API, resumable upload), and the shared client of each `auth` block.
//!
//! The feature modules send their own S3 requests with [`S3Backend::send`]. The HTTP client follows no
//! redirect, reads no proxy variable, uses TLS 1.2 or newer with the system root certificates of the image, and
//! verifies the certificate unless `insecure_skip_verify` is set (refer to [`client`]).

pub mod client;
pub mod gcs;
pub use crate::common::md5;
pub mod s3;
pub mod url;
pub mod xml;

#[cfg(test)]
mod client_tests;
#[cfg(test)]
mod copy_tests;
#[cfg(test)]
mod gcs_tests;
#[cfg(test)]
mod s3_tests;
#[cfg(test)]
pub mod test_server;
#[cfg(test)]
pub mod testing;
#[cfg(test)]
mod tests;

use std::sync::{Arc, Mutex};

use crate::common::config::{AuthConfig, BucketConfig, Provider};
use crate::common::error::{Error, Result};

pub use client::{Answer, StorageClient};
pub use gcs::GcsBackend;
pub use s3::{S3Answer, S3Backend, S3Request};

use gcs::GcsTokenSource;
use s3::sigv4::Credentials;
use url::BaseUrl;

/// The SHA-256 checksum of an upload: the base64 digest that the client sent, and the digest that the provider
/// sent back.
///
/// The S3 back end reads it from the context ([`crate::common::ctx::OpCtx::checksum`]). A write or a part sends a
/// digest that is not empty as `x-amz-checksum-sha256`, and keeps the `x-amz-checksum-sha256` of the answer in
/// `echoed`. A multipart initiation with a transfer in its context asks for the algorithm `SHA256`.
#[derive(Debug, Default)]
pub struct ChecksumTransfer {
    /// The base64 SHA-256 that the client sent.
    pub sha256: String,
    /// The base64 SHA-256 that the provider sent back (`x-amz-checksum-sha256`).
    pub echoed: Mutex<String>,
}

/// The shared state of one `auth` block: the endpoint, the HTTP client, the credentials, the GCS token and the
/// usage reader. The buckets of the block share it, so they share one pool of connections and one token.
pub struct SharedAuth {
    /// The configuration of the block.
    pub cfg: AuthConfig,
    /// The HTTP client.
    pub client: StorageClient,
    /// The usage reader, with a `usage` block. It sends its admin requests with the client of the block.
    pub usage: Option<Arc<dyn crate::bucket::BucketUsageReader>>,
    endpoint: BaseUrl,
    gcs_token: Option<Arc<GcsTokenSource>>,
}

impl std::fmt::Debug for SharedAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedAuth")
            .field("cfg", &self.cfg)
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl SharedAuth {
    /// Build the shared state of an `auth` block: check the endpoint, make the client, check the S3 credentials,
    /// read the key of a GCS service account, and make the usage reader of a `usage` block.
    pub fn new(cfg: &AuthConfig) -> Result<Self> {
        let endpoint = crate::config::url::parse_endpoint(cfg.provider.as_str(), &cfg.endpoint)?;
        Self::with_endpoint(
            cfg,
            BaseUrl::from_endpoint(&endpoint),
            StorageClient::new(cfg.insecure_skip_verify)?,
        )
    }

    /// Build the shared state of an `auth` block with a checked endpoint and a client.
    pub fn with_endpoint(cfg: &AuthConfig, endpoint: BaseUrl, client: StorageClient) -> Result<Self> {
        let mut auth = Self {
            cfg: cfg.clone(),
            client,
            usage: None,
            endpoint,
            gcs_token: None,
        };
        match cfg.provider {
            Provider::S3 => {
                if cfg.mode == "access_key" && (cfg.access_key_id.is_empty() || cfg.secret_access_key.is_empty()) {
                    return Err(Error::internal(format!(
                        "auth {:?} contains incomplete S3 credentials",
                        cfg.id
                    )));
                }
            }
            Provider::Gcs => {
                if cfg.mode == "service_account" {
                    let path = cfg.credentials_file.clone().unwrap_or_default();
                    auth.gcs_token = Some(Arc::new(GcsTokenSource::load(&path, auth.client.clone())?));
                }
            }
        }
        let credentials = crate::bucket::AdminCredentials {
            access_key_id: cfg.access_key_id.clone(),
            secret_access_key: cfg.secret_access_key.clone(),
            session_token: cfg.session_token.clone(),
        };
        auth.usage = crate::bucket::new_usage_reader(cfg, Arc::new(auth.client.clone()), credentials)?;
        Ok(auth)
    }

    /// The base URL of the endpoint.
    pub fn endpoint(&self) -> &BaseUrl {
        &self.endpoint
    }

    /// The S3 credentials of the block (empty texts for a block without them).
    pub fn s3_credentials(&self) -> Credentials {
        Credentials {
            access_key_id: self.cfg.access_key_id.clone(),
            secret_access_key: self.cfg.secret_access_key.clone(),
            session_token: self.cfg.session_token.clone(),
        }
    }

    /// True when the requests carry a signature or a token: mode `access_key` or `service_account`.
    pub fn signs_requests(&self) -> bool {
        self.cfg.mode == "access_key" || self.cfg.mode == "service_account"
    }

    /// The token source of a GCS service account.
    pub(crate) fn gcs_token(&self) -> Option<&Arc<GcsTokenSource>> {
        self.gcs_token.as_ref()
    }
}

/// The error of a bucket that names an `auth` block of another provider.
pub(crate) fn wrong_provider(cfg: &BucketConfig, provider: &str) -> Error {
    Error::internal(format!("bucket {:?} requires {provider} authentication", cfg.id))
}
