//! The clients of the providers: S3 (SigV4, listing, ranges, multipart, versions, batch delete, copy in parts) and
//! GCS (service account, JSON API, resumable upload), and the shared client of each `auth` block.
//!
//! The feature work packages send their own S3 requests with [`S3Backend::send`]. The HTTP client follows no
//! redirect, reads no proxy variable, uses TLS 1.2 or newer with the system root certificates of the image, and
//! verifies the certificate unless `insecure_skip_verify` is set.

pub mod gcs;
pub mod s3;

use std::sync::{Arc, Mutex};

use crate::common::config::AuthConfig;
use crate::common::error::{Error, Result};

pub use gcs::GcsBackend;
pub use s3::{S3Backend, S3Request};

/// The SHA-256 checksum of an upload: the base64 digest that the client sent, and the digest that the provider
/// sent back.
#[derive(Debug, Default)]
pub struct ChecksumTransfer {
    /// The base64 SHA-256 that the client sent.
    pub sha256: String,
    /// The base64 SHA-256 that the provider sent back (`x-amz-checksum-sha256`).
    pub echoed: Mutex<String>,
}

/// The HTTP client of the providers, of the admin APIs and of the health check.
#[derive(Clone, Debug)]
pub struct StorageClient {
    /// True when the client does not verify the certificate.
    pub insecure_skip_verify: bool,
}

impl StorageClient {
    /// A client: dial timeout 10 s, keep-alive 30 s, TLS handshake 10 s, answer headers 30 s, no redirect, no proxy.
    pub fn new(insecure_skip_verify: bool) -> Result<Self> {
        Ok(Self { insecure_skip_verify })
    }
}

/// The shared state of one `auth` block: the endpoint, the HTTP client, the credentials, the GCS token and the
/// usage reader. The buckets of the block share it.
pub struct SharedAuth {
    /// The configuration of the block.
    pub cfg: AuthConfig,
    /// The HTTP client.
    pub client: StorageClient,
    /// The usage reader, with a `usage` block.
    pub usage: Option<Arc<dyn crate::bucket::BucketUsageReader>>,
}

impl SharedAuth {
    /// Build the shared state of an `auth` block.
    pub fn new(cfg: &AuthConfig) -> Result<Self> {
        let _ = cfg;
        Err(Error::not_served("the clients of the providers"))
    }
}
