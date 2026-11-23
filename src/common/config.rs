// SPDX-License-Identifier: MIT OR Apache-2.0
//! The typed configuration.
//!
//! The module `config` reads the HCL file one time at start into these structures. The rest of the program
//! reads only these structures (docs/CONFIGURATION.md, docs/configuration-reference.md). The structures follow the
//! schema of the file: change the two together.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

/// The permission `read`.
pub const PERMISSION_READ: &str = "read";
/// The permission `write`.
pub const PERMISSION_WRITE: &str = "write";
/// The permission `delete`.
pub const PERMISSION_DELETE: &str = "delete";
/// The provider of the instance of a volume block.
pub const PROVIDER_VOLUME: &str = "fs";
/// The host word of each volume in the address of the interface (`/-/volume/<id>/`).
pub const VOLUME_HOST_ID: &str = "volume";

/// The whole configuration.
#[derive(Clone, Debug, Default)]
pub struct Config {
    /// `server.listen`: a numeric `host:port`.
    pub listen: String,
    /// `server.job_history_limit`.
    pub job_history_limit: u32,
    /// The other keys of the `server` block.
    pub runtime: RuntimePolicy,
    /// The `access` block.
    pub access: AccessConfig,
    /// The `auth` blocks, in the order of the file.
    pub auths: Vec<AuthConfig>,
    /// The `bucket` blocks, in the order of the file.
    pub buckets: Vec<BucketConfig>,
    /// The `volume` blocks, in the order of the file.
    pub volumes: Vec<VolumeConfig>,
    /// The folder of the configuration file: a relative path of the file starts there.
    pub source_dir: PathBuf,
    /// The absolute path of the configuration file.
    pub source_name: PathBuf,
    /// The source of each key that the file sets: `file`, `env:VAR` or `file:/path`. The name is the path of the key,
    /// for example `auth "s3".secret_access_key`. A key that is not in the map has its default.
    pub sources: BTreeMap<String, String>,
    /// The text of each duration key of the access block, as the file writes it or as the default is.
    pub duration_texts: BTreeMap<String, String>,
}

/// `server.access_mode`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AccessMode {
    /// `inherit_credentials` (the default).
    #[default]
    InheritCredentials,
    /// `force_read_only`: each write and each delete is refused.
    ForceReadOnly,
}

impl AccessMode {
    /// The text of the file.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::InheritCredentials => "inherit_credentials",
            Self::ForceReadOnly => "force_read_only",
        }
    }
}

/// `server.log_mode`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum LogMode {
    /// `anonymous` (the default): no object key in the request log.
    #[default]
    Anonymous,
    /// `detailed`.
    Detailed,
}

impl LogMode {
    /// The text of the file.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Anonymous => "anonymous",
            Self::Detailed => "detailed",
        }
    }
}

/// The limits of the process: the keys of the `server` block other than `listen` and `job_history_limit`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimePolicy {
    /// `access_mode`.
    pub access_mode: AccessMode,
    /// `allow_full_object_fallback`.
    pub allow_full_object_fallback: bool,
    /// `log_mode`.
    pub log_mode: LogMode,
    /// `memory_limit_bytes`. 0: no limit.
    pub memory_limit_bytes: i64,
    /// `max_storage_bytes_per_request`.
    pub max_storage_bytes_per_request: i64,
    /// `max_storage_requests_per_request`.
    pub max_storage_requests_per_request: i64,
    /// `max_range_cache_bytes`.
    pub max_range_cache_bytes: i64,
    /// `max_concurrent_storage_requests`.
    pub max_concurrent_storage_requests: u32,
    /// `max_concurrent_requests_per_storage`.
    pub max_concurrent_requests_per_storage: u32,
    /// `session_ttl_seconds`.
    pub session_ttl_seconds: u32,
    /// `max_stats_folders`.
    pub max_stats_folders: u32,
    /// `max_archive_entries`.
    pub max_archive_entries: u32,
    /// `max_background_storage_bytes`.
    pub max_background_storage_bytes: i64,
    /// `max_background_storage_requests`.
    pub max_background_storage_requests: i64,
}

impl Default for RuntimePolicy {
    fn default() -> Self {
        Self {
            access_mode: AccessMode::InheritCredentials,
            allow_full_object_fallback: false,
            log_mode: LogMode::Anonymous,
            memory_limit_bytes: 0,
            max_storage_bytes_per_request: 256 << 30,
            max_storage_requests_per_request: 4096,
            max_range_cache_bytes: 8 << 20,
            max_concurrent_storage_requests: 4,
            max_concurrent_requests_per_storage: 2,
            session_ttl_seconds: 20 * 60,
            max_stats_folders: 1000,
            max_archive_entries: 10_000,
            max_background_storage_bytes: 256 << 30,
            max_background_storage_requests: 100_000,
        }
    }
}

impl RuntimePolicy {
    /// True with `access_mode = "force_read_only"`.
    pub fn force_read_only(&self) -> bool {
        self.access_mode == AccessMode::ForceReadOnly
    }

    /// The life of a preview session.
    pub fn session_ttl(&self) -> Duration {
        Duration::from_secs(u64::from(self.session_ttl_seconds))
    }
}

/// `access.mode`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum AccessPolicy {
    /// `open`: no token check and no PDP.
    #[default]
    Open,
    /// `authzen`: the identity token and the PDP.
    AuthZen,
}

/// The `access` block.
#[derive(Clone, Debug, Default)]
pub struct AccessConfig {
    /// `mode`.
    pub mode: AccessPolicy,
    /// The `identity` block. `Some` with mode `authzen` only.
    pub identity: Option<IdentityConfig>,
    /// The `pdp` block. `Some` with mode `authzen` only.
    pub pdp: Option<PdpConfig>,
}

impl AccessConfig {
    /// True with mode `authzen`: the server checks the identity token and asks the PDP.
    pub fn enforced(&self) -> bool {
        self.mode == AccessPolicy::AuthZen
    }

    /// The id of the service (`identity.audience`), or an empty text in mode `open`.
    pub fn audience(&self) -> &str {
        self.identity.as_ref().map_or("", |identity| identity.audience.as_str())
    }
}

/// The `access.identity` block.
#[derive(Clone, Debug, Default)]
pub struct IdentityConfig {
    /// `header`.
    pub header: String,
    /// `issuer`.
    pub issuer: String,
    /// `audience`: the id of the service.
    pub audience: String,
    /// The text of `public_keys` (PEM or a JWK Set), as the file or its source gives it.
    pub public_keys_text: String,
    /// The short name of each key for print-config and the log, for example `Ed25519 kid=...`.
    pub key_names: Vec<String>,
    /// `max_age`.
    pub max_age: Duration,
    /// `clock_skew`.
    pub clock_skew: Duration,
}

/// The `access.pdp` block.
#[derive(Clone, Default)]
pub struct PdpConfig {
    /// `url`.
    pub url: String,
    /// `plain_http`.
    pub plain_http: bool,
    /// `token`: a secret. Its debug text never shows it.
    pub token: String,
    /// `timeout`.
    pub timeout: Duration,
    /// `usage_timeout`.
    pub usage_timeout: Duration,
    /// `cache_ttl`.
    pub cache_ttl: Duration,
    /// `max_evaluations`.
    pub max_evaluations: u32,
}

impl std::fmt::Debug for PdpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PdpConfig")
            .field("url", &self.url)
            .field("plain_http", &self.plain_http)
            .field("token", &"<hidden>")
            .field("timeout", &self.timeout)
            .field("usage_timeout", &self.usage_timeout)
            .field("cache_ttl", &self.cache_ttl)
            .field("max_evaluations", &self.max_evaluations)
            .finish()
    }
}

/// `auth.provider`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Provider {
    /// `s3`.
    #[default]
    S3,
    /// `gcs`.
    Gcs,
}

impl Provider {
    /// The text of the file and of `/api/instances`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::S3 => "s3",
            Self::Gcs => "gcs",
        }
    }
}

/// An `auth` block.
#[derive(Clone, Default)]
pub struct AuthConfig {
    /// The label.
    pub id: String,
    /// `provider`.
    pub provider: Provider,
    /// `mode`: `access_key` or `anonymous` for S3, `service_account` or `anonymous` for GCS.
    pub mode: String,
    /// `endpoint`.
    pub endpoint: String,
    /// `region` (S3 only; empty for GCS).
    pub region: String,
    /// `access_key_id`.
    pub access_key_id: String,
    /// `secret_access_key`: a secret.
    pub secret_access_key: String,
    /// `session_token`: a secret.
    pub session_token: String,
    /// `credentials_file`, absolute.
    pub credentials_file: Option<PathBuf>,
    /// `insecure_skip_verify`.
    pub insecure_skip_verify: bool,
    /// The `usage` block.
    pub usage: Option<UsageConfig>,
}

impl std::fmt::Debug for AuthConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthConfig")
            .field("id", &self.id)
            .field("provider", &self.provider)
            .field("mode", &self.mode)
            .field("endpoint", &self.endpoint)
            .field("region", &self.region)
            .field("access_key_id", &self.access_key_id)
            .field("credentials_file", &self.credentials_file)
            .field("insecure_skip_verify", &self.insecure_skip_verify)
            .field("usage", &self.usage)
            .finish_non_exhaustive()
    }
}

/// `auth.usage.source`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsageSource {
    /// `garage`.
    Garage,
    /// `seaweedfs`.
    SeaweedFs,
    /// `minio`.
    MinIo,
}

impl UsageSource {
    /// The text of the file.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Garage => "garage",
            Self::SeaweedFs => "seaweedfs",
            Self::MinIo => "minio",
        }
    }
}

/// The `usage` block of an `auth` block.
#[derive(Clone)]
pub struct UsageConfig {
    /// `source`.
    pub source: UsageSource,
    /// `endpoint`.
    pub endpoint: String,
    /// `filer_endpoint` (SeaweedFS only).
    pub filer_endpoint: String,
    /// `token` (Garage only): a secret.
    pub token: String,
}

impl std::fmt::Debug for UsageConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsageConfig")
            .field("source", &self.source)
            .field("endpoint", &self.endpoint)
            .field("filer_endpoint", &self.filer_endpoint)
            .finish_non_exhaustive()
    }
}

/// `bucket.encryption`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Encryption {
    /// `""`: no encryption header.
    #[default]
    None,
    /// `sse-s3`: `x-amz-server-side-encryption: AES256` on each write.
    SseS3,
}

impl Encryption {
    /// The text of the file and of `/api/instances`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "",
            Self::SseS3 => "sse-s3",
        }
    }
}

/// A `bucket` block, or the instance form of a `volume` block.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BucketConfig {
    /// The label: the id of the instance.
    pub id: String,
    /// `name`.
    pub name: String,
    /// `auth`: the label of the auth block, or `volume` for a volume.
    pub auth_id: String,
    /// The provider: `s3`, `gcs` or `fs` for a volume.
    pub provider: String,
    /// `bucket`: the name at the provider (the id for a volume).
    pub bucket: String,
    /// The region of the auth block.
    pub region: String,
    /// `permissions`.
    pub permissions: Vec<String>,
    /// True when the block has the key `permissions`.
    pub permissions_defined: bool,
    /// `root_prefix`.
    pub root_prefix: String,
    /// `max_scan_pages`.
    pub max_scan_pages: u32,
    /// `encryption`.
    pub encryption: Encryption,
    /// `quota_bytes`. 0: no limit of the operator.
    pub quota_bytes: i64,
}

impl BucketConfig {
    /// True when the configuration lets the permission (no `permissions` key lets each permission).
    pub fn allows(&self, permission: &str) -> bool {
        !self.permissions_defined || self.permissions.iter().any(|value| value == permission)
    }
}

/// A `volume` block.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct VolumeConfig {
    /// The label: the id of the instance.
    pub id: String,
    /// `name`.
    pub name: String,
    /// `path`: absolute, as the file gives it.
    pub path: PathBuf,
    /// `permissions`.
    pub permissions: Vec<String>,
    /// True when the block has the key `permissions`.
    pub permissions_defined: bool,
    /// `root_prefix`.
    pub root_prefix: String,
    /// `max_scan_pages`.
    pub max_scan_pages: u32,
    /// True with `access.mode = "authzen"`: the volume follows no symbolic link. It is not a key of the file.
    pub refuse_links: bool,
}

impl VolumeConfig {
    /// The instance form of the volume: host `volume`, provider `fs`.
    pub fn bucket_config(&self) -> BucketConfig {
        BucketConfig {
            id: self.id.clone(),
            name: self.name.clone(),
            auth_id: VOLUME_HOST_ID.to_owned(),
            provider: PROVIDER_VOLUME.to_owned(),
            bucket: self.id.clone(),
            region: String::new(),
            permissions: self.permissions.clone(),
            permissions_defined: self.permissions_defined,
            root_prefix: self.root_prefix.clone(),
            max_scan_pages: self.max_scan_pages,
            encryption: Encryption::None,
            quota_bytes: 0,
        }
    }

    /// True when the server can change the files: `write` or `delete` in the permissions, or no `permissions` key.
    pub fn writes(&self) -> bool {
        !self.permissions_defined
            || self
                .permissions
                .iter()
                .any(|value| value == PERMISSION_WRITE || value == PERMISSION_DELETE)
    }
}
