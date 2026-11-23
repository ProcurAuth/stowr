//! The public facts of an instance in `/api/instances` (docs/ARCHITECTURE.md).
//!
//! The facts of the feature work packages (tags, lifecycle, uploads, Object Lock, encryption, metadata, usage) come
//! from the methods that those work packages give to the instance.

use std::collections::BTreeMap;

use serde::Serialize;

use super::Instance;
use super::capability::operation_capabilities;
use crate::bucket::ObjectLockDefaultJson;
use crate::common::storage::{Capabilities, CapabilityState};

/// The public facts of an instance in `/api/instances`. The members are in the order of the answers.
#[derive(Clone, Debug, Default, Serialize)]
pub struct InstanceInfo {
    /// The id.
    pub id: String,
    /// The host: the label of the auth block, or `volume`.
    pub host: String,
    /// The name.
    pub name: String,
    /// `s3`, `gcs` or `fs`.
    pub provider: String,
    /// The S3 provider that the start probe recognised: `aws`, `minio`, `seaweedfs`, `garage`, or absent.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub flavour: String,
    /// The bucket at the provider.
    pub bucket: String,
    /// The region.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub region: String,
    /// The root prefix.
    #[serde(rename = "rootPrefix", skip_serializing_if = "String::is_empty")]
    pub root_prefix: String,
    /// True when the start probe found the versions.
    #[serde(rename = "versioningSupported")]
    pub versioning_supported: bool,
    /// The versioning of the bucket: `enabled`, `suspended` or `off`. Absent when the server could not read it.
    #[serde(rename = "versioningState", skip_serializing_if = "String::is_empty")]
    pub versioning_state: String,
    /// True when the instance keeps object tags.
    #[serde(rename = "tagsSupported")]
    pub tags_supported: bool,
    /// True when the instance can change the metadata of an object.
    #[serde(rename = "metadataEditSupported")]
    pub metadata_edit_supported: bool,
    /// True when the instance can list the incomplete uploads.
    #[serde(rename = "multipartUploadsSupported")]
    pub multipart_uploads_supported: bool,
    /// True when the instance gives the lifecycle rules.
    #[serde(rename = "lifecycleSupported")]
    pub lifecycle_supported: bool,
    /// The number of lifecycle rules at the last read of this process. Absent when the server could not read them.
    #[serde(rename = "lifecycleRules", skip_serializing_if = "Option::is_none")]
    pub lifecycle_rules: Option<usize>,
    /// True when the bucket has Object Lock.
    #[serde(rename = "objectLockSupported")]
    pub object_lock_supported: bool,
    /// The default retention of the bucket that the start probe read. Absent without Object Lock or without a
    /// default retention.
    #[serde(rename = "objectLockDefault", skip_serializing_if = "Option::is_none")]
    pub object_lock_default: Option<ObjectLockDefaultJson>,
    /// True when the page can read the default encryption of the bucket.
    #[serde(rename = "bucketEncryptionSupported")]
    pub bucket_encryption_supported: bool,
    /// The key encryption of the bucket: empty or `sse-s3`.
    pub encryption: String,
    /// The algorithm of the default encryption of the bucket at start, empty when it has none.
    #[serde(rename = "defaultEncryption")]
    pub default_encryption: String,
    /// What the provider does with `encryption = "sse-s3"`: `yes`, `no` or `unknown`. Absent without the key.
    #[serde(rename = "encryptionApplied", skip_serializing_if = "String::is_empty")]
    pub encryption_applied: String,
    /// True when `GET /api/usage` reads the usage of the bucket.
    #[serde(rename = "usageSupported")]
    pub usage_supported: bool,
    /// The three permissions.
    pub capabilities: Capabilities,
    /// The states of the operations of the interface.
    pub operations: BTreeMap<String, CapabilityState>,
}

impl Instance {
    /// The public facts of the instance.
    pub fn public_info(&self) -> InstanceInfo {
        let (default_encryption, encryption_applied) = self.encryption_state();
        let capabilities = self.capabilities();
        let operations = operation_capabilities(&capabilities);
        InstanceInfo {
            id: self.cfg.id.clone(),
            host: self.cfg.auth_id.clone(),
            name: self.cfg.name.clone(),
            provider: self.cfg.provider.clone(),
            flavour: self.known_flavour(),
            bucket: self.cfg.bucket.clone(),
            region: self.cfg.region.clone(),
            root_prefix: self.cfg.root_prefix.clone(),
            versioning_supported: self.versioning_available(),
            versioning_state: self.versioning_state().unwrap_or_default().to_owned(),
            tags_supported: self.tags_available(),
            metadata_edit_supported: self.metadata_edit_available(),
            multipart_uploads_supported: self.multipart_uploads_available(),
            lifecycle_supported: self.lifecycle_available(),
            lifecycle_rules: self.lifecycle_rule_count(),
            object_lock_supported: self.object_lock_available(),
            object_lock_default: self.object_lock_default_info(),
            bucket_encryption_supported: self.bucket_encryption_available(),
            encryption: self.cfg.encryption.as_str().to_owned(),
            default_encryption,
            encryption_applied,
            usage_supported: self.usage_available(),
            capabilities,
            operations,
        }
    }
}
