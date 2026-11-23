//! The public facts of an instance in `/api/instances` (docs/ARCHITECTURE.md).
//!
//! The facts of the feature work packages (tags, lifecycle, uploads, Object Lock, encryption, metadata, usage) come
//! from the state fields that the instance keeps for them. The functions of this file read those fields only.

use std::collections::BTreeMap;

use serde::Serialize;

use super::Instance;
use super::capability::operation_capabilities;
use crate::bucket::ObjectLockDefaultJson;
use crate::common::config::Encryption;
use crate::common::ctx::OpCtx;
use crate::common::storage::{Capabilities, CapabilityState};

/// The provider flavour of AWS S3.
pub const FLAVOUR_AWS: &str = "aws";
/// The provider flavour of MinIO.
pub const FLAVOUR_MINIO: &str = "minio";
/// The provider flavour of SeaweedFS.
pub const FLAVOUR_SEAWEEDFS: &str = "seaweedfs";
/// The provider flavour of Garage.
pub const FLAVOUR_GARAGE: &str = "garage";

/// The longest time of the read of the provider flavour.
const FLAVOUR_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

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
        let (default_encryption, encryption_applied) = encryption_state(self);
        let capabilities = self.capabilities();
        let operations = operation_capabilities(&capabilities);
        InstanceInfo {
            id: self.cfg.id.clone(),
            host: self.cfg.auth_id.clone(),
            name: self.cfg.name.clone(),
            provider: self.cfg.provider.clone(),
            flavour: known_flavour(self),
            bucket: self.cfg.bucket.clone(),
            region: self.cfg.region.clone(),
            root_prefix: self.cfg.root_prefix.clone(),
            versioning_supported: self.versioning_available(),
            versioning_state: self.versioning_state().unwrap_or_default().to_owned(),
            tags_supported: tags_supported(self),
            metadata_edit_supported: metadata_edit_supported(self),
            multipart_uploads_supported: multipart_uploads_supported(self),
            lifecycle_supported: lifecycle_supported(self),
            lifecycle_rules: lifecycle_rules(self),
            object_lock_supported: object_lock_supported(self),
            object_lock_default: object_lock_default(self),
            bucket_encryption_supported: bucket_encryption_supported(self),
            encryption: self.cfg.encryption.as_str().to_owned(),
            default_encryption,
            encryption_applied,
            usage_supported: usage_supported(self),
            capabilities,
            operations,
        }
    }
}

/// The provider flavour that an earlier probe recognised, or an empty text. It never asks the provider.
pub fn known_flavour(instance: &Instance) -> String {
    instance
        .rules
        .inner
        .lock()
        .map(|inner| inner.flavour.clone())
        .unwrap_or_default()
}

/// The provider flavour of the instance. When no probe recognised it, the function asks the provider one time,
/// 5 seconds at most, and keeps the answer. A failure gives an empty text.
pub async fn provider_flavour(instance: &Instance, ctx: &OpCtx) -> String {
    let known = known_flavour(instance);
    if !known.is_empty() {
        return known;
    }
    let Some(rules) = instance.backend.bucket_rules() else {
        return String::new();
    };
    let probe = ctx.with_timeout(FLAVOUR_PROBE_TIMEOUT);
    let Ok(flavour) = probe.run(rules.provider_flavour(&probe)).await else {
        return String::new();
    };
    if let Ok(mut inner) = instance.rules.inner.lock() {
        inner.flavour.clone_from(&flavour);
    }
    flavour
}

fn tags_supported(instance: &Instance) -> bool {
    instance.backend.tagger().is_some() && !instance.tags.off.load(std::sync::atomic::Ordering::SeqCst)
}

fn metadata_edit_supported(instance: &Instance) -> bool {
    instance.backend.metadata_editor().is_some() && !instance.metadata.off.load(std::sync::atomic::Ordering::SeqCst)
}

fn multipart_uploads_supported(instance: &Instance) -> bool {
    instance.backend.multipart_lister().is_some() && !instance.multiparts.off.load(std::sync::atomic::Ordering::SeqCst)
}

fn lifecycle_supported(instance: &Instance) -> bool {
    instance.lifecycle_available()
}

fn lifecycle_rules(instance: &Instance) -> Option<usize> {
    if !lifecycle_supported(instance) {
        return None;
    }
    instance.rules.inner.lock().ok().and_then(|inner| inner.rule_count)
}

fn object_lock_supported(instance: &Instance) -> bool {
    instance.backend.object_lock().is_some()
        && instance
            .object_lock
            .probed
            .lock()
            .is_ok_and(|probed| probed.as_ref().is_some_and(|configuration| configuration.enabled))
}

fn object_lock_default(instance: &Instance) -> Option<ObjectLockDefaultJson> {
    if !object_lock_supported(instance) {
        return None;
    }
    let probed = instance.object_lock.probed.lock().ok()?;
    let configuration = probed.as_ref()?;
    if configuration.default_mode.is_empty() {
        return None;
    }
    Some(ObjectLockDefaultJson {
        mode: configuration.default_mode.clone(),
        days: (configuration.default_days > 0).then_some(configuration.default_days),
        years: (configuration.default_years > 0).then_some(configuration.default_years),
    })
}

fn bucket_encryption_supported(instance: &Instance) -> bool {
    instance.backend.encryption_reader().is_some()
        && instance
            .encryption
            .probed
            .lock()
            .is_ok_and(|probed| probed.as_ref().is_some_and(|(supported, _)| *supported))
}

/// The default encryption of the bucket at start, and what the provider does with `encryption = "sse-s3"`.
fn encryption_state(instance: &Instance) -> (String, String) {
    let probed = instance.encryption.probed.lock().ok().and_then(|probed| probed.clone());
    let Some((_, configuration)) = probed else {
        return (String::new(), String::new());
    };
    let algorithm = configuration
        .map(|configuration| configuration.algorithm)
        .unwrap_or_default();
    let applied = if instance.cfg.encryption == Encryption::SseS3 {
        match known_flavour(instance).as_str() {
            FLAVOUR_AWS | FLAVOUR_MINIO | FLAVOUR_SEAWEEDFS => "yes",
            FLAVOUR_GARAGE => "no",
            _ => "unknown",
        }
    } else {
        ""
    };
    (algorithm, applied.to_owned())
}

fn usage_supported(instance: &Instance) -> bool {
    instance.usage.reader.lock().is_ok_and(|reader| reader.is_some())
}
