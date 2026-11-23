//! The storage functions that the uploads use, as one interface for each instance.
//!
//! The upload manager and the incomplete-upload functions work with an [`UploadTarget`]: one storage instance with
//! its key and its permissions. [`InstanceTarget`] is the target of a real instance. The tests use a target in memory.
//! [`Targets`] finds a target by the id of an instance. The application is the registry of the process.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use serde::Deserialize;

use super::checksum::UPLOAD_CHECKSUM_SHA256;
use super::token::derive_cipher_key;
use super::{MultipartCursor, MultipartPartsSummary, MultipartUploadPage};
use crate::common::BoxFuture;
use crate::common::app::App;
use crate::common::config::{AuthConfig, Provider};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Body, empty};
use crate::common::storage::{CompletedPart, MultipartPart, ObjectResponse};
use crate::instance::Instance;
use crate::lifecycle::Tag;
use crate::provider::ChecksumTransfer;

/// One storage instance, as the uploads see it.
pub trait UploadTarget: Send + Sync {
    /// The id of the instance.
    fn id(&self) -> &str;
    /// The provider: `s3`, `gcs` or `fs`.
    fn provider(&self) -> &str;
    /// The key of the cipher of the resume tokens of the instance.
    fn cipher_key(&self) -> [u8; 32];
    /// The full key of a relative key.
    fn full_key(&self, relative: &str) -> String;
    /// The relative key of a full key, or `None` for a key outside the root prefix.
    fn relative_key(&self, full: &str) -> Option<String>;
    /// True when the configuration lets the permission.
    fn permitted(&self, permission: &str) -> bool;
    /// `403 permission_denied` when the permission is not permitted.
    fn require_permission(&self, permission: &str) -> Result<()>;
    /// `501 tagging_unsupported` for tags on an instance that keeps no tags.
    fn require_tags(&self, tags: &[Tag]) -> Result<()>;

    /// Write an empty object.
    fn put_empty<'a>(&'a self, ctx: &'a OpCtx, key: &'a str, content_type: &'a str) -> BoxFuture<'a, Result<()>>;
    /// The headers of an object.
    fn head<'a>(&'a self, ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<ObjectResponse>>;

    /// Start an S3 multipart upload.
    fn initiate_multipart<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        content_type: &'a str,
    ) -> BoxFuture<'a, Result<String>>;
    /// Send one part.
    fn upload_part<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        upload_id: &'a str,
        number: u32,
        body: Body,
        size: i64,
    ) -> BoxFuture<'a, Result<String>>;
    /// Complete an S3 multipart upload.
    fn complete_multipart<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        upload_id: &'a str,
        parts: &'a [CompletedPart],
    ) -> BoxFuture<'a, Result<()>>;
    /// Abort a multipart upload, or remove the temporary file of a volume upload.
    fn abort_multipart<'a>(&'a self, ctx: &'a OpCtx, key: &'a str, upload_id: &'a str) -> BoxFuture<'a, Result<()>>;
    /// The parts of an S3 multipart upload.
    fn list_multipart_parts<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        upload_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<MultipartPart>>>;

    /// Start a resumable upload (GCS, volume).
    fn initiate_resumable<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        total: i64,
        content_type: &'a str,
    ) -> BoxFuture<'a, Result<String>>;
    /// Send one chunk of a resumable upload.
    #[allow(clippy::too_many_arguments)]
    fn upload_resumable_chunk<'a>(
        &'a self,
        ctx: &'a OpCtx,
        session: &'a str,
        body: Body,
        start: i64,
        size: i64,
        total: i64,
        content_type: &'a str,
    ) -> BoxFuture<'a, Result<(i64, bool)>>;
    /// The next offset of a resumable upload.
    fn query_resumable<'a>(
        &'a self,
        ctx: &'a OpCtx,
        session: &'a str,
        total: i64,
    ) -> BoxFuture<'a, Result<(i64, bool)>>;
    /// Abort a resumable upload.
    fn abort_resumable<'a>(&'a self, ctx: &'a OpCtx, session: &'a str) -> BoxFuture<'a, Result<()>>;

    /// True when the instance lists its incomplete uploads and the provider does not refuse the list.
    fn multipart_available(&self) -> bool;
    /// `501 multipart_unsupported` when the instance cannot list its incomplete uploads.
    fn require_multipart_list(&self) -> Result<()>;
    /// One page of the incomplete uploads.
    fn list_multipart_uploads<'a>(
        &'a self,
        ctx: &'a OpCtx,
        cursor: &'a MultipartCursor,
        maximum: u32,
    ) -> BoxFuture<'a, Result<MultipartUploadPage>>;
    /// The first page of the parts of one incomplete upload.
    fn multipart_upload_parts<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        upload_id: &'a str,
    ) -> BoxFuture<'a, Result<MultipartPartsSummary>>;
}

/// The registry of the targets: the application, or a set of targets in a test.
pub trait Targets: Send + Sync {
    /// The target of an instance, or `None` for an id that no instance has.
    fn target(&self, id: &str) -> Option<Arc<dyn UploadTarget>>;
}

/// The access check of an upload request. It gets the target and the key from the upload, never from the client.
pub trait AccessCheck: Send + Sync {
    /// Ask the permission to write the key of the target.
    fn check<'a>(&'a self, target: &'a dyn UploadTarget, key: &'a str) -> BoxFuture<'a, Result<()>>;
}

/// A request without an access rule.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoCheck;

impl AccessCheck for NoCheck {
    fn check<'a>(&'a self, _target: &'a dyn UploadTarget, _key: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { Ok(()) })
    }
}

/// The target of a real instance.
pub struct InstanceTarget {
    instance: Arc<Instance>,
    cipher_key: [u8; 32],
}

impl InstanceTarget {
    /// The target of an instance with the key of its cipher.
    pub fn new(instance: Arc<Instance>, cipher_key: [u8; 32]) -> Self {
        Self { instance, cipher_key }
    }
}

impl UploadTarget for InstanceTarget {
    fn id(&self) -> &str {
        &self.instance.cfg.id
    }

    fn provider(&self) -> &str {
        &self.instance.cfg.provider
    }

    fn cipher_key(&self) -> [u8; 32] {
        self.cipher_key
    }

    fn full_key(&self, relative: &str) -> String {
        self.instance.full_key(relative)
    }

    fn relative_key(&self, full: &str) -> Option<String> {
        self.instance.relative_key(full)
    }

    fn permitted(&self, permission: &str) -> bool {
        self.instance.permitted(permission)
    }

    fn require_permission(&self, permission: &str) -> Result<()> {
        self.instance.require_permission(permission)
    }

    fn require_tags(&self, tags: &[Tag]) -> Result<()> {
        let available = self.instance.backend.tagger().is_some()
            && !self.instance.tags.off.load(std::sync::atomic::Ordering::SeqCst);
        if !tags.is_empty() && !available {
            return Err(Error::api(
                501,
                "tagging_unsupported",
                "this storage provider does not support object tags",
            ));
        }
        Ok(())
    }

    fn put_empty<'a>(&'a self, ctx: &'a OpCtx, key: &'a str, content_type: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { self.instance.put(ctx, key, empty(), 0, content_type).await })
    }

    fn head<'a>(&'a self, ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<ObjectResponse>> {
        Box::pin(async move { self.instance.head(ctx, key).await })
    }

    fn initiate_multipart<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        content_type: &'a str,
    ) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move { self.instance.initiate_multipart(ctx, key, content_type).await })
    }

    fn upload_part<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        upload_id: &'a str,
        number: u32,
        body: Body,
        size: i64,
    ) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move { self.instance.upload_part(ctx, key, upload_id, number, body, size).await })
    }

    fn complete_multipart<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        upload_id: &'a str,
        parts: &'a [CompletedPart],
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { self.instance.complete_multipart(ctx, key, upload_id, parts).await })
    }

    fn abort_multipart<'a>(&'a self, ctx: &'a OpCtx, key: &'a str, upload_id: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { self.instance.abort_multipart(ctx, key, upload_id).await })
    }

    fn list_multipart_parts<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        upload_id: &'a str,
    ) -> BoxFuture<'a, Result<Vec<MultipartPart>>> {
        Box::pin(async move { self.instance.list_multipart_parts(ctx, key, upload_id).await })
    }

    fn initiate_resumable<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        total: i64,
        content_type: &'a str,
    ) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move { self.instance.initiate_resumable(ctx, key, total, content_type).await })
    }

    fn upload_resumable_chunk<'a>(
        &'a self,
        ctx: &'a OpCtx,
        session: &'a str,
        body: Body,
        start: i64,
        size: i64,
        total: i64,
        content_type: &'a str,
    ) -> BoxFuture<'a, Result<(i64, bool)>> {
        Box::pin(async move {
            self.instance
                .upload_resumable_chunk(ctx, session, body, start, size, total, content_type)
                .await
        })
    }

    fn query_resumable<'a>(
        &'a self,
        ctx: &'a OpCtx,
        session: &'a str,
        total: i64,
    ) -> BoxFuture<'a, Result<(i64, bool)>> {
        Box::pin(async move { self.instance.query_resumable(ctx, session, total).await })
    }

    fn abort_resumable<'a>(&'a self, ctx: &'a OpCtx, session: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { self.instance.abort_resumable(ctx, session).await })
    }

    fn multipart_available(&self) -> bool {
        self.instance.multipart_uploads_available()
    }

    fn require_multipart_list(&self) -> Result<()> {
        self.instance.multipart_lister().map(|_| ())
    }

    fn list_multipart_uploads<'a>(
        &'a self,
        ctx: &'a OpCtx,
        cursor: &'a MultipartCursor,
        maximum: u32,
    ) -> BoxFuture<'a, Result<MultipartUploadPage>> {
        Box::pin(async move { self.instance.list_multipart_uploads(ctx, cursor, maximum).await })
    }

    fn multipart_upload_parts<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        upload_id: &'a str,
    ) -> BoxFuture<'a, Result<MultipartPartsSummary>> {
        Box::pin(async move { self.instance.multipart_upload_parts(ctx, key, upload_id).await })
    }
}

impl Targets for App {
    fn target(&self, id: &str) -> Option<Arc<dyn UploadTarget>> {
        let instance = self.instances.iter().find(|instance| instance.cfg.id == id)?;
        let auth = self.auths.get(&instance.cfg.auth_id).map(|auth| &auth.cfg);
        let material = resume_material(auth, &self.resume_token_key);
        let key = derive_cipher_key(&instance.cfg.auth_id, &material);
        Some(Arc::new(InstanceTarget::new(instance.clone(), key)))
    }
}

/// The credential material of the key of the resume tokens. An S3 block gives its secret access key and its session
/// token. A GCS block gives the e-mail and the private key of its service account. Any other case gives the random key
/// of the process, so a volume has a key that does not stay valid after a restart.
pub fn resume_material(auth: Option<&AuthConfig>, process_key: &[u8; 32]) -> Vec<u8> {
    let mut material = Vec::new();
    if let Some(auth) = auth {
        match auth.provider {
            Provider::S3 => {
                material.extend_from_slice(auth.secret_access_key.as_bytes());
                material.push(0);
                material.extend_from_slice(auth.session_token.as_bytes());
            }
            Provider::Gcs => {
                if let Some(path) = &auth.credentials_file
                    && let Some(account) = service_account(path)
                {
                    material.extend_from_slice(account.client_email.as_bytes());
                    material.push(0);
                    material.extend_from_slice(account.private_key.as_bytes());
                }
            }
        }
    }
    if material.is_empty() {
        return process_key.to_vec();
    }
    material
}

/// The largest credentials file that the server reads: 4 MiB.
const MAXIMUM_CREDENTIALS_BYTES: u64 = 4 << 20;

/// The two fields of a service account key file that make the key of the tokens.
#[derive(Clone, Debug, Default, Deserialize)]
struct ServiceAccount {
    #[serde(default)]
    client_email: String,
    #[serde(default)]
    private_key: String,
}

/// The service accounts that the process reads, by path. The process reads each file one time, as the token source of
/// the provider does at start.
fn service_account(path: &Path) -> Option<ServiceAccount> {
    static READ: OnceLock<Mutex<BTreeMap<std::path::PathBuf, Option<ServiceAccount>>>> = OnceLock::new();
    let table = READ.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut table = table.lock().ok()?;
    table
        .entry(path.to_path_buf())
        .or_insert_with(|| read_service_account(path))
        .clone()
}

fn read_service_account(path: &Path) -> Option<ServiceAccount> {
    use std::io::Read as _;
    let mut data = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(MAXIMUM_CREDENTIALS_BYTES + 1)
        .read_to_end(&mut data)
        .ok()?;
    if u64::try_from(data.len()).ok()? > MAXIMUM_CREDENTIALS_BYTES {
        return None;
    }
    serde_json::from_slice(&data).ok()
}

/// The context of the multipart initiation of an upload with the SHA-256 checksum. A transfer without a digest asks
/// the provider for the algorithm (`x-amz-checksum-algorithm: SHA256`). Each part then carries its own digest.
pub fn initiation_context(ctx: &OpCtx, checksum: &str) -> OpCtx {
    let mut next = ctx.clone();
    if checksum == UPLOAD_CHECKSUM_SHA256 {
        next.checksum = Some(Arc::new(ChecksumTransfer::default()));
    }
    next
}

/// Validate the tags of a request with the limits of S3: 10 tags, a key of 1 to 128 characters that is unique and does
/// not start with `aws:`, and a value of 0 to 256 characters. A tag has letters, digits, spaces and `+ - = . _ : / @`
/// only.
pub(super) fn validate_upload_tags(tags: &[Tag]) -> Result<()> {
    const MAXIMUM_TAGS: usize = 10;
    const MAXIMUM_KEY_CHARACTERS: usize = 128;
    const MAXIMUM_VALUE_CHARACTERS: usize = 256;
    let invalid = |message: String| Error::api(400, "invalid_tags", message);
    if tags.len() > MAXIMUM_TAGS {
        return Err(invalid(format!(
            "an object has at most {MAXIMUM_TAGS} tags, got {}",
            tags.len()
        )));
    }
    let mut seen = std::collections::BTreeSet::new();
    for tag in tags {
        let key_length = tag.key.chars().count();
        if key_length == 0 || key_length > MAXIMUM_KEY_CHARACTERS {
            return Err(invalid(format!(
                "a tag key has 1 to {MAXIMUM_KEY_CHARACTERS} characters, got {key_length}"
            )));
        }
        if tag.value.chars().count() > MAXIMUM_VALUE_CHARACTERS {
            return Err(invalid(format!(
                "the value of the tag {:?} has at most {MAXIMUM_VALUE_CHARACTERS} characters",
                tag.key
            )));
        }
        if tag.key.to_lowercase().starts_with("aws:") {
            return Err(invalid(format!(
                "the tag key {:?} starts with the reserved prefix aws:",
                tag.key
            )));
        }
        if !valid_tag_text(&tag.key) || !valid_tag_text(&tag.value) {
            return Err(invalid(format!(
                "the tag {:?} has a character that S3 does not allow: use letters, digits, spaces and + - = . _ : / @",
                tag.key
            )));
        }
        if !seen.insert(tag.key.as_str()) {
            return Err(invalid(format!("the tag key {:?} is twice in the request", tag.key)));
        }
    }
    Ok(())
}

fn valid_tag_text(text: &str) -> bool {
    text.chars()
        .all(|c| c.is_alphabetic() || c.is_numeric() || c.is_whitespace() || "+-=._:/@".contains(c))
}
