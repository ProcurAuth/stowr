//! The resume token `stowr1`: the provider coordinates of an upload, sealed with an authenticated cipher.
//!
//! The server never writes the token to a disk or to the connected object store. The client keeps it. The key comes
//! from the credential material of the `auth` block, so another process with the same configuration can open the
//! token. The form is `stowr1.<instance, base64url>.<sealed, base64url>`. The sealed part is a 12-byte nonce, the
//! AES-256-GCM cipher text of the JSON descriptor and a 16-byte tag. The additional data is `stowr1.<instance>`.

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::digest;
use base64::Engine as _;
use base64::alphabet;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
use serde::{Deserialize, Serialize};

use super::session::UploadSession;
use super::target::{Targets, UploadTarget};
use crate::common::error::{Error, Result};
use crate::common::json;
use crate::common::misc::{clean_relative_key, random_bytes};
use crate::common::time::Timestamp;
use std::sync::Arc;

/// The version word at the start of each token.
pub const RESUME_TOKEN_VERSION: &str = "stowr1";

/// The life of a token: 30 days.
pub const RESUME_TOKEN_LIFETIME_SECONDS: i64 = 30 * 24 * 60 * 60;

/// The most that a token may be ahead of the clock of the server.
const ISSUED_AT_SKEW_SECONDS: i64 = 5 * 60;

/// The text that starts the input of the key. It makes the key unique for this use.
const KEY_DOMAIN: &str = "stowr-transfer-resume-v1";

/// The provider coordinates that the token holds. A field that is empty or 0 is not in the JSON text when it is
/// optional.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeDescriptor {
    /// The id of the instance.
    #[serde(rename = "i", default)]
    pub instance: String,
    /// The relative key.
    #[serde(rename = "k", default)]
    pub key: String,
    /// The provider of the instance.
    #[serde(rename = "p", default)]
    pub provider: String,
    /// The media type.
    #[serde(rename = "ct", default)]
    pub content_type: String,
    /// The size of the object.
    #[serde(rename = "s", default)]
    pub total_size: i64,
    /// The size of a chunk.
    #[serde(rename = "cs", default)]
    pub chunk_size: i64,
    /// The upload id of an S3 multipart upload.
    #[serde(rename = "u", default, skip_serializing_if = "String::is_empty")]
    pub provider_upload_id: String,
    /// The session of a GCS or volume resumable upload.
    #[serde(rename = "r", default, skip_serializing_if = "String::is_empty")]
    pub session_url: String,
    /// The checksum algorithm.
    #[serde(rename = "ck", default, skip_serializing_if = "String::is_empty")]
    pub checksum: String,
    /// The time of issue, in seconds since 1970.
    #[serde(rename = "iat", default)]
    pub issued_at: i64,
    /// The end of the life, in seconds since 1970.
    #[serde(rename = "exp", default)]
    pub expires_at: i64,
}

/// The key of the cipher for the credential material of an `auth` block. The material is empty for a block without a
/// secret that the server can use: the key then comes from the random key of the process.
pub fn derive_cipher_key(auth_id: &str, material: &[u8]) -> [u8; 32] {
    let mut context = digest::Context::new(&digest::SHA256);
    context.update(KEY_DOMAIN.as_bytes());
    context.update(&[0]);
    context.update(auth_id.as_bytes());
    context.update(&[0]);
    context.update(material);
    let mut key = [0u8; 32];
    key.copy_from_slice(context.finish().as_ref());
    key
}

fn url_safe() -> GeneralPurpose {
    GeneralPurpose::new(
        &alphabet::URL_SAFE,
        GeneralPurposeConfig::new()
            .with_encode_padding(false)
            .with_decode_padding_mode(DecodePaddingMode::RequireNone)
            .with_decode_allow_trailing_bits(true),
    )
}

fn invalid_token(message: &str) -> Error {
    Error::api(400, "invalid_resume_token", message)
}

fn cipher(key: &[u8; 32]) -> Result<LessSafeKey> {
    UnboundKey::new(&AES_256_GCM, key)
        .map(LessSafeKey::new)
        .map_err(|_| Error::internal("create upload resume cipher"))
}

/// Seal the coordinates of an upload into a token.
pub fn seal_resume_token(target: &dyn UploadTarget, upload: &UploadSession, now: Timestamp) -> Result<String> {
    let issued_at = if upload.created_at == Timestamp::default() {
        now.secs
    } else {
        upload.created_at.secs
    };
    let descriptor = ResumeDescriptor {
        instance: target.id().to_owned(),
        key: upload.key.clone(),
        provider: upload.provider.clone(),
        content_type: upload.content_type.clone(),
        total_size: upload.total_size,
        chunk_size: upload.chunk_size,
        provider_upload_id: upload.provider_upload_id.clone(),
        session_url: upload.session_url.clone(),
        checksum: upload.checksum.clone(),
        issued_at,
        expires_at: issued_at.saturating_add(RESUME_TOKEN_LIFETIME_SECONDS),
    };
    seal_descriptor(&target.cipher_key(), target.id(), &descriptor)
}

/// Seal a descriptor for an instance with a key.
pub fn seal_descriptor(key: &[u8; 32], instance_id: &str, descriptor: &ResumeDescriptor) -> Result<String> {
    let plain = json::to_vec(descriptor)?;
    let cipher = cipher(key)?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    random_bytes(&mut nonce_bytes)?;
    let instance_part = url_safe().encode(instance_id);
    let aad = format!("{RESUME_TOKEN_VERSION}.{instance_part}");
    let mut buffer = plain;
    cipher
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(aad.as_bytes()),
            &mut buffer,
        )
        .map_err(|_| Error::internal("seal the upload resume token"))?;
    let mut sealed = Vec::with_capacity(NONCE_LEN + buffer.len());
    sealed.extend_from_slice(&nonce_bytes);
    sealed.extend_from_slice(&buffer);
    Ok(format!("{aad}.{}", url_safe().encode(sealed)))
}

/// Open a token: the descriptor and the target of its instance. A token that is not valid gives `400
/// invalid_resume_token`, an unknown instance gives `404`, and an old token gives `410 resume_token_expired`.
pub fn open_resume_token(
    token: &str,
    targets: &dyn Targets,
    now: Timestamp,
) -> Result<(ResumeDescriptor, Arc<dyn UploadTarget>)> {
    let invalid = || invalid_token("upload resume token is invalid");
    let parts: Vec<&str> = token.trim().split('.').collect();
    if parts.len() != 3 || parts[0] != RESUME_TOKEN_VERSION {
        return Err(invalid());
    }
    let instance_bytes = url_safe().decode(parts[1]).map_err(|_| invalid())?;
    let target = String::from_utf8(instance_bytes)
        .ok()
        .and_then(|id| targets.target(&id))
        .ok_or_else(|| Error::api(404, "unknown_instance", "storage instance was not found"))?;
    let sealed = url_safe().decode(parts[2]).map_err(|_| invalid())?;
    if sealed.len() < NONCE_LEN {
        return Err(invalid());
    }
    let cipher = cipher(&target.cipher_key())?;
    let (nonce_bytes, cipher_text) = sealed.split_at(NONCE_LEN);
    let nonce = Nonce::try_assume_unique_for_key(nonce_bytes).map_err(|_| invalid())?;
    let aad = format!("{}.{}", parts[0], parts[1]);
    let mut buffer = cipher_text.to_vec();
    let plain = cipher
        .open_in_place(nonce, Aad::from(aad.as_bytes()), &mut buffer)
        .map_err(|_| invalid_token("upload resume token could not be verified"))?;
    let descriptor: ResumeDescriptor = serde_json::from_slice(plain).map_err(|_| invalid())?;
    if descriptor.instance != target.id()
        || descriptor.provider != target.provider()
        || clean_relative_key(&descriptor.key).is_empty()
        || descriptor.total_size < 0
    {
        return Err(invalid_token(
            "upload resume token does not match the configured storage",
        ));
    }
    check_lifetime(&descriptor, now)?;
    Ok((descriptor, target))
}

fn check_lifetime(descriptor: &ResumeDescriptor, now: Timestamp) -> Result<()> {
    let issued = descriptor.issued_at;
    let expires = descriptor.expires_at;
    let after_expiry = now.secs > expires || (now.secs == expires && now.nanos > 0);
    if issued <= 0
        || expires <= 0
        || after_expiry
        || issued > now.secs.saturating_add(ISSUED_AT_SKEW_SECONDS)
        || expires < issued
        || expires.saturating_sub(issued) > RESUME_TOKEN_LIFETIME_SECONDS
    {
        return Err(Error::api(
            410,
            "resume_token_expired",
            "upload resume token has expired",
        ));
    }
    Ok(())
}

/// The id of a session: `upl_` and the first 16 bytes of the SHA-256 of the token, in hexadecimal.
pub fn upload_id_from_token(token: &str) -> String {
    let sum = digest::digest(&digest::SHA256, token.as_bytes());
    let mut id = String::from("upl_");
    id.push_str(&crate::common::misc::hex(&sum.as_ref()[..16]));
    id
}
