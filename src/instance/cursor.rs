//! The signed cursors of the paged previews: an opaque token that the client sends back, authenticated with a
//! random key of the process (HMAC-SHA-256) and bound to a scope (the kind, the instance and the key).

use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::common::error::{Error, Result};

/// The scope of a cursor: the kind of the preview, the instance and the key.
pub fn signed_cursor_scope(kind: &str, instance: &str, key: &str) -> String {
    format!("{kind}\u{0}{instance}\u{0}{key}")
}

/// Encode a value as a signed cursor.
pub fn encode_signed_cursor<T: Serialize>(value: &T) -> Result<String> {
    let _ = value;
    Err(Error::not_served("the signed cursors"))
}

/// Decode a signed cursor. A changed or foreign cursor gives an error.
pub fn decode_signed_cursor<T: DeserializeOwned>(raw: &str) -> Result<T> {
    let _ = raw;
    Err(Error::not_served("the signed cursors"))
}
