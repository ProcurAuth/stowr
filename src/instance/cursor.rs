// SPDX-License-Identifier: MIT OR Apache-2.0
//! The signed cursors of the paged previews: an opaque token that the client sends back, authenticated with a
//! random key of the process (HMAC-SHA-256) and bound to a scope (the kind, the instance and the key).
//!
//! A token is `base64url(payload) "." base64url(signature)`, without padding. The payload is the JSON text of the
//! value, at most 64 KiB. A token with another spelling of the same bytes is refused: each token has one form only.

use std::sync::OnceLock;

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::hmac;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::common::error::{Error, Result};
use crate::common::misc::random_bytes;

/// The largest payload of a cursor: 64 KiB.
pub const MAX_SIGNED_CURSOR_PAYLOAD_BYTES: usize = 64 << 10;

/// The length of an HMAC-SHA-256 signature.
const SIGNATURE_BYTES: usize = 32;

/// The random key of the process. A restart makes each cursor invalid.
fn process_key() -> Result<&'static hmac::Key> {
    static KEY: OnceLock<std::result::Result<hmac::Key, String>> = OnceLock::new();
    let key = KEY.get_or_init(|| {
        let mut secret = [0u8; 32];
        random_bytes(&mut secret).map_err(|error| error.to_string())?;
        Ok(hmac::Key::new(hmac::HMAC_SHA256, &secret))
    });
    key.as_ref().map_err(|text| Error::internal(text.clone()))
}

fn invalid(message: &str) -> Error {
    Error::api(400, "invalid_cursor", message)
}

/// The scope of a cursor: the SHA-256 of the kind of the preview, the instance and the key, in base64url.
pub fn signed_cursor_scope(kind: &str, instance: &str, key: &str) -> String {
    let text = format!("{}\u{0}{}\u{0}{key}", kind.trim(), instance.trim());
    URL_SAFE_NO_PAD.encode(digest(&SHA256, text.as_bytes()).as_ref())
}

/// Encode a value as a signed cursor.
pub fn encode_signed_cursor<T: Serialize>(value: &T) -> Result<String> {
    let payload = crate::common::json::to_vec(value)?;
    if payload.is_empty() || payload.len() > MAX_SIGNED_CURSOR_PAYLOAD_BYTES {
        return Err(Error::internal("cursor payload exceeds the supported limit"));
    }
    let signature = hmac::sign(process_key()?, &payload);
    Ok(format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(&payload),
        URL_SAFE_NO_PAD.encode(signature.as_ref())
    ))
}

/// Decode a signed cursor. A changed, foreign or malformed cursor gives `400 invalid_cursor`.
pub fn decode_signed_cursor<T: DeserializeOwned>(raw: &str) -> Result<T> {
    let raw = raw.trim();
    let parts: Vec<&str> = raw.split('.').collect();
    let [payload_text, signature_text] = parts.as_slice() else {
        return Err(invalid("invalid signed cursor"));
    };
    if payload_text.is_empty() || signature_text.is_empty() {
        return Err(invalid("invalid signed cursor"));
    }
    let payload = URL_SAFE_NO_PAD
        .decode(payload_text)
        .ok()
        .filter(|payload| !payload.is_empty() && payload.len() <= MAX_SIGNED_CURSOR_PAYLOAD_BYTES)
        .ok_or_else(|| invalid("invalid signed cursor payload"))?;
    // Each token has one spelling: a change of the unused bits of the last character is a change of the token.
    if URL_SAFE_NO_PAD.encode(&payload) != *payload_text {
        return Err(invalid("invalid signed cursor payload"));
    }
    let signature = URL_SAFE_NO_PAD
        .decode(signature_text)
        .ok()
        .filter(|signature| signature.len() == SIGNATURE_BYTES)
        .ok_or_else(|| invalid("invalid signed cursor signature"))?;
    if URL_SAFE_NO_PAD.encode(&signature) != *signature_text {
        return Err(invalid("invalid signed cursor signature"));
    }
    hmac::verify(process_key()?, &payload, &signature).map_err(|_| invalid("invalid signed cursor signature"))?;
    serde_json::from_slice(&payload).map_err(|_| invalid("invalid signed cursor payload"))
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
    struct TextCursor {
        offset: i64,
        line: i64,
        scope: String,
    }

    /// The token with its last character changed.
    fn mutate(value: &str) -> String {
        let Some(last) = value.chars().last() else {
            return "x".to_owned();
        };
        let replacement = if last == 'A' { 'B' } else { 'A' };
        format!("{}{replacement}", &value[..value.len() - last.len_utf8()])
    }

    #[test]
    fn a_signed_cursor_refuses_a_change_and_another_scope() {
        let value = TextCursor {
            offset: 42,
            line: 7,
            scope: signed_cursor_scope("json-raw", "alpha", "a.json"),
        };
        let encoded = encode_signed_cursor(&value).unwrap();
        let decoded: TextCursor = decode_signed_cursor(&encoded).unwrap();
        assert_eq!(decoded, value);
        let error = decode_signed_cursor::<TextCursor>(&mutate(&encoded)).err().unwrap();
        assert!(error.has_code("invalid_cursor"));
        assert_ne!(decoded.scope, signed_cursor_scope("json-raw", "alpha", "b.json"));
    }

    #[test]
    fn the_scope_is_a_digest_of_its_parts() {
        let scope = signed_cursor_scope(" json-raw ", " alpha ", "a.json");
        assert_eq!(scope, signed_cursor_scope("json-raw", "alpha", "a.json"));
        assert_eq!(scope.len(), 43);
        assert_ne!(scope, signed_cursor_scope("json-raw", "alpha", " a.json"));
    }

    #[test]
    fn a_malformed_cursor_is_refused() {
        let encoded = encode_signed_cursor(&TextCursor::default()).unwrap();
        let (payload, signature) = encoded.split_once('.').unwrap();
        for raw in [
            "",
            "abc",
            ".x",
            "x.",
            "a.b.c",
            &format!("{payload}.{signature}.x"),
            &format!("{payload}=.{signature}"),
            &format!("{payload}.{}", &signature[..signature.len() - 2]),
            &format!("{}.{signature}", URL_SAFE_NO_PAD.encode("[1]")),
        ] {
            assert!(decode_signed_cursor::<TextCursor>(raw).is_err(), "{raw}");
        }
        let spaced: TextCursor = decode_signed_cursor(&format!(" {encoded} ")).unwrap();
        assert_eq!(spaced, TextCursor::default());
    }

    #[test]
    fn a_large_payload_is_refused() {
        let value = "x".repeat(MAX_SIGNED_CURSOR_PAYLOAD_BYTES);
        assert!(encode_signed_cursor(&value).is_err());
    }
}
