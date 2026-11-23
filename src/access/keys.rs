// SPDX-License-Identifier: MIT OR Apache-2.0
//! The public keys of the issuer of the identity tokens.
//!
//! The configuration gives them as PEM text or as a JWK Set (RFC 7517), with the rules of ClickHouse Dash: a text
//! that starts with `{` after white space is a JWK Set, any other text is PEM. Both forms hold 1 to 16 keys, and
//! each key is Ed25519 or P-256. The JWK reader also refuses a duplicate member and data after the JSON value.
//!
//! The kid of a key is the kid that the JWK declares, or else the RFC 7638 thumbprint of the key. The guard of the
//! PEP gets each key as a JWK with this kid ([`PublicKey::to_jwk`]).

use base64::Engine as _;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, URL_SAFE_NO_PAD};
use serde_json::{Map, Value, json};

use super::quote;

/// The most keys in the text: PEM blocks or keys of the JWK Set.
pub const MAX_KEYS: usize = 16;
/// The longest base64 text of one PEM block.
pub const MAX_PEM_BODY_BYTES: usize = 4096;
/// The longest kid of a JWK.
pub const MAX_KID_BYTES: usize = 256;
/// The deepest nesting of the JSON text of a JWK Set.
const MAX_JSON_DEPTH: usize = 512;

/// The members that a private or a secret key has. A public key set cannot have them.
const PRIVATE_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// The DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410).
const ED25519_SPKI_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
/// The DER prefix of a P-256 SubjectPublicKeyInfo with an uncompressed point (RFC 5480). It ends with the byte 0x04
/// of the uncompressed point.
const P256_SPKI_PREFIX: [u8; 27] = [
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce,
    0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];

/// The standard base64 of a PEM block: padding is mandatory, and the bits after the last character can be other
/// than zero.
const PEM_ENGINE: GeneralPurpose = GeneralPurpose::new(
    &base64::alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::RequireCanonical)
        .with_decode_allow_trailing_bits(true),
);

/// The algorithm of a key: the only header `alg` that the key verifies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    /// `Ed25519`.
    Ed25519,
    /// `ES256`: ECDSA with P-256 and SHA-256.
    Es256,
}

impl Algorithm {
    /// The name of the header `alg`.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
            Self::Es256 => "ES256",
        }
    }
}

/// One public key of the issuer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    /// The algorithm.
    pub alg: Algorithm,
    /// The kid: the declared kid, or the RFC 7638 thumbprint.
    pub kid: String,
    /// The key of 32 bytes (Ed25519), or the x coordinate (P-256).
    pub x: [u8; 32],
    /// The y coordinate of a P-256 key.
    pub y: Option<[u8; 32]>,
}

impl PublicKey {
    /// The short name of the key for print-config and for the log: the type and the kid.
    pub fn display(&self) -> String {
        match self.alg {
            Algorithm::Ed25519 => format!("Ed25519 kid={}", self.kid),
            Algorithm::Es256 => format!("P-256 kid={}", self.kid),
        }
    }

    /// The key as a JWK with its kid, for the key set of the guard.
    pub fn to_jwk(&self) -> Value {
        let x = URL_SAFE_NO_PAD.encode(self.x);
        match self.y {
            None => json!({"kty": "OKP", "crv": "Ed25519", "x": x, "kid": self.kid}),
            Some(y) => json!({"kty": "EC", "crv": "P-256", "x": x, "y": URL_SAFE_NO_PAD.encode(y), "kid": self.kid}),
        }
    }

    fn ed25519(x: [u8; 32]) -> Self {
        Self {
            alg: Algorithm::Ed25519,
            kid: thumbprint(&format!(
                r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
                URL_SAFE_NO_PAD.encode(x)
            )),
            x,
            y: None,
        }
    }

    /// A P-256 key from its coordinates. The point must be on the curve.
    fn p256(x: [u8; 32], y: [u8; 32]) -> Result<Self, String> {
        let mut point = Vec::with_capacity(65);
        point.push(4);
        point.extend_from_slice(&x);
        point.extend_from_slice(&y);
        if aws_lc_rs::signature::ParsedPublicKey::new(&aws_lc_rs::signature::ECDSA_P256_SHA256_FIXED, &point).is_err() {
            return Err("is not a point of the curve P-256".to_owned());
        }
        Ok(Self {
            alg: Algorithm::Es256,
            kid: thumbprint(&format!(
                r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
                URL_SAFE_NO_PAD.encode(x),
                URL_SAFE_NO_PAD.encode(y)
            )),
            x,
            y: Some(y),
        })
    }
}

/// The RFC 7638 thumbprint of a canonical JWK: the SHA-256 of the text, in base64url.
fn thumbprint(canonical: &str) -> String {
    URL_SAFE_NO_PAD.encode(aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA256,
        canonical.as_bytes(),
    ))
}

/// Read the public keys of the issuer. A text that starts with `{` after spaces, tabs and line ends is a JWK Set.
/// Any other text is PEM. The error text names the problem and the position of the key.
pub fn parse(text: &str) -> Result<Vec<PublicKey>, String> {
    if text.trim_start_matches([' ', '\t', '\r', '\n']).starts_with('{') {
        parse_jwk_set(text)
    } else {
        parse_pem(text)
    }
}

/// Read 1 to 16 `PUBLIC KEY` PEM blocks. Each block is the SubjectPublicKeyInfo of an Ed25519 key, or of a P-256 key
/// with an uncompressed point. The reader cuts the text at each line end and removes the spaces, the tabs and the
/// carriage returns at the two ends of a line. Outside a block, a line must be empty or the line of the start of a
/// block.
fn parse_pem(text: &str) -> Result<Vec<PublicKey>, String> {
    let mut keys = Vec::new();
    let mut inside = false;
    let mut body = String::new();
    for (index, raw) in text.split('\n').enumerate() {
        let line = raw.trim_matches([' ', '\t', '\r']);
        if !inside {
            if line.is_empty() {
                continue;
            }
            if line != "-----BEGIN PUBLIC KEY-----" {
                return Err(format!(
                    "line {} is not -----BEGIN PUBLIC KEY-----: give PEM public keys or a JWK Set",
                    index + 1
                ));
            }
            inside = true;
            body.clear();
            continue;
        }
        if line != "-----END PUBLIC KEY-----" {
            body.push_str(line);
            if body.len() > MAX_PEM_BODY_BYTES {
                return Err(format!(
                    "key {} is too long for an Ed25519 or a P-256 public key",
                    keys.len() + 1
                ));
            }
            continue;
        }
        inside = false;
        let key = pem_key(&body).map_err(|error| format!("key {} {error}", keys.len() + 1))?;
        if keys.len() == MAX_KEYS {
            return Err(format!("more than {MAX_KEYS} keys: give 1 to {MAX_KEYS} keys"));
        }
        keys.push(key);
    }
    if inside {
        return Err("-----END PUBLIC KEY----- is missing".to_owned());
    }
    if keys.is_empty() {
        return Err("no key: give at least one -----BEGIN PUBLIC KEY----- block, or a JWK Set".to_owned());
    }
    Ok(keys)
}

/// Read the base64 body of one PEM block.
fn pem_key(body: &str) -> Result<PublicKey, String> {
    let der = PEM_ENGINE.decode(body).map_err(|_| "is not valid base64".to_owned())?;
    if der.len() == ED25519_SPKI_PREFIX.len() + 32 && der.starts_with(&ED25519_SPKI_PREFIX) {
        return Ok(PublicKey::ed25519(coordinate(&der[ED25519_SPKI_PREFIX.len()..])));
    }
    if der.len() == P256_SPKI_PREFIX.len() + 64 && der.starts_with(&P256_SPKI_PREFIX) {
        let point = &der[P256_SPKI_PREFIX.len()..];
        return PublicKey::p256(coordinate(&point[..32]), coordinate(&point[32..]));
    }
    Err(
        "is not an Ed25519 public key or a P-256 public key with an uncompressed point (SubjectPublicKeyInfo)"
            .to_owned(),
    )
}

fn coordinate(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes[..32]);
    out
}

/// Read a JWK Set with 1 to 16 keys. Each key is Ed25519 (`OKP`) or P-256 (`EC`).
fn parse_jwk_set(text: &str) -> Result<Vec<PublicKey>, String> {
    StrictJson::check(text)?;
    let set: Value =
        serde_json::from_str(text).map_err(|error| format!("the JWK Set must be a JSON object: {error}"))?;
    let Value::Object(set) = set else {
        return Err("the JWK Set must be a JSON object".to_owned());
    };
    let Some(items) = set.get("keys") else {
        return Err(r#"the JWK Set must have the member "keys""#.to_owned());
    };
    let Value::Array(items) = items else {
        return Err(r#"the member "keys" must be an array"#.to_owned());
    };
    if items.is_empty() {
        return Err(format!(r#"the member "keys" has no key: give 1 to {MAX_KEYS} keys"#));
    }
    if items.len() > MAX_KEYS {
        return Err(format!(
            r#"the member "keys" has {} keys: give 1 to {MAX_KEYS} keys"#,
            items.len()
        ));
    }
    let mut keys: Vec<PublicKey> = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let key = jwk_key(item).map_err(|error| format!("key {}: {error}", index + 1))?;
        if let Some(first) = keys.iter().position(|other| other.kid == key.kid) {
            return Err(format!(
                "key {}: the kid {} is also the kid of key {}; each kid must be unique",
                index + 1,
                quote(&key.kid),
                first + 1
            ));
        }
        keys.push(key);
    }
    Ok(keys)
}

/// Read one JWK. The caller adds the position of the key to the error.
fn jwk_key(item: &Value) -> Result<PublicKey, String> {
    let Value::Object(members) = item else {
        return Err("must be a JSON object".to_owned());
    };
    for name in PRIVATE_MEMBERS {
        if members.contains_key(name) {
            return Err(format!("has the private member {}; give public keys only", quote(name)));
        }
    }
    let kty = text_member(members, "kty")?.unwrap_or_default();
    let crv = text_member(members, "crv")?.unwrap_or_default();
    let mut key = match (kty, crv) {
        ("OKP", "Ed25519") => PublicKey::ed25519(jwk_coordinate(members, "x")?),
        ("EC", "P-256") => {
            let x = jwk_coordinate(members, "x")?;
            let y = jwk_coordinate(members, "y")?;
            PublicKey::p256(x, y).map_err(|error| format!("the point (x, y) {error}"))?
        }
        (kty, crv) => {
            return Err(format!(
                r#"kty {} with crv {} is not supported; use kty "OKP" with crv "Ed25519", or kty "EC" with crv "P-256""#,
                quote(kty),
                quote(crv)
            ));
        }
    };
    // alg is optional. When present, it must fit the key: "Ed25519" or "EdDSA" for OKP, "ES256" for EC. A token
    // header with the alg EdDSA stays refused. The members use and key_ops have no effect.
    if let Some(alg) = text_member(members, "alg")?
        && alg != key.alg.as_str()
        && !(key.alg == Algorithm::Ed25519 && alg == "EdDSA")
    {
        return Err(format!(
            "alg must be {} for this key, got {}",
            quote(key.alg.as_str()),
            quote(alg)
        ));
    }
    // The declared kid replaces the thumbprint: 1 to 256 bytes without a control character (below 0x20, or 0x7f).
    if let Some(kid) = text_member(members, "kid")? {
        if kid.is_empty() || kid.len() > MAX_KID_BYTES || kid.chars().any(|c| (c as u32) < 0x20 || c == '\u{7f}') {
            return Err(format!(
                "kid must have 1 to {MAX_KID_BYTES} bytes without a control character, got {}",
                quote(kid)
            ));
        }
        kid.clone_into(&mut key.kid);
    }
    Ok(key)
}

/// A member that must be a string when it is present.
fn text_member<'a>(members: &'a Map<String, Value>, name: &str) -> Result<Option<&'a str>, String> {
    match members.get(name) {
        None => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => Err(format!("the member {} must be a string", quote(name))),
    }
}

/// A member that holds 32 bytes in base64url without padding.
fn jwk_coordinate(members: &Map<String, Value>, name: &str) -> Result<[u8; 32], String> {
    let Some(text) = text_member(members, name)? else {
        return Err(format!("the member {} is required", quote(name)));
    };
    let decoded = URL_SAFE_NO_PAD.decode(text).map_err(|error| {
        let offset = match error {
            base64::DecodeError::InvalidByte(offset, _) | base64::DecodeError::InvalidLastSymbol(offset, _) => offset,
            _ => text.len(),
        };
        format!(
            "the member {} must be base64url without padding: the byte {offset} is not base64url",
            quote(name)
        )
    })?;
    if decoded.len() != 32 {
        return Err(format!(
            "the member {} must hold 32 bytes, got {}",
            quote(name),
            decoded.len()
        ));
    }
    Ok(coordinate(&decoded))
}

/// A strict walk of a JSON text: it refuses a duplicate member name at any level and any data after the value.
struct StrictJson<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> StrictJson<'a> {
    fn check(text: &'a str) -> Result<(), String> {
        let mut walker = Self {
            bytes: text.as_bytes(),
            at: 0,
        };
        walker.value("the JWK Set", 0)?;
        walker.space();
        if walker.at < walker.bytes.len() {
            return Err("the JWK Set has data after the JSON value".to_owned());
        }
        Ok(())
    }

    fn invalid(&self, what: &str) -> String {
        format!("the JWK Set is not valid JSON: {what} at offset {}", self.at)
    }

    fn space(&mut self) {
        while self.at < self.bytes.len() && matches!(self.bytes[self.at], b' ' | b'\t' | b'\r' | b'\n') {
            self.at += 1;
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.at).copied()
    }

    fn expect(&mut self, byte: u8) -> Result<(), String> {
        self.space();
        if self.peek() == Some(byte) {
            self.at += 1;
            Ok(())
        } else if self.peek().is_none() {
            Err(self.invalid("the JSON text ends too early"))
        } else {
            Err(self.invalid(&format!("expected {}", char::from(byte))))
        }
    }

    fn value(&mut self, place: &str, depth: usize) -> Result<(), String> {
        if depth > MAX_JSON_DEPTH {
            return Err(self.invalid("the value is nested too deep"));
        }
        self.space();
        match self.peek() {
            None => Err(self.invalid("the JSON text ends too early")),
            Some(b'{') => {
                self.at += 1;
                let mut seen: Vec<String> = Vec::new();
                self.space();
                if self.peek() == Some(b'}') {
                    self.at += 1;
                    return Ok(());
                }
                loop {
                    self.space();
                    let name = self.string()?;
                    if seen.contains(&name) {
                        return Err(format!("the member {} is two times in {place}", quote(&name)));
                    }
                    self.expect(b':')?;
                    self.value(&format!("{place} member {}", quote(&name)), depth + 1)?;
                    seen.push(name);
                    self.space();
                    match self.peek() {
                        Some(b',') => self.at += 1,
                        Some(b'}') => {
                            self.at += 1;
                            return Ok(());
                        }
                        None => return Err(self.invalid("the JSON text ends too early")),
                        Some(_) => return Err(self.invalid("expected , or }")),
                    }
                }
            }
            Some(b'[') => {
                self.at += 1;
                self.space();
                if self.peek() == Some(b']') {
                    self.at += 1;
                    return Ok(());
                }
                let mut index = 0;
                loop {
                    index += 1;
                    self.value(&format!("{place} item {index}"), depth + 1)?;
                    self.space();
                    match self.peek() {
                        Some(b',') => self.at += 1,
                        Some(b']') => {
                            self.at += 1;
                            return Ok(());
                        }
                        None => return Err(self.invalid("the JSON text ends too early")),
                        Some(_) => return Err(self.invalid("expected , or ]")),
                    }
                }
            }
            Some(b'"') => self.string().map(|_| ()),
            Some(_) => self.scalar(),
        }
    }

    /// A literal or a number: the bytes until a delimiter, checked by the JSON reader.
    fn scalar(&mut self) -> Result<(), String> {
        let start = self.at;
        while self.at < self.bytes.len()
            && !matches!(self.bytes[self.at], b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n')
        {
            self.at += 1;
        }
        let token = &self.bytes[start..self.at];
        let valid = matches!(token, b"true" | b"false" | b"null")
            || (serde_json::from_slice::<serde_json::Number>(token).is_ok());
        if valid {
            Ok(())
        } else {
            self.at = start;
            Err(self.invalid("a character that is not valid JSON"))
        }
    }

    /// A string: its decoded text.
    fn string(&mut self) -> Result<String, String> {
        if self.peek() != Some(b'"') {
            return Err(self.invalid("expected a string"));
        }
        let start = self.at;
        self.at += 1;
        while let Some(byte) = self.peek() {
            self.at += 1;
            match byte {
                b'"' => {
                    return serde_json::from_slice::<String>(&self.bytes[start..self.at]).map_err(|_| {
                        self.at = start;
                        self.invalid("invalid string")
                    });
                }
                b'\\' => self.at += 1,
                _ => {}
            }
        }
        Err(self.invalid("the JSON text ends too early"))
    }
}

#[cfg(test)]
#[path = "keys_tests.rs"]
mod tests;
