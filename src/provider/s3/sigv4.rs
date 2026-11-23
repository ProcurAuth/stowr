//! The AWS Signature Version 4 of a request (service `s3`).
//!
//! The signature covers the method, the escaped path, the query in its canonical form, the host, and these headers:
//! each `x-amz-*` header, `content-type`, `content-md5`, `range`, `if-match`, `if-none-match`, `if-modified-since` and
//! `if-unmodified-since`. A request with a body has the payload hash `UNSIGNED-PAYLOAD`. A request without a body
//! has the hash of the empty text. The signing key of a secret, a day and a region stays in a small cache.

use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;

use aws_lc_rs::{digest, hmac};
use http::header::{AUTHORIZATION, HeaderValue};
use http::{HeaderMap, Method, Uri};

use crate::common::error::{Error, Result};
use crate::common::misc::hex;
use crate::common::time::Timestamp;

/// The credentials of an `auth` block in mode `access_key`.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Credentials {
    /// The access key id.
    pub access_key_id: String,
    /// The secret access key.
    pub secret_access_key: String,
    /// The session token, or an empty text.
    pub session_token: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials")
            .field("access_key_id", &self.access_key_id)
            .finish_non_exhaustive()
    }
}

/// The payload hash of a request with a body: the body is not part of the signature.
pub const UNSIGNED_PAYLOAD: &str = "UNSIGNED-PAYLOAD";

/// The lower-case hexadecimal SHA-256 of bytes.
pub fn sha256_hex(data: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, data).as_ref())
}

/// The HMAC-SHA-256 of a text with a key.
pub fn hmac_sha256(key: &[u8], value: &str) -> Vec<u8> {
    hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), value.as_bytes())
        .as_ref()
        .to_vec()
}

/// The URI encoding of AWS: letters, digits and `-_.~` stay, `/` stays when `encode_slash` is false, and each other
/// byte becomes `%XX` with upper-case digits.
pub fn aws_uri_encode(value: &str, encode_slash: bool) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(value.len());
    for &byte in value.as_bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') || (byte == b'/' && !encode_slash)
        {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(char::from(DIGITS[usize::from(byte >> 4)]));
            out.push(char::from(DIGITS[usize::from(byte & 0xf)]));
        }
    }
    out
}

/// The canonical query of pairs: each `name=value` with the URI encoding of AWS, in the order of the texts, joined
/// with `&`.
pub fn canonical_query<N: AsRef<str>, V: AsRef<str>>(pairs: &[(N, V)]) -> String {
    let mut encoded: Vec<String> = pairs
        .iter()
        .map(|(name, value)| {
            format!(
                "{}={}",
                aws_uri_encode(name.as_ref(), true),
                aws_uri_encode(value.as_ref(), true)
            )
        })
        .collect();
    encoded.sort();
    encoded.join("&")
}

/// The canonical form of a raw query. A query that does not parse (a part with `;` or a bad escape) stays as it is.
pub fn canonical_raw_query(raw: &str) -> String {
    if raw.is_empty() {
        return String::new();
    }
    let mut pairs = Vec::new();
    for part in raw.split('&') {
        if part.is_empty() {
            continue;
        }
        if part.contains(';') {
            return raw.to_owned();
        }
        let (name, value) = part.split_once('=').unwrap_or((part, ""));
        let (Some(name), Some(value)) = (
            crate::common::query::unescape(name, true),
            crate::common::query::unescape(value, true),
        ) else {
            return raw.to_owned();
        };
        pairs.push((name, value));
    }
    canonical_query(&pairs)
}

type KeyId = (String, String, String);

/// The signing keys that the process derived: one for each secret, day and region.
static SIGNING_KEYS: Mutex<Option<HashMap<KeyId, Vec<u8>>>> = Mutex::new(None);

/// The most signing keys in the cache. A full cache starts again empty.
const MAX_SIGNING_KEYS: usize = 16;

fn derive_signing_key(secret: &str, date: &str, region: &str) -> Vec<u8> {
    let date_key = hmac_sha256(format!("AWS4{secret}").as_bytes(), date);
    let region_key = hmac_sha256(&date_key, region);
    let service_key = hmac_sha256(&region_key, "s3");
    hmac_sha256(&service_key, "aws4_request")
}

/// The signing key of a secret, a day (`YYYYMMDD`) and a region. The key changes only with these three values, so
/// the process keeps the keys that it derived instead of four HMAC operations for each request.
pub fn signing_key(secret: &str, date: &str, region: &str) -> Vec<u8> {
    let id = (secret.to_owned(), date.to_owned(), region.to_owned());
    let Ok(mut cache) = SIGNING_KEYS.lock() else {
        return derive_signing_key(secret, date, region);
    };
    if let Some(key) = cache.as_ref().and_then(|keys| keys.get(&id)) {
        return key.clone();
    }
    let key = derive_signing_key(secret, date, region);
    let keys = cache.get_or_insert_with(HashMap::new);
    if keys.len() >= MAX_SIGNING_KEYS {
        keys.clear();
    }
    keys.insert(id, key.clone());
    key
}

/// The date and time of the signature (`19941106T084937Z`) and the day (`19941106`).
fn amz_date(now: Timestamp) -> (String, String) {
    let text: String = now
        .utc()
        .rfc3339()
        .chars()
        .filter(|character| *character != '-' && *character != ':')
        .collect();
    let day = text.chars().take(8).collect();
    (text, day)
}

/// The canonical headers and the list of the signed headers.
fn canonical_headers(host: &str, headers: &HeaderMap) -> (String, String) {
    let mut values: BTreeMap<String, Vec<String>> = BTreeMap::new();
    values.insert("host".to_owned(), vec![host.to_owned()]);
    for (name, value) in headers {
        let lower = name.as_str();
        if matches!(
            lower,
            "authorization" | "user-agent" | "accept-encoding" | "content-length" | "host"
        ) {
            continue;
        }
        let signed = lower.starts_with("x-amz-")
            || matches!(
                lower,
                "content-type"
                    | "content-md5"
                    | "range"
                    | "if-match"
                    | "if-none-match"
                    | "if-modified-since"
                    | "if-unmodified-since"
            );
        if !signed {
            continue;
        }
        let text = String::from_utf8_lossy(value.as_bytes());
        values
            .entry(lower.to_owned())
            .or_default()
            .push(text.split_whitespace().collect::<Vec<_>>().join(" "));
    }
    let mut canonical = String::new();
    for (name, list) in &values {
        canonical.push_str(name);
        canonical.push(':');
        canonical.push_str(&list.join(","));
        canonical.push('\n');
    }
    let names: Vec<&str> = values.keys().map(String::as_str).collect();
    (canonical, names.join(";"))
}

fn header_value(text: &str) -> Result<HeaderValue> {
    HeaderValue::from_str(text).map_err(|_| Error::internal("the signature of the s3 request has an invalid header"))
}

/// Sign a request: set `x-amz-date`, `x-amz-content-sha256`, `x-amz-security-token` (with a session token) and
/// `Authorization` in the headers. The URI is absolute: its authority is the signed host.
pub fn sign(
    method: &Method,
    uri: &Uri,
    headers: &mut HeaderMap,
    has_body: bool,
    credentials: &Credentials,
    region: &str,
    now: Timestamp,
) -> Result<()> {
    if credentials.access_key_id.is_empty() || credentials.secret_access_key.is_empty() {
        return Err(Error::internal("cannot sign s3 request without credentials"));
    }
    if region.is_empty() {
        return Err(Error::internal("cannot sign s3 request without a region"));
    }
    let (date_time, day) = amz_date(now);
    let payload_hash = if has_body {
        UNSIGNED_PAYLOAD.to_owned()
    } else {
        sha256_hex(b"")
    };
    headers.insert("x-amz-date", header_value(&date_time)?);
    headers.insert("x-amz-content-sha256", header_value(&payload_hash)?);
    if !credentials.session_token.is_empty() {
        headers.insert("x-amz-security-token", header_value(&credentials.session_token)?);
    }
    let host = uri.authority().map_or("", |authority| authority.as_str());
    let (canonical, signed_headers) = canonical_headers(host, headers);
    let path = match uri.path() {
        "" => "/",
        path => path,
    };
    let canonical_request = [
        method.as_str(),
        path,
        &canonical_raw_query(uri.query().unwrap_or("")),
        &canonical,
        &signed_headers,
        &payload_hash,
    ]
    .join("\n");
    let scope = format!("{day}/{region}/s3/aws4_request");
    let string_to_sign = [
        "AWS4-HMAC-SHA256",
        &date_time,
        &scope,
        &sha256_hex(canonical_request.as_bytes()),
    ]
    .join("\n");
    let key = signing_key(&credentials.secret_access_key, &day, region);
    let signature = hex(&hmac_sha256(&key, &string_to_sign));
    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope},SignedHeaders={signed_headers},Signature={signature}",
        credentials.access_key_id
    );
    headers.insert(AUTHORIZATION, header_value(&authorization)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_signature_matches_the_aws_reference_vector() {
        let uri: Uri = "https://examplebucket.s3.amazonaws.com/test.txt".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("range", HeaderValue::from_static("bytes=0-9"));
        let credentials = Credentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_owned(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_owned(),
            session_token: String::new(),
        };
        let when = Timestamp::parse_rfc3339("2013-05-24T00:00:00Z").unwrap();
        sign(&Method::GET, &uri, &mut headers, false, &credentials, "us-east-1", when).unwrap();
        let want = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,\
                    SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,\
                    Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41";
        assert_eq!(headers.get(AUTHORIZATION).unwrap(), want);
        assert_eq!(
            headers.get("x-amz-content-sha256").unwrap().to_str().unwrap(),
            sha256_hex(b"")
        );
    }

    #[test]
    fn the_canonical_query_and_the_path_encoding() {
        let pairs = [("prefix", "a b/+"), ("max-keys", "2"), ("empty", "")];
        assert_eq!(canonical_query(&pairs), "empty=&max-keys=2&prefix=a%20b%2F%2B");
        assert_eq!(canonical_raw_query("prefix=a+b%2F&x"), "prefix=a%20b%2F&x=");
        assert_eq!(canonical_raw_query("a=1;b=2"), "a=1;b=2");
        assert_eq!(aws_uri_encode("a//./../b +é.txt", false), "a//./../b%20%2B%C3%A9.txt");
        assert_eq!(aws_uri_encode("my bucket", true), "my%20bucket");
    }

    #[test]
    fn the_signing_key_matches_the_derivation() {
        let want = hmac_sha256(
            &hmac_sha256(
                &hmac_sha256(&hmac_sha256(b"AWS4secret-a", "20260102"), "eu-west-1"),
                "s3",
            ),
            "aws4_request",
        );
        for attempt in 0..2 {
            assert_eq!(
                signing_key("secret-a", "20260102", "eu-west-1"),
                want,
                "attempt {attempt}"
            );
        }
        assert_ne!(signing_key("secret-b", "20260102", "eu-west-1"), want);
    }

    #[test]
    fn a_signature_needs_credentials_and_a_region() {
        let uri: Uri = "http://127.0.0.1:9000/bucket".parse().unwrap();
        let mut headers = HeaderMap::new();
        let credentials = Credentials {
            access_key_id: "id".to_owned(),
            secret_access_key: "secret".to_owned(),
            session_token: "token".to_owned(),
        };
        let now = Timestamp::now();
        assert!(
            sign(
                &Method::GET,
                &uri,
                &mut headers,
                false,
                &Credentials::default(),
                "r",
                now
            )
            .is_err()
        );
        assert!(sign(&Method::GET, &uri, &mut headers, false, &credentials, "", now).is_err());
        sign(&Method::PUT, &uri, &mut headers, true, &credentials, "r", now).unwrap();
        assert_eq!(headers.get("x-amz-content-sha256").unwrap(), UNSIGNED_PAYLOAD);
        assert_eq!(headers.get("x-amz-security-token").unwrap(), "token");
        let authorization = headers.get(AUTHORIZATION).unwrap().to_str().unwrap();
        assert!(authorization.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token,"));
    }
}
