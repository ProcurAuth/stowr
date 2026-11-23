//! The AWS Signature Version 4 of a `GET` request to an admin API (the admin API of MinIO uses service `s3`).

use aws_lc_rs::{digest, hmac};

use super::support::aws_uri_encode;
use crate::common::misc::hex;
use crate::common::time::Timestamp;

/// The values that a signature needs.
pub struct SigningInput<'a> {
    /// The method.
    pub method: &'a str,
    /// The path of the URL in its escaped form.
    pub canonical_uri: &'a str,
    /// The query pairs.
    pub query: &'a [(String, String)],
    /// The signed headers: the lower-case name and the value. They go in the order of the names.
    pub headers: &'a [(String, String)],
    /// The hexadecimal SHA-256 of the body.
    pub payload_hash: &'a str,
    /// The access key id.
    pub access_key_id: &'a str,
    /// The secret access key.
    pub secret_access_key: &'a str,
    /// The region.
    pub region: &'a str,
    /// The service (`s3`).
    pub service: &'a str,
    /// The time of the request.
    pub time: Timestamp,
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&key, data).as_ref().to_vec()
}

/// The hexadecimal SHA-256 of bytes.
pub fn sha256_hex(data: &[u8]) -> String {
    hex(digest::digest(&digest::SHA256, data).as_ref())
}

/// The date and time of a signature: `20130524T000000Z`.
pub fn amz_date(time: Timestamp) -> String {
    time.utc().rfc3339().replace(['-', ':'], "")
}

/// The canonical form of the query: the pairs encoded and sorted.
pub fn canonical_query(query: &[(String, String)]) -> String {
    let mut pairs: Vec<String> = query
        .iter()
        .map(|(name, value)| format!("{}={}", aws_uri_encode(name, true), aws_uri_encode(value, true)))
        .collect();
    pairs.sort();
    pairs.join("&")
}

/// The value of the header `Authorization`.
pub fn authorization(input: &SigningInput<'_>) -> String {
    let date = amz_date(input.time);
    let stamp = &date[..8];
    let mut canonical_headers = String::new();
    let mut names: Vec<&str> = Vec::new();
    for (name, value) in input.headers {
        canonical_headers.push_str(&format!("{name}:{}\n", value.trim()));
        names.push(name);
    }
    let signed_headers = names.join(";");
    let canonical_request = [
        input.method,
        input.canonical_uri,
        &canonical_query(input.query),
        &canonical_headers,
        &signed_headers,
        input.payload_hash,
    ]
    .join("\n");
    let scope = format!("{stamp}/{}/{}/aws4_request", input.region, input.service);
    let string_to_sign = [
        "AWS4-HMAC-SHA256",
        date.as_str(),
        scope.as_str(),
        &sha256_hex(canonical_request.as_bytes()),
    ]
    .join("\n");
    let date_key = hmac_sha256(format!("AWS4{}", input.secret_access_key).as_bytes(), stamp.as_bytes());
    let region_key = hmac_sha256(&date_key, input.region.as_bytes());
    let service_key = hmac_sha256(&region_key, input.service.as_bytes());
    let signing_key = hmac_sha256(&service_key, b"aws4_request");
    let signature = hex(&hmac_sha256(&signing_key, string_to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope},SignedHeaders={signed_headers},Signature={signature}",
        input.access_key_id
    )
}
