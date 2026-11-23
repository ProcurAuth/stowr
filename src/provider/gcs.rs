//! The GCS back end: the JSON API, the OAuth token of a service account (an RS256 JWT), the generations and the
//! resumable upload.
//!
//! A bucket in mode `service_account` sends `Authorization: Bearer <token>`. The token comes from the token endpoint
//! of the key file, in exchange for a JWT that the RSA key of the file signs. The token stays in memory until one
//! minute before its end. A bucket in mode `anonymous` sends no token.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read as _;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use http::header::{ACCEPT_ENCODING, AUTHORIZATION, CONTENT_TYPE, HeaderValue, RANGE};
use http::{HeaderMap, Method, Response};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer};

use super::client::{StorageClient, build_request, header_text, parse_answer, status_text, with_context};
use super::s3::{READ_HEADERS, first_value, probed_state, read_ceiling_applies, read_some, set_header, sort_versions};
use super::url::WebUrl;
use super::{SharedAuth, wrong_provider};
use crate::common::BoxFuture;
use crate::common::config::{BucketConfig, PERMISSION_DELETE, PERMISSION_READ, PERMISSION_WRITE, Provider};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Body, empty, full, read_limited};
use crate::common::query::encode_sorted;
use crate::common::storage::{
    Backend, ConditionalWriter, DiscoveredCapabilities, ListOptions, ListPage, ObjectInfo, ObjectResponse,
    ObjectVersionPage, ResumableApi, StoredObjectVersion, VersionStore,
};
use crate::common::time::Timestamp;

/// The OAuth scope of the token of a service account.
pub const OAUTH_SCOPE: &str = "https://www.googleapis.com/auth/devstorage.full_control";

/// The largest key file of a service account: 4 MiB.
const MAX_CREDENTIALS_BYTES: u64 = 4 << 20;
/// The limit of a listing answer.
const LIST_LIMIT: usize = 32 << 20;
/// The limit of the other answers.
const SMALL_LIMIT: usize = 1 << 20;
/// The limit of an error answer.
const ERROR_LIMIT: usize = 256 << 10;
/// The most requests of one copy on the provider.
const MAX_COPY_STEPS: usize = 10_000;
/// A token is used again while it has more than this time left.
const TOKEN_MARGIN: Duration = Duration::from_secs(60);

/// The DER object identifiers of the private keys of PKCS #8.
const OID_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
const OID_EC: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70];
const OID_X25519: &[u8] = &[0x2b, 0x65, 0x6e];

/// A text member of a JSON answer: `null` and a missing member give an empty text.
fn text<'de, D: Deserializer<'de>>(deserializer: D) -> std::result::Result<String, D::Error> {
    Ok(Option::<String>::deserialize(deserializer)?.unwrap_or_default())
}

/// Decode the first JSON value of a body. The bytes after the value are ignored.
fn decode_first<T: DeserializeOwned>(bytes: &[u8]) -> std::result::Result<T, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    T::deserialize(&mut deserializer)
}

/// The text of an operating system error: the message in lower case, without the error number.
fn os_error_text(error: &std::io::Error) -> String {
    let text = error.to_string();
    let text = match text.rfind(" (os error ") {
        Some(index) => text[..index].to_owned(),
        None => text,
    };
    let mut characters = text.chars();
    match characters.next() {
        Some(first) => first.to_lowercase().chain(characters).collect(),
        None => text,
    }
}

/// The key file of a service account.
#[derive(Clone, Default, Deserialize)]
struct ServiceAccount {
    #[serde(rename = "type", default, deserialize_with = "text")]
    kind: String,
    #[serde(default, deserialize_with = "text")]
    private_key_id: String,
    #[serde(default, deserialize_with = "text")]
    private_key: String,
    #[serde(default, deserialize_with = "text")]
    client_email: String,
    #[serde(default, deserialize_with = "text")]
    token_uri: String,
}

/// The token in memory and its end.
#[derive(Default)]
struct TokenState {
    token: String,
    expiry: Option<Instant>,
}

/// The OAuth token source of a service account. The buckets of an `auth` block share it.
pub struct GcsTokenSource {
    info: ServiceAccount,
    key: RsaKeyPair,
    client: StorageClient,
    state: tokio::sync::Mutex<TokenState>,
}

impl std::fmt::Debug for GcsTokenSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcsTokenSource")
            .field("client_email", &self.info.client_email)
            .finish_non_exhaustive()
    }
}

/// The first PEM block of a text: the bytes of its base64 content.
fn pem_block(text: &str) -> Option<Vec<u8>> {
    let mut rest = text;
    loop {
        let start = if rest.starts_with("-----BEGIN ") {
            0
        } else {
            rest.find("\n-----BEGIN ")? + 1
        };
        rest = &rest[start + "-----BEGIN ".len()..];
        let (type_line, after) = rest.split_once('\n').unwrap_or((rest, ""));
        let type_line = type_line.trim_end_matches('\r');
        let Some(kind) = type_line.strip_suffix("-----") else {
            continue;
        };
        let end_marker = format!("-----END {kind}-----");
        let (content, after_end) = if after.starts_with("-----END ") {
            ("", after)
        } else {
            match after.find("\n-----END ") {
                Some(index) => (&after[..index], &after[index + 1..]),
                None => continue,
            }
        };
        if !after_end.starts_with(&end_marker) {
            continue;
        }
        let tail = &after_end[end_marker.len()..];
        if !tail.split('\n').next().unwrap_or("").trim().is_empty() {
            continue;
        }
        let compact: String = content.chars().filter(|character| !character.is_whitespace()).collect();
        if let Ok(bytes) = STANDARD.decode(compact) {
            return Some(bytes);
        }
    }
}

/// One DER element: the tag, the content and the bytes after the element.
fn der_element(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 || rest.len() < count {
            return None;
        }
        let length = rest[..count]
            .iter()
            .fold(0usize, |total, byte| (total << 8) | usize::from(*byte));
        (length, &rest[count..])
    };
    if rest.len() < length {
        return None;
    }
    Some((tag, &rest[..length], &rest[length..]))
}

/// The algorithm of a PKCS #8 private key, or `None` for bytes that are not PKCS #8.
fn pkcs8_algorithm(der: &[u8]) -> Option<&[u8]> {
    let (0x30, info, _) = der_element(der)? else {
        return None;
    };
    let (0x02, _, rest) = der_element(info)? else {
        return None;
    };
    let (0x30, algorithm, rest) = der_element(rest)? else {
        return None;
    };
    let (0x06, oid, _) = der_element(algorithm)? else {
        return None;
    };
    let (0x04, _, _) = der_element(rest)? else {
        return None;
    };
    Some(oid)
}

/// The RSA key of a key file: PKCS #8, else PKCS #1.
fn parse_rsa_key(der: &[u8]) -> Result<RsaKeyPair> {
    let rejected = |error: aws_lc_rs::error::KeyRejected| {
        if error.description_() == "TooSmall" || error.description_() == "TooLarge" {
            Error::internal("parse gcs RSA private key: the key must have 2048 to 8192 bits")
        } else {
            Error::internal("parse gcs RSA private key: unsupported key encoding")
        }
    };
    match pkcs8_algorithm(der) {
        Some(OID_RSA) => RsaKeyPair::from_pkcs8(der).map_err(rejected),
        Some(OID_EC | OID_ED25519 | OID_X25519) => Err(Error::internal("gcs private key is not RSA")),
        _ => RsaKeyPair::from_der(der).map_err(rejected),
    }
}

impl GcsTokenSource {
    /// Read the key file of a service account: at most 4 MiB, a JSON object of type `service_account` with
    /// `client_email`, `private_key` (an RSA key in PEM) and `token_uri`.
    pub fn load(path: &Path, client: StorageClient) -> Result<Self> {
        let name = format!("{:?}", path.display().to_string());
        let file = std::fs::File::open(path).map_err(|error| {
            Error::internal(format!(
                "open gcs credentials file {name}: open {}: {}",
                path.display(),
                os_error_text(&error)
            ))
        })?;
        let size = file
            .metadata()
            .map_err(|error| {
                Error::internal(format!(
                    "inspect gcs credentials file {name}: {}",
                    os_error_text(&error)
                ))
            })?
            .len();
        let too_large = || {
            Error::internal(format!(
                "gcs credentials file {name} exceeds the {MAX_CREDENTIALS_BYTES}-byte limit"
            ))
        };
        if size > MAX_CREDENTIALS_BYTES {
            return Err(too_large());
        }
        let mut data = Vec::new();
        file.take(MAX_CREDENTIALS_BYTES + 1)
            .read_to_end(&mut data)
            .map_err(|error| Error::internal(format!("read gcs credentials file {name}: {}", os_error_text(&error))))?;
        if data.len() as u64 > MAX_CREDENTIALS_BYTES {
            return Err(too_large());
        }
        Self::from_json(&data, &name, client)
    }

    /// Read the JSON text of a key file. `name` is the quoted name of the file for the errors.
    pub fn from_json(data: &[u8], name: &str, client: StorageClient) -> Result<Self> {
        let info: ServiceAccount = serde_json::from_slice(data)
            .map_err(|error| Error::internal(format!("decode gcs credentials file {name}: {error}")))?;
        if info.kind != "service_account" {
            return Err(Error::internal(format!(
                "gcs credentials file {name} is not a service_account key"
            )));
        }
        if info.client_email.is_empty() || info.private_key.is_empty() || info.token_uri.is_empty() {
            return Err(Error::internal(format!(
                "gcs credentials file {name} is missing client_email, private_key or token_uri"
            )));
        }
        let der = pem_block(&info.private_key).ok_or_else(|| {
            Error::internal(format!(
                "gcs credentials file {name} contains an invalid PEM private key"
            ))
        })?;
        let key = parse_rsa_key(&der)?;
        Ok(Self {
            info,
            key,
            client,
            state: tokio::sync::Mutex::new(TokenState::default()),
        })
    }

    /// The signed JWT of the token request.
    fn assertion(&self, now: Timestamp) -> Result<String> {
        let mut header = BTreeMap::new();
        header.insert("alg", self.json_text("RS256"));
        header.insert("typ", self.json_text("JWT"));
        if !self.info.private_key_id.is_empty() {
            header.insert("kid", self.json_text(&self.info.private_key_id));
        }
        let mut claims = BTreeMap::new();
        claims.insert("iss", self.json_text(&self.info.client_email));
        claims.insert("scope", self.json_text(OAUTH_SCOPE));
        claims.insert("aud", self.json_text(&self.info.token_uri));
        claims.insert("iat", serde_json::Value::from(now.secs));
        claims.insert("exp", serde_json::Value::from(now.secs + 3600));
        let encode = |value: &BTreeMap<&str, serde_json::Value>| -> Result<String> {
            let json = crate::common::json::to_vec(value).map_err(|error| with_context("encode JWT", error))?;
            Ok(URL_SAFE_NO_PAD.encode(json))
        };
        let unsigned = format!("{}.{}", encode(&header)?, encode(&claims)?);
        let mut signature = vec![0u8; self.key.public_modulus_len()];
        self.key
            .sign(
                &RSA_PKCS1_SHA256,
                &SystemRandom::new(),
                unsigned.as_bytes(),
                &mut signature,
            )
            .map_err(|_| Error::internal("sign gcs service account JWT: the signature failed"))?;
        Ok(format!("{unsigned}.{}", URL_SAFE_NO_PAD.encode(signature)))
    }

    fn json_text(&self, value: &str) -> serde_json::Value {
        serde_json::Value::String(value.to_owned())
    }

    /// The access token: the token in memory while it has more than one minute left, else a new token from the
    /// token endpoint. Concurrent callers wait for one request.
    pub async fn token(&self, ctx: &OpCtx) -> Result<String> {
        let mut state = ctx.run(async { Ok(self.state.lock().await) }).await?;
        if !state.token.is_empty()
            && state
                .expiry
                .is_some_and(|expiry| expiry.saturating_duration_since(Instant::now()) > TOKEN_MARGIN)
        {
            return Ok(state.token.clone());
        }
        let started = Instant::now();
        let assertion = self.assertion(Timestamp::now())?;
        let form = encode_sorted(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer"),
            ("assertion", &assertion),
        ]);
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        let size = form.len() as i64;
        let request = build_request(Method::POST, &self.info.token_uri, headers, Some((full(form), size)))
            .map_err(|error| with_context("create gcs token request", error))?;
        let response = self
            .client
            .send(ctx, request)
            .await
            .map_err(|error| with_context("gcs token request failed", error))?;
        let status = response.status().as_u16();
        let (body, _) = read_limited(response.into_body(), SMALL_LIMIT)
            .await
            .map_err(|error| with_context("read gcs token response", error))?;
        if !(200..300).contains(&status) {
            return Err(Error::internal(format!(
                "gcs token endpoint returned HTTP {status}: {}",
                String::from_utf8_lossy(&body).trim()
            )));
        }
        #[derive(Deserialize)]
        struct TokenAnswer {
            #[serde(default, deserialize_with = "text")]
            access_token: String,
            #[serde(default)]
            expires_in: Option<i64>,
        }
        let answer: TokenAnswer = serde_json::from_slice(&body)
            .map_err(|error| Error::internal(format!("decode gcs token response: {error}")))?;
        if answer.access_token.is_empty() {
            return Err(Error::internal("gcs token response did not contain access_token"));
        }
        let lifetime = answer.expires_in.filter(|seconds| *seconds > 0).unwrap_or(3600);
        state.token = answer.access_token;
        state.expiry = Some(started + Duration::from_secs(lifetime.unsigned_abs()));
        Ok(state.token.clone())
    }
}

/// One path segment of the JSON API: each byte except letters, digits and `-_.~` becomes `%XX`.
pub fn path_segment(value: &str) -> String {
    super::s3::sigv4::aws_uri_encode(value, true)
}

/// The next offset of a resumable session from the `Range` header of an answer `308` (`bytes=0-1048575` gives
/// 1048576). A missing or bad header gives 0.
pub fn resumable_next_offset(value: &str) -> i64 {
    let value = value.trim();
    if value.is_empty() {
        return 0;
    }
    let Some((_, last)) = value.strip_prefix("bytes=").unwrap_or(value).split_once('-') else {
        return 0;
    };
    match last.trim().parse::<i64>() {
        Ok(last) if last >= 0 => last + 1,
        _ => 0,
    }
}

/// The provider error of a GCS answer: the `error.status` and the `error.message` of the JSON body. Without a
/// message, the message is the body, else the status line.
fn error_of(status: u16, body: &[u8]) -> Error {
    let parsed: serde_json::Value = serde_json::from_slice(body).unwrap_or_default();
    let field = |name: &str| {
        parsed
            .get("error")
            .and_then(|error| error.get(name))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_owned()
    };
    let mut message = field("message").trim().to_owned();
    if message.is_empty() {
        message = String::from_utf8_lossy(body).trim().to_owned();
    }
    if message.is_empty() {
        message = status_text(status);
    }
    Error::upstream(status, field("status"), message)
}

async fn gcs_error(response: Response<Body>) -> Error {
    let status = response.status().as_u16();
    let body = read_some(response.into_body(), ERROR_LIMIT).await;
    error_of(status, &body)
}

fn success(status: u16) -> bool {
    (200..300).contains(&status)
}

/// The GCS back end of one bucket.
pub struct GcsBackend {
    /// The configuration of the bucket.
    pub cfg: BucketConfig,
    /// The shared state of the auth block.
    pub auth: Arc<SharedAuth>,
}

impl std::fmt::Debug for GcsBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GcsBackend")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
struct ListItem {
    #[serde(default, deserialize_with = "text")]
    name: String,
    #[serde(default, deserialize_with = "text")]
    size: String,
    #[serde(default, deserialize_with = "text")]
    updated: String,
    #[serde(rename = "timeDeleted", default, deserialize_with = "text")]
    time_deleted: String,
    #[serde(default, deserialize_with = "text")]
    etag: String,
    #[serde(rename = "contentType", default, deserialize_with = "text")]
    content_type: String,
    #[serde(default, deserialize_with = "text")]
    generation: String,
    #[serde(rename = "md5Hash", default, deserialize_with = "text")]
    md5_hash: String,
    #[serde(default, deserialize_with = "text")]
    crc32c: String,
}

#[derive(Deserialize)]
struct ListAnswer {
    #[serde(default)]
    prefixes: Option<Vec<String>>,
    #[serde(rename = "nextPageToken", default, deserialize_with = "text")]
    next_page_token: String,
    #[serde(default)]
    items: Option<Vec<ListItem>>,
}

#[derive(Deserialize)]
struct ObjectMetadata {
    #[serde(default, deserialize_with = "text")]
    size: String,
    #[serde(default, deserialize_with = "text")]
    updated: String,
    #[serde(default, deserialize_with = "text")]
    etag: String,
    #[serde(rename = "contentType", default, deserialize_with = "text")]
    content_type: String,
    #[serde(rename = "cacheControl", default, deserialize_with = "text")]
    cache_control: String,
    #[serde(rename = "contentDisposition", default, deserialize_with = "text")]
    content_disposition: String,
    #[serde(rename = "contentEncoding", default, deserialize_with = "text")]
    content_encoding: String,
    #[serde(default, deserialize_with = "text")]
    generation: String,
    #[serde(default, deserialize_with = "text")]
    metageneration: String,
    #[serde(rename = "md5Hash", default, deserialize_with = "text")]
    md5_hash: String,
    #[serde(default, deserialize_with = "text")]
    crc32c: String,
    #[serde(default)]
    metadata: Option<BTreeMap<String, Option<String>>>,
}

/// Set a header of an answer that the back end makes. A value that a header cannot carry is left out.
fn put_header(headers: &mut HeaderMap, name: &str, value: &str) {
    if let (Ok(name), Ok(value)) = (
        http::header::HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_bytes(value.as_bytes()),
    ) {
        headers.insert(name, value);
    }
}

impl GcsBackend {
    /// The back end of a bucket. The `auth` block must be a GCS block.
    pub fn new(cfg: BucketConfig, auth: Arc<SharedAuth>) -> Result<Self> {
        if auth.cfg.provider != Provider::Gcs {
            return Err(wrong_provider(&cfg, "a GCS"));
        }
        Ok(Self { cfg, auth })
    }

    /// The URL of a path of the API below the endpoint (an escaped path) with a query.
    pub fn api_url(&self, relative_raw_path: &str, query: &[(&str, &str)]) -> String {
        let raw = relative_raw_path.trim_start_matches('/');
        self.auth.endpoint().join(&format!("/{raw}"), &encode_sorted(query))
    }

    /// The URL of the metadata of an object.
    pub fn object_metadata_url(&self, key: &str, query: &[(&str, &str)]) -> String {
        self.api_url(
            &format!(
                "storage/v1/b/{}/o/{}",
                path_segment(&self.cfg.bucket),
                path_segment(key)
            ),
            query,
        )
    }

    fn objects_url(&self, upload: bool, query: &[(&str, &str)]) -> String {
        let prefix = if upload { "upload/" } else { "" };
        self.api_url(
            &format!("{prefix}storage/v1/b/{}/o", path_segment(&self.cfg.bucket)),
            query,
        )
    }

    async fn authorize(&self, ctx: &OpCtx, headers: &mut HeaderMap) -> Result<()> {
        if let Some(tokens) = self.auth.gcs_token() {
            let token = tokens.token(ctx).await?;
            set_header(headers, AUTHORIZATION.as_str(), &format!("Bearer {token}"))?;
        }
        Ok(())
    }

    async fn execute(
        &self,
        ctx: &OpCtx,
        method: Method,
        url: &str,
        mut headers: HeaderMap,
        body: Option<(Body, i64)>,
        what: &str,
    ) -> Result<Response<Body>> {
        self.authorize(ctx, &mut headers).await?;
        let request = build_request(method, url, headers, body)
            .map_err(|error| with_context(&format!("create {what}"), error))?;
        self.auth
            .client
            .send(ctx, request)
            .await
            .map_err(|error| with_context(&format!("{what} failed"), error))
    }

    async fn request(&self, ctx: &OpCtx, method: Method, url: &str, headers: HeaderMap) -> Result<Response<Body>> {
        self.execute(ctx, method, url, headers, None, "gcs request").await
    }

    async fn read_json<T: DeserializeOwned + Send + 'static>(
        response: Response<Body>,
        limit: usize,
        what: &str,
    ) -> Result<T> {
        let (body, _) = read_limited(response.into_body(), limit)
            .await
            .map_err(|error| with_context(what, error))?;
        parse_answer(body, |body| decode_first::<T>(body).map_err(|error| error.to_string()))
            .await?
            .map_err(|error| Error::internal(format!("{what}: {error}")))
    }

    async fn list_page(&self, ctx: &OpCtx, options: &ListOptions) -> Result<ListPage> {
        let max_results = options.max_results.to_string();
        let mut query: Vec<(&str, &str)> = Vec::new();
        if !options.prefix.is_empty() {
            query.push(("prefix", &options.prefix));
        }
        if !options.delimiter.is_empty() {
            query.push(("delimiter", &options.delimiter));
            query.push(("includeTrailingDelimiter", "false"));
        }
        if options.max_results > 0 {
            query.push(("maxResults", &max_results));
        }
        if !options.page_token.is_empty() {
            query.push(("pageToken", &options.page_token));
        }
        if !options.start_after.is_empty() {
            query.push(("startOffset", &options.start_after));
        }
        query.push((
            "fields",
            "items(name,size,updated,etag,contentType),prefixes,nextPageToken",
        ));
        let response = self
            .request(ctx, Method::GET, &self.objects_url(false, &query), HeaderMap::new())
            .await?;
        if !success(response.status().as_u16()) {
            return Err(gcs_error(response).await);
        }
        let answer: ListAnswer = Self::read_json(response, LIST_LIMIT, "decode gcs list response").await?;
        Ok(ListPage {
            prefixes: answer.prefixes.unwrap_or_default(),
            next_page_token: answer.next_page_token,
            objects: answer
                .items
                .unwrap_or_default()
                .into_iter()
                .map(|item| ObjectInfo {
                    size: item.size.parse().unwrap_or(0),
                    last_modified: Timestamp::parse_rfc3339(&item.updated),
                    key: item.name,
                    etag: item.etag,
                    content_type: item.content_type,
                    unreadable: false,
                })
                .collect(),
        })
    }

    async fn head_generation(&self, ctx: &OpCtx, key: &str, generation: &str) -> Result<ObjectResponse> {
        let mut query = vec![(
            "fields",
            "name,size,updated,timeCreated,timeDeleted,etag,contentType,cacheControl,contentDisposition,contentEncoding,generation,metageneration,md5Hash,crc32c,metadata",
        )];
        if !generation.is_empty() {
            query.push(("generation", generation));
        }
        let response = self
            .request(
                ctx,
                Method::GET,
                &self.object_metadata_url(key, &query),
                HeaderMap::new(),
            )
            .await?;
        if !success(response.status().as_u16()) {
            return Err(gcs_error(response).await);
        }
        let metadata: ObjectMetadata = Self::read_json(response, SMALL_LIMIT, "decode gcs object metadata").await?;
        let mut headers = HeaderMap::new();
        put_header(&mut headers, "content-length", &metadata.size);
        if !metadata.content_type.is_empty() {
            put_header(&mut headers, "content-type", &metadata.content_type);
        }
        if !metadata.etag.is_empty() {
            put_header(&mut headers, "etag", &metadata.etag);
        }
        if let Some(updated) = Timestamp::parse_rfc3339(&metadata.updated) {
            put_header(&mut headers, "last-modified", &updated.http_date());
        }
        if !metadata.cache_control.is_empty() {
            put_header(&mut headers, "cache-control", &metadata.cache_control);
        }
        if !metadata.content_disposition.is_empty() {
            put_header(&mut headers, "content-disposition", &metadata.content_disposition);
        }
        if !metadata.content_encoding.is_empty() {
            put_header(&mut headers, "content-encoding", &metadata.content_encoding);
        }
        if !metadata.generation.is_empty() {
            put_header(&mut headers, "x-goog-generation", &metadata.generation);
        }
        if !metadata.metageneration.is_empty() {
            put_header(&mut headers, "x-goog-metageneration", &metadata.metageneration);
        }
        if !metadata.md5_hash.is_empty() || !metadata.crc32c.is_empty() {
            let mut values = Vec::new();
            if !metadata.crc32c.is_empty() {
                values.push(format!("crc32c={}", metadata.crc32c));
            }
            if !metadata.md5_hash.is_empty() {
                values.push(format!("md5={}", metadata.md5_hash));
            }
            put_header(&mut headers, "x-goog-hash", &values.join(","));
        }
        for (name, value) in metadata.metadata.unwrap_or_default() {
            put_header(&mut headers, &format!("x-goog-meta-{name}"), &value.unwrap_or_default());
        }
        Ok(ObjectResponse {
            status: 200,
            headers,
            body: empty(),
        })
    }

    async fn get_generation(
        &self,
        ctx: &OpCtx,
        key: &str,
        generation: &str,
        request: &HeaderMap,
    ) -> Result<ObjectResponse> {
        let mut query = vec![("alt", "media")];
        if !generation.is_empty() {
            query.push(("generation", generation));
        }
        let mut headers = HeaderMap::new();
        for name in &READ_HEADERS {
            if let Some(value) = first_value(request, name) {
                headers.insert(name.clone(), value);
            }
        }
        // With a ceiling of object.read, the answer must tell the real size of the object: no decode of gzip.
        if headers.contains_key(RANGE) || read_ceiling_applies(ctx) {
            headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("identity"));
        }
        let response = self
            .request(ctx, Method::GET, &self.object_metadata_url(key, &query), headers)
            .await?;
        let status = response.status().as_u16();
        if !(success(status) || status == 304) {
            return Err(gcs_error(response).await);
        }
        let (parts, body) = response.into_parts();
        Ok(ObjectResponse {
            status,
            headers: parts.headers,
            body,
        })
    }

    async fn list_generations(
        &self,
        ctx: &OpCtx,
        key: &str,
        page_token: &str,
        maximum: u32,
    ) -> Result<ObjectVersionPage> {
        let maximum = if maximum == 0 || maximum > 1000 { 1000 } else { maximum }.to_string();
        let mut query = vec![("prefix", key), ("versions", "true"), ("maxResults", &maximum)];
        if !page_token.is_empty() {
            query.push(("pageToken", page_token));
        }
        query.push((
            "fields",
            "items(name,size,updated,timeCreated,timeDeleted,etag,contentType,generation,metageneration,md5Hash,crc32c),nextPageToken",
        ));
        let response = self
            .request(ctx, Method::GET, &self.objects_url(false, &query), HeaderMap::new())
            .await?;
        if !success(response.status().as_u16()) {
            return Err(gcs_error(response).await);
        }
        let answer: ListAnswer = Self::read_json(response, LIST_LIMIT, "decode gcs version response").await?;
        let mut page = ObjectVersionPage::default();
        let mut last_exact_key = false;
        for item in answer.items.unwrap_or_default() {
            last_exact_key = item.name == key;
            if !last_exact_key {
                continue;
            }
            let mut checksums = BTreeMap::new();
            if !item.md5_hash.is_empty() {
                checksums.insert("md5".to_owned(), item.md5_hash);
            }
            if !item.crc32c.is_empty() {
                checksums.insert("crc32c".to_owned(), item.crc32c);
            }
            page.versions.push(StoredObjectVersion {
                version: item.generation,
                is_current: item.time_deleted.is_empty(),
                delete_marker: false,
                size: item.size.parse().unwrap_or(0),
                last_modified: Timestamp::parse_rfc3339(&item.updated),
                etag: item.etag,
                content_type: item.content_type,
                checksums,
            });
        }
        sort_versions(&mut page.versions);
        // One generation at most is current. Some compatible APIs leave out timeDeleted for archived generations: only
        // the newest live generation of the first page stays current, and no generation of a later page is current.
        let mut current_kept = false;
        for version in &mut page.versions {
            if page_token.is_empty() && version.is_current && !current_kept {
                current_kept = true;
                continue;
            }
            version.is_current = false;
        }
        // A prefix listing can continue with another object: the cursor stays only while the page ends on the key.
        if !answer.next_page_token.is_empty() && last_exact_key {
            page.next_page_token = answer.next_page_token;
        }
        Ok(page)
    }

    async fn put_object(
        &self,
        ctx: &OpCtx,
        key: &str,
        body: Body,
        size: i64,
        content_type: &str,
        if_absent: bool,
    ) -> Result<()> {
        let mut query = vec![("uploadType", "media"), ("name", key)];
        if if_absent {
            query.push(("ifGenerationMatch", "0"));
        }
        let mut headers = HeaderMap::new();
        let content_type = if content_type.is_empty() {
            "application/octet-stream"
        } else {
            content_type
        };
        set_header(&mut headers, CONTENT_TYPE.as_str(), content_type)?;
        let response = self
            .execute(
                ctx,
                Method::POST,
                &self.objects_url(true, &query),
                headers,
                Some((body, size)),
                "gcs request",
            )
            .await?;
        let status = response.status().as_u16();
        if if_absent && status == 412 {
            let _ = read_some(response.into_body(), SMALL_LIMIT).await;
            return Err(Error::api(
                409,
                "object_exists",
                "an object already exists at the extraction destination",
            ));
        }
        if !success(status) {
            return Err(gcs_error(response).await);
        }
        let _ = read_some(response.into_body(), SMALL_LIMIT).await;
        Ok(())
    }

    /// Check a session URL of a resumable upload. A relative URL resolves against the endpoint. The URL must have
    /// the origin of the endpoint, or both must be `https` hosts of `googleapis.com`.
    pub fn validate_resumable_url(&self, raw: &str) -> Result<WebUrl> {
        let endpoint = self.auth.endpoint();
        let mut url = WebUrl::parse(raw.trim())
            .map_err(|error| Error::internal(format!("parse gcs resumable session URL: {error}")))?;
        if !url.is_absolute() {
            url = url.resolve_against(endpoint);
        }
        if url.scheme != "http" && url.scheme != "https" {
            return Err(Error::internal("gcs resumable session URL has an unsupported scheme"));
        }
        if url.authority.is_empty() || url.has_user || !url.fragment.is_empty() {
            return Err(Error::internal("gcs resumable session URL is invalid"));
        }
        let google = |scheme: &str, host: &str| {
            scheme.eq_ignore_ascii_case("https")
                && (host.eq_ignore_ascii_case("storage.googleapis.com")
                    || host.to_ascii_lowercase().ends_with(".googleapis.com"))
        };
        let same_origin = url.scheme.eq_ignore_ascii_case(&endpoint.scheme)
            && url.authority.eq_ignore_ascii_case(&endpoint.authority);
        let official = google(&endpoint.scheme, &endpoint.hostname) && google(&url.scheme, url.hostname());
        if !same_origin && !official {
            return Err(Error::internal(
                "gcs resumable session URL points to an unexpected host",
            ));
        }
        Ok(url)
    }

    async fn session_request(
        &self,
        ctx: &OpCtx,
        method: Method,
        url: &WebUrl,
        headers: HeaderMap,
        body: Option<(Body, i64)>,
    ) -> Result<Response<Body>> {
        self.execute(ctx, method, &url.text(), headers, body, "gcs resumable request")
            .await
    }

    async fn initiate_session(&self, ctx: &OpCtx, key: &str, total: i64, content_type: &str) -> Result<String> {
        let query = [("uploadType", "resumable"), ("name", key)];
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/json; charset=utf-8"),
        );
        let content_type = if content_type.is_empty() {
            "application/octet-stream"
        } else {
            content_type
        };
        set_header(&mut headers, "x-upload-content-type", content_type)?;
        if total >= 0 {
            headers.insert("x-upload-content-length", HeaderValue::from(total));
        }
        let response = self
            .execute(
                ctx,
                Method::POST,
                &self.objects_url(true, &query),
                headers,
                Some((full("{}"), 2)),
                "gcs request",
            )
            .await?;
        if !success(response.status().as_u16()) {
            return Err(gcs_error(response).await);
        }
        let location = header_text(response.headers(), &http::header::LOCATION)
            .trim()
            .to_owned();
        let _ = read_some(response.into_body(), SMALL_LIMIT).await;
        if location.is_empty() {
            return Err(Error::internal(
                "gcs resumable upload initiation did not return a session URL",
            ));
        }
        Ok(self.validate_resumable_url(&location)?.text())
    }

    #[allow(clippy::too_many_arguments)]
    async fn upload_session_chunk(
        &self,
        ctx: &OpCtx,
        session: &str,
        body: Body,
        start: i64,
        size: i64,
        total: i64,
        content_type: &str,
    ) -> Result<(i64, bool)> {
        if size <= 0 || start < 0 || total <= 0 || start + size > total {
            return Err(Error::internal("invalid gcs resumable upload range"));
        }
        let url = self.validate_resumable_url(session)?;
        let content_type = if content_type.is_empty() {
            "application/octet-stream"
        } else {
            content_type
        };
        let mut headers = HeaderMap::new();
        set_header(&mut headers, CONTENT_TYPE.as_str(), content_type)?;
        set_header(
            &mut headers,
            "content-range",
            &format!("bytes {start}-{}/{total}", start + size - 1),
        )?;
        let response = self
            .session_request(ctx, Method::PUT, &url, headers, Some((body, size)))
            .await?;
        Self::session_progress(response, total).await
    }

    /// The answer of a session: `308` gives the next offset, a success gives the end.
    async fn session_progress(response: Response<Body>, total: i64) -> Result<(i64, bool)> {
        let status = response.status().as_u16();
        if status == 308 {
            let next = resumable_next_offset(header_text(response.headers(), &RANGE));
            let _ = read_some(response.into_body(), SMALL_LIMIT).await;
            return Ok((next, false));
        }
        if success(status) {
            let _ = read_some(response.into_body(), SMALL_LIMIT).await;
            return Ok((total, true));
        }
        Err(gcs_error(response).await)
    }

    async fn query_session(&self, ctx: &OpCtx, session: &str, total: i64) -> Result<(i64, bool)> {
        let url = self.validate_resumable_url(session)?;
        let mut headers = HeaderMap::new();
        set_header(&mut headers, "content-range", &format!("bytes */{total}"))?;
        let response = self.session_request(ctx, Method::PUT, &url, headers, None).await?;
        Self::session_progress(response, total).await
    }

    async fn abort_session(&self, ctx: &OpCtx, session: &str) -> Result<()> {
        let url = self.validate_resumable_url(session)?;
        let response = self
            .session_request(ctx, Method::DELETE, &url, HeaderMap::new(), None)
            .await?;
        let status = response.status().as_u16();
        if success(status) || status == 404 || status == 499 {
            let _ = read_some(response.into_body(), SMALL_LIMIT).await;
            return Ok(());
        }
        Err(gcs_error(response).await)
    }

    /// Delete an object, or one generation (`Some`, also an empty one).
    async fn delete_generation(&self, ctx: &OpCtx, key: &str, generation: Option<&str>) -> Result<()> {
        let query: Vec<(&str, &str)> = generation.map_or_else(Vec::new, |generation| vec![("generation", generation)]);
        let response = self
            .request(
                ctx,
                Method::DELETE,
                &self.object_metadata_url(key, &query),
                HeaderMap::new(),
            )
            .await?;
        if !success(response.status().as_u16()) {
            return Err(gcs_error(response).await);
        }
        let _ = read_some(response.into_body(), SMALL_LIMIT).await;
        Ok(())
    }

    /// Copy an object with `rewriteTo`, with the continuation tokens of a large object.
    async fn server_copy(&self, ctx: &OpCtx, source: &str, destination: &str, source_generation: &str) -> Result<()> {
        let bucket = path_segment(&self.cfg.bucket);
        let path = format!(
            "storage/v1/b/{bucket}/o/{}/rewriteTo/b/{bucket}/o/{}",
            path_segment(source),
            path_segment(destination)
        );
        let mut continuation = String::new();
        for _ in 0..MAX_COPY_STEPS {
            let mut query = Vec::new();
            if !source_generation.is_empty() {
                query.push(("sourceGeneration", source_generation));
            }
            if !continuation.is_empty() {
                query.push(("rewriteToken", continuation.as_str()));
            }
            let url = self.api_url(&path, &query);
            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            let response = self
                .execute(ctx, Method::POST, &url, headers, Some((full("{}"), 2)), "gcs request")
                .await?;
            if !success(response.status().as_u16()) {
                return Err(gcs_error(response).await);
            }
            #[derive(Deserialize)]
            struct CopyStepAnswer {
                #[serde(default)]
                done: Option<bool>,
                #[serde(rename = "rewriteToken", default, deserialize_with = "text")]
                continuation: String,
            }
            let answer: CopyStepAnswer = Self::read_json(response, SMALL_LIMIT, "decode gcs rewrite response").await?;
            if answer.done.unwrap_or(false) {
                return Ok(());
            }
            if answer.continuation.is_empty() || answer.continuation == continuation {
                return Err(Error::internal(
                    "gcs rewrite did not complete and returned no new rewrite token",
                ));
            }
            continuation = answer.continuation;
        }
        Err(Error::internal("gcs rewrite exceeded maximum number of iterations"))
    }

    async fn discover(&self, ctx: &OpCtx) -> Result<DiscoveredCapabilities> {
        let query = [
            ("permissions", "storage.objects.list"),
            ("permissions", "storage.objects.get"),
            ("permissions", "storage.objects.create"),
            ("permissions", "storage.objects.delete"),
        ];
        let url = self.api_url(
            &format!("storage/v1/b/{}/iam/testPermissions", path_segment(&self.cfg.bucket)),
            &query,
        );
        let response = self.request(ctx, Method::GET, &url, HeaderMap::new()).await?;
        if !success(response.status().as_u16()) {
            return Err(gcs_error(response).await);
        }
        #[derive(Deserialize)]
        struct PermissionAnswer {
            #[serde(default)]
            permissions: Option<Vec<String>>,
        }
        let answer: PermissionAnswer = Self::read_json(response, SMALL_LIMIT, "decode gcs permission response").await?;
        let mut permissions = answer.permissions.unwrap_or_default();
        let has: BTreeSet<String> = permissions.iter().cloned().collect();
        permissions.sort();
        let source = "gcs-test-iam-permissions";
        let mut found = DiscoveredCapabilities::default();
        found.states.insert(
            PERMISSION_READ.to_owned(),
            probed_state(
                has.contains("storage.objects.list") && has.contains("storage.objects.get"),
                true,
                source,
                "requires storage.objects.list and storage.objects.get",
            ),
        );
        found.states.insert(
            PERMISSION_WRITE.to_owned(),
            probed_state(
                has.contains("storage.objects.create"),
                true,
                source,
                "requires storage.objects.create",
            ),
        );
        found.states.insert(
            PERMISSION_DELETE.to_owned(),
            probed_state(
                has.contains("storage.objects.delete"),
                true,
                source,
                "requires storage.objects.delete",
            ),
        );
        found.permissions = permissions;
        Ok(found)
    }
}

impl Backend for GcsBackend {
    fn list<'a>(&'a self, ctx: &'a OpCtx, options: &'a ListOptions) -> BoxFuture<'a, Result<ListPage>> {
        Box::pin(self.list_page(ctx, options))
    }
    fn head<'a>(&'a self, ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<ObjectResponse>> {
        Box::pin(self.head_generation(ctx, key, ""))
    }
    fn get<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        Box::pin(self.get_generation(ctx, key, "", headers))
    }
    fn put<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        body: Body,
        size: i64,
        content_type: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.put_object(ctx, key, body, size, content_type, false))
    }
    fn delete<'a>(&'a self, ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.delete_generation(ctx, key, None))
    }
    fn copy<'a>(&'a self, ctx: &'a OpCtx, source: &'a str, destination: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.server_copy(ctx, source, destination, ""))
    }
    fn discover_capabilities<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<DiscoveredCapabilities>> {
        Box::pin(self.discover(ctx))
    }
    fn conditional_writer(&self) -> Option<&dyn ConditionalWriter> {
        Some(self)
    }
    fn version_store(&self) -> Option<&dyn VersionStore> {
        Some(self)
    }
    fn resumable(&self) -> Option<&dyn ResumableApi> {
        Some(self)
    }
}

impl ConditionalWriter for GcsBackend {
    /// Write with `ifGenerationMatch=0`. A provider answer `412` gives `409 object_exists`.
    fn put_if_absent<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        body: Body,
        size: i64,
        content_type: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.put_object(ctx, key, body, size, content_type, true))
    }
}

impl VersionStore for GcsBackend {
    fn list_versions<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        page_token: &'a str,
        maximum: u32,
    ) -> BoxFuture<'a, Result<ObjectVersionPage>> {
        Box::pin(self.list_generations(ctx, key, page_token, maximum))
    }
    fn head_version<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        version: &'a str,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        Box::pin(self.head_generation(ctx, key, version))
    }
    fn get_version<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        version: &'a str,
        headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        Box::pin(self.get_generation(ctx, key, version, headers))
    }
    fn delete_version<'a>(&'a self, ctx: &'a OpCtx, key: &'a str, version: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.delete_generation(ctx, key, Some(version)))
    }
    /// Copy one generation onto its key. The extra headers do not apply to GCS.
    fn restore_version<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        version: &'a str,
        _extra: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.server_copy(ctx, key, key, version))
    }
}

impl ResumableApi for GcsBackend {
    fn initiate_resumable<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        total: i64,
        content_type: &'a str,
    ) -> BoxFuture<'a, Result<String>> {
        Box::pin(self.initiate_session(ctx, key, total, content_type))
    }
    fn upload_chunk<'a>(
        &'a self,
        ctx: &'a OpCtx,
        session: &'a str,
        body: Body,
        start: i64,
        size: i64,
        total: i64,
        content_type: &'a str,
    ) -> BoxFuture<'a, Result<(i64, bool)>> {
        Box::pin(self.upload_session_chunk(ctx, session, body, start, size, total, content_type))
    }
    fn query_resumable<'a>(
        &'a self,
        ctx: &'a OpCtx,
        session: &'a str,
        total: i64,
    ) -> BoxFuture<'a, Result<(i64, bool)>> {
        Box::pin(self.query_session(ctx, session, total))
    }
    fn abort_resumable<'a>(&'a self, ctx: &'a OpCtx, session: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(self.abort_session(ctx, session))
    }
}
