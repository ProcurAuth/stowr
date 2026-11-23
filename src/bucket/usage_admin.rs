//! The admin requests of the usage readers: the transport seam, the URL of an admin API, the error that names the
//! step and the status but never the URL, and the read of a size-limited JSON answer.
//!
//! Each admin request is a read (`GET`), with a time limit and a size limit for the answer. The token and the URL of
//! the admin API never go into an error text: an error names the step and the HTTP status only.

use std::time::Duration;

use bytes::Bytes;
use http::HeaderMap;
use serde::de::DeserializeOwned;

use super::support::escape_url_path;
use crate::common::BoxFuture;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result, safe_provider_code};

/// The longest time of one read of the usage, with all its admin requests.
pub const USAGE_TIMEOUT: Duration = Duration::from_secs(5);

/// The answer of an admin API.
#[derive(Clone, Debug, Default)]
pub struct AdminAnswer {
    /// The HTTP status.
    pub status: u16,
    /// The body, at most the limit of the request.
    pub body: Bytes,
}

/// Why an admin request got no answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminFailure {
    /// The TLS certificate of the admin API is not valid.
    Certificate,
    /// The connection failed, or the transport broke.
    Connect,
    /// The admin API did not answer in time.
    Timeout,
}

/// The HTTP client of the admin APIs. The client of the `auth` block implements it: it follows no redirect, uses no
/// proxy, and verifies the certificate unless `insecure_skip_verify` is set.
pub trait AdminTransport: Send + Sync {
    /// Send a `GET` request. Read at most `limit` bytes of the body.
    fn get<'a>(
        &'a self,
        url: &'a str,
        headers: HeaderMap,
        limit: usize,
    ) -> BoxFuture<'a, std::result::Result<AdminAnswer, AdminFailure>>;
}

/// The credentials that sign the requests to MinIO.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct AdminCredentials {
    /// The access key id.
    pub access_key_id: String,
    /// The secret access key.
    pub secret_access_key: String,
    /// The session token.
    pub session_token: String,
}

impl std::fmt::Debug for AdminCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AdminCredentials")
            .field("access_key_id", &self.access_key_id)
            .finish_non_exhaustive()
    }
}

/// An error of an admin request. It names the step and the status, never the URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminError {
    /// An answer that is not a success.
    Http {
        /// The step.
        step: String,
        /// The HTTP status.
        status: u16,
        /// The code of a JSON error document (`Code` for MinIO, `code` for Garage), when the answer has one.
        code: String,
    },
    /// Any other failure, with its text.
    Message(String),
}

impl std::fmt::Display for AdminError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http { step, status, .. } => match status {
                401 | 403 => write!(f, "{step}: the admin API refused the credentials (HTTP {status})"),
                404 => write!(f, "{step}: the admin API does not know the bucket (HTTP 404)"),
                _ => write!(f, "{step}: the admin API answered HTTP {status}"),
            },
            Self::Message(text) => f.write_str(text),
        }
    }
}

impl std::error::Error for AdminError {}

impl From<AdminError> for Error {
    fn from(error: AdminError) -> Self {
        Error::internal(error.to_string())
    }
}

impl AdminError {
    pub(crate) fn message(text: impl Into<String>) -> Self {
        Self::Message(text.into())
    }
}

/// The reason of a failed admin request without the URL.
fn transport_error(step: &str, failure: AdminFailure) -> AdminError {
    AdminError::message(match failure {
        AdminFailure::Certificate => format!("{step}: the TLS certificate of the admin API is not valid"),
        AdminFailure::Timeout => format!("{step}: the admin API did not answer in {}s", USAGE_TIMEOUT.as_secs()),
        AdminFailure::Connect => format!("{step}: cannot connect to the admin API"),
    })
}

/// Send one admin request and decode its JSON answer. The answer must be a success (200) and must not be longer than
/// `limit` bytes.
pub async fn get_usage_json<T: DeserializeOwned>(
    transport: &dyn AdminTransport,
    ctx: &OpCtx,
    url: &str,
    headers: HeaderMap,
    step: &str,
    limit: usize,
) -> std::result::Result<T, AdminError> {
    let outcome = ctx
        .run(async { Ok(transport.get(url, headers, limit.saturating_add(1)).await) })
        .await;
    let answer = match outcome {
        Ok(Ok(answer)) => answer,
        Ok(Err(failure)) => return Err(transport_error(step, failure)),
        Err(Error::Canceled) => return Err(AdminError::message(format!("{step}: the request was canceled"))),
        Err(_) => return Err(transport_error(step, AdminFailure::Timeout)),
    };
    if answer.status != 200 {
        #[derive(serde::Deserialize, Default)]
        struct ErrorDocument {
            #[serde(rename = "Code", default)]
            upper: Option<String>,
            #[serde(rename = "code", default)]
            lower: Option<String>,
        }
        let document: ErrorDocument = serde_json::from_slice(&answer.body).unwrap_or_default();
        let code = document
            .upper
            .filter(|value| !value.is_empty())
            .or(document.lower)
            .unwrap_or_default();
        return Err(AdminError::Http {
            step: step.to_owned(),
            status: answer.status,
            code: safe_provider_code(&code),
        });
    }
    if answer.body.len() > limit {
        return Err(AdminError::message(format!(
            "{step}: the answer of the admin API is longer than {limit} bytes"
        )));
    }
    serde_json::from_slice(&answer.body)
        .map_err(|_| AdminError::message(format!("{step}: the answer of the admin API is not the expected JSON")))
}

/// The URL of an admin API: the scheme, the host with its port, and a path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdminUrl {
    /// `http` or `https`.
    pub scheme: String,
    /// The host with its port, as the file gives it.
    pub authority: String,
    /// The path, possibly empty.
    pub path: String,
}

impl AdminUrl {
    /// Read and check an endpoint: `http` or `https`, a host, no user information, no query, no fragment.
    pub fn parse(provider: &str, raw: &str) -> Result<Self> {
        let Some((scheme, rest)) = raw.split_once("://") else {
            return Err(Error::internal(format!(
                "{provider} endpoint scheme must be http or https"
            )));
        };
        if scheme != "http" && scheme != "https" {
            return Err(Error::internal(format!(
                "{provider} endpoint scheme must be http or https"
            )));
        }
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        if authority.is_empty() {
            return Err(Error::internal(format!("{provider} endpoint must include a host")));
        }
        if authority.contains('@') {
            return Err(Error::internal(format!(
                "{provider} endpoint must not contain user information"
            )));
        }
        if tail.contains(['?', '#']) {
            return Err(Error::internal(format!(
                "{provider} endpoint must not contain a query string or fragment"
            )));
        }
        Ok(Self {
            scheme: scheme.to_owned(),
            authority: authority.to_owned(),
            path: tail.to_owned(),
        })
    }

    /// The host without the port and without the brackets of an IPv6 address.
    pub fn hostname(&self) -> &str {
        split_host_port(&self.authority).map_or_else(|| self.authority.as_str(), |(host, _)| host)
    }

    /// The URL of a path below the endpoint: the segments go after the path of the endpoint.
    pub fn join(&self, segments: &[&str]) -> String {
        format!("{}://{}{}", self.scheme, self.authority, self.join_path(segments))
    }

    /// The path of the same segments, as the signature of the request uses it.
    pub fn join_path(&self, segments: &[&str]) -> String {
        let mut path = self.path.trim_end_matches('/').to_owned();
        for segment in segments {
            path.push('/');
            path.push_str(&escape_url_path(segment));
        }
        if path.is_empty() {
            path.push('/');
        }
        path
    }
}

/// Split `host:port` or `[host]:port`. A text with more than one colon and no brackets gives `None`.
pub fn split_host_port(address: &str) -> Option<(&str, &str)> {
    if let Some(rest) = address.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail.strip_prefix(':')?;
        return Some((host, port));
    }
    if address.matches(':').count() != 1 {
        return None;
    }
    address.split_once(':')
}

/// Join a host and a port, with brackets for an IPv6 address.
pub fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}
