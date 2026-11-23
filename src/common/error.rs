//! The error type of the program and the error envelope of the answers.
//!
//! Every function that can fail returns [`Result`]. An [`Error`] gives the HTTP status, the code and the public
//! message of the answer. The public message never shows a URL, a credential or the text of a provider.

use std::fmt;

use serde::Serialize;

/// The result type of the program.
pub type Result<T, E = Error> = std::result::Result<T, E>;

/// The code of an action that needs the approval of its owner (ProcurAuth 17.7a). No route can wait for the
/// approval. The answer is 403 with exactly the body `{"error":"approval_cannot_wait"}`.
pub const CODE_APPROVAL_CANNOT_WAIT: &str = "approval_cannot_wait";

/// A typed answer: the status, the code and the message that the client gets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiError {
    /// The HTTP status.
    pub status: u16,
    /// The code of the error object, for example `invalid_json`.
    pub code: String,
    /// The message of the error object.
    pub message: String,
    /// The action of an access refusal. The error object shows it.
    pub action: Option<String>,
    /// The wait in seconds. A value above 0 gives the header `Retry-After`.
    pub retry_after: u64,
    /// The name and the value of the ceiling of a refusal for a ceiling. The error object shows both.
    pub ceiling: Option<(String, i64)>,
}

/// An HTTP error answer of a storage provider.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamError {
    /// The HTTP status of the provider.
    pub status: u16,
    /// The error code of the provider, for example `NoSuchKey`.
    pub code: String,
    /// The message of the provider. It never goes to the client.
    pub message: String,
}

/// One key that a batch delete did not delete.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchDeleteFailure {
    /// The full key.
    pub key: String,
    /// The code of the provider.
    pub code: String,
    /// The message of the provider.
    pub message: String,
}

/// The keys that a batch delete did not delete. It acts as an [`UpstreamError`] for the status and the code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchDeleteError {
    /// The number of keys of the batch.
    pub total: usize,
    /// The refused keys.
    pub failures: Vec<BatchDeleteFailure>,
}

impl BatchDeleteError {
    /// The provider error that represents the batch: the code of the first failure, the status 502, and the message
    /// `<refused> of <total> keys were not deleted: <first message>`.
    pub fn upstream(&self) -> UpstreamError {
        let first = self.failures.first();
        UpstreamError {
            status: 502,
            code: first.map(|failure| failure.code.clone()).unwrap_or_default(),
            message: format!(
                "{} of {} keys were not deleted: {}",
                self.failures.len(),
                self.total,
                first.map(|failure| failure.message.as_str()).unwrap_or_default()
            ),
        }
    }
}

/// The kind of a resource budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitKind {
    /// The number of provider calls.
    StorageRequests,
    /// The number of provider bytes.
    StorageBytes,
}

/// A resource budget that a request or a job used up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceLimit {
    /// The kind of the budget.
    pub kind: LimitKind,
    /// The limit.
    pub limit: i64,
    /// The used value.
    pub used: i64,
}

/// Why a job stopped before its end.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Interrupt {
    /// A person paused the job.
    Paused,
    /// A person canceled the job.
    Canceled,
}

/// The error of the program.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// A typed answer.
    Api(Box<ApiError>),
    /// An HTTP error answer of a provider.
    Upstream(Box<UpstreamError>),
    /// The refused keys of a batch delete.
    BatchDelete(Box<BatchDeleteError>),
    /// A resource budget is used up.
    Budget(ResourceLimit),
    /// A job stopped on a control.
    Interrupted(Interrupt),
    /// The deadline of the operation is past.
    Timeout,
    /// The operation is canceled.
    Canceled,
    /// The connection to a provider, its TLS handshake or its transport failed. The text is for the log only.
    Connect(String),
    /// Any other failure. The text is for the log only.
    Internal(String),
}

impl Error {
    /// A typed answer with a status, a code and a message.
    pub fn api(status: u16, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Api(Box::new(ApiError {
            status,
            code: code.into(),
            message: message.into(),
            action: None,
            retry_after: 0,
            ceiling: None,
        }))
    }

    /// An HTTP error answer of a provider.
    pub fn upstream(status: u16, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Upstream(Box::new(UpstreamError {
            status,
            code: code.into(),
            message: message.into(),
        }))
    }

    /// Any other failure, with a text for the log.
    pub fn internal(text: impl Into<String>) -> Self {
        Self::Internal(text.into())
    }

    /// The typed answer, when the error is one.
    pub fn as_api(&self) -> Option<&ApiError> {
        match self {
            Self::Api(api) => Some(api),
            _ => None,
        }
    }

    /// The provider error, when the error is one. A batch delete gives its representative error.
    pub fn as_upstream(&self) -> Option<UpstreamError> {
        match self {
            Self::Upstream(upstream) => Some((**upstream).clone()),
            Self::BatchDelete(batch) => Some(batch.upstream()),
            _ => None,
        }
    }

    /// True for a provider answer 404.
    pub fn is_not_found(&self) -> bool {
        self.as_upstream().is_some_and(|upstream| upstream.status == 404)
    }

    /// True when the error has this API code.
    pub fn has_code(&self, code: &str) -> bool {
        self.as_api().is_some_and(|api| api.code == code)
    }

    /// The typed answer of a used-up resource budget (429 `resource_budget_exceeded`).
    fn budget_answer(limit: &ResourceLimit) -> ApiError {
        let message = match limit.kind {
            LimitKind::StorageRequests => {
                format!("the operation exceeded the limit of {} storage requests", limit.limit)
            }
            LimitKind::StorageBytes => format!(
                "the operation exceeded the limit of {} bytes read from storage",
                limit.limit
            ),
        };
        ApiError {
            status: 429,
            code: "resource_budget_exceeded".to_owned(),
            message,
            action: None,
            retry_after: 0,
            ceiling: None,
        }
    }

    /// The typed answer of the error, when it has one: a typed answer, or a used-up budget.
    pub fn answer(&self) -> Option<ApiError> {
        match self {
            Self::Api(api) => Some((**api).clone()),
            Self::Budget(limit) => Some(Self::budget_answer(limit)),
            _ => None,
        }
    }

    /// The HTTP status of the answer.
    pub fn status(&self) -> u16 {
        if let Some(api) = self.answer() {
            return api.status;
        }
        match self.as_upstream() {
            Some(upstream) => match upstream.status {
                400 | 401 | 403 | 404 | 409 | 412 | 416 | 429 => upstream.status,
                400..=499 => 400,
                _ => 502,
            },
            None => 502,
        }
    }

    /// The code of the error object.
    pub fn code(&self) -> String {
        if let Some(api) = self.answer() {
            return api.code;
        }
        match self.as_upstream().map(|upstream| safe_provider_code(&upstream.code)) {
            Some(code) if !code.is_empty() => code.to_lowercase(),
            _ => "storage_error".to_owned(),
        }
    }

    /// The message of the answer. It never shows the text of a provider, a URL or a credential.
    pub fn public_message(&self) -> String {
        if let Some(api) = self.answer() {
            return api.message;
        }
        if let Some(upstream) = self.as_upstream() {
            let code = safe_provider_code(&upstream.code);
            if code.is_empty() {
                return format!("the storage provider returned HTTP {}", upstream.status);
            }
            return format!("the storage provider returned HTTP {} ({code})", upstream.status);
        }
        match self {
            Self::Timeout => "the storage provider connection timed out".to_owned(),
            Self::Canceled => "the storage provider request was canceled".to_owned(),
            Self::Connect(_) => "unable to connect to or authenticate with the storage provider".to_owned(),
            _ => "the storage provider operation failed".to_owned(),
        }
    }

    /// The JSON body of the error answer: `{"error":{...}}`, with the members in the order of their names.
    pub fn envelope(&self) -> ErrorEnvelope {
        let mut body = ErrorBody {
            action: None,
            ceiling: None,
            code: self.code(),
            limit: None,
            message: self.public_message(),
            retryable: None,
        };
        if let Some(api) = self.as_api() {
            body.action.clone_from(&api.action);
            if let Some((name, value)) = &api.ceiling {
                body.ceiling = Some(name.clone());
                body.limit = Some(*value);
            }
            if api.code == "too_many_requests" || api.code == "pdp_unavailable" {
                body.retryable = Some(true);
            }
        }
        ErrorEnvelope { error: body }
    }

    /// The wait of the header `Retry-After`, or 0 for no header.
    pub fn retry_after(&self) -> u64 {
        self.as_api().map_or(0, |api| api.retry_after)
    }
}

/// The JSON body of an error answer.
#[derive(Clone, Debug, Serialize)]
pub struct ErrorEnvelope {
    /// The error object.
    pub error: ErrorBody,
}

/// The error object. The members are in the order of their names, as the answers have always had them.
#[derive(Clone, Debug, Serialize)]
pub struct ErrorBody {
    /// The action of an access refusal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    /// The name of the ceiling of a refusal for a ceiling.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ceiling: Option<String>,
    /// The code.
    pub code: String,
    /// The value of the ceiling.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<i64>,
    /// The message.
    pub message: String,
    /// True for an answer that the client can send again later.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retryable: Option<bool>,
}

/// The provider code when it has 1 to 64 safe characters (letters, digits, `.`, `_`, `-`), else an empty text.
pub fn safe_provider_code(value: &str) -> String {
    let value = value.trim();
    let cut: String = value.chars().take(64).collect();
    let cut = if value.len() > 64 {
        value.get(..64).unwrap_or(&cut).to_owned()
    } else {
        cut
    };
    if cut
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        cut
    } else {
        String::new()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Api(api) => f.write_str(&api.message),
            Self::Upstream(upstream) => write_upstream(f, upstream),
            Self::BatchDelete(batch) => write_upstream(f, &batch.upstream()),
            Self::Budget(limit) => {
                let kind = match limit.kind {
                    LimitKind::StorageRequests => "storage_requests",
                    LimitKind::StorageBytes => "storage_bytes",
                };
                write!(
                    f,
                    "{kind} resource budget exceeded: used {}, limit {}",
                    limit.used, limit.limit
                )
            }
            Self::Interrupted(Interrupt::Paused) => f.write_str("job paused"),
            Self::Interrupted(Interrupt::Canceled) => f.write_str("job canceled"),
            Self::Timeout => f.write_str("deadline exceeded"),
            Self::Canceled => f.write_str("canceled"),
            Self::Connect(text) | Self::Internal(text) => f.write_str(text),
        }
    }
}

fn write_upstream(f: &mut fmt::Formatter<'_>, upstream: &UpstreamError) -> fmt::Result {
    match (upstream.code.is_empty(), upstream.message.is_empty()) {
        (true, true) => write!(f, "storage upstream returned HTTP {}", upstream.status),
        (false, true) => f.write_str(&upstream.code),
        (true, false) => f.write_str(&upstream.message),
        (false, false) => write!(f, "{}: {}", upstream.code, upstream.message),
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Internal(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_status_follows_the_table_of_the_answers() {
        assert_eq!(Error::upstream(404, "NoSuchKey", "x").status(), 404);
        assert_eq!(Error::upstream(418, "", "").status(), 400);
        assert_eq!(Error::upstream(500, "", "").status(), 502);
        assert_eq!(Error::internal("x").status(), 502);
    }

    #[test]
    fn public_message_never_shows_the_text_of_the_provider() {
        let error = Error::upstream(403, "AccessDenied", "secret detail");
        assert_eq!(
            error.public_message(),
            "the storage provider returned HTTP 403 (AccessDenied)"
        );
        assert_eq!(error.code(), "accessdenied");
        assert_eq!(Error::upstream(403, "bad code!", "").code(), "storage_error");
    }
}
