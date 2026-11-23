//! The context of an operation: what a storage call needs to know about the request or the job that makes it.
//!
//! Each storage call gets an [`OpCtx`]. The context carries the resource budget, the mode of the concurrency
//! gates, the object version that the request names, the identity and the ceilings of the access policy, the
//! checksum and the tags of an upload, and the cancellation token. A clone is cheap: the values are shared.

use std::sync::Arc;
use std::time::Instant;

use super::error::{Error, Result};
use super::misc::CancelToken;
use crate::access::AccessRequest;
use crate::instance::budget::Budget;
use crate::instance::ceiling::Ceilings;
use crate::lifecycle::Tag;
use crate::provider::ChecksumTransfer;

/// How a storage call waits for a slot of the concurrency gates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GateMode {
    /// Wait at most 30 seconds, then `503 storage_busy` (an interactive request).
    #[default]
    Bounded,
    /// Wait without a time limit (a background job, a copy in parts).
    Unbounded,
    /// Do not wait: `503 storage_busy` at once when no slot is free (an optional prefetch).
    NoWait,
    /// Take no slot: the caller already holds one for this operation.
    Exempt,
}

/// The context of an operation.
#[derive(Clone, Debug, Default)]
pub struct OpCtx {
    /// The resource budget of the request or of the job.
    pub budget: Option<Arc<Budget>>,
    /// The mode of the concurrency gates.
    pub gate: GateMode,
    /// The object version that the request names (`?version=`).
    pub version: Option<Arc<str>>,
    /// The identity of the request, in mode `authzen`.
    pub access: Option<Arc<AccessRequest>>,
    /// The ceilings that apply: those of the request (they grow as the PDP answers) or those that a job kept.
    pub ceilings: Option<Arc<Ceilings>>,
    /// The SHA-256 checksum of an upload, and the digest that the provider sends back.
    pub checksum: Option<Arc<ChecksumTransfer>>,
    /// The tags of an upload.
    pub upload_tags: Option<Arc<[Tag]>>,
    /// The cancellation token.
    pub cancel: CancelToken,
    /// The deadline of the operation.
    pub deadline: Option<Instant>,
}

impl OpCtx {
    /// A context with a budget and default values.
    pub fn with_budget(budget: Arc<Budget>) -> Self {
        Self {
            budget: Some(budget),
            ..Self::default()
        }
    }

    /// The same context with another gate mode.
    pub fn gated(&self, gate: GateMode) -> Self {
        Self { gate, ..self.clone() }
    }

    /// The same context with an object version (`None` or an empty text: the current version).
    pub fn with_version(&self, version: Option<&str>) -> Self {
        let version = version.filter(|value| !value.is_empty()).map(Arc::from);
        Self {
            version,
            ..self.clone()
        }
    }

    /// The same context with a deadline that is the earlier of the current one and `now + after`.
    pub fn with_timeout(&self, after: std::time::Duration) -> Self {
        let candidate = Instant::now() + after;
        let deadline = Some(self.deadline.map_or(candidate, |current| current.min(candidate)));
        Self {
            deadline,
            ..self.clone()
        }
    }

    /// The same context with a new cancellation token that does not follow the current one: for a short cleanup
    /// that must end after the client goes (for example the abort of a multipart upload).
    pub fn detached(&self) -> Self {
        Self {
            cancel: CancelToken::new(),
            ..self.clone()
        }
    }

    /// The object version of the request, or an empty text.
    pub fn version(&self) -> &str {
        self.version.as_deref().unwrap_or("")
    }

    /// `Err` when the operation is canceled or its deadline is past.
    pub fn check(&self) -> Result<()> {
        self.cancel.check()?;
        match self.deadline {
            Some(deadline) if Instant::now() >= deadline => Err(Error::Timeout),
            _ => Ok(()),
        }
    }

    /// Run a future until it ends, the token is canceled or the deadline is past.
    pub async fn run<T>(&self, future: impl std::future::Future<Output = Result<T>>) -> Result<T> {
        let cancel = self.cancel.clone();
        let deadline = self.deadline;
        tokio::select! {
            output = future => output,
            () = cancel.canceled() => Err(Error::Canceled),
            () = async move {
                match deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
                    None => std::future::pending::<()>().await,
                }
            } => Err(Error::Timeout),
        }
    }
}
