//! The guard of the access policy: the check of the identity token and the questions to the PDP.
//!
//! Stowr writes its routes against this trait. The mode `open` has [`OpenGuard`]. The mode `authzen` has the guard
//! of the library `procurauth-pep`; the library is synchronous, so its guard runs its calls on the blocking threads
//! of the runtime (`tokio::task::spawn_blocking`).

use http::HeaderMap;

use crate::common::BoxFuture;
use crate::common::error::Result;

/// One permission: an action on a resource. `resource` is the text form of the chain
/// (`service:svc/bucket:b/folder:reports`), each id percent-encoded.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ask {
    /// The action.
    pub action: String,
    /// The resource with its chain.
    pub resource: String,
}

/// The answer of the PDP to one question.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Answer {
    /// The decision.
    pub decision: bool,
    /// No valid answer: `503 pdp_unavailable`.
    pub failed: bool,
    /// The reason of a `false` answer (never sent to the client).
    pub reason: String,
    /// The wait of a `budget_exceeded` answer.
    pub retry_after: u64,
    /// `context.usage.units` of a `true` answer of a usage question.
    pub units: Option<u64>,
    /// `context.limits` of a `true` answer.
    pub limits: std::collections::BTreeMap<String, i64>,
}

/// The identity of a valid token.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Identity {
    /// `sub`.
    pub subject: String,
    /// `owner`, for the log only.
    pub owner: String,
}

/// The check of the token and the questions to the PDP.
pub trait AccessGuard: Send + Sync {
    /// Check the identity token of the request headers. `Ok(None)` in mode `open`. `Err` with the reason of the
    /// log (`missing`, `malformed`, `signature`...) for a refused token.
    fn authenticate(&self, headers: &HeaderMap) -> std::result::Result<Option<Identity>, String>;

    /// Ask questions without usage, in batches; one answer for each question, in order.
    fn decide<'a>(&'a self, request_id: &'a str, subject: &'a str, asks: &'a [Ask]) -> BoxFuture<'a, Vec<Answer>>;

    /// Ask one question with `context.usage` of 1 unit. Never sent again after a lost answer.
    fn use_one<'a>(&'a self, request_id: &'a str, subject: &'a str, ask: &'a Ask) -> BoxFuture<'a, Answer>;

    /// Ask questions with the match `subtree`, for the display only.
    fn display<'a>(
        &'a self,
        request_id: &'a str,
        subject: &'a str,
        asks: &'a [Ask],
    ) -> BoxFuture<'a, Result<Vec<bool>>>;
}

/// The guard of the mode `open`: no token, and each question is true.
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenGuard;

impl AccessGuard for OpenGuard {
    fn authenticate(&self, _headers: &HeaderMap) -> std::result::Result<Option<Identity>, String> {
        Ok(None)
    }

    fn decide<'a>(&'a self, _request_id: &'a str, _subject: &'a str, asks: &'a [Ask]) -> BoxFuture<'a, Vec<Answer>> {
        let answers = asks
            .iter()
            .map(|_| Answer {
                decision: true,
                ..Answer::default()
            })
            .collect();
        Box::pin(async move { answers })
    }

    fn use_one<'a>(&'a self, _request_id: &'a str, _subject: &'a str, _ask: &'a Ask) -> BoxFuture<'a, Answer> {
        Box::pin(async move {
            Answer {
                decision: true,
                units: Some(1),
                ..Answer::default()
            }
        })
    }

    fn display<'a>(
        &'a self,
        _request_id: &'a str,
        _subject: &'a str,
        asks: &'a [Ask],
    ) -> BoxFuture<'a, Result<Vec<bool>>> {
        let answers = vec![true; asks.len()];
        Box::pin(async move { Ok(answers) })
    }
}
