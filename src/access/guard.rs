//! The guard of the access policy: the check of the identity token and the questions to the PDP.
//!
//! Stowr writes its routes against this trait. The mode `open` has [`OpenGuard`]. The mode `authzen` has the guard
//! of the library `procurauth-pep`; the library is synchronous, so its guard runs its calls on the blocking threads
//! of the runtime (`tokio::task::spawn_blocking`).
//!
//! A guard keeps the rules of the client of the PDP: the batches, the deadlines, the answers that it keeps, the
//! check of the answers. Stowr keeps the rules of the service: the actions, the nodes, the order of the questions,
//! and the meaning of each answer for the client (docs/ACCESS.md).

use std::collections::BTreeMap;
use std::time::Duration;

use http::HeaderMap;

use crate::common::BoxFuture;

/// The reason of a `false` answer with a budget that is used.
pub const REASON_BUDGET: &str = "budget_exceeded";

/// The four reasons of an action that needs the approval of the owner (ProcurAuth 17.1). Stowr cannot wait for an
/// approval on any route.
pub const APPROVAL_REASONS: [&str; 4] = [
    "approval_required",
    "approval_pending",
    "approval_denied",
    "approval_expired",
];

/// True when a reason is one of the four reasons of an approval.
pub fn is_approval_reason(reason: &str) -> bool {
    APPROVAL_REASONS.contains(&reason)
}

/// The margin above `procurauth_usage_max_seconds` for the wait of a usage question.
pub const USAGE_WAIT_MARGIN: Duration = Duration::from_secs(1);

/// The wait of a usage question: the longer of `usage_timeout` and the time that the PDP publishes in
/// `procurauth_usage_max_seconds` plus [`USAGE_WAIT_MARGIN`]. Thus the wait is always longer than the time of the PDP.
pub fn usage_wait(usage_timeout: Duration, usage_max_seconds: Option<u64>) -> Duration {
    match usage_max_seconds {
        Some(seconds) => usage_timeout.max(Duration::from_secs(seconds).saturating_add(USAGE_WAIT_MARGIN)),
        None => usage_timeout,
    }
}

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
    pub limits: BTreeMap<String, i64>,
}

impl Answer {
    /// A `true` answer without limits.
    pub fn allow() -> Self {
        Self {
            decision: true,
            ..Self::default()
        }
    }

    /// A `false` answer with a reason (an empty text for no reason).
    pub fn deny(reason: &str) -> Self {
        Self {
            reason: reason.to_owned(),
            ..Self::default()
        }
    }

    /// The answer of a question that got no valid answer.
    pub fn failure() -> Self {
        Self {
            failed: true,
            ..Self::default()
        }
    }
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

    /// Ask questions without usage and with the match `node`, in batches; one answer for each question, in order.
    /// With `permission_only`, each question has `context.permission_only` equal to `true`: the questions are the
    /// other permissions of an operation, and the kept answers of these questions are apart from the others.
    fn decide<'a>(
        &'a self,
        request_id: &'a str,
        subject: &'a str,
        asks: &'a [Ask],
        permission_only: bool,
    ) -> BoxFuture<'a, Vec<Answer>>;

    /// Ask one question with `context.usage` of 1 unit. Never sent again after a lost answer.
    fn use_one<'a>(&'a self, request_id: &'a str, subject: &'a str, ask: &'a Ask) -> BoxFuture<'a, Answer>;

    /// Ask questions with the match `subtree` and without usage, for the display only; one answer for each
    /// question, in order.
    fn display<'a>(&'a self, request_id: &'a str, subject: &'a str, asks: &'a [Ask]) -> BoxFuture<'a, Vec<Answer>>;
}

/// The guard of the mode `open`: no token, and each question is true.
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenGuard;

impl AccessGuard for OpenGuard {
    fn authenticate(&self, _headers: &HeaderMap) -> std::result::Result<Option<Identity>, String> {
        Ok(None)
    }

    fn decide<'a>(
        &'a self,
        _request_id: &'a str,
        _subject: &'a str,
        asks: &'a [Ask],
        _permission_only: bool,
    ) -> BoxFuture<'a, Vec<Answer>> {
        let answers = vec![Answer::allow(); asks.len()];
        Box::pin(async move { answers })
    }

    fn use_one<'a>(&'a self, _request_id: &'a str, _subject: &'a str, _ask: &'a Ask) -> BoxFuture<'a, Answer> {
        Box::pin(async move {
            Answer {
                units: Some(1),
                ..Answer::allow()
            }
        })
    }

    fn display<'a>(&'a self, _request_id: &'a str, _subject: &'a str, asks: &'a [Ask]) -> BoxFuture<'a, Vec<Answer>> {
        let answers = vec![Answer::allow(); asks.len()];
        Box::pin(async move { answers })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_open_guard_says_true_to_each_question() {
        let guard = OpenGuard;
        assert_eq!(guard.authenticate(&HeaderMap::new()), Ok(None));
        let asks = vec![Ask::default(), Ask::default()];
        let answers = guard.decide("r", "s", &asks, true).await;
        assert_eq!(answers.len(), 2);
        assert!(answers.iter().all(|answer| answer.decision && !answer.failed));
        let answer = guard.use_one("r", "s", &asks[0]).await;
        assert!(answer.decision);
        assert_eq!(answer.units, Some(1));
        let shown = guard.display("r", "s", &asks).await;
        assert!(shown.iter().all(|answer| answer.decision));
    }

    #[test]
    fn the_wait_of_a_usage_question_is_longer_than_the_time_of_the_pdp() {
        let six = Duration::from_secs(6);
        assert_eq!(usage_wait(six, None), six);
        assert_eq!(usage_wait(six, Some(2)), six);
        assert_eq!(usage_wait(six, Some(5)), six);
        assert_eq!(usage_wait(six, Some(6)), Duration::from_secs(7));
        assert_eq!(usage_wait(Duration::from_secs(2), Some(10)), Duration::from_secs(11));
    }

    #[test]
    fn the_approval_reasons_are_the_four_reasons_of_an_approval() {
        for reason in APPROVAL_REASONS {
            assert!(is_approval_reason(reason));
        }
        assert!(!is_approval_reason(REASON_BUDGET));
        assert!(!is_approval_reason(""));
        assert!(!is_approval_reason("unknown_subject"));
    }
}
