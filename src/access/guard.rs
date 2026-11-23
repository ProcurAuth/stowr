// SPDX-License-Identifier: MIT OR Apache-2.0
//! The guard of the access policy: the check of the identity token and the questions to the PDP.
//!
//! Stowr writes its routes against this trait. The mode `open` has [`OpenGuard`]. The mode `authzen` has the guard
//! of the library `procurauth-pep` ([`super::pep_guard::PepGuard`]). The library is synchronous, so its guard runs
//! its calls on the blocking threads of the runtime (`tokio::task::spawn_blocking`).
//!
//! A guard keeps the rules of the client of the PDP: the batches, the deadlines, the answers that it keeps, the
//! check of the answers. Stowr keeps the rules of the service: the actions, the nodes, the order of the questions,
//! and the meaning of each answer for the client (docs/ACCESS.md).

use std::collections::BTreeMap;
use std::time::Duration;

use http::HeaderMap;

use super::actions::ActionDocument;
use crate::common::BoxFuture;
use crate::common::config::Config;
use crate::common::error::Result;

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
    /// `iat`, in seconds since the Unix epoch.
    pub issued_at: u64,
    /// `exp`, in seconds since the Unix epoch.
    pub expires_at: u64,
}

/// The answers to the permissions of one operation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct OperationAnswers {
    /// One answer for each other permission, in order. The list can stop at the first other that the guard refuses.
    pub others: Vec<Answer>,
    /// The answer of the use. `None` when the guard did not ask the use, because it refused an other.
    pub use_answer: Option<Answer>,
}

impl OperationAnswers {
    /// The answers of a call that got no valid answer.
    pub fn failure(others: usize) -> Self {
        Self {
            others: vec![Answer::failure(); others],
            use_answer: Some(Answer::failure()),
        }
    }
}

/// The check of the token and the questions to the PDP.
pub trait AccessGuard: Send + Sync {
    /// Get the configuration and the action document of the service. The access layer calls it one time, before the
    /// first request. The default does nothing.
    fn bind(&self, _config: &Config, _document: &ActionDocument) -> Result<()> {
        Ok(())
    }

    /// Check the identity token of the request headers. `Ok(None)` in mode `open`. `Err` with the reason of the
    /// log (`missing`, `malformed`, `signature`...) for a refused token.
    fn authenticate(&self, headers: &HeaderMap) -> std::result::Result<Option<Identity>, String>;

    /// Ask the permissions of one operation (docs/ACCESS.md, "The routes"). The guard asks the others first, in one
    /// batch, with `context.permission_only` and without usage. A refused other stops the operation: the guard then
    /// does not ask the use. Then the guard asks the use. With `usage`, the question of the use has `context.usage`
    /// of 1 unit and is never sent again after a lost answer.
    fn operation<'a>(
        &'a self,
        request_id: &'a str,
        who: &'a Identity,
        others: &'a [Ask],
        use_ask: &'a Ask,
        usage: bool,
    ) -> BoxFuture<'a, OperationAnswers>;

    /// Ask questions without usage, without `permission_only` and with the match `node`. Each answer is apart from
    /// the others: one answer for each question, in order.
    fn decide<'a>(&'a self, request_id: &'a str, who: &'a Identity, asks: &'a [Ask]) -> BoxFuture<'a, Vec<Answer>>;

    /// Ask the action `access` on the service node, without usage (ProcurAuth 10.1c).
    fn service<'a>(&'a self, request_id: &'a str, who: &'a Identity) -> BoxFuture<'a, Answer>;

    /// Ask questions with the match `subtree` and without usage, for the display only; one answer for each
    /// question, in order.
    fn display<'a>(&'a self, request_id: &'a str, who: &'a Identity, asks: &'a [Ask]) -> BoxFuture<'a, Vec<Answer>>;
}

/// The guard of the mode `open`: no token, and each question is true.
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenGuard;

impl AccessGuard for OpenGuard {
    fn authenticate(&self, _headers: &HeaderMap) -> std::result::Result<Option<Identity>, String> {
        Ok(None)
    }

    fn operation<'a>(
        &'a self,
        _request_id: &'a str,
        _who: &'a Identity,
        others: &'a [Ask],
        _use_ask: &'a Ask,
        usage: bool,
    ) -> BoxFuture<'a, OperationAnswers> {
        let answers = OperationAnswers {
            others: vec![Answer::allow(); others.len()],
            use_answer: Some(Answer {
                units: usage.then_some(1),
                ..Answer::allow()
            }),
        };
        Box::pin(async move { answers })
    }

    fn decide<'a>(&'a self, _request_id: &'a str, _who: &'a Identity, asks: &'a [Ask]) -> BoxFuture<'a, Vec<Answer>> {
        let answers = vec![Answer::allow(); asks.len()];
        Box::pin(async move { answers })
    }

    fn service<'a>(&'a self, _request_id: &'a str, _who: &'a Identity) -> BoxFuture<'a, Answer> {
        Box::pin(async move { Answer::allow() })
    }

    fn display<'a>(&'a self, _request_id: &'a str, _who: &'a Identity, asks: &'a [Ask]) -> BoxFuture<'a, Vec<Answer>> {
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
        let who = Identity::default();
        let asks = vec![Ask::default(), Ask::default()];
        let answers = guard.operation("r", &who, &asks, &asks[0], true).await;
        assert_eq!(answers.others.len(), 2);
        assert!(answers.others.iter().all(|answer| answer.decision && !answer.failed));
        let used = answers.use_answer.unwrap();
        assert!(used.decision);
        assert_eq!(used.units, Some(1));
        let plain = guard.operation("r", &who, &[], &asks[0], false).await;
        assert_eq!(plain.use_answer.unwrap().units, None);
        assert!(
            guard
                .decide("r", &who, &asks)
                .await
                .iter()
                .all(|answer| answer.decision)
        );
        assert!(guard.service("r", &who).await.decision);
        let shown = guard.display("r", &who, &asks).await;
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
