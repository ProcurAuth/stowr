// SPDX-License-Identifier: MIT OR Apache-2.0
//! The link of the guard to the PDP: a transport around the transport of the library `procurauth-pep`, and the
//! journal of one call.
//!
//! The library sends each request to the PDP through [`LinkTransport`]. This transport adds the rules of Stowr that
//! the library does not have (docs/ACCESS.md, "The PDP client"):
//!
//! - Each request of a call has the header `X-Request-ID` with the request id of the client request.
//! - A usage question waits at least `usage_timeout`. The library gives the longer of `timeout` and
//!   `procurauth_usage_max_seconds` plus 1 second, so the wait is the longer of the two values of Stowr.
//! - One deadline (`timeout`) covers the requests without usage of one call that have the same kind.
//!
//! The library calls the transport on the thread of the call. A call of the guard runs on one blocking thread, so a
//! value of the thread holds the call: its request id, its deadline and its journal. The journal keeps each request
//! of the call: the questions, the answers and the failure. The guard reads it to write the log lines, and to find
//! the permission that a refusal of the library is for.

use std::cell::RefCell;
use std::sync::Arc;
use std::time::Duration;

use procurauth_core::authzen::Decision;
use procurauth_pep::clock::Clock;
use procurauth_pep::transport::{HttpResponse, PdpTransport, TransportError};
use serde_json::Value;

use super::guard::{Answer, Ask};
use super::tree::{Node, Resource};

/// The header of the request id.
pub const REQUEST_ID_HEADER: &str = "X-Request-ID";

/// The kind of a request: the members of the context that the guard reads.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Kind {
    /// The question has `context.usage`.
    pub usage: bool,
    /// The questions have `context.permission_only` equal to `true`.
    pub permission_only: bool,
    /// The questions have the match `subtree`.
    pub subtree: bool,
}

impl Kind {
    /// The kind of a question of a use or of a plain question: no `permission_only` and the match `node`.
    pub fn is_plain_node(self) -> bool {
        !self.permission_only && !self.subtree
    }
}

/// One question of a request: the action and the text form of the resource with its chain.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Asked {
    /// The action.
    pub action: String,
    /// The text form of the resource (`service:s/bucket:b/folder:f`). Empty when the request has no valid resource.
    pub resource: String,
}

/// The result of one request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The PDP answered with the status 200: one item for each question, `None` for an answer that is not valid.
    Answers(Vec<Option<Answer>>),
    /// The request failed: no answer, a status other than 200, or a body that is not valid as a whole.
    Failed {
        /// The HTTP status of the answer, when there is one.
        status: Option<u16>,
        /// The text of the failure, for the log.
        error: String,
    },
}

/// One request of a call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    /// The kind of the request.
    pub kind: Kind,
    /// The questions, in order. A read of the metadata has none.
    pub questions: Vec<Asked>,
    /// The result.
    pub outcome: Outcome,
}

/// The requests of one call, in order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Journal {
    /// The requests.
    pub records: Vec<Record>,
}

impl Journal {
    /// The answer of a request of this call to a question, among the requests whose kind `select` accepts. The last
    /// request wins. `Some(None)` is a question without a valid answer. `None` is a question that no request held.
    pub fn answer(&self, ask: &Ask, select: impl Fn(Kind) -> bool) -> Option<Option<Answer>> {
        let mut found = None;
        for record in self.records.iter().filter(|record| select(record.kind)) {
            for (index, question) in record.questions.iter().enumerate() {
                if question.action != ask.action || question.resource != ask.resource {
                    continue;
                }
                found = Some(match &record.outcome {
                    Outcome::Answers(answers) => answers.get(index).cloned().flatten(),
                    Outcome::Failed { .. } => None,
                });
            }
        }
        found
    }

    /// True when a request of this call held the question, among the requests whose kind `select` accepts.
    pub fn asked(&self, ask: &Ask, select: impl Fn(Kind) -> bool) -> bool {
        self.answer(ask, select).is_some()
    }
}

/// The call of the current thread.
struct Call {
    request_id: String,
    /// The kind and the deadline (milliseconds of the clock) of the requests without usage.
    plain: Option<(Kind, u64)>,
    journal: Journal,
}

thread_local! {
    static CALL: RefCell<Option<Call>> = const { RefCell::new(None) };
}

/// Run a call of the library on this thread with a journal. `request_id` goes in the header `X-Request-ID` of each
/// request of the call.
pub fn journaled<T>(request_id: &str, call: impl FnOnce() -> T) -> (T, Journal) {
    CALL.with(|cell| {
        *cell.borrow_mut() = Some(Call {
            request_id: request_id.to_owned(),
            plain: None,
            journal: Journal::default(),
        });
    });
    let value = call();
    let journal = CALL
        .with(|cell| cell.borrow_mut().take())
        .map(|call| call.journal)
        .unwrap_or_default();
    (value, journal)
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// The text form of a resource of a question: `{"type", "id", "properties": {"ancestors": [...]}}`.
fn resource_text(value: &Value) -> Option<String> {
    let text = |value: &Value, name: &str| value.get(name).and_then(Value::as_str).map(str::to_owned);
    let mut ancestors = Vec::new();
    if let Some(list) = value
        .get("properties")
        .and_then(|properties| properties.get("ancestors"))
    {
        for node in list.as_array()? {
            ancestors.push(Node::new(&text(node, "type")?, &text(node, "id")?));
        }
    }
    Some(
        Resource {
            node_type: text(value, "type")?,
            id: text(value, "id")?,
            ancestors,
        }
        .path(),
    )
}

fn asked_of(item: &Value) -> Asked {
    Asked {
        action: item
            .get("action")
            .and_then(|action| action.get("name"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        resource: item.get("resource").and_then(resource_text).unwrap_or_default(),
    }
}

fn kind_of(context: Option<&Value>) -> Kind {
    let Some(context) = context else {
        return Kind::default();
    };
    Kind {
        usage: context.get("usage").is_some(),
        permission_only: context.get("permission_only") == Some(&Value::Bool(true)),
        subtree: context.get("match").and_then(Value::as_str) == Some("subtree"),
    }
}

/// The kind and the questions of the JSON body of a request, and true for an Access Evaluations request.
pub fn describe(body: &Value) -> (Kind, Vec<Asked>, bool) {
    let kind = kind_of(body.get("context"));
    match body.get("evaluations").and_then(Value::as_array) {
        Some(items) => (kind, items.iter().map(asked_of).collect(), true),
        None => (kind, vec![asked_of(body)], false),
    }
}

/// Read one answer with the rules of the library: a `false` answer has no limits, and the answer must be valid
/// (ProcurAuth 6.12, 7.6, 11.1). With `usage`, a `true` answer without `context.usage.units` is `false`.
pub fn parse_answer(value: &Value, usage: bool) -> Option<Answer> {
    let mut copy = value.clone();
    if copy.get("decision") == Some(&Value::Bool(false))
        && let Some(context) = copy.get_mut("context").and_then(Value::as_object_mut)
    {
        context.remove("limits");
    }
    let decision = Decision::from_value(&copy).ok()?;
    let context = decision.context;
    let answer = Answer {
        decision: decision.decision,
        failed: false,
        reason: context
            .reason
            .as_ref()
            .map(|reason| reason.as_str().to_owned())
            .unwrap_or_default(),
        retry_after: context.retry_after.unwrap_or(0),
        units: context.usage_units,
        limits: context
            .limits
            .into_iter()
            .map(|(name, value)| (name, i64::try_from(value).unwrap_or(i64::MAX)))
            .collect(),
    };
    if usage && answer.decision && answer.units.is_none() {
        return Some(Answer::default());
    }
    Some(answer)
}

/// The result of a request for the journal.
fn outcome_of(result: &Result<HttpResponse, TransportError>, kind: Kind, count: usize, batch: bool) -> Outcome {
    let response = match result {
        Err(error) => {
            return Outcome::Failed {
                status: None,
                error: error.to_string(),
            };
        }
        Ok(response) => response,
    };
    if response.status != 200 {
        return Outcome::Failed {
            status: Some(response.status),
            error: format!("HTTP status {}", response.status),
        };
    }
    let Ok(value) = serde_json::from_slice::<Value>(&response.body) else {
        return Outcome::Failed {
            status: None,
            error: "the answer is not valid JSON".to_owned(),
        };
    };
    if !batch {
        return Outcome::Answers(vec![parse_answer(&value, kind.usage)]);
    }
    let Some(items) = value.get("evaluations").and_then(Value::as_array) else {
        return Outcome::Failed {
            status: None,
            error: "the answer has no member evaluations".to_owned(),
        };
    };
    if items.len() != count {
        return Outcome::Failed {
            status: None,
            error: format!("the answer has {} items for {count} questions", items.len()),
        };
    }
    Outcome::Answers(items.iter().map(|item| parse_answer(item, false)).collect())
}

fn record(entry: Record) {
    CALL.with(|cell| {
        if let Some(call) = cell.borrow_mut().as_mut() {
            call.journal.records.push(entry);
        }
    });
}

/// The transport of the guard around the transport of the library.
pub struct LinkTransport {
    inner: Arc<dyn PdpTransport>,
    clock: Arc<dyn Clock>,
    timeout: Duration,
    usage_timeout: Duration,
}

impl LinkTransport {
    /// A transport around `inner`. `timeout` is the deadline of the requests without usage of one call.
    /// `usage_timeout` is the shortest wait of a usage question.
    pub fn new(
        inner: Arc<dyn PdpTransport>,
        clock: Arc<dyn Clock>,
        timeout: Duration,
        usage_timeout: Duration,
    ) -> Self {
        Self {
            inner,
            clock,
            timeout,
            usage_timeout,
        }
    }

    /// The request id of the call of this thread, and the wait of a request of this kind.
    fn wait(&self, kind: Kind, timeout: Duration) -> (Option<String>, Duration) {
        if kind.usage {
            let request_id = CALL.with(|cell| cell.borrow().as_ref().map(|call| call.request_id.clone()));
            return (request_id, timeout.max(self.usage_timeout));
        }
        let now = self.clock.now_millis();
        CALL.with(|cell| {
            let mut cell = cell.borrow_mut();
            let Some(call) = cell.as_mut() else {
                return (None, timeout);
            };
            let deadline = match call.plain {
                Some((known, deadline)) if known == kind => deadline,
                _ => {
                    let deadline = now.saturating_add(millis(self.timeout));
                    call.plain = Some((kind, deadline));
                    deadline
                }
            };
            let remaining = Duration::from_millis(deadline.saturating_sub(now));
            (Some(call.request_id.clone()), timeout.min(remaining))
        })
    }
}

fn with_request_id(headers: &[(String, String)], request_id: Option<&String>) -> Vec<(String, String)> {
    let mut out = headers.to_vec();
    if let Some(request_id) = request_id {
        out.push((REQUEST_ID_HEADER.to_owned(), request_id.clone()));
    }
    out
}

impl PdpTransport for LinkTransport {
    fn supports_scheme(&self, scheme: &str) -> bool {
        self.inner.supports_scheme(scheme)
    }

    fn post_json(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        timeout: Duration,
    ) -> Result<HttpResponse, TransportError> {
        let (kind, questions, batch) = serde_json::from_slice::<Value>(body)
            .map(|value| describe(&value))
            .unwrap_or_default();
        let (request_id, wait) = self.wait(kind, timeout);
        let result = if wait.is_zero() {
            // The deadline of the call is past: the request does not leave Stowr.
            Err(TransportError::Timeout)
        } else {
            self.inner
                .post_json(url, &with_request_id(headers, request_id.as_ref()), body, wait)
        };
        let outcome = outcome_of(&result, kind, questions.len(), batch);
        record(Record {
            kind,
            questions,
            outcome,
        });
        result
    }

    fn get_json(
        &self,
        url: &str,
        headers: &[(String, String)],
        timeout: Duration,
    ) -> Result<HttpResponse, TransportError> {
        let request_id = CALL.with(|cell| cell.borrow().as_ref().map(|call| call.request_id.clone()));
        let result = self
            .inner
            .get_json(url, &with_request_id(headers, request_id.as_ref()), timeout);
        // The library reads a PDP without metadata (404, 405, 410, 501) with the default paths.
        let failed = match &result {
            Err(error) => Some((None, format!("metadata: {error}"))),
            Ok(response) if !matches!(response.status, 200 | 404 | 405 | 410 | 501) => Some((
                Some(response.status),
                format!("metadata: HTTP status {}", response.status),
            )),
            Ok(_) => None,
        };
        if let Some((status, error)) = failed {
            record(Record {
                kind: Kind::default(),
                questions: Vec::new(),
                outcome: Outcome::Failed { status, error },
            });
        }
        result
    }

    fn set_idle_close(&self, idle_close_after: Duration) {
        self.inner.set_idle_close(idle_close_after);
    }
}

#[cfg(test)]
#[path = "pdp_link_tests.rs"]
mod tests;
