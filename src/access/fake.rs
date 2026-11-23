//! The fake PDP of the tests, behind the real guard of the mode `authzen`.
//!
//! [`FakePdp`] is an [`AccessGuard`]. It checks the token with a table of texts that the test gives. It asks each
//! question through the real guard ([`PepGuard`]) and the library `procurauth-pep`, over a fake transport: the fake
//! PDP. The fake PDP records each request and gives the answers of a function that the test gives. It can also fail:
//! an HTTP status, a delay, a body, a lost connection.
//!
//! The time does not run: the clock of the guard is a manual clock. A delay of the fake PDP moves the clock. A delay
//! longer than the wait of the request makes the request fail at once.
//!
//! Use it as follows:
//!
//! ```text
//! let fake = FakePdp::new();
//! fake.set_answer(|q| json!({"decision": q.action == "object.read"}));
//! ... ask questions ...
//! fake.questions()  // each question, also the items of a batch
//! fake.requests()   // the number of requests to the PDP
//! ```

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use http::HeaderMap;
use procurauth_core::jws::{KeySet, SigningKey};
use procurauth_pep::clock::{Clock, ManualClock};
use procurauth_pep::transport::{HttpResponse, PdpTransport, TransportError};
use serde_json::{Value, json};

use super::actions::ActionDocument;
use super::guard::{AccessGuard, Answer, Ask, Identity, OperationAnswers};
use super::pdp_link::{REQUEST_ID_HEADER, describe};
use super::pep_guard::{CACHE_ENTRIES, Parts, PepGuard};
use super::tree::Node;
use crate::common::BoxFuture;
use crate::common::config::Config;
use crate::common::error::Result;

pub use super::pdp_link::parse_answer;

/// The path of one Access Evaluation.
pub const EVALUATION_PATH: &str = "/access/v1/evaluation";
/// The path of an Access Evaluations request.
pub const EVALUATIONS_PATH: &str = "/access/v1/evaluations";
/// The path of the metadata of the PDP.
pub const METADATA_PATH: &str = "/.well-known/authzen-configuration";

/// One question that the fake PDP received. A batch gives one record for each item.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FakeQuestion {
    /// The subject.
    pub subject: String,
    /// The action.
    pub action: String,
    /// The type of the resource.
    pub resource_type: String,
    /// The id of the resource.
    pub resource_id: String,
    /// The chain of `resource.properties.ancestors`, from the service.
    pub ancestors: Vec<Node>,
    /// The text form of the chain: `service:s/bucket:b/folder:f`.
    pub path: String,
    /// `node` or `subtree`.
    pub match_mode: String,
    /// True when the question has `context.usage`.
    pub usage: bool,
    /// True when the question has `context.permission_only`.
    pub permission_only: bool,
    /// True when the question came in an Access Evaluations request.
    pub batch: bool,
    /// The request id of the request.
    pub request_id: String,
}

/// One request that the fake PDP received: the path and the exact JSON body.
#[derive(Clone, Debug, PartialEq)]
pub struct FakeRequest {
    /// The path.
    pub path: &'static str,
    /// The body.
    pub body: Value,
}

/// The settings of the client: the defaults of the configuration of the tests.
#[derive(Clone, Copy, Debug)]
pub struct FakeSettings {
    /// The deadline of a call without usage.
    pub timeout: Duration,
    /// The wait of a usage question, before the time that the PDP publishes.
    pub usage_timeout: Duration,
    /// `procurauth_usage_max_seconds` of the metadata of the PDP.
    pub usage_max_seconds: Option<u64>,
    /// The life of a kept answer. Zero keeps nothing.
    pub cache_ttl: Duration,
    /// The most items of one Access Evaluations request.
    pub max_evaluations: usize,
    /// The most kept answers of the two tables together.
    pub max_entries: usize,
}

impl Default for FakeSettings {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(1),
            usage_timeout: Duration::from_secs(6),
            usage_max_seconds: None,
            cache_ttl: Duration::ZERO,
            max_evaluations: 64,
            max_entries: CACHE_ENTRIES,
        }
    }
}

type AnswerFn = Arc<dyn Fn(&FakeQuestion) -> Value + Send + Sync>;

/// The state of the fake PDP: the answers, the failures and the records.
#[derive(Default)]
struct State {
    answer: Option<AnswerFn>,
    status: u16,
    delay: Duration,
    raw: Option<Vec<u8>>,
    close_connection: bool,
    usage_max_seconds: Option<u64>,
    questions: Vec<FakeQuestion>,
    requests: Vec<FakeRequest>,
}

/// The fake PDP: the transport of the guard.
struct FakeServer {
    state: Mutex<State>,
    clock: ManualClock,
    base: String,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// The text form of an id in a path, written again here: a fault in the encoder of the service cannot hide itself.
fn encode_id(id: &str) -> String {
    let mut out = String::new();
    for byte in id.bytes() {
        if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// The questions of the JSON body of a request.
fn questions_of(body: &Value, request_id: &str) -> Vec<FakeQuestion> {
    let (kind, _, batch) = describe(body);
    let subject = body
        .get("subject")
        .and_then(|subject| subject.get("id"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let items: Vec<&Value> = match body.get("evaluations").and_then(Value::as_array) {
        Some(items) => items.iter().collect(),
        None => vec![body],
    };
    items
        .into_iter()
        .map(|item| {
            let text = |value: Option<&Value>, name: &str| {
                value
                    .and_then(|value| value.get(name))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            let resource = item.get("resource");
            let ancestors: Vec<Node> = resource
                .and_then(|resource| resource.get("properties"))
                .and_then(|properties| properties.get("ancestors"))
                .and_then(Value::as_array)
                .map(|list| {
                    list.iter()
                        .map(|node| Node::new(&text(Some(node), "type"), &text(Some(node), "id")))
                        .collect()
                })
                .unwrap_or_default();
            let resource_type = text(resource, "type");
            let resource_id = text(resource, "id");
            let mut parts: Vec<String> = ancestors
                .iter()
                .map(|node| format!("{}:{}", node.node_type, encode_id(&node.id)))
                .collect();
            parts.push(format!("{resource_type}:{}", encode_id(&resource_id)));
            FakeQuestion {
                subject: subject.clone(),
                action: text(item.get("action"), "name"),
                resource_type,
                resource_id,
                ancestors,
                path: parts.join("/"),
                match_mode: if kind.subtree { "subtree" } else { "node" }.to_owned(),
                usage: kind.usage,
                permission_only: kind.permission_only,
                batch,
                request_id: request_id.to_owned(),
            }
        })
        .collect()
}

impl PdpTransport for FakeServer {
    fn supports_scheme(&self, scheme: &str) -> bool {
        scheme == "http" || scheme == "https"
    }

    fn post_json(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        timeout: Duration,
    ) -> std::result::Result<HttpResponse, TransportError> {
        let value: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
        let request_id = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(REQUEST_ID_HEADER))
            .map(|(_, value)| value.clone())
            .unwrap_or_default();
        let questions = questions_of(&value, &request_id);
        let path = if url.ends_with(EVALUATIONS_PATH) {
            EVALUATIONS_PATH
        } else {
            EVALUATION_PATH
        };
        let (answer, status, delay, raw, close) = {
            let mut state = lock(&self.state);
            state.requests.push(FakeRequest { path, body: value });
            state.questions.extend(questions.iter().cloned());
            (
                state.answer.clone(),
                state.status,
                state.delay,
                state.raw.clone(),
                state.close_connection,
            )
        };
        if delay > timeout {
            self.clock.advance_millis(millis(timeout));
            return Err(TransportError::Timeout);
        }
        self.clock.advance_millis(millis(delay));
        if close {
            return Err(TransportError::Lost("the PDP closed the connection".to_owned()));
        }
        let reply = |status: u16, body: Vec<u8>| HttpResponse {
            status,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body,
        };
        if status != 0 && status != 200 {
            return Ok(reply(status, Vec::new()));
        }
        if let Some(raw) = raw {
            return Ok(reply(200, raw));
        }
        let documents: Vec<Value> = questions
            .iter()
            .map(|question| match &answer {
                Some(answer) => answer(question),
                None => json!({"decision": true}),
            })
            .collect();
        let document = if path == EVALUATIONS_PATH {
            json!({ "evaluations": documents })
        } else {
            documents.into_iter().next().unwrap_or(Value::Null)
        };
        Ok(reply(200, document.to_string().into_bytes()))
    }

    fn get_json(
        &self,
        _url: &str,
        _headers: &[(String, String)],
        _timeout: Duration,
    ) -> std::result::Result<HttpResponse, TransportError> {
        let usage_max_seconds = lock(&self.state).usage_max_seconds;
        Ok(match usage_max_seconds {
            Some(seconds) => HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: json!({"policy_decision_point": self.base, "procurauth_usage_max_seconds": seconds})
                    .to_string()
                    .into_bytes(),
            },
            None => HttpResponse {
                status: 404,
                headers: Vec::new(),
                body: Vec::new(),
            },
        })
    }
}

/// The key set of the guard of the tests. The fake checks the tokens with its own table.
fn test_keys() -> KeySet {
    KeySet::from_keys(vec![SigningKey::from_ed25519_seed(&[7; 32]).public_key(Some("test"))])
}

#[derive(Default)]
struct Tokens {
    accepted: BTreeMap<String, Identity>,
    refused: BTreeMap<String, String>,
}

/// The fake PDP and the fake check of the token, behind the real guard.
pub struct FakePdp {
    server: Arc<FakeServer>,
    settings: Mutex<FakeSettings>,
    tokens: Mutex<Tokens>,
    bound: Mutex<Option<(Config, ActionDocument)>>,
    guard: Mutex<Option<Arc<PepGuard>>>,
    header: String,
}

impl Default for FakePdp {
    fn default() -> Self {
        Self::new()
    }
}

impl FakePdp {
    /// A fake that answers `{"decision": true}` to each question, with the default settings.
    pub fn new() -> Self {
        Self {
            server: Arc::new(FakeServer {
                state: Mutex::new(State::default()),
                clock: ManualClock::at_seconds(1_800_000_000),
                base: "http://127.0.0.1:8181".to_owned(),
            }),
            settings: Mutex::new(FakeSettings::default()),
            tokens: Mutex::new(Tokens::default()),
            bound: Mutex::new(None),
            guard: Mutex::new(None),
            header: "x-identity-token".to_owned(),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        lock(&self.server.state)
    }

    /// The settings of the client.
    pub fn settings(&self) -> FakeSettings {
        *lock(&self.settings)
    }

    /// Change the settings of the client. The guard starts again with no kept answer.
    pub fn configure(&self, change: impl FnOnce(&mut FakeSettings)) {
        change(&mut lock(&self.settings));
        self.state().usage_max_seconds = self.settings().usage_max_seconds;
        *lock(&self.guard) = None;
    }

    /// The guard over the fake PDP, built at the first use after the access layer gave the configuration.
    fn guard(&self) -> Option<Arc<PepGuard>> {
        let mut guard = lock(&self.guard);
        if let Some(guard) = guard.as_ref() {
            return Some(Arc::clone(guard));
        }
        let bound = lock(&self.bound);
        let (config, document) = bound.as_ref()?;
        let settings = self.settings();
        let mut config = config.clone();
        if let Some(pdp) = config.access.pdp.as_mut() {
            pdp.url = self.server.base.clone();
            pdp.plain_http = true;
            pdp.timeout = settings.timeout;
            pdp.usage_timeout = settings.usage_timeout;
            pdp.cache_ttl = settings.cache_ttl;
            pdp.max_evaluations = u32::try_from(settings.max_evaluations).unwrap_or(u32::MAX);
        }
        let clock: Arc<dyn Clock> = Arc::new(self.server.clock.clone());
        let parts = Parts {
            inner: Arc::clone(&self.server) as Arc<dyn PdpTransport>,
            clock,
            trusted: test_keys(),
            cache_entries: settings.max_entries,
        };
        let built = Arc::new(PepGuard::with_parts(&config, document, parts).ok()?);
        *guard = Some(Arc::clone(&built));
        Some(built)
    }

    /// Set the function that gives the JSON object of the decision of each question.
    pub fn set_answer(&self, answer: impl Fn(&FakeQuestion) -> Value + Send + Sync + 'static) {
        self.state().answer = Some(Arc::new(answer));
    }

    /// Make each request give this HTTP status. 0 or 200 stops it.
    pub fn set_status(&self, status: u16) {
        self.state().status = status;
    }

    /// Make each request wait before it answers.
    pub fn set_delay(&self, delay: Duration) {
        self.state().delay = delay;
    }

    /// Make each request give this body.
    pub fn set_raw(&self, body: &[u8]) {
        self.state().raw = Some(body.to_vec());
    }

    /// Make each request lose its connection after the PDP read it.
    pub fn set_close_connection(&self, on: bool) {
        self.state().close_connection = on;
    }

    /// Move the clock of the guard.
    pub fn advance(&self, by: Duration) {
        self.server.clock.advance_millis(millis(by));
    }

    /// Each question that the fake received, in order of arrival.
    pub fn questions(&self) -> Vec<FakeQuestion> {
        self.state().questions.clone()
    }

    /// The number of requests to the PDP.
    pub fn requests(&self) -> usize {
        self.state().requests.len()
    }

    /// Each request to the PDP: the path and the body.
    pub fn raw_requests(&self) -> Vec<FakeRequest> {
        self.state().requests.clone()
    }

    /// The number of kept answers of the guard.
    pub fn kept(&self) -> usize {
        self.guard().map_or(0, |guard| guard.kept_answers())
    }

    /// Clear the records and the failure injection. Keep the answer function, the tokens and the kept answers.
    pub fn reset(&self) {
        let mut state = self.state();
        state.status = 0;
        state.delay = Duration::ZERO;
        state.raw = None;
        state.close_connection = false;
        state.questions.clear();
        state.requests.clear();
    }

    /// Accept a token for a subject. The token is the text of the header.
    pub fn accept_token(&self, token: &str, subject: &str, owner: &str) {
        lock(&self.tokens).accepted.insert(
            token.to_owned(),
            Identity {
                subject: subject.to_owned(),
                owner: owner.to_owned(),
                issued_at: 1_800_000_000,
                expires_at: 1_800_000_300,
            },
        );
    }

    /// Refuse a token with a reason of the log.
    pub fn refuse_token(&self, token: &str, reason: &str) {
        lock(&self.tokens).refused.insert(token.to_owned(), reason.to_owned());
    }
}

impl AccessGuard for FakePdp {
    fn bind(&self, config: &Config, document: &ActionDocument) -> Result<()> {
        *lock(&self.bound) = Some((config.clone(), document.clone()));
        *lock(&self.guard) = None;
        Ok(())
    }

    fn authenticate(&self, headers: &HeaderMap) -> std::result::Result<Option<Identity>, String> {
        let values: Vec<&[u8]> = headers
            .get_all(self.header.as_str())
            .iter()
            .map(http::HeaderValue::as_bytes)
            .collect();
        let token = match values.as_slice() {
            [] => return Err("missing".to_owned()),
            [one] => String::from_utf8_lossy(one).into_owned(),
            _ => return Err("malformed".to_owned()),
        };
        if token.is_empty() {
            return Err("missing".to_owned());
        }
        let tokens = lock(&self.tokens);
        if let Some(reason) = tokens.refused.get(&token) {
            return Err(reason.clone());
        }
        match tokens.accepted.get(&token) {
            Some(identity) => Ok(Some(identity.clone())),
            None => Err("malformed".to_owned()),
        }
    }

    fn operation<'a>(
        &'a self,
        request_id: &'a str,
        who: &'a Identity,
        others: &'a [Ask],
        use_ask: &'a Ask,
        usage: bool,
    ) -> BoxFuture<'a, OperationAnswers> {
        Box::pin(async move {
            match self.guard() {
                Some(guard) => guard.operation(request_id, who, others, use_ask, usage).await,
                None => OperationAnswers::failure(others.len()),
            }
        })
    }

    fn decide<'a>(&'a self, request_id: &'a str, who: &'a Identity, asks: &'a [Ask]) -> BoxFuture<'a, Vec<Answer>> {
        Box::pin(async move {
            match self.guard() {
                Some(guard) => guard.decide(request_id, who, asks).await,
                None => vec![Answer::failure(); asks.len()],
            }
        })
    }

    fn service<'a>(&'a self, request_id: &'a str, who: &'a Identity) -> BoxFuture<'a, Answer> {
        Box::pin(async move {
            match self.guard() {
                Some(guard) => guard.service(request_id, who).await,
                None => Answer::failure(),
            }
        })
    }

    fn display<'a>(&'a self, request_id: &'a str, who: &'a Identity, asks: &'a [Ask]) -> BoxFuture<'a, Vec<Answer>> {
        Box::pin(async move {
            match self.guard() {
                Some(guard) => guard.display(request_id, who, asks).await,
                None => vec![Answer::failure(); asks.len()],
            }
        })
    }
}

#[cfg(test)]
#[path = "fake_tests.rs"]
mod tests;
