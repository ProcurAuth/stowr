//! The fake guard of the tests: a fake PDP and a fake check of the token behind [`AccessGuard`].
//!
//! The fake follows the rules of a real guard: one question is one Access Evaluation; two or more questions are
//! Access Evaluations requests of `max_evaluations` items at most; a repeated question of one call goes one time;
//! one deadline (`timeout`) covers a call without usage; a usage question waits for [`usage_wait`]; a failed request
//! stops the call, and each question without an answer fails; the answers of the PDP follow the rules of an answer
//! (a JSON boolean `decision`, a whole `retry_after` of 1 or more with `budget_exceeded`, whole limits of 0 or more,
//! `units` 0 or 1); a true answer to a usage question without `units` is false; the kept answers follow ProcurAuth
//! 10.1 (two tables, `permission_only` and the match in the key, no failure, no reason of an approval, no true
//! answer with one unit).
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
//!
//! The time does not run: a delay longer than the deadline makes a request fail at once.

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use http::HeaderMap;
use serde_json::{Map, Value, json};

use super::guard::{AccessGuard, Answer, Ask, Identity, REASON_BUDGET, is_approval_reason, usage_wait};
use super::tree::{Node, Resource};
use crate::common::BoxFuture;

/// The path of one Access Evaluation.
pub const EVALUATION_PATH: &str = "/access/v1/evaluation";
/// The path of an Access Evaluations request.
pub const EVALUATIONS_PATH: &str = "/access/v1/evaluations";

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
            max_entries: 16384,
        }
    }
}

type AnswerFn = Arc<dyn Fn(&FakeQuestion) -> Value + Send + Sync>;

#[derive(Clone)]
struct Kept {
    answer: Answer,
    expires_ms: u64,
}

#[derive(Default)]
struct State {
    answer: Option<AnswerFn>,
    status: u16,
    delay: Duration,
    raw: Option<Vec<u8>>,
    close_connection: bool,
    questions: Vec<FakeQuestion>,
    requests: Vec<FakeRequest>,
    now_ms: u64,
    plain_kept: HashMap<String, Kept>,
    usage_kept: HashMap<String, Kept>,
    tokens: BTreeMap<String, Identity>,
    refusals: BTreeMap<String, String>,
}

/// The fake guard.
pub struct FakePdp {
    state: Mutex<State>,
    settings: Mutex<FakeSettings>,
    header: String,
}

impl Default for FakePdp {
    fn default() -> Self {
        Self::new()
    }
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

/// Read a JSON integer without fraction, exponent or sign, of 18 digits at most.
fn whole(value: &Value) -> Option<u64> {
    let text = value.as_number()?.to_string();
    if text.is_empty() || text.len() > 18 || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Read the answer to one question with the rules of an answer. `None` for an answer that is not valid.
pub fn parse_answer(value: &Value, usage: bool) -> Option<Answer> {
    let members = value.as_object()?;
    let decision = members.get("decision")?.as_bool()?;
    let mut answer = Answer {
        decision,
        ..Answer::default()
    };
    if let Some(context) = members.get("context") {
        let context = context.as_object()?;
        let reason = match context.get("reason") {
            None => String::new(),
            Some(reason) => reason.as_str()?.to_owned(),
        };
        if !decision {
            if reason == REASON_BUDGET {
                let retry = whole(context.get("retry_after")?)?;
                if retry < 1 {
                    return None;
                }
                answer.retry_after = retry;
            }
            answer.reason = reason;
        } else {
            if let Some(limits) = context.get("limits") {
                for (name, value) in limits.as_object()? {
                    answer.limits.insert(name.clone(), i64::try_from(whole(value)?).ok()?);
                }
            }
            if let Some(usage) = context.get("usage")
                && let Some(units) = usage.as_object()?.get("units")
            {
                let units = whole(units)?;
                if units > 1 {
                    return None;
                }
                answer.units = Some(units);
            }
        }
    }
    if usage && answer.decision && answer.units.is_none() {
        return Some(Answer::default());
    }
    Some(answer)
}

/// How a call of the fake asks one question.
#[derive(Clone, Copy)]
struct Kind {
    subtree: bool,
    permission_only: bool,
    usage: bool,
}

impl Kind {
    fn match_text(self) -> &'static str {
        if self.subtree { "subtree" } else { "node" }
    }

    fn context(self) -> Map<String, Value> {
        let mut context = Map::new();
        if self.subtree {
            context.insert("match".to_owned(), json!("subtree"));
        }
        if self.permission_only {
            context.insert("permission_only".to_owned(), json!(true));
        }
        if self.usage {
            context.insert("usage".to_owned(), json!({"units": 1}));
        }
        context
    }
}

impl FakePdp {
    /// A fake that answers `{"decision": true}` to each question, with the default settings.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(State::default()),
            settings: Mutex::new(FakeSettings::default()),
            header: "x-identity-token".to_owned(),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The settings of the client.
    pub fn settings(&self) -> FakeSettings {
        *self.settings.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Change the settings of the client.
    pub fn configure(&self, change: impl FnOnce(&mut FakeSettings)) {
        change(&mut self.settings.lock().unwrap_or_else(std::sync::PoisonError::into_inner));
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

    /// Move the clock of the kept answers.
    pub fn advance(&self, by: Duration) {
        let millis = u64::try_from(by.as_millis()).unwrap_or(u64::MAX);
        let mut state = self.state();
        state.now_ms = state.now_ms.saturating_add(millis);
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

    /// The number of kept answers.
    pub fn kept(&self) -> usize {
        let state = self.state();
        state.plain_kept.len() + state.usage_kept.len()
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
        self.state().tokens.insert(
            token.to_owned(),
            Identity {
                subject: subject.to_owned(),
                owner: owner.to_owned(),
            },
        );
    }

    /// Refuse a token with a reason of the log.
    pub fn refuse_token(&self, token: &str, reason: &str) {
        self.state().refusals.insert(token.to_owned(), reason.to_owned());
    }

    /// The key of a kept answer: the subject, the action, the resource with its chain, the match, and the mark of
    /// an other permission.
    fn cache_key(subject: &str, ask: &Ask, kind: Kind) -> String {
        format!(
            "{}:{subject}\x1f{}\x1f{}\x1f{}\x1f{}",
            subject.len(),
            ask.action,
            ask.resource,
            kind.match_text(),
            kind.permission_only
        )
    }

    fn question_of(subject: &str, request_id: &str, ask: &Ask, kind: Kind, batch: bool) -> FakeQuestion {
        let resource = Resource::parse(&ask.resource).unwrap_or_default();
        let mut parts: Vec<String> = resource
            .ancestors
            .iter()
            .map(|node| format!("{}:{}", node.node_type, encode_id(&node.id)))
            .collect();
        parts.push(format!("{}:{}", resource.node_type, encode_id(&resource.id)));
        FakeQuestion {
            subject: subject.to_owned(),
            action: ask.action.clone(),
            resource_type: resource.node_type.clone(),
            resource_id: resource.id.clone(),
            ancestors: resource.ancestors.clone(),
            path: parts.join("/"),
            match_mode: kind.match_text().to_owned(),
            usage: kind.usage,
            permission_only: kind.permission_only,
            batch,
            request_id: request_id.to_owned(),
        }
    }

    /// The JSON body of one request, as a guard sends it.
    fn body_of(subject: &str, asks: &[&Ask], kind: Kind) -> (&'static str, Value) {
        let resource =
            |ask: &Ask| serde_json::to_value(Resource::parse(&ask.resource).unwrap_or_default()).unwrap_or_default();
        let subject = json!({"type": "user", "id": subject});
        let context = kind.context();
        if let [ask] = asks {
            let mut body = json!({"subject": subject, "action": {"name": ask.action}, "resource": resource(ask)});
            if !context.is_empty()
                && let Some(map) = body.as_object_mut()
            {
                map.insert("context".to_owned(), Value::Object(context));
            }
            return (EVALUATION_PATH, body);
        }
        let items: Vec<Value> = asks
            .iter()
            .map(|ask| json!({"action": {"name": ask.action}, "resource": resource(ask)}))
            .collect();
        let mut body = json!({"subject": subject, "evaluations": items});
        if !context.is_empty()
            && let Some(map) = body.as_object_mut()
        {
            map.insert("context".to_owned(), Value::Object(context));
        }
        (EVALUATIONS_PATH, body)
    }

    /// Send one request: record it, then give one answer for each question, or `None` when the request failed.
    fn exchange(
        &self,
        subject: &str,
        request_id: &str,
        asks: &[&Ask],
        kind: Kind,
        budget: &mut Duration,
    ) -> Option<Vec<Answer>> {
        let batch = asks.len() > 1;
        let (path, body) = Self::body_of(subject, asks, kind);
        let questions: Vec<FakeQuestion> = asks
            .iter()
            .map(|ask| Self::question_of(subject, request_id, ask, kind, batch))
            .collect();
        let (answer, status, delay, raw, close) = {
            let mut state = self.state();
            state.requests.push(FakeRequest { path, body });
            state.questions.extend(questions.iter().cloned());
            (
                state.answer.clone(),
                state.status,
                state.delay,
                state.raw.clone(),
                state.close_connection,
            )
        };
        if delay > *budget {
            *budget = Duration::ZERO;
            return None;
        }
        *budget -= delay;
        if close || (status != 0 && status != 200) {
            return None;
        }
        let documents: Vec<Value> = match raw {
            Some(raw) => {
                let value: Value = serde_json::from_slice(&raw).ok()?;
                if batch {
                    let items = value.get("evaluations")?.as_array()?.clone();
                    if items.len() != asks.len() {
                        return None;
                    }
                    items
                } else {
                    vec![value]
                }
            }
            None => questions
                .iter()
                .map(|question| match &answer {
                    Some(answer) => answer(question),
                    None => json!({"decision": true}),
                })
                .collect(),
        };
        Some(
            documents
                .iter()
                .map(|document| parse_answer(document, kind.usage).unwrap_or_else(Answer::failure))
                .collect(),
        )
    }

    fn lookup(table: &mut HashMap<String, Kept>, key: &str, now: u64) -> Option<Kept> {
        let kept = table.get(key)?.clone();
        if now >= kept.expires_ms {
            table.remove(key);
            return None;
        }
        Some(kept)
    }

    fn store(&self, usage: bool, key: String, answer: &Answer, life: Duration) {
        let ttl = self.settings().cache_ttl;
        let life = life.min(ttl);
        if life.is_zero() || answer.failed || is_approval_reason(&answer.reason) {
            return;
        }
        let max_entries = self.settings().max_entries;
        let mut state = self.state();
        let now = state.now_ms;
        let expires_ms = now.saturating_add(u64::try_from(life.as_millis()).unwrap_or(u64::MAX));
        let full = |state: &State| state.plain_kept.len() + state.usage_kept.len() >= max_entries;
        let present = if usage {
            state.usage_kept.contains_key(&key)
        } else {
            state.plain_kept.contains_key(&key)
        };
        if !present && full(&state) {
            state.plain_kept.retain(|_, kept| kept.expires_ms > now);
            state.usage_kept.retain(|_, kept| kept.expires_ms > now);
            if full(&state) {
                return;
            }
        }
        let table = if usage {
            &mut state.usage_kept
        } else {
            &mut state.plain_kept
        };
        table.insert(
            key,
            Kept {
                answer: answer.clone(),
                expires_ms,
            },
        );
    }

    /// Ask questions without usage, with the kept answers, the removal of the repeated questions, the batches and
    /// one deadline.
    fn ask_plain(&self, request_id: &str, subject: &str, asks: &[Ask], kind: Kind) -> Vec<Answer> {
        let settings = self.settings();
        let mut out = vec![Answer::failure(); asks.len()];
        let mut groups: Vec<(String, Vec<usize>)> = Vec::new();
        for (index, ask) in asks.iter().enumerate() {
            let key = Self::cache_key(subject, ask, kind);
            match groups.iter_mut().find(|(known, _)| *known == key) {
                Some((_, indexes)) => indexes.push(index),
                None => groups.push((key, vec![index])),
            }
        }
        let mut pending = Vec::new();
        {
            let mut state = self.state();
            let now = state.now_ms;
            for (position, (key, indexes)) in groups.iter().enumerate() {
                match Self::lookup(&mut state.plain_kept, key, now) {
                    Some(kept) => indexes.iter().for_each(|index| out[*index] = kept.answer.clone()),
                    None => pending.push(position),
                }
            }
        }
        let mut budget = settings.timeout;
        let mut stopped = false;
        for chunk in pending.chunks(settings.max_evaluations.max(1)) {
            let answers = if stopped {
                None
            } else {
                let chunk_asks: Vec<&Ask> = chunk.iter().map(|position| &asks[groups[*position].1[0]]).collect();
                self.exchange(subject, request_id, &chunk_asks, kind, &mut budget)
            };
            stopped = answers.is_none();
            let answers = answers.unwrap_or_else(|| vec![Answer::failure(); chunk.len()]);
            for (position, answer) in chunk.iter().zip(answers) {
                let (key, indexes) = &groups[*position];
                for index in indexes {
                    out[*index] = answer.clone();
                }
                self.store(false, key.clone(), &answer, settings.cache_ttl);
            }
        }
        out
    }
}

impl AccessGuard for FakePdp {
    fn authenticate(&self, headers: &HeaderMap) -> Result<Option<Identity>, String> {
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
        let state = self.state();
        if let Some(reason) = state.refusals.get(&token) {
            return Err(reason.clone());
        }
        match state.tokens.get(&token) {
            Some(identity) => Ok(Some(identity.clone())),
            None => Err("malformed".to_owned()),
        }
    }

    fn decide<'a>(
        &'a self,
        request_id: &'a str,
        subject: &'a str,
        asks: &'a [Ask],
        permission_only: bool,
    ) -> BoxFuture<'a, Vec<Answer>> {
        let kind = Kind {
            subtree: false,
            permission_only,
            usage: false,
        };
        let answers = self.ask_plain(request_id, subject, asks, kind);
        Box::pin(async move { answers })
    }

    fn use_one<'a>(&'a self, request_id: &'a str, subject: &'a str, ask: &'a Ask) -> BoxFuture<'a, Answer> {
        let kind = Kind {
            subtree: false,
            permission_only: false,
            usage: true,
        };
        let settings = self.settings();
        let key = Self::cache_key(subject, ask, kind);
        let kept = {
            let mut state = self.state();
            let now = state.now_ms;
            Self::lookup(&mut state.usage_kept, &key, now).map(|kept| (kept, now))
        };
        let answer = match kept {
            Some((kept, now)) => {
                let mut answer = kept.answer;
                if !answer.decision && answer.reason == REASON_BUDGET {
                    // The seconds that remain, at least 1 and never more than the first value.
                    let remaining = kept.expires_ms.saturating_sub(now).div_ceil(1000).max(1);
                    answer.retry_after = answer.retry_after.min(remaining);
                }
                answer
            }
            None => {
                let mut budget = usage_wait(settings.usage_timeout, settings.usage_max_seconds);
                let answer = self
                    .exchange(subject, request_id, &[ask], kind, &mut budget)
                    .and_then(|answers| answers.into_iter().next())
                    .unwrap_or_else(Answer::failure);
                if answer.decision && answer.units == Some(0) {
                    self.store(true, key, &answer, settings.cache_ttl);
                } else if !answer.decision && answer.reason == REASON_BUDGET && answer.retry_after >= 1 {
                    self.store(true, key, &answer, Duration::from_secs(answer.retry_after));
                }
                answer
            }
        };
        Box::pin(async move { answer })
    }

    fn display<'a>(&'a self, request_id: &'a str, subject: &'a str, asks: &'a [Ask]) -> BoxFuture<'a, Vec<Answer>> {
        let kind = Kind {
            subtree: true,
            permission_only: false,
            usage: false,
        };
        let answers = self.ask_plain(request_id, subject, asks, kind);
        Box::pin(async move { answers })
    }
}

#[cfg(test)]
#[path = "fake_tests.rs"]
mod tests;
