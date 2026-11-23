//! The guard of the mode `authzen`: the library `procurauth-pep` of ProcurAuth 1.1.
//!
//! The library checks the identity token, asks the PDP, keeps the answers and the token results, and applies the
//! rules of an answer. The library is synchronous: each call runs on a blocking thread of the runtime. The guard
//! builds the PEP one time at start, from the typed configuration and the action document of Stowr. The rules of
//! the service stay in [`super::AccessLayer`]: the published actions, the order of the questions and the meaning of
//! each answer for the client.
//!
//! The library sends each request through [`LinkTransport`]: the request id, the wait of a usage question and one
//! deadline for each call. The journal of the transport gives the log lines, and the permission that a refusal is
//! for.
//!
//! The map of the outcomes of the library to the answers of the guard:
//!
//! | Outcome of the library | Answer of the guard |
//! |---|---|
//! | `Allowed` | `decision` true, the ceilings of the permission as `limits`, the `units` of a usage question |
//! | `Refused(Forbidden { cause: Decision, reason })` | `decision` false with the reason: `403`, or `403 approval_cannot_wait` |
//! | `Refused(Forbidden { cause: NoUsageUnits })` | `decision` false without reason: `403` |
//! | `Refused(Forbidden { cause: UnknownCeiling(name) })` | `decision` false, and the line `access.ceiling_unenforceable`: `403` |
//! | `Refused(RateLimited { retry_after })` | `decision` false, `budget_exceeded` and `retry_after`: `429` |
//! | `Refused(Unavailable(..))` with a reason of 17.1 for an other or for `access` | `decision` false with that reason: `503` |
//! | `Refused(Unavailable(..))` with a budget in `context.limits` | a failure, and the line `access.pdp_invalid_answer`: `503` |
//! | `Refused(Unavailable(..))`, `Refused(Internal(..))` | a failure: `503` |

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use http::HeaderMap;
use procurauth_core::jws::{KeySet, b64url_decode};
use procurauth_pep::ceilings::Ceilings as PepCeilings;
use procurauth_pep::clock::{Clock, SystemClock};
use procurauth_pep::config::{ConfigError, PdpConfig as PepPdpConfig, PepConfig, Secret};
use procurauth_pep::document::ActionDocumentBuilder;
use procurauth_pep::http_client::{HttpTransport, HttpTransportConfig};
use procurauth_pep::operation::{NodePath, Operation as PepOperation, Permission};
use procurauth_pep::refusal::{AuthFailure, DenialCause, Refusal, UnavailableCause};
use procurauth_pep::tls::TlsTransport;
use procurauth_pep::transport::PdpTransport;
use procurauth_pep::{Identity as PepIdentity, Outcome, Pep};

use super::actions::{ActionDocument, RESOURCE_TYPES, block_label};
use super::guard::{
    AccessGuard, Answer, Ask, Identity, OperationAnswers, REASON_BUDGET, USAGE_WAIT_MARGIN, is_approval_reason,
    usage_wait,
};
use super::pdp_link::{Journal, Kind, LinkTransport, Outcome as RequestOutcome, journaled};
use super::tree::{TYPE_BUCKET, percent_encode_id, service_resource};
use super::{ACTION_ACCESS, keys, log_token, quote};
use crate::common::BoxFuture;
use crate::common::config::{Config, IdentityConfig, LogMode, PdpConfig};
use crate::common::error::{Error, Result};

/// The largest body of an answer of the PDP.
pub const MAX_ANSWER_BYTES: u64 = 256 << 10;
/// The largest body of one Access Evaluations request, until the metadata of the PDP gives a lower value.
pub const MAX_REQUEST_BYTES: u64 = 1 << 20;
/// The most kept answers of the two tables together.
pub const CACHE_ENTRIES: usize = 16384;
/// The most kept results of a token check.
pub const TOKEN_CACHE_ENTRIES: usize = 4096;
/// The most questions of one request to the options route.
pub const OPTIONS_QUESTIONS: usize = 200;
/// The most connections to the PDP.
pub const MAX_CONNECTIONS: usize = 4;
/// The longest idle time of a connection to the PDP, until the metadata gives a lower value.
pub const IDLE_CLOSE: Duration = Duration::from_secs(5);
/// The longest wait for a new connection to the PDP, TLS handshake included.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// The deepest nesting of the JSON of a token: the header or the claims.
pub const MAX_TOKEN_DEPTH: usize = 32;

/// The parts of a guard that do not come from the configuration.
pub struct Parts {
    /// The transport to the PDP.
    pub inner: Arc<dyn PdpTransport>,
    /// The clock of the kept answers, of the token check and of the deadlines.
    pub clock: Arc<dyn Clock>,
    /// The public keys of the edge.
    pub trusted: KeySet,
    /// The most kept answers.
    pub cache_entries: usize,
}

/// The guard of the PEP.
pub struct PepGuard {
    pep: Arc<Pep>,
    clock: Arc<dyn Clock>,
    document: ActionDocument,
    detailed_log: bool,
    service_ask: Ask,
    usage_timeout: Duration,
    kept: KeptCopy,
    /// The algorithm of each trusted key, by `kid`.
    key_algorithms: HashMap<String, &'static str>,
}

impl std::fmt::Debug for PepGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PepGuard")
            .field("pep", &self.pep)
            .finish_non_exhaustive()
    }
}

/// The text of the errors of the configuration that the library refuses.
fn config_errors(errors: &[ConfigError]) -> Error {
    let text: Vec<String> = errors.iter().map(ToString::to_string).collect();
    Error::internal(format!("access: {}", text.join(" ")))
}

fn identity_block(config: &Config) -> Result<&IdentityConfig> {
    config
        .access
        .identity
        .as_ref()
        .ok_or_else(|| Error::internal("access.identity is missing"))
}

fn pdp_block(config: &Config) -> Result<&PdpConfig> {
    config
        .access
        .pdp
        .as_ref()
        .ok_or_else(|| Error::internal("access.pdp is missing"))
}

/// The public keys of the edge, from the text of `access.identity.public_keys` (PEM or a JWK Set).
pub fn trusted_keys(config: &Config) -> Result<KeySet> {
    let keys = keys::parse(&identity_block(config)?.public_keys_text).map_err(Error::internal)?;
    let set = serde_json::json!({"keys": keys.iter().map(keys::PublicKey::to_jwk).collect::<Vec<_>>()});
    KeySet::from_jwks_value(&set).map_err(|findings| {
        let text: Vec<String> = findings.iter().map(ToString::to_string).collect();
        Error::internal(format!("access.identity.public_keys: {}", text.join(" ")))
    })
}

/// The link to the PDP of the library, from the `access.pdp` block. `plain_http` is `allow_plain_http`. The link never
/// sends a question again, except when the request did not leave Stowr.
pub fn link_config(pdp: &PdpConfig) -> PepPdpConfig {
    let mut link = PepPdpConfig::new(pdp.url.clone(), Secret::new(pdp.token.clone()));
    link.allow_plain_http = pdp.plain_http;
    link.request_timeout = pdp.timeout;
    link.usage_wait_margin = USAGE_WAIT_MARGIN;
    link.idle_close_after = IDLE_CLOSE;
    link.max_connections = MAX_CONNECTIONS;
    link.evaluations_max_items = u64::from(pdp.max_evaluations);
    link.evaluations_max_bytes = MAX_REQUEST_BYTES;
    link.max_response_bytes = MAX_ANSWER_BYTES;
    link.plain_retries = 0;
    link
}

/// The bounds of the HTTP client of the link.
fn transport_bounds() -> HttpTransportConfig {
    HttpTransportConfig {
        max_connections: MAX_CONNECTIONS,
        connect_timeout: CONNECT_TIMEOUT,
        idle_close_after: IDLE_CLOSE,
        max_response_bytes: MAX_ANSWER_BYTES,
    }
}

/// The certificate bundle of the image: the first file of the list of the provider client. The link to the PDP
/// then trusts the same roots as the providers.
fn system_bundle() -> Option<PathBuf> {
    crate::provider::client::ROOT_BUNDLES
        .iter()
        .map(Path::new)
        .find(|path| path.is_file())
        .map(Path::to_path_buf)
}

/// The configuration of the library, from the typed configuration of Stowr.
fn pep_config(config: &Config, trusted: KeySet) -> Result<PepConfig> {
    let identity = identity_block(config)?;
    let pdp = pdp_block(config)?;
    let mut out = PepConfig::new(
        identity.audience.clone(),
        identity.header.clone(),
        identity.issuer.clone(),
        trusted,
        identity.max_age.as_secs(),
        identity.clock_skew.as_secs(),
        link_config(pdp),
    );
    out.cache_ttl = pdp.cache_ttl;
    out.cache_max_entries = CACHE_ENTRIES;
    out.token_cache_max_entries = TOKEN_CACHE_ENTRIES;
    out.display_max_questions = OPTIONS_QUESTIONS;
    Ok(out)
}

/// The action document of the library: the same types, actions, limits and resources as the document of Stowr.
fn pep_document(config: &Config, document: &ActionDocument) -> Result<procurauth_pep::document::ActionDocument> {
    let mut builder = ActionDocumentBuilder::new(config.access.audience());
    for kind in RESOURCE_TYPES {
        builder = builder.resource_type(kind.name, kind.parent, kind.description);
    }
    for name in document.published_actions() {
        if let Some(action) = document.action(name) {
            builder = builder.action(action.name, action.resource_types, action.description, action.limits);
        }
    }
    for limit in document.declared_limits() {
        builder = match (limit.min, limit.max) {
            (Some(min), Some(max)) => builder.ceiling(
                limit.name,
                limit.label,
                limit.description,
                limit.unit,
                u64::try_from(min).unwrap_or_default(),
                u64::try_from(max).unwrap_or_default(),
            ),
            _ => builder.budget(limit.name, limit.label, limit.description, limit.unit),
        };
    }
    let blocks = config
        .buckets
        .iter()
        .map(|bucket| (bucket.id.as_str(), bucket.name.as_str()))
        .chain(
            config
                .volumes
                .iter()
                .map(|volume| (volume.id.as_str(), volume.name.as_str())),
        );
    for (id, name) in blocks {
        builder = builder.resource(&format!("{TYPE_BUCKET}:{}", percent_encode_id(id)), block_label(name));
    }
    builder.build().map_err(|findings| {
        let text: Vec<String> = findings.iter().map(ToString::to_string).collect();
        Error::internal(format!("the action document of the PEP: {}", text.join(" ")))
    })
}

/// True when the JSON text nests objects and arrays deeper than `max` levels. The text of a string does not count.
pub fn json_deeper_than(bytes: &[u8], max: usize) -> bool {
    let mut depth = 0_usize;
    let mut in_string = false;
    let mut escaped = false;
    for byte in bytes {
        if in_string {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                in_string = false;
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > max {
                    return true;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    false
}

/// True when the header or the claims of a token nest deeper than [`MAX_TOKEN_DEPTH`].
fn token_too_deep(token: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(token) else {
        return false;
    };
    text.split('.')
        .take(2)
        .filter_map(b64url_decode)
        .any(|json| json_deeper_than(&json, MAX_TOKEN_DEPTH))
}

/// The reason of the log of a refused token.
pub fn auth_reason(failure: &AuthFailure) -> String {
    match failure {
        AuthFailure::NoToken => "missing",
        AuthFailure::DuplicateHeader => "malformed",
        AuthFailure::Token { check, detail, .. } => match check.as_str() {
            "alg" => "algorithm",
            "typ" => "type",
            "kid" => "kid",
            "signature" => "signature",
            "claims" => "claims",
            "iss" => "issuer",
            "sub" => "subject",
            "aud" => "audience",
            "iat" | "nbf" if detail.contains("later than the clock") => "not_yet_valid",
            "exp" if detail.starts_with("The clock") => "expired",
            "iat" | "nbf" | "exp" => "claims",
            "life" => "max_age",
            _ => "malformed",
        },
    }
    .to_owned()
}

/// The answer of a granted permission, with its ceilings.
fn granted(ceilings: Option<&PepCeilings>) -> Answer {
    Answer {
        limits: ceilings
            .map(|ceilings| {
                ceilings
                    .iter()
                    .map(|(name, value)| (name.to_owned(), i64::try_from(value).unwrap_or(i64::MAX)))
                    .collect()
            })
            .unwrap_or_default(),
        ..Answer::allow()
    }
}

/// The permission of the library for a question of Stowr.
fn permission_of(ask: &Ask) -> Option<Permission> {
    NodePath::parse(&ask.resource)
        .ok()
        .map(|node| Permission::new(ask.action.clone(), node))
}

/// The identity of the library for the identity of a request. The guard checked the token before.
fn pep_identity(who: &Identity) -> PepIdentity {
    PepIdentity::from_checked_token(
        who.subject.clone(),
        (!who.owner.is_empty()).then(|| who.owner.clone()),
        who.issued_at,
        who.expires_at,
    )
}

/// Run a call of the library on a blocking thread, with the journal of its requests. A call that panics gives `None`.
async fn run<T: Send + 'static>(request_id: &str, call: impl FnOnce() -> T + Send + 'static) -> Option<(T, Journal)> {
    let request_id = request_id.to_owned();
    tokio::task::spawn_blocking(move || journaled(&request_id, call))
        .await
        .ok()
}

/// The questions without repetition, and the place of each question in that list.
fn unique(asks: &[Ask]) -> (Vec<Ask>, Vec<usize>) {
    let mut list: Vec<Ask> = Vec::new();
    let mut places = Vec::with_capacity(asks.len());
    for ask in asks {
        match list.iter().position(|known| known == ask) {
            Some(place) => places.push(place),
            None => {
                places.push(list.len());
                list.push(ask.clone());
            }
        }
    }
    (list, places)
}

/// A copy of the kept answers of the library to the questions without usage and with the match `node`. The library
/// gives no permission and no `retry_after` in a refusal that comes from a kept answer: this copy gives them.
struct KeptCopy {
    ttl_ms: u64,
    max_entries: usize,
    map: Mutex<HashMap<String, (Answer, u64)>>,
}

impl KeptCopy {
    fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            ttl_ms: u64::try_from(ttl.as_millis()).unwrap_or(u64::MAX),
            max_entries,
            map: Mutex::new(HashMap::new()),
        }
    }

    fn key(subject: &str, ask: &Ask, permission_only: bool) -> String {
        format!(
            "{}:{subject}\u{1f}{}\u{1f}{}\u{1f}{permission_only}",
            subject.len(),
            ask.action,
            ask.resource
        )
    }

    fn put(&self, subject: &str, ask: &Ask, permission_only: bool, answer: &Answer, now_ms: u64) {
        if self.ttl_ms == 0 || answer.failed || is_approval_reason(&answer.reason) {
            return;
        }
        let key = Self::key(subject, ask, permission_only);
        let mut map = self.map.lock().unwrap_or_else(PoisonError::into_inner);
        if map.len() >= self.max_entries && !map.contains_key(&key) {
            map.retain(|_, (_, expires)| *expires > now_ms);
            if map.len() >= self.max_entries {
                return;
            }
        }
        map.insert(key, (answer.clone(), now_ms.saturating_add(self.ttl_ms)));
    }

    fn get(&self, subject: &str, ask: &Ask, permission_only: bool, now_ms: u64) -> Option<Answer> {
        let key = Self::key(subject, ask, permission_only);
        let mut map = self.map.lock().unwrap_or_else(PoisonError::into_inner);
        match map.get(&key) {
            Some((answer, expires)) if *expires > now_ms => Some(answer.clone()),
            Some(_) => {
                map.remove(&key);
                None
            }
            None => None,
        }
    }
}

/// The text between the backticks after `has the budget` in the text of a refusal of the library.
fn budget_name_of(text: &str) -> Option<&str> {
    let rest = text.split_once("has the budget `")?.1;
    rest.split_once('`').map(|(name, _)| name)
}

impl PepGuard {
    /// Build the guard from the configuration: the transport over TLS for an `https` URL, the plain transport with
    /// `plain_http = true`. The transport over TLS reads the certificate bundle of the image one time. Then the guard
    /// reads the metadata of the PDP in the background, when a runtime is there.
    pub fn new(config: &Config, document: &ActionDocument) -> Result<Self> {
        let trusted = trusted_keys(config)?;
        let mut link = link_config(pdp_block(config)?);
        let inner: Arc<dyn PdpTransport> = if link.allow_plain_http {
            Arc::new(HttpTransport::new(transport_bounds()))
        } else {
            if let Some(bundle) = system_bundle() {
                link.tls_ca_file = Some(bundle);
                link.tls_system_roots = false;
            }
            Arc::new(TlsTransport::with_bounds(&link, transport_bounds()).map_err(|errors| config_errors(&errors))?)
        };
        let parts = Parts {
            inner,
            clock: Arc::new(SystemClock),
            trusted,
            cache_entries: CACHE_ENTRIES,
        };
        let guard = Self::with_parts(config, document, parts)?;
        guard.read_metadata_at_start();
        Ok(guard)
    }

    /// Build the guard over the parts that the caller gives, for example the fake PDP of the tests.
    pub fn with_parts(config: &Config, document: &ActionDocument, parts: Parts) -> Result<Self> {
        let Parts {
            inner,
            clock,
            trusted,
            cache_entries,
        } = parts;
        let pdp = pdp_block(config)?;
        let key_algorithms = trusted
            .keys()
            .iter()
            .filter_map(|key| Some((key.kid()?.to_owned(), key.algorithm().as_str())))
            .collect();
        let transport = Arc::new(LinkTransport::new(
            inner,
            Arc::clone(&clock),
            pdp.timeout,
            pdp.usage_timeout,
        ));
        let mut pep_config = pep_config(config, trusted)?;
        pep_config.cache_max_entries = cache_entries;
        let pep = Pep::with_clock(
            pep_config,
            pep_document(config, document)?,
            transport,
            Arc::clone(&clock),
        )
        .map_err(|errors| config_errors(&errors))?;
        Ok(Self {
            pep: Arc::new(pep),
            clock,
            document: document.clone(),
            detailed_log: config.runtime.log_mode == LogMode::Detailed,
            service_ask: Ask {
                action: ACTION_ACCESS.to_owned(),
                resource: service_resource(config.access.audience()).path(),
            },
            usage_timeout: pdp.usage_timeout,
            kept: KeptCopy::new(pdp.cache_ttl, cache_entries),
            key_algorithms,
        })
    }

    /// The number of kept answers of the library.
    pub fn kept_answers(&self) -> usize {
        self.pep.kept_answers()
    }

    /// Read the metadata of the PDP on a blocking thread, and write the line `access.pdp_metadata` or
    /// `access.pdp_failed`. A failure does not stop the start: the library reads the metadata again before its first
    /// question.
    fn read_metadata_at_start(&self) {
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let pep = Arc::clone(&self.pep);
        let usage_timeout = self.usage_timeout;
        let shown = |value: Option<u64>| value.map_or_else(|| "-".to_owned(), |value| value.to_string());
        drop(handle.spawn_blocking(move || match pep.metadata() {
            Ok(meta) => crate::log!(
                "access.pdp_metadata usage_max_seconds={} usage_wait_ms={} idle_max_seconds={} evaluations_max_items={} evaluations_max_bytes={}",
                shown(meta.usage_max_seconds),
                usage_wait(usage_timeout, meta.usage_max_seconds).as_millis(),
                shown(meta.idle_max_seconds),
                shown(meta.evaluations_max_items),
                shown(meta.evaluations_max_bytes)
            ),
            Err(refusal) => crate::log!(
                "access.pdp_failed request_id=- evaluations=0 error={}",
                quote(&refusal.to_string())
            ),
        }));
    }

    /// The name of a limit of a true answer that the action does not list as a ceiling.
    fn unlisted_limit<'a>(&self, action: &str, answer: &'a Answer) -> Option<&'a str> {
        answer
            .limits
            .keys()
            .map(String::as_str)
            .find(|name| !self.document.lists_ceiling(action, name))
    }

    /// Keep a copy of the answers of the journal to the questions without usage and with the match `node`.
    fn keep_copy(&self, subject: &str, journal: &Journal, now_ms: u64) {
        for record in &journal.records {
            let RequestOutcome::Answers(answers) = &record.outcome else {
                continue;
            };
            if record.kind.usage || record.kind.subtree {
                continue;
            }
            for (question, answer) in record.questions.iter().zip(answers) {
                if let Some(answer) = answer {
                    let ask = Ask {
                        action: question.action.clone(),
                        resource: question.resource.clone(),
                    };
                    self.kept
                        .put(subject, &ask, record.kind.permission_only, answer, now_ms);
                }
            }
        }
    }

    /// The answer to a question without usage and with the match `node`: the answer of the journal, else the copy of
    /// the kept answers. `Some(None)` is a question without a valid answer.
    fn known(
        &self,
        subject: &str,
        ask: &Ask,
        permission_only: bool,
        journal: &Journal,
        now_ms: u64,
    ) -> Option<Option<Answer>> {
        journal
            .answer(ask, |kind| {
                kind.permission_only == permission_only && !kind.subtree && !kind.usage
            })
            .or_else(|| self.kept.get(subject, ask, permission_only, now_ms).map(Some))
    }

    /// The answer of the guard for a refusal of the library to the question `ask`. `known` is the answer of the PDP
    /// to this question, when the journal or the copy of the kept answers has it. The layer reads the answer with
    /// the rules of the service: it writes the log lines of a ceiling that the action does not list, of a budget in
    /// `context.limits` and of a reason of 17.1 where no approval is possible. The flag is true when the cause is
    /// not a failure of the link.
    fn refusal_answer(&self, request_id: &str, ask: &Ask, refusal: &Refusal, known: Option<&Answer>) -> (Answer, bool) {
        // A true answer with a limit that the layer refuses. A listed ceiling here means that the cause is another
        // question: the guard then refuses without the limit.
        let refused_limit = |name: &str| {
            if self.document.lists_ceiling(&ask.action, name) {
                crate::log!(
                    "access.ceiling_unenforceable request_id={} action={} ceiling={}",
                    log_token(request_id),
                    ask.action,
                    quote(name)
                );
                return Answer::deny("");
            }
            Answer {
                limits: [(name.to_owned(), 0)].into(),
                ..Answer::allow()
            }
        };
        match refusal {
            Refusal::Forbidden {
                reason,
                cause: DenialCause::Decision,
            } => {
                let reason = reason.as_ref().map_or("", |reason| reason.as_str());
                // A refusal without usage keeps the wait of a used budget that the PDP gave.
                let retry_after = known
                    .filter(|answer| !answer.decision && answer.reason == reason)
                    .map_or(0, |answer| answer.retry_after);
                (
                    Answer {
                        retry_after,
                        ..Answer::deny(reason)
                    },
                    true,
                )
            }
            Refusal::Forbidden {
                cause: DenialCause::NoUsageUnits,
                ..
            } => (Answer::deny(""), true),
            Refusal::Forbidden {
                cause: DenialCause::UnknownCeiling(name),
                ..
            } => (refused_limit(name), true),
            Refusal::RateLimited { retry_after } => (
                Answer {
                    retry_after: *retry_after,
                    ..Answer::deny(REASON_BUDGET)
                },
                true,
            ),
            Refusal::Unavailable(UnavailableCause::Answer(text)) => match known {
                // A reason of 17.1 for an other or for `access`.
                Some(answer) if !answer.decision && is_approval_reason(&answer.reason) => (answer.clone(), true),
                _ => match budget_name_of(text) {
                    Some(name) => (refused_limit(name), true),
                    None => (Answer::failure(), false),
                },
            },
            _ => (Answer::failure(), false),
        }
    }

    /// The answers of an operation that the library refused. The library asks the use only when it grants each
    /// other. Thus a use in the journal is the cause. Else the first other with a known refused answer is the cause:
    /// the journal of the call or the copy of the kept answers gives it. Else the use is the cause.
    #[allow(clippy::too_many_arguments)]
    fn refused_operation(
        &self,
        request_id: &str,
        who: &Identity,
        others: &[Ask],
        use_ask: &Ask,
        refusal: &Refusal,
        journal: &Journal,
        now_ms: u64,
    ) -> (OperationAnswers, bool) {
        let use_sent = journal.asked(use_ask, Kind::is_plain_node);
        let mut cause = None;
        if !use_sent {
            for (index, other) in others.iter().enumerate() {
                let known = journal
                    .answer(other, |kind| kind.permission_only)
                    .or_else(|| self.kept.get(&who.subject, other, true, now_ms).map(Some));
                let refused = match known {
                    Some(None) => true,
                    Some(Some(answer)) => !answer.decision || self.unlisted_limit(&other.action, &answer).is_some(),
                    None => false,
                };
                if refused {
                    cause = Some(index);
                    break;
                }
            }
        }
        match cause {
            Some(index) => {
                let known = journal.answer(&others[index], |kind| kind.permission_only).flatten();
                let (answer, explained) = self.refusal_answer(request_id, &others[index], refusal, known.as_ref());
                let mut list = vec![Answer::allow(); index];
                list.push(answer);
                (
                    OperationAnswers {
                        others: list,
                        use_answer: None,
                    },
                    explained,
                )
            }
            None => {
                let known = self.known(&who.subject, use_ask, false, journal, now_ms).flatten();
                let (answer, explained) = self.refusal_answer(request_id, use_ask, refusal, known.as_ref());
                (
                    OperationAnswers {
                        others: vec![Answer::allow(); others.len()],
                        use_answer: Some(answer),
                    },
                    explained,
                )
            }
        }
    }

    /// Write the line `access.decision` of one question. A kept answer writes it only with `log_mode = "detailed"`.
    #[allow(clippy::too_many_arguments)]
    fn log_decision(
        &self,
        request_id: &str,
        subject: &str,
        ask: &Ask,
        subtree: bool,
        usage: bool,
        answer: &Answer,
        source: &str,
    ) {
        if source == "cache" && !self.detailed_log {
            return;
        }
        let resource = super::tree::Resource::parse(&ask.resource)
            .map(|resource| resource.logged_path(self.detailed_log))
            .unwrap_or_default();
        crate::log!(
            "access.decision request_id={} subject={} action={} resource={} match={} usage={usage} decision={} units={} retry_after={} reason={} source={source} failed={}",
            log_token(request_id),
            quote(subject),
            log_token(&ask.action),
            quote(&resource),
            if subtree { "subtree" } else { "node" },
            answer.decision,
            answer.units.map_or_else(|| "-".to_owned(), |units| units.to_string()),
            if answer.retry_after > 0 {
                answer.retry_after.to_string()
            } else {
                "-".to_owned()
            },
            log_token(&answer.reason),
            answer.failed
        );
    }

    /// Write the line of a question: the answer of the journal (`pdp` or `error`), else the answer of the guard
    /// (`cache`, or `error` for a failure).
    #[allow(clippy::too_many_arguments)]
    fn log_question(
        &self,
        request_id: &str,
        subject: &str,
        ask: &Ask,
        kind: Kind,
        journal: &Journal,
        given: Option<&Answer>,
    ) {
        let selected = |found: Kind| found.permission_only == kind.permission_only && found.subtree == kind.subtree;
        let (answer, source) = match journal.answer(ask, selected) {
            Some(Some(answer)) => (answer, "pdp"),
            Some(None) => (Answer::failure(), "error"),
            None => match given {
                Some(answer) if answer.failed => (answer.clone(), "error"),
                Some(answer) => (answer.clone(), "cache"),
                None => return,
            },
        };
        self.log_decision(request_id, subject, ask, kind.subtree, kind.usage, &answer, source);
    }

    /// Write the lines of the failed requests of a call. When no request failed and the library gives no valid
    /// answer, write the cause that the library gives.
    fn log_failures(
        &self,
        request_id: &str,
        journal: &Journal,
        refusal: Option<&Refusal>,
        explained: bool,
        count: usize,
    ) {
        let mut logged = false;
        for record in &journal.records {
            match &record.outcome {
                RequestOutcome::Failed {
                    status: Some(status @ (401 | 403)),
                    ..
                } => {
                    crate::log!(
                        "access.pdp_credential_refused request_id={} status={status}",
                        log_token(request_id)
                    );
                    logged = true;
                }
                RequestOutcome::Failed { error, .. } => {
                    crate::log!(
                        "access.pdp_failed request_id={} evaluations={} error={}",
                        log_token(request_id),
                        record.questions.len(),
                        quote(error)
                    );
                    logged = true;
                }
                RequestOutcome::Answers(answers) => {
                    for _ in answers.iter().filter(|answer| answer.is_none()) {
                        crate::log!(
                            "access.pdp_failed request_id={} evaluations=1 error={}",
                            log_token(request_id),
                            quote("the answer is not valid")
                        );
                        logged = true;
                    }
                }
            }
        }
        if !logged
            && !explained
            && let Some(refusal @ (Refusal::Unavailable(_) | Refusal::Internal(_))) = refusal
        {
            crate::log!(
                "access.pdp_failed request_id={} evaluations={count} error={}",
                log_token(request_id),
                quote(&refusal.to_string())
            );
        }
    }

    /// True when the `kid` of the header of a token names a trusted key of another algorithm than its `alg`.
    fn kid_of_another_algorithm(&self, token: &[u8]) -> bool {
        let header = std::str::from_utf8(token)
            .ok()
            .and_then(|text| text.split('.').next())
            .and_then(b64url_decode)
            .and_then(|json| serde_json::from_slice::<serde_json::Value>(&json).ok());
        let text = |name: &str| {
            header
                .as_ref()
                .and_then(|header| header.get(name))
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        };
        match (text("kid"), text("alg")) {
            (Some(kid), Some(alg)) => self.key_algorithms.get(&kid).is_some_and(|known| *known != alg),
            _ => false,
        }
    }

    fn bad_resource(request_id: &str, count: usize) {
        crate::log!(
            "access.pdp_failed request_id={} evaluations={count} error={}",
            log_token(request_id),
            quote("a resource that the PEP cannot read")
        );
    }
}

impl AccessGuard for PepGuard {
    fn authenticate(&self, headers: &HeaderMap) -> std::result::Result<Option<Identity>, String> {
        let values: Vec<&http::HeaderValue> = headers.get_all(self.pep.token_header()).iter().collect();
        if let [value] = values.as_slice()
            && token_too_deep(value.as_bytes())
        {
            return Err("malformed".to_owned());
        }
        let pairs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.to_str().unwrap_or("\u{0}")))
            .collect();
        match self.pep.authenticate(pairs) {
            Ok(identity) => Ok(Some(Identity {
                subject: identity.sub().to_owned(),
                owner: identity.owner().unwrap_or_default().to_owned(),
                issued_at: identity.issued_at(),
                expires_at: identity.expires_at(),
            })),
            Err(Refusal::Unauthenticated(failure)) => {
                let reason = auth_reason(&failure);
                // A kid of a key of another algorithm is a refusal of the kid.
                match values.as_slice() {
                    [value] if reason == "signature" && self.kid_of_another_algorithm(value.as_bytes()) => {
                        Err("kid".to_owned())
                    }
                    _ => Err(reason),
                }
            }
            Err(_) => Err("malformed".to_owned()),
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
            let count = others.len();
            let permissions: Option<Vec<Permission>> = others.iter().map(permission_of).collect();
            let (Some(used), Some(permissions)) = (permission_of(use_ask), permissions) else {
                Self::bad_resource(request_id, count + 1);
                return OperationAnswers::failure(count);
            };
            let nodes: Vec<NodePath> = permissions.iter().map(|permission| permission.node.clone()).collect();
            let operation = PepOperation::new(used.action, used.node).also_all(permissions);
            let pep = Arc::clone(&self.pep);
            let identity = pep_identity(who);
            let call = run(request_id, move || {
                if usage {
                    pep.decide(&identity, &operation)
                } else {
                    pep.check(&identity, &operation)
                }
            })
            .await;
            let Some((outcome, journal)) = call else {
                return OperationAnswers::failure(count);
            };
            let now_ms = self.clock.now_millis();
            let (answers, refusal, explained) = match outcome {
                Outcome::Allowed(allowed) => (
                    OperationAnswers {
                        others: others
                            .iter()
                            .zip(&nodes)
                            .map(|(ask, node)| granted(allowed.ceilings_for(&ask.action, node)))
                            .collect(),
                        use_answer: Some(Answer {
                            units: usage.then_some(allowed.units()),
                            ..granted(Some(allowed.ceilings()))
                        }),
                    },
                    None,
                    false,
                ),
                Outcome::ApprovalRequired(_) => (
                    OperationAnswers {
                        others: vec![Answer::allow(); count],
                        use_answer: Some(Answer::deny("approval_required")),
                    },
                    None,
                    false,
                ),
                Outcome::Refused(refusal) => {
                    let (answers, explained) =
                        self.refused_operation(request_id, who, others, use_ask, &refusal, &journal, now_ms);
                    (answers, Some(refusal), explained)
                }
            };
            self.keep_copy(&who.subject, &journal, now_ms);
            let other_kind = Kind {
                permission_only: true,
                ..Kind::default()
            };
            for (index, other) in others.iter().enumerate() {
                self.log_question(
                    request_id,
                    &who.subject,
                    other,
                    other_kind,
                    &journal,
                    answers.others.get(index),
                );
            }
            let use_kind = Kind {
                usage,
                ..Kind::default()
            };
            self.log_question(
                request_id,
                &who.subject,
                use_ask,
                use_kind,
                &journal,
                answers.use_answer.as_ref(),
            );
            self.log_failures(request_id, &journal, refusal.as_ref(), explained, count + 1);
            answers
        })
    }

    fn decide<'a>(&'a self, request_id: &'a str, who: &'a Identity, asks: &'a [Ask]) -> BoxFuture<'a, Vec<Answer>> {
        Box::pin(async move {
            let (list, places) = unique(asks);
            let permissions: Vec<Option<Permission>> = list.iter().map(permission_of).collect();
            let pep = Arc::clone(&self.pep);
            let identity = pep_identity(who);
            let call = run(request_id, move || {
                permissions
                    .into_iter()
                    .map(|permission| {
                        permission.map(|permission| {
                            pep.check(&identity, &PepOperation::new(permission.action, permission.node))
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .await;
            let Some((outcomes, journal)) = call else {
                return vec![Answer::failure(); asks.len()];
            };
            let now_ms = self.clock.now_millis();
            let mut first_refusal = None;
            let mut explained_any = false;
            let mut answers = Vec::with_capacity(list.len());
            for (ask, outcome) in list.iter().zip(outcomes) {
                let answer = match outcome {
                    None => {
                        Self::bad_resource(request_id, 1);
                        Answer::failure()
                    }
                    Some(Outcome::Allowed(allowed)) => granted(Some(allowed.ceilings())),
                    Some(Outcome::ApprovalRequired(_)) => Answer::deny("approval_required"),
                    Some(Outcome::Refused(refusal)) => {
                        let known = self.known(&who.subject, ask, false, &journal, now_ms).flatten();
                        let (answer, explained) = self.refusal_answer(request_id, ask, &refusal, known.as_ref());
                        explained_any |= explained;
                        first_refusal.get_or_insert(refusal);
                        answer
                    }
                };
                self.log_question(request_id, &who.subject, ask, Kind::default(), &journal, Some(&answer));
                answers.push(answer);
            }
            self.keep_copy(&who.subject, &journal, now_ms);
            self.log_failures(request_id, &journal, first_refusal.as_ref(), explained_any, list.len());
            places
                .iter()
                .map(|place| answers.get(*place).cloned().unwrap_or_else(Answer::failure))
                .collect()
        })
    }

    fn service<'a>(&'a self, request_id: &'a str, who: &'a Identity) -> BoxFuture<'a, Answer> {
        Box::pin(async move {
            let pep = Arc::clone(&self.pep);
            let identity = pep_identity(who);
            let Some((result, journal)) = run(request_id, move || pep.decide_route_without_action(&identity)).await
            else {
                return Answer::failure();
            };
            let (answer, refusal, explained) = match result {
                Ok(()) => (Answer::allow(), None, false),
                Err(refusal) => {
                    let known = journal.answer(&self.service_ask, |_| true).flatten();
                    let (answer, explained) =
                        self.refusal_answer(request_id, &self.service_ask, &refusal, known.as_ref());
                    (answer, Some(refusal), explained)
                }
            };
            self.log_question(
                request_id,
                &who.subject,
                &self.service_ask,
                Kind::default(),
                &journal,
                Some(&answer),
            );
            self.log_failures(request_id, &journal, refusal.as_ref(), explained, 1);
            answer
        })
    }

    fn display<'a>(&'a self, request_id: &'a str, who: &'a Identity, asks: &'a [Ask]) -> BoxFuture<'a, Vec<Answer>> {
        Box::pin(async move {
            let (list, places) = unique(asks);
            let Some(permissions) = list.iter().map(permission_of).collect::<Option<Vec<_>>>() else {
                Self::bad_resource(request_id, list.len());
                return vec![Answer::failure(); asks.len()];
            };
            let pep = Arc::clone(&self.pep);
            let identity = pep_identity(who);
            let Some((result, journal)) = run(request_id, move || pep.display(&identity, &permissions)).await else {
                return vec![Answer::failure(); asks.len()];
            };
            let (answers, refusal) = match result {
                Ok(decisions) => (
                    decisions
                        .into_iter()
                        .map(|decision| Answer {
                            decision,
                            ..Answer::default()
                        })
                        .collect::<Vec<_>>(),
                    None,
                ),
                Err(refusal) => (vec![Answer::failure(); list.len()], Some(refusal)),
            };
            let kind = Kind {
                subtree: true,
                ..Kind::default()
            };
            for (ask, answer) in list.iter().zip(&answers) {
                self.log_question(request_id, &who.subject, ask, kind, &journal, Some(answer));
            }
            self.log_failures(request_id, &journal, refusal.as_ref(), false, list.len());
            places
                .iter()
                .map(|place| answers.get(*place).cloned().unwrap_or_else(Answer::failure))
                .collect()
        })
    }
}

#[cfg(test)]
#[path = "pep_guard_tests.rs"]
mod tests;
