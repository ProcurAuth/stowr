//! The guard of the mode `authzen`: the library `procurauth-pep`.
//!
//! The library is synchronous: each call runs on the blocking threads of the runtime. The guard builds the PEP one
//! time at start, from the typed configuration and the action document of Stowr. It keeps the rules of Stowr apart:
//! the published actions, the order of the questions and the meaning of each answer stay in [`super::AccessLayer`].
//!
//! The map of the answers of the library to the answers of the guard:
//!
//! | Outcome of the library | Answer of the guard |
//! |---|---|
//! | `Allowed` | `decision` true, the ceilings as `limits`, `units` of the use |
//! | `Refused(Forbidden { cause: Decision, reason })` | `decision` false, the text of the reason |
//! | `Refused(Forbidden { cause: NoUsageUnits })` | `decision` false, no reason |
//! | `Refused(Forbidden { cause: UnknownCeiling(name) })` | `decision` true with the limit `name`: Stowr refuses it (403) |
//! | `Refused(RateLimited { retry_after })` | `decision` false, `budget_exceeded`, `retry_after` |
//! | `Refused(Unavailable(..))`, `Refused(Internal(..))`, an approval | `failed` (503) |

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http::HeaderMap;
use procurauth_core::jws::KeySet;
use procurauth_pep::config::{PdpConfig as PepPdpConfig, PepConfig, Secret};
use procurauth_pep::document::ActionDocumentBuilder;
use procurauth_pep::http_client::{HttpTransport, HttpTransportConfig};
use procurauth_pep::operation::{NodePath, Operation as PepOperation, Permission};
use procurauth_pep::refusal::{AuthFailure, DenialCause, Refusal, UnavailableCause};
use procurauth_pep::tls::TlsTransport;
use procurauth_pep::transport::PdpTransport;
use procurauth_pep::{Identity as PepIdentity, Outcome, Pep};

use super::actions::{ActionDocument, RESOURCE_TYPES, block_label};
use super::guard::{AccessGuard, Answer, Ask, Identity, REASON_BUDGET};
use super::tree::{TYPE_BUCKET, percent_encode_id};
use super::{ACTION_ACCESS, keys, log_token};
use crate::common::BoxFuture;
use crate::common::config::Config;
use crate::common::error::{Error, Result};

/// The largest body of an answer of the PDP.
const MAX_ANSWER_BYTES: u64 = 256 << 10;
/// The most kept answers of the two tables together.
const CACHE_ENTRIES: usize = 16384;
/// The most kept results of a token check.
const TOKEN_CACHE_ENTRIES: usize = 4096;
/// The most identities that the guard keeps between the check of a token and the questions of its request.
const MAX_IDENTITIES: usize = 4096;
/// The most questions of one request to the options route.
const OPTIONS_QUESTIONS: usize = 200;

/// The guard of the PEP.
pub struct PepGuard {
    pep: Arc<Pep>,
    detailed_log: bool,
    /// The identity of each subject that a token gave. The library builds an identity only from a token.
    identities: Mutex<HashMap<String, PepIdentity>>,
}

/// The configuration of the library, from the typed configuration of Stowr.
fn pep_config(config: &Config) -> Result<PepConfig> {
    let identity = config
        .access
        .identity
        .as_ref()
        .ok_or_else(|| Error::internal("access.identity is missing"))?;
    let pdp = config
        .access
        .pdp
        .as_ref()
        .ok_or_else(|| Error::internal("access.pdp is missing"))?;
    let keys = keys::parse(&identity.public_keys_text).map_err(Error::internal)?;
    let set = serde_json::json!({"keys": keys.iter().map(keys::PublicKey::to_jwk).collect::<Vec<_>>()});
    let trusted = KeySet::from_jwks_value(&set)
        .map_err(|findings| Error::internal(format!("access.identity.public_keys: {findings:?}")))?;
    let mut link = PepPdpConfig::new(pdp.url.clone(), Secret::new(pdp.token.clone()));
    link.allow_plain_http = pdp.plain_http;
    link.request_timeout = pdp.timeout;
    link.usage_wait_margin = super::guard::USAGE_WAIT_MARGIN;
    link.idle_close_after = Duration::from_secs(5);
    link.max_connections = 4;
    link.evaluations_max_items = u64::from(pdp.max_evaluations);
    link.max_response_bytes = MAX_ANSWER_BYTES;
    link.plain_retries = 0;
    let mut out = PepConfig::new(
        identity.audience.clone(),
        identity.header.clone(),
        identity.issuer.clone(),
        trusted,
        identity.max_age.as_secs(),
        identity.clock_skew.as_secs(),
        link,
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
    builder
        .build()
        .map_err(|findings| Error::internal(format!("the action document of the PEP: {findings:?}")))
}

/// The reason of the log of a refused token.
fn auth_reason(failure: &AuthFailure) -> String {
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
            "iat" => "not_yet_valid",
            "exp" => "expired",
            "nbf" if detail.contains("later than the clock") => "not_yet_valid",
            "nbf" => "claims",
            "life" => "max_age",
            _ => "malformed",
        },
    }
    .to_owned()
}

/// The answer of the guard for an outcome of the library.
fn answer_of(outcome: Outcome, request_id: &str) -> Answer {
    match outcome {
        Outcome::Allowed(allowed) => Answer {
            decision: true,
            units: Some(allowed.units()),
            limits: allowed
                .ceilings()
                .iter()
                .map(|(name, value)| (name.to_owned(), i64::try_from(value).unwrap_or(i64::MAX)))
                .collect(),
            ..Answer::default()
        },
        Outcome::ApprovalRequired(_) => Answer::deny("approval_required"),
        Outcome::Refused(refusal) => refusal_answer(&refusal, request_id),
    }
}

/// The answer of the guard for a refusal of the library.
fn refusal_answer(refusal: &Refusal, request_id: &str) -> Answer {
    match refusal {
        Refusal::Forbidden {
            reason,
            cause: DenialCause::Decision,
        } => Answer::deny(reason.as_ref().map_or("", |reason| reason.as_str())),
        Refusal::Forbidden {
            cause: DenialCause::NoUsageUnits,
            ..
        } => Answer::default(),
        Refusal::Forbidden {
            cause: DenialCause::UnknownCeiling(name),
            ..
        } => Answer {
            limits: [(name.clone(), 0)].into(),
            ..Answer::allow()
        },
        Refusal::RateLimited { retry_after } => Answer {
            retry_after: *retry_after,
            ..Answer::deny(REASON_BUDGET)
        },
        Refusal::Unavailable(UnavailableCause::Status(status @ (401 | 403))) => {
            crate::log!(
                "access.pdp_credential_refused request_id={} status={status}",
                log_token(request_id)
            );
            Answer::failure()
        }
        other => {
            crate::log!(
                "access.pdp_failed request_id={} error={}",
                log_token(request_id),
                super::quote(&other.to_string())
            );
            Answer::failure()
        }
    }
}

impl PepGuard {
    /// Build the guard: the transport over TLS for an `https` URL, the plain transport with `plain_http = true`.
    /// The transport over TLS reads the CA bundle of the system one time.
    pub fn new(config: &Config, document: &ActionDocument) -> Result<Self> {
        let link = pep_config(config)?.pdp;
        let transport: Arc<dyn PdpTransport> = if link.allow_plain_http {
            Arc::new(HttpTransport::new(HttpTransportConfig::from_pdp(&link)))
        } else {
            Arc::new(TlsTransport::new(&link).map_err(|errors| Error::internal(format!("access.pdp: {errors:?}")))?)
        };
        Self::with_transport(config, document, transport)
    }

    /// Build the guard over a transport that the caller gives, for example the scripted transport of a test.
    pub fn with_transport(
        config: &Config,
        document: &ActionDocument,
        transport: Arc<dyn PdpTransport>,
    ) -> Result<Self> {
        let pep_config = pep_config(config)?;
        let pep = Pep::new(pep_config, pep_document(config, document)?, transport)
            .map_err(|errors| Error::internal(format!("access: {errors:?}")))?;
        Ok(Self {
            pep: Arc::new(pep),
            detailed_log: config.runtime.log_mode == crate::common::config::LogMode::Detailed,
            identities: Mutex::new(HashMap::new()),
        })
    }

    fn identity(&self, subject: &str) -> Option<PepIdentity> {
        self.identities.lock().ok()?.get(subject).cloned()
    }

    fn keep_identity(&self, identity: &PepIdentity) {
        if let Ok(mut identities) = self.identities.lock() {
            if identities.len() >= MAX_IDENTITIES && !identities.contains_key(identity.sub()) {
                identities.clear();
            }
            identities.insert(identity.sub().to_owned(), identity.clone());
        }
    }

    fn log_decision(&self, request_id: &str, subject: &str, ask: &Ask, kind: &str, usage: bool, answer: &Answer) {
        let resource = super::tree::Resource::parse(&ask.resource)
            .map(|resource| resource.logged_path(self.detailed_log))
            .unwrap_or_default();
        crate::log!(
            "access.decision request_id={} subject={} action={} resource={} match={kind} usage={usage} decision={} units={} retry_after={} reason={} source=pdp failed={}",
            log_token(request_id),
            super::quote(subject),
            log_token(&ask.action),
            super::quote(&resource),
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
}

/// The permission of the library for a question of Stowr.
fn permission_of(ask: &Ask) -> Option<Permission> {
    NodePath::parse(&ask.resource)
        .ok()
        .map(|node| Permission::new(ask.action.clone(), node))
}

/// Run a call of the library on a blocking thread. A call that panics gives the fallback.
async fn blocking<T: Send + 'static>(call: impl FnOnce() -> T + Send + 'static, fallback: impl FnOnce() -> T) -> T {
    tokio::task::spawn_blocking(call).await.unwrap_or_else(|_| fallback())
}

impl AccessGuard for PepGuard {
    fn authenticate(&self, headers: &HeaderMap) -> std::result::Result<Option<Identity>, String> {
        let pairs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.to_str().unwrap_or("\u{0}")))
            .collect();
        match self.pep.authenticate(pairs) {
            Ok(identity) => {
                self.keep_identity(&identity);
                Ok(Some(Identity {
                    subject: identity.sub().to_owned(),
                    owner: identity.owner().unwrap_or_default().to_owned(),
                }))
            }
            Err(Refusal::Unauthenticated(failure)) => Err(auth_reason(&failure)),
            Err(_) => Err("malformed".to_owned()),
        }
    }

    fn decide<'a>(
        &'a self,
        request_id: &'a str,
        subject: &'a str,
        asks: &'a [Ask],
        permission_only: bool,
    ) -> BoxFuture<'a, Vec<Answer>> {
        Box::pin(async move {
            let count = asks.len();
            let Some(identity) = self.identity(subject) else {
                return vec![Answer::failure(); count];
            };
            // The action access on the service: the question of a route that runs no action of the document.
            if let [ask] = asks
                && ask.action == ACTION_ACCESS
            {
                let pep = Arc::clone(&self.pep);
                let request = request_id.to_owned();
                let answer = blocking(
                    move || match pep.decide_route_without_action(&identity) {
                        Ok(()) => Answer::allow(),
                        Err(refusal) => refusal_answer(&refusal, &request),
                    },
                    Answer::failure,
                )
                .await;
                self.log_decision(request_id, subject, ask, "node", false, &answer);
                return vec![answer];
            }
            // The library asks one plain question for each permission. The mark permission_only and the batches
            // need a call of the library for a list of permissions.
            let _ = permission_only;
            let pep = Arc::clone(&self.pep);
            let owned: Vec<Ask> = asks.to_vec();
            let request = request_id.to_owned();
            let answers = blocking(
                move || {
                    owned
                        .iter()
                        .map(|ask| match permission_of(ask) {
                            Some(permission) => answer_of(
                                pep.check(&identity, &PepOperation::new(permission.action, permission.node)),
                                &request,
                            ),
                            None => Answer::failure(),
                        })
                        .collect::<Vec<_>>()
                },
                move || vec![Answer::failure(); count],
            )
            .await;
            for (ask, answer) in asks.iter().zip(&answers) {
                self.log_decision(request_id, subject, ask, "node", false, answer);
            }
            answers
        })
    }

    fn use_one<'a>(&'a self, request_id: &'a str, subject: &'a str, ask: &'a Ask) -> BoxFuture<'a, Answer> {
        Box::pin(async move {
            let (Some(identity), Some(permission)) = (self.identity(subject), permission_of(ask)) else {
                return Answer::failure();
            };
            let pep = Arc::clone(&self.pep);
            let request = request_id.to_owned();
            let answer = blocking(
                move || {
                    answer_of(
                        pep.decide(&identity, &PepOperation::new(permission.action, permission.node)),
                        &request,
                    )
                },
                Answer::failure,
            )
            .await;
            self.log_decision(request_id, subject, ask, "node", true, &answer);
            answer
        })
    }

    fn display<'a>(&'a self, request_id: &'a str, subject: &'a str, asks: &'a [Ask]) -> BoxFuture<'a, Vec<Answer>> {
        Box::pin(async move {
            let count = asks.len();
            let Some(identity) = self.identity(subject) else {
                return vec![Answer::failure(); count];
            };
            let Some(permissions) = asks.iter().map(permission_of).collect::<Option<Vec<_>>>() else {
                return vec![Answer::failure(); count];
            };
            let pep = Arc::clone(&self.pep);
            let request = request_id.to_owned();
            let answers = blocking(
                move || match pep.display(&identity, &permissions) {
                    Ok(decisions) => decisions
                        .into_iter()
                        .map(|decision| Answer {
                            decision,
                            ..Answer::default()
                        })
                        .collect(),
                    Err(refusal) => {
                        let _ = refusal_answer(&refusal, &request);
                        vec![Answer::failure(); count]
                    }
                },
                move || vec![Answer::failure(); count],
            )
            .await;
            for (ask, answer) in asks.iter().zip(&answers) {
                self.log_decision(request_id, subject, ask, "subtree", false, answer);
            }
            answers
        })
    }
}
