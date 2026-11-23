//! The access policy of ProcurAuth: the identity token, the questions to the PDP, the resource tree, the action
//! document, the options route, the budgets and the display rules (docs/ACCESS.md).
//!
//! Stowr keeps its own part: the routes and their actions, the resource tree (service, bucket, folder, subfolder),
//! the options route, the ceilings and the budget `writes`, the error envelope and the keys of the configuration.
//! The check of the token, the questions to the PDP and the kept answers use an [`AccessGuard`]. The
//! library `procurauth-pep` gives the guard of the mode `authzen`.
//!
//! The order of the checks of a route: the token (401), the instance (404), the shape of the request (400), the
//! process ceiling (403 `permission_denied`), then the PDP ([`authorize`]), then the effect.

pub mod actions;
pub mod display;
pub mod guard;
pub mod keys;
pub mod mutation;
pub mod options;
pub mod pdp_link;
pub mod pep_guard;
pub mod tree;

#[cfg(test)]
pub mod fake;

#[cfg(test)]
pub mod test_support;

#[cfg(test)]
mod authorize_tests;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use http::header::{CONNECTION, HeaderValue};
use http::{HeaderMap, Method};
use serde::Serialize;

use crate::common::app::App;
use crate::common::config::{Config, LogMode};
use crate::common::ctx::OpCtx;
use crate::common::error::{ApiError, Error, Result};
use crate::common::http::{Req, Response, Route, RouteAccess, api_error, route};
use crate::instance::Instance;
use crate::instance::ceiling::Ceilings;

pub use actions::ActionDocument;
pub use guard::{AccessGuard, Answer, Ask, Identity, OpenGuard, OperationAnswers};

/// The action `object.read`.
pub const ACTION_READ: &str = "object.read";
/// The action `object.write`.
pub const ACTION_WRITE: &str = "object.write";
/// The action `object.delete`.
pub const ACTION_DELETE: &str = "object.delete";
/// The action `object.lock`.
pub const ACTION_LOCK: &str = "object.lock";
/// The action `bucket.admin`.
pub const ACTION_BUCKET_ADMIN: &str = "bucket.admin";
/// The action that opens the service to a subject. The routes without data of a bucket ask it on the service node.
/// The action document never lists it.
pub const ACTION_ACCESS: &str = "access";
/// The action that the answer of a route without an access rule shows.
pub const ACTION_UNKNOWN: &str = "unknown";

/// The code of a request without a valid identity token.
pub const CODE_UNAUTHENTICATED: &str = "unauthenticated";
/// The code of a refusal of the PDP.
pub const CODE_FORBIDDEN: &str = "forbidden";
/// The code of a used budget.
pub const CODE_TOO_MANY_REQUESTS: &str = "too_many_requests";
/// The code of a PDP that gives no valid answer.
pub const CODE_PDP_UNAVAILABLE: &str = "pdp_unavailable";
/// The code of an action that needs an approval: no route of Stowr can wait for it.
pub const CODE_APPROVAL_CANNOT_WAIT: &str = "approval_cannot_wait";

/// The longest request id of the client that Stowr keeps.
const MAX_REQUEST_ID_BYTES: usize = 128;
/// The longest value that a log field shows as it is.
const MAX_LOG_TOKEN_BYTES: usize = 128;

/// The identity of a request that passed the check of the token.
#[derive(Debug, Default)]
pub struct AccessRequest {
    /// The subject: the `sub` of the token.
    pub subject: String,
    /// The `owner` of the token, for the log only.
    pub owner: String,
    /// The `iat` of the token.
    pub issued_at: u64,
    /// The `exp` of the token.
    pub expires_at: u64,
    /// The request id (`X-Request-ID` of the client when it is valid, else a random id).
    pub request_id: String,
    /// The ceilings of the true answers of the request.
    pub ceilings: Arc<Ceilings>,
    /// The subject and the request id for the request log.
    pub log: Mutex<Option<(String, String)>>,
}

impl AccessRequest {
    /// The identity of a request: the request log gets the subject and the request id.
    pub fn new(subject: &str, owner: &str, request_id: &str) -> Self {
        Self {
            subject: subject.to_owned(),
            owner: owner.to_owned(),
            request_id: request_id.to_owned(),
            ceilings: Arc::new(Ceilings::default()),
            log: Mutex::new(Some((subject.to_owned(), request_id.to_owned()))),
            ..Self::default()
        }
    }

    /// The identity of a request from the identity that the guard gave for its token.
    pub fn from_identity(identity: &Identity, request_id: &str) -> Self {
        Self {
            issued_at: identity.issued_at,
            expires_at: identity.expires_at,
            ..Self::new(&identity.subject, &identity.owner, request_id)
        }
    }

    /// The identity of the token of the request, for the questions of the guard.
    pub fn identity(&self) -> Identity {
        Identity {
            subject: self.subject.clone(),
            owner: self.owner.clone(),
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        }
    }
}

/// The permissions of one operation: the others first, without usage, then the use (docs/ACCESS.md, "The routes").
#[derive(Clone, Debug, Default)]
pub struct Operation {
    /// The other permissions.
    pub others: Vec<Ask>,
    /// The permission that the operation uses.
    pub use_ask: Ask,
    /// True for a continuation: the use never carries usage.
    pub continuation: bool,
}

/// The grant of an operation: the ceilings, by action and by name.
#[derive(Clone, Debug, Default)]
pub struct Grant {
    /// The ceilings.
    pub limits: BTreeMap<String, BTreeMap<String, i64>>,
}

/// The access layer of the application: the guard, the action document and the facts of the configuration that
/// the questions need.
pub struct AccessLayer {
    /// The guard of the mode of the configuration.
    pub guard: Arc<dyn AccessGuard>,
    /// The action document. It is empty in mode `open`.
    pub document: ActionDocument,
    enforced: bool,
    audience: String,
    log_mode: LogMode,
}

impl std::fmt::Debug for AccessLayer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessLayer")
            .field("enforced", &self.enforced)
            .field("audience", &self.audience)
            .finish_non_exhaustive()
    }
}

impl AccessLayer {
    /// Build the layer from the configuration: the open guard in mode `open`, the guard of the PEP in mode `authzen`.
    /// A configuration error (an action document above 64 KiB, a key or a link that the PEP refuses) stops the start.
    pub fn new(config: &Config) -> Result<Self> {
        if !config.access.enforced() {
            return Self::with_guard(config, Arc::new(OpenGuard));
        }
        let document = ActionDocument::build(config)?;
        let guard = pep_guard::PepGuard::new(config, &document)?;
        Self::with_guard(config, Arc::new(guard))
    }

    /// Build the layer with a guard that the caller gives. The layer gives the guard the configuration and the action
    /// document.
    pub fn with_guard(config: &Config, guard: Arc<dyn AccessGuard>) -> Result<Self> {
        let document = ActionDocument::build(config)?;
        guard.bind(config, &document)?;
        Ok(Self {
            guard,
            document,
            enforced: config.access.enforced(),
            audience: config.access.audience().to_owned(),
            log_mode: config.runtime.log_mode,
        })
    }

    /// True in mode `authzen`.
    pub fn enforced(&self) -> bool {
        self.enforced
    }

    /// The id of the service (`access.identity.audience`).
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// True with `server.log_mode = "detailed"`.
    pub fn detailed_log(&self) -> bool {
        self.log_mode == LogMode::Detailed
    }

    /// The permission of an action on the node of a key or of a prefix of an instance. `relative` is the exact
    /// relative key or prefix that the handler sends to the storage.
    pub fn object_ask(&self, action: &str, instance: &Instance, relative: &str) -> Ask {
        Ask {
            action: action.to_owned(),
            resource: tree::key_resource(&self.audience, &instance.cfg.id, relative).path(),
        }
    }

    /// The permission of an action on the bucket node of an instance.
    pub fn bucket_ask(&self, action: &str, instance: &Instance) -> Ask {
        Ask {
            action: action.to_owned(),
            resource: tree::bucket_resource(&self.audience, &instance.cfg.id).path(),
        }
    }

    /// The permission `access` on the service node.
    pub fn service_ask(&self) -> Ask {
        Ask {
            action: ACTION_ACCESS.to_owned(),
            resource: tree::service_resource(&self.audience).path(),
        }
    }

    /// Check the identity token of a request: the access middleware. It gives `Ok(None)` in mode `open` and for the
    /// two exempt paths. It never reads `Authorization`, a cookie or a query parameter. A refusal gives the answer
    /// 401 to send, with `Connection: close` for an unsafe method, and writes the line `access.unauthenticated`.
    pub fn check_token(
        &self,
        method: &Method,
        path: &str,
        headers: &HeaderMap,
    ) -> std::result::Result<Option<Arc<AccessRequest>>, Box<Response>> {
        if !self.enforced || is_exempt_path(path) {
            return Ok(None);
        }
        let request_id = request_id_from(headers);
        match self.guard.authenticate(headers) {
            Ok(Some(identity)) => Ok(Some(Arc::new(AccessRequest::from_identity(&identity, &request_id)))),
            refused => {
                let reason = match refused {
                    Err(reason) => reason,
                    Ok(_) => "missing".to_owned(),
                };
                crate::log!(
                    "access.unauthenticated request_id={} method={} path={} reason={}",
                    request_id,
                    method,
                    quote(&logged_request_path(self.log_mode, path)),
                    log_token(&reason)
                );
                let mut response = api_error(&unauthenticated());
                if !is_safe_method(method) {
                    response
                        .headers_mut()
                        .insert(CONNECTION, HeaderValue::from_static("close"));
                }
                Err(Box::new(response))
            }
        }
    }

    /// The access rule of a route, after the check of the token. A route without a rule answers `403 forbidden`
    /// with the action `unknown` and writes the line `access.no_rule`. A route of the kind `TokenOnly` asks the
    /// action `access` on the service node. The other kinds ask nothing here.
    pub async fn guard_route(
        &self,
        ctx: &OpCtx,
        kind: RouteAccess,
        method: &Method,
        path: &str,
        headers: &HeaderMap,
    ) -> Result<()> {
        match kind {
            RouteAccess::Denied => {
                let request_id = ctx
                    .access
                    .as_ref()
                    .map_or_else(|| request_id_from(headers), |request| request.request_id.clone());
                crate::log!(
                    "access.no_rule request_id={} method={} path={}",
                    request_id,
                    method,
                    quote(&logged_request_path(self.log_mode, path))
                );
                Err(forbidden(ACTION_UNKNOWN))
            }
            RouteAccess::TokenOnly => self.authorize_service(ctx).await,
            RouteAccess::Exempt | RouteAccess::HandlerAsks => Ok(()),
        }
    }

    /// Ask the action `access` on the service node, without usage (ProcurAuth 10.1c). The static files, the pages,
    /// `/api/build`, `OPTIONS /s3` and `/api/jobs` use it. The action never needs an approval: an answer with a reason
    /// of an approval is not valid. In mode `open` it asks nothing.
    pub async fn authorize_service(&self, ctx: &OpCtx) -> Result<()> {
        if !self.enforced {
            return Ok(());
        }
        let request = ctx.access.as_deref().ok_or_else(unauthenticated)?;
        let ask = self.service_ask();
        let who = request.identity();
        let answer = run_guarded(ctx, || self.guard.service(&request.request_id, &who), Answer::failure).await;
        self.check_answer(request, &ask, &answer, &mut Grant::default(), true)
    }

    /// Ask the PDP for the permissions of an operation and give the grant. In mode `open` it asks nothing.
    ///
    /// The guard asks the others first, in one batch, with `permission_only` and without usage. A refused other stops
    /// the operation before the question of the use. When the action of the use lists a budget, the use is one
    /// question with usage. Else the use is one question without usage. A continuation never asks usage.
    pub async fn authorize(&self, ctx: &OpCtx, operation: Operation) -> Result<Grant> {
        if !self.enforced {
            return Ok(Grant::default());
        }
        let request = ctx.access.as_deref().ok_or_else(unauthenticated)?;
        for ask in operation.others.iter().chain(std::iter::once(&operation.use_ask)) {
            if !self.document.published(&ask.action) {
                return Err(forbidden(&ask.action));
            }
        }
        // Remove each repeated other, and each other that equals the use: the same question without usage must
        // never come before the question with usage (ProcurAuth 10.1).
        let mut seen = BTreeSet::from([&operation.use_ask]);
        let others: Vec<Ask> = operation
            .others
            .iter()
            .filter(|ask| seen.insert(*ask))
            .cloned()
            .collect();

        let mut grant = Grant::default();
        let use_ask = &operation.use_ask;
        let usage = !operation.continuation && self.document.lists_budget(&use_ask.action);
        let who = request.identity();
        let count = others.len();
        let answers = run_guarded(
            ctx,
            || self.guard.operation(&request.request_id, &who, &others, use_ask, usage),
            || OperationAnswers::failure(count),
        )
        .await;
        for (index, ask) in others.iter().enumerate() {
            let answer = answers.others.get(index).cloned().unwrap_or_else(Answer::failure);
            self.check_answer(request, ask, &answer, &mut grant, true)?;
        }
        let mut answer = answers.use_answer.unwrap_or_else(Answer::failure);
        if usage && answer.decision && !answer.failed && answer.units.is_none() {
            // A true answer to a usage question without context.usage.units is false (ProcurAuth 6.12).
            answer = Answer::default();
        }
        self.check_answer(request, use_ask, &answer, &mut grant, false)?;
        Ok(grant)
    }

    /// Ask `object.read` on the node of a key or of a prefix.
    pub async fn authorize_read(&self, ctx: &OpCtx, instance: &Instance, relative: &str) -> Result<Grant> {
        self.authorize(
            ctx,
            Operation {
                use_ask: self.object_ask(ACTION_READ, instance, relative),
                ..Operation::default()
            },
        )
        .await
    }

    /// Ask `object.read` on the bucket node.
    pub async fn authorize_read_bucket(&self, ctx: &OpCtx, instance: &Instance) -> Result<Grant> {
        self.authorize(
            ctx,
            Operation {
                use_ask: self.bucket_ask(ACTION_READ, instance),
                ..Operation::default()
            },
        )
        .await
    }

    /// Ask `object.read` for each key. The first key is the use; the other keys are the others.
    pub async fn authorize_read_many(&self, ctx: &OpCtx, instance: &Instance, keys: &[String]) -> Result<Grant> {
        let Some((first, rest)) = keys.split_first() else {
            return self.authorize_read(ctx, instance, "").await;
        };
        self.authorize(
            ctx,
            Operation {
                others: rest
                    .iter()
                    .map(|key| self.object_ask(ACTION_READ, instance, key))
                    .collect(),
                use_ask: self.object_ask(ACTION_READ, instance, first),
                continuation: false,
            },
        )
        .await
    }

    /// Read one answer. It gives `Ok` for a true answer with valid limits, and adds the ceilings to the grant and to
    /// the request. `approval_invalid` is true for a question that never needs an approval: an other permission of an
    /// operation (ProcurAuth 5.5a) and the action `access` (ProcurAuth 10.1c).
    fn check_answer(
        &self,
        request: &AccessRequest,
        ask: &Ask,
        answer: &Answer,
        grant: &mut Grant,
        approval_invalid: bool,
    ) -> Result<()> {
        let action = ask.action.as_str();
        if answer.failed {
            return Err(pdp_unavailable(action));
        }
        if !answer.decision {
            if guard::is_approval_reason(&answer.reason) {
                if approval_invalid {
                    // This question never needs an approval: the answer is not valid.
                    crate::log!(
                        "access.pdp_invalid_answer request_id={} action={} reason={}",
                        log_token(&request.request_id),
                        action,
                        log_token(&answer.reason)
                    );
                    return Err(pdp_unavailable(action));
                }
                return Err(approval_cannot_wait());
            }
            if answer.reason == guard::REASON_BUDGET && answer.retry_after >= 1 {
                return Err(too_many_requests(action, answer.retry_after));
            }
            return Err(forbidden(action));
        }
        for (name, value) in &answer.limits {
            if self.document.lists_ceiling(action, name) {
                let kept = grant
                    .limits
                    .entry(action.to_owned())
                    .or_default()
                    .entry(name.clone())
                    .or_insert(*value);
                if value < kept {
                    *kept = *value;
                }
                // The request keeps the ceiling. The storage layer applies it.
                request.ceilings.lower(action, name, *value);
            } else if self.document.is_budget(name) {
                // A budget never comes as a limit of an answer (ProcurAuth 7.3).
                crate::log!(
                    "access.pdp_invalid_answer request_id={} action={} limit={}",
                    log_token(&request.request_id),
                    action,
                    quote(name)
                );
                return Err(pdp_unavailable(action));
            } else {
                crate::log!(
                    "access.ceiling_unenforceable request_id={} action={} ceiling={}",
                    log_token(&request.request_id),
                    action,
                    quote(name)
                );
                return Err(forbidden(action));
            }
        }
        Ok(())
    }
}

/// Run a call of the guard until it ends, or until the request is canceled or its deadline is past. A request that
/// is already canceled asks nothing. A stopped call gives the fallback: failed answers.
async fn run_guarded<'a, T>(
    ctx: &OpCtx,
    call: impl FnOnce() -> crate::common::BoxFuture<'a, T>,
    fallback: impl FnOnce() -> T,
) -> T {
    if ctx.check().is_err() {
        return fallback();
    }
    match ctx.run(async { Ok(call().await) }).await {
        Ok(value) => value,
        Err(_) => fallback(),
    }
}

/// Ask the PDP for the permissions of an operation. In mode `open`, it asks nothing.
pub async fn authorize(app: &App, ctx: &OpCtx, operation: Operation) -> Result<Grant> {
    app.access.authorize(ctx, operation).await
}

/// The permission of an action on the node of a key or of a prefix of an instance.
pub fn object_ask(app: &App, action: &str, instance: &Instance, relative: &str) -> Ask {
    app.access.object_ask(action, instance, relative)
}

/// The permission of an action on the bucket node of an instance.
pub fn bucket_ask(app: &App, action: &str, instance: &Instance) -> Ask {
    app.access.bucket_ask(action, instance)
}

/// Ask `object.read` on the node of a key or of a prefix.
pub async fn authorize_read(app: &App, ctx: &OpCtx, instance: &Instance, relative: &str) -> Result<Grant> {
    app.access.authorize_read(ctx, instance, relative).await
}

/// Ask `object.read` on the bucket node.
pub async fn authorize_read_bucket(app: &App, ctx: &OpCtx, instance: &Instance) -> Result<Grant> {
    app.access.authorize_read_bucket(ctx, instance).await
}

/// Ask `object.read` for each key: the first key is the use, the other keys are the others.
pub async fn authorize_read_many(app: &App, ctx: &OpCtx, instance: &Instance, keys: &[String]) -> Result<Grant> {
    app.access.authorize_read_many(ctx, instance, keys).await
}

/// Ask the use of an action on the node of a key (with usage when the action lists the budget `writes`).
pub async fn authorize_use(app: &App, ctx: &OpCtx, action: &str, instance: &Instance, relative: &str) -> Result<Grant> {
    app.access
        .authorize(ctx, app.access.use_operation(action, instance, relative))
        .await
}

/// Ask the action `access` on the service node (the routes without data of a bucket).
pub async fn authorize_service(app: &App, ctx: &OpCtx) -> Result<()> {
    app.access.authorize_service(ctx).await
}

/// The `401 unauthenticated` answer.
pub fn unauthenticated() -> Error {
    Error::api(401, CODE_UNAUTHENTICATED, "A valid identity token is required.")
}

fn access_error(status: u16, code: &str, message: String, action: &str, retry_after: u64) -> Error {
    Error::Api(Box::new(ApiError {
        status,
        code: code.to_owned(),
        message,
        action: Some(action.to_owned()),
        retry_after,
        ceiling: None,
    }))
}

/// The `403 forbidden` answer of an action. The answer never shows the reason of the PDP.
pub fn forbidden(action: &str) -> Error {
    access_error(
        403,
        CODE_FORBIDDEN,
        format!("The action {action} is not allowed."),
        action,
        0,
    )
}

/// The `429 too_many_requests` answer of an action that has used its budget.
pub fn too_many_requests(action: &str, retry_after: u64) -> Error {
    access_error(
        429,
        CODE_TOO_MANY_REQUESTS,
        format!("The budget of the action {action} is used."),
        action,
        retry_after,
    )
}

/// The `503 pdp_unavailable` answer when the PDP gives no valid decision.
pub fn pdp_unavailable(action: &str) -> Error {
    access_error(
        503,
        CODE_PDP_UNAVAILABLE,
        format!("The decision for the action {action} is not available."),
        action,
        0,
    )
}

/// The `403 approval_cannot_wait` answer of an action that needs the approval of the owner. Its body is exactly
/// `{"error":"approval_cannot_wait"}`.
pub fn approval_cannot_wait() -> Error {
    Error::api(
        403,
        CODE_APPROVAL_CANNOT_WAIT,
        "The action needs an approval, and this request cannot wait for it.",
    )
}

/// True for the two paths that need no identity token: `/healthz` and the action document.
pub fn is_exempt_path(path: &str) -> bool {
    path == "/healthz" || path == actions::ACTIONS_PATH
}

/// True for `GET`, `HEAD` and `OPTIONS`.
fn is_safe_method(method: &Method) -> bool {
    *method == Method::GET || *method == Method::HEAD || *method == Method::OPTIONS
}

/// The request id: a valid `X-Request-ID` of the client (1 to 128 characters of `A-Z`, `a-z`, `0-9`, `.`, `_`,
/// `:` and `-`), else a random id of 32 hexadecimal digits.
pub fn request_id_from(headers: &HeaderMap) -> String {
    let value = headers
        .get("x-request-id")
        .map(HeaderValue::as_bytes)
        .unwrap_or_default();
    let valid = !value.is_empty()
        && value.len() <= MAX_REQUEST_ID_BYTES
        && value
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'));
    if valid {
        return String::from_utf8_lossy(value).into_owned();
    }
    crate::common::misc::random_hex16().unwrap_or_else(|_| "unknown".to_owned())
}

/// The path of a request for the log. The mode `anonymous` keeps the ids of the jobs, the uploads and the sessions,
/// and the object keys of the pages, out of the log.
pub fn logged_request_path(mode: LogMode, path: &str) -> String {
    if mode == LogMode::Detailed {
        return path.to_owned();
    }
    for (prefix, shown) in [
        ("/api/jobs/", "/api/jobs/<id>"),
        ("/api/uploads/", "/api/uploads/<id>"),
        ("/api/sqlite/sessions/", "/api/sqlite/sessions/<id>"),
        ("/-/", "/-/<path>"),
    ] {
        if path.starts_with(prefix) {
            return shown.to_owned();
        }
    }
    path.to_owned()
}

/// A value for a log line: `-` when empty, the value when it is a short token, else a quoted text. A value of the
/// PDP or of a header then cannot add a field or a line to the log.
pub fn log_token(value: &str) -> String {
    if value.is_empty() {
        return "-".to_owned();
    }
    let safe = value.len() <= MAX_LOG_TOKEN_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b':'));
    if safe { value.to_owned() } else { quote(value) }
}

/// A text in double quotes for a log line: `"` and `\` get a `\`, a control character gets its escape.
pub fn quote(value: &str) -> String {
    crate::config::quote::quote(value)
}

/// The JSON formatter of the access routes: the form of the answers without the escape of `<`, `>` and `&`.
struct PlainFormatter;

impl serde_json::ser::Formatter for PlainFormatter {
    fn write_string_fragment<W: ?Sized + std::io::Write>(
        &mut self,
        writer: &mut W,
        fragment: &str,
    ) -> std::io::Result<()> {
        let mut start = 0;
        for (index, character) in fragment.char_indices() {
            if matches!(character, '\u{2028}' | '\u{2029}') {
                writer.write_all(&fragment.as_bytes()[start..index])?;
                write!(writer, "\\u{:04x}", character as u32)?;
                start = index + character.len_utf8();
            }
        }
        writer.write_all(&fragment.as_bytes()[start..])
    }

    fn write_char_escape<W: ?Sized + std::io::Write>(
        &mut self,
        writer: &mut W,
        escape: serde_json::ser::CharEscape,
    ) -> std::io::Result<()> {
        use serde_json::ser::CharEscape;
        match escape {
            CharEscape::Quote => writer.write_all(b"\\\""),
            CharEscape::ReverseSolidus => writer.write_all(b"\\\\"),
            CharEscape::LineFeed => writer.write_all(b"\\n"),
            CharEscape::CarriageReturn => writer.write_all(b"\\r"),
            CharEscape::Tab => writer.write_all(b"\\t"),
            CharEscape::Backspace => writer.write_all(b"\\u0008"),
            CharEscape::FormFeed => writer.write_all(b"\\u000c"),
            CharEscape::AsciiControl(byte) => write!(writer, "\\u{byte:04x}"),
            _ => Ok(()),
        }
    }
}

/// The JSON bytes of a value of an access route, without a line end. The characters `<`, `>` and `&` stay as
/// they are.
pub fn plain_json<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(1024);
    let mut serializer = serde_json::Serializer::with_formatter(&mut out, PlainFormatter);
    value
        .serialize(&mut serializer)
        .map_err(|error| Error::internal(format!("encode JSON: {error}")))?;
    Ok(out)
}

/// Read the text of `access.identity.public_keys` (PEM or a JWK Set) and give the short name of each key for
/// print-config (`Ed25519 kid=...`, `P-256 kid=...`).
pub fn parse_public_keys(text: &str) -> Result<Vec<String>> {
    keys::parse(text)
        .map(|keys| keys.iter().map(keys::PublicKey::display).collect())
        .map_err(Error::internal)
}

/// The action document: `GET` and `HEAD /.well-known/procurauth/actions`. It needs no token.
pub fn handle_actions(app: Arc<App>, req: Req) -> crate::common::BoxFuture<'static, Response> {
    Box::pin(async move { app.access.document.response(app.access.enforced(), &req.method) })
}

/// The options route: `GET` and `HEAD /.well-known/procurauth/resources`.
pub fn handle_options(app: Arc<App>, req: Req) -> crate::common::BoxFuture<'static, Response> {
    Box::pin(async move { options::serve(&app.access, &app.instances, &req.method, &req.raw_query, &req.ctx).await })
}

/// The routes of this module.
pub fn routes() -> Vec<Route> {
    vec![
        route(actions::ACTIONS_PATH, RouteAccess::Exempt, handle_actions),
        route(options::OPTIONS_PATH, RouteAccess::HandlerAsks, handle_options),
    ]
}
