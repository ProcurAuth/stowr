// SPDX-License-Identifier: MIT OR Apache-2.0
//! The SQLite preview sessions and their routes (`/api/sqlite/sessions`).
//!
//! A session keeps the range reader of one object and its tables in memory. Its life ends after
//! `server.session_ttl_seconds` without a request, and at the latest after three times that value. The table keeps
//! four sessions at most: a new session takes the place of the session that has waited the longest. A sweep removes
//! the expired sessions each minute, and each read of a session checks its expiry too.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use super::query::{PageAnswer, TableQuery, query_table};
use super::schema::{TableDefinition, TableInfo, inspect_tables};
use super::{Database, DatabaseSource, null_when_empty};
use crate::common::app::App;
use crate::common::config::{PERMISSION_READ, RuntimePolicy};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{self, Req, Response};
use crate::common::misc::{CancelToken, clean_relative_key, hex, parse_bounded_int, random_bytes};
use crate::instance::range::RangeSource;
use crate::pv_docs::util::{lower, quote};

/// The largest SQLite object of a preview: 16 TiB.
pub(crate) const MAX_PREVIEW_BYTES: i64 = 16 << 40;
/// The number of sessions in memory.
pub(crate) const MAX_SESSIONS: usize = 4;
/// The longest life of a session, as a multiple of the idle life.
pub(crate) const MAX_AGE_TTLS: u32 = 3;
/// The interval of the sweep of the expired sessions.
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
/// The path of the creation route.
const SESSIONS_PATH: &str = "/api/sqlite/sessions";
/// The largest JSON body of a creation request: 1 MiB.
const MAX_REQUEST_BYTES: usize = 1 << 20;
/// The largest text of the `filters` parameter: 64 KiB.
const MAX_FILTERS_BYTES: usize = 64 << 10;
/// The largest text of one column filter.
const MAX_FILTER_BYTES: usize = 1024;

/// One preview session.
#[derive(Clone, Debug)]
pub(crate) struct Session {
    /// The random id.
    pub(crate) id: String,
    /// The id of the instance.
    pub(crate) instance: String,
    /// The relative key of the object.
    pub(crate) key: String,
    /// The size of the object.
    pub(crate) size: i64,
    /// The range reader of the object, shared by the requests of the session.
    pub(crate) source: Option<Arc<RangeSource>>,
    /// The warning of a database in WAL mode, or an empty text.
    pub(crate) warning: String,
    /// The visible tables.
    pub(crate) tables: Arc<Vec<TableInfo>>,
    /// The table definitions by name.
    pub(crate) definitions: Arc<BTreeMap<String, TableDefinition>>,
    /// The time of the creation.
    pub(crate) created_at: SystemTime,
    /// The time of the last request.
    pub(crate) last_access: SystemTime,
}

impl Session {
    /// A session with an id and the times of a test, without a source.
    #[cfg(test)]
    pub(crate) fn bare(id: &str, created_at: SystemTime, last_access: SystemTime) -> Self {
        Self {
            id: id.to_owned(),
            instance: String::new(),
            key: String::new(),
            size: 0,
            source: None,
            warning: String::new(),
            tables: Arc::new(Vec::new()),
            definitions: Arc::new(BTreeMap::new()),
            created_at,
            last_access,
        }
    }

    /// Clear the cache of the range reader.
    fn clear_cache(&self) {
        if let Some(source) = &self.source {
            source.clear_cache();
        }
    }
}

/// The answer that describes a session.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct SessionAnswer {
    /// The id.
    pub(crate) id: String,
    /// The id of the instance.
    pub(crate) instance: String,
    /// The key.
    pub(crate) key: String,
    /// The size of the object.
    pub(crate) size: i64,
    /// The visible tables, or `null` when there is none.
    #[serde(serialize_with = "null_when_empty")]
    pub(crate) tables: Vec<TableInfo>,
    /// The warning of a database in WAL mode.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) warning: String,
}

/// The request of a new session.
#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct SessionRequest {
    /// The id of the instance.
    #[serde(default)]
    pub(crate) instance: Option<String>,
    /// The key of the object.
    #[serde(default)]
    pub(crate) key: Option<String>,
    /// The size of the object from the listing.
    #[serde(default)]
    pub(crate) size: Option<i64>,
}

/// The filters and the sort of a table page.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct TableRequest {
    /// The filters by column name (no empty filter).
    pub(crate) filters: BTreeMap<String, String>,
    /// The sort column, or an empty text.
    pub(crate) sort_column: String,
    /// `asc`, `desc`, another text, or an empty text without a sort column.
    pub(crate) sort_direction: String,
}

#[derive(Debug, Default)]
struct Shared {
    sessions: Mutex<HashMap<String, Session>>,
    ttl_seconds: AtomicU64,
    sweep_started: AtomicBool,
    stop: CancelToken,
}

/// The SQLite preview sessions in memory (their life is `server.session_ttl_seconds`).
#[derive(Debug, Default)]
pub struct SqliteSessions {
    shared: Arc<Shared>,
}

/// The time that has passed from `then` to `now`, or zero when `then` is later.
fn elapsed(now: SystemTime, then: SystemTime) -> Duration {
    now.duration_since(then).unwrap_or(Duration::ZERO)
}

impl SqliteSessions {
    /// A table with no session.
    pub fn new() -> Self {
        Self::default()
    }

    /// Stop the cleanup of the expired sessions and remove each session.
    pub fn close(&self) {
        self.shared.stop.cancel();
        let removed: Vec<Session> = self.lock().drain().map(|(_, session)| session).collect();
        for session in removed {
            session.clear_cache();
        }
    }

    fn lock(&self) -> MutexGuard<'_, HashMap<String, Session>> {
        match self.shared.sessions.lock() {
            Ok(sessions) => sessions,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Set the idle life of the sessions (`server.session_ttl_seconds`).
    pub fn set_ttl(&self, ttl: Duration) {
        self.shared.ttl_seconds.store(ttl.as_secs(), Ordering::Relaxed);
    }

    /// The idle life of the sessions. A life of 0 gives the default (20 minutes).
    pub(crate) fn ttl(&self) -> Duration {
        match self.shared.ttl_seconds.load(Ordering::Relaxed) {
            0 => RuntimePolicy::default().session_ttl(),
            seconds => Duration::from_secs(seconds),
        }
    }

    /// True when a session is past its idle life or its longest life.
    fn expired(&self, session: &Session, now: SystemTime) -> bool {
        let ttl = self.ttl();
        elapsed(now, session.last_access) >= ttl || elapsed(now, session.created_at) >= ttl * MAX_AGE_TTLS
    }

    /// Remove the expired sessions.
    pub(crate) fn cleanup_expired(&self, now: SystemTime) {
        let removed: Vec<Session> = {
            let mut sessions = self.lock();
            let expired: Vec<String> = sessions
                .values()
                .filter(|session| self.expired(session, now))
                .map(|session| session.id.clone())
                .collect();
            expired.iter().filter_map(|id| sessions.remove(id)).collect()
        };
        for session in removed {
            session.clear_cache();
        }
    }

    /// The session with this id, when it is not expired. The read is a request: it moves the time of the last request.
    pub(crate) fn get(&self, id: &str) -> Option<Session> {
        let now = SystemTime::now();
        let mut sessions = self.lock();
        let expired = self.expired(sessions.get(id)?, now);
        if expired {
            let removed = sessions.remove(id);
            drop(sessions);
            if let Some(session) = removed {
                session.clear_cache();
            }
            return None;
        }
        let session = sessions.get_mut(id)?;
        session.last_access = now;
        Some(session.clone())
    }

    /// Keep a session. A full table removes the session that has waited the longest.
    pub(crate) fn register(&self, session: Session) -> Result<()> {
        if session.id.trim().is_empty() {
            return Err(Error::internal("SQLite preview session is invalid"));
        }
        let evicted = {
            let mut sessions = self.lock();
            let mut evicted = None;
            if !sessions.contains_key(&session.id) && sessions.len() >= MAX_SESSIONS {
                let oldest = sessions
                    .values()
                    .min_by_key(|candidate| candidate.last_access)
                    .map(|candidate| candidate.id.clone());
                if let Some(oldest) = oldest {
                    evicted = sessions.remove(&oldest);
                }
            }
            sessions.insert(session.id.clone(), session);
            evicted
        };
        if let Some(evicted) = evicted {
            evicted.clear_cache();
        }
        self.start_sweep();
        Ok(())
    }

    /// Remove a session; false when it does not exist.
    pub(crate) fn remove(&self, id: &str) -> bool {
        let removed = self.lock().remove(id);
        match removed {
            Some(session) => {
                session.clear_cache();
                true
            }
            None => false,
        }
    }

    /// The number of sessions in memory.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.lock().len()
    }

    /// True when the table has a session with this id, without a change of its time.
    #[cfg(test)]
    pub(crate) fn contains(&self, id: &str) -> bool {
        self.lock().contains_key(id)
    }

    /// Put a session in the table without the limit of the table (a test).
    #[cfg(test)]
    pub(crate) fn insert_raw(&self, session: Session) {
        self.lock().insert(session.id.clone(), session);
    }

    /// Start the sweep of the expired sessions one time, in the runtime of the caller.
    fn start_sweep(&self) {
        if self.shared.sweep_started.swap(true, Ordering::SeqCst) {
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            self.shared.sweep_started.store(false, Ordering::SeqCst);
            return;
        };
        let weak: Weak<Shared> = Arc::downgrade(&self.shared);
        let stop = self.shared.stop.clone();
        runtime.spawn(async move {
            let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + SWEEP_INTERVAL, SWEEP_INTERVAL);
            loop {
                tokio::select! {
                    () = stop.canceled() => return,
                    _ = ticker.tick() => {
                        let Some(shared) = weak.upgrade() else { return };
                        SqliteSessions { shared }.cleanup_expired(SystemTime::now());
                    }
                }
            }
        });
    }

    /// Open a session: check the request, ask `object.read` on the key, read the header and the schema, and keep
    /// the session.
    pub(crate) async fn create(&self, app: &App, ctx: &OpCtx, request: SessionRequest) -> Result<Session> {
        let instance_id = request.instance.unwrap_or_default();
        let Some(instance) = app
            .instances
            .iter()
            .find(|instance| instance.cfg.id == instance_id.trim())
            .cloned()
        else {
            return Err(Error::api(404, "unknown_instance", "unknown storage instance"));
        };
        instance.require_permission(PERMISSION_READ)?;
        let key = clean_relative_key(&request.key.unwrap_or_default());
        if key.is_empty() {
            return Err(Error::api(400, "invalid_key", "SQLite key cannot be empty"));
        }
        let requested_size = request.size.unwrap_or(0);
        if requested_size > MAX_PREVIEW_BYTES {
            return Err(Error::api(
                413,
                "sqlite_too_large",
                format!("SQLite previews are limited to {} GiB", MAX_PREVIEW_BYTES >> 30),
            ));
        }
        crate::access::authorize_read(app, ctx, &instance, &key).await?;
        let mut source = RangeSource::open(ctx, &instance, &key).await?;
        if requested_size > 0 {
            source.set_known_size(requested_size);
        }
        let header = source.read_prefix(100).await?;
        let size = source.size_or_zero();
        if size < 100 {
            return Err(Error::api(
                422,
                "invalid_sqlite",
                "the object is too small to be a SQLite 3 database",
            ));
        }
        if size > MAX_PREVIEW_BYTES {
            return Err(Error::api(
                413,
                "sqlite_too_large",
                "the SQLite object exceeds the remote preview safety limit",
            ));
        }
        let warning = if header.len() >= 20 && (header[18] == 2 || header[19] == 2) {
            "This database uses WAL journaling. The preview reads the main database object only and may not include uncheckpointed WAL changes.".to_owned()
        } else {
            String::new()
        };
        let database = Database::open(DatabaseSource::Remote(source.with_context(ctx)), size).await?;
        let (tables, definitions) = inspect_tables(ctx, &database).await?;
        let mut random = [0u8; 18];
        random_bytes(&mut random)?;
        let now = SystemTime::now();
        let session = Session {
            id: hex(&random),
            instance: instance.cfg.id.clone(),
            key,
            size,
            source: Some(Arc::new(source)),
            warning,
            tables: Arc::new(tables),
            definitions: Arc::new(definitions),
            created_at: now,
            last_access: now,
        };
        if let Err(error) = self.register(session.clone()) {
            session.clear_cache();
            return Err(error);
        }
        Ok(session)
    }

    /// The answer that describes a session.
    pub(crate) fn public(session: &Session) -> SessionAnswer {
        SessionAnswer {
            id: session.id.clone(),
            instance: session.instance.clone(),
            key: session.key.clone(),
            size: session.size,
            tables: session.tables.as_ref().clone(),
            warning: session.warning.clone(),
        }
    }

    /// One page of a table of a session.
    pub(crate) async fn table_page(
        ctx: &OpCtx,
        session: &Session,
        table: &str,
        query: &TableQuery<'_>,
    ) -> Result<PageAnswer> {
        let Some(definition) = session.definitions.get(table) else {
            return Err(Error::api(
                400,
                "unknown_sqlite_table",
                "the selected table does not exist in this preview session",
            ));
        };
        let Some(source) = &session.source else {
            return Err(Error::api(
                410,
                "sqlite_session_expired",
                "the SQLite preview source is no longer available",
            ));
        };
        let visible = |name: &str| definition.info.columns.iter().any(|column| column.name == name);
        for (column, filter) in query.filters {
            if !visible(column) {
                return Err(Error::api(
                    400,
                    "invalid_filter_column",
                    format!("unknown SQLite filter column {}", quote(column)),
                ));
            }
            if filter.len() > MAX_FILTER_BYTES {
                return Err(Error::api(
                    400,
                    "filter_too_long",
                    "SQLite column filters are limited to 1024 characters",
                ));
            }
        }
        if !query.sort_column.is_empty() {
            if !visible(query.sort_column) {
                return Err(Error::api(
                    400,
                    "invalid_sort_column",
                    "sortColumn must name a visible SQLite column",
                ));
            }
            if !matches!(query.sort_direction, "asc" | "desc") {
                return Err(Error::api(
                    400,
                    "invalid_sort_direction",
                    "sortDirection must be asc or desc",
                ));
            }
        }
        let database = Database::open(DatabaseSource::Remote(source.with_context(ctx)), session.size).await?;
        let mut answer = query_table(ctx, &database, definition, query).await?;
        answer.id = session.id.clone();
        Ok(answer)
    }
}

/// Read the filters and the sort of a table page: `filters` (a JSON object of texts, at most 64 KiB, the empty
/// filters removed), `sortColumn` and `sortDirection` (in lower case; empty without a sort column).
pub(crate) fn parse_table_request(query: &crate::common::query::Query) -> Result<TableRequest> {
    let mut request = TableRequest::default();
    let raw = query.get("filters").trim();
    if !raw.is_empty() {
        if raw.len() > MAX_FILTERS_BYTES {
            return Err(Error::api(400, "filters_too_large", "SQLite filters are too large"));
        }
        let filters: Option<BTreeMap<String, String>> = serde_json::from_str(raw).map_err(|_| {
            Error::api(
                400,
                "invalid_filters",
                "filters must be a JSON object keyed by SQLite column name",
            )
        })?;
        request.filters = filters.unwrap_or_default();
        request.filters.retain(|_, value| !value.trim().is_empty());
    }
    request.sort_column = query.get("sortColumn").trim().to_owned();
    request.sort_direction = lower(query.get("sortDirection").trim());
    if request.sort_column.is_empty() {
        request.sort_direction.clear();
    }
    Ok(request)
}

/// The answer of an unknown session.
fn unknown_session() -> Error {
    Error::api(404, "sqlite_session_not_found", "SQLite preview session was not found")
}

/// True for the refusal 403 of the PDP.
fn is_forbidden(error: &Error) -> bool {
    error
        .as_api()
        .is_some_and(|api| api.status == 403 && api.code == "forbidden")
}

/// Ask `object.read` again on the key of a session. The instance and the key come from the session. A refusal gives
/// the answer of an unknown session; a failure of the PDP keeps its status.
async fn authorize_session(app: &App, ctx: &OpCtx, session: &Session) -> Result<()> {
    if !app.config.access.enforced() {
        return Ok(());
    }
    let Some(instance) = app
        .instances
        .iter()
        .find(|instance| instance.cfg.id == session.instance)
    else {
        return Err(unknown_session());
    };
    let operation = crate::access::Operation {
        use_ask: crate::access::object_ask(app, crate::access::ACTION_READ, instance, &session.key),
        continuation: true,
        ..crate::access::Operation::default()
    };
    match crate::access::authorize(app, ctx, operation).await {
        Ok(_) => Ok(()),
        Err(error) if is_forbidden(&error) => Err(unknown_session()),
        Err(error) => Err(error),
    }
}

/// Read the JSON body of a creation request: the first JSON value of the first MiB. Unknown members and the bytes
/// after the value do not count.
async fn decode_request(body: http::Body) -> Result<SessionRequest> {
    let invalid_json = || Error::api(400, "invalid_json", "invalid SQLite preview request");
    let (bytes, _) = http::read_limited(body, MAX_REQUEST_BYTES)
        .await
        .map_err(|_| invalid_json())?;
    let mut deserializer = serde_json::Deserializer::from_slice(&bytes);
    let request: Option<SessionRequest> = Deserialize::deserialize(&mut deserializer).map_err(|_| invalid_json())?;
    Ok(request.unwrap_or_default())
}

/// The route `/api/sqlite/sessions` and its subtree.
pub(crate) async fn sessions_route(app: Arc<App>, req: Req) -> Response {
    app.sqlite.set_ttl(app.config.runtime.session_ttl());
    if req.path != SESSIONS_PATH {
        return session_resource(&app, req).await;
    }
    if req.method != ::http::Method::POST {
        return http::method_not_allowed(&["POST"]);
    }
    let Req { body, ctx, .. } = req;
    let request = match decode_request(body).await {
        Ok(request) => request,
        Err(error) => return http::api_error(&error),
    };
    match app.sqlite.create(&app, &ctx, request).await {
        Ok(session) => http::json(201, &SqliteSessions::public(&session)),
        Err(error) => http::api_error(&error),
    }
}

/// The routes of one session: `GET` (the description), `GET .../table` (a page) and `DELETE`.
async fn session_resource(app: &App, req: Req) -> Response {
    let path_value = req.path.strip_prefix("/api/sqlite/sessions/").unwrap_or(&req.path);
    let parts: Vec<&str> = path_value.trim_matches('/').split('/').collect();
    let Some(id) = parts.first().copied().filter(|id| !id.is_empty()) else {
        return http::api_error(&unknown_session());
    };
    if req.method == ::http::Method::DELETE && parts.len() == 1 {
        let Some(session) = app.sqlite.get(id) else {
            return http::api_error(&unknown_session());
        };
        if let Err(error) = authorize_session(app, &req.ctx, &session).await {
            return http::api_error(&error);
        }
        if !app.sqlite.remove(id) {
            return http::api_error(&unknown_session());
        }
        return http::no_content();
    }
    let Some(session) = app.sqlite.get(id) else {
        return http::api_error(&Error::api(
            404,
            "sqlite_session_not_found",
            "SQLite preview session was not found or expired",
        ));
    };
    if let Err(error) = authorize_session(app, &req.ctx, &session).await {
        return http::api_error(&error);
    }
    if req.method == ::http::Method::GET && parts.len() == 1 {
        return http::json(200, &SqliteSessions::public(&session));
    }
    if req.method == ::http::Method::GET && parts.len() == 2 && parts[1] == "table" {
        let page = parse_bounded_int(req.query.get("page"), 0, 0, 1 << 30);
        let page_size = parse_bounded_int(req.query.get("pageSize"), 100, 1, 1000);
        let exact_totals = req.query.get("count") == "1";
        let table_request = match parse_table_request(&req.query) {
            Ok(request) => request,
            Err(error) => return http::api_error(&error),
        };
        let query = TableQuery {
            page,
            page_size,
            search: req.query.get("q"),
            filters: &table_request.filters,
            sort_column: &table_request.sort_column,
            sort_direction: &table_request.sort_direction,
            exact_totals,
        };
        return match SqliteSessions::table_page(&req.ctx, &session, req.query.get("table"), &query).await {
            Ok(answer) if answer.has_unencodable_value() => unencodable_answer(),
            Ok(answer) => http::json(200, &answer),
            Err(error) => http::api_error(&error),
        };
    }
    http::method_not_allowed(&["GET", "DELETE"])
}

/// The answer of a page with a value that has no JSON form: the status 200, the JSON headers and an empty body.
fn unencodable_answer() -> Response {
    let mut response = http::json(200, &());
    *response.body_mut() = http::empty();
    response.headers_mut().remove(::http::header::CONTENT_LENGTH);
    response
}

/// The handler of `/api/sqlite/sessions` and `/api/sqlite/sessions/`.
pub fn handle_sqlite_sessions(app: Arc<App>, req: Req) -> crate::common::BoxFuture<'static, Response> {
    Box::pin(sessions_route(app, req))
}
