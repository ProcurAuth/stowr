//! Object Lock: the retention and the legal hold of one version of an object (`GET` and `PUT /api/object-lock`).
//!
//! A bucket has Object Lock only when its owner made it with it. Such a bucket always keeps versions. The start
//! probe reads the configuration of the bucket. The function shows only when the answer says `Enabled`. A bucket
//! without a configuration, a provider that answers 501 or 405 (Garage), and any other failure hide it.
//!
//! The read gives the mode and the date of the retention, the legal hold, and the default retention of the bucket.
//! A change names the version. The server reads the lock of the version first and applies these rules:
//!
//! - A version without an active retention gets any mode and any date in the future.
//! - An active Governance retention gets a later date in the same mode. Any other change needs the bypass of the
//!   Governance retention, and the request must ask for it.
//! - An active Compliance retention gets only a later date in the same mode. Nobody can shorten it or remove it.
//! - The legal hold goes on and off with no rule.
//!
//! A delete that the lock refuses gets a clear error (`object_locked`). The providers refuse with different answers:
//! SeaweedFS answers 403 `AccessDenied`, and MinIO answers 400 `InvalidRequest`. Thus the server does not trust the
//! status alone. After such a refusal it reads the lock of the version, and only an active lock makes the error
//! `object_locked`. Only the S3 back end has Object Lock. The GCS back end answers 501.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use http::Method;
use http::header::{CONTENT_TYPE, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};

use super::support::{
    MAX_ANSWER_BYTES, S3_NAMESPACE, S3Call, begin_request, decode_document, embedded_error, is_success, md5, observe_permission,
    printable_ascii, provider_refused_feature, quote, upstream_status_text, xml_integer,
};
use super::{ObjectLockConfiguration, ObjectLockDefaultJson, ObjectLockManager, Retention};
use crate::access;
use crate::common::app::App;
use crate::common::BoxFuture;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Req, Response, api_error, decode_json, json, method_not_allowed};
use crate::common::misc::clean_relative_key;
use crate::common::time::Timestamp;
use crate::instance::Instance;
use crate::provider::S3Backend;
use crate::provider::s3::S3Request;

/// The mode `GOVERNANCE`.
pub const GOVERNANCE: &str = "GOVERNANCE";
/// The mode `COMPLIANCE`.
pub const COMPLIANCE: &str = "COMPLIANCE";

/// The latest retain-until date that the server sets, in days from now.
pub const MAX_OBJECT_LOCK_DAYS: i64 = 36500;
/// The limit of the version id of a request.
pub const MAX_OBJECT_LOCK_VERSION_BYTES: usize = 1024;
/// The limit of the text of a retain-until date.
const MAX_OBJECT_LOCK_DATE_CHARS: usize = 64;
/// The number of locked keys that a job keeps to show them.
pub const MAX_LOCKED_KEYS: usize = 20;
/// The largest number of refused keys of one batch delete for which the server reads the lock.
pub const MAX_LOCK_CHECKS: usize = 100;
/// The time that the start probe waits for the provider.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// The S3 error codes that mean "no configuration" or "no lock on this version". SeaweedFS answers
/// `ObjectLockConfigurationNotFoundError` (404) for a version without a retention and `NoSuchObjectLegalHold` (404)
/// without a legal hold. MinIO answers `NoSuchObjectLockConfiguration` (400) for both. AWS S3 answers
/// `NoSuchObjectLockConfiguration` (404).
const NO_OBJECT_LOCK_CODES: [&str; 3] = [
    "ObjectLockConfigurationNotFoundError",
    "NoSuchObjectLockConfiguration",
    "NoSuchObjectLegalHold",
];

impl Retention {
    /// True when the retain-until date is after `now`.
    pub fn active(&self, now: Timestamp) -> bool {
        self.retain_until.is_some_and(|until| until > now)
    }
}

/// True for a retention that exists and is active.
pub fn retention_active(retention: Option<&Retention>, now: Timestamp) -> bool {
    retention.is_some_and(|value| value.active(now))
}

/// The lock of one version. `retention` is `None` for a version without a retention.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObjectLockState {
    /// The retention.
    pub retention: Option<Retention>,
    /// The legal hold.
    pub legal_hold: bool,
}

impl ObjectLockState {
    /// True for a legal hold or an active retention.
    pub fn locked(&self, now: Timestamp) -> bool {
        self.legal_hold || retention_active(self.retention.as_ref(), now)
    }
}

/// A checked change of the lock of one version. A `None` part does not change.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObjectLockChange {
    /// The new retention.
    pub retention: Option<Retention>,
    /// The new legal hold.
    pub legal_hold: Option<bool>,
    /// True when the request asks for the bypass of the Governance retention.
    pub bypass_governance: bool,
}

fn object_lock_unsupported() -> Error {
    Error::api(501, "object_lock_unsupported", "this storage bucket has no Object Lock")
}

fn invalid_object_lock(message: impl Into<String>) -> Error {
    Error::api(400, "invalid_object_lock", message)
}

/// A date in the form of the messages, such as `2026-10-21 07:28:00 UTC`.
pub fn lock_date(value: Timestamp) -> String {
    let text = value.utc().rfc3339();
    format!("{} UTC", text.trim_end_matches('Z').replace('T', " "))
}

/// The name of a mode for a person.
pub fn mode_name(mode: &str) -> &str {
    match mode {
        GOVERNANCE => "Governance",
        COMPLIANCE => "Compliance",
        other => other,
    }
}

/// True for an answer that says "no lock".
fn no_object_lock(error: &Error) -> bool {
    error
        .as_upstream()
        .is_some_and(|upstream| NO_OBJECT_LOCK_CODES.contains(&upstream.code.as_str()))
}

fn version_query(name: &str, version: &str) -> Vec<(String, String)> {
    let mut query = vec![(name.to_owned(), String::new())];
    if !version.is_empty() {
        query.push(("versionId".to_owned(), version.to_owned()));
    }
    query
}

// --- The S3 requests ----------------------------------------------------------------------------------------------

async fn get_lock_document(
    s3: &dyn S3Call,
    ctx: &OpCtx,
    key: &str,
    query: Vec<(String, String)>,
    what: &str,
) -> Result<Option<super::support::XmlNode>> {
    let request = S3Request {
        method: Method::GET,
        key,
        query,
        headers: http::HeaderMap::new(),
        body: None,
    };
    let answer = s3.call(ctx, request, MAX_ANSWER_BYTES).await?;
    if !is_success(answer.status) {
        return Err(s3.provider_error(&answer));
    }
    decode_document(&answer.body, what)
}

/// Send a `PUT` with an XML body. S3 needs `Content-MD5` for these requests.
async fn put_lock_document(
    s3: &dyn S3Call,
    ctx: &OpCtx,
    key: &str,
    query: Vec<(String, String)>,
    body: String,
    mut headers: http::HeaderMap,
) -> Result<()> {
    use base64::Engine as _;
    let digest = base64::engine::general_purpose::STANDARD.encode(md5(body.as_bytes()));
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/xml"));
    if let Ok(value) = HeaderValue::from_str(&digest) {
        headers.insert(HeaderName::from_static("content-md5"), value);
    }
    let size = i64::try_from(body.len()).unwrap_or(i64::MAX);
    let request = S3Request {
        method: Method::PUT,
        key,
        query,
        headers,
        body: Some((crate::common::http::full(body), size)),
    };
    let answer = s3.call(ctx, request, MAX_ANSWER_BYTES).await?;
    if !is_success(answer.status) {
        return Err(s3.provider_error(&answer));
    }
    match embedded_error(&answer.body) {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Read `GetObjectLockConfiguration`. A bucket without a configuration gives a configuration that is not enabled.
pub async fn read_configuration(s3: &dyn S3Call, ctx: &OpCtx) -> Result<ObjectLockConfiguration> {
    let document = match get_lock_document(s3, ctx, "", version_query("object-lock", ""), "object lock").await {
        Ok(document) => document,
        Err(error) if no_object_lock(&error) => return Ok(ObjectLockConfiguration::default()),
        Err(error) => return Err(error),
    };
    let Some(root) = document else {
        return Ok(ObjectLockConfiguration::default());
    };
    let mut configuration = ObjectLockConfiguration {
        enabled: root.text_at(&["ObjectLockEnabled"]).trim() == "Enabled",
        ..ObjectLockConfiguration::default()
    };
    if let Some(rule) = root.child("Rule") {
        let mode = rule.text_at(&["DefaultRetention", "Mode"]).trim().to_uppercase();
        let days = xml_integer(rule.text_at(&["DefaultRetention", "Days"]), "object lock")?;
        let years = xml_integer(rule.text_at(&["DefaultRetention", "Years"]), "object lock")?;
        if !mode.is_empty() {
            configuration.default_mode = mode;
            configuration.default_days = u32::try_from(days)
                .map_err(|_| Error::internal("decode s3 object lock response: the days are out of range"))?;
            configuration.default_years = u32::try_from(years)
                .map_err(|_| Error::internal("decode s3 object lock response: the years are out of range"))?;
        }
    }
    Ok(configuration)
}

/// Read `GetObjectRetention`. A version without a retention gives `None`.
pub async fn read_retention(s3: &dyn S3Call, ctx: &OpCtx, key: &str, version: &str) -> Result<Option<Retention>> {
    let document = match get_lock_document(s3, ctx, key, version_query("retention", version), "object lock").await {
        Ok(document) => document,
        Err(error) if no_object_lock(&error) => return Ok(None),
        Err(error) => return Err(error),
    };
    let Some(root) = document else {
        return Ok(None);
    };
    let mode = root.text_at(&["Mode"]).trim().to_uppercase();
    let date = root.text_at(&["RetainUntilDate"]).trim().to_owned();
    if mode.is_empty() && date.is_empty() {
        return Ok(None);
    }
    let until = Timestamp::parse_rfc3339(&date)
        .ok_or_else(|| Error::internal(format!("decode s3 retain-until date {}: not an RFC 3339 date", quote(&date))))?;
    Ok(Some(Retention {
        mode,
        retain_until: Some(until.utc()),
    }))
}

/// Read `GetObjectLegalHold`. A version without a legal hold gives false.
pub async fn read_legal_hold(s3: &dyn S3Call, ctx: &OpCtx, key: &str, version: &str) -> Result<bool> {
    let document = match get_lock_document(s3, ctx, key, version_query("legal-hold", version), "object lock").await {
        Ok(document) => document,
        Err(error) if no_object_lock(&error) => return Ok(false),
        Err(error) => return Err(error),
    };
    Ok(document.is_some_and(|root| root.text_at(&["Status"]).trim().eq_ignore_ascii_case("ON")))
}

/// Send `PutObjectRetention`. `bypass_governance` adds `x-amz-bypass-governance-retention: true`.
pub async fn write_retention(
    s3: &dyn S3Call,
    ctx: &OpCtx,
    key: &str,
    version: &str,
    retention: &Retention,
    bypass_governance: bool,
) -> Result<()> {
    let until = retention.retain_until.map(|value| value.utc().rfc3339()).unwrap_or_default();
    let body = format!(
        "<Retention xmlns=\"{S3_NAMESPACE}\"><Mode>{}</Mode><RetainUntilDate>{until}</RetainUntilDate></Retention>",
        retention.mode
    );
    let mut headers = http::HeaderMap::new();
    if bypass_governance {
        headers.insert(
            HeaderName::from_static("x-amz-bypass-governance-retention"),
            HeaderValue::from_static("true"),
        );
    }
    put_lock_document(s3, ctx, key, version_query("retention", version), body, headers).await
}

/// Send `PutObjectLegalHold` with the status `ON` or `OFF`.
pub async fn write_legal_hold(s3: &dyn S3Call, ctx: &OpCtx, key: &str, version: &str, on: bool) -> Result<()> {
    let status = if on { "ON" } else { "OFF" };
    let body = format!("<LegalHold xmlns=\"{S3_NAMESPACE}\"><Status>{status}</Status></LegalHold>");
    put_lock_document(
        s3,
        ctx,
        key,
        version_query("legal-hold", version),
        body,
        http::HeaderMap::new(),
    )
    .await
}

impl ObjectLockManager for S3Backend {
    fn configuration<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<ObjectLockConfiguration>> {
        Box::pin(async move { read_configuration(self, ctx).await })
    }

    fn retention<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        version: &'a str,
    ) -> BoxFuture<'a, Result<Option<Retention>>> {
        Box::pin(async move { read_retention(self, ctx, key, version).await })
    }

    fn legal_hold<'a>(&'a self, ctx: &'a OpCtx, key: &'a str, version: &'a str) -> BoxFuture<'a, Result<bool>> {
        Box::pin(async move { read_legal_hold(self, ctx, key, version).await })
    }

    fn put_retention<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        version: &'a str,
        retention: &'a Retention,
        bypass_governance: bool,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { write_retention(self, ctx, key, version, retention, bypass_governance).await })
    }

    fn put_legal_hold<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        version: &'a str,
        on: bool,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { write_legal_hold(self, ctx, key, version, on).await })
    }
}

// --- The rules ----------------------------------------------------------------------------------------------------

/// True for a refusal that a lock can give: the codes `AccessDenied` (SeaweedFS, AWS S3) and `InvalidRequest`
/// (MinIO), or a message that names the lock. The lock of the version decides.
fn lock_refusal_candidate(error: &Error) -> bool {
    let Some(upstream) = error.as_upstream() else {
        return false;
    };
    if matches!(upstream.code.as_str(), "AccessDenied" | "InvalidRequest" | "ObjectLocked") {
        return true;
    }
    let message = upstream.message.to_lowercase();
    message.contains("worm") || message.contains("object lock")
}

/// True for the error of a delete that the lock refused.
pub fn is_object_locked(error: &Error) -> bool {
    error.has_code("object_locked")
}

/// The error that tells which lock keeps the version, and what the person can do.
pub fn object_locked_error(key: &str, version: &str, state: &ObjectLockState, now: Timestamp) -> Error {
    let what = if version.is_empty() {
        quote(key)
    } else {
        format!("the version {version} of {}", quote(key))
    };
    let mut reasons: Vec<String> = Vec::new();
    let mut actions: Vec<String> = Vec::new();
    if state.legal_hold {
        reasons.push("a legal hold is on".to_owned());
        actions.push("remove the legal hold in the details of the file".to_owned());
    }
    if let Some(retention) = state.retention.as_ref().filter(|value| value.active(now)) {
        let until = retention.retain_until.map(lock_date).unwrap_or_default();
        reasons.push(format!("a {} retention keeps it until {until}", mode_name(&retention.mode)));
        if retention.mode == COMPLIANCE {
            actions.push("wait for the end of the Compliance retention (nobody can remove it before this date)".to_owned());
        } else {
            actions.push(
                "wait for the end of the Governance retention, or shorten it with the bypass in the details of the file"
                    .to_owned(),
            );
        }
    }
    Error::api(
        409,
        "object_locked",
        format!(
            "Object Lock keeps {what}: {}. To delete it, {}.",
            reasons.join(" and "),
            actions.join(", and ")
        ),
    )
}

/// Decide how a new retention applies to the current one. It gives true when the change needs the bypass of the
/// Governance retention, and an error for a change that no request can make.
pub fn retention_change(current: Option<&Retention>, next: &Retention, now: Timestamp) -> Result<bool> {
    let Some(current) = current.filter(|value| value.active(now)) else {
        return Ok(false);
    };
    // SeaweedFS keeps the seconds and MinIO the milliseconds: the comparison uses the seconds.
    let current_until = current.retain_until.map_or(0, |value| value.secs);
    let next_until = next.retain_until.map_or(0, |value| value.secs);
    let current_text = current.retain_until.map(lock_date).unwrap_or_default();
    if current.mode == COMPLIANCE {
        if next.mode != COMPLIANCE {
            return Err(Error::api(
                409,
                "compliance_retention",
                format!(
                    "A Compliance retention cannot change to {}: it keeps the version until {current_text}, and nobody can remove it or change it before this date, not even the owner of the bucket.",
                    mode_name(&next.mode)
                ),
            ));
        }
        if next_until < current_until {
            return Err(Error::api(
                409,
                "compliance_retention",
                format!(
                    "A Compliance retention cannot be shortened: it keeps the version until {current_text}, and nobody can remove it or shorten it before this date, not even the owner of the bucket. Give the same date or a later date."
                ),
            ));
        }
        return Ok(false);
    }
    Ok(next.mode != current.mode || next_until < current_until)
}

/// The answer of the API for the refusal of a change. A provider that refuses for the lock answers 403 on
/// SeaweedFS and 400 on MinIO: the refusal does not change the write permission of the instance.
fn object_lock_write_error(error: Error, part: &str) -> Error {
    let Some(upstream) = error.as_upstream() else {
        return error;
    };
    if provider_refused_feature(&error) {
        return object_lock_unsupported();
    }
    if upstream.status == 404 {
        return error;
    }
    if (400..500).contains(&upstream.status) {
        return Error::api(
            409,
            "object_lock_refused",
            format!(
                "The storage provider refused the change of the {part} ({}): the lock of the version forbids it, or the credentials of this instance cannot change it.",
                upstream_status_text(upstream.status, &upstream.code)
            ),
        );
    }
    error
}

// --- The instance -------------------------------------------------------------------------------------------------

impl Instance {
    /// True when the bucket of the instance has Object Lock. Until the probe has run, the answer is no.
    pub fn object_lock_available(&self) -> bool {
        self.backend.object_lock().is_some() && self.object_lock.on.load(Ordering::SeqCst)
    }

    /// Read the Object Lock configuration of the bucket. Only `Enabled` shows the function. The request is a read.
    /// An instance without the read permission is not probed.
    pub async fn probe_object_lock(&self, ctx: &OpCtx) {
        let Some(manager) = self.backend.object_lock() else {
            return;
        };
        if !self.permitted(crate::common::config::PERMISSION_READ) {
            return;
        }
        let probe = ctx.with_timeout(PROBE_TIMEOUT);
        let result = probe.run(manager.configuration(&probe)).await;
        let enabled = matches!(&result, Ok(configuration) if configuration.enabled);
        self.object_lock.on.store(enabled, Ordering::SeqCst);
        if let (true, Ok(configuration)) = (enabled, result)
            && let Ok(mut slot) = self.object_lock.bucket_default.lock()
        {
            *slot = Some(configuration);
        }
    }

    /// The default retention of the bucket that the probe read, for `/api/instances`. It is `None` for a bucket
    /// without Object Lock or without a default retention.
    pub fn object_lock_default_info(&self) -> Option<ObjectLockDefaultJson> {
        if !self.object_lock_available() {
            return None;
        }
        let configuration = self.object_lock.bucket_default.lock().ok()?.clone()?;
        default_json(&configuration)
    }

    fn object_lock_manager(&self) -> Result<&dyn ObjectLockManager> {
        match self.backend.object_lock() {
            Some(manager) if self.object_lock.on.load(Ordering::SeqCst) => Ok(manager),
            _ => Err(object_lock_unsupported()),
        }
    }

    /// Read the retention and the legal hold of the version (the current version for an empty version). The caller
    /// holds no slot of the gates.
    pub async fn read_object_lock(&self, ctx: &OpCtx, key: &str, version: &str) -> Result<ObjectLockState> {
        let manager = self.object_lock_manager()?;
        let retention = {
            let _slot = begin_request(self, ctx).await?;
            manager.retention(ctx, key, version).await?
        };
        let legal_hold = {
            let _slot = begin_request(self, ctx).await?;
            manager.legal_hold(ctx, key, version).await?
        };
        observe_permission(self, crate::common::config::PERMISSION_READ, None);
        Ok(ObjectLockState { retention, legal_hold })
    }

    /// Explain a refused delete: an active legal hold or retention of the version gives `409 object_locked`; any
    /// other refusal stays as it is. `key` is the full key. The caller holds no slot of the gates.
    pub async fn explain_lock_refusal(&self, ctx: &OpCtx, key: &str, version: &str, error: Error) -> Error {
        if !self.object_lock_available() || !lock_refusal_candidate(&error) || ctx.check().is_err() {
            return error;
        }
        let state = self.read_object_lock(ctx, key, version).await;
        let now = Timestamp::now();
        let Ok(state) = state else {
            return error;
        };
        if !state.locked(now) {
            return error;
        }
        let relative = self.relative_key(key).unwrap_or_else(|| key.to_owned());
        object_locked_error(&relative, version, &state, now)
    }

    /// Read the lock of the version, check the change against the rules, and send it: first the retention, then
    /// the legal hold. A part that changes nothing is not sent.
    pub async fn change_object_lock(&self, ctx: &OpCtx, key: &str, version: &str, change: &ObjectLockChange) -> Result<()> {
        let manager = self.object_lock_manager()?;
        let current = self.read_object_lock(ctx, key, version).await?;
        let now = Timestamp::now();
        if let Some(next) = &change.retention {
            let bypass = retention_change(current.retention.as_ref(), next, now)?;
            if bypass && !change.bypass_governance {
                let until = current
                    .retention
                    .as_ref()
                    .and_then(|value| value.retain_until)
                    .map(lock_date)
                    .unwrap_or_default();
                return Err(Error::api(
                    409,
                    "governance_bypass_required",
                    format!(
                        "This change shortens or changes a Governance retention that keeps the version until {until}. Confirm the bypass of the Governance retention to make it."
                    ),
                ));
            }
            let same = current.retention.as_ref().is_some_and(|value| {
                value.active(now)
                    && value.mode == next.mode
                    && value.retain_until.map(|date| date.secs) == next.retain_until.map(|date| date.secs)
            });
            if !same {
                let _slot = begin_request(self, ctx).await?;
                manager
                    .put_retention(ctx, key, version, next, bypass)
                    .await
                    .map_err(|error| object_lock_write_error(error, "retention"))?;
            }
        }
        if let Some(hold) = change.legal_hold
            && hold != current.legal_hold
        {
            let _slot = begin_request(self, ctx).await?;
            manager
                .put_legal_hold(ctx, key, version, hold)
                .await
                .map_err(|error| object_lock_write_error(error, "legal hold"))?;
        }
        observe_permission(self, crate::common::config::PERMISSION_WRITE, None);
        Ok(())
    }
}

fn default_json(configuration: &ObjectLockConfiguration) -> Option<ObjectLockDefaultJson> {
    if configuration.default_mode.is_empty() {
        return None;
    }
    Some(ObjectLockDefaultJson {
        mode: configuration.default_mode.clone(),
        days: Some(configuration.default_days).filter(|days| *days > 0),
        years: Some(configuration.default_years).filter(|years| *years > 0),
    })
}

// --- HTTP ---------------------------------------------------------------------------------------------------------

/// The retention in the answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectLockRetentionJson {
    /// The mode.
    pub mode: String,
    /// The date, in RFC 3339 and UTC.
    pub retain_until: String,
    /// False for a date in the past: the retention keeps the version no longer.
    pub active: bool,
}

/// The answer of `/api/object-lock`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectLockResponse {
    /// The instance.
    pub instance: String,
    /// The key.
    pub key: String,
    /// The version that the lock applies to: the request names it, or the HEAD of the object gives it.
    pub version: String,
    /// The retention, or null.
    pub retention: Option<ObjectLockRetentionJson>,
    /// The legal hold.
    pub legal_hold: bool,
    /// The default retention of the bucket, or null.
    pub bucket_default: Option<ObjectLockDefaultJson>,
    /// The date of the server (RFC 3339): the form compares the dates with it.
    pub now: String,
    /// The latest retention in days from now.
    pub max_retention_days: i64,
}

/// A value that may be null in the JSON of a request: null gives the default.
pub fn null_default<'de, D, T>(deserializer: D) -> std::result::Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

/// The retention of a request.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct RetentionRequest {
    /// The mode.
    #[serde(default, deserialize_with = "null_default")]
    pub mode: String,
    /// The retain-until date.
    #[serde(default, deserialize_with = "null_default")]
    pub retain_until: String,
}

/// The body of `PUT /api/object-lock`.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ObjectLockRequest {
    /// The instance.
    #[serde(default, deserialize_with = "null_default")]
    pub instance: String,
    /// The key.
    #[serde(default, deserialize_with = "null_default")]
    pub key: String,
    /// The version.
    #[serde(default, deserialize_with = "null_default")]
    pub version: String,
    /// The legal hold.
    #[serde(default)]
    pub legal_hold: Option<bool>,
    /// The retention.
    #[serde(default)]
    pub retention: Option<RetentionRequest>,
    /// The bypass of the Governance retention.
    #[serde(default, deserialize_with = "null_default")]
    pub bypass_governance: bool,
}

/// True for a version id of 1 to 1024 printable characters.
fn valid_version_id(version: &str) -> bool {
    !version.is_empty() && version.len() <= MAX_OBJECT_LOCK_VERSION_BYTES && printable_ascii(version)
}

/// Check the request without the provider: the version, a closed set of modes, and a retain-until date in the
/// future and not later than 36500 days from now.
pub fn validate_object_lock_request(request: &ObjectLockRequest, now: Timestamp) -> Result<ObjectLockChange> {
    if !valid_version_id(&request.version) {
        return Err(invalid_object_lock(
            "version is required: give the id of the version that the lock applies to",
        ));
    }
    if request.legal_hold.is_none() && request.retention.is_none() {
        return Err(invalid_object_lock("give legalHold, retention or both"));
    }
    let mut change = ObjectLockChange {
        legal_hold: request.legal_hold,
        bypass_governance: request.bypass_governance,
        ..ObjectLockChange::default()
    };
    if let Some(retention) = &request.retention {
        let mode = retention.mode.as_str();
        if mode != GOVERNANCE && mode != COMPLIANCE {
            return Err(invalid_object_lock(format!(
                "retention.mode must be {GOVERNANCE} or {COMPLIANCE}, got {}",
                quote(mode)
            )));
        }
        let text = retention.retain_until.as_str();
        let parsed = Timestamp::parse_rfc3339(text);
        let Some(until) = parsed.filter(|_| text.len() <= MAX_OBJECT_LOCK_DATE_CHARS) else {
            return Err(invalid_object_lock(format!(
                "retention.retainUntil must be an RFC 3339 date such as 2026-10-21T07:28:00Z, got {}",
                quote(text)
            )));
        };
        if until <= now {
            return Err(invalid_object_lock(format!(
                "retention.retainUntil must be in the future, got {}",
                lock_date(until)
            )));
        }
        if until > now.plus_secs(MAX_OBJECT_LOCK_DAYS * 86_400) {
            return Err(invalid_object_lock(format!(
                "retention.retainUntil must be at most {MAX_OBJECT_LOCK_DAYS} days from now, got {}",
                lock_date(until)
            )));
        }
        change.retention = Some(Retention {
            mode: mode.to_owned(),
            retain_until: Some(Timestamp::from_unix(until.secs, 0)),
        });
    }
    Ok(change)
}

/// Read the lock of the version and the default retention of the bucket. An empty version reads the current
/// version, and the HEAD of the object gives its id.
pub async fn object_lock_response_for(
    ctx: &OpCtx,
    instance: &Instance,
    key: &str,
    version: &str,
) -> Result<ObjectLockResponse> {
    let manager = instance.object_lock_manager()?;
    let full = instance.full_key(key);
    let mut version = version.to_owned();
    if version.is_empty() {
        let head = instance.head(&ctx.with_version(None), &full).await?;
        version = head
            .headers
            .get("x-amz-version-id")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .trim()
            .to_owned();
    }
    let state = instance.read_object_lock(ctx, &full, &version).await?;
    let configuration = {
        let _slot = begin_request(instance, ctx).await?;
        manager.configuration(ctx).await?
    };
    let now = Timestamp::now().utc();
    Ok(ObjectLockResponse {
        instance: instance.cfg.id.clone(),
        key: key.to_owned(),
        version,
        retention: state.retention.as_ref().map(|retention| ObjectLockRetentionJson {
            mode: retention.mode.clone(),
            retain_until: retention.retain_until.map(|value| value.utc().rfc3339()).unwrap_or_default(),
            active: retention.active(now),
        }),
        legal_hold: state.legal_hold,
        bucket_default: default_json(&configuration),
        now: now.rfc3339(),
        max_retention_days: MAX_OBJECT_LOCK_DAYS,
    })
}

/// Write one log line for a change of a lock: what changed and the use of the bypass.
fn log_object_lock_change(instance: &Instance, key: &str, version: &str, change: &ObjectLockChange) {
    let hold = match change.legal_hold {
        Some(true) => "on",
        Some(false) => "off",
        None => "unchanged",
    };
    let retention = match &change.retention {
        Some(value) => format!(
            "{} until {}",
            value.mode,
            value.retain_until.map(|date| date.utc().rfc3339()).unwrap_or_default()
        ),
        None => "unchanged".to_owned(),
    };
    crate::log!(
        "object_lock.change instance={} key={} version={} legal_hold={hold} retention={} bypass_governance={}",
        instance.cfg.id,
        quote(key),
        quote(version),
        quote(&retention),
        change.bypass_governance
    );
}

/// `GET` reads (permission read) and `PUT` changes (permission write) the lock of one version of an object. The
/// answer of a `PUT` is the new state. Each change goes to the log.
pub fn handle_object_lock(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        match serve(&app, req).await {
            Ok(response) => response,
            Err(error) => api_error(&error),
        }
    })
}

async fn serve(app: &App, req: Req) -> Result<Response> {
    match req.method {
        Method::GET => read_route(app, req).await,
        Method::PUT => change_route(app, req).await,
        _ => Ok(method_not_allowed(&["GET", "PUT"])),
    }
}

async fn read_route(app: &App, req: Req) -> Result<Response> {
    let Req { query, ctx, .. } = req;
    let key = clean_relative_key(query.get("key"));
    let instance = app.instance_of("", query.get("instance"))?.clone();
    instance.require_permission(crate::common::config::PERMISSION_READ)?;
    if key.is_empty() {
        return Err(Error::api(400, "invalid_key", "object key is required"));
    }
    access::authorize_read(app, &ctx, &instance, &key).await?;
    let version = query.get("version").trim().to_owned();
    if !version.is_empty() && !valid_version_id(&version) {
        return Err(invalid_object_lock("version must be the id of a version of the object"));
    }
    let response = object_lock_response_for(&ctx, &instance, &key, &version).await?;
    Ok(json(200, &response))
}

async fn change_route(app: &App, req: Req) -> Result<Response> {
    let Req { query, body, ctx, .. } = req;
    let request: ObjectLockRequest = decode_json(body).await?;
    let key = clean_relative_key(&request.key);
    let instance = app.instance_of(&request.instance, query.get("instance"))?.clone();
    for permission in [crate::common::config::PERMISSION_READ, crate::common::config::PERMISSION_WRITE] {
        instance.require_permission(permission)?;
    }
    if key.is_empty() {
        return Err(Error::api(400, "invalid_key", "object key is required"));
    }
    let change = validate_object_lock_request(&request, Timestamp::now())?;
    access::authorize_use(app, &ctx, access::ACTION_LOCK, &instance, &key).await?;
    instance
        .change_object_lock(&ctx, &instance.full_key(&key), &request.version, &change)
        .await?;
    log_object_lock_change(&instance, &key, &request.version, &change);
    let response = object_lock_response_for(&ctx, &instance, &key, &request.version).await?;
    Ok(json(200, &response))
}
