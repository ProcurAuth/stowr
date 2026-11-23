//! The ceilings of the access policy (`max_object_size`) and their checks in the storage calls
//! (docs/ACCESS.md, "The ceiling max_object_size").
//!
//! The value of a true answer is the size in bytes of the largest object that one use reads (`object.read`) or
//! writes (`object.write`). The value of `object.read` bounds each object that the operation reads. The value of
//! `object.write` bounds each object that it writes. A HEAD, a list, a tag and a read of metadata read no object
//! bytes: they have no check.
//!
//! The access layer keeps the ceilings in the request. A job keeps the ceilings of its request in its own context.
//! The storage calls of the instance and the range reader apply them, so each route has the check. A result over a
//! ceiling is a refusal. The service never cuts an answer.

use std::collections::BTreeMap;
use std::sync::Mutex;

use http::HeaderMap;
use http::header::{CONTENT_LENGTH, CONTENT_RANGE};

use crate::common::ctx::OpCtx;
use crate::common::error::{ApiError, Error, Result};

/// The action `object.read`.
pub const ACTION_READ: &str = "object.read";
/// The action `object.write`.
pub const ACTION_WRITE: &str = "object.write";
/// The ceiling `max_object_size`.
pub const MAX_OBJECT_SIZE: &str = "max_object_size";
/// The code of a refusal for a ceiling.
pub const CODE_CEILING_EXCEEDED: &str = "ceiling_exceeded";

/// The ceilings by action, then by name, then the value.
pub type CeilingMap = BTreeMap<String, BTreeMap<String, i64>>;

/// The ceilings of a request or of a job, by action and by name. The lower value of two answers wins.
#[derive(Debug, Default)]
pub struct Ceilings {
    values: Mutex<CeilingMap>,
}

impl Ceilings {
    /// Ceilings with the values of a map. The lower value of a ceiling applies.
    pub fn from_map(map: &CeilingMap) -> Self {
        let ceilings = Self::default();
        ceilings.lower_all(map);
        ceilings
    }

    /// Keep a ceiling. A lower value replaces a higher one.
    pub fn lower(&self, action: &str, name: &str, value: i64) {
        if let Ok(mut values) = self.values.lock() {
            let entry = values
                .entry(action.to_owned())
                .or_default()
                .entry(name.to_owned())
                .or_insert(value);
            if value < *entry {
                *entry = value;
            }
        }
    }

    /// Keep each ceiling of a map. The lower value of a ceiling wins.
    pub fn lower_all(&self, map: &CeilingMap) {
        for (action, names) in map {
            for (name, value) in names {
                self.lower(action, name, *value);
            }
        }
    }

    /// The value of a ceiling, when one applies.
    pub fn get(&self, action: &str, name: &str) -> Option<i64> {
        self.values
            .lock()
            .ok()
            .and_then(|values| values.get(action).and_then(|names| names.get(name).copied()))
    }

    /// A copy of the values.
    pub fn values(&self) -> CeilingMap {
        self.values.lock().map(|values| values.clone()).unwrap_or_default()
    }

    /// True when no ceiling applies.
    pub fn is_empty(&self) -> bool {
        self.values.lock().map(|values| values.is_empty()).unwrap_or(true)
    }

    /// A copy of the values, for a job that keeps the ceilings of its request.
    pub fn snapshot(&self) -> Ceilings {
        Ceilings {
            values: Mutex::new(self.values()),
        }
    }

    /// The ceilings of this value and of `other`. The lower value of a ceiling wins.
    pub fn merge(&self, other: &Ceilings) -> Ceilings {
        let merged = self.snapshot();
        merged.lower_all(&other.values());
        merged
    }
}

/// The ceiling `max_object_size` of an action for the context: the lower value of the ceilings of the request and
/// of the ceilings that the context carries. `None` when no ceiling applies (always in mode `open`).
pub fn ceiling_of(ctx: &OpCtx, action: &str) -> Option<i64> {
    let request = ctx
        .access
        .as_ref()
        .and_then(|access| access.ceilings.get(action, MAX_OBJECT_SIZE));
    let carried = ctx
        .ceilings
        .as_ref()
        .and_then(|ceilings| ceilings.get(action, MAX_OBJECT_SIZE));
    match (request, carried) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (left, right) => left.or(right),
    }
}

/// All the ceilings of a context: those of its request and those that it carries. The lower value wins. An empty
/// map in mode `open`.
pub fn ceilings_of(ctx: &OpCtx) -> CeilingMap {
    let merged = Ceilings::default();
    if let Some(access) = &ctx.access {
        merged.lower_all(&access.ceilings.values());
    }
    if let Some(carried) = &ctx.ceilings {
        merged.lower_all(&carried.values());
    }
    merged.values()
}

/// True when a ceiling `max_object_size` applies to one of the actions.
pub fn ceiling_applies(ctx: &OpCtx, actions: &[&str]) -> bool {
    actions.iter().any(|action| ceiling_of(ctx, action).is_some())
}

/// The `403 ceiling_exceeded` answer of a size over a ceiling. A size below 0 is a size that the service does not
/// know. The message never gives the size of the object.
pub fn ceiling_exceeded(action: &str, limit: i64, size: i64) -> Error {
    let message = if size < 0 {
        format!("The size of the object is not known. The ceiling {MAX_OBJECT_SIZE} of the action {action} applies.")
    } else {
        format!("The object is larger than the ceiling {MAX_OBJECT_SIZE} of the action {action}.")
    };
    Error::Api(Box::new(ApiError {
        status: 403,
        code: CODE_CEILING_EXCEEDED.to_owned(),
        message,
        action: Some(action.to_owned()),
        retry_after: 0,
        ceiling: Some((MAX_OBJECT_SIZE.to_owned(), limit)),
    }))
}

/// The refusal for a ceiling that an error holds, or `None` for any other error.
pub fn ceiling_error_of(error: &Error) -> Option<&ApiError> {
    error.as_api().filter(|api| api.code == CODE_CEILING_EXCEEDED)
}

/// Check a size against the ceiling of an action. A size below 0 (unknown) is refused when a ceiling applies. A
/// refusal writes the log line `access.ceiling_refused`.
pub fn check_object_ceiling(ctx: &OpCtx, action: &str, size: i64) -> Result<()> {
    let Some(limit) = ceiling_of(ctx, action) else {
        return Ok(());
    };
    if size >= 0 && size <= limit {
        return Ok(());
    }
    let request_id = ctx.access.as_ref().map_or("", |access| access.request_id.as_str());
    crate::log!(
        "access.ceiling_refused request_id={} action={action} ceiling={MAX_OBJECT_SIZE} limit={limit} size={size}",
        log_token(request_id)
    );
    Err(ceiling_exceeded(action, limit, size))
}

/// Check the size of an object that the operation reads.
pub fn check_read_ceiling(ctx: &OpCtx, size: i64) -> Result<()> {
    check_object_ceiling(ctx, ACTION_READ, size)
}

/// Check the size of an object that the operation writes.
pub fn check_write_ceiling(ctx: &OpCtx, size: i64) -> Result<()> {
    check_object_ceiling(ctx, ACTION_WRITE, size)
}

/// Check the size of an object that the operation reads and writes: a copy, a move, a restore.
pub fn check_copy_ceilings(ctx: &OpCtx, size: i64) -> Result<()> {
    check_read_ceiling(ctx, size)?;
    check_write_ceiling(ctx, size)
}

/// The size of the whole object of a read answer: the total of `Content-Range`, or the `Content-Length` of a full
/// answer. -1 when the answer does not tell the size.
pub fn read_answer_size(status: u16, headers: &HeaderMap) -> i64 {
    let content_range = header_text(headers, CONTENT_RANGE.as_str());
    if !content_range.is_empty() {
        let Some(slash) = content_range.rfind('/') else {
            return -1;
        };
        return match content_range[slash + 1..].trim().parse::<i64>() {
            Ok(total) if total >= 0 => total,
            _ => -1,
        };
    }
    if status == 206 {
        return -1;
    }
    match header_text(headers, CONTENT_LENGTH.as_str()).parse::<i64>() {
        Ok(length) if length >= 0 => length,
        _ => -1,
    }
}

/// Apply the ceiling `object.read` to the answer of a read, before the body goes to the caller. Only an answer with
/// object bytes (200 and 206) has the check.
pub fn check_read_answer(ctx: &OpCtx, status: u16, headers: &HeaderMap) -> Result<()> {
    if status != 200 && status != 206 {
        return Ok(());
    }
    if !ceiling_applies(ctx, &[ACTION_READ]) {
        return Ok(());
    }
    check_read_ceiling(ctx, read_answer_size(status, headers))
}

/// The same context with a copy of the ceilings of a job. The ceilings replace those that the context carried. An
/// empty map gives the context unchanged.
pub fn with_access_ceilings(ctx: &OpCtx, ceilings: &CeilingMap) -> OpCtx {
    if ceilings.is_empty() {
        return ctx.clone();
    }
    OpCtx {
        ceilings: Some(std::sync::Arc::new(Ceilings::from_map(ceilings))),
        ..ctx.clone()
    }
}

/// List each object under a relative prefix and check its size against the ceilings of the actions, before the
/// first effect of an operation on many objects (a copy of a prefix reads and writes each object). The check stops
/// at the first object over a ceiling. Without a ceiling of the actions, it lists nothing.
pub async fn check_listed_sizes(
    ctx: &OpCtx,
    instance: &crate::instance::Instance,
    prefix: &str,
    actions: &[&str],
) -> Result<()> {
    if !ceiling_applies(ctx, actions) {
        return Ok(());
    }
    const PAGE: u32 = 1000;
    let full_prefix = instance.full_key(prefix);
    let mut last_key = String::new();
    loop {
        let options = crate::common::storage::ListOptions {
            prefix: full_prefix.clone(),
            max_results: PAGE,
            start_after: if last_key.is_empty() {
                String::new()
            } else {
                instance.full_key(&last_key)
            },
            ..Default::default()
        };
        let mut page = instance.list(ctx, &options).await?;
        page.objects.sort_by(|left, right| left.key.cmp(&right.key));
        let mut progressed = false;
        for object in &page.objects {
            let Some(relative) = instance.relative_key(&object.key) else {
                continue;
            };
            if relative.is_empty() || !relative.starts_with(prefix) || (!last_key.is_empty() && relative <= last_key) {
                continue;
            }
            for action in actions {
                check_object_ceiling(ctx, action, object.size)?;
            }
            last_key = relative;
            progressed = true;
        }
        if !progressed || (page.next_page_token.is_empty() && page.objects.len() < PAGE as usize) {
            return Ok(());
        }
    }
}

/// The trimmed text of a header, or an empty text.
pub(crate) fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map_or("", str::trim)
}

/// The longest value that a log line shows without quotes.
const MAX_LOG_TOKEN_LENGTH: usize = 128;

/// A value for a log line: `-` when empty, the value when it is a short token, else a quoted text. A value of a
/// header then cannot add a field or a line to the log.
pub fn log_token(value: &str) -> String {
    if value.is_empty() {
        return "-".to_owned();
    }
    let safe = value.bytes().all(|c| c.is_ascii_alphanumeric() || b"-._:".contains(&c));
    if value.len() <= MAX_LOG_TOKEN_LENGTH && safe {
        return value.to_owned();
    }
    quote(value)
}

/// A quoted text with escapes for the quote, the backslash and the control characters.
fn quote(value: &str) -> String {
    crate::config::quote::quote(value)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::access::AccessRequest;

    fn request_with(action: &str, value: i64, request_id: &str) -> Arc<AccessRequest> {
        let request = AccessRequest {
            subject: "user-1".to_owned(),
            request_id: request_id.to_owned(),
            ..AccessRequest::default()
        };
        request.ceilings.lower(action, MAX_OBJECT_SIZE, value);
        Arc::new(request)
    }

    #[test]
    fn a_job_context_carries_a_copy_of_the_ceilings() {
        let mut map = CeilingMap::new();
        map.entry(ACTION_READ.to_owned())
            .or_default()
            .insert(MAX_OBJECT_SIZE.to_owned(), 7);
        let ctx = OpCtx {
            ceilings: Some(Arc::new(Ceilings::from_map(&map))),
            ..OpCtx::default()
        };
        map.entry(ACTION_READ.to_owned())
            .or_default()
            .insert(MAX_OBJECT_SIZE.to_owned(), 1000);
        assert_eq!(ceiling_of(&ctx, ACTION_READ), Some(7));
        assert_eq!(ceiling_of(&ctx, ACTION_WRITE), None);
        assert!(check_read_ceiling(&ctx, 8).is_err());
        assert!(check_read_ceiling(&ctx, 7).is_ok());

        // The lower value wins between the ceilings of the request and the ceilings of the context.
        let both = OpCtx {
            access: Some(request_with(ACTION_READ, 3, "")),
            ..ctx.clone()
        };
        assert_eq!(ceiling_of(&both, ACTION_READ), Some(3));
        assert_eq!(ceilings_of(&both)[ACTION_READ][MAX_OBJECT_SIZE], 3);
        let empty = OpCtx {
            ceilings: Some(Arc::new(Ceilings::from_map(&CeilingMap::new()))),
            ..OpCtx::default()
        };
        assert!(ceilings_of(&empty).is_empty());
    }

    #[test]
    fn the_lower_value_of_a_ceiling_stays() {
        let ceilings = Ceilings::default();
        ceilings.lower(ACTION_READ, MAX_OBJECT_SIZE, 50);
        ceilings.lower(ACTION_READ, MAX_OBJECT_SIZE, 20);
        ceilings.lower(ACTION_WRITE, MAX_OBJECT_SIZE, 9);
        ceilings.lower(ACTION_READ, MAX_OBJECT_SIZE, 60);
        assert_eq!(ceilings.get(ACTION_READ, MAX_OBJECT_SIZE), Some(20));
        assert_eq!(ceilings.get(ACTION_WRITE, MAX_OBJECT_SIZE), Some(9));
        let other = Ceilings::default();
        other.lower(ACTION_WRITE, MAX_OBJECT_SIZE, 4);
        let merged = ceilings.merge(&other);
        assert_eq!(merged.get(ACTION_WRITE, MAX_OBJECT_SIZE), Some(4));
        assert_eq!(ceilings.get(ACTION_WRITE, MAX_OBJECT_SIZE), Some(9));
    }

    #[test]
    fn the_refusal_names_the_action_the_ceiling_and_the_limit() {
        let error = ceiling_exceeded(ACTION_READ, 10, 12);
        assert_eq!(error.status(), 403);
        assert_eq!(
            error.public_message(),
            "The object is larger than the ceiling max_object_size of the action object.read."
        );
        let unknown = ceiling_exceeded(ACTION_WRITE, 10, -1);
        assert_eq!(
            unknown.public_message(),
            "The size of the object is not known. The ceiling max_object_size of the action object.write applies."
        );
        let body = crate::common::json::to_vec(&unknown.envelope()).unwrap();
        assert_eq!(
            String::from_utf8(body).unwrap(),
            "{\"error\":{\"action\":\"object.write\",\"ceiling\":\"max_object_size\",\"code\":\"ceiling_exceeded\",\"limit\":10,\"message\":\"The size of the object is not known. The ceiling max_object_size of the action object.write applies.\"}}"
        );
        assert!(ceiling_error_of(&unknown).is_some());
        assert!(ceiling_error_of(&Error::api(403, "forbidden", "no")).is_none());
    }

    #[tokio::test]
    async fn the_gateway_text_of_a_refusal_has_no_json() {
        let response = crate::common::http::gateway_error(&ceiling_exceeded(ACTION_READ, 10, 12));
        assert_eq!(response.status(), 403);
        let (bytes, _) = crate::common::http::read_limited(response.into_body(), 4096)
            .await
            .unwrap();
        assert!(!bytes.contains(&b'{'));
    }

    #[test]
    fn an_unknown_size_is_refused_when_a_ceiling_applies() {
        let ctx = OpCtx {
            access: Some(request_with(ACTION_WRITE, 10, "rid-up")),
            ..OpCtx::default()
        };
        assert!(check_write_ceiling(&ctx, -1).is_err());
        assert!(check_write_ceiling(&ctx, 10).is_ok());
        assert!(check_read_ceiling(&ctx, -1).is_ok());
        assert!(check_copy_ceilings(&ctx, 11).is_err());
    }

    #[test]
    fn the_open_mode_has_no_ceiling() {
        let ctx = OpCtx::default();
        assert!(!ceiling_applies(&ctx, &[ACTION_READ, ACTION_WRITE]));
        assert!(check_copy_ceilings(&ctx, i64::MAX).is_ok());
        assert!(check_read_ceiling(&ctx, -1).is_ok());
    }

    #[test]
    fn the_size_of_a_read_answer_comes_from_the_content_range_or_the_length() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_LENGTH, "5".parse().unwrap());
        assert_eq!(read_answer_size(200, &headers), 5);
        assert_eq!(read_answer_size(206, &headers), -1);
        headers.insert(CONTENT_RANGE, "bytes 0-4/100".parse().unwrap());
        assert_eq!(read_answer_size(206, &headers), 100);
        headers.insert(CONTENT_RANGE, "bytes 0-4/*".parse().unwrap());
        assert_eq!(read_answer_size(206, &headers), -1);
        headers.insert(CONTENT_RANGE, "bytes 0-4".parse().unwrap());
        assert_eq!(read_answer_size(206, &headers), -1);
    }

    #[test]
    fn a_log_token_quotes_an_unsafe_value() {
        assert_eq!(log_token(""), "-");
        assert_eq!(log_token("rid-get"), "rid-get");
        assert_eq!(log_token("a b"), "\"a b\"");
        assert_eq!(log_token("a\"\n"), "\"a\\\"\\n\"");
        assert_eq!(log_token(&"x".repeat(129)), format!("\"{}\"", "x".repeat(129)));
    }
}
