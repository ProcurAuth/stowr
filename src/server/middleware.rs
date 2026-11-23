// SPDX-License-Identifier: MIT OR Apache-2.0
//! The middlewares of each request: the security headers, the request log, the check of the identity token, the
//! budget of the request and its trailers, the idle limit of an upload body, and the same-origin check of the
//! mutations.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::header::{CACHE_CONTROL, HeaderName, HeaderValue};
use http::{HeaderMap, Method};
use http_body::{Frame, SizeHint};
use serde::Serialize;

use super::logfmt::{duration_ms, quote};
use crate::common::app::App;
use crate::common::config::LogMode;
use crate::common::error::{Error, Result};
use crate::common::http::{Body, Req, Response, json};
use crate::instance::budget::Budget;

/// The trailer of the number of provider calls of a request.
pub const REQUESTS_TRAILER: &str = "X-Stowr-Storage-Requests";
/// The trailer of the number of provider bytes of a request.
pub const BYTES_TRAILER: &str = "X-Stowr-Storage-Bytes";
/// The trailer of the time of a request, in milliseconds.
pub const ELAPSED_TRAILER: &str = "X-Stowr-Elapsed-Ms";

/// The longest time that an upload body or a download may make no progress.
pub const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; base-uri 'self'; connect-src 'self'; font-src 'self'; form-action 'self'; frame-ancestors 'self'; img-src 'self' data: blob:; media-src 'self' blob:; object-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; worker-src 'self' blob:";

/// The security headers of an answer, for the path of the request. The API and the object gateway also get
/// `Cache-Control: private, no-store`.
pub fn security_headers(path: &str) -> Vec<(HeaderName, &'static str)> {
    let mut headers = vec![
        (http::header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (http::header::REFERRER_POLICY, "same-origin"),
        (http::header::X_FRAME_OPTIONS, "SAMEORIGIN"),
        (HeaderName::from_static("cross-origin-opener-policy"), "same-origin"),
        (HeaderName::from_static("cross-origin-resource-policy"), "same-origin"),
        (
            HeaderName::from_static("permissions-policy"),
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()",
        ),
        (http::header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY),
    ];
    if path.starts_with("/api/") || path == "/s3" {
        headers.push((CACHE_CONTROL, "private, no-store"));
    }
    headers
}

/// Add the security headers that the handler did not set: the handler value wins, as it replaces the value of the
/// middleware.
pub fn apply_security_headers(headers: &mut HeaderMap, path: &str) {
    for (name, value) in security_headers(path) {
        if !headers.contains_key(&name) {
            headers.insert(name, HeaderValue::from_static(value));
        }
    }
}

/// True for `GET`, `HEAD` and `OPTIONS`.
pub fn is_safe_method(method: &Method) -> bool {
    *method == Method::GET || *method == Method::HEAD || *method == Method::OPTIONS
}

#[derive(Serialize)]
struct RefusalBody {
    code: &'static str,
    message: &'static str,
}

#[derive(Serialize)]
struct RefusalEnvelope {
    error: RefusalBody,
}

fn refusal(code: &'static str, message: &'static str) -> Response {
    json(
        403,
        &RefusalEnvelope {
            error: RefusalBody { code, message },
        },
    )
}

/// The refusal of a cross-site mutation from a browser, or `None`. A client without the Fetch Metadata and `Origin`
/// headers passes. A header value that is not visible ASCII counts as absent: a browser never sends one. The host
/// of the request is the authority of the request target (HTTP/2 `:authority`), else the `Host` header: the server
/// never reads `X-Forwarded-Host`.
///
/// `Origin: null` is an opaque origin: a sandboxed frame, a `data:` or `file:` page, or a redirect from another
/// origin. It is not the origin of this application, so a mutation with it gets `origin_mismatch`.
pub fn same_origin_refusal(method: &Method, headers: &HeaderMap, host: &str) -> Option<Response> {
    if is_safe_method(method) {
        return None;
    }
    let site = header_first(headers, "sec-fetch-site").trim().to_lowercase();
    if site == "cross-site" {
        return Some(refusal(
            "cross_site_request_blocked",
            "cross-site mutation requests are not allowed",
        ));
    }
    let origin = header_first(headers, "origin").trim();
    if !origin.is_empty() {
        let matches = !origin.eq_ignore_ascii_case("null")
            && parse_origin(origin).is_some_and(|(scheme, origin_host)| {
                origin_host.to_lowercase() == host.to_lowercase()
                    && (scheme == "http" || scheme == "https")
                    && !origin_host.is_empty()
            });
        if !matches {
            return Some(refusal(
                "origin_mismatch",
                "the request origin does not match this application",
            ));
        }
    }
    None
}

fn header_first<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers.get(name).and_then(|value| value.to_str().ok()).unwrap_or("")
}

fn valid_escapes(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let valid = bytes.get(index + 1).is_some_and(u8::is_ascii_hexdigit)
                && bytes.get(index + 2).is_some_and(u8::is_ascii_hexdigit);
            if !valid {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

fn valid_port(port: &str) -> bool {
    port.is_empty()
        || port
            .strip_prefix(':')
            .is_some_and(|digits| digits.bytes().all(|byte| byte.is_ascii_digit()))
}

/// Decode a host of a URL: `%XX` only for the bytes that are not ASCII (and `%25`), and no byte that a host cannot
/// hold.
fn unescape_host(host: &str) -> Option<String> {
    let bytes = host.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            let high = char::from(*bytes.get(index + 1)?).to_digit(16)?;
            let low = char::from(*bytes.get(index + 2)?).to_digit(16)?;
            if high < 8 && &host[index..index + 3] != "%25" {
                return None;
            }
            out.push(u8::try_from(high << 4 | low).ok()?);
            index += 3;
            continue;
        }
        let allowed = byte >= 0x80 || byte.is_ascii_alphanumeric() || b"-_.~!$&'()*+,;=:[]<>\"".contains(&byte);
        if !allowed {
            return None;
        }
        out.push(byte);
        index += 1;
    }
    String::from_utf8(out).ok()
}

fn valid_userinfo(text: &str) -> bool {
    text.chars()
        .all(|character| character.is_ascii_alphanumeric() || "-._:~!$&'()*+,;=%@".contains(character))
}

/// The scheme (in lower case) and the host of an `Origin` value, with the rules of a URL reader. `None` for a value
/// that is not a valid URL.
pub fn parse_origin(origin: &str) -> Option<(String, String)> {
    if origin.bytes().any(|byte| byte < 0x20 || byte == 0x7f) {
        return None;
    }
    let (url, fragment) = origin.split_once('#').unwrap_or((origin, ""));
    if !valid_escapes(fragment) {
        return None;
    }
    // The scheme: a letter, then letters, digits, `+`, `-` or `.`, then `:`.
    let mut scheme = "";
    let mut rest = url;
    for (index, byte) in url.bytes().enumerate() {
        match byte {
            b'a'..=b'z' | b'A'..=b'Z' => {}
            b'0'..=b'9' | b'+' | b'-' | b'.' if index > 0 => {}
            b':' => {
                if index == 0 {
                    return None;
                }
                scheme = &url[..index];
                rest = &url[index + 1..];
                break;
            }
            _ => break,
        }
    }
    let scheme = scheme.to_ascii_lowercase();
    if rest.ends_with('?') && rest.matches('?').count() == 1 {
        rest = &rest[..rest.len() - 1];
    } else {
        rest = rest.split_once('?').map_or(rest, |(path, _)| path);
    }
    if !rest.starts_with('/') {
        if !scheme.is_empty() {
            return Some((scheme, String::new()));
        }
        if rest.split('/').next().unwrap_or("").contains(':') {
            return None;
        }
    }
    let mut host = String::new();
    if (!scheme.is_empty() || !rest.starts_with("///")) && rest.starts_with("//") {
        let authority_and_path = &rest[2..];
        let (authority, path) = match authority_and_path.find('/') {
            Some(index) => (&authority_and_path[..index], &authority_and_path[index..]),
            None => (authority_and_path, ""),
        };
        let raw_host = match authority.rfind('@') {
            Some(index) => {
                if !valid_userinfo(&authority[..index]) || !valid_escapes(&authority[..index]) {
                    return None;
                }
                &authority[index + 1..]
            }
            None => authority,
        };
        if raw_host.starts_with('[') {
            let close = raw_host.rfind(']')?;
            if !valid_port(&raw_host[close + 1..]) {
                return None;
            }
        } else if let Some(colon) = raw_host.rfind(':')
            && !valid_port(&raw_host[colon..])
        {
            return None;
        }
        host = unescape_host(raw_host)?;
        rest = path;
    }
    if !valid_escapes(rest) {
        return None;
    }
    Some((scheme, host))
}

/// The path of the log: the object keys and the ids hidden in the mode `anonymous`.
pub fn logged_request_path(mode: LogMode, path: &[u8]) -> Vec<u8> {
    if mode == LogMode::Detailed {
        return path.to_vec();
    }
    let replacements: [(&[u8], &[u8]); 4] = [
        (b"/api/jobs/", b"/api/jobs/<id>"),
        (b"/api/uploads/", b"/api/uploads/<id>"),
        (b"/api/sqlite/sessions/", b"/api/sqlite/sessions/<id>"),
        (b"/-/", b"/-/<path>"),
    ];
    for (prefix, replacement) in replacements {
        if path.starts_with(prefix) {
            return replacement.to_vec();
        }
    }
    path.to_vec()
}

/// The identity of a request: the subject and the request id, for the log.
pub type LogIdentity = Option<(String, String)>;

/// The check of the identity token in mode `authzen` (the access layer): the identity of the request, or the answer
/// 401. The request keeps the identity and the ceilings of its true answers. The paths `/healthz` and
/// `/.well-known/procurauth/actions` need no token.
pub fn authenticate(app: &App, req: &mut Req) -> std::result::Result<LogIdentity, Box<Response>> {
    let Some(request) = app.access.check_token(&req.method, &req.path, &req.headers)? else {
        return Ok(None);
    };
    let identity = (request.subject.clone(), request.request_id.clone());
    req.ctx.ceilings = Some(request.ceilings.clone());
    req.ctx.access = Some(request);
    Ok(Some(identity))
}

/// True when the request gets a resource budget and its trailers: the API and the object gateway.
pub fn budget_applies(path: &str) -> bool {
    path.starts_with("/api/") || path == "/s3"
}

/// Declare the trailers of the budget in the headers of an answer.
pub fn declare_trailers(headers: &mut HeaderMap) {
    for name in [REQUESTS_TRAILER, BYTES_TRAILER, ELAPSED_TRAILER] {
        headers.append(http::header::TRAILER, HeaderValue::from_static(name));
    }
}

fn usage_trailers(budget: &Budget) -> HeaderMap {
    let usage = budget.usage();
    let mut trailers = HeaderMap::new();
    for (name, value) in [
        (REQUESTS_TRAILER, usage.storage_requests),
        (BYTES_TRAILER, usage.storage_bytes),
        (ELAPSED_TRAILER, usage.elapsed_ms),
    ] {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_str(&value.to_string()),
        ) {
            trailers.insert(name, value);
        }
    }
    trailers
}

/// A body that sends the use of the budget as trailers after its last byte. Its length is unknown, so the answer has
/// no automatic `Content-Length`.
pub struct BudgetBody {
    inner: Body,
    budget: Arc<Budget>,
    finished: bool,
}

impl BudgetBody {
    /// Wrap a body.
    pub fn new(inner: Body, budget: Arc<Budget>) -> Self {
        Self {
            inner,
            budget,
            finished: false,
        }
    }
}

impl http_body::Body for BudgetBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>>>> {
        if self.finished {
            return Poll::Ready(None);
        }
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(None) => {
                self.finished = true;
                Poll::Ready(Some(Ok(Frame::trailers(usage_trailers(&self.budget)))))
            }
            Poll::Ready(Some(Ok(frame))) if frame.is_trailers() => {
                // The trailers of the handler, then the use of the budget.
                let mut trailers = frame.into_trailers().unwrap_or_default();
                trailers.extend(usage_trailers(&self.budget));
                self.finished = true;
                Poll::Ready(Some(Ok(Frame::trailers(trailers))))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

/// A request body that must make progress at least every 30 seconds. A stalled client must not keep a storage slot.
pub struct IdleBody {
    inner: Body,
    idle: Duration,
    sleep: Pin<Box<tokio::time::Sleep>>,
    failed: bool,
}

impl IdleBody {
    /// Wrap a body with an idle limit.
    pub fn new(inner: Body, idle: Duration) -> Self {
        Self {
            inner,
            idle,
            sleep: Box::pin(tokio::time::sleep(idle)),
            failed: false,
        }
    }
}

impl http_body::Body for IdleBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>>>> {
        if self.failed {
            return Poll::Ready(Some(Err(Error::Timeout)));
        }
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Pending => {
                if self.sleep.as_mut().poll(cx).is_ready() {
                    self.failed = true;
                    return Poll::Ready(Some(Err(Error::Timeout)));
                }
                Poll::Pending
            }
            ready => {
                let deadline = tokio::time::Instant::now() + self.idle;
                self.sleep.as_mut().reset(deadline);
                ready
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// The values of one line of the request log.
pub struct LogLine {
    /// The method.
    pub method: Method,
    /// The path of the log (keys hidden in the mode `anonymous`).
    pub path: Vec<u8>,
    /// The status of the answer.
    pub status: u16,
    /// The start of the request.
    pub started: Instant,
    /// The identity of the request.
    pub identity: LogIdentity,
}

impl LogLine {
    /// The text of the line, without the date: the method, the quoted path, the status, the bytes, the time, and the
    /// subject and the request id in mode `authzen`.
    pub fn text(&self, bytes: u64) -> String {
        let elapsed = duration_ms(self.started.elapsed());
        let mut text = format!(
            "{} {} {} {}B {}",
            self.method,
            quote(&self.path),
            self.status,
            bytes,
            elapsed
        );
        if let Some((subject, request_id)) = &self.identity {
            text.push_str(&format!(
                " subject={} request_id={}",
                quote(subject.as_bytes()),
                request_id
            ));
        }
        text
    }

    fn write(&self, bytes: u64) {
        crate::log!("{}", self.text(bytes));
    }
}

/// A body that counts the bytes of the answer and writes the line of the request log at its end, or when the client
/// goes.
pub struct LogBody {
    inner: Body,
    line: Option<LogLine>,
    bytes: u64,
}

impl LogBody {
    /// Wrap a body.
    pub fn new(inner: Body, line: LogLine) -> Self {
        Self {
            inner,
            line: Some(line),
            bytes: 0,
        }
    }

    fn finish(&mut self) {
        if let Some(line) = self.line.take() {
            line.write(self.bytes);
        }
    }
}

impl http_body::Body for LogBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>>>> {
        let polled = Pin::new(&mut self.inner).poll_frame(cx);
        match &polled {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    self.bytes += data.len() as u64;
                }
            }
            Poll::Ready(None) | Poll::Ready(Some(Err(_))) => self.finish(),
            Poll::Pending => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for LogBody {
    fn drop(&mut self) {
        self.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins_follow_the_rules_of_a_url() {
        assert_eq!(
            parse_origin("https://browser.example"),
            Some(("https".to_owned(), "browser.example".to_owned()))
        );
        assert_eq!(
            parse_origin("HTTP://user@Host.example:8080/x"),
            Some(("http".to_owned(), "Host.example:8080".to_owned()))
        );
        assert_eq!(parse_origin("https://host:80x"), None);
        assert_eq!(parse_origin("https://ho st"), None);
        assert_eq!(parse_origin("://x"), None);
        assert_eq!(parse_origin("https://br%6Fwser"), None);
        assert_eq!(
            parse_origin("https://%C3%A9.example"),
            Some(("https".to_owned(), "é.example".to_owned()))
        );
    }

    fn origin_headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.insert(*name, HeaderValue::from_static(value));
        }
        headers
    }

    async fn refusal_code(response: Option<Response>) -> Option<String> {
        let answer = crate::server::testing::collect(response?).await;
        assert_eq!(answer.status, 403, "{}", answer.text());
        Some(answer.json()["error"]["code"].as_str().unwrap_or_default().to_owned())
    }

    #[tokio::test]
    async fn a_mutation_with_the_opaque_origin_null_is_refused() {
        for origin in ["null", " null ", "NULL"] {
            let refusal = same_origin_refusal(&Method::POST, &origin_headers(&[("origin", origin)]), "browser.example");
            assert_eq!(
                refusal_code(refusal).await.as_deref(),
                Some("origin_mismatch"),
                "{origin:?}"
            );
        }
        // The Fetch Metadata does not make an opaque origin the origin of the application.
        let same_origin = origin_headers(&[("sec-fetch-site", "same-origin"), ("origin", "null")]);
        let refusal = same_origin_refusal(&Method::DELETE, &same_origin, "browser.example");
        assert_eq!(refusal_code(refusal).await.as_deref(), Some("origin_mismatch"));
    }

    #[tokio::test]
    async fn the_origin_rule_keeps_safe_methods_and_clients_without_origin() {
        let null = origin_headers(&[("origin", "null")]);
        for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert!(
                same_origin_refusal(&method, &null, "browser.example").is_none(),
                "{method}"
            );
        }
        assert!(same_origin_refusal(&Method::PUT, &HeaderMap::new(), "browser.example").is_none());
        let matching = origin_headers(&[("origin", "https://Browser.example")]);
        assert!(same_origin_refusal(&Method::POST, &matching, "browser.example").is_none());
    }

    #[test]
    fn the_policy_of_the_pages_limits_the_targets_of_a_form() {
        let headers = security_headers("/");
        let policy = headers
            .iter()
            .find(|(name, _)| *name == http::header::CONTENT_SECURITY_POLICY)
            .map(|(_, value)| *value)
            .expect("a content security policy");
        assert_eq!(policy, CONTENT_SECURITY_POLICY);
        let directives: Vec<&str> = policy.split("; ").collect();
        assert!(directives.contains(&"form-action 'self'"), "{policy}");
        assert!(directives.contains(&"frame-ancestors 'self'"), "{policy}");
        assert!(directives.contains(&"object-src 'none'"), "{policy}");
    }

    #[test]
    fn request_ids_keep_a_valid_client_value() {
        let mut headers = HeaderMap::new();
        headers.insert("x-request-id", HeaderValue::from_static("abc-1.2:3_4"));
        assert_eq!(crate::access::request_id_from(&headers), "abc-1.2:3_4");
        headers.insert("x-request-id", HeaderValue::from_static("bad id"));
        assert_eq!(crate::access::request_id_from(&headers).len(), 32);
    }

    #[test]
    fn the_anonymous_log_hides_keys_and_ids() {
        assert_eq!(
            logged_request_path(LogMode::Anonymous, b"/-/host/bucket/secret.pdf"),
            b"/-/<path>"
        );
        assert_eq!(
            logged_request_path(LogMode::Anonymous, b"/api/jobs/job_1"),
            b"/api/jobs/<id>"
        );
        assert_eq!(
            logged_request_path(LogMode::Detailed, b"/-/host/bucket/secret.pdf"),
            b"/-/host/bucket/secret.pdf"
        );
    }
}
