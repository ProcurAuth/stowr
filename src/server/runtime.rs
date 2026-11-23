//! The HTTP/1.1 runtime: the listener, the timeouts of the connections, the conversion of a request, the final form
//! of an answer, and the graceful stop.
//!
//! The limits of a connection: 10 seconds to read the head of a request, 2 minutes of idle time between two
//! requests, 1 MiB of request head, and 30 seconds at most without progress when the server writes an answer.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http::header::{
    CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, HOST, HeaderValue, TRAILER, TRANSFER_ENCODING,
};
use http::{HeaderMap, Method, Uri, Version};
use http_body::{Body as _, Frame, SizeHint};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, Sleep};

use super::mediatype::{SNIFF_LEN, detect_content_type};
use super::paths;
use crate::common::app::App;
use crate::common::error::{Error, Result};
use crate::common::http::{Body, Req, Response, answer, empty, full};
use crate::common::query::Query;

/// The longest time to read the head of a request.
pub const READ_HEADER_TIMEOUT: Duration = Duration::from_secs(10);
/// The longest idle time of a connection between two requests.
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(120);
/// The largest head of a request.
pub const MAX_HEADER_BYTES: usize = 1 << 20;
/// The longest time that a write of an answer may make no progress.
pub const WRITE_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
/// The longest time of the graceful stop.
pub const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
/// The number of bytes of an answer that the server keeps before it sends the head: an answer that ends within
/// them gets a `Content-Length`, a longer answer goes in chunks.
pub const BUFFER_BEFORE_CHUNKING: usize = 2048;

/// The request target as the client sent it.
#[derive(Clone, Debug, Default)]
pub struct Target {
    /// The path in its escaped form.
    pub escaped_path: String,
    /// The decoded path, as bytes (it can be other than UTF-8).
    pub path_bytes: Vec<u8>,
}

fn bad_request(text: &str) -> Response {
    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
    headers.insert(CONNECTION, HeaderValue::from_static("close"));
    let message = if text.is_empty() {
        "400 Bad Request".to_owned()
    } else {
        format!("400 Bad Request: {text}")
    };
    answer(400, headers, full(message))
}

/// Convert the head and the body of a request into a [`Req`]. A malformed request gives the answer 400.
pub fn request_from_parts(
    method: Method,
    uri: &Uri,
    version: Version,
    headers: HeaderMap,
    body: Body,
) -> std::result::Result<(Req, Target), Box<Response>> {
    let hosts = headers.get_all(HOST).iter().count();
    if hosts > 1 {
        return Err(Box::new(bad_request("too many Host headers")));
    }
    if version >= Version::HTTP_11 && hosts == 0 && uri.authority().is_none() && method != Method::CONNECT {
        return Err(Box::new(bad_request("missing required Host header")));
    }
    let raw_path = if uri.path().is_empty() { "/" } else { uri.path() };
    let (escaped_path, path_bytes) = if raw_path == "*" {
        ("*".to_owned(), b"*".to_vec())
    } else {
        let Some(decoded) = paths::unescape_bytes(raw_path) else {
            return Err(Box::new(bad_request("")));
        };
        (paths::escaped_request_path(raw_path, &decoded), decoded)
    };
    let path = String::from_utf8_lossy(&path_bytes).into_owned();
    let raw_query = uri.query().unwrap_or("").to_owned();
    let host = match uri.authority() {
        Some(authority) => authority.as_str().to_owned(),
        None => headers
            .get(HOST)
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
            .unwrap_or_default(),
    };
    let req = Req {
        method,
        path,
        query: Query::parse(&raw_query),
        raw_query,
        headers,
        body,
        ctx: crate::common::ctx::OpCtx::default(),
        host,
    };
    Ok((
        req,
        Target {
            escaped_path,
            path_bytes,
        },
    ))
}

/// A body that replays bytes that the server read, then the rest of a body.
struct Prefixed {
    head: Option<Bytes>,
    rest: Option<Body>,
}

impl http_body::Body for Prefixed {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>>>> {
        if let Some(head) = self.head.take() {
            return Poll::Ready(Some(Ok(Frame::data(head))));
        }
        match self.rest.as_mut() {
            Some(rest) => Pin::new(rest).poll_frame(cx),
            None => Poll::Ready(None),
        }
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

/// A body whose length the head of the answer gives.
struct UnknownLength {
    inner: Body,
}

impl http_body::Body for UnknownLength {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

/// Read the first bytes of a body: until more than `limit` bytes or the end. Gives the bytes, true at the end, an
/// error of the body and the trailers.
async fn read_head(body: &mut Body, limit: usize) -> (Bytes, bool, Option<Error>, Option<HeaderMap>) {
    let mut head = BytesMut::new();
    loop {
        if head.len() > limit {
            return (head.freeze(), false, None, None);
        }
        match body.frame().await {
            None => return (head.freeze(), true, None, None),
            Some(Err(error)) => return (head.freeze(), false, Some(error), None),
            Some(Ok(frame)) => match frame.into_data() {
                Ok(data) => head.extend_from_slice(&data),
                Err(frame) => return (head.freeze(), true, None, frame.into_trailers().ok()),
            },
        }
    }
}

struct Replay {
    head: Option<Bytes>,
    error: Option<Error>,
    trailers: Option<HeaderMap>,
}

impl http_body::Body for Replay {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>>>> {
        if let Some(head) = self.head.take() {
            return Poll::Ready(Some(Ok(Frame::data(head))));
        }
        if let Some(error) = self.error.take() {
            return Poll::Ready(Some(Err(error)));
        }
        Poll::Ready(self.trailers.take().map(|trailers| Ok(Frame::trailers(trailers))))
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

fn header_present(headers: &HeaderMap, name: http::header::HeaderName) -> bool {
    headers.get(name).is_some_and(|value| !value.is_empty())
}

/// The final form of an answer, as a writer of HTTP/1.1 answers makes it: no body and no length for 1xx, 204 and 304
/// (and no type for 304), no body for `HEAD`, a `Content-Length` for a short answer without trailers, and a media
/// type from the first bytes when the handler set none.
pub async fn finalize(method: &Method, response: Response) -> Response {
    let (mut parts, mut body) = response.into_parts();
    let status = parts.status.as_u16();
    let body_allowed = !(100..200).contains(&status) && status != 204 && status != 304;
    if !body_allowed {
        parts.headers.remove(CONTENT_LENGTH);
        parts.headers.remove(TRANSFER_ENCODING);
        if status == 304 {
            parts.headers.remove(CONTENT_TYPE);
        }
        return Response::from_parts(parts, empty());
    }
    let has_length = parts.headers.contains_key(CONTENT_LENGTH);
    let trailers = parts.headers.contains_key(TRAILER);
    let has_encoding = parts.headers.contains_key(TRANSFER_ENCODING);
    let needs_type =
        !parts.headers.contains_key(CONTENT_TYPE) && !header_present(&parts.headers, CONTENT_ENCODING) && !has_encoding;
    if *method == Method::HEAD {
        parts.headers.remove(TRANSFER_ENCODING);
        let small = body
            .size_hint()
            .exact()
            .is_some_and(|size| size as usize <= BUFFER_BEFORE_CHUNKING);
        if small && (needs_type || (!has_length && !trailers && !has_encoding)) {
            let (head, _, _, _) = read_head(&mut body, BUFFER_BEFORE_CHUNKING).await;
            if needs_type && !head.is_empty() {
                parts
                    .headers
                    .insert(CONTENT_TYPE, HeaderValue::from_static(detect_content_type(&head)));
            }
            if !has_length && !trailers && !has_encoding && !head.is_empty() {
                parts.headers.insert(CONTENT_LENGTH, HeaderValue::from(head.len()));
            }
        }
        return Response::from_parts(parts, empty());
    }
    if has_length {
        if needs_type {
            let (head, ended, error, trailers) = read_head(&mut body, SNIFF_LEN).await;
            if !head.is_empty() {
                parts
                    .headers
                    .insert(CONTENT_TYPE, HeaderValue::from_static(detect_content_type(&head)));
            }
            let replay: Body = if ended || error.is_some() {
                Replay {
                    head: Some(head).filter(|head| !head.is_empty()),
                    error,
                    trailers,
                }
                .boxed_unsync()
            } else {
                Prefixed {
                    head: Some(head).filter(|head| !head.is_empty()),
                    rest: Some(body),
                }
                .boxed_unsync()
            };
            return Response::from_parts(parts, UnknownLength { inner: replay }.boxed_unsync());
        }
        return Response::from_parts(parts, UnknownLength { inner: body }.boxed_unsync());
    }
    let limit = if !trailers && !has_encoding {
        BUFFER_BEFORE_CHUNKING
    } else if needs_type {
        SNIFF_LEN
    } else {
        return Response::from_parts(parts, body);
    };
    let (head, ended, error, end_trailers) = read_head(&mut body, limit).await;
    if needs_type && !head.is_empty() {
        parts
            .headers
            .insert(CONTENT_TYPE, HeaderValue::from_static(detect_content_type(&head)));
    }
    if ended && error.is_none() && !trailers && !has_encoding && end_trailers.is_none() {
        // The whole answer is short: it gets its length.
        return Response::from_parts(parts, full(head));
    }
    let head = Some(head).filter(|head| !head.is_empty());
    let replay: Body = if ended || error.is_some() {
        Replay {
            head,
            error,
            trailers: end_trailers,
        }
        .boxed_unsync()
    } else {
        Prefixed { head, rest: Some(body) }.boxed_unsync()
    };
    Response::from_parts(parts, replay)
}

/// The phase of a connection, for its read timeouts.
#[derive(Clone, Copy, Debug)]
enum Phase {
    /// The server reads the head of a request: it must end before the deadline.
    Head(Instant),
    /// No request: the first byte of the next request must come before the end of the idle time.
    Idle(Instant),
    /// A request runs: no read deadline.
    Active,
}

/// The shared state of one connection.
#[derive(Debug)]
pub struct ConnState {
    phase: Mutex<Phase>,
}

impl ConnState {
    fn new() -> Self {
        Self {
            phase: Mutex::new(Phase::Head(Instant::now() + READ_HEADER_TIMEOUT)),
        }
    }

    fn set(&self, phase: Phase) {
        if let Ok(mut current) = self.phase.lock() {
            *current = phase;
        }
    }

    fn get(&self) -> Phase {
        self.phase.lock().map(|phase| *phase).unwrap_or(Phase::Active)
    }

    fn bytes_received(&self) {
        if let Ok(mut current) = self.phase.lock()
            && matches!(*current, Phase::Idle(_))
        {
            *current = Phase::Head(Instant::now() + READ_HEADER_TIMEOUT);
        }
    }

    fn read_deadline(&self) -> Option<Instant> {
        match self.get() {
            Phase::Head(deadline) => Some(deadline),
            Phase::Idle(since) => Some(since + IDLE_TIMEOUT),
            Phase::Active => None,
        }
    }
}

/// A TCP stream with the read deadlines of the phase of its connection and a limit of 30 seconds for a write that
/// makes no progress.
struct TimedStream {
    inner: TcpStream,
    state: Arc<ConnState>,
    read_sleep: Pin<Box<Sleep>>,
    read_armed: Option<Instant>,
    write_sleep: Pin<Box<Sleep>>,
    write_deadline: Option<Instant>,
}

impl TimedStream {
    fn new(inner: TcpStream, state: Arc<ConnState>) -> Self {
        let now = Instant::now();
        Self {
            inner,
            state,
            read_sleep: Box::pin(tokio::time::sleep_until(now)),
            read_armed: None,
            write_sleep: Box::pin(tokio::time::sleep_until(now)),
            write_deadline: None,
        }
    }

    fn poll_write_progress<T>(&mut self, cx: &mut Context<'_>, polled: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        match polled {
            Poll::Ready(result) => {
                self.write_deadline = None;
                Poll::Ready(result)
            }
            Poll::Pending => {
                if self.write_deadline.is_none() {
                    let deadline = Instant::now() + WRITE_IDLE_TIMEOUT;
                    self.write_deadline = Some(deadline);
                    self.write_sleep.as_mut().reset(deadline);
                }
                if self.write_sleep.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, "i/o timeout")));
                }
                Poll::Pending
            }
        }
    }
}

impl AsyncRead for TimedStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                if buf.filled().len() > before {
                    this.state.bytes_received();
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => {
                let Some(deadline) = this.state.read_deadline() else {
                    this.read_armed = None;
                    return Poll::Pending;
                };
                if this.read_armed != Some(deadline) {
                    this.read_sleep.as_mut().reset(deadline);
                    this.read_armed = Some(deadline);
                }
                if this.read_sleep.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Err(io::Error::new(io::ErrorKind::TimedOut, "i/o timeout")));
                }
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for TimedStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, data: &[u8]) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let polled = Pin::new(&mut this.inner).poll_write(cx, data);
        this.poll_write_progress(cx, polled)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        let polled = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        this.poll_write_progress(cx, polled)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        let polled = Pin::new(&mut this.inner).poll_flush(cx);
        this.poll_write_progress(cx, polled)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A body that marks the connection idle at its end or when hyper drops it.
struct ConnBody {
    inner: Body,
    state: Option<Arc<ConnState>>,
}

impl ConnBody {
    fn release(&mut self) {
        if let Some(state) = self.state.take() {
            state.set(Phase::Idle(Instant::now()));
        }
    }
}

impl http_body::Body for ConnBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>>>> {
        let polled = Pin::new(&mut self.inner).poll_frame(cx);
        if matches!(polled, Poll::Ready(None) | Poll::Ready(Some(Err(_)))) {
            self.release();
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

impl Drop for ConnBody {
    fn drop(&mut self) {
        self.release();
    }
}

/// Answer one request of a connection.
async fn serve_request(app: Arc<App>, state: Arc<ConnState>, request: http::Request<Incoming>) -> Response {
    state.set(Phase::Active);
    let (parts, incoming) = request.into_parts();
    let body: Body = incoming
        .map_err(|error| Error::internal(format!("read the request body: {error}")))
        .boxed_unsync();
    let method = parts.method.clone();
    let response = match request_from_parts(parts.method, &parts.uri, parts.version, parts.headers, body) {
        Ok((req, target)) => {
            let response = super::handle(app, req, target).await;
            finalize(&method, response).await
        }
        Err(response) => *response,
    };
    let (parts, body) = response.into_parts();
    let body = ConnBody {
        inner: body,
        state: Some(state),
    };
    Response::from_parts(parts, body.boxed_unsync())
}

fn connection_builder() -> hyper::server::conn::http1::Builder {
    let mut builder = hyper::server::conn::http1::Builder::new();
    builder
        .keep_alive(true)
        .title_case_headers(true)
        .header_read_timeout(None)
        .max_buf_size(MAX_HEADER_BYTES + 4096 + 8192)
        .max_headers(1024);
    builder
}

async fn serve_connection(app: Arc<App>, stream: TcpStream, mut shutdown: tokio::sync::watch::Receiver<bool>) {
    let state = Arc::new(ConnState::new());
    let io = hyper_util::rt::TokioIo::new(TimedStream::new(stream, state.clone()));
    let service = hyper::service::service_fn(move |request: http::Request<Incoming>| {
        let app = app.clone();
        let state = state.clone();
        async move { Ok::<Response, std::convert::Infallible>(serve_request(app, state, request).await) }
    });
    let builder = connection_builder();
    let connection = builder.serve_connection(io, service);
    let mut connection = std::pin::pin!(connection);
    let mut draining = *shutdown.borrow();
    if draining {
        connection.as_mut().graceful_shutdown();
    }
    loop {
        tokio::select! {
            _ = connection.as_mut() => break,
            changed = shutdown.changed(), if !draining => {
                draining = true;
                if changed.is_ok() {
                    connection.as_mut().graceful_shutdown();
                }
            }
        }
    }
}

/// The text of an error of the system: the message in lower case, without the number of the error.
fn system_error_text(error: &io::Error) -> String {
    match error.raw_os_error() {
        Some(libc::EADDRINUSE) => return "address already in use".to_owned(),
        Some(libc::EADDRNOTAVAIL) => return "cannot assign requested address".to_owned(),
        Some(libc::EACCES) => return "permission denied".to_owned(),
        _ => {}
    }
    let text = error.to_string();
    let text = match text.find(" (os error") {
        Some(index) => text[..index].to_owned(),
        None => text,
    };
    let mut characters = text.chars();
    match characters.next() {
        Some(first) => first.to_lowercase().chain(characters).collect(),
        None => text,
    }
}

/// Open the listener of `server.listen`. An empty host listens on each address.
pub async fn bind(listen: &str) -> Result<TcpListener> {
    let fail = |error: io::Error| Error::internal(format!("listen tcp {listen}: bind: {}", system_error_text(&error)));
    let (host, port) = match listen.rfind(':') {
        Some(index) => (&listen[..index], &listen[index + 1..]),
        None => return Err(Error::internal(format!("listen tcp {listen}: missing port in address"))),
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port: u16 = port
        .parse()
        .map_err(|_| Error::internal(format!("listen tcp {listen}: invalid port")))?;
    if host.is_empty() {
        return match TcpListener::bind(("::", port)).await {
            Ok(listener) => Ok(listener),
            Err(_) => TcpListener::bind(("0.0.0.0", port)).await.map_err(fail),
        };
    }
    TcpListener::bind((host, port)).await.map_err(fail)
}

/// Wait for SIGINT or SIGTERM; give the name of the signal.
async fn stop_signal() -> &'static str {
    use tokio::signal::unix::{SignalKind, signal};
    let interrupt = signal(SignalKind::interrupt());
    let terminate = signal(SignalKind::terminate());
    match (interrupt, terminate) {
        (Ok(mut interrupt), Ok(mut terminate)) => {
            tokio::select! {
                _ = interrupt.recv() => "interrupt",
                _ = terminate.recv() => "terminated",
            }
        }
        _ => std::future::pending().await,
    }
}

/// Accept the connections of a listener until the stop future ends, then stop gracefully: no new connection, each
/// idle connection closes, each running request ends. After 10 seconds the remaining connections close.
pub async fn run_listener(app: Arc<App>, listener: TcpListener, stop: impl Future<Output = &'static str>) {
    let (shutdown_sender, shutdown) = tokio::sync::watch::channel(false);
    let mut connections = tokio::task::JoinSet::new();
    let mut stop = std::pin::pin!(stop);
    let mut backoff = Duration::from_millis(5);
    loop {
        tokio::select! {
            name = stop.as_mut() => {
                crate::log!("received {name}; shutting down");
                break;
            }
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    backoff = Duration::from_millis(5);
                    let _ = stream.set_nodelay(true);
                    connections.spawn(serve_connection(app.clone(), stream, shutdown.clone()));
                }
                Err(error) => {
                    crate::log!("http: Accept error: {error}; retrying in {}", super::logfmt::duration_ms(backoff));
                    tokio::time::sleep(backoff).await;
                    backoff = (backoff * 2).min(Duration::from_secs(1));
                }
            },
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
        }
    }
    drop(listener);
    let _ = shutdown_sender.send(true);
    let drained = tokio::time::timeout(SHUTDOWN_TIMEOUT, async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        crate::log!("graceful shutdown failed: context deadline exceeded");
        connections.abort_all();
        while connections.join_next().await.is_some() {}
    }
}

/// Serve on a listener until SIGINT or SIGTERM.
pub async fn serve_listener(app: Arc<App>, listener: TcpListener) {
    run_listener(app, listener, stop_signal()).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::http::read_limited;

    async fn finalized(method: Method, response: Response) -> (Response, Vec<u8>) {
        let response = finalize(&method, response).await;
        let (parts, body) = response.into_parts();
        let size = body.size_hint().exact();
        let (bytes, _) = read_limited(body, 1 << 20).await.unwrap();
        let mut response = Response::from_parts(parts, empty());
        if let Some(size) = size {
            response
                .headers_mut()
                .insert("x-test-exact-size", HeaderValue::from(size));
        }
        (response, bytes.to_vec())
    }

    #[tokio::test]
    async fn a_short_answer_gets_its_length_and_a_type_from_its_bytes() {
        let (response, body) = finalized(Method::GET, answer(200, HeaderMap::new(), full("<html><body>"))).await;
        assert_eq!(response.headers()[CONTENT_TYPE], "text/html; charset=utf-8");
        assert_eq!(response.headers()["x-test-exact-size"], "12");
        assert_eq!(body, b"<html><body>");
    }

    #[tokio::test]
    async fn a_long_answer_goes_in_chunks() {
        let (channel_sender, channel_body) = crate::common::http::channel(4);
        tokio::spawn(async move {
            channel_sender.send(Bytes::from(vec![b'a'; 3000])).await.unwrap();
        });
        let (response, body) = finalized(Method::GET, answer(200, HeaderMap::new(), channel_body)).await;
        assert!(response.headers().get("x-test-exact-size").is_none());
        assert_eq!(response.headers()[CONTENT_TYPE], "text/plain; charset=utf-8");
        assert_eq!(body.len(), 3000);
    }

    #[tokio::test]
    async fn head_and_no_content_answers_lose_their_body() {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/plain; charset=utf-8"));
        let (response, body) = finalized(Method::HEAD, answer(404, headers, full("404 page not found\n"))).await;
        assert_eq!(response.headers()[CONTENT_LENGTH], "19");
        assert!(body.is_empty());
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/css"));
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("4"));
        let (response, body) = finalized(Method::GET, answer(304, headers, full("abcd"))).await;
        assert!(response.headers().get(CONTENT_TYPE).is_none());
        assert!(response.headers().get(CONTENT_LENGTH).is_none());
        assert!(body.is_empty());
    }

    #[test]
    fn requests_need_one_host_and_valid_escapes() {
        let uri: Uri = "/a%20b?x=1".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("example.com"));
        let (req, target) = request_from_parts(Method::GET, &uri, Version::HTTP_11, headers.clone(), empty()).unwrap();
        assert_eq!(req.path, "/a b");
        assert_eq!(req.raw_query, "x=1");
        assert_eq!(req.host, "example.com");
        assert_eq!(target.escaped_path, "/a%20b");
        let bad: Uri = "/a%zz".parse().unwrap();
        let refused = request_from_parts(Method::GET, &bad, Version::HTTP_11, headers, empty())
            .err()
            .unwrap();
        assert_eq!(refused.status(), 400);
        let missing = request_from_parts(Method::GET, &uri, Version::HTTP_11, HeaderMap::new(), empty())
            .err()
            .unwrap();
        assert_eq!(missing.status(), 400);
    }

    #[test]
    fn system_errors_have_the_short_lower_case_form() {
        let error = io::Error::from_raw_os_error(98);
        assert_eq!(system_error_text(&error), "address already in use");
    }
}
