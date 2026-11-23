// SPDX-License-Identifier: MIT OR Apache-2.0
//! The HTTP client of the providers, of the admin APIs and of the health check.
//!
//! The client speaks HTTP/1.1. It follows no redirect: the caller gets a `3xx` answer as it is. It reads no proxy
//! variable and no other environment variable. TLS is version 1.2 or 1.3. The roots of TLS are the certificate
//! bundle of the image: the first file of [`ROOT_BUNDLES`] that the process can read. The client verifies the
//! certificate unless `insecure_skip_verify` is set.
//!
//! The time limits are these: 10 seconds for the TCP connection, 10 seconds for the TLS handshake, and 30 seconds
//! for the headers of the answer after the client sent the request. An idle connection stays in the pool for
//! 90 seconds, with 20 idle connections at most for each host.
//!
//! A request without `Accept-Encoding` and without `Range` (and not `HEAD`) asks for gzip. An answer with
//! `Content-Encoding: gzip` to such a request comes back decoded, without `Content-Encoding` and without
//! `Content-Length`. The body of an answer stops with an error when the operation is canceled or its deadline is past.

use std::future::Future;
use std::io::Write as _;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::{Buf as _, Bytes};
use flate2::write::MultiGzDecoder;
use http::header::{
    ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, HOST, HeaderName, HeaderValue, RANGE, TRANSFER_ENCODING,
};
use http::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use http_body::{Frame, SizeHint};
use http_body_util::BodyExt as _;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::{Connected, Connection, HttpConnector};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use rustls::RootCertStore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, WebPkiSupportedAlgorithms};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Body, empty, read_limited};

/// The certificate bundles of the image, in the order of the search. The client reads the first one that exists.
pub const ROOT_BUNDLES: [&str; 6] = [
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/pki/tls/cacert.pem",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/cert.pem",
];

/// The most idle connections for each host.
const MAX_IDLE_PER_HOST: usize = 20;

/// The most headers of an answer. An object can have many user metadata headers.
const MAX_ANSWER_HEADERS: usize = 1000;

/// The most bytes of compressed input that one step of the gzip decoder reads. The output of one step stays near
/// 1 MiB at most.
const GZIP_STEP: usize = 1024;

/// The time limits of the client.
#[derive(Clone, Copy, Debug)]
pub struct Timeouts {
    /// The TCP connection.
    pub connect: Duration,
    /// The TLS handshake.
    pub handshake: Duration,
    /// The headers of the answer, after the client sent the request.
    pub headers: Duration,
    /// The life of an idle connection in the pool.
    pub idle: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(10),
            handshake: Duration::from_secs(10),
            headers: Duration::from_secs(30),
            idle: Duration::from_secs(90),
        }
    }
}

/// The HTTP client of the providers, of the admin APIs and of the health check. A clone shares the pool.
#[derive(Clone)]
pub struct StorageClient {
    /// True when the client does not verify the certificate.
    pub insecure_skip_verify: bool,
    inner: Arc<ClientInner>,
}

struct ClientInner {
    client: Client<Connector, RequestBody>,
    timeouts: Timeouts,
}

impl std::fmt::Debug for StorageClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StorageClient")
            .field("insecure_skip_verify", &self.insecure_skip_verify)
            .finish_non_exhaustive()
    }
}

/// The roots of the image, read one time.
fn system_roots() -> Arc<RootCertStore> {
    static ROOTS: OnceLock<Arc<RootCertStore>> = OnceLock::new();
    ROOTS
        .get_or_init(|| {
            let mut roots = RootCertStore::empty();
            for path in ROOT_BUNDLES {
                if let Ok(data) = std::fs::read(path) {
                    let certificates = CertificateDer::pem_slice_iter(&data).filter_map(|item| item.ok());
                    roots.add_parsable_certificates(certificates);
                    break;
                }
            }
            Arc::new(roots)
        })
        .clone()
}

impl StorageClient {
    /// A client with the roots of the image and the time limits of the module.
    pub fn new(insecure_skip_verify: bool) -> Result<Self> {
        Self::with_roots(insecure_skip_verify, system_roots(), Timeouts::default())
    }

    /// A client with other roots and other time limits.
    pub fn with_roots(insecure_skip_verify: bool, roots: Arc<RootCertStore>, timeouts: Timeouts) -> Result<Self> {
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|error| Error::internal(format!("configure TLS: {error}")))?
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        if insecure_skip_verify {
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(NoCertificateCheck { provider }));
        }
        let mut tcp = HttpConnector::new();
        tcp.enforce_http(false);
        tcp.set_connect_timeout(Some(timeouts.connect));
        tcp.set_keepalive(Some(Duration::from_secs(30)));
        tcp.set_nodelay(true);
        let connector = Connector {
            tcp,
            tls: TlsConnector::from(Arc::new(config)),
            handshake: timeouts.handshake,
        };
        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(timeouts.idle)
            .pool_max_idle_per_host(MAX_IDLE_PER_HOST)
            .pool_timer(TokioTimer::new())
            .http1_title_case_headers(true)
            .http1_max_headers(MAX_ANSWER_HEADERS)
            .build(connector);
        Ok(Self {
            insecure_skip_verify,
            inner: Arc::new(ClientInner { client, timeouts }),
        })
    }

    /// Send a request and give the answer with its body as a stream. The URI is absolute. A status of 300 or more
    /// is not an error. A failure of the connection, of TLS or of the transport gives [`Error::Connect`]; a canceled
    /// operation gives [`Error::Canceled`]; a past deadline gives [`Error::Timeout`]. An error of the body of the
    /// request comes back as it is.
    pub async fn send(&self, ctx: &OpCtx, request: Request<Body>) -> Result<Response<Body>> {
        ctx.check()?;
        let (mut parts, body) = request.into_parts();
        let added_gzip = parts.method != Method::HEAD
            && header_text(&parts.headers, &ACCEPT_ENCODING).is_empty()
            && header_text(&parts.headers, &RANGE).is_empty();
        if added_gzip {
            parts.headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
        }
        if !parts.headers.contains_key(HOST)
            && let Some(authority) = parts.uri.authority()
            && let Ok(value) = HeaderValue::from_str(authority.as_str())
        {
            parts.headers.insert(HOST, value);
        }
        let (sent, written) = oneshot::channel();
        let request = Request::from_parts(
            parts,
            RequestBody {
                inner: body,
                sent: Some(sent),
            },
        );
        let header_limit = self.inner.timeouts.headers;
        let pending = self.inner.client.request(request);
        let exchange = async move {
            tokio::select! {
                result = pending => result.map_err(client_error),
                () = async move {
                    let _ = written.await;
                    tokio::time::sleep(header_limit).await;
                } => Err(Error::Connect("timeout awaiting response headers".to_owned())),
            }
        };
        let response = ctx.run(exchange).await?;
        let (mut parts, incoming) = response.into_parts();
        parts.headers.remove(TRANSFER_ENCODING);
        let mut body: Body = incoming
            .map_err(|error| Error::internal(format!("read the answer of the provider: {error}")))
            .boxed_unsync();
        let gzip = header_text(&parts.headers, &CONTENT_ENCODING).eq_ignore_ascii_case("gzip");
        if added_gzip && gzip {
            parts.headers.remove(CONTENT_ENCODING);
            parts.headers.remove(CONTENT_LENGTH);
            body = GzipBody::new(body).boxed_unsync();
        }
        Ok(Response::from_parts(parts, CtxBody::new(body, ctx).boxed_unsync()))
    }

    /// Send a request and read at most `limit` bytes of the body of the answer.
    pub async fn fetch(&self, ctx: &OpCtx, request: Request<Body>, limit: usize) -> Result<Answer> {
        let response = self.send(ctx, request).await?;
        Answer::read(response, limit).await
    }
}

/// The admin APIs of the usage readers use the client of their `auth` block: no redirect, no proxy, and the check of
/// the certificate of the block.
impl crate::bucket::AdminTransport for StorageClient {
    fn get<'a>(
        &'a self,
        url: &'a str,
        headers: HeaderMap,
        limit: usize,
    ) -> crate::common::BoxFuture<'a, std::result::Result<crate::bucket::AdminAnswer, crate::bucket::AdminFailure>>
    {
        Box::pin(async move {
            let uri = Uri::try_from(url).map_err(|_| crate::bucket::AdminFailure::Connect)?;
            let mut request = Request::new(empty());
            *request.method_mut() = Method::GET;
            *request.uri_mut() = uri;
            *request.headers_mut() = headers;
            // The caller applies the time limit of the read of the usage: a drop of this call stops the request.
            let answer = self
                .fetch(&OpCtx::default(), request, limit)
                .await
                .map_err(|error| admin_failure(&error))?;
            Ok(crate::bucket::AdminAnswer {
                status: answer.status,
                body: answer.body,
            })
        })
    }
}

/// The reason of a failed admin request: a certificate that is not valid, a time limit, or any other failure of the
/// connection.
fn admin_failure(error: &Error) -> crate::bucket::AdminFailure {
    use crate::bucket::AdminFailure;
    match error {
        Error::Timeout => AdminFailure::Timeout,
        Error::Connect(text) => {
            let text = text.to_ascii_lowercase();
            if text.contains("certificate") {
                AdminFailure::Certificate
            } else if text.contains("timeout") || text.contains("timed out") || text.contains("deadline") {
                AdminFailure::Timeout
            } else {
                AdminFailure::Connect
            }
        }
        _ => AdminFailure::Connect,
    }
}

/// An answer with its body read to its end, or to the limit of the call.
#[derive(Clone, Debug, Default)]
pub struct Answer {
    /// The status.
    pub status: u16,
    /// The headers.
    pub headers: HeaderMap,
    /// The body.
    pub body: Bytes,
}

impl Answer {
    /// Read at most `limit` bytes of the body of an answer. The rest of the body is not read.
    pub async fn read(response: Response<Body>, limit: usize) -> Result<Self> {
        let (parts, body) = response.into_parts();
        let (body, _) = read_limited(body, limit).await?;
        Ok(Self {
            status: parts.status.as_u16(),
            headers: parts.headers,
            body,
        })
    }

    /// The first value of a header as text, or an empty text.
    pub fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
    }
}

/// The size from which the parse of an answer runs on a thread for blocking work, not on the runtime.
const BLOCKING_PARSE_SIZE: usize = 256 << 10;

/// Parse the body of an answer. A large body goes to a thread for blocking work, so that the parse does not hold
/// the runtime.
pub async fn parse_answer<T: Send + 'static>(
    body: Bytes,
    parse: impl FnOnce(&[u8]) -> T + Send + 'static,
) -> Result<T> {
    if body.len() < BLOCKING_PARSE_SIZE {
        return Ok(parse(&body));
    }
    tokio::task::spawn_blocking(move || parse(&body))
        .await
        .map_err(|error| Error::internal(format!("the parse of the answer stopped: {error}")))
}

/// The status line text of a status: the code and its reason, for example `404 Not Found`.
pub fn status_text(status: u16) -> String {
    let reason = StatusCode::from_u16(status)
        .ok()
        .and_then(|code| code.canonical_reason())
        .unwrap_or("");
    format!("{status} {reason}").trim_end().to_owned()
}

/// The first value of a header as text, or an empty text.
pub fn header_text<'a>(headers: &'a HeaderMap, name: &HeaderName) -> &'a str {
    headers.get(name).and_then(|value| value.to_str().ok()).unwrap_or("")
}

/// Build a request. A body has its size: a size of 0 or more gives `Content-Length`, a size below 0 gives a body
/// in chunks. A request without a body sends `Content-Length: 0`, except `GET` and `HEAD`. The URI is absolute.
pub fn build_request(
    method: Method,
    url: &str,
    mut headers: HeaderMap,
    body: Option<(Body, i64)>,
) -> Result<Request<Body>> {
    let uri: Uri = url
        .parse()
        .map_err(|error| Error::internal(format!("invalid request URL: {error}")))?;
    headers.remove(CONTENT_LENGTH);
    let body = match body {
        Some((body, size)) => {
            if size >= 0 {
                headers.insert(CONTENT_LENGTH, HeaderValue::from(size));
            }
            body
        }
        None => {
            if method != Method::GET && method != Method::HEAD {
                headers.insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
            }
            empty()
        }
    };
    let mut request = Request::new(body);
    *request.method_mut() = method;
    *request.uri_mut() = uri;
    *request.headers_mut() = headers;
    Ok(request)
}

/// The error of the client: an error of the body of the request as it is, else a connection error with the text of
/// each cause.
fn client_error(error: hyper_util::client::legacy::Error) -> Error {
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&error);
    let mut texts = Vec::new();
    while let Some(current) = source {
        if let Some(own) = current.downcast_ref::<Error>() {
            return own.clone();
        }
        let text = current.to_string();
        if texts.last() != Some(&text) {
            texts.push(text);
        }
        source = current.source();
    }
    Error::Connect(texts.join(": "))
}

/// Add a prefix to the text of a connection error or of another failure. The other errors stay as they are.
pub fn with_context(prefix: &str, error: Error) -> Error {
    match error {
        Error::Connect(text) => Error::Connect(format!("{prefix}: {text}")),
        Error::Internal(text) => Error::Internal(format!("{prefix}: {text}")),
        other => other,
    }
}

/// The body of a request. Its drop tells that the client wrote the request: the time limit of the headers starts.
struct RequestBody {
    inner: Body,
    sent: Option<oneshot::Sender<()>>,
}

impl Drop for RequestBody {
    fn drop(&mut self) {
        if let Some(sent) = self.sent.take() {
            let _ = sent.send(());
        }
    }
}

impl http_body::Body for RequestBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>>>> {
        Pin::new(&mut self.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// The body of an answer that stops when the operation is canceled or its deadline is past.
struct CtxBody {
    inner: Body,
    canceled: Pin<Box<dyn Future<Output = ()> + Send>>,
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl CtxBody {
    fn new(inner: Body, ctx: &OpCtx) -> Self {
        let token = ctx.cancel.clone();
        Self {
            inner,
            canceled: Box::pin(async move { token.canceled().await }),
            deadline: ctx
                .deadline
                .map(|deadline| Box::pin(tokio::time::sleep_until(deadline.into()))),
        }
    }
}

impl http_body::Body for CtxBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>>>> {
        let this = &mut *self;
        if this.canceled.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Some(Err(Error::Canceled)));
        }
        if let Some(deadline) = this.deadline.as_mut()
            && deadline.as_mut().poll(cx).is_ready()
        {
            return Poll::Ready(Some(Err(Error::Timeout)));
        }
        Pin::new(&mut this.inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// The body of an answer in gzip, decoded. The members of a file with more than one member follow each other.
struct GzipBody {
    inner: Body,
    decoder: MultiGzDecoder<Vec<u8>>,
    input: Bytes,
    started: bool,
    done: bool,
}

impl GzipBody {
    fn new(inner: Body) -> Self {
        Self {
            inner,
            decoder: MultiGzDecoder::new(Vec::new()),
            input: Bytes::new(),
            started: false,
            done: false,
        }
    }

    fn fail(&mut self, error: &std::io::Error) -> Poll<Option<Result<Frame<Bytes>>>> {
        self.done = true;
        Poll::Ready(Some(Err(Error::internal(format!("gzip error: {error}")))))
    }

    fn output(&mut self) -> Option<Bytes> {
        let out = std::mem::take(self.decoder.get_mut());
        (!out.is_empty()).then(|| Bytes::from(out))
    }
}

impl http_body::Body for GzipBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>>>> {
        let this = &mut *self;
        loop {
            if this.done {
                return Poll::Ready(None);
            }
            if !this.input.is_empty() {
                let step = this.input.len().min(GZIP_STEP);
                match this.decoder.write(&this.input[..step]) {
                    Ok(0) => {
                        let error = std::io::Error::new(std::io::ErrorKind::InvalidData, "the stream does not advance");
                        return this.fail(&error);
                    }
                    Ok(count) => this.input.advance(count),
                    Err(error) => return this.fail(&error),
                }
                if let Err(error) = this.decoder.flush() {
                    return this.fail(&error);
                }
                if let Some(out) = this.output() {
                    return Poll::Ready(Some(Ok(Frame::data(out))));
                }
                continue;
            }
            match ready!(Pin::new(&mut this.inner).poll_frame(cx)) {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data()
                        && !data.is_empty()
                    {
                        this.started = true;
                        this.input = data;
                    }
                }
                Some(Err(error)) => {
                    this.done = true;
                    return Poll::Ready(Some(Err(error)));
                }
                None => {
                    this.done = true;
                    if !this.started {
                        return Poll::Ready(None);
                    }
                    if let Err(error) = this.decoder.try_finish() {
                        let error = std::io::Error::new(error.kind(), format!("unexpected end of the stream: {error}"));
                        return this.fail(&error);
                    }
                    return Poll::Ready(this.output().map(|out| Ok(Frame::data(out))));
                }
            }
        }
    }
}

/// The verifier of `insecure_skip_verify`: it accepts each certificate, and it still checks the signatures of the
/// handshake.
#[derive(Debug)]
struct NoCertificateCheck {
    provider: Arc<CryptoProvider>,
}

impl NoCertificateCheck {
    fn algorithms(&self) -> &WebPkiSupportedAlgorithms {
        &self.provider.signature_verification_algorithms
    }
}

impl ServerCertVerifier for NoCertificateCheck {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, self.algorithms())
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, self.algorithms())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms().supported_schemes()
    }
}

/// The connector of the client: a TCP connection, then TLS for `https` with its own time limit.
#[derive(Clone)]
struct Connector {
    tcp: HttpConnector,
    tls: TlsConnector,
    handshake: Duration,
}

type ConnectError = Box<dyn std::error::Error + Send + Sync>;

impl tower_service::Service<Uri> for Connector {
    type Response = ProviderStream;
    type Error = ConnectError;
    type Future = Pin<Box<dyn Future<Output = std::result::Result<ProviderStream, ConnectError>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<std::result::Result<(), ConnectError>> {
        tower_service::Service::<Uri>::poll_ready(&mut self.tcp, cx).map_err(Into::into)
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let mut tcp = self.tcp.clone();
        let tls = self.tls.clone();
        let handshake = self.handshake;
        Box::pin(async move {
            let https = uri
                .scheme_str()
                .is_some_and(|scheme| scheme.eq_ignore_ascii_case("https"));
            let host = uri
                .host()
                .unwrap_or("")
                .trim_start_matches('[')
                .trim_end_matches(']')
                .to_owned();
            let stream = tower_service::Service::<Uri>::call(&mut tcp, uri).await?;
            if !https {
                return Ok(ProviderStream::Plain(stream));
            }
            let name = ServerName::try_from(host).map_err(|error| format!("invalid TLS server name: {error}"))?;
            let secured = tokio::time::timeout(handshake, tls.connect(name, stream.into_inner()))
                .await
                .map_err(|_| "TLS handshake timeout".to_owned())??;
            Ok(ProviderStream::Tls(Box::new(TokioIo::new(secured))))
        })
    }
}

/// A connection to a provider: plain TCP or TLS.
enum ProviderStream {
    Plain(TokioIo<TcpStream>),
    Tls(Box<TokioIo<TlsStream<TcpStream>>>),
}

impl Connection for ProviderStream {
    fn connected(&self) -> Connected {
        match self {
            Self::Plain(stream) => stream.connected(),
            Self::Tls(stream) => stream.inner().get_ref().0.connected(),
        }
    }
}

impl hyper::rt::Read for ProviderStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_read(cx, buf),
            Self::Tls(stream) => Pin::new(&mut **stream).poll_read(cx, buf),
        }
    }
}

impl hyper::rt::Write for ProviderStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write(cx, buf),
            Self::Tls(stream) => Pin::new(&mut **stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_flush(cx),
            Self::Tls(stream) => Pin::new(&mut **stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_shutdown(cx),
            Self::Tls(stream) => Pin::new(&mut **stream).poll_shutdown(cx),
        }
    }

    fn is_write_vectored(&self) -> bool {
        match self {
            Self::Plain(stream) => stream.is_write_vectored(),
            Self::Tls(stream) => stream.is_write_vectored(),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Plain(stream) => Pin::new(stream).poll_write_vectored(cx, bufs),
            Self::Tls(stream) => Pin::new(&mut **stream).poll_write_vectored(cx, bufs),
        }
    }
}
