// SPDX-License-Identifier: MIT OR Apache-2.0
//! A local HTTP server for the tests of the provider clients. Each request goes to a handler with its body read. The
//! server can also speak TLS with the fixture certificate of this module.

use std::convert::Infallible;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt as _, Full};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::TcpListener;

use crate::common::BoxFuture;
use crate::common::query::{Query, unescape};

/// The root of the fixture certificates (an EC P-256 certificate authority).
pub const TEST_ROOT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBmzCCAUGgAwIBAgIUX0MCoPY+wM8lmFEw7sOUQuqTe1gwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPU3Rvd3IgVGVzdCBSb290MCAXDTI1MDEwMTAwMDAwMFoYDzIx
MjUwMTAxMDAwMDAwWjAaMRgwFgYDVQQDDA9TdG93ciBUZXN0IFJvb3QwWTATBgcq
hkjOPQIBBggqhkjOPQMBBwNCAAQStK3A6h/buDm7lLDAwmeSPAoVoCDGkXCBf6zy
t7gs26hEuKjzihJYvO5b/UpYaL/Om7PTS6FKOGgLUBxo+xxfo2MwYTAdBgNVHQ4E
FgQUNI44FtioKJjp98ZRIbcbXYFfJCUwHwYDVR0jBBgwFoAUNI44FtioKJjp98ZR
IbcbXYFfJCUwDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZI
zj0EAwIDSAAwRQIhAMHyW1eqOs3krJZ5PV4yOIviCFm7BpF2ynXOheJtGPxmAiBU
a6Q6onNhY0+Oso+aBKFPEPXxsYJpbCXXN3mhcNLTyA==
-----END CERTIFICATE-----
";

/// The certificate of the test server: `localhost` and `127.0.0.1`, signed by [`TEST_ROOT_PEM`].
const SERVER_CERTIFICATE_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIBxjCCAWugAwIBAgIUe9vJimh33NbwJhMhpAattSYVTpEwCgYIKoZIzj0EAwIw
GjEYMBYGA1UEAwwPU3Rvd3IgVGVzdCBSb290MCAXDTI1MDEwMTAwMDAwMFoYDzIx
MjUwMTAxMDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAQOs+RMA1+S+bvGl5g93Q0hZEI6/QvVgFBYzPAaw0BD0/W5
HE+iuY9PWlg77BJoKzz56hR7dn0he0BAwtOilgFio4GSMIGPMAwGA1UdEwEB/wQC
MAAwDgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMBoGA1UdEQQT
MBGCCWxvY2FsaG9zdIcEfwAAATAdBgNVHQ4EFgQUx3as4RIXK71vr9uY85il382H
XCAwHwYDVR0jBBgwFoAUNI44FtioKJjp98ZRIbcbXYFfJCUwCgYIKoZIzj0EAwID
SQAwRgIhAMQSDT6yZDeibEeHqf4i2KpDK0Iv9NoX972cCpBd4V1JAiEAqJXt0sdw
OfHMrBUo9jzBU7vgI50lrUC9aOa0VU8nz28=
-----END CERTIFICATE-----
";

/// The private key of [`SERVER_CERTIFICATE_PEM`] (PKCS #8). It is a public test key, made for these tests only. It protects nothing.
const SERVER_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg1xsPtwh5tsVRrKel
uun2yhYtGW4iM2pC/t4egiJ2UjahRANCAAQOs+RMA1+S+bvGl5g93Q0hZEI6/QvV
gFBYzPAaw0BD0/W5HE+iuY9PWlg77BJoKzz56hR7dn0he0BAwtOilgFi
-----END PRIVATE KEY-----
";

/// One request that the test server got.
#[derive(Clone, Debug)]
pub struct TestRequest {
    /// The method.
    pub method: Method,
    /// The path with its escapes decoded.
    pub path: String,
    /// The path as the client sent it.
    pub raw_path: String,
    /// The query as the client sent it.
    pub raw_query: String,
    /// The parsed query.
    pub query: Query,
    /// The headers.
    pub headers: HeaderMap,
    /// The body.
    pub body: Bytes,
}

impl TestRequest {
    /// The first value of a header, or an empty text.
    pub fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
    }

    /// The body as text.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// The answer of a handler.
#[derive(Clone, Debug, Default)]
pub struct TestResponse {
    /// The status.
    pub status: u16,
    /// The headers.
    pub headers: HeaderMap,
    /// The body.
    pub body: Bytes,
}

impl TestResponse {
    /// An answer without a body.
    pub fn status(status: u16) -> Self {
        Self {
            status,
            ..Self::default()
        }
    }

    /// An answer with a body.
    pub fn body(status: u16, body: impl Into<Bytes>) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
            body: body.into(),
        }
    }

    /// The same answer with one more header.
    pub fn header(mut self, name: &'static str, value: &str) -> Self {
        self.headers.append(
            name,
            HeaderValue::from_str(value).unwrap_or(HeaderValue::from_static("")),
        );
        self
    }
}

/// The handler of the test server.
pub type Handler = Arc<dyn Fn(TestRequest) -> BoxFuture<'static, TestResponse> + Send + Sync>;

/// The problems that a handler saw. A test checks at its end that the list is empty.
#[derive(Debug, Default)]
pub struct Problems(Mutex<Vec<String>>);

impl Problems {
    /// Keep a problem.
    pub fn report(&self, text: impl Into<String>) {
        self.0.lock().unwrap().push(text.into());
    }

    /// Fail the test when a handler saw a problem.
    pub fn check(&self) {
        let problems = self.0.lock().unwrap();
        assert!(problems.is_empty(), "the server saw problems: {problems:#?}");
    }
}

/// A test server. Its drop stops it.
pub struct TestServer {
    /// The base URL: `http://127.0.0.1:<port>` or `https://127.0.0.1:<port>`.
    pub url: String,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The TLS configuration of the test server with the fixture certificate.
pub fn tls_config() -> Arc<rustls::ServerConfig> {
    let certificates = CertificateDer::pem_slice_iter(SERVER_CERTIFICATE_PEM.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let key = PrivateKeyDer::from_pem_slice(SERVER_KEY_PEM.as_bytes()).unwrap();
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .unwrap();
    Arc::new(config)
}

/// The roots that trust the fixture certificate.
pub fn test_roots() -> Arc<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    for certificate in CertificateDer::pem_slice_iter(TEST_ROOT_PEM.as_bytes()) {
        roots.add(certificate.unwrap()).unwrap();
    }
    Arc::new(roots)
}

async fn answer(handler: Handler, request: Request<Incoming>) -> Result<Response<Full<Bytes>>, Infallible> {
    let (parts, body) = request.into_parts();
    let body = body.collect().await.map(|body| body.to_bytes()).unwrap_or_default();
    let raw_path = parts.uri.path().to_owned();
    let raw_query = parts.uri.query().unwrap_or("").to_owned();
    let request = TestRequest {
        method: parts.method,
        path: unescape(&raw_path, false).unwrap_or_else(|| raw_path.clone()),
        raw_path,
        query: Query::parse(&raw_query),
        raw_query,
        headers: parts.headers,
        body,
    };
    let reply = handler(request).await;
    let mut response = Response::new(Full::new(reply.body));
    *response.status_mut() = StatusCode::from_u16(reply.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    *response.headers_mut() = reply.headers;
    Ok(response)
}

impl TestServer {
    /// Start a server with a handler that answers at once.
    pub async fn start(handler: impl Fn(TestRequest) -> TestResponse + Send + Sync + 'static) -> Self {
        let handler = Arc::new(handler);
        Self::start_async(Arc::new(move |request| {
            let reply = handler(request);
            Box::pin(async move { reply })
        }))
        .await
    }

    /// Start a server with a handler that can wait.
    pub async fn start_async(handler: Handler) -> Self {
        Self::launch(handler, None).await
    }

    /// Start a server that speaks TLS with the fixture certificate.
    pub async fn start_tls(handler: impl Fn(TestRequest) -> TestResponse + Send + Sync + 'static) -> Self {
        let handler = Arc::new(handler);
        Self::launch(
            Arc::new(move |request| {
                let reply = handler(request);
                Box::pin(async move { reply })
            }),
            Some(tokio_rustls::TlsAcceptor::from(tls_config())),
        )
        .await
    }

    async fn launch(handler: Handler, tls: Option<tokio_rustls::TlsAcceptor>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let scheme = if tls.is_some() { "https" } else { "http" };
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let handler = handler.clone();
                let tls = tls.clone();
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(move |request| answer(handler.clone(), request));
                    let builder = hyper::server::conn::http1::Builder::new();
                    match tls {
                        Some(acceptor) => {
                            if let Ok(stream) = acceptor.accept(stream).await {
                                let _ = builder.serve_connection(TokioIo::new(stream), service).await;
                            }
                        }
                        None => {
                            let _ = builder.serve_connection(TokioIo::new(stream), service).await;
                        }
                    }
                });
            }
        });
        Self {
            url: format!("{scheme}://{address}"),
            task,
        }
    }
}
