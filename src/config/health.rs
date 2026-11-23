//! The request of `stowr healthcheck`: one `GET` of the health URL, with a deadline of 3 seconds for the connection,
//! the TLS handshake and the headers of the answer. The request follows no redirect and uses no proxy. An answer
//! other than 200 is a failure.

use std::sync::Arc;
use std::time::Duration;

use http_body_util::Empty;
use hyper_util::rt::TokioIo;
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, ServerName};
use tokio::io::{AsyncRead, AsyncWrite};

use super::oserror::cause;
use super::quote::quote;
use super::url::{Url, join_host_port, parse};

/// The deadline of the health check.
const DEADLINE: Duration = Duration::from_secs(3);

/// The certificate bundles of the system, in the order of the search. The first file that the process can read
/// gives the root certificates of an `https` URL.
const ROOT_BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/pki/tls/cacert.pem",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/cert.pem",
];

/// Why the health check failed.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Failure {
    /// The URL is not valid: `healthcheck request: ...`.
    Request(String),
    /// The request or the answer failed: `healthcheck failed: ...`.
    Failed(String),
}

/// Send `GET` to the URL and expect the status 200.
pub(super) fn check(raw: &str) -> Result<(), Failure> {
    let url = parse(raw).map_err(Failure::Request)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| Failure::Failed(format!("cannot start the runtime: {}", cause(&error))))?;
    let status = runtime.block_on(async {
        match tokio::time::timeout(DEADLINE, get(&url, raw)).await {
            Ok(result) => result,
            Err(_) => Err(format!("Get {}: no answer in 3 seconds", quote(raw))),
        }
    });
    match status {
        Ok(200) => Ok(()),
        Ok(status) => Err(Failure::Failed(format!("HTTP {status}"))),
        Err(message) => Err(Failure::Failed(message)),
    }
}

/// The target of the request line: the path with its escapes (or `/`) and the query.
fn request_target(url: &Url) -> String {
    let mut target = if url.opaque.is_empty() {
        let path = url.escaped_path();
        if path.is_empty() { "/".to_owned() } else { path }
    } else if url.opaque.starts_with("//") {
        format!("{}:{}", url.scheme, url.opaque)
    } else {
        url.opaque.clone()
    };
    if url.force_query || !url.raw_query.is_empty() {
        target.push('?');
        target.push_str(&url.raw_query);
    }
    target
}

async fn get(url: &Url, raw: &str) -> Result<u16, String> {
    let fail = |message: String| format!("cannot get {}: {message}", quote(raw));
    let default_port = match url.scheme.as_str() {
        "http" => "80",
        "https" => "443",
        other => return Err(fail(format!("the scheme {} is not supported", quote(other)))),
    };
    let host_header = url.host.strip_suffix(':').unwrap_or(&url.host).to_owned();
    if host_header.is_empty() {
        return Err(fail("the URL has no host".to_owned()));
    }
    let hostname = url.hostname().to_owned();
    let port = if url.port().is_empty() {
        default_port
    } else {
        url.port()
    };
    let port_number: u16 = port
        .parse()
        .map_err(|_| fail(format!("the port {port} is not valid")))?;
    let address = join_host_port(&hostname, port);
    let addresses: Vec<std::net::SocketAddr> = tokio::net::lookup_host((hostname.as_str(), port_number))
        .await
        .map_err(|error| fail(format!("cannot resolve the host {hostname}: {}", cause(&error))))?
        .collect();
    let mut last_error = None;
    let mut stream = None;
    for candidate in addresses {
        match tokio::net::TcpStream::connect(candidate).await {
            Ok(connected) => {
                stream = Some(connected);
                break;
            }
            Err(error) => last_error = Some(error),
        }
    }
    let Some(stream) = stream else {
        let message = last_error.map_or_else(|| "no address".to_owned(), |error| cause(&error));
        return Err(fail(format!("cannot connect to {address}: {message}")));
    };
    let target = request_target(url);
    if url.scheme == "https" {
        let config = tls_config().map_err(fail)?;
        let name = ServerName::try_from(hostname.clone())
            .map_err(|_| fail(format!("invalid TLS server name {}", quote(&hostname))))?;
        let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
            .connect(name, stream)
            .await
            .map_err(|error| fail(format!("TLS error: {error}")))?;
        return send(tls, &target, &host_header).await.map_err(fail);
    }
    send(stream, &target, &host_header).await.map_err(fail)
}

/// The TLS configuration: TLS 1.2 or 1.3, the root certificates of the bundle of the system.
fn tls_config() -> Result<rustls::ClientConfig, String> {
    let mut roots = rustls::RootCertStore::empty();
    let bundle = ROOT_BUNDLES
        .iter()
        .find_map(|path| std::fs::read(path).ok())
        .ok_or_else(|| "the system has no bundle of root certificates for TLS".to_owned())?;
    for certificate in CertificateDer::pem_slice_iter(&bundle).flatten() {
        let _ = roots.add(certificate);
    }
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|error| format!("TLS error: {error}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(config)
}

async fn send<S>(stream: S, target: &str, host: &str) -> Result<u16, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake::<_, Empty<bytes::Bytes>>(TokioIo::new(stream))
            .await
            .map_err(|error| error.to_string())?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri(target)
        .header(http::header::HOST, host)
        .body(Empty::new())
        .map_err(|error| error.to_string())?;
    let response = sender.send_request(request).await.map_err(|error| error.to_string())?;
    Ok(response.status().as_u16())
}

/// The health URL of a listen address: the loopback address for an address without a host or for an address of
/// each interface.
pub(super) fn url_from_listen(listen: &str) -> String {
    let listen = listen.trim();
    let Ok((host, port)) = super::url::split_host_port(listen) else {
        if listen.starts_with(':') {
            return format!("http://127.0.0.1{listen}/healthz");
        }
        return "http://127.0.0.1:8080/healthz".to_owned();
    };
    let host = if host.is_empty() || host == "0.0.0.0" || host == "::" {
        "127.0.0.1"
    } else {
        host
    };
    format!("http://{}/healthz", join_host_port(host, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_health_url_uses_the_loopback_address_for_each_interface() {
        assert_eq!(url_from_listen(":8080"), "http://127.0.0.1:8080/healthz");
        assert_eq!(url_from_listen("0.0.0.0:9000"), "http://127.0.0.1:9000/healthz");
        assert_eq!(url_from_listen("[::]:9000"), "http://127.0.0.1:9000/healthz");
        assert_eq!(url_from_listen("[::1]:9000"), "http://[::1]:9000/healthz");
        assert_eq!(url_from_listen("10.0.0.5:81"), "http://10.0.0.5:81/healthz");
        assert_eq!(url_from_listen("bad"), "http://127.0.0.1:8080/healthz");
    }

    #[test]
    fn the_request_target_has_the_path_and_the_query() {
        let target = |raw: &str| request_target(&parse(raw).unwrap());
        assert_eq!(target("http://h"), "/");
        assert_eq!(target("http://h/healthz"), "/healthz");
        assert_eq!(target("http://h/a%20b?x=1"), "/a%20b?x=1");
        assert_eq!(target("http://h/x?"), "/x?");
    }

    #[test]
    fn a_url_that_is_not_http_fails() {
        assert_eq!(
            check("ftp://h/x"),
            Err(Failure::Failed(
                "cannot get \"ftp://h/x\": the scheme \"ftp\" is not supported".to_owned()
            ))
        );
        assert_eq!(
            check("/healthz"),
            Err(Failure::Failed(
                "cannot get \"/healthz\": the scheme \"\" is not supported".to_owned()
            ))
        );
        assert_eq!(
            check("http:///healthz"),
            Err(Failure::Failed(
                "cannot get \"http:///healthz\": the URL has no host".to_owned()
            ))
        );
        assert_eq!(
            check("http://h:x/"),
            Err(Failure::Request(
                "invalid URL \"http://h:x/\": invalid port \":x\"".to_owned()
            ))
        );
    }
}
