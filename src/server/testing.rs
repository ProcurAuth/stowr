//! The test kit of the HTTP layer: an application over back ends in memory, and requests that pass the whole
//! dispatch (the middlewares, the router and the final form of the answer) without a network.
//!
//! ```ignore
//! let (app, _, rw) = testing::memory_app();
//! let answer = testing::get(&app, "/api/list?instance=rw").await;
//! assert_eq!(answer.status, 200);
//! ```

use std::collections::BTreeMap;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use http::header::{CONTENT_LENGTH, HOST, HeaderName, HeaderValue};
use http::{HeaderMap, Method, Uri, Version};
use http_body_util::BodyExt;

use crate::common::app::App;
use crate::common::config::{BucketConfig, Config, PERMISSION_DELETE, PERMISSION_READ, PERMISSION_WRITE};
use crate::common::http::{Body, empty, full};
use crate::common::storage::Backend;
use crate::instance::Instance;
use crate::instance::gate::Gate;
use crate::testkit::MemoryBackend;

/// An answer, with its body and its trailers read.
#[derive(Debug)]
pub struct TestResponse {
    /// The status.
    pub status: u16,
    /// The headers.
    pub headers: HeaderMap,
    /// The body.
    pub body: Bytes,
    /// The trailers, when the body sent them.
    pub trailers: Option<HeaderMap>,
}

impl TestResponse {
    /// The first value of a header, or an empty text.
    pub fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
    }

    /// Each value of a header.
    pub fn header_values(&self, name: &str) -> Vec<String> {
        self.headers
            .get_all(name)
            .iter()
            .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
            .collect()
    }

    /// The body as text.
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// The body as JSON (`null` for a body that is not JSON).
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap_or(serde_json::Value::Null)
    }
}

/// A request to send to an application.
#[derive(Debug)]
pub struct TestRequest {
    method: Method,
    target: String,
    headers: HeaderMap,
    body: Option<Bytes>,
}

impl TestRequest {
    /// A request with a method and a target (`/path?query`), with `Host: example.com`.
    pub fn new(method: &str, target: &str) -> Self {
        let mut headers = HeaderMap::new();
        headers.insert(HOST, HeaderValue::from_static("example.com"));
        Self {
            method: Method::from_bytes(method.as_bytes()).unwrap_or(Method::GET),
            target: target.to_owned(),
            headers,
            body: None,
        }
    }

    /// A `GET` request.
    pub fn get(target: &str) -> Self {
        Self::new("GET", target)
    }

    /// Set a header (a second call with the same name adds a value).
    pub fn header(mut self, name: &str, value: &str) -> Self {
        if let (Ok(name), Ok(value)) = (
            HeaderName::from_bytes(name.as_bytes()),
            HeaderValue::from_bytes(value.as_bytes()),
        ) {
            if name == HOST {
                self.headers.insert(name, value);
            } else {
                self.headers.append(name, value);
            }
        }
        self
    }

    /// Set the body and its `Content-Length`.
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        let body = body.into();
        self.headers.insert(CONTENT_LENGTH, HeaderValue::from(body.len()));
        self.body = Some(body);
        self
    }

    /// Send the request to the whole dispatch.
    pub async fn send(self, app: &Arc<App>) -> TestResponse {
        let uri: Uri = self.target.parse().unwrap_or_else(|_| Uri::from_static("/"));
        let body: Body = match self.body {
            Some(body) => full(body),
            None => empty(),
        };
        let method = self.method.clone();
        let response = match super::runtime::request_from_parts(self.method, &uri, Version::HTTP_11, self.headers, body)
        {
            Ok((req, target)) => {
                let response = super::handle(app.clone(), req, target).await;
                super::runtime::finalize(&method, response).await
            }
            Err(response) => *response,
        };
        collect(response).await
    }
}

/// Read an answer: its body and its trailers.
pub async fn collect(response: crate::common::http::Response) -> TestResponse {
    let (parts, mut body) = response.into_parts();
    let mut data = BytesMut::new();
    let mut trailers = None;
    while let Some(frame) = body.frame().await {
        let Ok(frame) = frame else {
            break;
        };
        match frame.into_data() {
            Ok(chunk) => data.extend_from_slice(&chunk),
            Err(frame) => trailers = frame.into_trailers().ok(),
        }
    }
    TestResponse {
        status: parts.status.as_u16(),
        headers: parts.headers,
        body: data.freeze(),
        trailers,
    }
}

/// Send a `GET` request.
pub async fn get(app: &Arc<App>, target: &str) -> TestResponse {
    TestRequest::get(target).send(app).await
}

/// The configuration of a test bucket: the auth block `test-auth`, the provider `s3`, the bucket `<id>-bucket`, the
/// region `test`, and the permissions.
pub fn bucket_config(id: &str, root_prefix: &str, permissions: &[&str]) -> BucketConfig {
    BucketConfig {
        id: id.to_owned(),
        name: id.to_owned(),
        auth_id: "test-auth".to_owned(),
        provider: "s3".to_owned(),
        bucket: format!("{id}-bucket"),
        region: "test".to_owned(),
        permissions: permissions.iter().map(|permission| (*permission).to_owned()).collect(),
        permissions_defined: true,
        root_prefix: root_prefix.to_owned(),
        ..BucketConfig::default()
    }
}

/// The configuration of the tests: the default limits and a history of 10 jobs.
pub fn test_config() -> Config {
    Config {
        listen: "127.0.0.1:0".to_owned(),
        job_history_limit: 10,
        ..Config::default()
    }
}

/// An instance over a back end, with the limits of a configuration.
pub fn instance_with(config: &Config, cfg: BucketConfig, backend: Arc<dyn Backend>) -> Arc<Instance> {
    let policy = Arc::new(config.runtime.clone());
    let gate = Gate::new(policy.max_concurrent_storage_requests);
    Arc::new(Instance::new(cfg, backend, policy, gate))
}

/// An instance over a back end, with the default limits.
pub fn instance(cfg: BucketConfig, backend: Arc<dyn Backend>) -> Arc<Instance> {
    instance_with(&test_config(), cfg, backend)
}

/// An application over instances, with a configuration.
pub fn app_with(config: Config, instances: Vec<Arc<Instance>>) -> Arc<App> {
    let access = crate::access::AccessLayer::new(&config).unwrap_or_else(|error| panic!("access layer: {error}"));
    super::assemble::assemble(Arc::new(config), BTreeMap::new(), instances, access)
        .unwrap_or_else(|error| panic!("application: {error}"))
}

/// An application over instances, with the test configuration.
pub fn app_of(instances: Vec<Arc<Instance>>) -> Arc<App> {
    app_with(test_config(), instances)
}

/// The application of the route tests: `readonly` (read only, the object `readonly.txt`) and `rw` (read, write and
/// delete, root prefix `tenant/`, three objects). It gives the application and the two back ends.
pub fn memory_app() -> (Arc<App>, Arc<MemoryBackend>, Arc<MemoryBackend>) {
    let readonly = Arc::new(MemoryBackend::with_objects(&[("readonly.txt", "read")]));
    let rw = Arc::new(MemoryBackend::with_objects(&[
        ("tenant/folder/direct.txt", "direct"),
        ("tenant/folder/nested/deep.txt", "deep"),
        ("tenant/a//./../b\\c", "opaque"),
    ]));
    let app = app_of(vec![
        instance(bucket_config("readonly", "", &[PERMISSION_READ]), readonly.clone()),
        instance(
            bucket_config("rw", "tenant/", &[PERMISSION_READ, PERMISSION_WRITE, PERMISSION_DELETE]),
            rw.clone(),
        ),
    ]);
    (app, readonly, rw)
}
