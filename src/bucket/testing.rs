//! The helpers of the tests of this folder. They are a fake S3 provider, a back end that exposes it, and a fake admin
//! API. They also build an application, instances and requests.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method};

use super::support::{S3Call, XmlNode, parse_xml};
use super::usage_admin::{AdminAnswer, AdminFailure, AdminTransport};
use super::{
    BucketEncryption, EncryptionReader, MetadataEditor, ObjectLockConfiguration, ObjectLockManager, Retention,
};
use crate::access::{AccessLayer, OpenGuard};
use crate::common::BoxFuture;
use crate::common::app::App;
use crate::common::config::{BucketConfig, Config, RuntimePolicy};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Body, Req, Response, empty, full, read_limited};
use crate::common::query::Query;
use crate::common::storage::{
    Backend, DiscoveredCapabilities, ListOptions, ListPage, MultipartCopier, MultipartCopyOptions, ObjectResponse,
    ObjectVersionPage, VersionStore,
};
use crate::instance::Instance;
use crate::instance::gate::Gate;
use crate::provider::s3::{S3Answer, S3Request};
use crate::testkit::MemoryBackend;

/// One request that the fake provider received.
#[derive(Clone, Debug)]
pub struct Recorded {
    /// The method.
    pub method: Method,
    /// The key (empty for the bucket).
    pub key: String,
    /// The query pairs.
    pub query: Vec<(String, String)>,
    /// The headers.
    pub headers: HeaderMap,
    /// The body as text.
    pub body: String,
}

impl Recorded {
    /// True when the query has the name.
    pub fn has(&self, name: &str) -> bool {
        self.query.iter().any(|(key, _)| key == name)
    }

    /// The value of a query name, or an empty text.
    pub fn value(&self, name: &str) -> &str {
        self.query
            .iter()
            .find(|(key, _)| key == name)
            .map_or("", |(_, value)| value.as_str())
    }

    /// The value of a header, or an empty text.
    pub fn header(&self, name: &str) -> &str {
        self.headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
    }
}

/// The answer of the fake provider.
#[derive(Clone, Debug, Default)]
pub struct Reply {
    /// The status.
    pub status: u16,
    /// The headers.
    pub headers: HeaderMap,
    /// The body.
    pub body: String,
}

impl Reply {
    /// An answer with a status and a body.
    pub fn new(status: u16, body: &str) -> Self {
        Self {
            status,
            headers: HeaderMap::new(),
            body: body.to_owned(),
        }
    }

    /// The same answer with a header.
    pub fn with_header(mut self, name: &'static str, value: &str) -> Self {
        if let Ok(value) = HeaderValue::from_str(value) {
            self.headers.insert(HeaderName::from_static(name), value);
        }
        self
    }
}

/// A function that answers each request.
pub type Handler = Box<dyn FnMut(&Recorded) -> Reply + Send>;

/// A fake S3 provider. It records each request and answers with its handler.
pub struct FakeS3 {
    /// The configuration of the bucket.
    pub cfg: BucketConfig,
    requests: Mutex<Vec<Recorded>>,
    handler: Mutex<Handler>,
}

impl FakeS3 {
    /// A provider with a handler. The bucket is `bucket`.
    pub fn new(handler: impl FnMut(&Recorded) -> Reply + Send + 'static) -> Arc<Self> {
        Arc::new(Self {
            cfg: bucket_config("rw"),
            requests: Mutex::new(Vec::new()),
            handler: Mutex::new(Box::new(handler)),
        })
    }

    /// A provider with a configuration of the bucket and a handler.
    pub fn with_config(cfg: BucketConfig, handler: impl FnMut(&Recorded) -> Reply + Send + 'static) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            requests: Mutex::new(Vec::new()),
            handler: Mutex::new(Box::new(handler)),
        })
    }

    /// A provider that answers each request with the same status and body.
    pub fn constant(status: u16, body: &str) -> Arc<Self> {
        let body = body.to_owned();
        Self::new(move |_| Reply::new(status, &body))
    }

    /// The requests that arrived.
    pub fn requests(&self) -> Vec<Recorded> {
        self.requests.lock().map(|list| list.clone()).unwrap_or_default()
    }

    /// Answer one request, and record it.
    pub fn serve(&self, recorded: Recorded) -> Reply {
        if let Ok(mut list) = self.requests.lock() {
            list.push(recorded.clone());
        }
        match self.handler.lock() {
            Ok(mut handler) => handler(&recorded),
            Err(_) => Reply::new(500, ""),
        }
    }
}

/// The provider error of a fake answer: the `Code` and the `Message` of the XML body.
pub fn fake_provider_error(status: u16, body: &[u8]) -> Error {
    let node: Option<XmlNode> = parse_xml(body).ok().flatten();
    let (code, message) = node.map_or((String::new(), String::new()), |node| {
        (
            node.text_at(&["Code"]).to_owned(),
            node.text_at(&["Message"]).to_owned(),
        )
    });
    Error::upstream(status, code, message)
}

impl S3Call for FakeS3 {
    fn call<'a>(&'a self, _ctx: &'a OpCtx, request: S3Request<'a>, limit: usize) -> BoxFuture<'a, Result<S3Answer>> {
        Box::pin(async move {
            let body = match request.body {
                Some((body, _)) => read_limited(body, usize::MAX).await?.0,
                None => Bytes::new(),
            };
            let recorded = Recorded {
                method: request.method,
                key: request.key.to_owned(),
                query: request.query,
                headers: request.headers,
                body: String::from_utf8_lossy(&body).into_owned(),
            };
            let reply = self.serve(recorded);
            let mut answer_body = reply.body.into_bytes();
            answer_body.truncate(limit);
            Ok(S3Answer {
                status: reply.status,
                headers: reply.headers,
                body: Bytes::from(answer_body),
            })
        })
    }

    fn provider_error(&self, answer: &S3Answer) -> Error {
        fake_provider_error(answer.status, &answer.body)
    }

    fn bucket_config(&self) -> &BucketConfig {
        &self.cfg
    }
}

/// A function that gives an object response for a key.
pub type ReadFn = Arc<dyn Fn(&str) -> Result<ObjectResponse> + Send + Sync>;
/// A function that gives a page of a listing.
pub type ListFn = Arc<dyn Fn(&ListOptions) -> Result<ListPage> + Send + Sync>;

/// A back end that exposes the functions of this folder over a fake provider. The objects are in memory.
pub struct FakeBackend {
    /// The fake provider.
    pub s3: Arc<FakeS3>,
    /// The objects.
    pub memory: MemoryBackend,
    /// True for a back end with Object Lock.
    pub lock: bool,
    /// True for a back end that reads the default encryption.
    pub encryption: bool,
    /// True for a back end that edits the metadata.
    pub metadata: bool,
    /// The flavour that the lifecycle probe finds.
    pub flavour: Option<String>,
    /// A HEAD that replaces the HEAD of the memory.
    pub head_fn: Mutex<Option<ReadFn>>,
    /// A GET that replaces the GET of the memory.
    pub get_fn: Mutex<Option<ReadFn>>,
    /// A listing that replaces the listing of the memory.
    pub list_fn: Mutex<Option<ListFn>>,
    /// The copies in parts that the back end received: the source, the destination and the options.
    pub copies: Mutex<Vec<(String, String, MultipartCopyOptions)>>,
}

impl FakeBackend {
    /// A back end over a fake provider, with the three functions and no flavour.
    pub fn new(s3: Arc<FakeS3>) -> Arc<Self> {
        Arc::new(Self {
            s3,
            memory: MemoryBackend::default(),
            lock: true,
            encryption: true,
            metadata: true,
            flavour: None,
            head_fn: Mutex::new(None),
            get_fn: Mutex::new(None),
            list_fn: Mutex::new(None),
            copies: Mutex::new(Vec::new()),
        })
    }

    /// The same back end with other flags.
    pub fn flags(s3: Arc<FakeS3>, lock: bool, encryption: bool, metadata: bool, flavour: Option<&str>) -> Arc<Self> {
        Arc::new(Self {
            s3,
            memory: MemoryBackend::default(),
            lock,
            encryption,
            metadata,
            flavour: flavour.map(str::to_owned),
            head_fn: Mutex::new(None),
            get_fn: Mutex::new(None),
            list_fn: Mutex::new(None),
            copies: Mutex::new(Vec::new()),
        })
    }

    fn replaced<T: Clone>(slot: &Mutex<Option<T>>) -> Option<T> {
        slot.lock().ok().and_then(|value| value.clone())
    }
}

/// An object response with a status, headers and a body.
pub fn object_response(status: u16, headers: HeaderMap, body: &str) -> ObjectResponse {
    ObjectResponse {
        status,
        headers,
        body: if body.is_empty() {
            empty()
        } else {
            full(body.to_owned())
        },
    }
}

impl Backend for FakeBackend {
    fn list<'a>(&'a self, ctx: &'a OpCtx, options: &'a ListOptions) -> BoxFuture<'a, Result<ListPage>> {
        match Self::replaced(&self.list_fn) {
            Some(list) => Box::pin(async move { list(options) }),
            None => self.memory.list(ctx, options),
        }
    }

    fn head<'a>(&'a self, ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<ObjectResponse>> {
        if let Some(head) = Self::replaced(&self.head_fn) {
            return Box::pin(async move { head(key) });
        }
        let version = ctx.version().to_owned();
        Box::pin(async move {
            let mut query = Vec::new();
            if !version.is_empty() {
                query.push(("versionId".to_owned(), version));
            }
            let reply = self.s3.serve(Recorded {
                method: Method::HEAD,
                key: key.to_owned(),
                query,
                headers: HeaderMap::new(),
                body: String::new(),
            });
            if reply.status >= 300 {
                return Err(Error::upstream(reply.status, "", ""));
            }
            Ok(object_response(reply.status, reply.headers, ""))
        })
    }

    fn get<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        match Self::replaced(&self.get_fn) {
            Some(get) => Box::pin(async move { get(key) }),
            None => self.memory.get(ctx, key, headers),
        }
    }

    fn put<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        body: Body,
        size: i64,
        content_type: &'a str,
    ) -> BoxFuture<'a, Result<()>> {
        self.memory.put(ctx, key, body, size, content_type)
    }

    fn delete<'a>(&'a self, ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<()>> {
        self.memory.delete(ctx, key)
    }

    fn copy<'a>(&'a self, ctx: &'a OpCtx, source: &'a str, destination: &'a str) -> BoxFuture<'a, Result<()>> {
        self.memory.copy(ctx, source, destination)
    }

    fn discover_capabilities<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<DiscoveredCapabilities>> {
        self.memory.discover_capabilities(ctx)
    }

    fn object_lock(&self) -> Option<&dyn ObjectLockManager> {
        self.lock.then_some(self as &dyn ObjectLockManager)
    }

    fn encryption_reader(&self) -> Option<&dyn EncryptionReader> {
        self.encryption.then_some(self as &dyn EncryptionReader)
    }

    fn metadata_editor(&self) -> Option<&dyn MetadataEditor> {
        self.metadata.then_some(self as &dyn MetadataEditor)
    }

    fn multipart_copier(&self) -> Option<&dyn MultipartCopier> {
        Some(self)
    }

    fn version_store(&self) -> Option<&dyn VersionStore> {
        Some(self)
    }

    fn bucket_rules(&self) -> Option<&dyn crate::lifecycle::BucketRules> {
        self.flavour
            .is_some()
            .then_some(self as &dyn crate::lifecycle::BucketRules)
    }
}

impl ObjectLockManager for FakeBackend {
    fn configuration<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<ObjectLockConfiguration>> {
        Box::pin(async move { super::object_lock::read_configuration(self.s3.as_ref(), ctx).await })
    }

    fn retention<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        version: &'a str,
    ) -> BoxFuture<'a, Result<Option<Retention>>> {
        Box::pin(async move { super::object_lock::read_retention(self.s3.as_ref(), ctx, key, version).await })
    }

    fn legal_hold<'a>(&'a self, ctx: &'a OpCtx, key: &'a str, version: &'a str) -> BoxFuture<'a, Result<bool>> {
        Box::pin(async move { super::object_lock::read_legal_hold(self.s3.as_ref(), ctx, key, version).await })
    }

    fn put_retention<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        version: &'a str,
        retention: &'a Retention,
        bypass_governance: bool,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            super::object_lock::write_retention(self.s3.as_ref(), ctx, key, version, retention, bypass_governance).await
        })
    }

    fn put_legal_hold<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        version: &'a str,
        on: bool,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { super::object_lock::write_legal_hold(self.s3.as_ref(), ctx, key, version, on).await })
    }
}

impl EncryptionReader for FakeBackend {
    fn bucket_encryption<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<Option<BucketEncryption>>> {
        Box::pin(async move { super::encryption::read_bucket_encryption(self.s3.as_ref(), ctx).await })
    }
}

impl MetadataEditor for FakeBackend {
    fn replace_metadata<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        version: &'a str,
        etag: &'a str,
        headers: &'a http::HeaderMap,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            super::metadata::replace_object_metadata(self.s3.as_ref(), ctx, key, version, etag, headers).await
        })
    }
}

// --- The configuration, the instances, the application and the requests -------------------------------------------

/// The configuration of a bucket of the tests: the label, the root prefix `tenant/` and no restriction.
pub fn bucket_config(id: &str) -> BucketConfig {
    BucketConfig {
        id: id.to_owned(),
        name: id.to_owned(),
        auth_id: "a".to_owned(),
        provider: "s3".to_owned(),
        bucket: "bucket".to_owned(),
        root_prefix: "tenant/".to_owned(),
        max_scan_pages: 10,
        ..BucketConfig::default()
    }
}

/// An instance over a back end.
pub fn instance_of(cfg: BucketConfig, backend: Arc<dyn Backend>) -> Arc<Instance> {
    Arc::new(Instance::new(
        cfg,
        backend,
        Arc::new(RuntimePolicy::default()),
        Gate::new(8),
    ))
}

/// An application with these instances, in the mode `open`.
pub fn app_of(instances: Vec<Arc<Instance>>) -> Arc<App> {
    let config = Arc::new(Config::default());
    let access = AccessLayer::with_guard(&config, Arc::new(OpenGuard)).unwrap();
    Arc::new(App {
        config,
        instances,
        auths: BTreeMap::new(),
        jobs: crate::jobs::JobManager::default(),
        uploads: crate::uploads::UploadManager::default(),
        sqlite: crate::pv_data::SqliteSessions::default(),
        access,
        resume_token_key: [0; 32],
    })
}

/// A request: the method, the target (`/api/x?a=b`) and a JSON body.
pub fn request(method: Method, target: &str, body: Option<serde_json::Value>) -> Req {
    let (path, raw_query) = target.split_once('?').unwrap_or((target, ""));
    let body = match body {
        Some(value) => full(value.to_string()),
        None => empty(),
    };
    Req {
        method,
        path: path.to_owned(),
        raw_query: raw_query.to_owned(),
        query: Query::parse(raw_query),
        headers: HeaderMap::new(),
        body,
        ctx: OpCtx::default(),
        host: "localhost".to_owned(),
    }
}

/// The status, the headers and the JSON body of an answer.
pub async fn answer_of(response: Response) -> (u16, HeaderMap, serde_json::Value, String) {
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let (bytes, _) = read_limited(response.into_body(), 1 << 20).await.unwrap_or_default();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    let value = serde_json::from_str(&text).unwrap_or(serde_json::Value::Null);
    (status, headers, value, text)
}

// --- The fake admin API -------------------------------------------------------------------------------------------

/// One request that the fake admin API received.
#[derive(Clone, Debug)]
pub struct AdminRecorded {
    /// The URL, with its query.
    pub url: String,
    /// The path.
    pub path: String,
    /// The query text.
    pub query: String,
    /// The headers.
    pub headers: HeaderMap,
}

/// What a fake admin API does with a request.
pub enum AdminReply {
    /// An answer.
    Answer(u16, String),
    /// A failure.
    Failure(AdminFailure),
    /// A wait that never ends: the request waits for the time limit.
    Hang,
}

/// A fake admin API. The handler answers each request. The fake records each request first.
pub struct FakeAdmin {
    requests: Mutex<Vec<AdminRecorded>>,
    handler: Box<dyn Fn(&AdminRecorded) -> AdminReply + Send + Sync>,
}

impl FakeAdmin {
    /// A fake with a handler.
    pub fn new(handler: impl Fn(&AdminRecorded) -> AdminReply + Send + Sync + 'static) -> Arc<Self> {
        Arc::new(Self {
            requests: Mutex::new(Vec::new()),
            handler: Box::new(handler),
        })
    }

    /// A fake that answers each request with the same status and body.
    pub fn answer(status: u16, body: &str) -> Arc<Self> {
        let body = body.to_owned();
        Self::new(move |_| AdminReply::Answer(status, body.clone()))
    }

    /// The requests that arrived.
    pub fn seen(&self) -> Vec<AdminRecorded> {
        self.requests.lock().map(|list| list.clone()).unwrap_or_default()
    }
}

impl AdminTransport for FakeAdmin {
    fn get<'a>(
        &'a self,
        url: &'a str,
        headers: HeaderMap,
        limit: usize,
    ) -> BoxFuture<'a, std::result::Result<AdminAnswer, AdminFailure>> {
        Box::pin(async move {
            let without_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
            let target = without_scheme.find('/').map_or("/", |index| &without_scheme[index..]);
            let (path, query) = target.split_once('?').unwrap_or((target, ""));
            let recorded = AdminRecorded {
                url: url.to_owned(),
                path: path.to_owned(),
                query: query.to_owned(),
                headers,
            };
            if let Ok(mut list) = self.requests.lock() {
                list.push(recorded.clone());
            }
            match (self.handler)(&recorded) {
                AdminReply::Answer(status, body) => {
                    let mut bytes = body.into_bytes();
                    bytes.truncate(limit);
                    Ok(AdminAnswer {
                        status,
                        body: Bytes::from(bytes),
                    })
                }
                AdminReply::Failure(failure) => Err(failure),
                AdminReply::Hang => {
                    tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                    Err(AdminFailure::Timeout)
                }
            }
        })
    }
}

impl crate::lifecycle::BucketRules for FakeBackend {
    fn lifecycle_rules<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<Vec<crate::lifecycle::LifecycleRule>>> {
        Box::pin(async { Err(Error::api(501, "unsupported", "The fake has no lifecycle rules.")) })
    }

    fn read_lifecycle<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<crate::lifecycle::LifecycleDocument>> {
        Box::pin(async { Err(Error::api(501, "unsupported", "The fake has no lifecycle rules.")) })
    }

    fn write_lifecycle<'a>(&'a self, _ctx: &'a OpCtx, _body: Bytes) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Err(Error::api(501, "unsupported", "The fake has no lifecycle rules.")) })
    }

    fn delete_lifecycle<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Err(Error::api(501, "unsupported", "The fake has no lifecycle rules.")) })
    }

    fn versioning_status<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<String>> {
        Box::pin(async { Ok(String::new()) })
    }

    fn provider_flavour<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<String>> {
        let flavour = self.flavour.clone().unwrap_or_default();
        Box::pin(async move { Ok(flavour) })
    }
}

impl MultipartCopier for FakeBackend {
    fn copy_multipart<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        source: &'a str,
        destination: &'a str,
        options: MultipartCopyOptions,
    ) -> BoxFuture<'a, Result<()>> {
        if let Ok(mut list) = self.copies.lock() {
            list.push((source.to_owned(), destination.to_owned(), options));
        }
        Box::pin(async { Ok(()) })
    }
}

impl VersionStore for FakeBackend {
    fn list_versions<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _page_token: &'a str,
        _maximum: u32,
    ) -> BoxFuture<'a, Result<ObjectVersionPage>> {
        Box::pin(async { Err(Error::api(501, "unsupported", "The fake has no versions.")) })
    }

    fn head_version<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        key: &'a str,
        version: &'a str,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        Box::pin(async move {
            let reply = self.s3.serve(Recorded {
                method: Method::HEAD,
                key: key.to_owned(),
                query: vec![("versionId".to_owned(), version.to_owned())],
                headers: HeaderMap::new(),
                body: String::new(),
            });
            if reply.status >= 300 {
                return Err(Error::upstream(reply.status, "", ""));
            }
            Ok(object_response(reply.status, reply.headers, ""))
        })
    }

    fn get_version<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        key: &'a str,
        _version: &'a str,
        _headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        match Self::replaced(&self.get_fn) {
            Some(get) => Box::pin(async move { get(key) }),
            None => Box::pin(async { Err(Error::api(501, "unsupported", "The fake has no versions.")) }),
        }
    }

    fn delete_version<'a>(&'a self, _ctx: &'a OpCtx, _key: &'a str, _version: &'a str) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Err(Error::api(501, "unsupported", "The fake has no versions.")) })
    }

    fn restore_version<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _version: &'a str,
        _extra: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Err(Error::api(501, "unsupported", "The fake has no versions.")) })
    }
}
