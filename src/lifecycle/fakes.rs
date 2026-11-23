//! The fakes of the tests: a provider that keeps the lifecycle configuration and the tags as bytes, the back ends
//! that carry it, and the helpers that call a route.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};

use bytes::Bytes;
use http::header::{CONTENT_TYPE, HeaderValue};
use http::{HeaderMap, Method};

use super::md5::content_md5;
use super::s3::{self, S3Wire};
use super::xml;
use super::{BucketRules, LifecycleDocument, LifecycleRule, ObjectTagger, Tag};
use crate::access::AccessLayer;
use crate::common::BoxFuture;
use crate::common::app::App;
use crate::common::config::{BucketConfig, Config, RuntimePolicy};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Body, Req, Response, empty, full, read_limited};
use crate::common::query::Query;
use crate::common::storage::{Backend, DiscoveredCapabilities, ListOptions, ListPage, ObjectResponse};
use crate::instance::Instance;
use crate::instance::gate::Gate;
use crate::provider::s3::{S3Answer, S3Request};
use crate::testkit::MemoryBackend;

// --- A provider that keeps the lifecycle configuration and the tags -----------------------------------------------

/// A function that changes a written document before the fake keeps it.
pub type Keep = fn(&mut FakeState, Vec<u8>) -> Vec<u8>;

/// The state of the fake provider.
#[derive(Default)]
pub struct FakeState {
    /// The configuration of the bucket as bytes; `None` for a bucket without configuration.
    pub body: Option<Vec<u8>>,
    /// The header `Server` of each answer. Empty: no `Server` header and no request id.
    pub server: String,
    /// True for the answers of Garage: an error document with a `Region` and no request id.
    pub garage: bool,
    /// The status of `GetBucketVersioning`.
    pub versioning: String,
    /// A function that changes a written document before the fake keeps it, as a provider that drops a setting.
    pub keep: Option<Keep>,
    /// The status of a refused write, or 0.
    pub refuse: u16,
    /// The status of a read of the configuration, when it is not 0.
    pub lifecycle: u16,
    /// The documents that the fake received.
    pub puts: Vec<Vec<u8>>,
    /// The number of deletes of the configuration.
    pub deletes: usize,
    /// The tags of each object by key.
    pub tags: BTreeMap<String, Vec<Tag>>,
    /// The query and the body of each tag write.
    pub tag_puts: Vec<(String, String)>,
    /// The keys of the tag deletes.
    pub tag_deletes: Vec<String>,
    /// The problems that the fake saw: a request that it does not know, a wrong checksum.
    pub problems: Vec<String>,
}

/// The fake provider.
pub struct FakeS3 {
    /// The state.
    pub state: Mutex<FakeState>,
    /// The endpoint of the provider.
    pub endpoint: String,
    /// The root prefix of the instance.
    pub root: String,
}

impl FakeS3 {
    /// A provider with a `Server` header and a configuration. The bucket has versioning.
    pub fn new(server: &str, body: &str) -> Arc<Self> {
        let state = FakeState {
            body: (!body.is_empty()).then(|| body.as_bytes().to_vec()),
            server: server.to_owned(),
            versioning: "Enabled".to_owned(),
            ..FakeState::default()
        };
        Arc::new(Self {
            state: Mutex::new(state),
            endpoint: "http://storage.local:9000".to_owned(),
            root: "tenant/".to_owned(),
        })
    }

    /// Change the state.
    pub fn with<R>(&self, change: impl FnOnce(&mut FakeState) -> R) -> R {
        change(&mut self.state.lock().unwrap())
    }

    /// The configuration as text.
    pub fn stored(&self) -> String {
        self.with(|state| String::from_utf8_lossy(state.body.as_deref().unwrap_or_default()).into_owned())
    }

    /// Replace the configuration.
    pub fn set_stored(&self, body: &str) {
        self.with(|state| state.body = Some(body.as_bytes().to_vec()));
    }
}

fn answer(state: &FakeState, status: u16, body: &str) -> S3Answer {
    let mut headers = HeaderMap::new();
    if !state.server.is_empty() {
        headers.insert("server", HeaderValue::from_str(&state.server).unwrap());
        headers.insert("x-amz-request-id", HeaderValue::from_static("1"));
    }
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/xml"));
    S3Answer {
        status,
        headers,
        body: Bytes::from(body.to_owned()),
    }
}

fn failure(state: &FakeState, status: u16, code: &str) -> S3Answer {
    let body = if state.garage {
        format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code><Message>no</Message><Resource>/bucket</Resource><Region>garage</Region></Error>"
        )
    } else {
        format!("<Error><Code>{code}</Code><Message>no</Message><RequestId>1</RequestId></Error>")
    };
    answer(state, status, &body)
}

fn has(query: &[(String, String)], name: &str) -> bool {
    query.iter().any(|(key, _)| key == name)
}

impl S3Wire for FakeS3 {
    fn send<'a>(&'a self, _ctx: &'a OpCtx, request: S3Request<'a>, limit: usize) -> BoxFuture<'a, Result<S3Answer>> {
        Box::pin(async move {
            let body = match request.body {
                Some((body, _)) => read_limited(body, usize::MAX).await?.0,
                None => Bytes::new(),
            };
            let mut state = self.state.lock().unwrap();
            let state = &mut *state;
            let method = request.method.clone();
            let key = request.key;
            let query = &request.query;
            let result = if key.is_empty() && has(query, "lifecycle") && method == Method::GET {
                if state.lifecycle != 0 {
                    failure(state, state.lifecycle, "NotImplemented")
                } else if let Some(document) = &state.body {
                    answer(state, 200, &String::from_utf8_lossy(document))
                } else {
                    failure(state, 404, "NoSuchLifecycleConfiguration")
                }
            } else if key.is_empty() && has(query, "lifecycle") && method == Method::PUT {
                let wanted = content_md5(&body);
                let sent = request
                    .headers
                    .get("content-md5")
                    .map(|value| value.to_str().unwrap_or("").to_owned())
                    .unwrap_or_default();
                if sent != wanted {
                    state.problems.push(format!("Content-MD5 = {sent:?}"));
                }
                state.puts.push(body.to_vec());
                if state.refuse != 0 {
                    let code = match state.refuse {
                        403 => "AccessDenied",
                        501 => "NotImplemented",
                        _ => "InvalidArgument",
                    };
                    failure(state, state.refuse, code)
                } else {
                    let mut document = body.to_vec();
                    if let Some(keep) = state.keep {
                        document = keep(state, document);
                    }
                    state.body = Some(document);
                    answer(state, 200, "")
                }
            } else if key.is_empty() && has(query, "lifecycle") && method == Method::DELETE {
                state.deletes += 1;
                state.body = None;
                answer(state, 204, "")
            } else if key.is_empty() && has(query, "versioning") && method == Method::GET {
                let text = format!(
                    "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>{}</Status></VersioningConfiguration>",
                    state.versioning
                );
                answer(state, 200, &text)
            } else if method == Method::GET && key.ends_with(super::rules::FLAVOUR_PROBE_KEY) {
                failure(state, 404, "NoSuchKey")
            } else if has(query, "tagging") && method == Method::GET {
                let mut text = String::from("<Tagging xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><TagSet>");
                for tag in state.tags.get(key).cloned().unwrap_or_default() {
                    text.push_str(&format!(
                        "<Tag><Key>{}</Key><Value>{}</Value></Tag>",
                        xml::escape_text(&tag.key),
                        xml::escape_text(&tag.value)
                    ));
                }
                text.push_str("</TagSet></Tagging>");
                answer(state, 200, &text)
            } else if has(query, "tagging") && method == Method::PUT {
                if request.headers.get("content-md5").is_none() {
                    state.problems.push("no Content-MD5".to_owned());
                }
                let query_text = query
                    .iter()
                    .map(|(name, value)| format!("{name}={value}"))
                    .collect::<Vec<_>>()
                    .join("&");
                state
                    .tag_puts
                    .push((query_text, String::from_utf8_lossy(&body).into_owned()));
                answer(state, 200, "")
            } else if has(query, "tagging") && method == Method::DELETE {
                state.tag_deletes.push(key.to_owned());
                answer(state, 204, "")
            } else {
                state
                    .problems
                    .push(format!("unexpected request {method} {key} {query:?}"));
                answer(state, 400, "")
            };
            let mut result = result;
            if result.body.len() > limit {
                result.body = result.body.slice(..limit);
            }
            Ok(result)
        })
    }

    fn endpoint(&self) -> &str {
        &self.endpoint
    }

    fn root_prefix(&self) -> &str {
        &self.root
    }

    fn failure(&self, answer: &S3Answer) -> Error {
        let root = xml::parse_document(&answer.body).ok();
        let text = |name: &str| {
            root.as_ref()
                .and_then(|root| root.last_child(name))
                .map(|child| child.raw_text.clone())
                .unwrap_or_default()
        };
        Error::upstream(answer.status, text("Code"), text("Message"))
    }
}

// --- Back ends -----------------------------------------------------------------------------------------------------

/// A back end over the memory back end and the fake provider. It has the tags and the lifecycle rules of S3.
pub struct WireBackend {
    /// The objects.
    pub memory: MemoryBackend,
    /// The provider.
    pub wire: Arc<FakeS3>,
    /// True when the back end gives the tag functions.
    pub tags: bool,
    /// True when the back end gives the lifecycle functions.
    pub rules: bool,
}

impl WireBackend {
    /// A back end with the tags and the rules.
    pub fn new(wire: Arc<FakeS3>) -> Self {
        Self {
            memory: MemoryBackend::default(),
            wire,
            tags: true,
            rules: true,
        }
    }
}

macro_rules! delegate_backend {
    ($field:ident) => {
        fn list<'a>(&'a self, ctx: &'a OpCtx, options: &'a ListOptions) -> BoxFuture<'a, Result<ListPage>> {
            self.$field.list(ctx, options)
        }
        fn get<'a>(
            &'a self,
            ctx: &'a OpCtx,
            key: &'a str,
            headers: &'a HeaderMap,
        ) -> BoxFuture<'a, Result<ObjectResponse>> {
            self.$field.get(ctx, key, headers)
        }
        fn put<'a>(
            &'a self,
            ctx: &'a OpCtx,
            key: &'a str,
            body: Body,
            size: i64,
            content_type: &'a str,
        ) -> BoxFuture<'a, Result<()>> {
            self.$field.put(ctx, key, body, size, content_type)
        }
        fn delete<'a>(&'a self, ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<()>> {
            self.$field.delete(ctx, key)
        }
        fn copy<'a>(&'a self, ctx: &'a OpCtx, source: &'a str, destination: &'a str) -> BoxFuture<'a, Result<()>> {
            self.$field.copy(ctx, source, destination)
        }
        fn discover_capabilities<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<DiscoveredCapabilities>> {
            self.$field.discover_capabilities(ctx)
        }
    };
}

impl Backend for WireBackend {
    delegate_backend!(memory);

    fn head<'a>(&'a self, ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<ObjectResponse>> {
        self.memory.head(ctx, key)
    }

    fn tagger(&self) -> Option<&dyn ObjectTagger> {
        self.tags.then_some(self as &dyn ObjectTagger)
    }

    fn bucket_rules(&self) -> Option<&dyn BucketRules> {
        self.rules.then_some(self as &dyn BucketRules)
    }
}

impl ObjectTagger for WireBackend {
    fn get_tags<'a>(&'a self, ctx: &'a OpCtx, key: &'a str, version: &'a str) -> BoxFuture<'a, Result<Vec<Tag>>> {
        Box::pin(s3::get_tags(&*self.wire, ctx, key, version))
    }

    fn put_tags<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        version: &'a str,
        tags: &'a [Tag],
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(s3::put_tags(&*self.wire, ctx, key, version, tags))
    }
}

impl BucketRules for WireBackend {
    fn lifecycle_rules<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<Vec<LifecycleRule>>> {
        Box::pin(s3::lifecycle_rules(&*self.wire, ctx))
    }

    fn read_lifecycle<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<LifecycleDocument>> {
        Box::pin(s3::read_lifecycle(&*self.wire, ctx))
    }

    fn write_lifecycle<'a>(&'a self, ctx: &'a OpCtx, body: Bytes) -> BoxFuture<'a, Result<()>> {
        Box::pin(s3::write_lifecycle(&*self.wire, ctx, body))
    }

    fn delete_lifecycle<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<()>> {
        Box::pin(s3::delete_lifecycle(&*self.wire, ctx))
    }

    fn versioning_status<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<String>> {
        Box::pin(s3::versioning_status(&*self.wire, ctx))
    }

    fn provider_flavour<'a>(&'a self, ctx: &'a OpCtx) -> BoxFuture<'a, Result<String>> {
        Box::pin(s3::provider_flavour(&*self.wire, ctx))
    }
}

/// How the tag functions of [`TaggingMemory`] answer.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TagMode {
    /// The tags of the memory.
    #[default]
    Normal,
    /// The provider answers 501 to each read of the tags.
    NotImplemented,
    /// The provider answers 403 to each read of the tags.
    Denied,
}

/// A memory back end with object tags. It counts the writes and the requests, and reports a version id.
pub struct TaggingMemory {
    /// The objects.
    pub memory: MemoryBackend,
    /// The tags by full key.
    pub tags: Mutex<BTreeMap<String, Vec<Tag>>>,
    /// The number of tag writes.
    pub puts: AtomicUsize,
    /// The number of HEAD requests.
    pub heads: AtomicUsize,
    /// The tag requests with the version: `get:v1`, `put:v1`.
    pub seen: Mutex<Vec<String>>,
    /// The version id that a HEAD reports, or `None`.
    pub version_id: Option<String>,
    /// How the reads answer.
    pub mode: TagMode,
}

impl TaggingMemory {
    /// A back end with these objects.
    pub fn new(objects: &[(&str, &str)]) -> Self {
        Self {
            memory: MemoryBackend::with_objects(objects),
            tags: Mutex::new(BTreeMap::new()),
            puts: AtomicUsize::new(0),
            heads: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
            version_id: None,
            mode: TagMode::Normal,
        }
    }

    /// The tags of a key.
    pub fn tags_of(&self, key: &str) -> Vec<Tag> {
        self.tags.lock().unwrap().get(key).cloned().unwrap_or_default()
    }

    /// Set the tags of a key.
    pub fn set_tags(&self, key: &str, tags: &[Tag]) {
        self.tags.lock().unwrap().insert(key.to_owned(), tags.to_vec());
    }
}

impl Backend for TaggingMemory {
    delegate_backend!(memory);

    fn head<'a>(&'a self, ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<ObjectResponse>> {
        Box::pin(async move {
            self.heads.fetch_add(1, Ordering::SeqCst);
            let mut response = self.memory.head(ctx, key).await?;
            if let Some(version) = &self.version_id {
                response
                    .headers
                    .insert("x-amz-version-id", HeaderValue::from_str(version).unwrap());
            }
            Ok(response)
        })
    }

    fn tagger(&self) -> Option<&dyn ObjectTagger> {
        Some(self)
    }
}

impl ObjectTagger for TaggingMemory {
    fn get_tags<'a>(&'a self, _ctx: &'a OpCtx, key: &'a str, version: &'a str) -> BoxFuture<'a, Result<Vec<Tag>>> {
        Box::pin(async move {
            self.seen.lock().unwrap().push(format!("get:{version}"));
            match self.mode {
                TagMode::NotImplemented => return Err(Error::upstream(501, "NotImplemented", "")),
                TagMode::Denied => return Err(Error::upstream(403, "AccessDenied", "")),
                TagMode::Normal => {}
            }
            if !self.memory.objects.lock().unwrap().contains_key(key) {
                return Err(Error::upstream(404, "NoSuchKey", ""));
            }
            Ok(self.tags_of(key))
        })
    }

    fn put_tags<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        key: &'a str,
        version: &'a str,
        tags: &'a [Tag],
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.seen.lock().unwrap().push(format!("put:{version}"));
            self.puts.fetch_add(1, Ordering::SeqCst);
            let mut all = self.tags.lock().unwrap();
            if tags.is_empty() {
                all.remove(key);
            } else {
                all.insert(key.to_owned(), tags.to_vec());
            }
            Ok(())
        })
    }
}

// --- Instances, application, calls ---------------------------------------------------------------------------------

/// The configuration of a test instance. `permissions` is `None` for all permissions.
pub fn instance_config(id: &str, root_prefix: &str, permissions: Option<&[&str]>) -> BucketConfig {
    BucketConfig {
        id: id.to_owned(),
        name: id.to_owned(),
        auth_id: "s3".to_owned(),
        provider: "s3".to_owned(),
        bucket: "bucket".to_owned(),
        permissions: permissions
            .map(|list| list.iter().map(|value| (*value).to_owned()).collect())
            .unwrap_or_default(),
        permissions_defined: permissions.is_some(),
        root_prefix: root_prefix.to_owned(),
        max_scan_pages: 100,
        ..BucketConfig::default()
    }
}

/// An instance over a back end.
pub fn instance(cfg: BucketConfig, backend: Arc<dyn Backend>) -> Arc<Instance> {
    Arc::new(Instance::new(
        cfg,
        backend,
        Arc::new(RuntimePolicy::default()),
        Gate::new(8),
    ))
}

/// Tell the instance that the start probe found the versions.
pub fn with_versions(instance: &Instance) {
    *instance.versioning.probe.lock().unwrap() = (true, true);
}

/// An application over instances, in the mode `open`.
pub fn application(instances: Vec<Arc<Instance>>) -> Arc<App> {
    let config = Config::default();
    let access = AccessLayer::new(&config).unwrap();
    Arc::new(App {
        config: Arc::new(config),
        instances,
        auths: BTreeMap::new(),
        jobs: crate::jobs::JobManager::new(Weak::new(), 10),
        uploads: crate::uploads::UploadManager::new(),
        sqlite: crate::pv_data::SqliteSessions::new(),
        access,
        resume_token_key: [0; 32],
    })
}

/// The answer of a call: the status and the body.
pub struct Called {
    /// The status.
    pub status: u16,
    /// The body as text.
    pub text: String,
}

impl Called {
    /// The body as JSON.
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.text).unwrap_or(serde_json::Value::Null)
    }

    /// The code of the error object, or an empty text.
    pub fn code(&self) -> String {
        self.json()["error"]["code"].as_str().unwrap_or("").to_owned()
    }
}

/// Call a route of this folder with a method, a target (`/api/tags?instance=rw`) and an optional JSON body.
pub async fn call(app: &Arc<App>, method: &str, target: &str, body: Option<serde_json::Value>) -> Called {
    let (path, raw_query) = target.split_once('?').unwrap_or((target, ""));
    let request = Req {
        method: Method::from_bytes(method.as_bytes()).unwrap(),
        path: path.to_owned(),
        raw_query: raw_query.to_owned(),
        query: Query::parse(raw_query),
        headers: HeaderMap::new(),
        body: body.map_or_else(empty, |value| full(Bytes::from(value.to_string()))),
        ctx: OpCtx::default(),
        host: "localhost".to_owned(),
    };
    let handler = match path {
        "/api/tags" => super::handle_tags,
        "/api/tags/bulk" => super::handle_tags_bulk,
        "/api/lifecycle" => super::handle_lifecycle,
        other => panic!("no route {other}"),
    };
    let response: Response = handler(Arc::clone(app), request).await;
    let status = response.status().as_u16();
    let (bytes, _) = read_limited(response.into_body(), usize::MAX).await.unwrap();
    Called {
        status,
        text: String::from_utf8_lossy(&bytes).into_owned(),
    }
}
