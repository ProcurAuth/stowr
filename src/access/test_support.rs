//! The helpers of the tests of the access policy: a configuration in mode `authzen`, the instances over the memory
//! back end, the layer with the fake guard, and the context of a request with a valid token.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;

use super::fake::{FakePdp, FakeQuestion};
use super::{AccessLayer, AccessRequest};
use crate::common::config::{
    AccessConfig, AccessPolicy, BucketConfig, Config, IdentityConfig, PdpConfig, RuntimePolicy, VolumeConfig,
};
use crate::common::ctx::OpCtx;
use crate::common::storage::Backend;
use crate::instance::Instance;
use crate::instance::gate::Gate;
use crate::testkit::{MemoryBackend, MemoryObject};

/// The id of the service of the tests.
pub const SERVICE: &str = "svc-1";
/// The subject of the tests.
pub const SUBJECT: &str = "user-1";
/// The node of the bucket `rw`.
pub const BUCKET: &str = "service:svc-1/bucket:rw";
/// The node of the folder `folder` of the bucket `rw`.
pub const FOLDER: &str = "service:svc-1/bucket:rw/folder:folder";
/// The node of the subfolder `nested` of the folder `folder`.
pub const SUBFOLDER: &str = "service:svc-1/bucket:rw/folder:folder/subfolder:nested";

/// The node of a folder of the bucket `rw`.
pub fn folder(name: &str) -> String {
    format!("{BUCKET}/folder:{name}")
}

/// A bucket block. `None` for the permissions means that the block has no `permissions` key.
pub fn bucket(id: &str, name: &str, permissions: Option<&[&str]>) -> BucketConfig {
    BucketConfig {
        id: id.to_owned(),
        name: name.to_owned(),
        auth_id: "test-auth".to_owned(),
        provider: "s3".to_owned(),
        bucket: id.to_owned(),
        region: "test".to_owned(),
        permissions: permissions
            .unwrap_or_default()
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        permissions_defined: permissions.is_some(),
        max_scan_pages: 10,
        ..BucketConfig::default()
    }
}

/// A volume block. `None` for the permissions means that the block has no `permissions` key.
pub fn volume(id: &str, name: &str, permissions: Option<&[&str]>) -> VolumeConfig {
    VolumeConfig {
        id: id.to_owned(),
        name: name.to_owned(),
        path: format!("/data/{id}").into(),
        permissions: permissions
            .unwrap_or_default()
            .iter()
            .map(|value| (*value).to_owned())
            .collect(),
        permissions_defined: permissions.is_some(),
        ..VolumeConfig::default()
    }
}

/// A configuration in mode `authzen` with the audience of the tests.
pub fn authzen_config(audience: &str, buckets: Vec<BucketConfig>, volumes: Vec<VolumeConfig>) -> Config {
    Config {
        access: AccessConfig {
            mode: AccessPolicy::AuthZen,
            identity: Some(IdentityConfig {
                header: "X-Identity-Token".to_owned(),
                issuer: "https://edge.example".to_owned(),
                audience: audience.to_owned(),
                max_age: Duration::from_secs(300),
                clock_skew: Duration::from_secs(60),
                ..IdentityConfig::default()
            }),
            pdp: Some(PdpConfig {
                url: "http://127.0.0.1:8181".to_owned(),
                plain_http: true,
                token: "fake-pdp-token".to_owned(),
                timeout: Duration::from_secs(1),
                usage_timeout: Duration::from_secs(6),
                cache_ttl: Duration::ZERO,
                max_evaluations: 64,
            }),
        },
        buckets,
        volumes,
        ..Config::default()
    }
}

/// An instance over a back end.
pub fn instance_over(cfg: BucketConfig, backend: Arc<dyn Backend>) -> Arc<Instance> {
    Arc::new(Instance::new(
        cfg,
        backend,
        Arc::new(RuntimePolicy::default()),
        Gate::new(4),
    ))
}

/// A memory back end with objects (key and text).
pub fn memory(objects: &[(&str, &str)]) -> Arc<MemoryBackend> {
    Arc::new(MemoryBackend::with_objects(objects))
}

/// Add an object to a memory back end.
pub fn put_object(backend: &MemoryBackend, key: &str, text: &str) {
    backend.objects.lock().unwrap().insert(
        key.to_owned(),
        MemoryObject {
            data: Bytes::from(text.to_owned()),
            content_type: "text/plain".to_owned(),
        },
    );
}

/// The context of a request with a valid token of a subject.
pub fn ctx_of(subject: &str, request_id: &str) -> OpCtx {
    OpCtx {
        access: Some(Arc::new(AccessRequest::new(subject, "", request_id))),
        ..OpCtx::default()
    }
}

/// The environment of the tests of the routes: two buckets (`readonly` and `rw`) in mode `authzen`, the fake guard
/// with an answer cache of 0 s, and the objects of the bucket `rw` below the root prefix `tenant/`.
pub struct Env {
    /// The layer.
    pub layer: AccessLayer,
    /// The fake guard.
    pub fake: Arc<FakePdp>,
    /// The bucket `readonly`.
    pub readonly: Arc<Instance>,
    /// The bucket `rw`.
    pub rw: Arc<Instance>,
    /// The back end of `rw`.
    pub rw_backend: Arc<MemoryBackend>,
}

impl Default for Env {
    fn default() -> Self {
        Self::new()
    }
}

impl Env {
    /// The environment.
    pub fn new() -> Self {
        let mut readonly_cfg = bucket("readonly", "Read only", Some(&["read"]));
        readonly_cfg.root_prefix = String::new();
        let mut rw_cfg = bucket("rw", "Read write", None);
        rw_cfg.root_prefix = "tenant/".to_owned();
        let config = authzen_config(SERVICE, vec![readonly_cfg.clone(), rw_cfg.clone()], Vec::new());
        let fake = Arc::new(FakePdp::new());
        let layer = AccessLayer::with_guard(&config, fake.clone()).unwrap();
        let rw_backend = memory(&[
            ("tenant/folder/direct.txt", "direct"),
            ("tenant/folder/nested/deep.txt", "deep"),
            ("tenant/a/x.txt", "a"),
        ]);
        Self {
            layer,
            fake,
            readonly: instance_over(readonly_cfg, memory(&[("ro.txt", "ro")])),
            rw: instance_over(rw_cfg, rw_backend.clone()),
            rw_backend,
        }
    }

    /// The instances in the order of the configuration.
    pub fn instances(&self) -> Vec<Arc<Instance>> {
        vec![self.readonly.clone(), self.rw.clone()]
    }

    /// The context of a request of the subject of the tests.
    pub fn ctx(&self, request_id: &str) -> OpCtx {
        ctx_of(SUBJECT, request_id)
    }

    /// The permission of an action on a key of the bucket `rw`.
    pub fn ask(&self, action: &str, relative: &str) -> super::Ask {
        self.layer.object_ask(action, &self.rw, relative)
    }
}

/// An answer function that says the same decision to each question.
pub fn answer_all(decision: bool) -> impl Fn(&FakeQuestion) -> serde_json::Value + Send + Sync + 'static {
    move |_| serde_json::json!({"decision": decision})
}

/// An answer function that answers a usage question with units 1, and the other questions with the decision.
pub fn usage_answer(decision: bool) -> impl Fn(&FakeQuestion) -> serde_json::Value + Send + Sync + 'static {
    move |question| {
        if question.usage && decision {
            serde_json::json!({"decision": true, "context": {"usage": {"units": 1}}})
        } else {
            serde_json::json!({"decision": decision})
        }
    }
}

/// One expected question: the action, the path, the usage, the batch and the mark of an other permission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Summary {
    /// The action.
    pub action: String,
    /// The path.
    pub path: String,
    /// `context.usage`.
    pub usage: bool,
    /// An Access Evaluations request.
    pub batch: bool,
    /// `context.permission_only`.
    pub permission_only: bool,
}

/// An expected question.
pub fn summary(action: &str, path: &str, usage: bool, batch: bool, permission_only: bool) -> Summary {
    Summary {
        action: action.to_owned(),
        path: path.to_owned(),
        usage,
        batch,
        permission_only,
    }
}

/// The summary of the questions of the fake.
pub fn summarize(questions: &[FakeQuestion]) -> Vec<Summary> {
    questions
        .iter()
        .map(|question| {
            summary(
                &question.action,
                &question.path,
                question.usage,
                question.batch,
                question.permission_only,
            )
        })
        .collect()
}
