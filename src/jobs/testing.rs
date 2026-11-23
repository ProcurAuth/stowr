//! The helpers of the tests of the jobs: an application over the memory back end, the call of a route and the wait
//! for a status of a job.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Method};

use super::{JobManager, JobState};
use crate::access::AccessLayer;
use crate::common::app::App;
use crate::common::config::{Config, PERMISSION_DELETE, PERMISSION_READ, PERMISSION_WRITE};
use crate::common::ctx::OpCtx;
use crate::common::http::{Handler, Req, Response, empty, full, read_limited};
use crate::common::query::Query;
use crate::common::storage::Backend;
use crate::instance::Instance;
use crate::instance::budget::Budget;
use crate::testkit::{MemoryBackend, bucket_config, instance_over, read_only_backend, read_write_backend};

/// An application in mode `open` over instances, with a history of 10 finished jobs.
pub fn application(instances: Vec<Arc<Instance>>) -> Arc<App> {
    let config = Config {
        job_history_limit: 10,
        ..Config::default()
    };
    let access = AccessLayer::new(&config).unwrap();
    Arc::new_cyclic(|weak| App {
        config: Arc::new(config),
        instances,
        auths: BTreeMap::new(),
        jobs: JobManager::new(weak.clone(), 10),
        uploads: crate::uploads::UploadManager::new(),
        sqlite: crate::pv_data::SqliteSessions::new(),
        access,
        resume_token_key: [0; 32],
    })
}

/// The test instance `rw` over a back end: root prefix `tenant/`, the permissions read, write and delete.
pub fn read_write_over(backend: Arc<dyn Backend>) -> Arc<Instance> {
    Arc::new(instance_over(
        bucket_config("rw", "tenant/", &[PERMISSION_READ, PERMISSION_WRITE, PERMISSION_DELETE]),
        backend,
    ))
}

/// The test application: the instance `readonly`, then the instance `rw` over its memory back end.
pub struct Rig {
    /// The application.
    pub app: Arc<App>,
    /// The memory back end of `rw`.
    pub backend: Arc<MemoryBackend>,
}

/// The test application with the objects of `rw`: `tenant/folder/direct.txt`, `tenant/folder/nested/deep.txt` and
/// `tenant/a//./../b\c`.
pub fn rig() -> Rig {
    let backend = read_write_backend();
    let app = rig_over(backend.clone());
    Rig { app, backend }
}

/// The test application with `rw` over another back end.
pub fn rig_over(backend: Arc<dyn Backend>) -> Arc<App> {
    let readonly = Arc::new(instance_over(
        bucket_config("readonly", "", &[PERMISSION_READ]),
        read_only_backend(),
    ));
    application(vec![readonly, read_write_over(backend)])
}

/// The answer of a route.
pub struct Called {
    /// The status.
    pub status: u16,
    /// The headers.
    pub headers: HeaderMap,
    /// The body as text.
    pub text: String,
}

impl Called {
    /// The body as JSON.
    pub fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.text).unwrap_or(serde_json::Value::Null)
    }
}

/// The context of a request: the budget of one request.
pub fn request_ctx(app: &App) -> OpCtx {
    OpCtx::with_budget(Arc::new(Budget::for_request(&app.config.runtime)))
}

/// Call a handler with a method, a target (`/api/stats?instance=rw`), an optional JSON body and a context.
pub async fn call_with(
    handler: Handler,
    app: &Arc<App>,
    method: &str,
    target: &str,
    body: Option<serde_json::Value>,
    ctx: OpCtx,
) -> Called {
    let (path, raw_query) = target.split_once('?').unwrap_or((target, ""));
    let request = Req {
        method: Method::from_bytes(method.as_bytes()).unwrap(),
        path: path.to_owned(),
        raw_query: raw_query.to_owned(),
        query: Query::parse(raw_query),
        headers: HeaderMap::new(),
        body: body.map_or_else(empty, |value| full(Bytes::from(value.to_string()))),
        ctx,
        host: "localhost".to_owned(),
    };
    let response: Response = handler(app.clone(), request).await;
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let (bytes, _) = read_limited(response.into_body(), usize::MAX).await.unwrap();
    Called {
        status,
        headers,
        text: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

/// Call a route of this folder with the context of a request.
pub async fn call(app: &Arc<App>, method: &str, target: &str, body: Option<serde_json::Value>) -> Called {
    let path = target.split_once('?').map_or(target, |(path, _)| path);
    let handler: Handler = match path {
        "/api/jobs" => super::handle_job_collection,
        "/api/stats" => super::handle_stats,
        "/api/versions" => super::handle_versions,
        "/api/version-counts" => super::handle_version_counts,
        "/api/versions/restore" => super::handle_version_restore,
        "/api/integrity" => super::handle_integrity,
        "/api/inspect" => super::handle_inspect,
        other if other.starts_with("/api/jobs/") => super::handle_jobs,
        other => panic!("no route {other}"),
    };
    call_with(handler, app, method, target, body, request_ctx(app)).await
}

/// Wait at most 5 seconds for a status of a job.
pub async fn wait_for_status(app: &App, id: &str, status: &str) -> JobState {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        if let Some(job) = app.jobs.get(id)
            && job.status == status
        {
            return job;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("job {id} did not reach {status}: {:?}", app.jobs.get(id));
}
