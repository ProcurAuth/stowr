//! The assembly of the application: the shared provider clients of the `auth` blocks, the instances (the buckets,
//! then the volumes), the managers in memory and the access layer; then the start probes and the stop.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use crate::common::app::App;
use crate::common::config::Config;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::misc::random_bytes;
use crate::instance::Instance;
use crate::instance::gate::Gate;
use crate::provider::SharedAuth;

use super::logfmt::quote;

/// The longest time of the start probes of all the instances.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(6);

fn context(prefix: String, error: Error) -> Error {
    Error::internal(format!("{prefix}: {error}"))
}

/// Build the application from its instances: the job manager, the upload manager, the SQLite sessions and the access
/// layer.
pub fn assemble(
    config: Arc<Config>,
    auths: BTreeMap<String, Arc<SharedAuth>>,
    instances: Vec<Arc<Instance>>,
    access: crate::access::AccessLayer,
) -> Result<Arc<App>> {
    let mut resume_token_key = [0u8; 32];
    random_bytes(&mut resume_token_key)
        .map_err(|error| context("generate upload resume token key".to_owned(), error))?;
    let history_limit = config.job_history_limit;
    Ok(Arc::new_cyclic(|weak| App {
        config,
        instances,
        auths,
        jobs: crate::jobs::JobManager::new(weak.clone(), history_limit),
        uploads: crate::uploads::UploadManager::new(),
        sqlite: crate::pv_data::SqliteSessions::new(),
        access,
        resume_token_key,
    }))
}

/// Build the application from the configuration. The start probes are not part of it: [`start_app`] runs them.
pub fn build_app(config: Config) -> Result<Arc<App>> {
    let config = Arc::new(config);
    let access = crate::access::AccessLayer::new(&config)?;
    let policy = Arc::new(config.runtime.clone());
    let gate = Gate::new(policy.max_concurrent_storage_requests);
    let mut auths = BTreeMap::new();
    for auth in &config.auths {
        let shared = SharedAuth::new(auth)
            .map_err(|error| context(format!("initialize auth {}", quote(auth.id.as_bytes())), error))?;
        auths.insert(auth.id.clone(), Arc::new(shared));
    }
    let mut instances = Vec::with_capacity(config.buckets.len() + config.volumes.len());
    for bucket in &config.buckets {
        let auth = auths.get(&bucket.auth_id).cloned();
        let instance = Instance::for_bucket(bucket.clone(), auth, policy.clone(), gate.clone())
            .map_err(|error| context(format!("initialize bucket {}", quote(bucket.id.as_bytes())), error))?;
        instances.push(Arc::new(instance));
    }
    // The volumes follow the buckets in the list of the interface.
    for volume in &config.volumes {
        let instance = crate::volume::new_volume_instance(volume, policy.clone(), gate.clone())
            .map_err(|error| context(format!("initialize volume {}", quote(volume.id.as_bytes())), error))?;
        instances.push(Arc::new(instance));
    }
    assemble(config, auths, instances, access)
}

/// The start probes of each instance, all at the same time, within 6 seconds: the versioning, the tags, the edit of
/// the metadata, the incomplete uploads, the lifecycle rules, Object Lock, the default encryption and the usage. Then
/// each instance notes the time of the read of the facts of its bucket.
pub async fn probe_instances(app: &App) {
    let ctx = OpCtx::default().with_timeout(PROBE_TIMEOUT);
    let mut probes = tokio::task::JoinSet::new();
    for instance in &app.instances {
        let instance = instance.clone();
        let ctx = ctx.clone();
        probes.spawn(async move {
            let _ = ctx
                .run(async {
                    tokio::join!(
                        instance.probe_versioning(&ctx),
                        instance.probe_tags(&ctx),
                        instance.probe_metadata_edit(&ctx),
                        instance.probe_multipart_uploads(&ctx),
                        instance.probe_lifecycle(&ctx),
                        instance.probe_object_lock(&ctx),
                        instance.probe_bucket_encryption(&ctx),
                        instance.probe_usage(&ctx),
                    );
                    Ok(())
                })
                .await;
        });
    }
    while probes.join_next().await.is_some() {}
    for instance in &app.instances {
        instance.mark_bucket_facts_read();
    }
}

/// Build the application and run its start probes.
pub async fn start_app(config: Config) -> Result<Arc<App>> {
    let app = build_app(config)?;
    // The fingerprint of the interface reads each embedded file: compute it one time before the first request.
    let _ = super::frontend::frontend_version();
    probe_instances(&app).await;
    Ok(app)
}

/// Stop the background work of the application: the SQLite sessions and the job manager.
pub fn close_app(app: &App) {
    app.sqlite.close();
    app.jobs.close();
}
