//! The tests of the storage calls of an instance.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http::HeaderMap;

use super::ceiling::{ACTION_READ, ACTION_WRITE, CODE_CEILING_EXCEEDED, MAX_OBJECT_SIZE};
use super::*;
use crate::access::AccessRequest;
use crate::common::BoxFuture;
use crate::common::config::{PERMISSION_DELETE, PERMISSION_READ, PERMISSION_WRITE};
use crate::common::ctx::GateMode;
use crate::common::error::{BatchDeleteError, BatchDeleteFailure};
use crate::common::http::{empty, full};
use crate::common::storage::{
    BatchDeleter, CapabilityStateName, DiscoveredCapabilities, ListOptions, ListPage, MultipartCopier,
    MultipartCopyOptions, ObjectInfo, ObjectResponse,
};
use crate::instance::budget::Budget;
use crate::lifecycle::{BucketRules, LifecycleDocument, LifecycleRule};
use crate::testkit::{
    MemoryBackend, MemoryLayer, MemoryVersion, body_bytes, bucket_config, instance_over, read_only_instance,
    read_write_backend, read_write_instance,
};

fn ctx_with_ceiling(action: &str, value: i64, request_id: &str) -> OpCtx {
    let request = AccessRequest {
        subject: "user-1".to_owned(),
        request_id: request_id.to_owned(),
        ..AccessRequest::default()
    };
    request.ceilings.lower(action, MAX_OBJECT_SIZE, value);
    OpCtx {
        access: Some(Arc::new(request)),
        ..OpCtx::default()
    }
}

fn is_ceiling(error: &Error) -> bool {
    error.has_code(CODE_CEILING_EXCEEDED)
}

// ---- the folders of a delete marker ----

/// A back end that lists a folder `ghost/` with a delimiter and no key under it, as MinIO does for an object whose
/// current version is a delete marker. It gives the flavour and the versions of a bucket with versions.
struct GhostLister {
    memory: MemoryBackend,
    probes: AtomicI64,
    flavour: String,
}

impl MemoryLayer for GhostLister {
    fn memory(&self) -> &MemoryBackend {
        &self.memory
    }
    fn list<'a>(&'a self, _ctx: &'a OpCtx, options: &'a ListOptions) -> BoxFuture<'a, Result<ListPage>> {
        Box::pin(async move {
            if !options.delimiter.is_empty() {
                let mut prefixes = vec!["ghost/".to_owned(), "live/".to_owned(), "broken/".to_owned()];
                prefixes.extend((0..250).map(|index| format!("many-{index}/")));
                return Ok(ListPage {
                    prefixes,
                    ..ListPage::default()
                });
            }
            self.probes.fetch_add(1, Ordering::SeqCst);
            match options.prefix.as_str() {
                "live/" => Ok(ListPage {
                    objects: vec![ObjectInfo {
                        key: "live/a.txt".to_owned(),
                        ..ObjectInfo::default()
                    }],
                    ..ListPage::default()
                }),
                "broken/" => Err(Error::upstream(500, "InternalError", "")),
                _ => Ok(ListPage::default()),
            }
        })
    }
    fn bucket_rules(&self) -> Option<&dyn BucketRules> {
        Some(self)
    }
}

impl BucketRules for GhostLister {
    fn lifecycle_rules<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<Vec<LifecycleRule>>> {
        Box::pin(async { Ok(Vec::new()) })
    }
    fn read_lifecycle<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<LifecycleDocument>> {
        Box::pin(async { Ok(LifecycleDocument::default()) })
    }
    fn write_lifecycle<'a>(&'a self, _ctx: &'a OpCtx, _body: Bytes) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Ok(()) })
    }
    fn delete_lifecycle<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { Ok(()) })
    }
    fn versioning_status<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<String>> {
        Box::pin(async { Ok("Enabled".to_owned()) })
    }
    fn provider_flavour<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<String>> {
        Box::pin(async move { Ok(self.flavour.clone()) })
    }
}

fn ghost_instance(flavour: &str, versioning: bool) -> (Arc<Instance>, Arc<GhostLister>) {
    let backend = Arc::new(GhostLister {
        memory: MemoryBackend::new(),
        probes: AtomicI64::new(0),
        flavour: flavour.to_owned(),
    });
    let instance = read_write_instance(backend.clone());
    instance.set_versioning_available(versioning);
    (instance, backend)
}

fn delimited() -> ListOptions {
    ListOptions {
        delimiter: "/".to_owned(),
        ..ListOptions::default()
    }
}

#[tokio::test]
async fn the_folder_of_a_delete_marker_leaves_the_listing_of_minio_with_versions() {
    let (instance, backend) = ghost_instance(info::FLAVOUR_MINIO, true);
    let page = instance.list(&OpCtx::default(), &delimited()).await.unwrap();
    let got: std::collections::BTreeSet<&str> = page.prefixes.iter().map(String::as_str).collect();
    assert!(
        !got.contains("ghost/"),
        "the empty folder shows: {:?}",
        &page.prefixes[..3]
    );
    assert!(got.contains("live/") && got.contains("broken/"));
    // The probes are bounded: the folders after the limit stay without a probe.
    assert_eq!(backend.probes.load(Ordering::SeqCst), ops::MAX_PREFIX_PROBES as i64);
    assert!(got.contains("many-249/"));
    assert_eq!(info::known_flavour(&instance), "minio");
}

#[tokio::test]
async fn each_folder_stays_where_the_provider_has_no_such_folder() {
    for (flavour, versioning) in [
        (info::FLAVOUR_SEAWEEDFS, true),
        (info::FLAVOUR_AWS, true),
        (info::FLAVOUR_GARAGE, true),
        (info::FLAVOUR_MINIO, false),
    ] {
        let (instance, backend) = ghost_instance(flavour, versioning);
        let page = instance.list(&OpCtx::default(), &delimited()).await.unwrap();
        assert_eq!(page.prefixes.len(), 253, "{flavour}");
        assert_eq!(backend.probes.load(Ordering::SeqCst), 0, "{flavour}");
    }
}

#[tokio::test]
async fn a_listing_without_a_delimiter_adds_no_probe() {
    let (instance, backend) = ghost_instance(info::FLAVOUR_MINIO, true);
    let options = ListOptions {
        prefix: "live/".to_owned(),
        ..ListOptions::default()
    };
    instance.list(&OpCtx::default(), &options).await.unwrap();
    assert_eq!(backend.probes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn the_probes_of_the_folders_count_in_the_budget() {
    let (instance, _) = ghost_instance(info::FLAVOUR_MINIO, true);
    let budget = Arc::new(Budget::new(0, 0));
    instance
        .list(&OpCtx::with_budget(budget.clone()), &delimited())
        .await
        .unwrap();
    assert_eq!(budget.usage().storage_requests, 1 + ops::MAX_PREFIX_PROBES as i64);
}

// ---- the batch delete ----

/// A back end that counts the single and the batch deletes.
struct BatchLayer {
    memory: Arc<MemoryBackend>,
    batches: Mutex<Vec<usize>>,
    singles: AtomicI64,
    refuse: Option<Error>,
}

impl BatchLayer {
    fn new(memory: Arc<MemoryBackend>, refuse: Option<Error>) -> Arc<Self> {
        Arc::new(Self {
            memory,
            batches: Mutex::new(Vec::new()),
            singles: AtomicI64::new(0),
            refuse,
        })
    }

    fn batches(&self) -> Vec<usize> {
        self.batches.lock().unwrap().clone()
    }
}

impl MemoryLayer for BatchLayer {
    fn memory(&self) -> &MemoryBackend {
        &self.memory
    }
    fn delete<'a>(&'a self, ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<()>> {
        self.singles.fetch_add(1, Ordering::SeqCst);
        self.memory.delete(ctx, key)
    }
    fn batch_deleter(&self) -> Option<&dyn BatchDeleter> {
        Some(self)
    }
}

impl BatchDeleter for BatchLayer {
    fn delete_many<'a>(&'a self, ctx: &'a OpCtx, keys: &'a [String]) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if let Some(error) = &self.refuse {
                return Err(error.clone());
            }
            self.batches.lock().unwrap().push(keys.len());
            for key in keys {
                self.memory.delete(ctx, key).await?;
            }
            Ok(())
        })
    }
}

fn plain_instance(backend: Arc<dyn Backend>) -> Arc<Instance> {
    Arc::new(instance_over(
        BucketConfig {
            id: "rw".to_owned(),
            ..BucketConfig::default()
        },
        backend,
    ))
}

#[tokio::test]
async fn a_delete_of_many_keys_goes_in_batches_of_a_thousand() {
    let backend = BatchLayer::new(Arc::new(MemoryBackend::new()), None);
    let instance = plain_instance(backend.clone());
    let keys: Vec<String> = (0..2500).map(|index| format!("k/{index:05}")).collect();
    let locked = instance.delete_many(&OpCtx::default(), &keys).await.unwrap();
    assert!(locked.is_empty());
    assert_eq!(backend.batches(), vec![1000, 1000, 500]);
    assert_eq!(backend.singles.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_key_that_xml_cannot_carry_stays_out_of_the_batch() {
    let backend = BatchLayer::new(Arc::new(MemoryBackend::new()), None);
    let instance = plain_instance(backend.clone());
    let keys = ["a", "bad\u{1}key", "c", "bad\u{fffe}key"].map(str::to_owned);
    instance.delete_many(&OpCtx::default(), &keys).await.unwrap();
    assert_eq!(backend.batches(), vec![2]);
    assert_eq!(backend.singles.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn a_provider_that_refuses_the_batch_request_gets_single_deletes() {
    let backend = BatchLayer::new(
        Arc::new(MemoryBackend::new()),
        Some(Error::upstream(501, "NotImplemented", "")),
    );
    let instance = plain_instance(backend.clone());
    let keys = ["a", "b", "c"].map(str::to_owned);
    instance.delete_many(&OpCtx::default(), &keys).await.unwrap();
    assert_eq!(backend.singles.load(Ordering::SeqCst), 3);
    assert!(backend.batches().is_empty());
    assert!(instance.batch_delete_off.load(Ordering::SeqCst));
    instance
        .delete_many(&OpCtx::default(), &["d".to_owned()])
        .await
        .unwrap();
    assert_eq!(backend.singles.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn another_provider_error_of_the_batch_stays() {
    let backend = BatchLayer::new(
        Arc::new(MemoryBackend::new()),
        Some(Error::upstream(403, "AccessDenied", "")),
    );
    let instance = plain_instance(backend.clone());
    let error = instance
        .delete_many(&OpCtx::default(), &["a".to_owned()])
        .await
        .err()
        .unwrap();
    assert_eq!(error.status(), 403);
    assert_eq!(backend.singles.load(Ordering::SeqCst), 0);
    assert!(!instance.batch_delete_off.load(Ordering::SeqCst));
    assert_eq!(
        instance.capability(PERMISSION_DELETE).state,
        CapabilityStateName::Denied
    );
}

#[tokio::test]
async fn the_refused_keys_of_a_batch_give_a_batch_error() {
    let refusal = Error::BatchDelete(Box::new(BatchDeleteError {
        total: 3,
        failures: vec![BatchDeleteFailure {
            key: "b".to_owned(),
            code: "AccessDenied".to_owned(),
            message: "no".to_owned(),
        }],
    }));
    let backend = BatchLayer::new(Arc::new(MemoryBackend::new()), Some(refusal));
    let instance = plain_instance(backend.clone());
    let keys = ["a", "b", "c"].map(str::to_owned);
    let error = instance.delete_many(&OpCtx::default(), &keys).await.err().unwrap();
    assert!(matches!(&error, Error::BatchDelete(batch) if batch.failures.len() == 1 && batch.total == 3));
    assert_eq!(error.status(), 502);
    assert_eq!(backend.singles.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_back_end_without_the_batch_deletes_each_key() {
    let memory = Arc::new(MemoryBackend::with_objects(&[("a", "1"), ("b", "2")]));
    let instance = plain_instance(memory.clone());
    let keys = ["a", "b"].map(str::to_owned);
    instance.delete_many(&OpCtx::default(), &keys).await.unwrap();
    assert!(memory.keys().is_empty());
}

// ---- the permissions that the calls teach ----

/// A back end that answers 403 for one key, as a policy of a prefix does.
struct ForbiddenKey {
    memory: MemoryBackend,
    forbidden: String,
}

impl MemoryLayer for ForbiddenKey {
    fn memory(&self) -> &MemoryBackend {
        &self.memory
    }
    fn get<'a>(
        &'a self,
        ctx: &'a OpCtx,
        key: &'a str,
        headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        if key == self.forbidden {
            return Box::pin(async { Err(Error::upstream(403, "AccessDenied", "")) });
        }
        self.memory.get(ctx, key, headers)
    }
}

#[tokio::test]
async fn the_denial_of_one_object_does_not_block_the_other_requests() {
    let instance = read_write_instance(Arc::new(ForbiddenKey {
        memory: MemoryBackend::with_objects(&[("tenant/ok.txt", "ok")]),
        forbidden: "tenant/secret.txt".to_owned(),
    }));
    let ctx = OpCtx::default();
    let error = instance
        .get(&ctx, "tenant/secret.txt", &HeaderMap::new())
        .await
        .err()
        .unwrap();
    assert_eq!(error.status(), 403);
    let read = instance.capability(PERMISSION_READ);
    assert_eq!(
        (read.state, read.source.as_str()),
        (CapabilityStateName::Denied, "provider")
    );
    assert!(instance.permitted(PERMISSION_READ));
    assert!(instance.require_permission(PERMISSION_READ).is_ok());
    let response = instance.get(&ctx, "tenant/ok.txt", &HeaderMap::new()).await.unwrap();
    assert_eq!(&body_bytes(response.body).await[..], b"ok");
    assert_eq!(instance.capability(PERMISSION_READ).state, CapabilityStateName::Allowed);

    // The reported denial is a short hint, not a lasting verdict.
    instance.observe_permission(PERMISSION_WRITE, Some(&Error::upstream(403, "", "")));
    assert_eq!(instance.capability(PERMISSION_WRITE).state, CapabilityStateName::Denied);
    instance.caps.lock().unwrap().write.expires = Some(crate::common::time::Timestamp::now().plus_secs(-1));
    let write = instance.capability(PERMISSION_WRITE);
    assert_eq!(write.state, CapabilityStateName::Unknown);
    assert!(write.allowed);

    // A configuration ceiling stays a hard gate.
    let readonly = read_only_instance(Arc::new(MemoryBackend::new()));
    let error = readonly.require_permission(PERMISSION_WRITE).err().unwrap();
    assert!(error.has_code("permission_denied"));
    assert_eq!(
        error.public_message(),
        "instance \"readonly\" does not expose write permission"
    );
    readonly.observe_permission(PERMISSION_WRITE, None);
    assert_eq!(readonly.capability(PERMISSION_WRITE).source, "configuration");
}

#[tokio::test]
async fn a_read_answer_403_is_a_denial_and_other_errors_teach_nothing() {
    struct Status403 {
        memory: MemoryBackend,
    }
    impl MemoryLayer for Status403 {
        fn memory(&self) -> &MemoryBackend {
            &self.memory
        }
        fn head<'a>(&'a self, _ctx: &'a OpCtx, _key: &'a str) -> BoxFuture<'a, Result<ObjectResponse>> {
            Box::pin(async {
                Ok(ObjectResponse {
                    status: 403,
                    headers: HeaderMap::new(),
                    body: empty(),
                })
            })
        }
    }
    let instance = read_write_instance(Arc::new(Status403 {
        memory: MemoryBackend::new(),
    }));
    let error = instance.head(&OpCtx::default(), "tenant/x").await.err().unwrap();
    assert_eq!(error.code(), "accessdenied");
    assert_eq!(instance.capability(PERMISSION_READ).state, CapabilityStateName::Denied);
    instance.observe_permission(PERMISSION_WRITE, Some(&Error::upstream(500, "", "")));
    assert_eq!(
        instance.capability(PERMISSION_WRITE).state,
        CapabilityStateName::Unknown
    );
}

#[tokio::test]
async fn force_read_only_refuses_the_writes() {
    let policy = crate::common::config::RuntimePolicy {
        access_mode: crate::common::config::AccessMode::ForceReadOnly,
        ..Default::default()
    };
    let instance = crate::testkit::instance_with_policy(
        bucket_config("rw", "", &[PERMISSION_READ, PERMISSION_WRITE]),
        Arc::new(MemoryBackend::new()),
        policy,
    );
    assert!(!instance.permitted(PERMISSION_WRITE));
    assert!(instance.permitted(PERMISSION_READ));
    assert_eq!(instance.capability(PERMISSION_WRITE).source, "runtime");
    instance.observe_permission(PERMISSION_WRITE, None);
    assert_eq!(instance.capability(PERMISSION_WRITE).source, "runtime");
}

/// A back end whose discovery fails or finds a denial.
struct Discovery {
    memory: MemoryBackend,
    result: std::result::Result<DiscoveredCapabilities, Error>,
}

impl MemoryLayer for Discovery {
    fn memory(&self) -> &MemoryBackend {
        &self.memory
    }
    fn discover_capabilities<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<DiscoveredCapabilities>> {
        let result = self.result.clone();
        Box::pin(async move { result })
    }
}

#[tokio::test]
async fn the_refresh_of_the_permissions_keeps_the_state_on_a_probe_error() {
    let instance = plain_instance(Arc::new(Discovery {
        memory: MemoryBackend::new(),
        result: Err(Error::upstream(500, "InternalError", "")),
    }));
    let read = instance.refresh_capabilities(&OpCtx::default()).await.read;
    assert!(!read.verified && read.allowed);

    let mut found = DiscoveredCapabilities::default();
    found.states.insert(
        PERMISSION_READ.to_owned(),
        capability::denied("s3-list-probe", "denied", true),
    );
    let instance = plain_instance(Arc::new(Discovery {
        memory: MemoryBackend::new(),
        result: Ok(found),
    }));
    // A canceled probe leaves the state as it is.
    let canceled = OpCtx::default();
    canceled.cancel.cancel();
    let caps = instance.refresh_capabilities(&canceled).await;
    assert_eq!(caps.read.state, CapabilityStateName::Unknown);
    let caps = instance.refresh_capabilities(&OpCtx::default()).await;
    assert_eq!(caps.read.state, CapabilityStateName::Denied);
    assert!(!instance.permitted(PERMISSION_READ));
    assert!(caps.checked_at.is_some());
}

// ---- the reads, the gates and the budget ----

#[tokio::test]
async fn a_read_holds_its_slot_until_its_body_ends() {
    let memory = read_write_backend();
    let mut instance = instance_over(bucket_config("rw", "tenant/", &[PERMISSION_READ]), memory.clone());
    instance.gate = super::gate::Gate::with_wait(1, Duration::from_millis(50));
    let instance = Arc::new(instance);
    let budget = Arc::new(Budget::new(0, 0));
    let ctx = OpCtx::with_budget(budget.clone());
    let response = instance
        .get(&ctx, "tenant/folder/direct.txt", &HeaderMap::new())
        .await
        .unwrap();
    assert_eq!(instance.gate.held(), 1);
    let error = instance.head(&ctx, "tenant/folder/direct.txt").await.err().unwrap();
    assert!(error.has_code("storage_busy"));
    // A call for an operation that holds the slot takes no other slot.
    assert!(
        instance
            .head(&ctx.gated(GateMode::Exempt), "tenant/folder/direct.txt")
            .await
            .is_ok()
    );
    assert_eq!(&body_bytes(response.body).await[..], b"direct");
    assert_eq!(instance.gate.held(), 0);
    let usage = budget.usage();
    assert_eq!((usage.storage_requests, usage.storage_bytes), (3, 6));
    // A dropped body gives the slot back.
    let response = instance
        .get(&ctx, "tenant/folder/direct.txt", &HeaderMap::new())
        .await
        .unwrap();
    drop(response);
    assert_eq!(instance.gate.held(), 0);
}

#[tokio::test]
async fn the_budget_of_requests_stops_a_call_before_the_provider() {
    let memory = read_write_backend();
    let instance = read_write_instance(memory.clone());
    let ctx = OpCtx::with_budget(Arc::new(Budget::new(1, 0)));
    instance.head(&ctx, "tenant/folder/direct.txt").await.unwrap();
    let error = instance.head(&ctx, "tenant/folder/direct.txt").await.err().unwrap();
    assert_eq!(error.code(), "resource_budget_exceeded");
    assert_eq!(memory.state().head_count, 1);
    let bytes = OpCtx::with_budget(Arc::new(Budget::new(0, 3)));
    let error = instance
        .put(&bytes, "tenant/x", full("abcd"), 4, "text/plain")
        .await
        .err()
        .unwrap();
    assert_eq!(error.status(), 429);
    assert!(!memory.contains("tenant/x"));
}

#[tokio::test]
async fn the_version_of_the_context_goes_to_the_version_calls() {
    let memory = Arc::new(MemoryBackend::new().with_versions());
    memory.add_version(
        "tenant/v.txt",
        MemoryVersion {
            id: "v1".to_owned(),
            data: Bytes::from_static(b"old"),
            content_type: "text/plain".to_owned(),
            ..MemoryVersion::default()
        },
    );
    let instance = read_write_instance(memory.clone());
    instance.set_versioning_available(true);
    let ctx = OpCtx::default().with_version(Some("v1"));
    let head = instance.head(&ctx, "tenant/v.txt").await.unwrap();
    assert_eq!(head.headers.get("etag").unwrap(), "\"version-v1\"");
    let mut headers = HeaderMap::new();
    headers.insert("if-match", "\"x\"".parse().unwrap());
    let response = instance.get(&ctx, "tenant/v.txt", &headers).await.unwrap();
    assert_eq!(&body_bytes(response.body).await[..], b"old");
    assert!(memory.state().last_get_headers.get("if-match").is_none());
    // An empty version reads the current object.
    assert!(
        instance
            .head_version(&OpCtx::default(), "tenant/v.txt", " ")
            .await
            .is_err()
    );
}

// ---- the writes ----

#[tokio::test]
async fn a_write_that_creates_only_refuses_an_existing_object() {
    let memory = read_write_backend();
    let instance = read_write_instance(memory.clone());
    let ctx = OpCtx::default();
    let error = instance
        .put_if_absent(&ctx, "tenant/folder/direct.txt", full("x"), 1, "text/plain")
        .await
        .err()
        .unwrap();
    assert!(error.has_code("object_exists"));
    assert_eq!(error.status(), 409);
    instance
        .put_if_absent(&ctx, "tenant/new.txt", full("new"), 3, "text/plain")
        .await
        .unwrap();
    assert_eq!(&memory.object("tenant/new.txt").unwrap().data[..], b"new");
    assert_eq!(
        instance.capability(PERMISSION_WRITE).state,
        CapabilityStateName::Allowed
    );
}

#[tokio::test]
async fn the_uploads_check_the_write_ceiling_first() {
    let instance = read_write_instance(read_write_backend());
    let ctx = ctx_with_ceiling(ACTION_WRITE, 10, "rid-up");
    let error = instance
        .upload_part(&ctx, "tenant/x", "upload-1", 1, full("0123456789ab"), 12)
        .await
        .err()
        .unwrap();
    assert!(is_ceiling(&error));
    let error = instance
        .initiate_resumable(&ctx, "tenant/x", 12, "text/plain")
        .await
        .err()
        .unwrap();
    assert!(is_ceiling(&error));
    let error = instance
        .upload_resumable_chunk(&ctx, "session", full("abc"), 0, 3, 12, "text/plain")
        .await
        .err()
        .unwrap();
    assert!(is_ceiling(&error));
    let error = instance
        .put_if_absent(&ctx, "tenant/x", full("0123456789ab"), 12, "text/plain")
        .await
        .err()
        .unwrap();
    assert!(is_ceiling(&error));
    let error = instance
        .put(&ctx, "tenant/x", full("abc"), -1, "text/plain")
        .await
        .err()
        .unwrap();
    assert!(is_ceiling(&error));
    instance
        .put(&ctx, "tenant/x", full("0123456789"), 10, "text/plain")
        .await
        .unwrap();
}

#[tokio::test]
async fn a_multipart_upload_goes_through_the_instance() {
    let memory = Arc::new(MemoryBackend::new());
    let instance = read_write_instance(memory.clone());
    let ctx = OpCtx::default();
    let id = instance
        .initiate_multipart(&ctx, "tenant/m", "text/plain")
        .await
        .unwrap();
    let etag = instance
        .upload_part(&ctx, "tenant/m", &id, 1, full("part"), 4)
        .await
        .unwrap();
    let parts = instance.list_multipart_parts(&ctx, "tenant/m", &id).await.unwrap();
    assert_eq!(parts.len(), 1);
    let completed = [crate::common::storage::CompletedPart {
        number: 1,
        etag,
        ..Default::default()
    }];
    instance
        .complete_multipart(&ctx, "tenant/m", &id, &completed)
        .await
        .unwrap();
    assert_eq!(&memory.object("tenant/m").unwrap().data[..], b"part");
    let id = instance.initiate_multipart(&ctx, "tenant/n", "").await.unwrap();
    instance.abort_multipart(&ctx, "tenant/n", &id).await.unwrap();
    assert!(memory.state().multipart.is_empty());
    let error = instance
        .initiate_resumable(&ctx, "tenant/r", 3, "")
        .await
        .err()
        .unwrap();
    assert_eq!(error.status(), 502);
}

// ---- the copies, the moves and the versions ----

#[tokio::test]
async fn a_copy_checks_its_source_with_a_head_when_a_ceiling_applies() {
    let memory = Arc::new(MemoryBackend::new());
    memory.insert("tenant/folder/big.bin", vec![b'x'; 40], "application/octet-stream");
    let instance = read_write_instance(memory.clone());
    let ctx = ctx_with_ceiling(ACTION_WRITE, 10, "rid-meta");
    let error = instance
        .copy(&ctx, "tenant/folder/big.bin", "tenant/folder/copy.bin")
        .await
        .err()
        .unwrap();
    assert!(is_ceiling(&error));
    assert!(!memory.contains("tenant/folder/copy.bin"));
    // The copy of a known size trusts the size of the caller and makes no HEAD request.
    let before = memory.state().head_count;
    let error = instance
        .copy_sized(&ctx, "tenant/folder/big.bin", "tenant/folder/copy.bin", 40, None)
        .await
        .err()
        .unwrap();
    assert!(is_ceiling(&error));
    assert_eq!(memory.state().head_count, before);
}

#[tokio::test]
async fn a_copy_without_a_ceiling_makes_no_head() {
    let memory = Arc::new(MemoryBackend::new());
    memory.insert("tenant/folder/big.bin", vec![b'x'; 5000], "");
    let instance = read_write_instance(memory.clone());
    instance
        .copy(&OpCtx::default(), "tenant/folder/big.bin", "tenant/other/big.bin")
        .await
        .unwrap();
    assert!(memory.contains("tenant/other/big.bin"));
    assert_eq!(memory.state().head_count, 0);
    assert_eq!(instance.capability(PERMISSION_READ).state, CapabilityStateName::Allowed);
    assert_eq!(
        instance.capability(PERMISSION_WRITE).state,
        CapabilityStateName::Allowed
    );
    let error = instance
        .copy(&OpCtx::default(), "tenant/none", "tenant/x")
        .await
        .err()
        .unwrap();
    assert!(error.is_not_found());
    let error = instance
        .move_object(&OpCtx::default(), "tenant/a", "tenant/b")
        .await
        .err()
        .unwrap();
    assert!(error.has_code("move_unsupported"));
    assert!(!instance.moves_objects());
    assert!(
        instance
            .remove_empty_folders(&OpCtx::default(), "tenant/")
            .await
            .is_ok()
    );
}

/// A back end that copies in parts: it records the options and takes the gate of each part.
struct PartCopier {
    memory: Arc<MemoryBackend>,
    calls: Mutex<Vec<(String, String, String, usize)>>,
    held: AtomicI64,
}

impl MemoryLayer for PartCopier {
    fn memory(&self) -> &MemoryBackend {
        &self.memory
    }
    fn multipart_copier(&self) -> Option<&dyn MultipartCopier> {
        Some(self)
    }
}

impl MultipartCopier for PartCopier {
    fn copy_multipart<'a>(
        &'a self,
        ctx: &'a OpCtx,
        source: &'a str,
        destination: &'a str,
        options: MultipartCopyOptions,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            assert_eq!(ctx.gate, GateMode::Unbounded);
            let gate = options.gate.clone().unwrap();
            let slot = gate(ctx.clone()).await?;
            self.held.store(1, Ordering::SeqCst);
            drop(slot);
            if let Some(progress) = &options.progress {
                progress(7);
            }
            self.calls.lock().unwrap().push((
                source.to_owned(),
                destination.to_owned(),
                options.source_version.clone(),
                options.extra_headers.len(),
            ));
            self.memory.copy(ctx, source, destination).await
        })
    }
}

#[tokio::test]
async fn a_large_copy_goes_in_parts_with_the_gates_of_the_instance() {
    let memory = Arc::new(MemoryBackend::new());
    memory.insert("tenant/big.bin", vec![b'x'; 2048], "");
    let copier = Arc::new(PartCopier {
        memory: memory.clone(),
        calls: Mutex::new(Vec::new()),
        held: AtomicI64::new(0),
    });
    let instance = read_write_instance(copier.clone());
    instance.set_multipart_copy_threshold(1024);
    assert!(instance.copies_in_parts(1024));
    assert!(!instance.copies_in_parts(1023));
    let copied = Arc::new(AtomicI64::new(0));
    let progress = copied.clone();
    let budget = Arc::new(Budget::new(0, 0));
    instance
        .copy_sized(
            &OpCtx::with_budget(budget.clone()),
            "tenant/big.bin",
            "tenant/copy/big.bin",
            2048,
            Some(Arc::new(move |size| {
                progress.fetch_add(size, Ordering::SeqCst);
            })),
        )
        .await
        .unwrap();
    assert_eq!(copied.load(Ordering::SeqCst), 7);
    assert_eq!(copier.held.load(Ordering::SeqCst), 1);
    assert_eq!(budget.usage().storage_requests, 1);
    assert!(memory.contains("tenant/copy/big.bin"));
    // A small copy is one request.
    instance
        .copy_sized(&OpCtx::default(), "tenant/big.bin", "tenant/small.bin", 10, None)
        .await
        .unwrap();
    assert_eq!(copier.calls.lock().unwrap().len(), 1);
    // The copy in parts of the API checks the ceilings of its source.
    let ctx = ctx_with_ceiling(ACTION_READ, 100, "rid-parts");
    let error = instance
        .copy_multipart(&ctx, "tenant/big.bin", "tenant/x", MultipartCopyOptions::default())
        .await
        .err()
        .unwrap();
    assert!(is_ceiling(&error));
}

fn versioned_backend() -> Arc<MemoryBackend> {
    let memory = Arc::new(MemoryBackend::new().with_versions());
    let now = crate::common::time::Timestamp::now();
    for (id, data, current, seconds) in [("v2", "current", true, 0), ("v1", "previous", false, -3600)] {
        memory.add_version(
            "tenant/versioned.txt",
            MemoryVersion {
                id: id.to_owned(),
                data: Bytes::from(data),
                content_type: "text/plain".to_owned(),
                modified: Some(now.plus_secs(seconds)),
                current,
                ..MemoryVersion::default()
            },
        );
    }
    memory.add_version(
        "tenant/versioned.txt",
        MemoryVersion {
            id: "delete-marker".to_owned(),
            modified: Some(now.plus_secs(-7200)),
            delete_marker: true,
            ..MemoryVersion::default()
        },
    );
    memory.insert("tenant/versioned.txt", "current", "text/plain");
    memory
}

#[tokio::test]
async fn the_versioning_probe_hides_a_provider_without_versions() {
    let supported = plain_instance(Arc::new(MemoryBackend::new().with_versions()));
    assert!(supported.probe_versioning(&OpCtx::default()).await);
    assert!(supported.versioning_available());
    assert_eq!(supported.versioning_state(), None);

    let unsupported_backend = MemoryBackend::new().with_versions();
    unsupported_backend.state().version_list_error = Some(Error::upstream(
        501,
        "NotImplemented",
        "version listing is not implemented",
    ));
    let unsupported = plain_instance(Arc::new(unsupported_backend));
    assert!(!unsupported.probe_versioning(&OpCtx::default()).await);
    assert!(!unsupported.versioning_available());
    assert!(!unsupported.public_info().versioning_supported);
    assert_eq!(unsupported.versioning_state(), Some("off"));
    let error = unsupported
        .list_versions(&OpCtx::default(), "k", "", 10)
        .await
        .err()
        .unwrap();
    assert!(error.has_code("versioning_unavailable"));
    assert_eq!(error.status(), 501);

    let without = plain_instance(Arc::new(MemoryBackend::new()));
    assert!(!without.probe_versioning(&OpCtx::default()).await);
    assert!(without.version_store().is_err());
}

#[tokio::test]
async fn the_versioning_probe_reads_the_status_of_the_bucket() {
    let (instance, _) = ghost_instance(info::FLAVOUR_MINIO, false);
    // The ghost lister has no version store: the probe finds no versions.
    assert!(!instance.probe_versioning(&OpCtx::default()).await);
    assert_eq!(instance.versioning_state(), Some("off"));

    struct Versioned {
        memory: MemoryBackend,
        status: String,
    }
    impl MemoryLayer for Versioned {
        fn memory(&self) -> &MemoryBackend {
            &self.memory
        }
        fn bucket_rules(&self) -> Option<&dyn BucketRules> {
            Some(self)
        }
    }
    impl BucketRules for Versioned {
        fn lifecycle_rules<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<Vec<LifecycleRule>>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn read_lifecycle<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<LifecycleDocument>> {
            Box::pin(async { Ok(LifecycleDocument::default()) })
        }
        fn write_lifecycle<'a>(&'a self, _ctx: &'a OpCtx, _body: Bytes) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
        fn delete_lifecycle<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<()>> {
            Box::pin(async { Ok(()) })
        }
        fn versioning_status<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<String>> {
            Box::pin(async move { Ok(self.status.clone()) })
        }
        fn provider_flavour<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<String>> {
            Box::pin(async { Ok(String::new()) })
        }
    }
    for (status, state) in [("Enabled", "enabled"), ("Suspended", "suspended"), ("", "off")] {
        let instance = plain_instance(Arc::new(Versioned {
            memory: MemoryBackend::new().with_versions(),
            status: status.to_owned(),
        }));
        assert!(instance.probe_versioning(&OpCtx::default()).await);
        assert_eq!(instance.versioning_state(), Some(state));
        assert_eq!(instance.public_info().versioning_state, state);
    }
}

#[tokio::test]
async fn the_version_calls_list_read_delete_and_restore() {
    let memory = versioned_backend();
    let instance = read_write_instance(memory.clone());
    instance.set_versioning_available(true);
    let ctx = OpCtx::default();
    let page = instance
        .list_versions(&ctx, "tenant/versioned.txt", "", 10)
        .await
        .unwrap();
    let order: Vec<&str> = page.versions.iter().map(|version| version.version.as_str()).collect();
    assert_eq!(order, vec!["v2", "v1", "delete-marker"]);
    let response = instance
        .get_version(&ctx, "tenant/versioned.txt", "v1", &HeaderMap::new())
        .await
        .unwrap();
    assert_eq!(&body_bytes(response.body).await[..], b"previous");
    instance
        .restore_version(&ctx, "tenant/versioned.txt", "v1")
        .await
        .unwrap();
    assert_eq!(&memory.object("tenant/versioned.txt").unwrap().data[..], b"previous");
    instance
        .delete_version(&ctx, "tenant/versioned.txt", "v2")
        .await
        .unwrap();
    assert_eq!(memory.state().deleted_versions, vec!["tenant/versioned.txt@v2"]);
    for error in [
        instance
            .delete_version(&ctx, "tenant/versioned.txt", " ")
            .await
            .err()
            .unwrap(),
        instance
            .restore_version(&ctx, "tenant/versioned.txt", "")
            .await
            .err()
            .unwrap(),
    ] {
        assert!(error.has_code("version_required"));
        assert_eq!(error.status(), 400);
    }
    assert!(
        instance
            .get_version(&ctx, "tenant/versioned.txt", "delete-marker", &HeaderMap::new())
            .await
            .err()
            .unwrap()
            .is_not_found()
    );
    assert_eq!(
        instance.capability(PERMISSION_DELETE).state,
        CapabilityStateName::Allowed
    );
}

#[tokio::test]
async fn a_restore_checks_the_ceilings_with_a_head_of_the_version() {
    let memory = versioned_backend();
    let instance = read_write_instance(memory.clone());
    instance.set_versioning_available(true);
    let ctx = ctx_with_ceiling(ACTION_WRITE, 5, "rid-restore");
    let error = instance
        .restore_version(&ctx, "tenant/versioned.txt", "v1")
        .await
        .err()
        .unwrap();
    assert!(is_ceiling(&error));
    assert_eq!(&memory.object("tenant/versioned.txt").unwrap().data[..], b"current");
    // A HEAD that fails stops the restore when a ceiling applies.
    let error = instance
        .restore_version(&ctx, "tenant/versioned.txt", "nothing")
        .await
        .err()
        .unwrap();
    assert!(error.is_not_found());
    let ctx = ctx_with_ceiling(ACTION_WRITE, 100, "rid-restore");
    instance
        .restore_version(&ctx, "tenant/versioned.txt", "v1")
        .await
        .unwrap();
}

#[tokio::test]
async fn a_large_version_comes_back_with_a_copy_in_parts() {
    let memory = versioned_backend();
    let copier = Arc::new(PartCopier {
        memory: memory.clone(),
        calls: Mutex::new(Vec::new()),
        held: AtomicI64::new(0),
    });
    let instance = read_write_instance(copier.clone());
    instance.set_versioning_available(true);
    instance.set_multipart_copy_threshold(5);
    instance
        .restore_version(&OpCtx::default(), "tenant/versioned.txt", "v1")
        .await
        .unwrap();
    let calls = copier.calls.lock().unwrap().clone();
    assert_eq!(
        calls,
        vec![(
            "tenant/versioned.txt".to_owned(),
            "tenant/versioned.txt".to_owned(),
            "v1".to_owned(),
            0
        )]
    );
}

// ---- the public facts ----

#[tokio::test]
async fn the_public_facts_of_an_instance_have_the_members_of_the_answers() {
    let instance = read_write_instance(read_write_backend());
    let info = instance.public_info();
    assert_eq!(info.id, "rw");
    assert_eq!(info.host, "test-auth");
    assert!(!info.tags_supported && !info.lifecycle_supported && !info.usage_supported);
    let text = String::from_utf8(crate::common::json::to_vec(&info).unwrap()).unwrap();
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    let keys: Vec<&str> = value.as_object().unwrap().keys().map(String::as_str).collect();
    let mut expected = vec![
        "id",
        "host",
        "name",
        "provider",
        "bucket",
        "region",
        "rootPrefix",
        "versioningSupported",
        "tagsSupported",
        "metadataEditSupported",
        "multipartUploadsSupported",
        "lifecycleSupported",
        "objectLockSupported",
        "bucketEncryptionSupported",
        "encryption",
        "defaultEncryption",
        "usageSupported",
        "capabilities",
        "operations",
    ];
    expected.sort_unstable();
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, expected);
    assert!(text.starts_with(
        "{\"id\":\"rw\",\"host\":\"test-auth\",\"name\":\"rw\",\"provider\":\"s3\",\"bucket\":\"rw-bucket\",\"region\":\"test\",\"rootPrefix\":\"tenant/\",\"versioningSupported\":false,\"tagsSupported\":false"
    ));
    assert!(text.contains(
        "\"capabilities\":{\"read\":{\"state\":\"unknown\",\"allowed\":true,\"verified\":false,\"source\":\"credentials\",\"reason\":\"the permission is enabled by the configuration ceiling and will be verified when used\"}"
    ));
    assert_eq!(value["operations"].as_object().unwrap().len(), 10);
    assert_eq!(value["operations"]["createFolder"]["state"], "unknown");
}

#[test]
fn the_compiled_copy_threshold_has_a_default() {
    assert_eq!(DEFAULT_MULTIPART_COPY_THRESHOLD, 5_100_273_664);
    assert!(compiled_copy_threshold().is_ok());
    assert!(multipart_copy_threshold() >= 1);
    let instance = plain_instance(Arc::new(MemoryBackend::new()));
    assert_eq!(instance.multipart_copy_threshold(), multipart_copy_threshold());
}

#[tokio::test]
async fn bounded_futures_keep_their_order() {
    let futures: Vec<_> = (0..10u64)
        .map(|index| async move {
            tokio::time::sleep(Duration::from_millis(10 - index)).await;
            index
        })
        .collect();
    assert_eq!(ops::run_bounded(futures, 3).await, (0..10).collect::<Vec<_>>());
}

// ---- the checks of many objects and the start of a bucket ----

#[tokio::test]
async fn a_prefix_with_one_object_over_the_ceiling_is_refused_before_the_first_effect() {
    let memory = Arc::new(MemoryBackend::new());
    for (key, size) in [("a.txt", 3), ("b.txt", 5), ("z.txt", 30)] {
        memory.insert(&format!("tenant/folder/set/{key}"), vec![b'x'; size], "");
    }
    memory.insert("tenant/folder/other.txt", vec![b'x'; 300], "");
    let instance = read_write_instance(memory.clone());
    let actions = [ACTION_READ, ACTION_WRITE];
    let ctx = ctx_with_ceiling(ACTION_READ, 10, "rid-prefix");
    let error = ceiling::check_listed_sizes(&ctx, &instance, "folder/set/", &actions)
        .await
        .err()
        .unwrap();
    assert!(is_ceiling(&error));
    assert!(error.public_message().contains("action object.read"));
    let ctx = ctx_with_ceiling(ACTION_WRITE, 30, "rid-prefix");
    ceiling::check_listed_sizes(&ctx, &instance, "folder/set/", &actions)
        .await
        .unwrap();
    // Without a ceiling, the check lists nothing.
    let calls = memory.state().list_calls;
    ceiling::check_listed_sizes(&OpCtx::default(), &instance, "folder/", &actions)
        .await
        .unwrap();
    assert_eq!(memory.state().list_calls, calls);
    // A job context keeps its own copy of the ceilings.
    let mut map = ceiling::CeilingMap::new();
    map.entry(ACTION_WRITE.to_owned())
        .or_default()
        .insert(MAX_OBJECT_SIZE.to_owned(), 10);
    let job = ceiling::with_access_ceilings(&OpCtx::default(), &map);
    let error = ceiling::check_listed_sizes(&job, &instance, "folder/set/", &actions)
        .await
        .err()
        .unwrap();
    assert!(error.public_message().contains("action object.write"));
    assert!(
        ceiling::with_access_ceilings(&OpCtx::default(), &ceiling::CeilingMap::new())
            .ceilings
            .is_none()
    );
}

#[tokio::test]
async fn a_bucket_needs_its_auth_block() {
    let cfg = bucket_config("rw", "", &[PERMISSION_READ]);
    let error = Instance::for_bucket(cfg, None, Arc::new(Default::default()), super::gate::Gate::new(4))
        .err()
        .unwrap();
    assert_eq!(
        error.to_string(),
        "bucket \"rw\" references an unavailable authentication"
    );
}

#[test]
fn a_read_works_with_a_success_or_not_modified() {
    for status in [200, 206, 204, 304] {
        assert!(ops::is_successful_read_status(status), "{status}");
    }
    for status in [199, 300, 301, 404, 500] {
        assert!(!ops::is_successful_read_status(status), "{status}");
    }
}

#[tokio::test]
async fn the_cache_tells_which_bytes_it_holds() {
    let memory = Arc::new(MemoryBackend::new());
    memory.insert("tenant/k", vec![b'x'; 100], "");
    let instance = read_write_instance(memory);
    let source = range::RangeSource::open(&OpCtx::default(), &instance, "k")
        .await
        .unwrap();
    assert!(!source.has_byte(5));
    source.read_range(0, 10).await.unwrap();
    assert!(source.has_byte(5) && source.has_byte(9));
    assert!(!source.has_byte(10));
}

/// A back end whose reads never end.
struct StalledReads {
    memory: MemoryBackend,
}

impl MemoryLayer for StalledReads {
    fn memory(&self) -> &MemoryBackend {
        &self.memory
    }
    fn get<'a>(
        &'a self,
        _ctx: &'a OpCtx,
        _key: &'a str,
        _headers: &'a HeaderMap,
    ) -> BoxFuture<'a, Result<ObjectResponse>> {
        Box::pin(std::future::pending())
    }
}

#[tokio::test]
async fn a_canceled_job_stops_a_read_that_waits_for_the_provider() {
    let instance = read_write_instance(Arc::new(StalledReads {
        memory: MemoryBackend::new(),
    }));
    let ctx = OpCtx::default().gated(GateMode::Unbounded);
    let token = ctx.cancel.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        token.cancel();
    });
    let error = instance.get(&ctx, "tenant/x", &HeaderMap::new()).await.err().unwrap();
    assert_eq!(error, Error::Canceled);
    assert_eq!(instance.gate.held(), 0);
    let deadline = OpCtx::default().with_timeout(Duration::from_millis(20));
    let error = instance
        .get(&deadline, "tenant/x", &HeaderMap::new())
        .await
        .err()
        .unwrap();
    assert_eq!(error, Error::Timeout);
}
