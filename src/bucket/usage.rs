//! Usage and quota of a bucket.
//!
//! The S3 API gives no usage and no quota of a bucket. Each provider gives them in its own admin API. The `usage`
//! block of an `auth` block names the reader (`source`) and its URLs: the server never guesses the source. Without
//! the block, the server makes no admin request and the page shows no usage. There is one reader for each source:
//! `usage_garage`, `usage_seaweedfs` and `usage_minio`. AWS S3 has no quota: no reader.
//!
//! Cost and safety: each admin request is a read (`GET`), with a time limit of 5 seconds and a size limit for the
//! answer. The server keeps the result of an instance for 60 seconds (a failure for 10 seconds), and one read at a
//! time runs for an instance. A request with `fresh=1` (the reload of the page, or the end of a change) reads again
//! when the result is older than 10 seconds. The token and the URLs of the admin API never go into an answer or a
//! log line: the errors of the readers name the step and the HTTP status only.
//!
//! The numbers are for the whole bucket, also for an instance with a root prefix.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use tokio::sync::watch;

use super::support::quote;
use super::usage_admin::USAGE_TIMEOUT;
use super::{BucketUsage, BucketUsageReader, StorageCapacity};
use crate::access;
use crate::common::BoxFuture;
use crate::common::app::App;
use crate::common::config::{PERMISSION_READ, PROVIDER_VOLUME};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Req, Response, api_error, json, method_not_allowed};
use crate::common::time::{Timestamp, serialize_or_zero};
use crate::instance::Instance;

/// The source of a usage block: Garage.
pub const USAGE_SOURCE_GARAGE: &str = "garage";
/// The source of a usage block: SeaweedFS.
pub const USAGE_SOURCE_SEAWEEDFS: &str = "seaweedfs";
/// The source of a usage block: MinIO.
pub const USAGE_SOURCE_MINIO: &str = "minio";
/// The source of the usage of a volume: the size of its file system. A volume block has it; a usage block cannot
/// name it.
pub const USAGE_SOURCE_STATFS: &str = "statfs";

/// The life of a result in the cache of an instance.
pub const USAGE_CACHE_TTL: Duration = Duration::from_secs(60);
/// The life of a failure in the cache, and the shortest interval between two reads with `fresh=1`.
pub const USAGE_RETRY_INTERVAL: Duration = Duration::from_secs(10);

/// The used part of the limit from which the level is `warning`.
const USAGE_WARNING_RATIO: f64 = 0.80;
/// The used part of the limit from which the level is `error`.
const USAGE_ERROR_RATIO: f64 = 0.95;

/// The scope of the capacity: the data partitions of the nodes of a Garage cluster.
pub const STORAGE_SCOPE_CLUSTER: &str = "cluster";
/// The scope of the capacity: the disks of the volume servers of SeaweedFS or the drives of MinIO.
pub const STORAGE_SCOPE_DISKS: &str = "disks";
/// The scope of the capacity: the file system of a volume (`statfs`).
pub const STORAGE_SCOPE_FILESYSTEM: &str = "filesystem";

/// The state of the count of the files of a volume: the count runs, and the number is at least the bytes so far.
pub const SELF_STATE_COMPUTING: &str = "computing";
/// The state of the count of the files of a volume: the count stopped at its budget.
pub const SELF_STATE_PARTIAL: &str = "partial";
/// The state of the count of the files of a volume: the count is complete.
pub const SELF_STATE_READY: &str = "ready";

/// Why the numbers of a source are approximate. The page shows the text in a tooltip.
pub fn usage_approximate_reason(source: &str) -> &'static str {
    match source {
        USAGE_SOURCE_SEAWEEDFS => {
            "SeaweedFS gives the size of the volumes of the bucket, with a delay of some seconds. The number of objects is not known."
        }
        USAGE_SOURCE_MINIO => {
            "MinIO counts the usage in a background scan, about one time each minute or less often on a large server."
        }
        _ => "",
    }
}

/// The answer for an instance without a usage block.
pub fn usage_unsupported() -> Error {
    Error::api(
        501,
        "usage_unsupported",
        "this bucket has no usage source in the configuration",
    )
}

/// One read of the usage of an instance: the part of the bucket and the part of the storage behind it, each with its
/// error. A failure of one part does not hide the other. `storage` is `None` for a reader without the capacity of the
/// storage, and for a failed read of it.
#[derive(Clone, Debug, Default)]
pub struct UsageResult {
    /// The usage of the bucket. It is the empty value when `error` is set.
    pub value: BucketUsage,
    /// The failure of the read of the bucket.
    pub error: Option<Error>,
    /// The capacity of the storage.
    pub storage: Option<StorageCapacity>,
    /// The failure of the read of the storage.
    pub storage_error: Option<Error>,
}

impl UsageResult {
    /// True when a part of the read failed: the cache then keeps it for the retry interval only.
    pub fn failed(&self) -> bool {
        self.error.is_some() || self.storage_error.is_some()
    }

    fn with_error(error: &Error) -> Self {
        Self {
            error: Some(error.clone()),
            storage_error: Some(error.clone()),
            ..Self::default()
        }
    }
}

type Clock = Arc<dyn Fn() -> Timestamp + Send + Sync>;
type FlightSender = Arc<watch::Sender<Option<UsageResult>>>;

#[derive(Default)]
struct UsageCache {
    /// The last result and the time of its read, in milliseconds.
    result: Option<(UsageResult, i64)>,
    /// Open while a read runs. The other requests wait for it.
    flight: Option<FlightSender>,
}

struct UsageShared {
    cache: Mutex<UsageCache>,
    clock: Mutex<Clock>,
}

impl UsageShared {
    fn now_ms(&self) -> i64 {
        let clock = self.clock.lock().map(|clock| clock.clone()).ok();
        clock.map_or_else(|| Timestamp::now().unix_millis(), |clock| clock().unix_millis())
    }
}

/// The usage reader of an instance and its cache.
pub struct UsageCapability {
    /// The reader. `None` for an instance whose `auth` block has no `usage` block.
    pub reader: Mutex<Option<Arc<dyn BucketUsageReader>>>,
    source: Mutex<String>,
    shared: Arc<UsageShared>,
}

impl Default for UsageCapability {
    fn default() -> Self {
        Self {
            reader: Mutex::new(None),
            source: Mutex::new(String::new()),
            shared: Arc::new(UsageShared {
                cache: Mutex::new(UsageCache::default()),
                clock: Mutex::new(Arc::new(Timestamp::now)),
            }),
        }
    }
}

impl std::fmt::Debug for UsageCapability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UsageCapability").finish_non_exhaustive()
    }
}

impl UsageCapability {
    /// Set the reader and its source (`garage`, `seaweedfs`, `minio` or `statfs`).
    pub fn set_reader(&self, reader: Arc<dyn BucketUsageReader>, source: &str) {
        if let Ok(mut slot) = self.reader.lock() {
            *slot = Some(reader);
        }
        if let Ok(mut slot) = self.source.lock() {
            *slot = source.to_owned();
        }
    }

    /// Replace the clock of the cache. The tests move the time with it.
    pub fn set_clock(&self, clock: Arc<dyn Fn() -> Timestamp + Send + Sync>) {
        if let Ok(mut slot) = self.shared.clock.lock() {
            *slot = clock;
        }
    }
}

/// Close the open read when its task ends without a result (a panic): the waiters get a failure.
struct FlightGuard {
    shared: Arc<UsageShared>,
    sender: FlightSender,
    finished: bool,
}

impl Drop for FlightGuard {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        if let Ok(mut cache) = self.shared.cache.lock() {
            cache.flight = None;
        }
        let failure = UsageResult::with_error(&Error::internal("the read of the usage stopped"));
        self.sender.send_replace(Some(failure));
    }
}

enum Step {
    Cached(Box<UsageResult>),
    Wait(watch::Receiver<Option<UsageResult>>),
    Start(FlightSender, watch::Receiver<Option<UsageResult>>),
}

/// Make one read of the two parts at the same time, in 5 seconds for the two. The read does not stop with a request.
async fn read_usage(reader: Arc<dyn BucketUsageReader>, bucket: String, id: String, source: String) -> UsageResult {
    let ctx = OpCtx::default().with_timeout(USAGE_TIMEOUT);
    let net = USAGE_TIMEOUT + Duration::from_secs(1);
    let storage_part = async {
        match tokio::time::timeout(net, reader.storage_capacity(&ctx)).await {
            Ok(Ok(storage)) => (storage, None),
            Ok(Err(error)) => (None, Some(error)),
            Err(_) => (None, Some(Error::Timeout)),
        }
    };
    let bucket_part = async {
        match tokio::time::timeout(net, reader.bucket_usage(&ctx, &bucket)).await {
            Ok(result) => result,
            Err(_) => Err(Error::Timeout),
        }
    };
    let ((storage, storage_error), usage) = tokio::join!(storage_part, bucket_part);
    let mut result = UsageResult {
        storage,
        storage_error,
        ..UsageResult::default()
    };
    if let Some(error) = &result.storage_error {
        crate::log!("usage.error bucket={} source={source} part=storage: {error}", quote(&id));
    }
    match usage {
        Ok(mut value) => {
            value.source = source;
            result.value = value;
        }
        Err(error) => {
            crate::log!("usage.error bucket={} source={source}: {error}", quote(&id));
            result.error = Some(error);
        }
    }
    result
}

impl Instance {
    /// True when the page can show the usage of the bucket.
    pub fn usage_available(&self) -> bool {
        self.usage.reader.lock().is_ok_and(|reader| reader.is_some())
    }

    fn usage_reader(&self) -> Option<Arc<dyn BucketUsageReader>> {
        self.usage.reader.lock().ok().and_then(|reader| reader.clone())
    }

    /// The source of the usage: `garage`, `seaweedfs`, `minio`, or `statfs` for a volume.
    pub fn usage_source(&self) -> String {
        if let Ok(source) = self.usage.source.lock()
            && !source.is_empty()
        {
            return source.clone();
        }
        if let Some(reader) = self.usage_reader()
            && !reader.source().is_empty()
        {
            return reader.source().to_owned();
        }
        if self.cfg.provider == PROVIDER_VOLUME {
            return USAGE_SOURCE_STATFS.to_owned();
        }
        String::new()
    }

    /// The part of the bucket of [`Instance::usage_read`].
    pub async fn bucket_usage(&self, ctx: &OpCtx, fresh: bool) -> Result<BucketUsage> {
        let result = self.usage_read(ctx, fresh).await;
        match result.error {
            Some(error) => Err(error),
            None => Ok(result.value),
        }
    }

    /// The usage of the instance from the cache, or read now. One read at a time runs for the instance: the other
    /// requests wait for its result. With `fresh`, a result older than 10 seconds is read again. The read does not
    /// stop when the request that started it stops, so the other requests get its result.
    pub async fn usage_read(&self, ctx: &OpCtx, fresh: bool) -> UsageResult {
        let Some(reader) = self.usage_reader() else {
            return UsageResult {
                error: Some(usage_unsupported()),
                ..UsageResult::default()
            };
        };
        let source = self.usage_source();
        if reader.is_live() {
            return read_usage(reader, self.cfg.bucket.clone(), self.cfg.id.clone(), source).await;
        }
        let shared = self.usage.shared.clone();
        loop {
            let step = {
                let Ok(mut cache) = shared.cache.lock() else {
                    return UsageResult::with_error(&Error::internal("the cache of the usage is not available"));
                };
                let mut cached = None;
                if cache.flight.is_none()
                    && let Some((result, read_at)) = &cache.result
                {
                    let life = if result.failed() || fresh {
                        USAGE_RETRY_INTERVAL
                    } else {
                        USAGE_CACHE_TTL
                    };
                    let age = shared.now_ms().saturating_sub(*read_at);
                    if age < i64::try_from(life.as_millis()).unwrap_or(i64::MAX) {
                        cached = Some(Box::new(result.clone()));
                    }
                }
                if let Some(result) = cached {
                    Step::Cached(result)
                } else if let Some(sender) = &cache.flight {
                    Step::Wait(sender.subscribe())
                } else {
                    let (sender, receiver) = watch::channel(None);
                    let sender = Arc::new(sender);
                    cache.flight = Some(sender.clone());
                    Step::Start(sender, receiver)
                }
            };
            match step {
                Step::Cached(result) => return *result,
                Step::Wait(mut receiver) => {
                    let waited = ctx
                        .run(async {
                            receiver
                                .wait_for(Option::is_some)
                                .await
                                .map(|_| ())
                                .map_err(|_| Error::Canceled)
                        })
                        .await;
                    if let Err(error) = waited {
                        return UsageResult::with_error(&error);
                    }
                }
                Step::Start(sender, mut receiver) => {
                    let task_shared = shared.clone();
                    let task_sender = sender.clone();
                    let bucket = self.cfg.bucket.clone();
                    let id = self.cfg.id.clone();
                    tokio::spawn(async move {
                        let mut guard = FlightGuard {
                            shared: task_shared.clone(),
                            sender: task_sender.clone(),
                            finished: false,
                        };
                        let result = read_usage(reader, bucket, id, source).await;
                        let now = task_shared.now_ms();
                        if let Ok(mut cache) = task_shared.cache.lock() {
                            cache.result = Some((result.clone(), now));
                            cache.flight = None;
                        }
                        guard.finished = true;
                        task_sender.send_replace(Some(result));
                    });
                    let waited = receiver.wait_for(Option::is_some).await;
                    return match waited {
                        Ok(result) => result.clone().unwrap_or_default(),
                        Err(_) => UsageResult::with_error(&Error::internal("the read of the usage stopped")),
                    };
                }
            }
        }
    }

    /// Compare the source of the usage block with the provider that the lifecycle probe found. The source of the
    /// file applies. A different known provider gives a warning in the log. The probe makes no admin request.
    pub async fn probe_usage(&self, ctx: &OpCtx) {
        if !self.usage_available() || !self.permitted(PERMISSION_READ) {
            return;
        }
        let flavour = self.provider_flavour(ctx).await;
        let source = self.usage_source();
        if !flavour.is_empty() && flavour != source {
            crate::log!(
                "config.warning bucket {}: the usage block of auth {} has source = {}, but the provider answers as {}; the server uses the source of the file",
                quote(&self.cfg.id),
                quote(&self.cfg.auth_id),
                quote(&source),
                super::encryption::flavour_name(&flavour)
            );
        }
    }
}

/// The used part of the limit in percent, with one decimal (the next decimals are cut), and the level: empty without
/// a limit, `ok`, `warning` from 80 %, `error` from 95 %. With a limit of bytes and a limit of objects, the larger
/// part applies.
pub fn usage_level(value: &BucketUsage) -> (f64, &'static str) {
    let mut ratio = -1.0_f64;
    if value.limit_bytes > 0 && value.used_bytes >= 0 {
        ratio = value.used_bytes as f64 / value.limit_bytes as f64;
    }
    if value.limit_objects > 0 && value.used_objects >= 0 {
        ratio = ratio.max(value.used_objects as f64 / value.limit_objects as f64);
    }
    let percent = (ratio * 1000.0).floor() / 10.0;
    if ratio < 0.0 {
        (0.0, "")
    } else if ratio >= USAGE_ERROR_RATIO {
        (percent, "error")
    } else if ratio >= USAGE_WARNING_RATIO {
        (percent, "warning")
    } else {
        (percent, "ok")
    }
}

/// The used part of the storage in percent, with one decimal, and the level, as [`usage_level`] gives them.
pub fn storage_level(storage: &StorageCapacity) -> (f64, &'static str) {
    usage_level(&BucketUsage {
        used_bytes: storage.used_bytes,
        limit_bytes: storage.total_bytes,
        ..BucketUsage::default()
    })
}

// --- HTTP ---------------------------------------------------------------------------------------------------------

/// The error of a part of the answer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UsageErrorJson {
    /// The code.
    pub code: String,
    /// The message.
    pub message: String,
}

/// The capacity of the storage behind the bucket, as the answer gives it.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageJson {
    /// The scope: `cluster`, `disks` or `filesystem`.
    pub scope: String,
    /// The used bytes.
    pub used_bytes: i64,
    /// The total bytes.
    pub total_bytes: i64,
    /// The free bytes.
    pub free_bytes: i64,
    /// The used part in percent.
    pub percent: f64,
    /// The level.
    pub level: String,
    /// True for an approximate number.
    pub approximate: bool,
    /// Why the number is approximate.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub approximate_reason: String,
    /// What the numbers count.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub note: String,
    /// The time of the count at the source.
    #[serde(serialize_with = "serialize_or_zero")]
    pub as_of: Option<Timestamp>,
}

/// The answer of `GET /api/usage`.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UsageResponse {
    /// True: the instance has a usage source.
    pub supported: bool,
    /// False when the read failed. `error` then gives the reason, and the numbers are 0.
    pub available: bool,
    /// The error of the read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<UsageErrorJson>,
    /// The instance.
    pub instance: String,
    /// The bucket.
    pub bucket: String,
    /// The root prefix.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub root_prefix: String,
    /// The source.
    pub source: String,
    /// The used bytes.
    pub used_bytes: i64,
    /// The used objects, or -1.
    pub used_objects: i64,
    /// The limit of bytes, 0 without a limit.
    pub limit_bytes: i64,
    /// The limit of objects, 0 without a limit.
    pub limit_objects: i64,
    /// `provider`, `config` (`bucket.quota_bytes`) or empty without a limit.
    pub limit_source: String,
    /// True for an approximate number.
    pub approximate: bool,
    /// Why the number is approximate.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub approximate_reason: String,
    /// The time of the count at the source.
    #[serde(serialize_with = "serialize_or_zero")]
    pub as_of: Option<Timestamp>,
    /// The more constraining part: the quota of the bucket or the storage behind it.
    pub percent: f64,
    /// The level of that part.
    pub level: String,
    /// `quota`, `storage`, or empty when the answer has no limit.
    pub constraint: String,
    /// The used part of the quota of the bucket alone.
    pub quota_percent: f64,
    /// The level of the quota of the bucket alone.
    pub quota_level: String,
    /// The size of the files of a volume.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub self_bytes: Option<i64>,
    /// The state of the count of a volume: `computing`, `partial` or `ready`.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub self_state: String,
    /// The capacity of the storage behind the bucket.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage: Option<StorageJson>,
    /// The reason of a failed read of the storage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_error: Option<UsageErrorJson>,
}

/// Make the answer of `GET /api/usage` from a value. The limit of the operator (`bucket.quota_bytes`) applies when
/// the source gives no limit of bytes.
pub fn usage_answer(instance: &Instance, value: &BucketUsage) -> UsageResponse {
    let mut answer = UsageResponse {
        supported: true,
        available: true,
        instance: instance.cfg.id.clone(),
        bucket: instance.cfg.bucket.clone(),
        root_prefix: instance.cfg.root_prefix.clone(),
        source: value.source.clone(),
        used_bytes: value.used_bytes,
        used_objects: value.used_objects,
        limit_bytes: value.limit_bytes,
        limit_objects: value.limit_objects,
        approximate: value.approximate,
        as_of: value.as_of.map(Timestamp::utc),
        ..UsageResponse::default()
    };
    if answer.limit_bytes > 0 || answer.limit_objects > 0 {
        "provider".clone_into(&mut answer.limit_source);
    }
    if answer.limit_bytes == 0 && instance.cfg.quota_bytes > 0 {
        answer.limit_bytes = instance.cfg.quota_bytes;
        "config".clone_into(&mut answer.limit_source);
    }
    if answer.approximate {
        usage_approximate_reason(&value.source).clone_into(&mut answer.approximate_reason);
    }
    let (percent, level) = usage_level(&BucketUsage {
        used_bytes: answer.used_bytes,
        used_objects: answer.used_objects,
        limit_bytes: answer.limit_bytes,
        limit_objects: answer.limit_objects,
        ..BucketUsage::default()
    });
    answer.percent = percent;
    level.clone_into(&mut answer.level);
    answer.quota_percent = percent;
    level.clone_into(&mut answer.quota_level);
    if !answer.level.is_empty() {
        "quota".clone_into(&mut answer.constraint);
    }
    if !value.self_state.is_empty() {
        answer.self_bytes = Some(value.used_bytes);
        answer.self_state.clone_from(&value.self_state);
    }
    answer
}

/// Make the answer of `GET /api/usage` from the two parts of a read. A failed part gives its error, and the other
/// part stays. `percent`, `level` and `constraint` are the part with the larger used part.
pub fn usage_answer_of(instance: &Instance, result: &UsageResult) -> UsageResponse {
    let noun = if instance.cfg.provider == PROVIDER_VOLUME { "volume" } else { "bucket" };
    let mut answer = match &result.error {
        Some(error) => UsageResponse {
            supported: true,
            instance: instance.cfg.id.clone(),
            bucket: instance.cfg.bucket.clone(),
            root_prefix: instance.cfg.root_prefix.clone(),
            source: instance.usage_source(),
            error: Some(UsageErrorJson {
                code: "usage_unavailable".to_owned(),
                message: format!("The usage of the {noun} is unavailable: {error}."),
            }),
            ..UsageResponse::default()
        },
        None => usage_answer(instance, &result.value),
    };
    if let Some(error) = &result.storage_error {
        answer.storage_error = Some(UsageErrorJson {
            code: "storage_unavailable".to_owned(),
            message: format!("The capacity of the storage is unavailable: {error}."),
        });
    }
    if let Some(storage) = &result.storage {
        let (percent, level) = storage_level(storage);
        answer.storage = Some(StorageJson {
            scope: storage.scope.clone(),
            used_bytes: storage.used_bytes,
            total_bytes: storage.total_bytes,
            free_bytes: storage.free_bytes,
            percent,
            level: level.to_owned(),
            approximate: storage.approximate,
            approximate_reason: storage.approximate_reason.clone(),
            note: storage.note.clone(),
            as_of: storage.as_of.map(Timestamp::utc),
        });
        if !level.is_empty() && (answer.constraint.is_empty() || percent > answer.percent) {
            answer.percent = percent;
            level.clone_into(&mut answer.level);
            "storage".clone_into(&mut answer.constraint);
        }
    }
    answer
}

/// `GET` gives the usage and the quota of the bucket of an instance (permission read). An instance without a usage
/// block gives `{"supported": false}`. A failed read gives 200 with `"available": false` and the reason: an answer 502
/// would tell the page that the server does not answer, and a failure must not break the page.
pub fn handle_usage(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        if req.method != http::Method::GET {
            return method_not_allowed(&["GET"]);
        }
        match serve(&app, req).await {
            Ok(response) => response,
            Err(error) => api_error(&error),
        }
    })
}

async fn serve(app: &App, req: Req) -> Result<Response> {
    let Req { query, ctx, .. } = req;
    let instance = app.instance_of("", query.get("instance"))?.clone();
    instance.require_permission(PERMISSION_READ)?;
    access::authorize_read(app, &ctx, &instance, "").await?;
    if !instance.usage_available() {
        let mut answer: BTreeMap<&str, bool> = BTreeMap::new();
        answer.insert("supported", false);
        return Ok(json(200, &answer));
    }
    let fresh = query.get("fresh") == "1";
    let result = instance.usage_read(&ctx, fresh).await;
    Ok(json(200, &usage_answer_of(&instance, &result)))
}
