//! The storage instance: one bucket block or one volume block, over its back end.
//!
//! An [`Instance`] wraps a [`Backend`]. Each call takes a slot of the gate of the process and of the gate of the
//! instance, counts the resource budget of the context, checks the ceilings of the access policy, and learns the
//! permissions of the provider from the result (docs/ARCHITECTURE.md, "Storage interfaces"; docs/SECURITY.md,
//! "Permission enforcement"). The instance also gives the version functions, the multipart functions, the start
//! probes of the versioning, and the public facts of `/api/instances`.
//!
//! The feature work packages add their methods to `Instance` in their own folders (`impl Instance` blocks), and
//! keep their state in the fields that this structure gives them.

pub mod budget;
pub mod capability;
pub mod ceiling;
pub mod cursor;
pub mod gate;
pub mod info;
pub mod ops;
pub mod range;
pub mod versions;

#[cfg(test)]
mod ops_tests;

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use crate::common::config::{BucketConfig, PERMISSION_READ, RuntimePolicy};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::storage::{Backend, Capabilities, CapabilityState};
use crate::common::time::Timestamp;

pub use info::InstanceInfo;

/// The size of a source from which a copy goes in parts: 5 GiB minus 256 MiB. A single copy request accepts 5 GiB at
/// most; the margin keeps clear of that limit.
pub const DEFAULT_MULTIPART_COPY_THRESHOLD: i64 = (5 << 30) - (256 << 20);

/// The largest value of the copy threshold that a build can give: 5 GiB.
pub const MAX_MULTIPART_COPY_THRESHOLD: i64 = 5 << 30;

/// The copy threshold that the build gives (`STOWR_MULTIPART_COPY_THRESHOLD` at compile time, for the test images),
/// or `None` for a release build. A value that is not an integer from 1 to 5 GiB is an error: the start stops.
pub fn compiled_copy_threshold() -> Result<Option<i64>> {
    let Some(raw) = option_env!("STOWR_MULTIPART_COPY_THRESHOLD").map(str::trim) else {
        return Ok(None);
    };
    if raw.is_empty() {
        return Ok(None);
    }
    match raw.parse::<i64>() {
        Ok(value) if (1..=MAX_MULTIPART_COPY_THRESHOLD).contains(&value) => Ok(Some(value)),
        _ => Err(Error::internal(format!(
            "build value STOWR_MULTIPART_COPY_THRESHOLD must be an integer from 1 to {MAX_MULTIPART_COPY_THRESHOLD} bytes, got {raw:?}"
        ))),
    }
}

/// The copy threshold of the instances: the value of the build, else [`DEFAULT_MULTIPART_COPY_THRESHOLD`].
pub fn multipart_copy_threshold() -> i64 {
    match compiled_copy_threshold() {
        Ok(Some(value)) => value,
        _ => DEFAULT_MULTIPART_COPY_THRESHOLD,
    }
}

/// The state of the versioning of an instance: the result of the start probe and the last status of the bucket.
#[derive(Debug, Default)]
pub struct VersioningState {
    /// `(supported, checked)`.
    pub probe: Mutex<(bool, bool)>,
    /// The last status of `GetBucketVersioning`: `Enabled`, `Suspended` or empty, when a read worked.
    pub status: Mutex<Option<String>>,
}

/// One storage instance.
pub struct Instance {
    /// The configuration of the block.
    pub cfg: BucketConfig,
    /// The back end.
    pub backend: Arc<dyn Backend>,
    /// The limits of the process.
    pub policy: Arc<RuntimePolicy>,
    /// The gate of the process.
    pub global_gate: gate::Gate,
    /// The gate of the instance.
    pub gate: gate::Gate,
    /// The permissions that the process knows.
    pub caps: Mutex<Capabilities>,
    /// The versioning.
    pub versioning: VersioningState,
    /// Set when the provider refused the batch delete one time: the later deletes are one by one.
    pub batch_delete_off: AtomicBool,
    /// The source size from which a copy goes in parts (see [`multipart_copy_threshold`]).
    pub copy_threshold: AtomicI64,
    /// The state of the tags (work package `lifecycle`).
    pub tags: crate::lifecycle::TagsState,
    /// The state of the lifecycle editor and of the bucket facts (work package `lifecycle`).
    pub rules: crate::lifecycle::RulesState,
    /// The state of the list of the incomplete uploads (work package `uploads`).
    pub multiparts: crate::uploads::MultipartsState,
    /// The state of Object Lock (work package `bucket`).
    pub object_lock: crate::bucket::ObjectLockCapability,
    /// The state of the default encryption (work package `bucket`).
    pub encryption: crate::bucket::EncryptionCapability,
    /// The state of the edit of the metadata (work package `bucket`).
    pub metadata: crate::bucket::MetadataCapability,
    /// The reader and the cache of the usage (work package `bucket`).
    pub usage: crate::bucket::UsageCapability,
}

impl std::fmt::Debug for Instance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Instance")
            .field("cfg", &self.cfg)
            .finish_non_exhaustive()
    }
}

impl Instance {
    /// An instance over a back end, with the gates of the process and the permissions of the configuration.
    pub fn new(
        cfg: BucketConfig,
        backend: Arc<dyn Backend>,
        policy: Arc<RuntimePolicy>,
        global_gate: gate::Gate,
    ) -> Self {
        let per_storage = match policy.max_concurrent_requests_per_storage {
            0 => gate::DEFAULT_INSTANCE_SLOTS,
            value => value,
        };
        let caps = capability::initial_capabilities(&cfg, policy.force_read_only());
        Self {
            cfg,
            backend,
            policy,
            global_gate,
            gate: gate::Gate::new(per_storage),
            caps: Mutex::new(caps),
            versioning: VersioningState::default(),
            batch_delete_off: AtomicBool::new(false),
            copy_threshold: AtomicI64::new(multipart_copy_threshold()),
            tags: Default::default(),
            rules: Default::default(),
            multiparts: Default::default(),
            object_lock: Default::default(),
            encryption: Default::default(),
            metadata: Default::default(),
            usage: Default::default(),
        }
    }

    /// The full key of a relative key: the root prefix and the key, without the `/` at the start of the key.
    pub fn full_key(&self, relative: &str) -> String {
        format!("{}{}", self.cfg.root_prefix, relative.trim_start_matches('/'))
    }

    /// The relative key of a full key, or `None` for a key outside of the root prefix.
    pub fn relative_key(&self, full: &str) -> Option<String> {
        if self.cfg.root_prefix.is_empty() {
            return Some(full.trim_start_matches('/').to_owned());
        }
        full.strip_prefix(self.cfg.root_prefix.as_str()).map(str::to_owned)
    }

    /// True with `access_mode = "force_read_only"`.
    pub fn force_read_only(&self) -> bool {
        self.policy.force_read_only()
    }

    /// The permissions that the process knows now. A denial of one provider call becomes `unknown` again after one
    /// minute.
    pub fn capabilities(&self) -> Capabilities {
        let mut caps = self.caps.lock().map(|caps| caps.clone()).unwrap_or_default();
        let now = Timestamp::now();
        for name in capability::PERMISSIONS {
            let state = capability::state_of(&caps, name);
            if state.expires.is_some_and(|expires| now >= expires) {
                capability::set_state(
                    &mut caps,
                    name,
                    capability::unknown(
                        "provider",
                        "an earlier provider denial expired; the action will be verified when used",
                    ),
                );
            }
        }
        caps
    }

    /// The state of one permission (`read`, `write` or `delete`).
    pub fn capability(&self, permission: &str) -> CapabilityState {
        capability::state_of(&self.capabilities(), permission)
    }

    /// True when the interface offers the action of the permission.
    pub fn allowed(&self, permission: &str) -> bool {
        self.capability(permission).allowed
    }

    /// True when a request may reach the back end with this permission. The configuration, `force_read_only` and
    /// a denial of a probe stop it. A denial that one provider call taught does not: it can concern one object
    /// only, and the next call can disprove it.
    pub fn permitted(&self, permission: &str) -> bool {
        let state = self.capability(permission);
        state.allowed || state.source == "provider"
    }

    /// `403 permission_denied` when the permission is not permitted.
    pub fn require_permission(&self, permission: &str) -> Result<()> {
        if self.permitted(permission) {
            return Ok(());
        }
        Err(Error::api(
            403,
            "permission_denied",
            format!("instance {:?} does not expose {permission} permission", self.cfg.id),
        ))
    }

    /// Learn from the result of a real provider call. A success proves the permission. A provider answer 401 or 403
    /// is a short denial that the answers show and that no check applies. Any other error teaches nothing. A denial
    /// of the configuration or of `force_read_only` never changes.
    pub fn observe_permission(&self, permission: &str, error: Option<&Error>) {
        if permission.is_empty() {
            return;
        }
        if self.force_read_only() && permission != PERMISSION_READ {
            return;
        }
        if self.cfg.permissions_defined && !self.cfg.permissions.iter().any(|value| value == permission) {
            return;
        }
        let now = Timestamp::now();
        let next = match error {
            None => capability::allowed(
                "observed",
                "a real provider operation succeeded during this process",
                true,
            ),
            Some(error) => {
                let denied = error
                    .as_upstream()
                    .is_some_and(|upstream| upstream.status == 401 || upstream.status == 403);
                if !denied {
                    return;
                }
                let mut state = capability::denied(
                    "provider",
                    "the storage provider denied a real operation during this process",
                    true,
                );
                state.expires = Some(now.plus_secs(capability::OBSERVED_DENIAL_SECONDS));
                state
            }
        };
        if let Ok(mut caps) = self.caps.lock() {
            let current = capability::state_of(&caps, permission);
            if current.source != "runtime" && current.source != "configuration" {
                capability::set_state(&mut caps, permission, next);
                caps.checked_at = Some(now);
            }
        }
    }

    /// Take a slot of the gate of the process and of the gate of the instance, with the mode of the context.
    pub async fn acquire(&self, ctx: &OpCtx) -> Result<gate::Slot> {
        gate::acquire(ctx, &[&self.global_gate, &self.gate]).await
    }

    /// Count one provider call in the budget of the context, then take the slots of the gates. The gates get the
    /// slots back when the value is dropped.
    pub async fn begin_storage_request(&self, ctx: &OpCtx) -> Result<gate::Slot> {
        if let Some(budget) = &ctx.budget {
            budget.consume_request()?;
        }
        self.acquire(ctx).await
    }

    /// A gate for the provider requests of a copy in parts: each call counts one request and takes the slots.
    pub fn request_gate(&self) -> crate::common::storage::RequestGate {
        let process = self.global_gate.clone();
        let own = self.gate.clone();
        Arc::new(move |ctx: OpCtx| {
            let process = process.clone();
            let own = own.clone();
            Box::pin(async move {
                if let Some(budget) = &ctx.budget {
                    budget.consume_request()?;
                }
                gate::acquire(&ctx, &[&process, &own]).await
            })
        })
    }

    /// The source size from which a copy goes in parts.
    pub fn multipart_copy_threshold(&self) -> i64 {
        self.copy_threshold.load(Ordering::Relaxed)
    }

    /// Set the source size from which a copy goes in parts.
    pub fn set_multipart_copy_threshold(&self, value: i64) {
        self.copy_threshold.store(value, Ordering::Relaxed);
    }

    /// Learn the permissions again (`POST /api/permissions/refresh`). A canceled or timed-out discovery proves
    /// nothing: the known permissions stay.
    pub async fn refresh_capabilities(&self, ctx: &OpCtx) -> Capabilities {
        let discovered = self.discover_capabilities(ctx).await;
        if ctx.check().is_err() {
            return self.capabilities();
        }
        let merged = match &discovered {
            Ok(found) => capability::merge_capabilities(&self.cfg, self.force_read_only(), found, None),
            Err(error) => {
                capability::merge_capabilities(&self.cfg, self.force_read_only(), &Default::default(), Some(error))
            }
        };
        if let Ok(mut caps) = self.caps.lock() {
            *caps = merged.clone();
        }
        merged
    }

    async fn discover_capabilities(&self, ctx: &OpCtx) -> Result<crate::common::storage::DiscoveredCapabilities> {
        let _slot = self.begin_storage_request(ctx).await?;
        self.backend.discover_capabilities(ctx).await
    }
}
