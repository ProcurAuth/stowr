// SPDX-License-Identifier: MIT OR Apache-2.0
//! The two steps that each provider call of this folder takes: wait for a slot, and learn the permission from the
//! result. The instance has the same steps for its own calls; the calls of this folder use these copies.

use crate::common::config::{PERMISSION_DELETE, PERMISSION_READ, PERMISSION_WRITE};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::storage::CapabilityState;
use crate::common::storage::CapabilityStateName;
use crate::common::time::Timestamp;
use crate::instance::Instance;
use crate::instance::gate::{self, Slot};

/// How long a denial that one call taught stays in the facts of the instance.
const OBSERVED_DENIAL_SECONDS: i64 = 60;

fn observed(error: Option<&Error>) -> Option<CapabilityState> {
    match error {
        None => Some(CapabilityState {
            state: CapabilityStateName::Allowed,
            allowed: true,
            verified: true,
            source: "observed".to_owned(),
            reason: "a real provider operation succeeded during this process".to_owned(),
            expires: None,
        }),
        Some(error) => {
            let upstream = error.as_upstream()?;
            if upstream.status != 401 && upstream.status != 403 {
                return None;
            }
            Some(CapabilityState {
                state: CapabilityStateName::Denied,
                allowed: false,
                verified: true,
                source: "provider".to_owned(),
                reason: "the storage provider denied a real operation during this process".to_owned(),
                expires: Some(Timestamp::now().plus_secs(OBSERVED_DENIAL_SECONDS)),
            })
        }
    }
}

impl Instance {
    /// Count the call in the budget of the context and take the slots of the gates.
    pub(crate) async fn begin_lifecycle_call(&self, ctx: &OpCtx) -> Result<Slot> {
        if let Some(budget) = &ctx.budget {
            budget.consume_request()?;
        }
        gate::acquire(ctx, &[&self.global_gate, &self.gate]).await
    }

    /// Learn the permission from the result of a call: a success proves it, a 401 or 403 denies it for a short time.
    /// A denial of the configuration or of the runtime is never replaced.
    pub(crate) fn observe_lifecycle_call(&self, permission: &str, error: Option<&Error>) {
        if self.policy.force_read_only() && permission != PERMISSION_READ {
            return;
        }
        if self.cfg.permissions_defined && !self.cfg.permissions.iter().any(|value| value == permission) {
            return;
        }
        let Some(next) = observed(error) else {
            return;
        };
        let Ok(mut caps) = self.caps.lock() else {
            return;
        };
        let current = match permission {
            PERMISSION_READ => &mut caps.read,
            PERMISSION_WRITE => &mut caps.write,
            PERMISSION_DELETE => &mut caps.delete,
            _ => return,
        };
        if current.source == "runtime" || current.source == "configuration" {
            return;
        }
        *current = next;
        caps.checked_at = Some(Timestamp::now());
    }

    /// True when the start probe of the versions found them. The probe keeps `(supported, checked)`.
    pub(crate) fn versions_found(&self) -> bool {
        self.versioning
            .probe
            .lock()
            .map(|probe| probe.0 && probe.1)
            .unwrap_or(false)
    }
}
