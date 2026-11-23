//! The resource budget of a request or of a job: the provider calls and the provider bytes.

use std::sync::atomic::{AtomicI64, Ordering};

use serde::Serialize;

use crate::common::config::RuntimePolicy;
use crate::common::error::{Error, LimitKind, ResourceLimit, Result};
use crate::common::time::Timestamp;

/// The counters and the limits of one request or one job. The counters are safe for concurrent use.
#[derive(Debug)]
pub struct Budget {
    max_requests: i64,
    max_bytes: i64,
    requests: AtomicI64,
    bytes: AtomicI64,
    started_at: Timestamp,
    started: std::time::Instant,
}

/// The use of a budget, as the job state gives it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceUsage {
    /// The provider calls.
    pub storage_requests: i64,
    /// The provider bytes.
    pub storage_bytes: i64,
    /// The start.
    pub started_at: Timestamp,
    /// The time since the start, in milliseconds.
    #[serde(rename = "elapsedMs")]
    pub elapsed_ms: i64,
}

impl Budget {
    /// A budget with these limits. A limit of 0 or less has no effect.
    pub fn new(max_requests: i64, max_bytes: i64) -> Self {
        Self {
            max_requests,
            max_bytes,
            requests: AtomicI64::new(0),
            bytes: AtomicI64::new(0),
            started_at: Timestamp::now(),
            started: std::time::Instant::now(),
        }
    }

    /// The budget of one interactive request (`max_storage_*_per_request`).
    pub fn for_request(policy: &RuntimePolicy) -> Self {
        Self::new(
            policy.max_storage_requests_per_request,
            policy.max_storage_bytes_per_request,
        )
    }

    /// The budget of one background job that reads complete objects (`max_background_storage_*`).
    pub fn for_background(policy: &RuntimePolicy) -> Self {
        Self::new(
            policy.max_background_storage_requests,
            policy.max_background_storage_bytes,
        )
    }

    /// Count one provider call. `Err(Error::Budget)` above the limit.
    pub fn consume_request(&self) -> Result<()> {
        let used = self.requests.fetch_add(1, Ordering::SeqCst) + 1;
        if self.max_requests > 0 && used > self.max_requests {
            return Err(Error::Budget(ResourceLimit {
                kind: LimitKind::StorageRequests,
                limit: self.max_requests,
                used,
            }));
        }
        Ok(())
    }

    /// Count provider bytes. `Err(Error::Budget)` above the limit.
    pub fn consume_bytes(&self, count: i64) -> Result<()> {
        if count <= 0 {
            return Ok(());
        }
        let used = self.bytes.fetch_add(count, Ordering::SeqCst) + count;
        if self.max_bytes > 0 && used > self.max_bytes {
            return Err(Error::Budget(ResourceLimit {
                kind: LimitKind::StorageBytes,
                limit: self.max_bytes,
                used,
            }));
        }
        Ok(())
    }

    /// The use of the budget now.
    pub fn usage(&self) -> ResourceUsage {
        ResourceUsage {
            storage_requests: self.requests.load(Ordering::SeqCst),
            storage_bytes: self.bytes.load(Ordering::SeqCst),
            started_at: self.started_at,
            elapsed_ms: i64::try_from(self.started.elapsed().as_millis()).unwrap_or(i64::MAX),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_budget_refuses_the_call_above_its_limit() {
        let budget = Budget::new(2, 10);
        assert!(budget.consume_request().is_ok());
        assert!(budget.consume_request().is_ok());
        assert!(matches!(budget.consume_request(), Err(Error::Budget(_))));
        assert!(budget.consume_bytes(10).is_ok());
        assert_eq!(budget.consume_bytes(1).err().map(|error| error.status()), Some(429));
    }
}
