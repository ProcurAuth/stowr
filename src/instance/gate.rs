//! The concurrency gates of the provider calls: one gate for the process and one gate for each instance.
//!
//! A call takes one slot of each gate. An interactive request waits 30 seconds at most, then gets
//! `503 storage_busy`. A job waits without a time limit. A prefetch does not wait.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::common::ctx::{GateMode, OpCtx};
use crate::common::error::{Error, Result};

/// The longest wait of an interactive request for a slot.
pub const GATE_WAIT: Duration = Duration::from_secs(30);

/// A gate: a fixed number of slots.
#[derive(Clone, Debug)]
pub struct Gate {
    slots: Arc<Semaphore>,
}

impl Gate {
    /// A gate with this number of slots (at least 1).
    pub fn new(slots: u32) -> Self {
        Self {
            slots: Arc::new(Semaphore::new(slots.max(1) as usize)),
        }
    }
}

/// The slots that one provider call holds. The gates get the slots back when the value is dropped.
#[derive(Debug)]
pub struct Slot {
    _permits: Vec<OwnedSemaphorePermit>,
}

/// The `503 storage_busy` answer.
pub fn storage_busy() -> Error {
    Error::api(503, "storage_busy", "the storage backend is busy; retry shortly")
}

/// Take one slot of each gate, in order, with the mode of the context.
pub async fn acquire(ctx: &OpCtx, gates: &[&Gate]) -> Result<Slot> {
    let mut permits = Vec::with_capacity(gates.len());
    if ctx.gate == GateMode::Exempt {
        return Ok(Slot { _permits: permits });
    }
    let deadline = tokio::time::Instant::now() + GATE_WAIT;
    for gate in gates {
        if let Ok(permit) = gate.slots.clone().try_acquire_owned() {
            permits.push(permit);
            continue;
        }
        let wait = gate.slots.clone().acquire_owned();
        let permit = match ctx.gate {
            GateMode::NoWait => return Err(storage_busy()),
            GateMode::Unbounded | GateMode::Exempt => {
                ctx.run(async { wait.await.map_err(|_| Error::Canceled) }).await?
            }
            GateMode::Bounded => {
                let timed = async {
                    match tokio::time::timeout_at(deadline, wait).await {
                        Ok(Ok(permit)) => Ok(permit),
                        Ok(Err(_)) => Err(Error::Canceled),
                        Err(_) => Err(storage_busy()),
                    }
                };
                ctx.run(timed).await?
            }
        };
        permits.push(permit);
    }
    Ok(Slot { _permits: permits })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn no_wait_gives_storage_busy_when_the_gate_is_full() {
        let gate = Gate::new(1);
        let ctx = OpCtx::default();
        let _held = acquire(&ctx, &[&gate]).await.unwrap();
        let error = acquire(&ctx.gated(GateMode::NoWait), &[&gate]).await.err().unwrap();
        assert!(error.has_code("storage_busy"));
        assert!(acquire(&ctx.gated(GateMode::Exempt), &[&gate]).await.is_ok());
    }
}
