// SPDX-License-Identifier: MIT OR Apache-2.0
//! The concurrency gates of the provider calls: one gate for the process and one gate for each instance.
//!
//! A call takes one slot of each gate. An interactive request waits 30 seconds at most, then gets
//! `503 storage_busy`. A job waits without a time limit. A prefetch does not wait. A slow client can keep a slot
//! until the idle limit of its stream: the bounded wait keeps the other users from a wait without end.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::common::ctx::{GateMode, OpCtx};
use crate::common::error::{Error, Result};

/// The longest wait of an interactive request for a slot.
pub const GATE_WAIT: Duration = Duration::from_secs(30);

/// The default number of slots of the gate of the process.
pub const DEFAULT_PROCESS_SLOTS: u32 = 4;

/// The default number of slots of the gate of an instance.
pub const DEFAULT_INSTANCE_SLOTS: u32 = 2;

/// A gate: a fixed number of slots.
#[derive(Clone, Debug)]
pub struct Gate {
    slots: Arc<Semaphore>,
    size: usize,
    wait: Duration,
}

impl Gate {
    /// A gate with this number of slots (at least 1), and the wait of [`GATE_WAIT`].
    pub fn new(slots: u32) -> Self {
        Self::with_wait(slots, GATE_WAIT)
    }

    /// A gate with this number of slots (at least 1) and another longest wait of an interactive request.
    pub fn with_wait(slots: u32, wait: Duration) -> Self {
        let size = slots.max(1) as usize;
        Self {
            slots: Arc::new(Semaphore::new(size)),
            size,
            wait,
        }
    }

    /// The number of slots of the gate.
    pub fn size(&self) -> usize {
        self.size
    }

    /// The number of slots that a call holds now.
    pub fn held(&self) -> usize {
        self.size.saturating_sub(self.slots.available_permits())
    }
}

/// The slots that one provider call holds. The gates get the slots back when the value is dropped.
#[derive(Debug, Default)]
pub struct Slot {
    _permits: Vec<OwnedSemaphorePermit>,
}

impl Slot {
    /// A value that holds no slot: the caller already holds one for this operation.
    pub fn exempt() -> Self {
        Self::default()
    }
}

/// The `503 storage_busy` answer.
pub fn storage_busy() -> Error {
    Error::api(503, "storage_busy", "the storage backend is busy; retry shortly")
}

/// Take one slot of each gate, in order, with the mode of the context. A failure gives back the slots that the
/// call already took.
pub async fn acquire(ctx: &OpCtx, gates: &[&Gate]) -> Result<Slot> {
    let mut permits = Vec::with_capacity(gates.len());
    if ctx.gate == GateMode::Exempt {
        return Ok(Slot { _permits: permits });
    }
    // The deadline starts at the first gate that has no free slot: the path without a wait sets no timer.
    let mut deadline: Option<tokio::time::Instant> = None;
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
                let until = *deadline.get_or_insert_with(|| tokio::time::Instant::now() + gate.wait);
                let timed = async {
                    match tokio::time::timeout_at(until, wait).await {
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

    #[tokio::test]
    async fn the_wait_of_a_request_is_bounded_and_an_exempt_call_takes_no_slot() {
        let gate = Gate::with_wait(1, Duration::from_millis(50));
        let ctx = OpCtx::default();
        let held = acquire(&ctx, &[&gate]).await.unwrap();
        let start = std::time::Instant::now();
        let error = acquire(&ctx, &[&gate]).await.err().unwrap();
        assert_eq!(error.status(), 503);
        assert!(start.elapsed() < Duration::from_secs(2));

        // A job does not have the bounded wait: only its deadline stops it.
        let job = ctx.gated(GateMode::Unbounded).with_timeout(Duration::from_millis(200));
        let error = acquire(&job, &[&gate]).await.err().unwrap();
        assert_eq!(error, Error::Timeout);

        let exempt = acquire(&ctx.gated(GateMode::Exempt), &[&gate]).await.unwrap();
        drop(exempt);
        drop(held);
        assert_eq!(gate.held(), 0);
    }

    #[tokio::test]
    async fn a_failed_call_gives_back_the_slots_that_it_took() {
        let process = Gate::new(2);
        let instance = Gate::new(1);
        let ctx = OpCtx::default();
        let held = acquire(&ctx, &[&process, &instance]).await.unwrap();
        assert_eq!(process.held(), 1);
        let error = acquire(&ctx.gated(GateMode::NoWait), &[&process, &instance])
            .await
            .err()
            .unwrap();
        assert!(error.has_code("storage_busy"));
        assert_eq!(process.held(), 1);
        drop(held);
        assert_eq!((process.held(), instance.held()), (0, 0));
    }

    #[tokio::test]
    async fn a_canceled_wait_ends_at_once() {
        let gate = Gate::new(1);
        let ctx = OpCtx::default();
        let _held = acquire(&ctx, &[&gate]).await.unwrap();
        let waiter = ctx.gated(GateMode::Unbounded).detached();
        let token = waiter.cancel.clone();
        let task = tokio::spawn(async move { acquire(&waiter, &[&gate]).await.err() });
        tokio::time::sleep(Duration::from_millis(20)).await;
        token.cancel();
        assert_eq!(task.await.unwrap(), Some(Error::Canceled));
    }
}
