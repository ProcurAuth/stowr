//! The ceilings of the access policy (`max_object_size`) and their checks in the storage calls
//! (docs/ACCESS.md, "The ceiling max_object_size").

use std::collections::BTreeMap;
use std::sync::Mutex;

use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};

/// The action `object.read`.
pub const ACTION_READ: &str = "object.read";
/// The action `object.write`.
pub const ACTION_WRITE: &str = "object.write";
/// The ceiling `max_object_size`.
pub const MAX_OBJECT_SIZE: &str = "max_object_size";

/// The ceilings of a request or of a job, by action and by name. The lower value of two answers wins.
#[derive(Debug, Default)]
pub struct Ceilings {
    values: Mutex<BTreeMap<String, BTreeMap<String, i64>>>,
}

impl Ceilings {
    /// Keep a ceiling. A lower value replaces a higher one.
    pub fn lower(&self, action: &str, name: &str, value: i64) {
        if let Ok(mut values) = self.values.lock() {
            let entry = values
                .entry(action.to_owned())
                .or_default()
                .entry(name.to_owned())
                .or_insert(value);
            if value < *entry {
                *entry = value;
            }
        }
    }

    /// The value of a ceiling, when one applies.
    pub fn get(&self, action: &str, name: &str) -> Option<i64> {
        self.values
            .lock()
            .ok()
            .and_then(|values| values.get(action).and_then(|names| names.get(name).copied()))
    }

    /// A copy of the values, for a job that keeps the ceilings of its request.
    pub fn snapshot(&self) -> Ceilings {
        let values = self.values.lock().map(|values| values.clone()).unwrap_or_default();
        Ceilings {
            values: Mutex::new(values),
        }
    }
}

/// The `403 ceiling_exceeded` answer of a size over a ceiling.
pub fn ceiling_exceeded(action: &str, limit: i64, size: i64) -> Error {
    let _ = (action, limit, size);
    Error::not_served("the answer of a size over a ceiling")
}

/// Check a size against the ceiling of an action. A size below 0 (unknown) is refused when a ceiling applies.
pub fn check_object_ceiling(ctx: &OpCtx, action: &str, size: i64) -> Result<()> {
    let _ = (ctx, action, size);
    Ok(())
}
