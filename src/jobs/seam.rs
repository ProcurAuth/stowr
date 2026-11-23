// SPDX-License-Identifier: MIT OR Apache-2.0
//! The points where the routes of this folder meet the access policy (docs/ACCESS.md, "The routes"): the read and
//! the control of a job, the count of the versions of many keys, and the restore of a version.

use crate::access::Operation;
use crate::access::mutation::{authorize_continuation, is_forbidden_error, job_operation};
use crate::common::app::App;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::instance::Instance;

use super::JobState;

/// The permissions of the restore of a version of a key: read it, then write it (the use).
pub fn restore_operation(app: &App, instance: &Instance, key: &str) -> Operation {
    app.access.restore_operation(instance, key)
}

/// The answer for a job that does not exist, that has no access rule, or that the subject cannot do again. The
/// three cases give the same answer.
pub fn unknown_job() -> Error {
    Error::api(404, "unknown_job", "job was not found")
}

/// Ask again the permissions of the operation that made a job, as a continuation (without usage). A refusal gives the
/// answer of an unknown job. A failure of the PDP and a budget refusal keep their status.
pub async fn authorize_job(app: &App, ctx: &OpCtx, job: &JobState) -> Result<()> {
    if !app.config.access.enforced() {
        return Ok(());
    }
    let Some(operation) = job_operation(app, job) else {
        return Err(unknown_job());
    };
    match authorize_continuation(app, ctx, operation).await {
        Err(error) if is_forbidden_error(&error) => Err(unknown_job()),
        other => other,
    }
}

/// Ask `object.read` for each key. The first key is the use; the other keys come first. Without a key, the use is
/// the root of the instance.
pub async fn authorize_read_many(
    app: &App,
    ctx: &OpCtx,
    instance: &Instance,
    keys: &[String],
) -> Result<crate::access::Grant> {
    crate::access::authorize_read_many(app, ctx, instance, keys).await
}
