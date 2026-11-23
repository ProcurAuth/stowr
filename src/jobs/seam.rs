//! The points where the routes of this folder meet the access policy (docs/ACCESS.md, "The routes").
//!
//! Each function gives the rule of the access policy with the functions of the shared contract
//! (`crate::access::authorize` and `crate::access::object_ask`). The work package `access` gives the same functions
//! (`job_operation`, `authorize_continuation`, `is_forbidden_error`, `authorize_read_many`, `restore_operation`):
//! at the integration, each function here calls its function there.

use crate::access::{ACTION_DELETE, ACTION_READ, ACTION_WRITE, Ask, Grant, Operation, object_ask};
use crate::common::app::App;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::instance::Instance;

use super::{JobState, job_type};

/// The code of the refusal of the PDP.
const CODE_FORBIDDEN: &str = "forbidden";

fn operation(others: Vec<Ask>, use_ask: Ask) -> Operation {
    Operation {
        others,
        use_ask,
        continuation: false,
    }
}

/// The permissions of the restore of a version of a key: read it, then write it (the use).
pub fn restore_operation(app: &App, instance: &Instance, key: &str) -> Operation {
    operation(
        vec![object_ask(app, ACTION_READ, instance, key)],
        object_ask(app, ACTION_WRITE, instance, key),
    )
}

/// The archive key of the request of an archive entry integrity job: its member `key`.
fn archive_entry_key(request: &crate::archive::ArchiveEntryIntegrityRequest) -> Option<String> {
    let value = serde_json::to_value(request).ok()?;
    value.get("key")?.as_str().map(str::to_owned)
}

/// The permissions of the operation that made a job. `None` for a job that has no rule: the caller refuses it.
pub fn job_operation(app: &App, job: &JobState) -> Option<Operation> {
    let find = |id: &str| app.instances.iter().find(|instance| instance.cfg.id == id);
    let instance = find(&job.instance)?;
    let ask = |action: &str, instance: &Instance, relative: &str| object_ask(app, action, instance, relative);
    Some(match job.job_type.as_str() {
        job_type::COPY_PREFIX | job_type::COPY_OBJECT => operation(
            vec![ask(ACTION_READ, instance, &job.source)],
            ask(ACTION_WRITE, instance, &job.target),
        ),
        job_type::MOVE_PREFIX | job_type::MOVE_OBJECT => operation(
            vec![
                ask(ACTION_READ, instance, &job.source),
                ask(ACTION_WRITE, instance, &job.target),
            ],
            ask(ACTION_DELETE, instance, &job.source),
        ),
        job_type::DELETE_PREFIX => operation(
            vec![ask(ACTION_READ, instance, &job.prefix)],
            ask(ACTION_DELETE, instance, &job.prefix),
        ),
        job_type::TAG_PREFIX | job_type::ABORT_MULTIPARTS => operation(
            vec![ask(ACTION_READ, instance, &job.prefix)],
            ask(ACTION_WRITE, instance, &job.prefix),
        ),
        job_type::STATS_PREFIX => operation(Vec::new(), ask(ACTION_READ, instance, &job.prefix)),
        job_type::INTEGRITY => operation(
            Vec::new(),
            ask(ACTION_READ, instance, &job.integrity_request.as_ref()?.key),
        ),
        job_type::ARCHIVE_ENTRY_INTEGRITY => {
            let key = archive_entry_key(job.archive_entry_integrity_request.as_ref()?)?;
            operation(Vec::new(), ask(ACTION_READ, instance, &key))
        }
        job_type::EXTRACT_ARCHIVE => {
            let target = find(&job.target_instance)?;
            operation(
                vec![
                    ask(ACTION_READ, instance, &job.source),
                    ask(ACTION_READ, target, &job.target),
                ],
                ask(ACTION_WRITE, target, &job.target),
            )
        }
        _ => return None,
    })
}

/// True when an error is the refusal `403 forbidden` of the PDP.
pub fn is_forbidden_error(error: &Error) -> bool {
    error
        .as_api()
        .is_some_and(|api| api.status == 403 && api.code == CODE_FORBIDDEN)
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
    let Some(mut operation) = job_operation(app, job) else {
        return Err(unknown_job());
    };
    operation.continuation = true;
    match crate::access::authorize(app, ctx, operation).await {
        Ok(_) => Ok(()),
        Err(error) if is_forbidden_error(&error) => Err(unknown_job()),
        Err(error) => Err(error),
    }
}

/// Ask `object.read` for each key. The first key is the use; the other keys come first. Without a key, the use is
/// the root of the instance.
pub async fn authorize_read_many(app: &App, ctx: &OpCtx, instance: &Instance, keys: &[String]) -> Result<Grant> {
    let Some((first, others)) = keys.split_first() else {
        return crate::access::authorize(
            app,
            ctx,
            operation(Vec::new(), object_ask(app, ACTION_READ, instance, "")),
        )
        .await;
    };
    let others = others
        .iter()
        .map(|key| object_ask(app, ACTION_READ, instance, key))
        .collect();
    crate::access::authorize(
        app,
        ctx,
        operation(others, object_ask(app, ACTION_READ, instance, first)),
    )
    .await
}
