// SPDX-License-Identifier: MIT OR Apache-2.0
//! The permissions of the change routes, of the jobs and of the continuations (ProcurAuth 4.5 and 4.7).
//!
//! A route and the job that it starts build their operation with the same function. The job asks its operation again
//! at each read and each control, as a continuation. So the two operations never differ.

use std::sync::Arc;

use super::{ACTION_BUCKET_ADMIN, ACTION_DELETE, ACTION_READ, ACTION_WRITE, AccessLayer, CODE_FORBIDDEN, Operation};
use crate::common::app::App;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::misc::clean_relative_key;
use crate::instance::Instance;
use crate::jobs::{JobState, job_type};

impl AccessLayer {
    /// The operation of one permission on the node of a key or of a prefix.
    pub fn use_operation(&self, action: &str, instance: &Instance, relative: &str) -> Operation {
        Operation {
            use_ask: self.object_ask(action, instance, relative),
            ..Operation::default()
        }
    }

    /// The permissions of a copy of a key or of a prefix. `source` and `target` are the exact relative keys or
    /// prefixes that reach the storage.
    pub fn copy_operation(&self, instance: &Instance, source: &str, target: &str) -> Operation {
        Operation {
            others: vec![self.object_ask(ACTION_READ, instance, source)],
            use_ask: self.object_ask(ACTION_WRITE, instance, target),
            continuation: false,
        }
    }

    /// The permissions of a move of a key or of a prefix. The use is the delete of the source: it is the most
    /// destructive action of the move.
    pub fn move_operation(&self, instance: &Instance, source: &str, target: &str) -> Operation {
        Operation {
            others: vec![
                self.object_ask(ACTION_READ, instance, source),
                self.object_ask(ACTION_WRITE, instance, target),
            ],
            use_ask: self.object_ask(ACTION_DELETE, instance, source),
            continuation: false,
        }
    }

    /// The permissions of the delete of a prefix.
    pub fn delete_prefix_operation(&self, instance: &Instance, prefix: &str) -> Operation {
        Operation {
            others: vec![self.object_ask(ACTION_READ, instance, prefix)],
            use_ask: self.object_ask(ACTION_DELETE, instance, prefix),
            continuation: false,
        }
    }

    /// The permissions of a write of each object under a prefix: the bulk change of tags and the abort of the old
    /// incomplete uploads.
    pub fn write_prefix_operation(&self, instance: &Instance, prefix: &str) -> Operation {
        Operation {
            others: vec![self.object_ask(ACTION_READ, instance, prefix)],
            use_ask: self.object_ask(ACTION_WRITE, instance, prefix),
            continuation: false,
        }
    }

    /// The permissions of the restore of a version of a key.
    pub fn restore_operation(&self, instance: &Instance, key: &str) -> Operation {
        Operation {
            others: vec![self.object_ask(ACTION_READ, instance, key)],
            use_ask: self.object_ask(ACTION_WRITE, instance, key),
            continuation: false,
        }
    }

    /// The permissions of the save of the lifecycle rules. The two other permissions are always asked, whatever
    /// the rules are.
    pub fn lifecycle_operation(&self, instance: &Instance) -> Operation {
        Operation {
            others: vec![
                self.bucket_ask(ACTION_READ, instance),
                self.bucket_ask(ACTION_DELETE, instance),
            ],
            use_ask: self.bucket_ask(ACTION_BUCKET_ADMIN, instance),
            continuation: false,
        }
    }

    /// The permissions of the abort of a list of incomplete uploads. The first key is the use. The other keys come
    /// first, without usage. An empty list gives the bucket node.
    pub fn abort_uploads_operation(&self, instance: &Instance, keys: &[String]) -> Operation {
        let Some((first, rest)) = keys.split_first() else {
            return self.use_operation(ACTION_WRITE, instance, "");
        };
        Operation {
            others: rest
                .iter()
                .map(|key| self.object_ask(ACTION_WRITE, instance, key))
                .collect(),
            use_ask: self.object_ask(ACTION_WRITE, instance, first),
            continuation: false,
        }
    }

    /// The permissions of the extraction of entries of an archive. The target instance can differ from the source
    /// instance.
    pub fn extract_operation(&self, source: &Instance, key: &str, target: &Instance, target_prefix: &str) -> Operation {
        Operation {
            others: vec![
                self.object_ask(ACTION_READ, source, key),
                self.object_ask(ACTION_READ, target, target_prefix),
            ],
            use_ask: self.object_ask(ACTION_WRITE, target, target_prefix),
            continuation: false,
        }
    }

    /// The permissions of a continuation: the same permissions as the first request, without usage.
    pub async fn authorize_continuation(&self, ctx: &OpCtx, mut operation: Operation) -> Result<()> {
        operation.continuation = true;
        self.authorize(ctx, operation).await.map(|_| ())
    }

    /// The check of an upload request: `object.write` on the node of the key. The instance and the key come from
    /// the upload, never from the client. A continuation asks no usage.
    pub async fn authorize_upload(
        &self,
        ctx: &OpCtx,
        instance: &Instance,
        key: &str,
        continuation: bool,
    ) -> Result<()> {
        let mut operation = self.use_operation(ACTION_WRITE, instance, key);
        operation.continuation = continuation;
        self.authorize(ctx, operation).await.map(|_| ())
    }
}

/// The permissions of the operation that made a job. `None` for a job that has no rule: the caller refuses such a
/// job. The function reads only the fields that the route checked.
pub fn job_operation(app: &App, job: &JobState) -> Option<Operation> {
    job_operation_in(&app.access, &app.instances, job)
}

/// [`job_operation`] with the layer and the instances.
pub fn job_operation_in(access: &AccessLayer, instances: &[Arc<Instance>], job: &JobState) -> Option<Operation> {
    let find = |id: &str| instances.iter().find(|instance| instance.cfg.id == id);
    let instance = find(&job.instance)?;
    Some(match job.job_type.as_str() {
        job_type::COPY_PREFIX | job_type::COPY_OBJECT => access.copy_operation(instance, &job.source, &job.target),
        job_type::MOVE_PREFIX | job_type::MOVE_OBJECT => access.move_operation(instance, &job.source, &job.target),
        job_type::DELETE_PREFIX => access.delete_prefix_operation(instance, &job.prefix),
        job_type::TAG_PREFIX | job_type::ABORT_MULTIPARTS => access.write_prefix_operation(instance, &job.prefix),
        job_type::STATS_PREFIX => access.use_operation(ACTION_READ, instance, &job.prefix),
        job_type::INTEGRITY => {
            let request = job.integrity_request.as_ref()?;
            access.use_operation(ACTION_READ, instance, &request.key)
        }
        job_type::ARCHIVE_ENTRY_INTEGRITY => {
            let key = archive_entry_key(job.archive_entry_integrity_request.as_ref()?)?;
            access.use_operation(ACTION_READ, instance, &key)
        }
        job_type::EXTRACT_ARCHIVE => {
            let target = find(&job.target_instance)?;
            access.extract_operation(instance, &job.source, target, &job.target)
        }
        _ => return None,
    })
}

/// The archive key of the request of an archive entry integrity job: its member `key`, as the job keeps it.
fn archive_entry_key(request: &crate::archive::ArchiveEntryIntegrityRequest) -> Option<String> {
    let value = serde_json::to_value(request).ok()?;
    value.get("key")?.as_str().map(str::to_owned)
}

/// Ask the permissions of a continuation: the same permissions as the first request, without usage.
pub async fn authorize_continuation(app: &App, ctx: &OpCtx, operation: Operation) -> Result<()> {
    app.access.authorize_continuation(ctx, operation).await
}

/// True when an error is the refusal `403 forbidden` of the PDP.
pub fn is_forbidden_error(error: &Error) -> bool {
    error
        .as_api()
        .is_some_and(|api| api.status == 403 && api.code == CODE_FORBIDDEN)
}

/// Clean the source and the target of a copy or a move of one object. It refuses an empty key and two equal keys.
/// It makes no storage call.
pub fn clean_object_pair(source: &str, target: &str) -> Result<(String, String)> {
    let (source, target) = (clean_relative_key(source), clean_relative_key(target));
    if source.is_empty() || target.is_empty() {
        return Err(Error::api(400, "invalid_path", "src and dst are required"));
    }
    if source == target {
        return Err(Error::api(400, "same_path", "src and dst must be different"));
    }
    Ok((source, target))
}

#[cfg(test)]
#[path = "mutation_tests.rs"]
mod tests;
