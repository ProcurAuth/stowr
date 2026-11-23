// SPDX-License-Identifier: MIT OR Apache-2.0
//! The public form of a job: the JSON object that the routes give to the client.
//!
//! The form keeps the progress small: the result of an integrity job or of an archive job shows only after the job
//! completed. A copy job shows the bytes of the copied objects and the copied parts of the object in progress.

use serde::{Serialize, Serializer};

use super::stats::{StatsResponse, public_stats};
use super::{IntegrityResult, JobState, job_status};
use crate::common::http::{Response, json};
use crate::common::time::{Timestamp, ZERO_TIME_TEXT};

fn is_zero_i64(value: &i64) -> bool {
    *value == 0
}

fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}

/// A time that the job always has. A job that has no time yet (a value that a test makes) gives the zero time of the
/// answers.
fn serialize_known<S: Serializer>(value: &Timestamp, serializer: S) -> Result<S::Ok, S::Error> {
    if *value == Timestamp::default() {
        return serializer.serialize_str(ZERO_TIME_TEXT);
    }
    value.serialize(serializer)
}

/// The public form of a job.
#[derive(Clone, Debug, Serialize)]
pub struct PublicJob {
    /// The id.
    pub id: String,
    /// The type.
    #[serde(rename = "type")]
    pub job_type: String,
    /// The instance.
    pub instance: String,
    /// The instance of the target of an extraction.
    #[serde(rename = "targetInstance", skip_serializing_if = "String::is_empty")]
    pub target_instance: String,
    /// The source.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub source: String,
    /// The version.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version: String,
    /// The target.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub target: String,
    /// The selected entries of an archive.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<String>,
    /// The prefix.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub prefix: String,
    /// The status.
    pub status: String,
    /// The processed objects.
    pub processed: i64,
    /// The provider calls.
    #[serde(rename = "storageRequests", skip_serializing_if = "is_zero_i64")]
    pub storage_requests: i64,
    /// The provider bytes.
    #[serde(rename = "storageBytes", skip_serializing_if = "is_zero_i64")]
    pub storage_bytes: i64,
    /// The copied bytes, with the copied parts of the object in progress.
    #[serde(rename = "copiedBytes", skip_serializing_if = "is_zero_i64")]
    pub copied_bytes: i64,
    /// The size of the source of a copy of one object.
    #[serde(rename = "totalBytes", skip_serializing_if = "is_zero_i64")]
    pub total_bytes: i64,
    /// The last key that the job finished.
    #[serde(rename = "lastKey", skip_serializing_if = "String::is_empty")]
    pub last_key: String,
    /// The Insights statistics, with the sorted lists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<StatsResponse>,
    /// The result of an integrity job, after its end.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub integrity: Option<IntegrityResult>,
    /// The result of an extraction, after its end.
    #[serde(rename = "archiveExtract", skip_serializing_if = "Option::is_none")]
    pub archive_extract: Option<crate::archive::ArchiveExtractResult>,
    /// The result of an archive entry integrity job, after its end.
    #[serde(rename = "archiveEntryIntegrity", skip_serializing_if = "Option::is_none")]
    pub archive_entry_integrity: Option<crate::archive::ArchiveEntryIntegrityResult>,
    /// The age in days of an abort job.
    #[serde(rename = "olderThanDays", skip_serializing_if = "is_zero_u32")]
    pub older_than_days: u32,
    /// The counts of an abort job.
    #[serde(rename = "multipartAbort", skip_serializing_if = "Option::is_none")]
    pub multipart_abort: Option<crate::uploads::MultipartAbortResult>,
    /// The keys that an active Object Lock kept.
    #[serde(skip_serializing_if = "is_zero_i64")]
    pub locked: i64,
    /// The first 20 locked keys.
    #[serde(rename = "lockedKeys", skip_serializing_if = "Vec::is_empty")]
    pub locked_keys: Vec<String>,
    /// The public error.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
    /// The creation.
    #[serde(rename = "createdAt", serialize_with = "serialize_known")]
    pub created_at: Timestamp,
    /// The last change.
    #[serde(rename = "updatedAt", serialize_with = "serialize_known")]
    pub updated_at: Timestamp,
    /// The start.
    #[serde(rename = "startedAt", skip_serializing_if = "Option::is_none")]
    pub started_at: Option<Timestamp>,
    /// The end.
    #[serde(rename = "endedAt", skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<Timestamp>,
}

/// The public form of a job.
pub(super) fn public_job(job: &JobState) -> PublicJob {
    let completed = job.status == job_status::COMPLETED;
    PublicJob {
        id: job.id.clone(),
        job_type: job.job_type.clone(),
        instance: job.instance.clone(),
        target_instance: job.target_instance.clone(),
        source: job.source.clone(),
        version: job.version.clone(),
        target: job.target.clone(),
        entries: job.entries.clone(),
        prefix: job.prefix.clone(),
        status: job.status.clone(),
        processed: job.processed,
        storage_requests: job.storage_requests,
        storage_bytes: job.storage_bytes,
        copied_bytes: job.copied_bytes + job.copying_bytes,
        total_bytes: job.total_bytes,
        last_key: job.last_key.clone(),
        stats: job.stats.as_deref().map(public_stats),
        // A result can be large: it shows only after the end of the job, when it does not change any more.
        integrity: if completed { job.integrity.clone() } else { None },
        archive_extract: if completed { job.archive_extract.clone() } else { None },
        archive_entry_integrity: if completed {
            job.archive_entry_integrity.clone()
        } else {
            None
        },
        older_than_days: job
            .multipart_abort
            .as_ref()
            .map_or(0, |request| request.older_than_days),
        multipart_abort: job.multipart_result.clone(),
        locked: job.locked,
        locked_keys: job.locked_keys.clone(),
        error: job.error.clone(),
        created_at: job.created_at,
        updated_at: job.updated_at,
        started_at: job.started_at,
        ended_at: job.ended_at,
    }
}

/// The JSON answer of a job: the status and the public form of the job.
pub fn job_answer(status: u16, job: &JobState) -> Response {
    json(status, &public_job(job))
}
