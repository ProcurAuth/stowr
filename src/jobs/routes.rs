// SPDX-License-Identifier: MIT OR Apache-2.0
//! The routes of the jobs: `/api/jobs/<id>` (`GET`), `/api/jobs/<id>/<pause|resume|cancel>` (`POST`), `/api/jobs`
//! (always 404: no route lists the jobs), and `/api/stats` (Insights).
//!
//! Only the holder of the id of a job reads or controls it. In mode `authzen`, each read and each control asks again
//! the permissions of the operation that made the job, as a continuation.

use std::sync::Arc;

use http::Method;

use super::manager::STATS_INLINE_WAIT;
use super::seam::{authorize_job, unknown_job};
use super::stats::normalize_prefix;
use super::{JobState, job_answer, job_status, job_type};
use crate::common::BoxFuture;
use crate::common::app::App;
use crate::common::config::PERMISSION_READ;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Req, Response, api_error, method_not_allowed, not_found};
use crate::common::misc::clean_relative_key;
use crate::common::query::Query;
use crate::instance::ceiling::ceilings_of;

fn answer(result: Result<Response>) -> Response {
    result.unwrap_or_else(|error| api_error(&error))
}

/// The handler of `/api/jobs` without an id: always 404.
pub fn handle_job_collection(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        let _ = (app, req);
        not_found()
    })
}

/// The handler of `/api/jobs/<id>` and `/api/jobs/<id>/<action>`.
pub fn handle_jobs(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        let Req { method, path, ctx, .. } = req;
        answer(jobs_route(&app, &method, &path, &ctx).await)
    })
}

async fn jobs_route(app: &App, method: &Method, path: &str, ctx: &OpCtx) -> Result<Response> {
    let remainder = path.strip_prefix("/api/jobs/").unwrap_or("");
    let parts: Vec<&str> = remainder.split('/').collect();
    let id = parts[0];
    if id.is_empty() {
        return Err(unknown_job());
    }
    if parts.len() == 1 {
        if *method != Method::GET {
            return Ok(method_not_allowed(&["GET"]));
        }
        let job = app.jobs.get(id).ok_or_else(unknown_job)?;
        authorize_job(app, ctx, &job).await?;
        return Ok(job_answer(200, &job));
    }
    if parts.len() != 2 || *method != Method::POST {
        return Ok(method_not_allowed(&["POST"]));
    }
    let job = app.jobs.get(id).ok_or_else(unknown_job)?;
    let action = parts[1];
    if !matches!(action, "pause" | "resume" | "cancel") {
        return Err(Error::api(400, "invalid_job_action", "unknown job action"));
    }
    authorize_job(app, ctx, &job).await?;
    if action == "resume" {
        // The answers of the PDP can have a lower ceiling now: the job runs again with the lower value of each ceiling.
        app.jobs.lower_ceilings(id, &ceilings_of(ctx));
    }
    let job = app.jobs.change_status(id, action)?;
    Ok(job_answer(200, &job))
}

/// The handler of `GET /api/stats?instance=&prefix=`: the Insights statistics of a prefix. A completed job of the
/// last 30 seconds serves again; a job that ends within 100 ms gives `200`; else the answer is `202` with the job.
pub fn handle_stats(app: Arc<App>, req: Req) -> BoxFuture<'static, Response> {
    Box::pin(async move {
        if req.method != Method::GET {
            return method_not_allowed(&["GET"]);
        }
        let Req { query, ctx, .. } = req;
        answer(stats_route(&app, &query, &ctx).await)
    })
}

async fn stats_route(app: &App, query: &Query, ctx: &OpCtx) -> Result<Response> {
    let instance = app.instance_of("", query.get("instance"))?.clone();
    let prefix = normalize_prefix(&clean_relative_key(query.get("prefix")));
    instance.require_permission(PERMISSION_READ)?;
    crate::access::authorize_read(app, ctx, &instance, &prefix).await?;
    let job = match app.jobs.reusable_stats_job(&instance.cfg.id, &prefix) {
        Some(job) => job,
        None => app.jobs.create(JobState {
            job_type: job_type::STATS_PREFIX.to_owned(),
            instance: instance.cfg.id.clone(),
            prefix,
            ..JobState::default()
        })?,
    };
    if job.status == job_status::COMPLETED && job.stats.is_some() {
        return Ok(job_answer(200, &job));
    }
    if let Some(finished) = app.jobs.wait_for_terminal(&job.id, STATS_INLINE_WAIT).await {
        return Ok(job_answer(200, &finished));
    }
    Ok(job_answer(202, &job))
}
