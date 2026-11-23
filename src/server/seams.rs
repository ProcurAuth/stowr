//! The points where the routes of this folder meet a function of another work package that the shared contracts do
//! not give yet: the display questions of the access policy, the public form of a job, the reuse of a recent Insights
//! job, and the refresh of the facts of a bucket.
//!
//! Each function here gives the behaviour of the mode `open` in full. The behaviour of the mode `authzen` belongs to
//! the work package `access`: the mode `authzen` cannot start before that work package gives its guard
//! (`crate::access::AccessLayer::new`). Replace the body of each function with the call to the function of the other
//! work package when it exists.

use serde::Serialize;

use crate::common::app::App;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Response, api_error};
use crate::instance::{Instance, InstanceInfo};
use crate::jobs::JobState;

/// The decisions at the node of a listing, in mode `authzen`: the interface hides the controls that the person cannot
/// use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ListAccess {
    /// `object.read` at the node.
    pub read: bool,
    /// `object.write` at the node.
    pub write: bool,
    /// `object.delete` at the node.
    pub delete: bool,
}

/// The result of the display questions of one listing. `access` is `None` in mode `open`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ListDisplay {
    /// The decisions at the node.
    pub access: Option<ListAccess>,
    /// True when the person cannot read the node but can read a folder below it: the listing shows the folders only.
    pub navigation: bool,
}

fn display_not_served() -> Error {
    Error::not_served("the display questions of the access policy")
}

/// The instances that `/api/instances` shows, and the default instance. In mode `open`: each instance, and the first
/// one as the default.
pub fn visible_instances(app: &App, ctx: &OpCtx) -> Result<(Vec<InstanceInfo>, String)> {
    let _ = ctx;
    if app.config.access.enforced() {
        return Err(display_not_served());
    }
    let infos = app
        .instances
        .iter()
        .map(|instance| {
            refresh_bucket_facts(instance);
            instance.public_info()
        })
        .collect();
    let default = app
        .instances
        .first()
        .map(|instance| instance.cfg.id.clone())
        .unwrap_or_default();
    Ok((infos, default))
}

/// The display questions at the node of a listing. In mode `open`: no question and no access member.
pub fn list_display(app: &App, ctx: &OpCtx, instance: &Instance, prefix: &str) -> Result<ListDisplay> {
    let _ = (ctx, instance, prefix);
    if app.config.access.enforced() {
        return Err(display_not_served());
    }
    Ok(ListDisplay::default())
}

/// The folder items of a navigation listing that the person can read. Only the mode `authzen` asks it.
pub fn navigation_items<T>(app: &App, ctx: &OpCtx, instance: &Instance, items: Vec<T>) -> Result<Vec<T>> {
    let _ = (app, ctx, instance, items);
    Err(display_not_served())
}

/// Refresh the facts of a bucket (versioning, lifecycle rules) when they are old: a task of the work package
/// `lifecycle`.
pub fn refresh_bucket_facts(instance: &Instance) {
    let _ = instance;
}

/// A recent Insights job of the same instance and prefix: a completed one of the last 30 seconds, else one that
/// waits or runs. No job: the route makes a new job.
pub fn reusable_stats_job(app: &App, instance: &str, prefix: &str) -> Option<JobState> {
    let _ = (app, instance, prefix);
    None
}

/// The JSON answer of a job: the public form of the work package `jobs`.
pub fn job_answer(status: u16, job: &JobState) -> Response {
    let _ = (status, job);
    api_error(&Error::not_served("the public form of a job"))
}
