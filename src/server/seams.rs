// SPDX-License-Identifier: MIT OR Apache-2.0
//! The points where the routes of this folder meet the access policy: the instances that a person sees, the display
//! questions of a listing and the folders of a navigation listing.
//!
//! The display questions call the access layer: in mode `open` they ask nothing.

use crate::access::display::{ListDisplay, operations_of, with_access_capabilities};
use crate::common::app::App;
use crate::common::ctx::OpCtx;
use crate::common::error::Result;
use crate::instance::{Instance, InstanceInfo};

use super::api::ListItem;

/// The instances that `/api/instances` shows, and the default instance. In mode `open`: each instance, and the first
/// one as the default. In mode `authzen`: the instances where the person holds an action, with the permissions that
/// the person does not hold marked as denied. Each shown instance reads the facts of its bucket again when they are
/// old.
pub async fn visible_instances(app: &App, ctx: &OpCtx) -> Result<(Vec<InstanceInfo>, String)> {
    let (visible, default) = app.access.visible_instances(ctx, &app.instances).await?;
    let infos = visible
        .into_iter()
        .map(|entry| {
            let mut info = entry.instance.public_info();
            if let Some(held) = &entry.held {
                info.capabilities = with_access_capabilities(&info.capabilities, held);
                info.operations = operations_of(&info.capabilities);
            }
            entry.instance.refresh_bucket_facts();
            info
        })
        .collect();
    Ok((infos, default))
}

/// The display questions at the node of a listing. In mode `open`: no question and no access member.
pub async fn list_display(app: &App, ctx: &OpCtx, instance: &Instance, prefix: &str) -> Result<ListDisplay> {
    app.access.list_display(ctx, instance, prefix).await
}

/// The folder items of a navigation listing that the person can read. The object items leave the listing.
pub async fn navigation_items(
    app: &App,
    ctx: &OpCtx,
    instance: &Instance,
    items: Vec<ListItem>,
) -> Result<Vec<ListItem>> {
    let prefixes: Vec<Option<&str>> = items
        .iter()
        .map(|item| (item.item_type == "prefix").then_some(item.prefix.as_str()))
        .collect();
    let kept = app.access.navigation_items(ctx, instance, &prefixes).await?;
    Ok(items
        .into_iter()
        .zip(kept)
        .filter_map(|(item, keep)| keep.then_some(item))
        .collect())
}
