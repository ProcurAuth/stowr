// SPDX-License-Identifier: MIT OR Apache-2.0
//! The display questions of the access policy (ProcurAuth 4.4).
//!
//! They decide what the interface shows: the list of the buckets, the controls of a folder and the path to a folder
//! that the person can read. They never decide an operation: each route still asks its own question before it acts.
//! A match `subtree` never lets an operation run.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde::Serialize;

use super::tree::{TYPE_BUCKET, TYPE_FOLDER};
use super::{
    ACTION_BUCKET_ADMIN, ACTION_DELETE, ACTION_LOCK, ACTION_READ, ACTION_WRITE, AccessLayer, Answer, Ask, Grant,
    approval_cannot_wait, forbidden, guard, pdp_unavailable, run_guarded, unauthenticated,
};
use crate::common::config::{PERMISSION_DELETE, PERMISSION_READ, PERMISSION_WRITE};
use crate::common::ctx::OpCtx;
use crate::common::error::Result;
use crate::common::storage::Capabilities;
use crate::instance::Instance;
use crate::instance::capability::denied;

/// The actions of the display questions on a bucket node, in the order of the questions.
pub const DISPLAY_ACTIONS: [&str; 5] = [
    ACTION_READ,
    ACTION_WRITE,
    ACTION_DELETE,
    ACTION_LOCK,
    ACTION_BUCKET_ADMIN,
];

/// The decisions at the node of a listing (match `node`). The interface hides the controls that the person cannot
/// use.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ListAccess {
    /// `object.read`.
    pub read: bool,
    /// `object.write`.
    pub write: bool,
    /// `object.delete`.
    pub delete: bool,
}

/// The result of the display questions of one listing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ListDisplay {
    /// The member `access` of the answer. `None` in mode `open`: the answer has no such member.
    pub access: Option<ListAccess>,
    /// True when the person cannot read the node but can maybe read a folder below it. The listing then shows the
    /// folders only, after [`AccessLayer::navigation_items`].
    pub navigation: bool,
}

/// One instance that `GET /api/instances` shows.
#[derive(Clone)]
pub struct VisibleInstance {
    /// The instance.
    pub instance: Arc<Instance>,
    /// The actions that the person holds somewhere in the bucket. `None` in mode `open`.
    pub held: Option<BTreeSet<&'static str>>,
}

impl std::fmt::Debug for VisibleInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VisibleInstance")
            .field("id", &self.instance.cfg.id)
            .field("held", &self.held)
            .finish()
    }
}

/// The state of several permissions together: the first denial, else unknown when one is unknown, else allowed.
/// The reasons join with `; `.
pub use crate::instance::capability::combine as combine_states;
/// The operations of an instance from its three permissions.
pub use crate::instance::capability::operation_capabilities as operations_of;

/// Mark as denied, with the source `access`, each permission whose action the person holds nowhere in the bucket.
/// The caller computes the operations again with [`operations_of`]. This is display only: the server still checks
/// each operation. The facts of Object Lock and of the lifecycle rules tell what the bucket supports: this function
/// does not change them.
pub fn with_access_capabilities(caps: &Capabilities, held: &BTreeSet<&'static str>) -> Capabilities {
    let mut out = caps.clone();
    for (action, permission) in [
        (ACTION_READ, PERMISSION_READ),
        (ACTION_WRITE, PERMISSION_WRITE),
        (ACTION_DELETE, PERMISSION_DELETE),
    ] {
        if held.contains(action) {
            continue;
        }
        let state = denied(
            "access",
            &format!("the access policy does not give {action} in this bucket"),
            true,
        );
        match permission {
            PERMISSION_READ => out.read = state,
            PERMISSION_WRITE => out.write = state,
            _ => out.delete = state,
        }
    }
    out
}

/// True when a node of this type has a node type below it in the tree.
fn has_deeper_type(node_type: &str) -> bool {
    node_type == TYPE_BUCKET || node_type == TYPE_FOLDER
}

impl AccessLayer {
    /// The instances that `GET /api/instances` shows, and the default instance. In mode `open` it gives each
    /// instance. In mode `authzen` it asks one batch of display questions (match `subtree`, no usage) on the bucket
    /// node of each instance, for each published action. An instance is visible when one answer is true. A failed
    /// answer gives `503` and never an empty list.
    pub async fn visible_instances(
        &self,
        ctx: &OpCtx,
        instances: &[Arc<Instance>],
    ) -> Result<(Vec<VisibleInstance>, String)> {
        if !self.enforced() {
            let visible = instances
                .iter()
                .map(|instance| VisibleInstance {
                    instance: Arc::clone(instance),
                    held: None,
                })
                .collect();
            let default = instances
                .first()
                .map(|instance| instance.cfg.id.clone())
                .unwrap_or_default();
            return Ok((visible, default));
        }
        let request = ctx.access.as_deref().ok_or_else(unauthenticated)?;
        let who = request.identity();
        let mut slots: Vec<(usize, &'static str)> = Vec::new();
        let mut asks: Vec<Ask> = Vec::new();
        for (position, instance) in instances.iter().enumerate() {
            for action in DISPLAY_ACTIONS {
                if !self.document.published(action) {
                    continue;
                }
                slots.push((position, action));
                asks.push(self.bucket_ask(action, instance));
            }
        }
        let count = asks.len();
        let answers = if asks.is_empty() {
            Vec::new()
        } else {
            run_guarded(
                ctx,
                || self.guard.display(&request.request_id, &who, &asks),
                || vec![Answer::failure(); count],
            )
            .await
        };
        let mut held: Vec<BTreeSet<&'static str>> = vec![BTreeSet::new(); instances.len()];
        for (index, (position, action)) in slots.iter().enumerate() {
            let answer = answers.get(index).cloned().unwrap_or_else(Answer::failure);
            if answer.failed {
                return Err(pdp_unavailable(action));
            }
            if answer.decision
                && let Some(set) = held.get_mut(*position)
            {
                set.insert(action);
            }
        }
        let mut visible = Vec::new();
        let mut default = String::new();
        for (instance, actions) in instances.iter().zip(held) {
            if actions.is_empty() {
                continue;
            }
            if default.is_empty() {
                default = instance.cfg.id.clone();
            }
            visible.push(VisibleInstance {
                instance: Arc::clone(instance),
                held: Some(actions),
            });
        }
        Ok((visible, default))
    }

    /// The display questions at the node of a listed prefix (match `node`, no usage): `object.read` and, when the
    /// document publishes them, `object.write` and `object.delete`. Each question goes in its own request. In mode
    /// `open` it asks nothing and gives no member `access`. A failed answer gives `503`. When the person cannot read
    /// the node, a bucket or a folder gives a navigation listing, and a subfolder gives `403`. A read that needs an
    /// approval gives `403 approval_cannot_wait`.
    pub async fn list_display(&self, ctx: &OpCtx, instance: &Instance, prefix: &str) -> Result<ListDisplay> {
        if !self.enforced() {
            return Ok(ListDisplay::default());
        }
        let request = ctx.access.as_deref().ok_or_else(unauthenticated)?;
        let who = request.identity();
        if !self.document.published(ACTION_READ) {
            return Err(forbidden(ACTION_READ));
        }
        let mut actions = vec![ACTION_READ];
        actions.extend(
            [ACTION_WRITE, ACTION_DELETE]
                .into_iter()
                .filter(|action| self.document.published(action)),
        );
        let read_ask = self.object_ask(ACTION_READ, instance, prefix);
        let asks: Vec<Ask> = actions
            .iter()
            .map(|action| Ask {
                action: (*action).to_owned(),
                resource: read_ask.resource.clone(),
            })
            .collect();
        let count = asks.len();
        let answers = run_guarded(
            ctx,
            || self.guard.decide(&request.request_id, &who, &asks),
            || vec![Answer::failure(); count],
        )
        .await;
        let mut access = ListAccess::default();
        for (index, action) in actions.iter().enumerate() {
            let answer = answers.get(index).cloned().unwrap_or_else(Answer::failure);
            if answer.failed {
                return Err(pdp_unavailable(action));
            }
            match *action {
                ACTION_READ => {
                    access.read = answer.decision;
                    if answer.decision {
                        // The ceilings of a true answer must be valid, as for each other read.
                        self.check_answer(request, &read_ask, &answer, &mut Grant::default(), false)?;
                    } else if guard::is_approval_reason(&answer.reason) {
                        return Err(approval_cannot_wait());
                    }
                }
                ACTION_WRITE => access.write = answer.decision,
                _ => access.delete = answer.decision,
            }
        }
        if access.read {
            return Ok(ListDisplay {
                access: Some(access),
                navigation: false,
            });
        }
        let node_type = super::tree::Resource::parse(&read_ask.resource)
            .map(|resource| resource.node_type)
            .unwrap_or_default();
        if !has_deeper_type(&node_type) {
            return Err(forbidden(ACTION_READ));
        }
        Ok(ListDisplay {
            access: Some(access),
            navigation: true,
        })
    }

    /// The items of a navigation listing. `prefixes` has one entry for each item of the listing: the relative prefix
    /// of a folder item, or `None` for an object item. The result tells which items stay: the folders that the person
    /// can read (`object.read`, match `subtree`, at the node of the folder). It asks one batch with one question for
    /// each distinct node. A failed answer gives `503`. The listing shows the path to a folder; it lets no operation
    /// run.
    pub async fn navigation_items(
        &self,
        ctx: &OpCtx,
        instance: &Instance,
        prefixes: &[Option<&str>],
    ) -> Result<Vec<bool>> {
        let request = ctx.access.as_deref().ok_or_else(unauthenticated)?;
        let who = request.identity();
        let mut asks: Vec<Ask> = Vec::new();
        let mut index_of: BTreeMap<String, usize> = BTreeMap::new();
        let mut node_of: Vec<Option<usize>> = Vec::with_capacity(prefixes.len());
        for prefix in prefixes {
            let Some(prefix) = prefix else {
                node_of.push(None);
                continue;
            };
            let ask = self.object_ask(ACTION_READ, instance, prefix);
            let next = asks.len();
            let found = *index_of.entry(ask.resource.clone()).or_insert(next);
            if found == next {
                asks.push(ask);
            }
            node_of.push(Some(found));
        }
        if asks.is_empty() {
            return Ok(vec![false; prefixes.len()]);
        }
        let count = asks.len();
        let answers = run_guarded(
            ctx,
            || self.guard.display(&request.request_id, &who, &asks),
            || vec![Answer::failure(); count],
        )
        .await;
        if answers.len() != count || answers.iter().any(|answer| answer.failed) {
            return Err(pdp_unavailable(ACTION_READ));
        }
        Ok(node_of
            .iter()
            .map(|node| node.is_some_and(|index| answers[index].decision))
            .collect())
    }
}

#[cfg(test)]
#[path = "display_tests.rs"]
mod tests;
