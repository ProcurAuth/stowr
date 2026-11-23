//! The access policy of ProcurAuth: the identity token, the questions to the PDP, the resource tree, the action
//! document, the options route, the budgets and the display rules (docs/ACCESS.md).
//!
//! Stowr keeps its own part: the routes and their actions, the resource tree (service, bucket, folder, subfolder),
//! the options route, the ceilings and the budget `writes`, the error envelope and the keys of the configuration.
//! The check of the token, the questions to the PDP and the kept answers use an [`AccessGuard`]. The
//! library `procurauth-pep` gives the guard of the mode `authzen`.

pub mod guard;

use std::sync::{Arc, Mutex};

use crate::common::app::App;
use crate::common::config::Config;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Route, RouteAccess, route};
use crate::instance::Instance;
use crate::instance::ceiling::Ceilings;

pub use guard::{AccessGuard, Answer, Ask, OpenGuard};

/// The action `object.read`.
pub const ACTION_READ: &str = "object.read";
/// The action `object.write`.
pub const ACTION_WRITE: &str = "object.write";
/// The action `object.delete`.
pub const ACTION_DELETE: &str = "object.delete";
/// The action `object.lock`.
pub const ACTION_LOCK: &str = "object.lock";
/// The action `bucket.admin`.
pub const ACTION_BUCKET_ADMIN: &str = "bucket.admin";

/// The identity of a request that passed the check of the token.
#[derive(Debug, Default)]
pub struct AccessRequest {
    /// The subject: the `sub` of the token.
    pub subject: String,
    /// The `owner` of the token, for the log only.
    pub owner: String,
    /// The request id (`X-Request-ID` of the client when it is valid, else a random id).
    pub request_id: String,
    /// The ceilings of the true answers of the request.
    pub ceilings: Arc<Ceilings>,
    /// The subject and the request id for the request log.
    pub log: Mutex<Option<(String, String)>>,
}

/// The permissions of one operation: the others first, without usage, then the use (docs/ACCESS.md, "The routes").
#[derive(Clone, Debug, Default)]
pub struct Operation {
    /// The other permissions.
    pub others: Vec<Ask>,
    /// The permission that the operation uses.
    pub use_ask: Ask,
    /// True for a continuation: the use never carries usage.
    pub continuation: bool,
}

/// The grant of an operation: the ceilings, by action and by name.
#[derive(Clone, Debug, Default)]
pub struct Grant {
    /// The ceilings.
    pub limits: std::collections::BTreeMap<String, std::collections::BTreeMap<String, i64>>,
}

/// The access layer of the application: the guard and the action document.
pub struct AccessLayer {
    /// The guard of the mode of the configuration.
    pub guard: Arc<dyn AccessGuard>,
}

impl AccessLayer {
    /// Build the layer from the configuration: the open guard in mode `open`, the guard of the PEP in mode `authzen`.
    pub fn new(config: &Config) -> Result<Self> {
        if config.access.enforced() {
            return Err(Error::not_served("the access mode authzen"));
        }
        Ok(Self {
            guard: Arc::new(OpenGuard),
        })
    }
}

/// Read the text of `access.identity.public_keys` (PEM or a JWK Set) and give the short name of each key for
/// print-config (`Ed25519 kid=...`, `ES256 kid=...`).
pub fn parse_public_keys(text: &str) -> Result<Vec<String>> {
    let _ = text;
    Err(Error::not_served("the public keys of the issuer"))
}

/// Ask the PDP for the permissions of an operation. In mode `open`, it asks nothing.
pub async fn authorize(app: &App, ctx: &OpCtx, operation: Operation) -> Result<Grant> {
    if !app.config.access.enforced() {
        return Ok(Grant::default());
    }
    let _ = (ctx, operation);
    Err(Error::not_served("the questions to the PDP"))
}

/// The permission of an action on the node of a key or of a prefix of an instance.
pub fn object_ask(app: &App, action: &str, instance: &Instance, relative: &str) -> Ask {
    let _ = relative;
    Ask {
        action: action.to_owned(),
        resource: format!("service:{}/bucket:{}", app.config.access.audience(), instance.cfg.id),
    }
}

/// Ask `object.read` on the node of a key or of a prefix.
pub async fn authorize_read(app: &App, ctx: &OpCtx, instance: &Instance, relative: &str) -> Result<Grant> {
    authorize(
        app,
        ctx,
        Operation {
            use_ask: object_ask(app, ACTION_READ, instance, relative),
            ..Operation::default()
        },
    )
    .await
}

/// Ask the use of an action on the node of a key (with usage when the action lists the budget `writes`).
pub async fn authorize_use(app: &App, ctx: &OpCtx, action: &str, instance: &Instance, relative: &str) -> Result<Grant> {
    authorize(
        app,
        ctx,
        Operation {
            use_ask: object_ask(app, action, instance, relative),
            ..Operation::default()
        },
    )
    .await
}

crate::stub_handler!(handle_actions, "the route /.well-known/procurauth/actions");
crate::stub_handler!(handle_options, "the route /.well-known/procurauth/resources");

/// The routes of this work package.
pub fn routes() -> Vec<Route> {
    vec![
        route("/.well-known/procurauth/actions", RouteAccess::Exempt, handle_actions),
        route(
            "/.well-known/procurauth/resources",
            RouteAccess::HandlerAsks,
            handle_options,
        ),
    ]
}
