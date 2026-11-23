//! The start of each route of this folder: the method, the instance, the permission, the key and the access policy.

use std::sync::Arc;

use http::Method;

use crate::access;
use crate::common::app::App;
use crate::common::config::PERMISSION_READ;
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Req, Response, api_error, method_not_allowed};
use crate::common::misc::clean_relative_key;
use crate::common::query::Query;
use crate::instance::Instance;

/// The object that a request names.
pub struct ObjectTarget {
    /// The instance.
    pub instance: Arc<Instance>,
    /// The relative key.
    pub key: String,
    /// The ETag that the request expects, without the space at its ends.
    pub etag: String,
}

/// The answer of a route: the answer, or the error answer.
pub fn answer(result: Result<Response>) -> Response {
    result.unwrap_or_else(|error| api_error(&error))
}

/// The parts of a request that the routes of this folder use. They have no body: a task that waits for a read of
/// the storage can hold them.
pub struct Call {
    /// The parsed query.
    pub query: Query,
    /// The context of the storage calls.
    pub ctx: OpCtx,
}

/// The start of a route: the method must be `GET`. The other methods get the answer 405.
pub fn start(req: Req) -> std::result::Result<Call, Box<Response>> {
    if req.method != Method::GET {
        return Err(Box::new(method_not_allowed(&["GET"])));
    }
    Ok(Call {
        query: req.query,
        ctx: req.ctx,
    })
}

/// The instance of a request, when the permission `read` is on.
pub fn read_instance(app: &App, req: &Call) -> Result<Arc<Instance>> {
    let instance = app.instance_of("", req.query.get("instance"))?.clone();
    instance.require_permission(PERMISSION_READ)?;
    Ok(instance)
}

/// The key of a request: the cleaned key, or the error `invalid_key` with this message.
pub fn required_key(req: &Call, message: &str) -> Result<String> {
    let key = clean_relative_key(req.query.get("key"));
    if key.is_empty() {
        return Err(Error::api(400, "invalid_key", message));
    }
    Ok(key)
}

/// The object of a request for the previews that read by ranges: the instance, the permission `read`, the key
/// and the access policy.
pub async fn object_target(app: &App, req: &Call, empty_key_message: &str) -> Result<ObjectTarget> {
    let instance = read_instance(app, req)?;
    let key = required_key(req, empty_key_message)?;
    access::authorize_read(app, &req.ctx, &instance, &key).await?;
    Ok(ObjectTarget {
        instance,
        key,
        etag: req.query.get("etag").trim().to_owned(),
    })
}

/// The lower case extension of a key, without the dot: the text after the last dot of the last name.
pub fn key_extension(key: &str) -> String {
    let name = key.rsplit('/').next().unwrap_or(key);
    match name.rfind('.') {
        Some(index) => name[index + 1..].to_lowercase(),
        None => String::new(),
    }
}
