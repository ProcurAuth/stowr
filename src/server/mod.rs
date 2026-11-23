// SPDX-License-Identifier: MIT OR Apache-2.0
//! The HTTP server: the listener, the route table and its dispatch, the middlewares (security headers, request
//! log, check of the identity token, budget of the request and its trailers, same-origin check of the mutations,
//! gzip of the large JSON answers), the embedded interface (pages, assets, fingerprints, ETags, ranges, 404 page),
//! the object gateway `/s3` and `/open/`, and the routes of the listing, of the instances, of the build, of the
//! health check, of Insights and of the copy, rename and delete of objects and prefixes.

pub mod api;
pub mod assemble;
pub mod compress;
pub mod frontend;
pub mod gateway;
pub mod kind;
pub mod logfmt;
pub mod mediatype;
pub mod middleware;
pub mod mux;
pub mod paths;
pub mod routes;
pub mod runtime;
pub mod seams;
pub mod serve_content;

#[cfg(test)]
mod access_route_tests;
#[cfg(test)]
mod access_tests;
#[cfg(test)]
mod ceiling_route_tests;
#[cfg(test)]
mod documented_rules_tests;
#[cfg(test)]
mod log_route_tests;
#[cfg(test)]
mod preview_route_tests;
#[cfg(test)]
pub mod testing;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod volume_usage_tests;

use std::sync::Arc;
use std::time::Instant;

use http_body::Body as _;
use http_body_util::BodyExt;

use crate::common::app::App;
use crate::common::config::{Config, LogMode};
use crate::common::error::Result;
use crate::common::http::{Req, Response, Route, RouteAccess, route};
use crate::common::misc::CancelToken;

pub use api::{
    handle_build, handle_copy, handle_delete_prefix, handle_health, handle_instances, handle_list,
    handle_permission_refresh, handle_rename,
};
pub use assemble::{build_app, close_app, probe_instances, start_app};
pub use frontend::{handle_static, handle_storage_frontend};
pub use gateway::{handle_object_gateway, handle_open_original};
pub use runtime::Target;

/// A request without its body: the part of a request that a handler can keep across an await.
#[derive(Debug)]
pub struct RequestHead {
    /// The method.
    pub method: http::Method,
    /// The path, with its escapes decoded.
    pub path: String,
    /// The query, as the client sent it.
    pub raw_query: String,
    /// The parsed query.
    pub query: crate::common::query::Query,
    /// The headers.
    pub headers: http::HeaderMap,
    /// The context of the storage calls of the request.
    pub ctx: crate::common::ctx::OpCtx,
    /// The host of the request.
    pub host: String,
}

/// Split a request into its head and its body.
pub fn split(req: Req) -> (RequestHead, crate::common::http::Body) {
    let Req {
        method,
        path,
        raw_query,
        query,
        headers,
        body,
        ctx,
        host,
    } = req;
    (
        RequestHead {
            method,
            path,
            raw_query,
            query,
            headers,
            ctx,
            host,
        },
        body,
    )
}

/// Run the server until SIGINT or SIGTERM: apply the copy values of the build and log them, build the application,
/// run the start probes, listen on `server.listen`, then serve. The command line logs the effective configuration
/// and the warnings before this call. A copy value of the build that is not valid stops the start.
pub async fn serve(config: Config) -> Result<()> {
    for note in crate::provider::s3::copy::apply_multipart_copy_build_settings()? {
        crate::log!("{note}");
    }
    crate::instance::compiled_copy_threshold()?;
    let listen = config.listen.clone();
    let detailed = config.runtime.log_mode == LogMode::Detailed;
    let source = config.source_name.display().to_string();
    let summary = format!(
        "object browser listening on {} with {} bucket(s) using {} auth configuration(s) and {} volume(s); stateless=true access={}",
        config.listen,
        config.buckets.len(),
        config.auths.len(),
        config.volumes.len(),
        config.runtime.access_mode.as_str()
    );
    let app = start_app(config).await?;
    if detailed {
        crate::log!("loaded configuration from {source}");
    }
    crate::log!("{summary}");
    let listener = match runtime::bind(&listen).await {
        Ok(listener) => listener,
        Err(error) => {
            close_app(&app);
            return Err(error);
        }
    };
    runtime::serve_listener(app.clone(), listener).await;
    close_app(&app);
    Ok(())
}

/// Answer one request: the middlewares, then the route of the table. The path of the request has its escapes
/// decoded; the router uses its escaped form.
pub async fn dispatch(app: Arc<App>, req: Req) -> Response {
    let target = Target {
        escaped_path: paths::escape_path_bytes(req.path.as_bytes()),
        path_bytes: req.path.as_bytes().to_vec(),
    };
    handle(app, req, target).await
}

/// A body that cancels the token of its request at its end or when the client goes.
struct CancelBody {
    inner: crate::common::http::Body,
    cancel: Option<CancelToken>,
}

impl CancelBody {
    fn finish(&mut self) {
        if let Some(cancel) = self.cancel.take() {
            cancel.cancel();
        }
    }
}

impl http_body::Body for CancelBody {
    type Data = bytes::Bytes;
    type Error = crate::common::error::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<bytes::Bytes>>>> {
        let polled = std::pin::Pin::new(&mut self.inner).poll_frame(cx);
        if matches!(polled, std::task::Poll::Ready(None)) {
            self.finish();
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for CancelBody {
    fn drop(&mut self) {
        self.finish();
    }
}

/// Cancel a token when the future that holds it is dropped before its end.
struct CancelGuard(Option<CancelToken>);

impl Drop for CancelGuard {
    fn drop(&mut self) {
        if let Some(token) = self.0.take() {
            token.cancel();
        }
    }
}

/// Answer one request whose target is known: the middlewares, in order (security headers, request log, identity
/// token, budget, same-origin check, gzip of the JSON answers), then the router.
pub async fn handle(app: Arc<App>, mut req: Req, target: Target) -> Response {
    let started = Instant::now();
    let method = req.method.clone();
    let path = req.path.clone();
    let logged_path = middleware::logged_request_path(app.config.runtime.log_mode, &target.path_bytes);
    let cancel = CancelToken::new();
    req.ctx.cancel = cancel.clone();
    let mut guard = CancelGuard(Some(cancel.clone()));
    let mut identity = None;
    let response = match middleware::authenticate(&app, &mut req) {
        Err(response) => *response,
        Ok(found) => {
            identity = found;
            inner(app.clone(), req, &target).await
        }
    };
    guard.0 = None;
    let (mut parts, body) = response.into_parts();
    middleware::apply_security_headers(&mut parts.headers, &path);
    let line = middleware::LogLine {
        method,
        path: logged_path,
        status: parts.status.as_u16(),
        started,
        identity,
    };
    let body = CancelBody {
        inner: body,
        cancel: Some(cancel),
    };
    let body = middleware::LogBody::new(body.boxed_unsync(), line);
    Response::from_parts(parts, body.boxed_unsync())
}

/// The middlewares inside the identity check: the budget and its trailers, the same-origin check, the gzip of the
/// JSON answers and the router.
async fn inner(app: Arc<App>, mut req: Req, target: &Target) -> Response {
    let mut budget = None;
    if middleware::budget_applies(&req.path) {
        if req.method == http::Method::PUT && !req.body.is_end_stream() {
            // An object or an upload chunk goes to the provider while a storage slot is held: a stalled client must
            // not keep it.
            let body = std::mem::replace(&mut req.body, crate::common::http::empty());
            req.body = middleware::IdleBody::new(body, middleware::STREAM_IDLE_TIMEOUT).boxed_unsync();
        }
        let request_budget = Arc::new(crate::instance::budget::Budget::for_request(&app.config.runtime));
        req.ctx.budget = Some(request_budget.clone());
        budget = Some(request_budget);
    }
    let response = match middleware::same_origin_refusal(&req.method, &req.headers, &req.host) {
        Some(refusal) => refusal,
        None => {
            let gzip = compress::gzip_json_applies(&req.path, &req.method, &req.headers);
            let response = mux::route(app, req, &target.escaped_path).await;
            if gzip {
                compress::gzip_json(response).await
            } else {
                response
            }
        }
    };
    match budget {
        Some(budget) => {
            let (mut parts, body) = response.into_parts();
            middleware::declare_trailers(&mut parts.headers);
            let body = middleware::BudgetBody::new(body, budget);
            Response::from_parts(parts, body.boxed_unsync())
        }
        None => response,
    }
}

/// The kind of a key for Insights and the details: `image`, `video`, `audio`, `pdf`, `markdown`, `document`,
/// `spreadsheet`, `presentation`, `database`, `contact`, `calendar`, `email`, `certificate`, `archive`, `code`,
/// `text` or `other`.
pub fn detect_kind(key: &str, content_type: &str) -> &'static str {
    kind::detect_kind(key, content_type)
}

/// The routes of this module.
pub fn own_routes() -> Vec<Route> {
    vec![
        route("/s3", RouteAccess::HandlerAsks, handle_object_gateway),
        route("/-/", RouteAccess::TokenOnly, handle_storage_frontend),
        route("/api/instances", RouteAccess::HandlerAsks, handle_instances),
        route("/api/build", RouteAccess::TokenOnly, handle_build),
        route(
            "/api/permissions/refresh",
            RouteAccess::HandlerAsks,
            handle_permission_refresh,
        ),
        route("/api/list", RouteAccess::HandlerAsks, handle_list),
        route("/api/stats", RouteAccess::HandlerAsks, crate::jobs::handle_stats),
        route("/api/copy", RouteAccess::HandlerAsks, handle_copy),
        route("/api/rename", RouteAccess::HandlerAsks, handle_rename),
        route("/api/delete-prefix", RouteAccess::HandlerAsks, handle_delete_prefix),
        route("/healthz", RouteAccess::Exempt, handle_health),
        route("/open/", RouteAccess::HandlerAsks, handle_open_original),
        route("/", RouteAccess::TokenOnly, handle_static),
    ]
}
