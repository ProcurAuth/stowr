//! The HTTP server: the listener, the route table and its dispatch, the middlewares (security headers, request
//! log, check of the identity token, budget of the request and its trailers, same-origin check of the mutations,
//! gzip of the large JSON answers), the embedded interface (pages, assets, fingerprints, ETags, ranges, 404 page),
//! the object gateway `/s3` and `/open/`, and the routes of the listing, of the instances, of the build, of the
//! health check, of Insights and of the copy, rename and delete of objects and prefixes.

pub mod routes;

use std::sync::Arc;

use crate::common::app::App;
use crate::common::config::Config;
use crate::common::error::{Error, Result};
use crate::common::http::{Req, Response, Route, RouteAccess, route};

/// Build the application: the shared provider clients, the instances (buckets, then volumes), the start probes, the
/// job manager, the upload manager, the SQLite sessions and the access layer.
pub fn build_app(config: Config) -> Result<Arc<App>> {
    let _ = config;
    Err(Error::not_served("the application"))
}

/// Run the server until SIGINT or SIGTERM: listen on `server.listen`, log the effective configuration and the
/// warnings, then serve.
pub async fn serve(config: Config) -> Result<()> {
    let _ = build_app(config)?;
    Err(Error::not_served("the HTTP server"))
}

/// Answer one request: the middlewares, then the route of the table.
pub async fn dispatch(app: Arc<App>, req: Req) -> Response {
    let _ = (app, req);
    crate::common::http::api_error(&Error::not_served("the dispatch of the requests"))
}

/// The kind of a key for Insights and the details: `image`, `video`, `audio`, `pdf`, `markdown`, `document`,
/// `spreadsheet`, `presentation`, `database`, `contact`, `calendar`, `email`, `certificate`, `archive`, `code`,
/// `text` or `other`.
pub fn detect_kind(key: &str, content_type: &str) -> &'static str {
    let _ = (key, content_type);
    "other"
}

crate::stub_handler!(handle_object_gateway, "the route /s3");
crate::stub_handler!(handle_storage_frontend, "the pages /-/");
crate::stub_handler!(handle_instances, "the route /api/instances");
crate::stub_handler!(handle_build, "the route /api/build");
crate::stub_handler!(handle_permission_refresh, "the route /api/permissions/refresh");
crate::stub_handler!(handle_list, "the route /api/list");
crate::stub_handler!(handle_stats, "the route /api/stats");
crate::stub_handler!(handle_copy, "the route /api/copy");
crate::stub_handler!(handle_rename, "the route /api/rename");
crate::stub_handler!(handle_delete_prefix, "the route /api/delete-prefix");
crate::stub_handler!(handle_health, "the route /healthz");
crate::stub_handler!(handle_open_original, "the route /open/");
crate::stub_handler!(handle_static, "the static files");

/// The routes of this work package.
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
        route("/api/stats", RouteAccess::HandlerAsks, handle_stats),
        route("/api/copy", RouteAccess::HandlerAsks, handle_copy),
        route("/api/rename", RouteAccess::HandlerAsks, handle_rename),
        route("/api/delete-prefix", RouteAccess::HandlerAsks, handle_delete_prefix),
        route("/healthz", RouteAccess::Exempt, handle_health),
        route("/open/", RouteAccess::HandlerAsks, handle_open_original),
        route("/", RouteAccess::TokenOnly, handle_static),
    ]
}
