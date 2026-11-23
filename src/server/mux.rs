// SPDX-License-Identifier: MIT OR Apache-2.0
//! The router of the route table. A path that is not clean gets a permanent redirect to its clean form. A path
//! `/x` without a route, whose subtree `/x/` has a route, gets a permanent redirect to `/x/`. The longest pattern
//! that matches wins. The match compares each segment of the path with its escapes decoded.

use std::sync::{Arc, LazyLock};

use http::header::{CONTENT_TYPE, HeaderValue, LOCATION};
use http::{HeaderMap, Method};

use super::paths;
use crate::common::app::App;
use crate::common::http::{Req, Response, Route, answer, api_error, empty, full, not_found};

/// One pattern of the table: its literal segments, and true for a subtree (a pattern that ends with `/`).
struct Pattern {
    segments: Vec<&'static str>,
    subtree: bool,
    route: Route,
}

/// The patterns of the table, without `/s3` and `/-/` (they come before the router).
struct Table {
    patterns: Vec<Pattern>,
    gateway: Option<Route>,
    frontend: Option<Route>,
}

fn table() -> &'static Table {
    static TABLE: LazyLock<Table> = LazyLock::new(|| {
        let mut patterns = Vec::new();
        let mut gateway = None;
        let mut frontend = None;
        for route in super::routes::table() {
            match route.pattern {
                "/s3" => gateway = Some(route),
                "/-/" => frontend = Some(route),
                pattern => {
                    let subtree = pattern.ends_with('/');
                    let inner = pattern.trim_start_matches('/');
                    let inner = inner.strip_suffix('/').unwrap_or(inner);
                    let segments = if inner.is_empty() {
                        Vec::new()
                    } else {
                        inner.split('/').collect()
                    };
                    patterns.push(Pattern {
                        segments,
                        subtree,
                        route,
                    });
                }
            }
        }
        Table {
            patterns,
            gateway,
            frontend,
        }
    });
    &TABLE
}

/// The segments of an escaped path, each with its escapes decoded. A `/` at the end gives the segment `/`.
fn segments_of(path: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = path;
    while !rest.is_empty() {
        if rest == "/" {
            out.push("/".to_owned());
            break;
        }
        let without = rest.strip_prefix('/').unwrap_or(rest);
        let end = without.find('/').unwrap_or(without.len());
        let segment = &without[..end];
        let decoded = paths::unescape_bytes(segment)
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .unwrap_or_else(|| segment.to_owned());
        out.push(decoded);
        rest = &without[end..];
    }
    out
}

/// The pattern that matches a clean escaped path, and true when the match is exact.
fn find(path: &str) -> Option<(&'static Pattern, bool)> {
    let segments = segments_of(path);
    let mut best: Option<&Pattern> = None;
    for pattern in &table().patterns {
        let literal = pattern.segments.len();
        if segments.len() < literal
            || segments
                .iter()
                .zip(&pattern.segments)
                .any(|(left, right)| left != right)
        {
            continue;
        }
        let matches = if pattern.subtree {
            segments.len() > literal
        } else {
            segments.len() == literal
        };
        if matches && best.is_none_or(|current| literal > current.segments.len()) {
            best = Some(pattern);
        }
    }
    best.map(|pattern| {
        let exact =
            !pattern.subtree || (path.ends_with('/') && pattern.segments.len() + 1 == path.matches('/').count());
        (pattern, exact)
    })
}

/// The URL of a redirect to a path (the path is escaped) and a raw query.
fn redirect_url(escaped_path: &str, raw_query: &str) -> String {
    let mut url = escaped_path.to_owned();
    if !raw_query.is_empty() {
        url.push('?');
        url.push_str(raw_query);
    }
    url
}

/// A permanent redirect (301) to a local URL: the path cleaned, the query kept, and a short HTML body for `GET`.
pub fn redirect(method: &Method, url: &str) -> Response {
    let (path, query) = match url.find('?') {
        Some(index) => (&url[..index], &url[index..]),
        None => (url, ""),
    };
    let mut cleaned = paths::clean(path);
    if path.ends_with('/') && !cleaned.ends_with('/') {
        cleaned.push('/');
    }
    let location = paths::hex_escape_non_ascii(&format!("{cleaned}{query}"));
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_str(&location) {
        headers.insert(LOCATION, value);
    }
    let mut body = empty();
    if *method == Method::GET || *method == Method::HEAD {
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    }
    if *method == Method::GET {
        body = full(format!(
            "<a href=\"{}\">Moved Permanently</a>.\n\n",
            paths::html_escape(&format!("{cleaned}{query}"))
        ));
    }
    answer(301, headers, body)
}

/// Call the handler of a route after its access rule: a route without a rule answers `403 forbidden`, and a route
/// of the kind `TokenOnly` asks the action `access` on the service node.
async fn call(app: Arc<App>, req: Req, route: Route) -> Response {
    if let Err(error) = app
        .access
        .guard_route(&req.ctx, route.access, &req.method, &req.path, &req.headers)
        .await
    {
        return api_error(&error);
    }
    (route.handler)(app, req).await
}

/// Route a request: `?version=` into the context, then `/s3` and `/-/` with the path as the client sent it, then
/// the table. `escaped_path` is the path in its escaped form.
pub async fn route(app: Arc<App>, mut req: Req, escaped_path: &str) -> Response {
    let version = req.query.get("version").trim().to_owned();
    if !version.is_empty() {
        req.ctx = req.ctx.with_version(Some(&version));
    }
    if escaped_path == "*" {
        let mut headers = HeaderMap::new();
        headers.insert(http::header::CONNECTION, HeaderValue::from_static("close"));
        return answer(400, headers, empty());
    }
    let table = table();
    if req.path == "/s3"
        && let Some(gateway) = table.gateway
    {
        return call(app, req, gateway).await;
    }
    if req.path.starts_with("/-/")
        && let Some(frontend) = table.frontend
    {
        return call(app, req, frontend).await;
    }
    let path = paths::clean_request_path(escaped_path);
    let found = find(&path);
    let exact = found.is_some_and(|(_, exact)| exact);
    if !exact && !path.ends_with('/') {
        let with_slash = format!("{path}/");
        if find(&with_slash).is_some_and(|(_, exact)| exact) {
            let decoded = paths::clean_request_path(&req.path);
            let target = paths::escape_path_bytes(format!("{decoded}/").as_bytes());
            return redirect(&req.method, &redirect_url(&target, &req.raw_query));
        }
    }
    if path != escaped_path {
        let target = paths::escape_path_bytes(path.as_bytes());
        return redirect(&req.method, &redirect_url(&target, &req.raw_query));
    }
    match found {
        Some((pattern, _)) => call(app, req, pattern.route).await,
        None => not_found(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_longest_pattern_wins() {
        let pattern = |path: &str| find(path).map(|(pattern, exact)| (pattern.route.pattern, exact));
        assert_eq!(pattern("/api/list"), Some(("/api/list", true)));
        assert_eq!(pattern("/api/list/"), Some(("/", false)));
        assert_eq!(pattern("/api/jobs"), Some(("/api/jobs", true)));
        assert_eq!(pattern("/api/jobs/"), Some(("/api/jobs/", true)));
        assert_eq!(pattern("/api/jobs/job_1/pause"), Some(("/api/jobs/", false)));
        assert_eq!(
            pattern("/api/sqlite/sessions/abc"),
            Some(("/api/sqlite/sessions/", false))
        );
        assert_eq!(pattern("/open"), Some(("/", false)));
        assert_eq!(pattern("/open/"), Some(("/open/", true)));
        assert_eq!(pattern("/"), Some(("/", true)));
        assert_eq!(pattern("/api/li%73t"), Some(("/api/list", true)));
        assert_eq!(pattern("/api%2Flist"), Some(("/", false)));
    }

    #[test]
    fn segments_decode_their_escapes() {
        assert_eq!(segments_of("/a/b%20c/"), vec!["a", "b c", "/"]);
        assert_eq!(segments_of("/"), vec!["/"]);
        assert_eq!(segments_of("/a%zz"), vec!["a%zz"]);
    }
}
