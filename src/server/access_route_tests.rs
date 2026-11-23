//! The route tests of the access policy in mode `authzen`, through the whole dispatch: the refusals of the identity
//! check, the exempt paths, the kinds of the route table, the routes that need only the token, the read routes, the
//! change routes, the uploads, the jobs, the SQLite sessions and the extraction to another instance.
//!
//! Each test uses the fake guard. A table test keeps each failure of each route and shows them all at the end.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};

use base64::Engine;
use bytes::Bytes;
use http::header::{CONTENT_LENGTH, HOST, HeaderValue};
use http::{HeaderMap, Method, Uri, Version};
use http_body::Frame;
use http_body_util::BodyExt;
use serde_json::{Value, json};

use super::testing::{TestRequest, TestResponse, app_with_access, collect};
use crate::access::fake::{FakePdp, FakeQuestion};
use crate::access::test_support::{
    BUCKET, FOLDER, SERVICE, SUBFOLDER, SUBJECT, Summary, answer_all, authzen_config, bucket, folder, instance_over,
    memory, summarize, summary, usage_answer,
};
use crate::access::{
    ACTION_ACCESS, ACTION_DELETE, ACTION_READ, ACTION_WRITE, AccessLayer, Ask, actions::ACTIONS_PATH,
    options::OPTIONS_PATH,
};
use crate::common::app::App;
use crate::common::config::BucketConfig;
use crate::common::error::{Error, LimitKind, ResourceLimit};
use crate::common::http::RouteAccess;
use crate::common::storage::Backend;
use crate::jobs::{JobState, job_type};
use crate::testkit::MemoryBackend;

/// The token of the subject of the tests.
const TOKEN: &str = "good-token";
/// The token of a second subject.
const OTHER_TOKEN: &str = "other-token";
/// The text of a refusal of the identity check.
const UNAUTHENTICATED: &str = "A valid identity token is required.";
/// The SQLite database of the tests: the tables `items` and `composite`.
const SQLITE_FIXTURE: &str = concat!(
    "U1FMaXRlIGZvcm1hdCAzAAIAAQEAQCAgAAAABAAAAAMAAAAAAAAAAAAAAAMAAAAEAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAC56cQ0AAAACAR4AAZEBHgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHEC",
    "BxcfHwGBMXRhYmxlY29tcG9zaXRlY29tcG9zaXRlA0NSRUFURSBUQUJMRSBjb21wb3NpdGUoYSBURVhULGIgSU5URUdFUix2",
    "YWx1ZSBURVhULFBSSU1BUlkgS0VZKGEsYikpIFdJVEhPVVQgUk9XSURtAQcXFxcBgTl0YWJsZWl0ZW1zaXRlbXMCQ1JFQVRF",
    "IFRBQkxFIGl0ZW1zKGlkIElOVEVHRVIgUFJJTUFSWSBLRVksbmFtZSBURVhULHNjb3JlIFJFQUwscGF5bG9hZCBCTE9CLG5v",
    "dGUgVEVYVCkNAAAAAwG9AAHiAc8BvQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAEAMGABcADBdnYW1tYXRoaXJkEQIGABUBABliZXRhAnNlY29uZBwBBgAXBxQXYWxwaGE/",
    "+AAAAAAAAAECAwRmaXJzdAoAAAADAeIAAfcB7QHiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACgQPCRd5",
    "dGhyZWUJBA8BE3gCdHdvCAQPCRN4b25l",
);

// --- The environment ----------------------------------------------------------------------------------------------

/// The application of the tests: `readonly` (read only), `rw` (root prefix `tenant/`) and the extra buckets, with the
/// fake guard that accepts [`TOKEN`] for the subject of the tests and [`OTHER_TOKEN`] for `user-2`.
struct Env {
    app: Arc<App>,
    fake: Arc<FakePdp>,
    rw: Arc<MemoryBackend>,
}

impl Env {
    fn new() -> Self {
        Self::with_extra(Vec::new())
    }

    fn with_extra(extra: Vec<(BucketConfig, Arc<MemoryBackend>)>) -> Self {
        Self::build(None, extra)
    }

    /// An environment whose instance `rw` has a back end with object tags and the same objects.
    fn with_tags() -> Self {
        let tagging = crate::lifecycle::fakes::TaggingMemory::new(&[
            ("tenant/folder/direct.txt", "direct"),
            ("tenant/folder/nested/deep.txt", "deep"),
            ("tenant/a/x.txt", "a"),
        ]);
        Self::build(Some(Arc::new(tagging)), Vec::new())
    }

    /// An environment with a back end of `rw` (by default the memory back end of [`Env::rw`]) and more instances.
    fn build(rw_backend: Option<Arc<dyn Backend>>, extra: Vec<(BucketConfig, Arc<MemoryBackend>)>) -> Self {
        let readonly = bucket("readonly", "Read only", Some(&["read"]));
        let mut rw = bucket("rw", "Read write", None);
        rw.root_prefix = "tenant/".to_owned();
        let mut buckets = vec![readonly.clone(), rw.clone()];
        buckets.extend(extra.iter().map(|(cfg, _)| cfg.clone()));
        let mut config = authzen_config(SERVICE, buckets, Vec::new());
        config.job_history_limit = 10;
        let fake = Arc::new(FakePdp::new());
        fake.accept_token(TOKEN, SUBJECT, "");
        fake.accept_token(OTHER_TOKEN, "user-2", "");
        let access = AccessLayer::with_guard(&config, fake.clone()).unwrap();
        let rw_memory = memory(&[
            ("tenant/folder/direct.txt", "direct"),
            ("tenant/folder/nested/deep.txt", "deep"),
            ("tenant/a/x.txt", "a"),
        ]);
        let readonly_backend: Arc<dyn Backend> = memory(&[("ro.txt", "ro")]);
        let rw_dyn: Arc<dyn Backend> = rw_backend.unwrap_or_else(|| rw_memory.clone());
        let mut instances = vec![instance_over(readonly, readonly_backend), instance_over(rw, rw_dyn)];
        for (cfg, backend) in extra {
            let backend: Arc<dyn Backend> = backend;
            instances.push(instance_over(cfg, backend));
        }
        let app = app_with_access(config, instances, access);
        // The start probe does not run in a test: the version routes need its result.
        app.instance("rw").unwrap().set_versioning_available(true);
        Self {
            app,
            fake,
            rw: rw_memory,
        }
    }

    /// An environment with the SQLite database at `tenant/folder/fixture.sqlite`.
    fn with_sqlite() -> Self {
        let env = Self::new();
        let data = base64::engine::general_purpose::STANDARD
            .decode(SQLITE_FIXTURE)
            .unwrap();
        env.rw
            .insert("tenant/folder/fixture.sqlite", data, "application/octet-stream");
        env
    }

    /// Send a request with an optional token, extra headers and an optional body.
    async fn send_as(
        &self,
        token: Option<&str>,
        method: &str,
        target: &str,
        body: Option<&str>,
        headers: &[(&str, &str)],
    ) -> TestResponse {
        let mut request = TestRequest::new(method, target);
        if let Some(token) = token {
            request = request.header("x-identity-token", token);
        }
        for (name, value) in headers {
            request = request.header(name, value);
        }
        if let Some(body) = body {
            request = request.body(body.to_owned());
        }
        request.send(&self.app).await
    }

    /// Send a request with the token of the subject of the tests.
    async fn send(&self, method: &str, target: &str, body: Option<&str>) -> TestResponse {
        self.send_as(Some(TOKEN), method, target, body, &[]).await
    }

    /// The action and the path of each question.
    fn questions(&self) -> Vec<(String, String)> {
        self.fake
            .questions()
            .into_iter()
            .map(|question| (question.action, question.path))
            .collect()
    }

    /// Create a copy job of `folder/nested/` to `copied/` with a PDP that says true, and give its id.
    async fn start_copy_job(&self) -> String {
        self.fake.set_answer(usage_answer(true));
        let answer = self
            .send(
                "POST",
                "/api/copy",
                Some(r#"{"instance":"rw","src":"folder/nested/","dst":"copied/","isPrefix":true}"#),
            )
            .await;
        assert_eq!(answer.status, 202, "copy: {}", answer.text());
        let id = answer.json()["id"].as_str().unwrap_or("").to_owned();
        assert!(!id.is_empty(), "copy: {}", answer.text());
        id
    }

    /// Create an upload of 3 bytes with a PDP that says true, and give its resume token.
    async fn create_upload(&self, key: &str) -> String {
        self.fake.set_answer(usage_answer(true));
        let body = json!({"instance": "rw", "key": key, "size": 3}).to_string();
        let answer = self.send("POST", "/api/uploads", Some(&body)).await;
        assert_eq!(answer.status, 201, "create: {}", answer.text());
        let token = answer.json()["resumeToken"].as_str().unwrap_or("").to_owned();
        assert!(!token.is_empty(), "create: {}", answer.text());
        token
    }

    /// A request of an upload with its resume token. A `PUT` sends the 3 bytes of the upload.
    async fn upload_request(&self, method: &str, target: &str, body: Option<&str>, token: &str) -> TestResponse {
        let mut headers = vec![("x-stowr-resume-token", token)];
        if method == "PUT" {
            headers.push(("content-range", "bytes 0-2/3"));
        }
        self.send_as(Some(TOKEN), method, target, body, &headers).await
    }

    /// Create a SQLite session of the database of the tests with a PDP that says true, and give its id.
    async fn create_sqlite_session(&self) -> String {
        self.fake.set_answer(answer_all(true));
        let answer = self
            .send(
                "POST",
                "/api/sqlite/sessions",
                Some(r#"{"instance":"rw","key":"folder/fixture.sqlite"}"#),
            )
            .await;
        assert_eq!(answer.status, 201, "create: {}", answer.text());
        let id = answer.json()["id"].as_str().unwrap_or("").to_owned();
        assert!(!id.is_empty(), "create: {}", answer.text());
        id
    }
}

/// The member `error.<name>` of a JSON answer.
fn error_member(answer: &TestResponse, name: &str) -> Value {
    answer.json()["error"][name].clone()
}

/// An answer that refuses each question with a used budget and `retry_after` 7.
fn budget_answer(_: &FakeQuestion) -> Value {
    json!({"decision": false, "context": {"reason": "budget_exceeded", "retry_after": 7}})
}

/// The code of an access error of an answer, or `None` for another answer.
fn access_error(answer: &TestResponse, gateway: bool) -> Option<String> {
    if gateway {
        let text = answer.text();
        let marks = [
            "The action ",
            "The budget of the action",
            "The decision for the action",
            "A valid identity token",
        ];
        return marks.iter().any(|mark| text.contains(mark)).then_some(text);
    }
    let code = error_member(answer, "code").as_str().unwrap_or("").to_owned();
    matches!(
        code.as_str(),
        "forbidden" | "too_many_requests" | "pdp_unavailable" | "unauthenticated"
    )
    .then_some(code)
}

/// A question of the continuation of an upload: `object.write` on the folder `other`, alone, without usage.
fn upload_continuation() -> Vec<Summary> {
    vec![summary(ACTION_WRITE, &folder("other"), false, false, false)]
}

// --- The identity check and the exempt paths -------------------------------------------------------------------------

/// A case of a token: its name, the target and the headers of the request.
type TokenCase<'a> = (&'a str, &'a str, Vec<(&'a str, &'a str)>);

#[tokio::test]
async fn each_request_without_a_valid_token_gets_401_and_asks_nothing() {
    let env = Env::new();
    env.fake.refuse_token("signed-by-other", "signature");
    let list = "/api/list?instance=rw";
    let query = format!("{list}&X-Identity-Token={TOKEN}");
    let authorization = format!("Bearer {TOKEN}");
    let cookie = format!("X-Identity-Token={TOKEN}");
    let cases: Vec<TokenCase<'_>> = vec![
        ("no token", list, vec![]),
        (
            "two copies of the header",
            list,
            vec![("x-identity-token", TOKEN), ("x-identity-token", TOKEN)],
        ),
        (
            "a token that the guard refuses",
            list,
            vec![("x-identity-token", "signed-by-other")],
        ),
        ("garbage", list, vec![("x-identity-token", "not-a-token")]),
        (
            "the token only in the authorization header",
            list,
            vec![("authorization", authorization.as_str())],
        ),
        ("the token only in a cookie", list, vec![("cookie", cookie.as_str())]),
        ("the token only in the query", query.as_str(), vec![]),
        ("a page", "/", vec![]),
        ("a page of a bucket", "/-/test-auth/rw/", vec![]),
        ("the build", "/api/build", vec![]),
        ("an asset", "/assets/js/app.js", vec![]),
        ("the gateway", "/s3?instance=rw&key=folder%2Fdirect.txt", vec![]),
        ("an unknown path", "/.well-known/access-actions", vec![]),
    ];
    for (name, target, headers) in cases {
        let answer = env.send_as(None, "GET", target, None, &headers).await;
        assert_eq!(answer.status, 401, "{name}: {}", answer.text());
        assert_eq!(error_member(&answer, "code"), "unauthenticated", "{name}");
        assert_eq!(error_member(&answer, "message"), UNAUTHENTICATED, "{name}");
    }
    assert_eq!(env.fake.requests(), 0);
}

#[tokio::test]
async fn the_exempt_paths_answer_without_a_token_and_with_a_bad_token() {
    let env = Env::new();
    let document = env.app.access.document.json().to_vec();
    for headers in [vec![], vec![("x-identity-token", "not-a-token")]] {
        for method in ["GET", "HEAD"] {
            let answer = env.send_as(None, method, "/healthz", None, &headers).await;
            assert_eq!(answer.status, 200, "{method} /healthz {headers:?}");
        }
        let answer = env.send_as(None, "GET", ACTIONS_PATH, None, &headers).await;
        assert_eq!(answer.status, 200, "{headers:?}");
        assert_eq!(answer.body.as_ref(), document.as_slice(), "{headers:?}");
        assert_eq!(answer.header("cache-control"), "no-store");
        let answer = env.send_as(None, "HEAD", ACTIONS_PATH, None, &headers).await;
        assert_eq!(answer.status, 200, "{headers:?}");
        assert!(answer.body.is_empty(), "{headers:?}");
        assert_eq!(answer.header("cache-control"), "no-store", "HEAD {headers:?}");
    }
    assert_eq!(env.fake.requests(), 0);
    // An unknown path of the protocol needs the token, then gives 404.
    let answer = env.send("GET", "/.well-known/access-actions", None).await;
    assert_eq!(answer.status, 404, "{}", answer.text());
}

#[test]
fn only_the_exempt_routes_have_exempt_paths_and_only_four_routes_need_only_the_token() {
    let table = super::routes::table();
    for route in &table {
        assert_ne!(route.access, RouteAccess::Denied, "{}", route.pattern);
        assert_eq!(
            crate::access::is_exempt_path(route.pattern),
            route.access == RouteAccess::Exempt,
            "{}",
            route.pattern
        );
        let token_only = matches!(route.pattern, "/" | "/-/" | "/api/build" | "/api/jobs");
        assert_eq!(route.access == RouteAccess::TokenOnly, token_only, "{}", route.pattern);
    }
    let exempt: Vec<&str> = table
        .iter()
        .filter(|route| route.access == RouteAccess::Exempt)
        .map(|route| route.pattern)
        .collect();
    assert_eq!(exempt.len(), 2);
    assert!(exempt.contains(&"/healthz") && exempt.contains(&ACTIONS_PATH));
    let actions_folder = format!("{ACTIONS_PATH}/");
    for path in [
        "/",
        "/healthz/",
        "//healthz",
        "/healthz2",
        actions_folder.as_str(),
        "/api/build",
        "/.well-known/access-actions",
    ] {
        assert!(!crate::access::is_exempt_path(path), "{path}");
    }
}

#[tokio::test]
async fn the_routes_that_need_only_the_token_ask_the_action_access_on_the_service() {
    let env = Env::new();
    env.fake.set_answer(answer_all(true));
    let service = format!("service:{SERVICE}");
    for (target, status) in [
        ("/", 200),
        ("/index.html", 200),
        ("/-/test-auth/rw/", 200),
        ("/api/build", 200),
        ("/assets/js/app.js", 200),
        ("/api/jobs", 404),
    ] {
        env.fake.reset();
        let answer = env.send("GET", target, None).await;
        assert_eq!(answer.status, status, "{target}: {}", answer.text());
        assert_eq!(
            env.questions(),
            vec![(ACTION_ACCESS.to_owned(), service.clone())],
            "{target}"
        );
    }
}

#[tokio::test]
async fn the_options_route_through_the_dispatch_needs_the_token_and_asks_subtree_questions() {
    let env = Env::new();
    let target = format!("{OPTIONS_PATH}?type=bucket");
    let answer = env.send_as(None, "GET", &target, None, &[]).await;
    assert_eq!(answer.status, 401, "{}", answer.text());
    assert!(env.fake.questions().is_empty());
    let answer = env.send("GET", &target, None).await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    let questions = env.fake.questions();
    assert!(!questions.is_empty());
    for question in questions {
        assert_eq!(question.match_mode, "subtree", "{question:?}");
        assert!(!question.usage, "{question:?}");
    }
}

#[tokio::test]
async fn the_error_of_a_used_resource_budget_keeps_its_shape() {
    let error = Error::Budget(ResourceLimit {
        kind: LimitKind::StorageRequests,
        limit: 1,
        used: 2,
    });
    let answer = collect(crate::common::http::api_error(&error)).await;
    assert_eq!(answer.status, 429);
    assert_eq!(error_member(&answer, "code"), "resource_budget_exceeded");
    assert!(answer.headers.get("retry-after").is_none());
    assert_ne!(error_member(&answer, "retryable"), true);
}

#[tokio::test]
async fn a_permission_that_the_configuration_denies_comes_before_the_pdp() {
    let env = Env::new();
    {
        let rw = env.app.instance("rw").unwrap();
        let mut caps = rw.caps.lock().unwrap();
        crate::instance::capability::set_state(
            &mut caps,
            "read",
            crate::instance::capability::denied("configuration", "off", true),
        );
    }
    let answer = env.send("GET", "/api/list?instance=rw", None).await;
    assert_eq!(answer.status, 403, "{}", answer.text());
    assert_eq!(error_member(&answer, "code"), "permission_denied");
    assert_eq!(env.fake.requests(), 0);
}

// --- The read routes ---------------------------------------------------------------------------------------------

/// A read route: the request and the paths of its questions, in order.
struct ReadRoute {
    name: &'static str,
    method: &'static str,
    target: String,
    body: Option<String>,
    gateway: bool,
    wants: Vec<String>,
}

fn read_routes() -> Vec<ReadRoute> {
    let key = "instance=rw&key=folder%2Fdirect.txt";
    let route = |name: &'static str, method: &'static str, target: String, gateway: bool, node: &str| ReadRoute {
        name,
        method,
        target,
        body: None,
        gateway,
        wants: vec![node.to_owned()],
    };
    let object = |name: &'static str, path: &str| route(name, "GET", format!("{path}?{key}"), false, FOLDER);
    let post = |name: &'static str, target: &str, body: &str, wants: Vec<String>| ReadRoute {
        name,
        method: "POST",
        target: target.to_owned(),
        body: Some(body.to_owned()),
        gateway: false,
        wants,
    };
    vec![
        route("gateway get", "GET", format!("/s3?{key}"), true, FOLDER),
        route("gateway head", "HEAD", format!("/s3?{key}"), true, FOLDER),
        route(
            "gateway listing",
            "GET",
            "/s3?instance=rw&prefix=folder%2F".to_owned(),
            true,
            FOLDER,
        ),
        route(
            "gateway listing of the root",
            "GET",
            "/s3?instance=rw".to_owned(),
            true,
            BUCKET,
        ),
        route(
            "gateway listing head",
            "HEAD",
            "/s3?instance=rw&prefix=folder%2Fnested%2F".to_owned(),
            true,
            SUBFOLDER,
        ),
        route("open get", "GET", format!("/open/?{key}"), true, FOLDER),
        route("open head", "HEAD", format!("/open/?{key}"), true, FOLDER),
        route(
            "stats",
            "GET",
            "/api/stats?instance=rw&prefix=folder%2F".to_owned(),
            false,
            FOLDER,
        ),
        route(
            "archive",
            "GET",
            "/api/archive?instance=rw&prefix=folder%2F".to_owned(),
            false,
            FOLDER,
        ),
        object("spreadsheet", "/api/spreadsheet"),
        object("delimited", "/api/delimited"),
        object("document count", "/api/document-count"),
        object("word", "/api/document/word"),
        object("parquet", "/api/parquet"),
        object("json raw", "/api/json/raw"),
        object("json beautify", "/api/json/beautify"),
        object("json summary", "/api/json/summary"),
        object("json tree", "/api/json/tree"),
        route("search", "GET", format!("/api/search?{key}&q=direct"), false, FOLDER),
        object("media info", "/api/media-info"),
        object("structured preview", "/api/structured-preview"),
        object("archive preview", "/api/archive-preview"),
        route(
            "archive entry",
            "GET",
            format!("/api/archive-entry?{key}&entry=a.txt"),
            false,
            FOLDER,
        ),
        route(
            "archive entry head",
            "HEAD",
            format!("/api/archive-entry?{key}&entry=a.txt"),
            false,
            FOLDER,
        ),
        object("image preview", "/api/image-preview"),
        object("inspect", "/api/inspect"),
        object("versions", "/api/versions"),
        post(
            "version counts",
            "/api/version-counts",
            r#"{"instance":"rw","keys":["folder/direct.txt","folder/nested/deep.txt","folder/direct.txt"]}"#,
            vec![SUBFOLDER.to_owned(), FOLDER.to_owned()],
        ),
        post(
            "integrity",
            "/api/integrity",
            r#"{"instance":"rw","key":"folder/direct.txt"}"#,
            vec![FOLDER.to_owned()],
        ),
        post(
            "archive entry integrity",
            "/api/archive-entry/integrity",
            r#"{"instance":"rw","key":"folder/direct.txt","entry":"a.txt"}"#,
            vec![FOLDER.to_owned()],
        ),
        object("tags", "/api/tags"),
        object("metadata", "/api/metadata"),
        object("object lock", "/api/object-lock"),
        route(
            "encryption",
            "GET",
            "/api/encryption?instance=rw".to_owned(),
            false,
            BUCKET,
        ),
        route("usage", "GET", "/api/usage?instance=rw".to_owned(), false, BUCKET),
        route(
            "lifecycle",
            "GET",
            "/api/lifecycle?instance=rw".to_owned(),
            false,
            BUCKET,
        ),
        route(
            "permissions refresh",
            "POST",
            "/api/permissions/refresh?instance=rw".to_owned(),
            false,
            BUCKET,
        ),
        route(
            "multiparts",
            "GET",
            "/api/multiparts?instance=rw&prefix=folder%2F".to_owned(),
            false,
            FOLDER,
        ),
    ]
}

/// Check one read route: a refusal, a grant, a failure of the PDP and an unknown instance.
async fn check_read_route(route: &ReadRoute, failures: &mut Vec<String>) {
    let name = route.name;
    let env = Env::new();
    let body = route.body.as_deref();
    let json_answer = !route.gateway && route.method != "HEAD";

    env.fake.set_answer(answer_all(false));
    let answer = env.send(route.method, &route.target, body).await;
    if answer.status != 403 {
        failures.push(format!("{name}: false gives {}: {}", answer.status, answer.text()));
        return;
    }
    if route.gateway && route.method != "HEAD" && !answer.text().contains("The action object.read is not allowed.") {
        failures.push(format!("{name}: false gives the text {:?}", answer.text()));
    }
    if json_answer && (error_member(&answer, "code") != "forbidden" || error_member(&answer, "action") != ACTION_READ) {
        failures.push(format!("{name}: false gives the error {}", answer.text()));
    }
    let questions = env.fake.questions();
    if questions.first().map(|question| question.path.as_str()) != route.wants.first().map(String::as_str) {
        failures.push(format!("{name}: false asks {questions:?}"));
    }

    env.fake.reset();
    env.fake.set_answer(answer_all(true));
    let answer = env.send(route.method, &route.target, body).await;
    if matches!(answer.status, 401 | 403 | 503) {
        failures.push(format!("{name}: true gives {}: {}", answer.status, answer.text()));
    }
    let questions = env.fake.questions();
    let fits = questions.len() == route.wants.len()
        && questions.iter().zip(&route.wants).all(|(question, want)| {
            question.action == ACTION_READ
                && question.path == *want
                && question.match_mode == "node"
                && !question.usage
                && question.subject == SUBJECT
        });
    if !fits {
        failures.push(format!(
            "{name}: true asks {questions:?}, want object.read on {:?}",
            route.wants
        ));
    }

    env.fake.reset();
    env.fake.set_status(500);
    let answer = env.send(route.method, &route.target, body).await;
    if answer.status != 503 {
        failures.push(format!("{name}: a failure gives {}: {}", answer.status, answer.text()));
    } else if json_answer
        && (error_member(&answer, "code") != "pdp_unavailable"
            || error_member(&answer, "action") != ACTION_READ
            || error_member(&answer, "retryable") != true)
    {
        failures.push(format!("{name}: a failure gives the error {}", answer.text()));
    }

    env.fake.reset();
    let target = route.target.replacen("instance=rw", "instance=nope", 1);
    let body = route
        .body
        .as_ref()
        .map(|body| body.replacen(r#""instance":"rw""#, r#""instance":"nope""#, 1));
    let answer = env.send(route.method, &target, body.as_deref()).await;
    if answer.status != 404 {
        failures.push(format!(
            "{name}: an unknown instance gives {}: {}",
            answer.status,
            answer.text()
        ));
    }
    if !env.fake.questions().is_empty() {
        failures.push(format!("{name}: an unknown instance asks {:?}", env.fake.questions()));
    }
}

#[tokio::test]
async fn each_read_route_asks_object_read_on_the_node_of_its_key() {
    let mut failures = Vec::new();
    for route in read_routes() {
        check_read_route(&route, &mut failures).await;
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

// --- The change routes -------------------------------------------------------------------------------------------

/// A change route: the request, the other permissions in order and the permission that it uses.
struct ChangeRoute {
    name: &'static str,
    method: &'static str,
    target: &'static str,
    body: &'static str,
    gateway: bool,
    /// True when a PDP that says true must give a 2xx answer.
    strict: bool,
    others: Vec<(&'static str, String)>,
    use_ask: (&'static str, String),
    /// True when the instance `rw` needs a back end with object tags.
    tags: bool,
}

fn change_routes() -> Vec<ChangeRoute> {
    let other = folder("other");
    let route = |name, method, target, body, gateway, strict, others, use_ask| ChangeRoute {
        name,
        method,
        target,
        body,
        gateway,
        strict,
        others,
        use_ask,
        tags: false,
    };
    vec![
        route(
            "gateway put",
            "PUT",
            "/s3?instance=rw&key=other%2Fnew.txt",
            "hello",
            true,
            true,
            vec![],
            (ACTION_WRITE, other.clone()),
        ),
        route(
            "gateway put of a folder",
            "PUT",
            "/s3?instance=rw&key=other%2Fsub%2F",
            "",
            true,
            true,
            vec![],
            (ACTION_WRITE, format!("{other}/subfolder:sub")),
        ),
        route(
            "gateway delete",
            "DELETE",
            "/s3?instance=rw&key=folder%2Fdirect.txt",
            "",
            true,
            true,
            vec![],
            (ACTION_DELETE, FOLDER.to_owned()),
        ),
        route(
            "gateway delete of a version",
            "DELETE",
            "/s3?instance=rw&key=folder%2Fdirect.txt&version=v1",
            "",
            true,
            false,
            vec![],
            (ACTION_DELETE, FOLDER.to_owned()),
        ),
        route(
            "upload create",
            "POST",
            "/api/uploads",
            r#"{"instance":"rw","key":"other/up.bin","size":3}"#,
            false,
            true,
            vec![],
            (ACTION_WRITE, other.clone()),
        ),
        route(
            "copy",
            "POST",
            "/api/copy",
            r#"{"instance":"rw","src":"folder/direct.txt","dst":"other/copy.txt"}"#,
            false,
            true,
            vec![(ACTION_READ, FOLDER.to_owned())],
            (ACTION_WRITE, other.clone()),
        ),
        route(
            "copy of a prefix",
            "POST",
            "/api/copy",
            r#"{"instance":"rw","src":"folder/nested/","dst":"copied/","isPrefix":true}"#,
            false,
            true,
            vec![(ACTION_READ, SUBFOLDER.to_owned())],
            (ACTION_WRITE, folder("copied")),
        ),
        route(
            "rename",
            "POST",
            "/api/rename",
            r#"{"instance":"rw","src":"folder/direct.txt","dst":"other/moved.txt"}"#,
            false,
            true,
            vec![(ACTION_READ, FOLDER.to_owned()), (ACTION_WRITE, other.clone())],
            (ACTION_DELETE, FOLDER.to_owned()),
        ),
        route(
            "rename of a prefix",
            "POST",
            "/api/rename",
            r#"{"instance":"rw","src":"folder/nested/","dst":"moved/","isPrefix":true}"#,
            false,
            true,
            vec![(ACTION_READ, SUBFOLDER.to_owned()), (ACTION_WRITE, folder("moved"))],
            (ACTION_DELETE, SUBFOLDER.to_owned()),
        ),
        route(
            "delete of a prefix",
            "POST",
            "/api/delete-prefix",
            r#"{"instance":"rw","prefix":"folder/nested/"}"#,
            false,
            true,
            vec![(ACTION_READ, SUBFOLDER.to_owned())],
            (ACTION_DELETE, SUBFOLDER.to_owned()),
        ),
        route(
            "delete of a version",
            "DELETE",
            "/api/versions?instance=rw&key=folder%2Fdirect.txt&version=v1",
            "",
            false,
            false,
            vec![],
            (ACTION_DELETE, FOLDER.to_owned()),
        ),
        route(
            "restore of a version",
            "POST",
            "/api/versions/restore",
            r#"{"instance":"rw","key":"folder/direct.txt","version":"v1"}"#,
            false,
            false,
            vec![(ACTION_READ, FOLDER.to_owned())],
            (ACTION_WRITE, FOLDER.to_owned()),
        ),
        route(
            "edit of the metadata",
            "PUT",
            "/api/metadata",
            r#"{"instance":"rw","key":"folder/direct.txt","etag":"abc"}"#,
            false,
            false,
            vec![],
            (ACTION_WRITE, FOLDER.to_owned()),
        ),
        route(
            "archive extraction",
            "POST",
            "/api/archive-extract",
            r#"{"instance":"rw","key":"folder/a.zip","target":"extracted/","entries":["x.txt"]}"#,
            false,
            true,
            vec![(ACTION_READ, FOLDER.to_owned()), (ACTION_READ, folder("extracted"))],
            (ACTION_WRITE, folder("extracted")),
        ),
        ChangeRoute {
            tags: true,
            ..route(
                "tags put",
                "PUT",
                "/api/tags",
                r#"{"instance":"rw","key":"folder/direct.txt","tags":[{"key":"a","value":"1"}]}"#,
                false,
                true,
                vec![],
                (ACTION_WRITE, FOLDER.to_owned()),
            )
        },
        ChangeRoute {
            tags: true,
            ..route(
                "tags bulk",
                "POST",
                "/api/tags/bulk",
                r#"{"instance":"rw","prefix":"folder/","add":[{"key":"a","value":"1"}]}"#,
                false,
                true,
                vec![(ACTION_READ, FOLDER.to_owned())],
                (ACTION_WRITE, FOLDER.to_owned()),
            )
        },
    ]
}

impl ChangeRoute {
    /// The body of the request: the methods `PUT` and `POST` always send one.
    fn body(&self) -> Option<&str> {
        (matches!(self.method, "PUT" | "POST") || !self.body.is_empty()).then_some(self.body)
    }

    /// The expected questions: the others, alone or in one batch, without usage; then the use alone with usage.
    fn expected(&self) -> Vec<Summary> {
        let batch = self.others.len() > 1;
        let mut out: Vec<Summary> = self
            .others
            .iter()
            .map(|(action, path)| summary(action, path, false, batch, true))
            .collect();
        out.push(summary(self.use_ask.0, &self.use_ask.1, true, false, false));
        out
    }

    /// Send the request in a new environment with an answer function.
    async fn send(&self, answer: impl Fn(&FakeQuestion) -> Value + Send + Sync + 'static) -> (Env, TestResponse) {
        let env = if self.tags { Env::with_tags() } else { Env::new() };
        env.fake.set_answer(answer);
        let response = env.send(self.method, self.target, self.body()).await;
        (env, response)
    }

    /// Check a refusal: 403 with the action, and no usage question after a refused other.
    fn check_refusal(&self, env: &Env, answer: &TestResponse, action: &str, no_usage: bool, case: &str) -> Vec<String> {
        let mut failures = Vec::new();
        let name = format!("{} ({case})", self.name);
        if answer.status != 403 {
            failures.push(format!("{name}: status {}: {}", answer.status, answer.text()));
            return failures;
        }
        if self.gateway {
            let want = format!("The action {action} is not allowed.");
            if !answer.text().contains(&want) {
                failures.push(format!("{name}: text {:?}, want {want:?}", answer.text()));
            }
        } else if error_member(answer, "code") != "forbidden" || error_member(answer, "action") != action {
            failures.push(format!("{name}: error {}, want the action {action}", answer.text()));
        }
        let questions = env.fake.questions();
        if no_usage && questions.iter().any(|question| question.usage) {
            failures.push(format!("{name}: a usage question after a refusal: {questions:?}"));
        }
        if questions.is_empty() {
            failures.push(format!("{name}: the PDP got no question"));
        }
        failures
    }

    async fn check(&self) -> Vec<String> {
        let mut failures = Vec::new();
        let name = self.name;

        let (env, answer) = self.send(usage_answer(true)).await;
        if self.strict && !(200..300).contains(&answer.status) {
            failures.push(format!("{name} (true): status {}: {}", answer.status, answer.text()));
        }
        if let Some(code) = access_error(&answer, self.gateway) {
            failures.push(format!("{name} (true): access error {code}: {}", answer.text()));
        }
        let questions = env.fake.questions();
        let got = summarize(&questions);
        if got != self.expected() {
            failures.push(format!("{name} (true): questions {got:?}, want {:?}", self.expected()));
        }
        let wrong = questions
            .iter()
            .any(|question| question.match_mode != "node" || question.subject != SUBJECT);
        if wrong {
            failures.push(format!("{name} (true): questions {questions:?}"));
        }
        let plain_use = questions
            .iter()
            .any(|question| question.action == self.use_ask.0 && question.path == self.use_ask.1 && !question.usage);
        if plain_use {
            failures.push(format!("{name} (true): a question without usage for the use"));
        }
        let requests = 1 + usize::from(!self.others.is_empty());
        if env.fake.requests() != requests {
            failures.push(format!(
                "{name} (true): {} requests, want {requests}",
                env.fake.requests()
            ));
        }

        for (index, (action, path)) in self.others.iter().enumerate() {
            let (refused_action, refused_path) = (action.to_string(), path.clone());
            let allow = usage_answer(true);
            let (env, answer) = self
                .send(move |question: &FakeQuestion| {
                    if question.action == refused_action && question.path == refused_path && !question.usage {
                        json!({"decision": false})
                    } else {
                        allow(question)
                    }
                })
                .await;
            failures.extend(self.check_refusal(&env, &answer, action, true, &format!("other {index} refused")));
        }

        let (env, answer) = self.send(answer_all(false)).await;
        let action = self.others.first().map_or(self.use_ask.0, |(action, _)| *action);
        failures.extend(self.check_refusal(&env, &answer, action, !self.others.is_empty(), "false"));

        let (_, answer) = self
            .send(|question: &FakeQuestion| {
                if question.usage {
                    budget_answer(question)
                } else {
                    json!({"decision": true})
                }
            })
            .await;
        if answer.status != 429 || answer.header("retry-after") != "7" {
            failures.push(format!(
                "{name} (budget): status {}, Retry-After {:?}: {}",
                answer.status,
                answer.header("retry-after"),
                answer.text()
            ));
        } else if !self.gateway
            && (error_member(&answer, "code") != "too_many_requests"
                || error_member(&answer, "action") != self.use_ask.0)
        {
            failures.push(format!("{name} (budget): error {}", answer.text()));
        }

        let env = Env::new();
        env.fake.set_status(500);
        let answer = env.send(self.method, self.target, self.body()).await;
        if answer.status != 503 {
            failures.push(format!("{name} (failure): status {}: {}", answer.status, answer.text()));
        } else if !self.gateway
            && (error_member(&answer, "code") != "pdp_unavailable" || error_member(&answer, "retryable") != true)
        {
            failures.push(format!("{name} (failure): error {}", answer.text()));
        }
        let questions = env.fake.questions();
        if questions.len() != self.others.len().max(1) {
            failures.push(format!("{name} (failure): questions {questions:?}"));
        }
        if !self.others.is_empty() && questions.iter().any(|question| question.usage) {
            failures.push(format!("{name} (failure): a usage question after a failure"));
        }
        failures
    }
}

#[tokio::test]
async fn each_change_route_asks_its_others_then_its_use_with_usage() {
    let mut failures = Vec::new();
    for route in change_routes() {
        failures.extend(route.check().await);
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A body that counts the reads of the handler and gives no byte.
struct CountingBody {
    reads: Arc<AtomicUsize>,
}

impl http_body::Body for CountingBody {
    type Data = Bytes;
    type Error = Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, Error>>> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        Poll::Ready(None)
    }
}

#[tokio::test]
async fn a_refused_gateway_put_reads_no_body_and_writes_nothing() {
    let env = Env::new();
    env.fake.set_answer(answer_all(false));
    let reads = Arc::new(AtomicUsize::new(0));
    let body = CountingBody { reads: reads.clone() }.boxed_unsync();
    let mut headers = HeaderMap::new();
    headers.insert(HOST, HeaderValue::from_static("example.com"));
    headers.insert("x-identity-token", HeaderValue::from_static(TOKEN));
    headers.insert(CONTENT_LENGTH, HeaderValue::from(5));
    let uri: Uri = "/s3?instance=rw&key=other%2Fnew.txt".parse().unwrap();
    let answer = match super::runtime::request_from_parts(Method::PUT, &uri, Version::HTTP_11, headers, body) {
        Ok((req, target)) => {
            let response = super::handle(env.app.clone(), req, target).await;
            collect(super::runtime::finalize(&Method::PUT, response).await).await
        }
        Err(response) => collect(*response).await,
    };
    assert_eq!(answer.status, 403, "{}", answer.text());
    assert_eq!(reads.load(Ordering::SeqCst), 0, "the handler read the body");
    assert!(!env.rw.contains("tenant/other/new.txt"));

    env.fake.set_answer(usage_answer(true));
    let answer = env
        .send("PUT", "/s3?instance=rw&key=other%2Fnew.txt", Some("hello"))
        .await;
    assert_eq!(answer.status, 204, "{}", answer.text());
    assert_eq!(
        env.rw.object("tenant/other/new.txt").map(|object| object.data),
        Some(Bytes::from_static(b"hello"))
    );
}

#[tokio::test]
async fn a_refused_gateway_delete_keeps_the_object() {
    let env = Env::new();
    env.fake.set_answer(answer_all(false));
    let target = "/s3?instance=rw&key=folder%2Fdirect.txt";
    let answer = env.send("DELETE", target, None).await;
    assert_eq!(answer.status, 403, "{}", answer.text());
    assert!(env.rw.contains("tenant/folder/direct.txt"));
    env.fake.set_answer(usage_answer(true));
    let answer = env.send("DELETE", target, None).await;
    assert_eq!(answer.status, 204, "{}", answer.text());
    assert!(!env.rw.contains("tenant/folder/direct.txt"));
}

#[tokio::test]
async fn a_write_that_the_configuration_refuses_or_an_unknown_instance_asks_nothing() {
    let env = Env::new();
    let answer = env.send("PUT", "/s3?instance=readonly&key=x.txt", Some("data")).await;
    assert_eq!(answer.status, 403, "{}", answer.text());
    assert_eq!(env.fake.requests(), 0);
    let answer = env.send("PUT", "/s3?instance=nope&key=x.txt", Some("")).await;
    assert_eq!(answer.status, 404, "{}", answer.text());
    let answer = env
        .send(
            "POST",
            "/api/uploads",
            Some(r#"{"instance":"nope","key":"x","size":1}"#),
        )
        .await;
    assert_eq!(answer.status, 404, "{}", answer.text());
    assert_eq!(env.fake.requests(), 0);
}

// --- The uploads -------------------------------------------------------------------------------------------------

#[tokio::test]
async fn an_upload_asks_one_usage_question_and_its_continuations_ask_none() {
    let env = Env::new();
    env.fake.set_answer(usage_answer(true));
    let answer = env
        .send(
            "POST",
            "/api/uploads",
            Some(r#"{"instance":"rw","key":"other/up.bin","size":3}"#),
        )
        .await;
    assert_eq!(answer.status, 201, "{}", answer.text());
    assert_eq!(
        summarize(&env.fake.questions()),
        vec![summary(ACTION_WRITE, &folder("other"), true, false, false)]
    );
    let token = answer.json()["resumeToken"].as_str().unwrap().to_owned();

    // A status, a resume and a chunk ask object.write on the key of the token, without usage.
    let resume = json!({"resumeToken": token}).to_string();
    for (name, method, target) in [
        ("status", "GET", "/api/uploads"),
        ("resume", "POST", "/api/uploads/resume"),
        ("chunk", "PUT", "/api/uploads"),
    ] {
        env.fake.reset();
        let answer = match method {
            "POST" => env.send(method, target, Some(&resume)).await,
            "PUT" => env.upload_request(method, target, Some("abc"), &token).await,
            _ => env.upload_request(method, target, None, &token).await,
        };
        assert_eq!(answer.status, 200, "{name}: {}", answer.text());
        assert_eq!(summarize(&env.fake.questions()), upload_continuation(), "{name}");
    }
    assert_eq!(
        env.rw.object("tenant/other/up.bin").map(|object| object.data),
        Some(Bytes::from_static(b"abc"))
    );

    // The cancel of a second upload.
    let second = env.create_upload("other/second.bin").await;
    env.fake.reset();
    let answer = env.upload_request("DELETE", "/api/uploads", None, &second).await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert_eq!(summarize(&env.fake.questions()), upload_continuation());
}

#[tokio::test]
async fn a_refused_continuation_of_an_upload_keeps_its_status() {
    let env = Env::new();
    let token = env.create_upload("other/up.bin").await;
    let resume = json!({"resumeToken": token}).to_string();
    type AnswerFn = fn(&FakeQuestion) -> Value;
    let refusal: AnswerFn = |_| json!({"decision": false});
    let cases: [(&str, AnswerFn, u16, &str); 2] = [
        ("refusal", refusal, 403, "forbidden"),
        ("budget", budget_answer, 429, "too_many_requests"),
    ];
    for (name, answer_fn, status, code) in cases {
        env.fake.reset();
        env.fake.set_answer(answer_fn);
        for method in ["GET", "PUT", "DELETE"] {
            let body = (method == "PUT").then_some("abc");
            let answer = env.upload_request(method, "/api/uploads", body, &token).await;
            assert_eq!(answer.status, status, "{name} {method}: {}", answer.text());
            assert_eq!(error_member(&answer, "code"), code, "{name} {method}");
            assert_eq!(error_member(&answer, "action"), ACTION_WRITE, "{name} {method}");
        }
        let answer = env.send("POST", "/api/uploads/resume", Some(&resume)).await;
        assert_eq!(answer.status, status, "{name} resume: {}", answer.text());
        assert!(
            env.fake.questions().iter().all(|question| !question.usage),
            "{name}: {:?}",
            env.fake.questions()
        );
    }

    // A failure of the PDP gives 503.
    env.fake.reset();
    env.fake.set_status(500);
    let answer = env.upload_request("PUT", "/api/uploads", Some("abc"), &token).await;
    assert_eq!(answer.status, 503, "{}", answer.text());

    // The refusals did not change the upload: a PDP that says true lets the chunk through.
    env.fake.reset();
    env.fake.set_answer(usage_answer(true));
    let answer = env.upload_request("PUT", "/api/uploads", Some("abc"), &token).await;
    assert_eq!(answer.status, 200, "{}", answer.text());
}

#[tokio::test]
async fn a_refused_chunk_writes_nothing() {
    let env = Env::new();
    let token = env.create_upload("other/up.bin").await;
    env.fake.reset();
    env.fake.set_answer(answer_all(false));
    let answer = env.upload_request("PUT", "/api/uploads", Some("abc"), &token).await;
    assert_eq!(answer.status, 403, "{}", answer.text());
    assert!(!env.rw.contains("tenant/other/up.bin"));
}

// --- The jobs ----------------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_job_of_a_route_is_read_and_controlled_with_its_operation_without_usage() {
    let env = Env::new();
    let id = env.start_copy_job().await;
    assert_eq!(
        summarize(&env.fake.questions()),
        vec![
            summary(ACTION_READ, SUBFOLDER, false, false, true),
            summary(ACTION_WRITE, &folder("copied"), true, false, false),
        ]
    );
    let continuation = vec![
        summary(ACTION_READ, SUBFOLDER, false, false, true),
        summary(ACTION_WRITE, &folder("copied"), false, false, false),
    ];
    env.fake.reset();
    let answer = env.send("GET", &format!("/api/jobs/{id}"), None).await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert_eq!(summarize(&env.fake.questions()), continuation);
    assert_eq!(env.fake.requests(), 2);

    env.fake.reset();
    let answer = env.send("POST", &format!("/api/jobs/{id}/cancel"), None).await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert_eq!(summarize(&env.fake.questions()), continuation);
}

#[tokio::test]
async fn the_job_of_an_archive_entry_integrity_reads_the_folder_of_the_archive() {
    let env = Env::new();
    let job = JobState {
        job_type: job_type::ARCHIVE_ENTRY_INTEGRITY.to_owned(),
        instance: "rw".to_owned(),
        archive_entry_integrity_request: Some(crate::archive::ArchiveEntryIntegrityRequest {
            key: "folder/a.zip".to_owned(),
            version: String::new(),
            entry: "x".to_owned(),
        }),
        ..JobState::default()
    };
    let operation = crate::access::mutation::job_operation(&env.app, &job).unwrap();
    assert!(operation.others.is_empty(), "{:?}", operation.others);
    assert_eq!(
        operation.use_ask,
        Ask {
            action: ACTION_READ.to_owned(),
            resource: FOLDER.to_owned(),
        }
    );
}

// --- The SQLite sessions -------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_sqlite_session_asks_object_read_on_its_key_at_each_request() {
    let env = Env::with_sqlite();
    let id = env.create_sqlite_session().await;
    let want = vec![summary(ACTION_READ, FOLDER, false, false, false)];
    assert_eq!(summarize(&env.fake.questions()), want);
    for (name, target) in [
        ("session", format!("/api/sqlite/sessions/{id}")),
        ("table", format!("/api/sqlite/sessions/{id}/table?table=items")),
    ] {
        env.fake.reset();
        let answer = env.send("GET", &target, None).await;
        assert_eq!(answer.status, 200, "{name}: {}", answer.text());
        assert_eq!(summarize(&env.fake.questions()), want, "{name}");
    }
}

#[tokio::test]
async fn a_sqlite_session_of_a_refused_key_answers_as_an_unknown_session() {
    let env = Env::with_sqlite();
    let id = env.create_sqlite_session().await;
    env.fake.reset();
    env.fake.set_answer(answer_all(false));
    for (method, target) in [
        ("GET", format!("/api/sqlite/sessions/{id}")),
        ("GET", format!("/api/sqlite/sessions/{id}/table?table=items")),
        ("DELETE", format!("/api/sqlite/sessions/{id}")),
    ] {
        let answer = env.send(method, &target, None).await;
        assert_eq!(answer.status, 404, "{method} {target}: {}", answer.text());
        assert_eq!(
            error_member(&answer, "code"),
            "sqlite_session_not_found",
            "{method} {target}"
        );
    }
    // The refused delete kept the session.
    env.fake.set_answer(answer_all(true));
    let session = format!("/api/sqlite/sessions/{id}");
    assert_eq!(env.send("GET", &session, None).await.status, 200);
    env.fake.set_status(500);
    assert_eq!(env.send("GET", &session, None).await.status, 503);
    env.fake.reset();
    let answer = env.send("GET", "/api/sqlite/sessions/nothing", None).await;
    assert_eq!(answer.status, 404, "{}", answer.text());
    assert!(env.fake.questions().is_empty());
}

#[tokio::test]
async fn a_sqlite_session_of_a_refused_key_opens_nothing() {
    let env = Env::with_sqlite();
    env.fake.set_answer(answer_all(false));
    let answer = env
        .send(
            "POST",
            "/api/sqlite/sessions",
            Some(r#"{"instance":"rw","key":"folder/fixture.sqlite"}"#),
        )
        .await;
    assert_eq!(answer.status, 403, "{}", answer.text());
    assert_eq!(error_member(&answer, "action"), ACTION_READ);
    assert_eq!(env.rw.state().get_count, 0);
    env.fake.reset();
    let answer = env
        .send("POST", "/api/sqlite/sessions", Some(r#"{"instance":"nope","key":"x"}"#))
        .await;
    assert_eq!(answer.status, 404, "{}", answer.text());
    assert!(env.fake.questions().is_empty());
}

// --- The extraction to another instance ----------------------------------------------------------------------------

#[tokio::test]
async fn an_extraction_to_another_instance_names_both_instances_before_the_decision() {
    let mut second = bucket("rw2", "rw2", None);
    second.root_prefix = "tenant/".to_owned();
    let env = Env::with_extra(vec![(second, memory(&[]))]);
    env.fake.set_answer(usage_answer(true));
    let answer = env
        .send(
            "POST",
            "/api/archive-extract",
            Some(
                r#"{"instance":"rw","targetInstance":"rw2","key":"folder/a.zip","target":"out/","entries":["x.txt"]}"#,
            ),
        )
        .await;
    assert_eq!(answer.status, 202, "{}", answer.text());
    let target_folder = format!("service:{SERVICE}/bucket:rw2/folder:out");
    assert_eq!(
        summarize(&env.fake.questions()),
        vec![
            summary(ACTION_READ, FOLDER, false, true, true),
            summary(ACTION_READ, &target_folder, false, true, true),
            summary(ACTION_WRITE, &target_folder, true, false, false),
        ]
    );
    env.fake.reset();
    let answer = env
        .send(
            "POST",
            "/api/archive-extract",
            Some(
                r#"{"instance":"rw","targetInstance":"nope","key":"folder/a.zip","target":"out/","entries":["x.txt"]}"#,
            ),
        )
        .await;
    assert_eq!(answer.status, 404, "{}", answer.text());
    assert!(env.fake.questions().is_empty());
}

// --- Each route that asks the PDP ----------------------------------------------------------------------------------

/// One request of a route: the method, the target, the body and the extra headers.
struct Surface {
    method: &'static str,
    target: String,
    body: Option<String>,
    headers: Vec<(&'static str, String)>,
}

fn surface(method: &'static str, target: &str) -> Surface {
    Surface {
        method,
        target: target.to_owned(),
        body: None,
        headers: Vec::new(),
    }
}

fn surface_with_body(method: &'static str, target: &str, body: &str) -> Surface {
    Surface {
        body: Some(body.to_owned()),
        ..surface(method, target)
    }
}

/// One request of a valid form for each method of each route that asks the PDP. The requests of a job, of an
/// upload and of a SQLite session use the state that the function makes with a PDP that says true.
async fn surfaces(env: &Env) -> Vec<(&'static str, Vec<Surface>)> {
    let job = env.start_copy_job().await;
    let upload = env.create_upload("other/surface.bin").await;
    let session = env.create_sqlite_session().await;
    let key = "instance=rw&key=folder%2Fdirect.txt";
    let object = |path: &str| vec![surface("GET", &format!("{path}?{key}"))];
    let upload_header = vec![("x-stowr-resume-token", upload.clone())];
    let chunk_header = vec![
        ("x-stowr-resume-token", upload.clone()),
        ("content-range", "bytes 0-2/3".to_owned()),
    ];
    let hash = "a".repeat(64);
    vec![
        (
            "/s3",
            vec![
                surface("GET", &format!("/s3?{key}")),
                surface("HEAD", &format!("/s3?{key}")),
                surface("GET", "/s3?instance=rw&prefix=folder%2F"),
                surface_with_body("PUT", "/s3?instance=rw&key=other%2Fnew.txt", "hello"),
                surface("DELETE", &format!("/s3?{key}")),
                surface("DELETE", &format!("/s3?{key}&version=v1")),
            ],
        ),
        (
            "/api/permissions/refresh",
            vec![surface_with_body("POST", "/api/permissions/refresh?instance=rw", "")],
        ),
        (
            "/api/list",
            vec![
                surface("GET", "/api/list?instance=rw&prefix=folder%2Fnested%2F"),
                surface("HEAD", "/api/list?instance=rw&prefix=folder%2Fnested%2F"),
            ],
        ),
        ("/api/instances", vec![surface("GET", "/api/instances")]),
        (
            "/api/stats",
            vec![surface("GET", "/api/stats?instance=rw&prefix=folder%2F")],
        ),
        (
            "/api/archive",
            vec![surface("GET", "/api/archive?instance=rw&prefix=folder%2F")],
        ),
        (
            "/api/copy",
            vec![
                surface_with_body(
                    "POST",
                    "/api/copy",
                    r#"{"instance":"rw","src":"folder/direct.txt","dst":"other/copy.txt"}"#,
                ),
                surface_with_body(
                    "POST",
                    "/api/copy",
                    r#"{"instance":"rw","src":"folder/nested/","dst":"copied2/","isPrefix":true}"#,
                ),
            ],
        ),
        (
            "/api/rename",
            vec![
                surface_with_body(
                    "POST",
                    "/api/rename",
                    r#"{"instance":"rw","src":"folder/direct.txt","dst":"other/moved.txt"}"#,
                ),
                surface_with_body(
                    "POST",
                    "/api/rename",
                    r#"{"instance":"rw","src":"folder/nested/","dst":"moved2/","isPrefix":true}"#,
                ),
            ],
        ),
        (
            "/api/delete-prefix",
            vec![surface_with_body(
                "POST",
                "/api/delete-prefix",
                r#"{"instance":"rw","prefix":"folder/nested/"}"#,
            )],
        ),
        (
            "/api/tags",
            vec![
                surface("GET", &format!("/api/tags?{key}")),
                surface_with_body(
                    "PUT",
                    "/api/tags",
                    r#"{"instance":"rw","key":"folder/direct.txt","tags":[{"key":"a","value":"1"}]}"#,
                ),
            ],
        ),
        (
            "/api/tags/bulk",
            vec![surface_with_body(
                "POST",
                "/api/tags/bulk",
                r#"{"instance":"rw","prefix":"folder/","add":[{"key":"a","value":"1"}]}"#,
            )],
        ),
        (
            "/api/metadata",
            vec![
                surface("GET", &format!("/api/metadata?{key}")),
                surface_with_body(
                    "PUT",
                    "/api/metadata",
                    r#"{"instance":"rw","key":"folder/direct.txt","etag":"abc"}"#,
                ),
            ],
        ),
        (
            "/api/lifecycle",
            vec![
                surface("GET", "/api/lifecycle?instance=rw"),
                surface_with_body(
                    "PUT",
                    "/api/lifecycle",
                    &format!(r#"{{"instance":"rw","hash":"{hash}","rules":[]}}"#),
                ),
            ],
        ),
        ("/api/encryption", vec![surface("GET", "/api/encryption?instance=rw")]),
        ("/api/usage", vec![surface("GET", "/api/usage?instance=rw")]),
        (
            "/api/object-lock",
            vec![
                surface("GET", &format!("/api/object-lock?{key}")),
                surface_with_body(
                    "PUT",
                    "/api/object-lock",
                    r#"{"instance":"rw","key":"folder/direct.txt","version":"v1","legalHold":true}"#,
                ),
            ],
        ),
        (
            "/api/multiparts",
            vec![surface("GET", "/api/multiparts?instance=rw&prefix=folder%2F")],
        ),
        (
            "/api/multiparts/abort",
            vec![
                surface_with_body(
                    "POST",
                    "/api/multiparts/abort",
                    r#"{"instance":"rw","uploads":[{"key":"folder/a.bin","uploadId":"u1"}]}"#,
                ),
                surface_with_body(
                    "POST",
                    "/api/multiparts/abort",
                    r#"{"instance":"rw","olderThanDays":7,"prefix":"folder/"}"#,
                ),
            ],
        ),
        (
            "/api/jobs/",
            vec![
                surface("GET", &format!("/api/jobs/{job}")),
                surface_with_body("POST", &format!("/api/jobs/{job}/pause"), ""),
                surface_with_body("POST", &format!("/api/jobs/{job}/resume"), ""),
                surface_with_body("POST", &format!("/api/jobs/{job}/cancel"), ""),
            ],
        ),
        (
            "/api/uploads/resume",
            vec![surface_with_body(
                "POST",
                "/api/uploads/resume",
                &json!({"resumeToken": upload}).to_string(),
            )],
        ),
        (
            "/api/uploads",
            vec![
                surface_with_body(
                    "POST",
                    "/api/uploads",
                    r#"{"instance":"rw","key":"other/new.bin","size":3}"#,
                ),
                Surface {
                    headers: upload_header.clone(),
                    ..surface("GET", "/api/uploads")
                },
                Surface {
                    headers: chunk_header,
                    ..surface_with_body("PUT", "/api/uploads", "abc")
                },
                Surface {
                    headers: upload_header,
                    ..surface("DELETE", "/api/uploads")
                },
            ],
        ),
        ("/api/spreadsheet", object("/api/spreadsheet")),
        ("/api/delimited", object("/api/delimited")),
        ("/api/document-count", object("/api/document-count")),
        ("/api/document/word", object("/api/document/word")),
        ("/api/parquet", object("/api/parquet")),
        (
            "/api/sqlite/sessions",
            vec![surface_with_body(
                "POST",
                "/api/sqlite/sessions",
                r#"{"instance":"rw","key":"folder/fixture.sqlite"}"#,
            )],
        ),
        (
            "/api/sqlite/sessions/",
            vec![
                surface("GET", &format!("/api/sqlite/sessions/{session}")),
                surface("GET", &format!("/api/sqlite/sessions/{session}/table?table=items")),
                surface("DELETE", &format!("/api/sqlite/sessions/{session}")),
            ],
        ),
        ("/api/json/raw", object("/api/json/raw")),
        ("/api/json/beautify", object("/api/json/beautify")),
        ("/api/json/summary", object("/api/json/summary")),
        ("/api/json/tree", object("/api/json/tree")),
        (
            "/api/search",
            vec![surface("GET", &format!("/api/search?{key}&q=direct"))],
        ),
        ("/api/media-info", object("/api/media-info")),
        ("/api/structured-preview", object("/api/structured-preview")),
        ("/api/archive-preview", object("/api/archive-preview")),
        (
            "/api/archive-entry",
            vec![
                surface("GET", &format!("/api/archive-entry?{key}&entry=a.txt")),
                surface("HEAD", &format!("/api/archive-entry?{key}&entry=a.txt")),
            ],
        ),
        (
            "/api/archive-entry/integrity",
            vec![surface_with_body(
                "POST",
                "/api/archive-entry/integrity",
                r#"{"instance":"rw","key":"folder/direct.txt","entry":"a.txt"}"#,
            )],
        ),
        (
            "/api/archive-extract",
            vec![surface_with_body(
                "POST",
                "/api/archive-extract",
                r#"{"instance":"rw","key":"folder/a.zip","target":"extracted/","entries":["x.txt"]}"#,
            )],
        ),
        (
            "/api/versions",
            vec![
                surface("GET", &format!("/api/versions?{key}")),
                surface("DELETE", &format!("/api/versions?{key}&version=v1")),
            ],
        ),
        (
            "/api/version-counts",
            vec![surface_with_body(
                "POST",
                "/api/version-counts",
                r#"{"instance":"rw","keys":["folder/direct.txt"]}"#,
            )],
        ),
        (
            "/api/versions/restore",
            vec![surface_with_body(
                "POST",
                "/api/versions/restore",
                r#"{"instance":"rw","key":"folder/direct.txt","version":"v1"}"#,
            )],
        ),
        (
            "/api/integrity",
            vec![surface_with_body(
                "POST",
                "/api/integrity",
                r#"{"instance":"rw","key":"folder/direct.txt"}"#,
            )],
        ),
        ("/api/inspect", object("/api/inspect")),
        ("/api/image-preview", object("/api/image-preview")),
        (
            OPTIONS_PATH,
            vec![surface("GET", &format!("{OPTIONS_PATH}?type=bucket"))],
        ),
        (
            "/open/",
            vec![
                surface("GET", &format!("/open/?{key}")),
                surface("HEAD", &format!("/open/?{key}")),
            ],
        ),
    ]
}

#[tokio::test]
async fn each_route_that_asks_the_pdp_refuses_with_a_pdp_that_says_false() {
    let env = Env::with_sqlite();
    let surfaces = surfaces(&env).await;
    let mut failures = Vec::new();

    // Each route that asks the PDP has a request here, and each request here has such a route.
    let asking: Vec<&str> = super::routes::table()
        .into_iter()
        .filter(|route| route.access == RouteAccess::HandlerAsks)
        .map(|route| route.pattern)
        .collect();
    for pattern in &asking {
        if !surfaces
            .iter()
            .any(|(known, requests)| known == pattern && !requests.is_empty())
        {
            failures.push(format!(
                "the route {pattern} asks the PDP and has no request in this test"
            ));
        }
    }
    for (pattern, _) in &surfaces {
        if !asking.contains(pattern) {
            failures.push(format!(
                "the test has requests for {pattern}, which is not a route that asks the PDP"
            ));
        }
    }

    env.fake.reset();
    env.fake.set_answer(answer_all(false));
    for (pattern, requests) in &surfaces {
        for request in requests {
            let headers: Vec<(&str, &str)> = request
                .headers
                .iter()
                .map(|(name, value)| (*name, value.as_str()))
                .collect();
            let answer = env
                .send_as(
                    Some(TOKEN),
                    request.method,
                    &request.target,
                    request.body.as_deref(),
                    &headers,
                )
                .await;
            let label = format!("{} {} (route {pattern})", request.method, request.target);
            if *pattern == OPTIONS_PATH {
                // The options route shows only what the PDP allows.
                if answer.text().contains("\"rw\"") {
                    failures.push(format!("{label}: the options show the bucket rw: {}", answer.text()));
                }
                continue;
            }
            if *pattern == "/api/instances" {
                // The list of the instances shows only what the PDP allows.
                if answer.text().contains("\"id\":\"rw\"") {
                    failures.push(format!("{label}: the instances show the bucket rw: {}", answer.text()));
                }
                continue;
            }
            if (200..300).contains(&answer.status) {
                failures.push(format!("{label}: status {} with a PDP that says false", answer.status));
            }
        }
    }
    if env.fake.questions().is_empty() {
        failures.push("no request reached the PDP".to_owned());
    }
    if env.rw.contains("tenant/other/new.txt") {
        failures.push("a refused write made an object".to_owned());
    }
    if !env.rw.contains("tenant/folder/direct.txt") {
        failures.push("a refused delete removed an object".to_owned());
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
