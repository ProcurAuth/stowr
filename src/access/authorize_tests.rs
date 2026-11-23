//! The tests of the check of the token, of the access rule of a route and of the questions of an operation.

use std::sync::Arc;

use http::header::{CONNECTION, RETRY_AFTER};
use http::{HeaderMap, HeaderValue, Method};
use serde_json::json;

use super::fake::{EVALUATION_PATH, EVALUATIONS_PATH, FakePdp};
use super::test_support::*;
use super::*;
use crate::common::config::{AccessMode, Config};
use crate::common::http::{gateway_error, read_limited};

fn token_headers(token: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.append("X-Identity-Token", HeaderValue::from_str(token).unwrap());
    headers
}

async fn body_of(response: Response) -> serde_json::Value {
    let (bytes, _) = read_limited(response.into_body(), 1 << 20).await.unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn api(error: &Error) -> &ApiError {
    error.as_api().expect("an API error")
}

// ---- the check of the token ----

#[tokio::test]
async fn a_request_without_a_valid_token_gets_401_and_asks_nothing() {
    let env = Env::new();
    env.fake.accept_token("good", SUBJECT, "");
    env.fake.refuse_token("signed-by-other", "signature");
    let mut two = token_headers("good");
    two.append("X-Identity-Token", HeaderValue::from_static("good"));
    let mut authorization = HeaderMap::new();
    authorization.insert("authorization", HeaderValue::from_static("Bearer good"));
    let mut cookie = HeaderMap::new();
    cookie.insert("cookie", HeaderValue::from_static("X-Identity-Token=good"));
    let cases = [
        ("no token", "/api/list", HeaderMap::new()),
        ("two copies of the header", "/api/list", two),
        ("bad signature", "/api/list", token_headers("signed-by-other")),
        ("garbage", "/api/list", token_headers("not-a-token")),
        ("token only in Authorization", "/api/list", authorization),
        ("token only in a cookie", "/api/list", cookie),
        ("a page without token", "/", HeaderMap::new()),
        ("a page of a bucket without token", "/-/test-auth/rw/", HeaderMap::new()),
        ("build without token", "/api/build", HeaderMap::new()),
        ("the gateway without token", "/s3", HeaderMap::new()),
        (
            "the options route without token",
            options::OPTIONS_PATH,
            HeaderMap::new(),
        ),
    ];
    for (name, path, headers) in cases {
        let response = env.layer.check_token(&Method::GET, path, &headers).expect_err(name);
        assert_eq!(response.status(), 401, "{name}");
        let body = body_of(*response).await;
        assert_eq!(body["error"]["code"], "unauthenticated", "{name}");
        assert_eq!(
            body["error"]["message"], "A valid identity token is required.",
            "{name}"
        );
    }
    assert_eq!(env.fake.requests(), 0);
}

#[tokio::test]
async fn a_valid_token_gives_the_subject_and_the_request_id() {
    let env = Env::new();
    env.fake.accept_token("good", SUBJECT, "boss");
    let mut headers = token_headers("good");
    headers.insert("x-request-id", HeaderValue::from_static("req-log-1"));
    let request = env
        .layer
        .check_token(&Method::GET, "/api/build", &headers)
        .unwrap()
        .unwrap();
    assert_eq!(request.subject, SUBJECT);
    assert_eq!(request.owner, "boss");
    assert_eq!(request.request_id, "req-log-1");
    assert_eq!(
        *request.log.lock().unwrap(),
        Some((SUBJECT.to_owned(), "req-log-1".to_owned()))
    );
}

#[test]
fn a_refusal_of_an_unsafe_method_closes_the_connection() {
    let env = Env::new();
    let response = env
        .layer
        .check_token(&Method::POST, "/api/copy", &HeaderMap::new())
        .err()
        .unwrap();
    assert_eq!(response.status(), 401);
    assert_eq!(response.headers().get(CONNECTION).unwrap(), "close");
    let response = env
        .layer
        .check_token(&Method::GET, "/api/list", &HeaderMap::new())
        .err()
        .unwrap();
    assert!(response.headers().get(CONNECTION).is_none());
}

#[test]
fn the_exempt_paths_need_no_token() {
    let env = Env::new();
    for headers in [HeaderMap::new(), token_headers("not-a-token")] {
        for path in ["/healthz", actions::ACTIONS_PATH] {
            assert!(
                env.layer.check_token(&Method::GET, path, &headers).unwrap().is_none(),
                "{path}"
            );
            assert!(
                env.layer.check_token(&Method::HEAD, path, &headers).unwrap().is_none(),
                "{path}"
            );
        }
    }
    for path in [
        "/",
        "/healthz/",
        "//healthz",
        "/healthz2",
        "/.well-known/procurauth/actions/",
        "/api/build",
        "/.well-known/access-actions",
    ] {
        assert!(!is_exempt_path(path), "{path}");
        assert!(
            env.layer.check_token(&Method::GET, path, &HeaderMap::new()).is_err(),
            "{path}"
        );
    }
    assert_eq!(env.fake.requests(), 0);
}

#[test]
fn the_open_mode_checks_no_token() {
    let layer = AccessLayer::new(&Config::default()).unwrap();
    assert!(!layer.enforced());
    for path in ["/api/list", "/", "/s3"] {
        assert!(
            layer
                .check_token(&Method::GET, path, &HeaderMap::new())
                .unwrap()
                .is_none()
        );
    }
    assert!(layer.document.json().is_empty());
}

#[test]
fn the_request_id_of_the_client_stays_only_when_it_is_valid() {
    for value in ["a", "req-1", "A.b_c:d-9", &"x".repeat(128)] {
        let mut headers = HeaderMap::new();
        headers.insert("x-request-id", HeaderValue::from_str(value).unwrap());
        assert_eq!(request_id_from(&headers), value);
    }
    let long = "x".repeat(129);
    for value in ["", "has space", long.as_str(), "semi;colon", "slash/x", "é"] {
        let mut headers = HeaderMap::new();
        if !value.is_empty() {
            headers.insert("x-request-id", HeaderValue::from_bytes(value.as_bytes()).unwrap());
        }
        let got = request_id_from(&headers);
        assert_ne!(got, value);
        assert_eq!(got.len(), 32, "{value:?}");
        assert!(
            got.bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        );
    }
}

#[test]
fn the_routes_of_the_access_policy_have_their_kind() {
    let routes = routes();
    assert_eq!(routes.len(), 2);
    assert_eq!(routes[0].pattern, actions::ACTIONS_PATH);
    assert_eq!(routes[0].access, RouteAccess::Exempt);
    assert_eq!(routes[1].pattern, options::OPTIONS_PATH);
    assert_eq!(routes[1].access, RouteAccess::HandlerAsks);
    for route in &routes {
        assert_eq!(is_exempt_path(route.pattern), route.access == RouteAccess::Exempt);
    }
}

#[test]
fn the_log_forms_keep_the_ids_out_in_mode_anonymous() {
    assert_eq!(
        logged_request_path(LogMode::Anonymous, "/api/jobs/job_1"),
        "/api/jobs/<id>"
    );
    assert_eq!(
        logged_request_path(LogMode::Anonymous, "/api/uploads/u"),
        "/api/uploads/<id>"
    );
    assert_eq!(
        logged_request_path(LogMode::Anonymous, "/api/sqlite/sessions/s/table"),
        "/api/sqlite/sessions/<id>"
    );
    assert_eq!(logged_request_path(LogMode::Anonymous, "/-/a/b/secret/"), "/-/<path>");
    assert_eq!(logged_request_path(LogMode::Anonymous, "/api/list"), "/api/list");
    assert_eq!(
        logged_request_path(LogMode::Detailed, "/-/a/b/secret/"),
        "/-/a/b/secret/"
    );
    assert_eq!(log_token(""), "-");
    assert_eq!(log_token("req-1:a.b_c"), "req-1:a.b_c");
    assert_eq!(log_token("a b"), "\"a b\"");
    assert_eq!(log_token(&"x".repeat(129)), format!("\"{}\"", "x".repeat(129)));
    assert_eq!(quote("a\"b\\c\nd\u{1}"), "\"a\\\"b\\\\c\\nd\\x01\"");
}

// ---- the access rule of a route ----

#[tokio::test]
async fn a_route_without_a_rule_is_denied_and_asks_nothing() {
    let env = Env::new();
    let error = env
        .layer
        .guard_route(
            &env.ctx("rid"),
            RouteAccess::Denied,
            &Method::GET,
            "/api/unruled",
            &HeaderMap::new(),
        )
        .await
        .unwrap_err();
    let api = api(&error);
    assert_eq!(
        (api.status, api.code.as_str(), api.action.as_deref()),
        (403, "forbidden", Some("unknown"))
    );
    for kind in [RouteAccess::Exempt, RouteAccess::HandlerAsks] {
        env.layer
            .guard_route(&env.ctx("rid"), kind, &Method::GET, "/api/list", &HeaderMap::new())
            .await
            .unwrap();
    }
    assert_eq!(env.fake.requests(), 0);
}

#[tokio::test]
async fn a_static_route_asks_the_action_access_on_the_service() {
    let env = Env::new();
    for path in ["/", "/index.html", "/-/test-auth/rw/", "/api/build", "/api/jobs"] {
        env.fake.reset();
        env.layer
            .guard_route(
                &env.ctx("rid-s"),
                RouteAccess::TokenOnly,
                &Method::GET,
                path,
                &HeaderMap::new(),
            )
            .await
            .unwrap();
        let questions = env.fake.questions();
        assert_eq!(questions.len(), 1, "{path}");
        let question = &questions[0];
        assert_eq!(question.action, "access");
        assert_eq!(question.path, "service:svc-1");
        assert_eq!(question.resource_type, "service");
        assert_eq!(question.resource_id, SERVICE);
        assert!(question.ancestors.is_empty());
        assert_eq!(question.match_mode, "node");
        assert!(!question.usage && !question.permission_only && !question.batch);
        assert_eq!(question.request_id, "rid-s");
    }
    // The body of the question has no properties: the service has no ancestors.
    let raw = env.fake.raw_requests();
    assert_eq!(raw[0].path, EVALUATION_PATH);
    assert_eq!(raw[0].body["resource"], json!({"type": "service", "id": SERVICE}));
    assert!(raw[0].body.get("context").is_none());

    env.fake.set_answer(answer_all(false));
    let error = env.layer.authorize_service(&env.ctx("rid")).await.unwrap_err();
    assert_eq!(api(&error).code, "forbidden");
    assert_eq!(api(&error).action.as_deref(), Some("access"));

    env.fake.set_status(500);
    let error = env.layer.authorize_service(&env.ctx("rid")).await.unwrap_err();
    assert_eq!(api(&error).code, "pdp_unavailable");
    assert_eq!(api(&error).status, 503);

    // The action access never needs an approval: a reason of an approval is an answer that is not valid.
    env.fake.reset();
    env.fake
        .set_answer(|_| json!({"decision": false, "context": {"reason": "approval_required"}}));
    let error = env.layer.authorize_service(&env.ctx("rid")).await.unwrap_err();
    assert_eq!(
        (api(&error).status, api(&error).code.as_str()),
        (503, "pdp_unavailable")
    );
    assert_eq!(api(&error).action.as_deref(), Some("access"));

    // Without a token in the context: 401 and no question.
    env.fake.reset();
    let error = env.layer.authorize_service(&OpCtx::default()).await.unwrap_err();
    assert_eq!(api(&error).status, 401);
    assert_eq!(env.fake.requests(), 0);
}

#[tokio::test]
async fn the_open_mode_asks_nothing_for_a_route() {
    let layer = AccessLayer::new(&Config::default()).unwrap();
    layer
        .guard_route(
            &OpCtx::default(),
            RouteAccess::TokenOnly,
            &Method::GET,
            "/",
            &HeaderMap::new(),
        )
        .await
        .unwrap();
    layer.authorize_service(&OpCtx::default()).await.unwrap();
}

// ---- authorize ----

#[tokio::test]
async fn authorize_without_an_identity_gives_401() {
    let env = Env::new();
    let error = env
        .layer
        .authorize(
            &OpCtx::default(),
            Operation {
                use_ask: env.ask(ACTION_READ, "a.txt"),
                ..Operation::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(
        (api(&error).status, api(&error).code.as_str()),
        (401, "unauthenticated")
    );
    assert_eq!(env.fake.requests(), 0);
}

#[tokio::test]
async fn authorize_in_mode_open_asks_nothing() {
    let env = Env::new();
    let layer = AccessLayer::new(&Config::default()).unwrap();
    let grant = layer
        .authorize(
            &OpCtx::default(),
            Operation {
                use_ask: env.ask(ACTION_WRITE, "a.txt"),
                ..Operation::default()
            },
        )
        .await
        .unwrap();
    assert!(grant.limits.is_empty());
}

#[tokio::test]
async fn authorize_asks_the_others_before_the_use() {
    let env = Env::new();
    env.fake.set_answer(usage_answer(true));
    let (folder_a, folder_b) = (env.ask(ACTION_READ, "a/x"), env.ask(ACTION_READ, "b/y"));

    // A use without budget: the others in one batch with permission_only, then the use alone.
    env.layer
        .authorize(
            &env.ctx("rid-1"),
            Operation {
                others: vec![folder_a.clone(), folder_b.clone()],
                use_ask: env.ask(ACTION_READ, "c/z"),
                continuation: false,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        summarize(&env.fake.questions()),
        vec![
            summary(ACTION_READ, &folder("a"), false, true, true),
            summary(ACTION_READ, &folder("b"), false, true, true),
            summary(ACTION_READ, &folder("c"), false, false, false),
        ]
    );
    assert_eq!(env.fake.requests(), 2);
    for question in env.fake.questions() {
        assert_eq!(question.request_id, "rid-1");
        assert_eq!(question.subject, SUBJECT);
        assert_eq!(question.match_mode, "node");
    }
    let raw = env.fake.raw_requests();
    assert_eq!(raw[0].path, EVALUATIONS_PATH);
    assert_eq!(raw[0].body["context"], json!({"permission_only": true}));
    assert_eq!(raw[0].body["subject"], json!({"type": "user", "id": SUBJECT}));
    assert!(raw[1].body.get("context").is_none());

    // A use with a budget: the others in one batch, then the use alone with usage.
    env.fake.reset();
    env.layer
        .authorize(
            &env.ctx("rid-2"),
            Operation {
                others: vec![folder_a.clone(), folder_b],
                use_ask: env.ask(ACTION_WRITE, "c/z"),
                continuation: false,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        summarize(&env.fake.questions()),
        vec![
            summary(ACTION_READ, &folder("a"), false, true, true),
            summary(ACTION_READ, &folder("b"), false, true, true),
            summary(ACTION_WRITE, &folder("c"), true, false, false),
        ]
    );
    assert_eq!(env.fake.requests(), 2);

    // One other: one Access Evaluation with permission_only, not a batch.
    env.fake.reset();
    env.layer
        .authorize(
            &env.ctx("rid-3"),
            Operation {
                others: vec![folder_a],
                use_ask: env.ask(ACTION_DELETE, "c/z"),
                continuation: false,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        summarize(&env.fake.questions()),
        vec![
            summary(ACTION_READ, &folder("a"), false, false, true),
            summary(ACTION_DELETE, &folder("c"), true, false, false),
        ]
    );
    let raw = env.fake.raw_requests();
    assert_eq!(raw[0].path, EVALUATION_PATH);
    assert_eq!(raw[0].body["context"], json!({"permission_only": true}));
    assert_eq!(raw[1].body["context"], json!({"usage": {"units": 1}}));
}

#[tokio::test]
async fn a_read_never_asks_usage() {
    let env = Env::new();
    env.layer.authorize_read(&env.ctx("rid"), &env.rw, "a/x").await.unwrap();
    let questions = env.fake.questions();
    assert_eq!(questions.len(), 1);
    assert!(!questions[0].usage && !questions[0].batch && !questions[0].permission_only);
}

#[tokio::test]
async fn a_refused_other_stops_before_the_use() {
    let env = Env::new();
    env.fake
        .set_answer(|q| json!({"decision": q.action != ACTION_READ, "context": {"usage": {"units": 1}}}));
    let error = env
        .layer
        .authorize(
            &env.ctx("rid"),
            Operation {
                others: vec![env.ask(ACTION_READ, "a/x")],
                use_ask: env.ask(ACTION_WRITE, "a/x"),
                continuation: false,
            },
        )
        .await
        .unwrap_err();
    let api = api(&error);
    assert_eq!(api.status, 403);
    assert_eq!(api.code, "forbidden");
    assert_eq!(api.action.as_deref(), Some(ACTION_READ));
    assert_eq!(api.message, "The action object.read is not allowed.");
    let questions = env.fake.questions();
    assert_eq!(questions.len(), 1);
    assert!(!questions[0].usage && questions[0].permission_only);
}

#[tokio::test]
async fn a_failed_other_stops_before_the_use() {
    let env = Env::new();
    env.fake.set_status(500);
    let error = env
        .layer
        .authorize(
            &env.ctx("rid"),
            Operation {
                others: vec![env.ask(ACTION_READ, "a/x")],
                use_ask: env.ask(ACTION_WRITE, "a/x"),
                continuation: false,
            },
        )
        .await
        .unwrap_err();
    let api = api(&error);
    assert_eq!((api.status, api.code.as_str()), (503, "pdp_unavailable"));
    assert_eq!(api.action.as_deref(), Some(ACTION_READ));
    assert_eq!(env.fake.questions().len(), 1);
}

#[tokio::test]
async fn authorize_removes_the_repeated_others_and_the_other_equal_to_the_use() {
    let env = Env::new();
    env.fake.set_answer(usage_answer(true));
    let read_a = env.ask(ACTION_READ, "a/x");
    // The nodes of "a/x" and "a/y" are one node: folder:a.
    let same_node = env.ask(ACTION_READ, "a/y");

    // A use with a budget: the other that equals the use never comes before the usage question.
    env.layer
        .authorize(
            &env.ctx("rid"),
            Operation {
                others: vec![
                    env.ask(ACTION_WRITE, "a/q"),
                    read_a.clone(),
                    same_node.clone(),
                    read_a.clone(),
                ],
                use_ask: env.ask(ACTION_WRITE, "a/x"),
                continuation: false,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        summarize(&env.fake.questions()),
        vec![
            summary(ACTION_READ, &folder("a"), false, false, true),
            summary(ACTION_WRITE, &folder("a"), true, false, false),
        ]
    );

    // A use without budget: the question appears one time.
    env.fake.reset();
    env.layer
        .authorize(
            &env.ctx("rid"),
            Operation {
                others: vec![read_a.clone(), same_node],
                use_ask: read_a,
                continuation: false,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        summarize(&env.fake.questions()),
        vec![summary(ACTION_READ, &folder("a"), false, false, false)]
    );
}

#[tokio::test]
async fn an_action_with_a_budget_asks_one_usage_question() {
    let env = Env::new();
    env.fake.set_answer(usage_answer(true));
    for action in [ACTION_WRITE, ACTION_DELETE, ACTION_LOCK, ACTION_BUCKET_ADMIN] {
        env.fake.reset();
        env.layer
            .authorize(
                &env.ctx("rid"),
                Operation {
                    use_ask: env.layer.bucket_ask(action, &env.rw),
                    ..Operation::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(
            summarize(&env.fake.questions()),
            vec![summary(action, BUCKET, true, false, false)]
        );
        let raw = env.fake.raw_requests();
        assert_eq!(raw.len(), 1);
        assert_eq!(raw[0].path, EVALUATION_PATH);
        assert_eq!(raw[0].body["context"], json!({"usage": {"units": 1}}));
    }
}

#[tokio::test]
async fn a_used_budget_gives_429_with_retry_after() {
    let env = Env::new();
    env.fake
        .set_answer(|_| json!({"decision": false, "context": {"reason": "budget_exceeded", "retry_after": 7}}));
    let error = env
        .layer
        .authorize(
            &env.ctx("rid"),
            Operation {
                use_ask: env.ask(ACTION_WRITE, "a/x"),
                ..Operation::default()
            },
        )
        .await
        .unwrap_err();
    let api = api(&error);
    assert_eq!(
        (api.status, api.code.as_str(), api.retry_after),
        (429, "too_many_requests", 7)
    );
    assert_eq!(api.action.as_deref(), Some(ACTION_WRITE));

    let response = crate::common::http::api_error(&error);
    assert_eq!(response.status(), 429);
    assert_eq!(response.headers().get(RETRY_AFTER).unwrap(), "7");
    let body = body_of(response).await;
    assert_eq!(body["error"]["code"], "too_many_requests");
    assert_eq!(body["error"]["action"], ACTION_WRITE);
    assert_eq!(body["error"]["retryable"], true);

    let response = gateway_error(&error);
    assert_eq!(response.status(), 429);
    assert_eq!(response.headers().get(RETRY_AFTER).unwrap(), "7");
    let (bytes, _) = read_limited(response.into_body(), 4096).await.unwrap();
    assert!(!bytes.starts_with(b"{"));
}

#[tokio::test]
async fn the_error_writers_keep_their_shapes() {
    let response = crate::common::http::api_error(&Error::api(400, "invalid_key", "bad"));
    assert!(response.headers().get(RETRY_AFTER).is_none());
    let body = body_of(response).await;
    assert!(body["error"].get("action").is_none() && body["error"].get("retryable").is_none());
    let response = crate::common::http::api_error(&pdp_unavailable(ACTION_READ));
    assert_eq!(response.status(), 503);
    let body = body_of(response).await;
    assert_eq!(body["error"]["code"], "pdp_unavailable");
    assert_eq!(body["error"]["retryable"], true);
    assert_eq!(
        body["error"]["message"],
        "The decision for the action object.read is not available."
    );
}

#[tokio::test]
async fn the_ceilings_of_an_answer() {
    let env = Env::new();
    let limits = |values: serde_json::Value| move |_: &super::fake::FakeQuestion| json!({"decision": true, "context": {"limits": values}});
    let read = |relative: &str| Operation {
        use_ask: env.ask(ACTION_READ, relative),
        ..Operation::default()
    };

    // A listed ceiling stays in the grant and in the request.
    env.fake.set_answer(limits(json!({"max_object_size": 10})));
    let ctx = env.ctx("rid");
    let grant = env.layer.authorize(&ctx, read("a/x")).await.unwrap();
    assert_eq!(grant.limits.len(), 1);
    assert_eq!(grant.limits[ACTION_READ]["max_object_size"], 10);
    assert_eq!(
        ctx.access
            .as_ref()
            .unwrap()
            .ceilings
            .get(ACTION_READ, "max_object_size"),
        Some(10)
    );

    // The lower value stays.
    env.fake.set_answer(|q| {
        let size = if q.path.ends_with("folder:b") { 5 } else { 50 };
        json!({"decision": true, "context": {"limits": {"max_object_size": size}}})
    });
    let ctx = env.ctx("rid");
    let grant = env
        .layer
        .authorize(
            &ctx,
            Operation {
                others: vec![env.ask(ACTION_READ, "b/y")],
                use_ask: env.ask(ACTION_READ, "a/x"),
                continuation: false,
            },
        )
        .await
        .unwrap();
    assert_eq!(grant.limits[ACTION_READ]["max_object_size"], 5);
    assert_eq!(
        ctx.access
            .as_ref()
            .unwrap()
            .ceilings
            .get(ACTION_READ, "max_object_size"),
        Some(5)
    );

    // A ceiling that the action does not list gives 403.
    env.fake.set_answer(limits(json!({"max_rows": 5})));
    let error = env.layer.authorize(&env.ctx("rid-c"), read("a/x")).await.unwrap_err();
    assert_eq!((api(&error).status, api(&error).code.as_str()), (403, "forbidden"));
    assert_eq!(api(&error).action.as_deref(), Some(ACTION_READ));

    // A ceiling of another action gives 403.
    env.fake.set_answer(|q| {
        if q.usage {
            json!({"decision": true, "context": {"usage": {"units": 1}, "limits": {"max_object_size": 5}}})
        } else {
            json!({"decision": true, "context": {"limits": {"max_object_size": 5}}})
        }
    });
    let error = env
        .layer
        .authorize(
            &env.ctx("rid"),
            Operation {
                use_ask: env.ask(ACTION_DELETE, "a/x"),
                ..Operation::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(api(&error).status, 403);

    // A budget as a limit gives 503.
    env.fake.set_answer(limits(json!({"writes": 1})));
    let error = env.layer.authorize(&env.ctx("rid-b"), read("a/x")).await.unwrap_err();
    assert_eq!(
        (api(&error).status, api(&error).code.as_str()),
        (503, "pdp_unavailable")
    );
    assert_eq!(api(&error).action.as_deref(), Some(ACTION_READ));

    // A ceiling in the answer to a usage question.
    env.fake.set_answer(
        |_| json!({"decision": true, "context": {"usage": {"units": 1}, "limits": {"max_object_size": 99}}}),
    );
    let grant = env
        .layer
        .authorize(
            &env.ctx("rid"),
            Operation {
                use_ask: env.ask(ACTION_WRITE, "a/x"),
                ..Operation::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(grant.limits[ACTION_WRITE]["max_object_size"], 99);
}

#[tokio::test]
async fn an_unpublished_action_gives_403_without_a_question() {
    let env = Env::new();
    let error = env
        .layer
        .authorize(
            &env.ctx("rid"),
            Operation {
                use_ask: Ask {
                    action: "object.bogus".to_owned(),
                    resource: BUCKET.to_owned(),
                },
                ..Operation::default()
            },
        )
        .await
        .unwrap_err();
    assert_eq!(
        (api(&error).status, api(&error).action.as_deref()),
        (403, Some("object.bogus"))
    );

    // A write action in a service with force_read_only.
    let mut config = authzen_config(SERVICE, vec![bucket("rw", "rw", None)], Vec::new());
    config.runtime.access_mode = AccessMode::ForceReadOnly;
    let fake = Arc::new(FakePdp::new());
    let layer = AccessLayer::with_guard(&config, fake.clone()).unwrap();
    let error = layer
        .authorize(&env.ctx("rid"), layer.use_operation(ACTION_WRITE, &env.rw, "a/x"))
        .await
        .unwrap_err();
    assert_eq!(
        (api(&error).status, api(&error).action.as_deref()),
        (403, Some(ACTION_WRITE))
    );
    // An unpublished other refuses the operation too.
    let error = layer
        .authorize(
            &env.ctx("rid"),
            Operation {
                others: vec![env.ask(ACTION_DELETE, "a/x")],
                use_ask: env.ask(ACTION_READ, "a/x"),
                continuation: false,
            },
        )
        .await
        .unwrap_err();
    assert_eq!(
        (api(&error).status, api(&error).action.as_deref()),
        (403, Some(ACTION_DELETE))
    );
    assert_eq!(fake.requests(), 0);
    assert_eq!(env.fake.requests(), 0);
}

#[test]
fn the_permissions_of_a_key_and_of_a_bucket() {
    let env = Env::new();
    let ask = env.layer.object_ask(ACTION_READ, &env.rw, "folder/nested/deep.txt");
    assert_eq!(ask.action, ACTION_READ);
    assert_eq!(ask.resource, SUBFOLDER);
    let ask = env.layer.bucket_ask(ACTION_BUCKET_ADMIN, &env.rw);
    assert_eq!(
        (ask.action.as_str(), ask.resource.as_str()),
        (ACTION_BUCKET_ADMIN, BUCKET)
    );
    assert_eq!(env.layer.service_ask().resource, "service:svc-1");
}

#[tokio::test]
async fn read_many_asks_each_key_and_the_first_is_the_use() {
    let env = Env::new();
    let keys = vec![
        "folder/direct.txt".to_owned(),
        "folder/nested/deep.txt".to_owned(),
        "folder/direct.txt".to_owned(),
    ];
    env.layer
        .authorize_read_many(&env.ctx("rid"), &env.rw, &keys)
        .await
        .unwrap();
    assert_eq!(
        summarize(&env.fake.questions()),
        vec![
            summary(ACTION_READ, SUBFOLDER, false, false, true),
            summary(ACTION_READ, FOLDER, false, false, false),
        ]
    );
    env.fake.reset();
    env.layer
        .authorize_read_many(&env.ctx("rid"), &env.rw, &[])
        .await
        .unwrap();
    assert_eq!(
        summarize(&env.fake.questions()),
        vec![summary(ACTION_READ, BUCKET, false, false, false)]
    );
    env.fake.reset();
    env.layer.authorize_read_bucket(&env.ctx("rid"), &env.rw).await.unwrap();
    assert_eq!(
        summarize(&env.fake.questions()),
        vec![summary(ACTION_READ, BUCKET, false, false, false)]
    );
}

// ---- the reasons of an approval ----

#[tokio::test]
async fn a_reason_of_an_approval_gives_the_fixed_403_and_runs_nothing() {
    let env = Env::new();
    for reason in guard::APPROVAL_REASONS {
        env.fake.reset();
        env.fake.set_answer(move |q| {
            if q.permission_only {
                json!({"decision": true})
            } else {
                json!({"decision": false, "context": {"reason": reason}})
            }
        });
        // A use without budget, a use with budget and a continuation.
        for operation in [
            env.layer.use_operation(ACTION_READ, &env.rw, "a/x"),
            env.layer.copy_operation(&env.rw, "a/x", "b/y"),
            Operation {
                continuation: true,
                ..env.layer.copy_operation(&env.rw, "a/x", "b/y")
            },
        ] {
            let error = env.layer.authorize(&env.ctx("rid"), operation).await.unwrap_err();
            assert!(error.has_code(CODE_APPROVAL_CANNOT_WAIT), "{reason}");
            let response = crate::common::http::api_error(&error);
            assert_eq!(response.status(), 403);
            let (bytes, _) = read_limited(response.into_body(), 4096).await.unwrap();
            assert_eq!(&bytes[..], b"{\"error\":\"approval_cannot_wait\"}\n");
        }
        // No question has an effect or an approval: the questions are the plain questions of the operation.
        for question in env.fake.questions() {
            assert!(question.permission_only || question.match_mode == "node");
        }
    }
}

#[tokio::test]
async fn a_reason_of_an_approval_for_an_other_permission_is_not_a_valid_answer() {
    let env = Env::new();
    env.fake
        .set_answer(|q| json!({"decision": !q.permission_only, "context": {"reason": "approval_required"}}));
    let error = env
        .layer
        .authorize(&env.ctx("rid"), env.layer.copy_operation(&env.rw, "a/x", "b/y"))
        .await
        .unwrap_err();
    let api = api(&error);
    assert_eq!((api.status, api.code.as_str()), (503, "pdp_unavailable"));
    assert_eq!(api.action.as_deref(), Some(ACTION_READ));
    // The use is never asked.
    assert_eq!(env.fake.questions().len(), 1);
}

#[tokio::test]
async fn a_reason_of_an_approval_is_never_kept() {
    let env = Env::new();
    env.fake
        .configure(|settings| settings.cache_ttl = std::time::Duration::from_secs(30));
    env.fake
        .set_answer(|_| json!({"decision": false, "context": {"reason": "approval_pending"}}));
    for _ in 0..2 {
        let error = env
            .layer
            .authorize_read(&env.ctx("rid"), &env.rw, "a/x")
            .await
            .unwrap_err();
        assert!(error.has_code(CODE_APPROVAL_CANNOT_WAIT));
        let error = env
            .layer
            .authorize(&env.ctx("rid"), env.layer.use_operation(ACTION_WRITE, &env.rw, "a/x"))
            .await
            .unwrap_err();
        assert!(error.has_code(CODE_APPROVAL_CANNOT_WAIT));
    }
    assert_eq!(env.fake.requests(), 4);
    assert_eq!(env.fake.kept(), 0);
}

#[tokio::test]
async fn the_answer_of_an_other_permission_is_kept_apart_from_the_answer_of_a_use() {
    let env = Env::new();
    env.fake
        .configure(|settings| settings.cache_ttl = std::time::Duration::from_secs(30));
    // A read of folder:a as an other, then the same read as the use: two questions, one for each table key.
    env.layer
        .authorize(
            &env.ctx("rid"),
            Operation {
                others: vec![env.ask(ACTION_READ, "a/x")],
                use_ask: env.ask(ACTION_READ, "b/y"),
                continuation: false,
            },
        )
        .await
        .unwrap();
    env.layer.authorize_read(&env.ctx("rid"), &env.rw, "a/x").await.unwrap();
    assert_eq!(env.fake.requests(), 3);
    // The same two operations again: each answer comes from the cache.
    env.layer
        .authorize(
            &env.ctx("rid"),
            Operation {
                others: vec![env.ask(ACTION_READ, "a/x")],
                use_ask: env.ask(ACTION_READ, "b/y"),
                continuation: false,
            },
        )
        .await
        .unwrap();
    env.layer.authorize_read(&env.ctx("rid"), &env.rw, "a/x").await.unwrap();
    assert_eq!(env.fake.requests(), 3);
}

#[tokio::test]
async fn a_true_answer_to_a_usage_question_without_units_is_a_refusal() {
    struct NoUnits;
    impl AccessGuard for NoUnits {
        fn authenticate(&self, _headers: &HeaderMap) -> std::result::Result<Option<Identity>, String> {
            Ok(None)
        }
        fn operation<'a>(
            &'a self,
            _request_id: &'a str,
            _who: &'a Identity,
            others: &'a [Ask],
            _use_ask: &'a Ask,
            _usage: bool,
        ) -> crate::common::BoxFuture<'a, OperationAnswers> {
            let answers = OperationAnswers {
                others: vec![Answer::allow(); others.len()],
                use_answer: Some(Answer::allow()),
            };
            Box::pin(async move { answers })
        }
        fn decide<'a>(
            &'a self,
            _request_id: &'a str,
            _who: &'a Identity,
            asks: &'a [Ask],
        ) -> crate::common::BoxFuture<'a, Vec<Answer>> {
            let answers = vec![Answer::allow(); asks.len()];
            Box::pin(async move { answers })
        }
        fn service<'a>(&'a self, _request_id: &'a str, _who: &'a Identity) -> crate::common::BoxFuture<'a, Answer> {
            Box::pin(async move { Answer::allow() })
        }
        fn display<'a>(
            &'a self,
            _request_id: &'a str,
            _who: &'a Identity,
            asks: &'a [Ask],
        ) -> crate::common::BoxFuture<'a, Vec<Answer>> {
            let answers = vec![Answer::allow(); asks.len()];
            Box::pin(async move { answers })
        }
    }
    let env = Env::new();
    let config = authzen_config(SERVICE, vec![bucket("rw", "rw", None)], Vec::new());
    let layer = AccessLayer::with_guard(&config, Arc::new(NoUnits)).unwrap();
    let error = layer
        .authorize(&env.ctx("rid"), layer.use_operation(ACTION_WRITE, &env.rw, "a/x"))
        .await
        .unwrap_err();
    assert_eq!((api(&error).status, api(&error).code.as_str()), (403, "forbidden"));
}

#[tokio::test]
async fn a_canceled_request_gets_no_decision() {
    let env = Env::new();
    let ctx = env.ctx("rid");
    ctx.cancel.cancel();
    let error = env.layer.authorize_read(&ctx, &env.rw, "a/x").await.unwrap_err();
    assert_eq!(api(&error).code, "pdp_unavailable");
}

#[test]
fn the_public_keys_give_their_names_for_print_config() {
    let names = parse_public_keys(
        r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}"#,
    )
    .unwrap();
    assert_eq!(names, vec!["Ed25519 kid=kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"]);
    let error = parse_public_keys("nothing").unwrap_err();
    assert!(
        error
            .to_string()
            .starts_with("line 1 is not -----BEGIN PUBLIC KEY-----")
    );
}
