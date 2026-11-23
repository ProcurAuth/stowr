//! The route tests of the access policy in mode `authzen`: each request goes through the whole dispatch, with the
//! fake guard of the access layer. They check the points where the routes meet the access layer: the check of the
//! token, the rule of each route, the display questions and the ceilings of the request.

use std::sync::Arc;

use serde_json::json;

use super::testing::{TestRequest, TestResponse, app_with_access};
use crate::access::AccessLayer;
use crate::access::fake::{FakePdp, FakeQuestion};
use crate::access::test_support::{BUCKET, SERVICE, SUBJECT, authzen_config, bucket, instance_over, memory};
use crate::common::app::App;

const TOKEN: &str = "good-token";

/// The application of the tests: `readonly` (read only) and `rw` (root prefix `tenant/`), the fake guard that
/// accepts [`TOKEN`] and answers true to each question.
fn authzen_app() -> (Arc<App>, Arc<FakePdp>) {
    let readonly = bucket("readonly", "Read only", Some(&["read"]));
    let mut rw = bucket("rw", "Read write", None);
    rw.root_prefix = "tenant/".to_owned();
    let config = authzen_config(SERVICE, vec![readonly.clone(), rw.clone()], Vec::new());
    let fake = Arc::new(FakePdp::new());
    fake.accept_token(TOKEN, SUBJECT, "");
    let access = AccessLayer::with_guard(&config, fake.clone()).unwrap();
    let instances = vec![
        instance_over(readonly, memory(&[("ro.txt", "ro")])),
        instance_over(
            rw,
            memory(&[
                ("tenant/folder/twelve.txt", "hello world!"),
                ("tenant/folder/nested/deep.txt", "deep"),
                ("tenant/root.txt", "root"),
            ]),
        ),
    ];
    (app_with_access(config, instances, access), fake)
}

async fn send(app: &Arc<App>, method: &str, target: &str) -> TestResponse {
    TestRequest::new(method, target)
        .header("x-identity-token", TOKEN)
        .send(app)
        .await
}

fn questions(fake: &FakePdp) -> Vec<(String, String)> {
    fake.questions()
        .into_iter()
        .map(|question| (question.action, question.path))
        .collect()
}

#[tokio::test]
async fn a_request_without_a_valid_token_gets_401_and_asks_nothing() {
    let (app, fake) = authzen_app();
    for target in [
        "/api/list?instance=rw",
        "/api/build",
        "/",
        "/s3?instance=rw&key=root.txt",
    ] {
        let answer = TestRequest::get(target).send(&app).await;
        assert_eq!(answer.status, 401, "{target}");
        assert_eq!(answer.json()["error"]["code"], "unauthenticated", "{target}");
    }
    let answer = TestRequest::new("POST", "/api/copy").send(&app).await;
    assert_eq!(answer.status, 401);
    assert_eq!(answer.header("connection"), "close");
    let answer = TestRequest::new("OPTIONS", "/s3?instance=rw&key=root.txt")
        .send(&app)
        .await;
    assert_eq!(answer.status, 401);
    // The exempt paths need no token.
    assert_eq!(TestRequest::get("/healthz").send(&app).await.status, 200);
    assert_eq!(
        TestRequest::get("/.well-known/procurauth/actions")
            .send(&app)
            .await
            .status,
        200
    );
    assert_eq!(fake.requests(), 0);
}

#[tokio::test]
async fn the_routes_without_data_of_a_bucket_ask_the_action_access_on_the_service() {
    let (app, fake) = authzen_app();
    for (method, target) in [
        ("GET", "/api/build"),
        ("OPTIONS", "/s3?instance=rw&key=root.txt"),
        ("GET", "/api/jobs"),
    ] {
        fake.reset();
        fake.set_answer(|_: &FakeQuestion| json!({"decision": false}));
        let answer = send(&app, method, target).await;
        assert_eq!(answer.status, 403, "{method} {target}: {}", answer.text());
        assert!(answer.text().contains("access"), "{method} {target}: {}", answer.text());
        assert_eq!(
            questions(&fake),
            vec![("access".to_owned(), format!("service:{SERVICE}"))],
            "{method} {target}"
        );
        fake.set_answer(|_: &FakeQuestion| json!({"decision": true}));
        let answer = send(&app, method, target).await;
        assert_ne!(answer.status, 403, "{method} {target}: {}", answer.text());
    }
    let answer = send(&app, "OPTIONS", "/s3?instance=rw&key=root.txt").await;
    assert_eq!(answer.status, 204);
    assert_eq!(answer.header("allow"), "GET, HEAD, PUT, DELETE, OPTIONS");
}

#[tokio::test]
async fn the_instances_show_only_the_buckets_with_one_true_answer() {
    let (app, fake) = authzen_app();
    fake.set_answer(
        |question: &FakeQuestion| json!({"decision": question.path == BUCKET && question.action == "object.read"}),
    );
    let answer = send(&app, "GET", "/api/instances").await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    let body = answer.json();
    let instances = body["instances"].as_array().unwrap();
    assert_eq!(instances.len(), 1);
    assert_eq!(instances[0]["id"], "rw");
    assert_eq!(body["default"], "rw");
    assert_eq!(instances[0]["capabilities"]["write"]["source"], "access");
    assert_eq!(instances[0]["capabilities"]["delete"]["source"], "access");
    assert_ne!(instances[0]["capabilities"]["read"]["source"], "access");
    assert_eq!(instances[0]["operations"]["upload"]["source"], "access");
    assert_eq!(instances[0]["operations"]["list"], instances[0]["capabilities"]["read"]);

    fake.set_answer(|_: &FakeQuestion| json!({"decision": false}));
    let body = send(&app, "GET", "/api/instances").await.json();
    assert_eq!(body["instances"], json!([]));
    assert_eq!(body["default"], "");
}

#[tokio::test]
async fn the_list_gives_the_access_member_and_the_navigation_listing() {
    let (app, fake) = authzen_app();
    let answer = send(&app, "GET", "/api/list?instance=rw").await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert_eq!(
        answer.json()["access"],
        json!({"read": true, "write": true, "delete": true})
    );

    // The person cannot read the bucket but can read the folder: the listing shows the folder only.
    fake.set_answer(|question: &FakeQuestion| {
        json!({"decision": question.match_mode == "subtree" && question.path.ends_with("folder:folder")})
    });
    let answer = send(&app, "GET", "/api/list?instance=rw").await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    let body = answer.json();
    assert_eq!(body["access"], json!({"read": false, "write": false, "delete": false}));
    let names: Vec<&str> = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["folder/"]);

    // A subfolder that the person cannot read gives 403.
    fake.set_answer(|_: &FakeQuestion| json!({"decision": false}));
    let answer = send(&app, "GET", "/api/list?instance=rw&prefix=folder%2Fnested%2F").await;
    assert_eq!(answer.status, 403, "{}", answer.text());
}

#[tokio::test]
async fn the_ceiling_of_a_true_answer_applies_to_the_gateway() {
    let (app, fake) = authzen_app();
    let ceiling = |limit: i64| move |_: &FakeQuestion| json!({"decision": true, "context": {"limits": {"max_object_size": limit}}});
    fake.set_answer(ceiling(10));
    let answer = send(&app, "GET", "/s3?instance=rw&key=folder%2Ftwelve.txt").await;
    assert_eq!(answer.status, 403, "{}", answer.text());
    assert!(!answer.text().contains("hello"));
    assert!(answer.text().contains("max_object_size"), "{}", answer.text());

    fake.set_answer(ceiling(12));
    let answer = send(&app, "GET", "/s3?instance=rw&key=folder%2Ftwelve.txt").await;
    assert_eq!(answer.status, 200, "{}", answer.text());
    assert_eq!(answer.text(), "hello world!");
}

#[tokio::test]
async fn the_open_mode_asks_nothing_and_gives_no_access_member() {
    let test = super::testing::memory_app();
    let answer = super::testing::get(&test.0, "/api/list?instance=rw").await;
    assert_eq!(answer.status, 200);
    assert!(answer.json().get("access").is_none(), "{}", answer.text());
    let answer = super::testing::get(&test.0, "/api/instances").await;
    let body = answer.json();
    assert_eq!(body["default"], "readonly");
    assert_eq!(body["instances"].as_array().unwrap().len(), 2);
    for instance in body["instances"].as_array().unwrap() {
        for name in ["read", "write", "delete"] {
            assert_ne!(instance["capabilities"][name]["source"], "access", "{}", instance["id"]);
        }
    }
}
