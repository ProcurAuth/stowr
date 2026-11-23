//! The tests of the guard of the mode `authzen`: the check of real tokens, the map of each outcome of the library to
//! the answer of Stowr, the permission of a refusal, the action `access`, and the configuration of the library.

use std::sync::Arc;
use std::time::Duration;

use http::HeaderValue;
use http::header::RETRY_AFTER;
use procurauth_core::jws::{SigningKey, sign_compact, sign_compact_text};
use procurauth_pep::clock::ManualClock;
use serde_json::{Value, json};

use super::*;
use crate::access::test_support::{Env, SERVICE, authzen_config, bucket};
use crate::access::{ACTION_READ, ACTION_WRITE, AccessLayer, Operation};
use crate::common::error::ApiError;

/// The time of the clock of the token tests.
const NOW: u64 = 1_800_000_000;

fn ed25519() -> SigningKey {
    SigningKey::from_ed25519_seed(&[3; 32])
}

fn es256() -> SigningKey {
    SigningKey::from_es256_scalar(&[9; 32]).unwrap()
}

/// A guard of the service of the tests that trusts these keys, with the clock at [`NOW`]. It asks no PDP.
fn token_guard(keys: &[(&SigningKey, &str)]) -> PepGuard {
    let config = authzen_config(SERVICE, vec![bucket("rw", "rw", None)], Vec::new());
    let document = ActionDocument::build(&config).unwrap();
    let parts = Parts {
        inner: Arc::new(HttpTransport::new(transport_bounds())),
        clock: Arc::new(ManualClock::at_seconds(NOW)),
        trusted: KeySet::from_keys(keys.iter().map(|(key, kid)| key.public_key(Some(kid))).collect()),
        cache_entries: 16,
    };
    PepGuard::with_parts(&config, &document, parts).unwrap()
}

fn header(alg: &str, kid: &str) -> Value {
    json!({"alg": alg, "typ": "JWT", "kid": kid})
}

fn claims() -> Value {
    json!({
        "iss": "https://edge.example",
        "sub": "alice",
        "aud": SERVICE,
        "iat": NOW - 10,
        "exp": NOW + 200,
        "owner": "ann",
    })
}

fn with(mut value: Value, name: &str, member: Value) -> Value {
    value[name] = member;
    value
}

fn without(mut value: Value, name: &str) -> Value {
    if let Some(map) = value.as_object_mut() {
        map.remove(name);
    }
    value
}

fn check(guard: &PepGuard, tokens: &[&str]) -> std::result::Result<Option<Identity>, String> {
    let mut headers = HeaderMap::new();
    for token in tokens {
        headers.append("x-identity-token", HeaderValue::from_str(token).unwrap());
    }
    guard.authenticate(&headers)
}

#[test]
fn a_valid_token_gives_the_identity_of_its_claims() {
    let key = ed25519();
    let guard = token_guard(&[(&key, "k1")]);
    let token = sign_compact(&header("Ed25519", "k1"), &claims(), &key);
    let identity = check(&guard, &[&token]).unwrap().unwrap();
    assert_eq!(
        identity,
        Identity {
            subject: "alice".to_owned(),
            owner: "ann".to_owned(),
            issued_at: NOW - 10,
            expires_at: NOW + 200,
        }
    );
    // A token of ES256, and a token without kid when the set has one key.
    let p256 = es256();
    let guard = token_guard(&[(&p256, "k2")]);
    let token = sign_compact(&header("ES256", "k2"), &claims(), &p256);
    assert!(check(&guard, &[&token]).unwrap().is_some());
    let token = sign_compact(&json!({"alg": "ES256", "typ": "JWT"}), &claims(), &p256);
    assert!(check(&guard, &[&token]).unwrap().is_some());
    // nbf equal to iat.
    let token = sign_compact(&header("ES256", "k2"), &with(claims(), "nbf", json!(NOW - 10)), &p256);
    assert!(check(&guard, &[&token]).unwrap().is_some());
}

#[test]
fn each_refused_token_gives_the_reason_of_the_log() {
    let key = ed25519();
    let p256 = es256();
    let other = SigningKey::from_ed25519_seed(&[4; 32]);
    let guard = token_guard(&[(&key, "k1"), (&p256, "k2")]);
    let good = header("Ed25519", "k1");
    let sign = |header: &Value, claims: &Value| sign_compact(header, claims, &key);
    let text = |claims: &str| sign_compact_text(&good.to_string(), claims, &key);
    let deep = format!("{}1{}", "[".repeat(32), "]".repeat(32));
    let cases: Vec<(&str, String, &str)> = vec![
        ("not a token", "abc".to_owned(), "malformed"),
        ("alg EdDSA", sign(&header("EdDSA", "k1"), &claims()), "algorithm"),
        ("alg none", sign(&header("none", "k1"), &claims()), "algorithm"),
        (
            "typ at+jwt",
            sign(&with(good.clone(), "typ", json!("at+jwt")), &claims()),
            "type",
        ),
        ("no typ", sign(&without(good.clone(), "typ"), &claims()), "type"),
        (
            "crit",
            sign(&with(good.clone(), "crit", json!(["exp"])), &claims()),
            "malformed",
        ),
        ("unknown kid", sign(&header("Ed25519", "k9"), &claims()), "kid"),
        (
            "no kid with two keys",
            sign(&without(good.clone(), "kid"), &claims()),
            "kid",
        ),
        (
            "kid of a key of another algorithm",
            sign(&header("Ed25519", "k2"), &claims()),
            "kid",
        ),
        ("another key", sign_compact(&good, &claims(), &other), "signature"),
        (
            "another issuer",
            sign(&good, &with(claims(), "iss", json!("https://other.example"))),
            "issuer",
        ),
        (
            "another audience",
            sign(&good, &with(claims(), "aud", json!("other"))),
            "audience",
        ),
        (
            "expired",
            sign(&good, &with(claims(), "exp", json!(NOW - 61))),
            "expired",
        ),
        (
            "iat after the clock",
            sign(
                &good,
                &with(with(claims(), "iat", json!(NOW + 61)), "exp", json!(NOW + 100)),
            ),
            "not_yet_valid",
        ),
        (
            "nbf after the clock",
            sign(&good, &with(claims(), "nbf", json!(NOW + 61))),
            "not_yet_valid",
        ),
        (
            "life above max_age",
            sign(&good, &with(claims(), "exp", json!(NOW + 291))),
            "max_age",
        ),
        (
            "exp before iat",
            sign(&good, &with(claims(), "exp", json!(NOW - 20))),
            "max_age",
        ),
        (
            "iat with a fraction",
            text(&format!(
                r#"{{"iss":"https://edge.example","sub":"alice","aud":"{SERVICE}","iat":{}.0,"exp":{}}}"#,
                NOW - 10,
                NOW + 200
            )),
            "claims",
        ),
        (
            "exp with an exponent",
            text(&format!(
                r#"{{"iss":"https://edge.example","sub":"alice","aud":"{SERVICE}","iat":{},"exp":{}e0}}"#,
                NOW - 10,
                NOW + 200
            )),
            "claims",
        ),
        (
            "iat with a sign",
            text(&format!(
                r#"{{"iss":"https://edge.example","sub":"alice","aud":"{SERVICE}","iat":-{},"exp":{}}}"#,
                NOW - 10,
                NOW + 200
            )),
            "claims",
        ),
        (
            "nbf with a fraction",
            text(&format!(
                r#"{{"iss":"https://edge.example","sub":"alice","aud":"{SERVICE}","iat":{0},"exp":{1},"nbf":{0}.0}}"#,
                NOW - 10,
                NOW + 200
            )),
            "claims",
        ),
        ("no sub", sign(&good, &without(claims(), "sub")), "claims"),
        (
            "a duplicate claim",
            text(&format!(
                r#"{{"iss":"https://edge.example","sub":"alice","sub":"bob","aud":"{SERVICE}","iat":{},"exp":{}}}"#,
                NOW - 10,
                NOW + 200
            )),
            "malformed",
        ),
        (
            "a claim deeper than 32 levels",
            sign(&good, &with(claims(), "extra", serde_json::from_str(&deep).unwrap())),
            "malformed",
        ),
        (
            "a token of more than 16384 bytes",
            sign(&good, &with(claims(), "extra", json!("x".repeat(16384)))),
            "malformed",
        ),
    ];
    let mut wrong = Vec::new();
    for (name, token, reason) in cases {
        let got = check(&guard, &[&token]);
        if got != Err(reason.to_owned()) {
            wrong.push(format!("{name}: {got:?}"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
    let token = sign(&good, &claims());
    assert_eq!(check(&guard, &[]), Err("missing".to_owned()));
    assert_eq!(check(&guard, &[&token, &token]), Err("malformed".to_owned()));
    assert!(check(&guard, &[&token]).unwrap().is_some());
    // A nesting of 32 levels stays valid.
    let deep = format!("{}1{}", "[".repeat(31), "]".repeat(31));
    let token = sign(&good, &with(claims(), "extra", serde_json::from_str(&deep).unwrap()));
    assert!(check(&guard, &[&token]).unwrap().is_some());
}

#[test]
fn the_depth_of_a_json_text_counts_the_objects_and_the_arrays_only() {
    assert!(!json_deeper_than(br#"{"a":[1,{"b":2}]}"#, 3));
    assert!(json_deeper_than(br#"{"a":[1,{"b":[2]}]}"#, 3));
    assert!(!json_deeper_than(br#"{"a":"[[[[[[\"[["}"#, 1));
    assert!(!json_deeper_than(b"", 0));
}

fn api(error: &crate::common::error::Error) -> &ApiError {
    match error {
        crate::common::error::Error::Api(api) => api,
        other => panic!("not an API error: {other:?}"),
    }
}

/// The operations of the map test.
#[derive(Clone, Copy, Debug)]
enum Kind {
    /// A use of `object.write`: a usage question.
    Usage,
    /// A use of `object.read`: a question without usage.
    Plain,
    /// A copy: the read of the source is an other, the write of the target is the use.
    WithOther,
    /// The action `access` on the service.
    Access,
}

async fn run(env: &Env, kind: Kind) -> crate::common::error::Result<()> {
    let ctx = env.ctx("rid-map");
    match kind {
        Kind::Usage => env
            .layer
            .authorize(&ctx, env.layer.use_operation(ACTION_WRITE, &env.rw, "a/x"))
            .await
            .map(drop),
        Kind::Plain => env.layer.authorize_read(&ctx, &env.rw, "a/x").await.map(drop),
        Kind::WithOther => env
            .layer
            .authorize(
                &ctx,
                Operation {
                    others: vec![env.ask(ACTION_READ, "a/x")],
                    use_ask: env.ask(ACTION_WRITE, "b/y"),
                    continuation: false,
                },
            )
            .await
            .map(drop),
        Kind::Access => env.layer.authorize_service(&ctx).await,
    }
}

#[tokio::test]
async fn each_outcome_of_the_library_gives_the_answer_of_stowr() {
    let other_says = |answer: Value| {
        move |question: &crate::access::fake::FakeQuestion| {
            if question.permission_only {
                answer.clone()
            } else {
                json!({"decision": true, "context": {"usage": {"units": 1}}})
            }
        }
    };
    type Script = Box<dyn Fn(&crate::access::fake::FakeQuestion) -> Value + Send + Sync>;
    let all = |answer: Value| -> Script { Box::new(move |_| answer.clone()) };
    // The name, the operation, the answers of the PDP, an HTTP status of the PDP, and the status, the code, the
    // action and the wait of the answer of Stowr.
    type Want = (u16, &'static str, &'static str, u64);
    let cases: Vec<(&str, Kind, Script, u16, Want)> = vec![
        (
            "approval_required on a use with usage",
            Kind::Usage,
            all(json!({"decision": false, "context": {"reason": "approval_required"}})),
            0,
            (403, "approval_cannot_wait", "", 0),
        ),
        (
            "approval_pending on a use without usage",
            Kind::Plain,
            all(json!({"decision": false, "context": {"reason": "approval_pending"}})),
            0,
            (403, "approval_cannot_wait", "", 0),
        ),
        (
            "approval_required on an other permission",
            Kind::WithOther,
            Box::new(other_says(
                json!({"decision": false, "context": {"reason": "approval_required"}}),
            )),
            0,
            (503, "pdp_unavailable", ACTION_READ, 0),
        ),
        (
            "approval_denied on the action access",
            Kind::Access,
            all(json!({"decision": false, "context": {"reason": "approval_denied"}})),
            0,
            (503, "pdp_unavailable", "access", 0),
        ),
        (
            "budget_exceeded on a usage question",
            Kind::Usage,
            all(json!({"decision": false, "context": {"reason": "budget_exceeded", "retry_after": 9}})),
            0,
            (429, "too_many_requests", ACTION_WRITE, 9),
        ),
        (
            "true without units on a usage question",
            Kind::Usage,
            all(json!({"decision": true})),
            0,
            (403, "forbidden", ACTION_WRITE, 0),
        ),
        (
            "a ceiling that the action does not list",
            Kind::Plain,
            all(json!({"decision": true, "context": {"limits": {"max_rows": 3}}})),
            0,
            (403, "forbidden", ACTION_READ, 0),
        ),
        (
            "a budget in context.limits",
            Kind::Plain,
            all(json!({"decision": true, "context": {"limits": {"writes": 3}}})),
            0,
            (503, "pdp_unavailable", ACTION_READ, 0),
        ),
        (
            "a ceiling of an other that its action does not list",
            Kind::WithOther,
            Box::new(other_says(
                json!({"decision": true, "context": {"limits": {"max_rows": 3}}}),
            )),
            0,
            (403, "forbidden", ACTION_READ, 0),
        ),
        (
            "an answer that is not valid",
            Kind::Plain,
            all(json!({"decision": "yes"})),
            0,
            (503, "pdp_unavailable", ACTION_READ, 0),
        ),
        (
            "a refused credential",
            Kind::Usage,
            all(json!({"decision": true})),
            401,
            (503, "pdp_unavailable", ACTION_WRITE, 0),
        ),
        (
            "a false answer with another reason",
            Kind::Plain,
            all(json!({"decision": false, "context": {"reason": "unknown_subject"}})),
            0,
            (403, "forbidden", ACTION_READ, 0),
        ),
        (
            "a refused other permission",
            Kind::WithOther,
            Box::new(other_says(json!({"decision": false}))),
            0,
            (403, "forbidden", ACTION_READ, 0),
        ),
        (
            "a refused use after the other permissions",
            Kind::WithOther,
            Box::new(|question: &crate::access::fake::FakeQuestion| json!({"decision": question.permission_only})),
            0,
            (403, "forbidden", ACTION_WRITE, 0),
        ),
        (
            "a false answer to the action access",
            Kind::Access,
            all(json!({"decision": false})),
            0,
            (403, "forbidden", "access", 0),
        ),
    ];
    for (name, kind, script, status, (want_status, code, action, retry_after)) in cases {
        let env = Env::new();
        env.fake.set_answer(script);
        if status != 0 {
            env.fake.set_status(status);
        }
        let error = run(&env, kind).await.unwrap_err();
        let got = api(&error);
        assert_eq!((got.status, got.code.as_str()), (want_status, code), "{name}");
        assert_eq!(got.action.as_deref().unwrap_or_default(), action, "{name}");
        assert_eq!(got.retry_after, retry_after, "{name}");
        let response = crate::common::http::api_error(&error);
        if code == "approval_cannot_wait" {
            let (body, _) = crate::common::http::read_limited(response.into_body(), 4096)
                .await
                .unwrap();
            assert_eq!(&body[..], &b"{\"error\":\"approval_cannot_wait\"}\n"[..], "{name}");
        } else if retry_after > 0 {
            assert_eq!(response.headers().get(RETRY_AFTER).unwrap(), "9", "{name}");
        }
        // The guard only asks questions: it never submits an approval and never asks for a usage again.
        assert!(
            env.fake
                .raw_requests()
                .iter()
                .all(|request| request.path.starts_with("/access/v1/evaluation")),
            "{name}"
        );
        let refused_other = matches!(kind, Kind::WithOther) && action == ACTION_READ;
        if refused_other {
            assert!(
                env.fake.questions().iter().all(|question| question.permission_only),
                "{name}: no question of the use after a refused other"
            );
        }
    }
}

#[tokio::test]
async fn the_answers_of_the_library_that_let_the_operation_run() {
    let env = Env::new();
    env.fake.set_answer(|question| {
        if question.usage {
            json!({"decision": true, "context": {"usage": {"units": 1}, "limits": {"max_object_size": 5}}})
        } else {
            json!({"decision": true, "context": {"limits": {"max_object_size": 7}}})
        }
    });
    let ctx = env.ctx("rid");
    let grant = env
        .layer
        .authorize(
            &ctx,
            Operation {
                others: vec![env.ask(ACTION_READ, "a/x")],
                use_ask: env.ask(ACTION_WRITE, "b/y"),
                continuation: false,
            },
        )
        .await
        .unwrap();
    assert_eq!(grant.limits[ACTION_READ]["max_object_size"], 7);
    assert_eq!(grant.limits[ACTION_WRITE]["max_object_size"], 5);
    let request = ctx.access.as_ref().unwrap();
    assert_eq!(request.ceilings.get(ACTION_READ, "max_object_size"), Some(7));
    assert_eq!(request.ceilings.get(ACTION_WRITE, "max_object_size"), Some(5));
    // The action access lets a route without action run.
    env.layer.authorize_service(&env.ctx("rid")).await.unwrap();
}

#[tokio::test]
async fn a_refusal_names_its_permission_also_from_a_kept_answer() {
    let env = Env::new();
    env.fake
        .configure(|settings| settings.cache_ttl = Duration::from_secs(30));
    env.fake
        .set_answer(|question| json!({"decision": !(question.permission_only && question.resource_id == "a")}));
    let copy = |source: &str, target: &str| Operation {
        others: vec![env.ask(ACTION_READ, &format!("{source}/x"))],
        use_ask: env.ask(ACTION_WRITE, &format!("{target}/y")),
        continuation: true,
    };
    for round in 0..2 {
        let error = env.layer.authorize(&env.ctx("rid"), copy("a", "b")).await.unwrap_err();
        assert_eq!(api(&error).action.as_deref(), Some(ACTION_READ), "round {round}");
    }
    assert_eq!(env.fake.requests(), 1, "the second round uses the kept answer");
    // A kept refusal of the use, after a granted other.
    env.fake
        .set_answer(|question| json!({"decision": question.permission_only}));
    for round in 0..2 {
        let error = env.layer.authorize(&env.ctx("rid"), copy("c", "d")).await.unwrap_err();
        assert_eq!(api(&error).action.as_deref(), Some(ACTION_WRITE), "round {round}");
    }
    assert_eq!(env.fake.requests(), 3);
}

#[tokio::test]
async fn the_action_access_has_the_service_node_and_no_usage() {
    let env = Env::new();
    env.layer.authorize_service(&env.ctx("rid-s")).await.unwrap();
    let questions = env.fake.questions();
    assert_eq!(questions.len(), 1);
    let question = &questions[0];
    assert_eq!(
        (
            question.action.as_str(),
            question.resource_type.as_str(),
            question.resource_id.as_str()
        ),
        ("access", "service", SERVICE)
    );
    assert!(question.ancestors.is_empty());
    assert!(!question.usage && !question.permission_only);
    assert_eq!(question.match_mode, "node");
    assert_eq!(question.request_id, "rid-s");
}

#[test]
fn the_link_of_the_library_follows_the_pdp_block() {
    let config = authzen_config(SERVICE, Vec::new(), Vec::new());
    let pdp = config.access.pdp.as_ref().unwrap();
    let link = link_config(pdp);
    assert_eq!(link.url, pdp.url);
    assert!(link.allow_plain_http);
    assert_eq!(link.request_timeout, pdp.timeout);
    assert_eq!(link.usage_wait_margin, Duration::from_secs(1));
    assert_eq!(link.idle_close_after, Duration::from_secs(5));
    assert_eq!(link.max_connections, 4);
    assert_eq!(link.evaluations_max_items, 64);
    assert_eq!(link.max_response_bytes, 256 * 1024);
    assert_eq!(link.plain_retries, 0);
    assert_eq!(link.metadata_max_age, Duration::from_secs(3600));
    let bounds = transport_bounds();
    assert_eq!(bounds.connect_timeout, Duration::from_secs(5));
    assert_eq!(bounds.max_response_bytes, 256 * 1024);
}

fn keyed_config(url: &str, plain_http: bool) -> Config {
    let mut config = authzen_config(SERVICE, vec![bucket("rw", "rw", None)], Vec::new());
    if let Some(identity) = config.access.identity.as_mut() {
        identity.public_keys_text = ed25519().public_jwks(Some("k1")).to_string();
    }
    if let Some(pdp) = config.access.pdp.as_mut() {
        pdp.url = url.to_owned();
        pdp.plain_http = plain_http;
    }
    config
}

#[test]
fn the_guard_of_the_configuration_checks_the_link() {
    let config = keyed_config("http://127.0.0.1:8181", true);
    let layer = AccessLayer::new(&config).unwrap();
    assert!(layer.enforced());
    // An https URL with plain_http is a contradiction.
    let error = AccessLayer::new(&keyed_config("https://pdp.example", true)).unwrap_err();
    assert!(error.to_string().contains("pdp.allow_plain_http"), "{error}");
    // An http URL without plain_http is not a secured link.
    let error = AccessLayer::new(&keyed_config("http://127.0.0.1:8181", false)).unwrap_err();
    assert!(error.to_string().contains("pdp.url"), "{error}");
    // The keys of the edge come from the configuration.
    let keys = trusted_keys(&config).unwrap();
    assert_eq!(keys.len(), 1);
    let mut empty = config;
    if let Some(identity) = empty.access.identity.as_mut() {
        identity.public_keys_text = String::new();
    }
    assert!(AccessLayer::new(&empty).is_err());
}

#[test]
fn the_budget_name_comes_from_the_text_of_the_library() {
    assert_eq!(
        budget_name_of("`context.limits` has the budget `writes`"),
        Some("writes")
    );
    assert_eq!(budget_name_of("another text"), None);
}

#[test]
fn the_copy_of_the_kept_answers_follows_the_rules_of_the_library() {
    let copy = KeptCopy::new(Duration::from_secs(30), 2);
    let ask = |id: &str| Ask {
        action: ACTION_READ.to_owned(),
        resource: format!("service:{SERVICE}/bucket:{id}"),
    };
    copy.put("alice", &ask("a"), true, &Answer::deny(""), 0);
    assert_eq!(copy.get("alice", &ask("a"), true, 1), Some(Answer::deny("")));
    assert_eq!(
        copy.get("alice", &ask("a"), false, 1),
        None,
        "the mark permission_only is part of the key"
    );
    assert_eq!(copy.get("bob", &ask("a"), true, 1), None);
    assert_eq!(copy.get("alice", &ask("a"), true, 30_000), None, "expired");
    // No failure and no reason of 17.1.
    copy.put("alice", &ask("b"), false, &Answer::failure(), 0);
    copy.put("alice", &ask("c"), false, &Answer::deny("approval_required"), 0);
    assert_eq!(copy.get("alice", &ask("b"), false, 1), None);
    assert_eq!(copy.get("alice", &ask("c"), false, 1), None);
    // The bound.
    copy.put("alice", &ask("d"), false, &Answer::allow(), 40_000);
    copy.put("alice", &ask("e"), false, &Answer::allow(), 40_000);
    copy.put("alice", &ask("f"), false, &Answer::allow(), 40_000);
    assert!(copy.get("alice", &ask("f"), false, 40_001).is_none());
    // A time to live of zero keeps nothing.
    let none = KeptCopy::new(Duration::ZERO, 2);
    none.put("alice", &ask("a"), false, &Answer::allow(), 0);
    assert_eq!(none.get("alice", &ask("a"), false, 0), None);
}
