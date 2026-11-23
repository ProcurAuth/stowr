// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tests of the guard of the mode `authzen` over the fake PDP: the rules of the client of the PDP that the library
//! `procurauth-pep` and the transport of Stowr give. The tests of the routes then test the service against the real
//! guard.

use super::*;
use crate::access::test_support::{authzen_config, bucket};
use crate::access::tree::{bucket_resource, key_resource};

fn read(id: &str) -> Ask {
    Ask {
        action: "object.read".to_owned(),
        resource: key_resource("svc", "logs", &format!("{id}/x")).path(),
    }
}

fn write(id: &str) -> Ask {
    Ask {
        action: "object.write".to_owned(),
        resource: key_resource("svc", "logs", &format!("{id}/x")).path(),
    }
}

fn who(subject: &str) -> Identity {
    Identity {
        subject: subject.to_owned(),
        ..Identity::default()
    }
}

/// A fake PDP behind the guard of the service `svc` with the bucket `logs`.
fn bound_fake() -> FakePdp {
    let fake = FakePdp::new();
    let config = authzen_config("svc", vec![bucket("logs", "Logs", None)], Vec::new());
    let document = ActionDocument::build(&config).unwrap();
    fake.bind(&config, &document).unwrap();
    fake
}

async fn decide_one(fake: &FakePdp, subject: &str, ask: &Ask) -> Answer {
    fake.decide("req-1", &who(subject), std::slice::from_ref(ask))
        .await
        .remove(0)
}

async fn use_one(fake: &FakePdp, subject: &str, ask: &Ask) -> Answer {
    fake.operation("req-1", &who(subject), &[], ask, true)
        .await
        .use_answer
        .unwrap()
}

async fn display(fake: &FakePdp, subject: &str, asks: &[Ask]) -> Vec<Answer> {
    fake.display("req-1", &who(subject), asks).await
}

fn kept_fake() -> FakePdp {
    let fake = bound_fake();
    fake.configure(|settings| settings.cache_ttl = Duration::from_secs(30));
    fake
}

#[tokio::test]
async fn the_rules_of_an_answer() {
    let failed = Answer::failure();
    let limits = |pairs: &[(&str, i64)]| pairs.iter().map(|(k, v)| ((*k).to_owned(), *v)).collect();
    let cases: Vec<(&str, u16, &str, bool, Answer)> = vec![
        ("true", 0, r#"{"decision":true}"#, false, Answer::allow()),
        ("false", 0, r#"{"decision":false}"#, false, Answer::default()),
        (
            "unknown members are ignored",
            0,
            r#"{"decision":true,"extra":1,"context":{"foo":[1],"limits":{}}}"#,
            false,
            Answer::allow(),
        ),
        (
            "false keeps the reason",
            0,
            r#"{"decision":false,"context":{"reason":"unknown_subject"}}"#,
            false,
            Answer::deny("unknown_subject"),
        ),
        (
            "true drops the reason",
            0,
            r#"{"decision":true,"context":{"reason":"x"}}"#,
            false,
            Answer::allow(),
        ),
        (
            "budget_exceeded with retry_after 12",
            0,
            r#"{"decision":false,"context":{"reason":"budget_exceeded","retry_after":12}}"#,
            false,
            Answer {
                retry_after: 12,
                ..Answer::deny("budget_exceeded")
            },
        ),
        (
            "limits of a false answer are ignored",
            0,
            r#"{"decision":false,"context":{"limits":{"max_object_size":-5}}}"#,
            false,
            Answer::default(),
        ),
        (
            "malformed limits of a false answer are ignored",
            0,
            r#"{"decision":false,"context":{"limits":"zzz"}}"#,
            false,
            Answer::default(),
        ),
        (
            "limits of a true answer",
            0,
            r#"{"decision":true,"context":{"limits":{"max_object_size":100}}}"#,
            false,
            Answer {
                limits: limits(&[("max_object_size", 100)]),
                ..Answer::allow()
            },
        ),
        (
            "a ceiling that the action does not list goes to the layer, which refuses it",
            0,
            r#"{"decision":true,"context":{"limits":{"max_object_size":100,"other":0}}}"#,
            false,
            Answer {
                limits: limits(&[("other", 0)]),
                ..Answer::allow()
            },
        ),
        (
            "a budget in the limits goes to the layer, which reads the answer as not valid",
            0,
            r#"{"decision":true,"context":{"limits":{"writes":3}}}"#,
            false,
            Answer {
                limits: limits(&[("writes", 0)]),
                ..Answer::allow()
            },
        ),
        (
            "usage units 1 of a plain answer",
            0,
            r#"{"decision":true,"context":{"usage":{"units":1}}}"#,
            false,
            Answer::allow(),
        ),
        ("status 500", 500, "", false, failed.clone()),
        ("status 401", 401, "", false, failed.clone()),
        ("status 403", 403, "", false, failed.clone()),
        ("status 404", 404, "", false, failed.clone()),
        ("redirect 302", 302, "", false, failed.clone()),
        ("empty body", 0, "", false, failed.clone()),
        ("bad JSON", 0, r#"{"decision":"#, false, failed.clone()),
        (
            "data after the document",
            0,
            r#"{"decision":true} {}"#,
            false,
            failed.clone(),
        ),
        ("answer is an array", 0, r#"[{"decision":true}]"#, false, failed.clone()),
        ("answer is null", 0, "null", false, failed.clone()),
        ("decision is missing", 0, r#"{"context":{}}"#, false, failed.clone()),
        (
            "decision is a string",
            0,
            r#"{"decision":"true"}"#,
            false,
            failed.clone(),
        ),
        ("decision is a number", 0, r#"{"decision":1}"#, false, failed.clone()),
        (
            "context is an array",
            0,
            r#"{"decision":true,"context":[]}"#,
            false,
            failed.clone(),
        ),
        (
            "context is null",
            0,
            r#"{"decision":true,"context":null}"#,
            false,
            failed.clone(),
        ),
        (
            "reason is a number",
            0,
            r#"{"decision":false,"context":{"reason":5}}"#,
            false,
            failed.clone(),
        ),
        (
            "reason is null",
            0,
            r#"{"decision":false,"context":{"reason":null}}"#,
            false,
            failed.clone(),
        ),
        (
            "reason of a true answer is a number",
            0,
            r#"{"decision":true,"context":{"reason":5}}"#,
            false,
            failed.clone(),
        ),
        (
            "retry_after 0",
            0,
            r#"{"decision":false,"context":{"reason":"budget_exceeded","retry_after":0}}"#,
            false,
            failed.clone(),
        ),
        (
            "retry_after 1.5",
            0,
            r#"{"decision":false,"context":{"reason":"budget_exceeded","retry_after":1.5}}"#,
            false,
            failed.clone(),
        ),
        (
            "retry_after 12.0",
            0,
            r#"{"decision":false,"context":{"reason":"budget_exceeded","retry_after":12.0}}"#,
            false,
            failed.clone(),
        ),
        (
            "retry_after is a string",
            0,
            r#"{"decision":false,"context":{"reason":"budget_exceeded","retry_after":"12"}}"#,
            false,
            failed.clone(),
        ),
        (
            "retry_after is negative",
            0,
            r#"{"decision":false,"context":{"reason":"budget_exceeded","retry_after":-3}}"#,
            false,
            failed.clone(),
        ),
        (
            "retry_after is absent",
            0,
            r#"{"decision":false,"context":{"reason":"budget_exceeded"}}"#,
            false,
            failed.clone(),
        ),
        (
            "limits with a negative value",
            0,
            r#"{"decision":true,"context":{"limits":{"max_object_size":-1}}}"#,
            false,
            failed.clone(),
        ),
        (
            "limits with a fraction",
            0,
            r#"{"decision":true,"context":{"limits":{"max_object_size":1.5}}}"#,
            false,
            failed.clone(),
        ),
        (
            "limits with a string",
            0,
            r#"{"decision":true,"context":{"limits":{"max_object_size":"7"}}}"#,
            false,
            failed.clone(),
        ),
        (
            "limits is an array",
            0,
            r#"{"decision":true,"context":{"limits":[1]}}"#,
            false,
            failed.clone(),
        ),
        (
            "limits is null",
            0,
            r#"{"decision":true,"context":{"limits":null}}"#,
            false,
            failed.clone(),
        ),
        (
            "usage units 2",
            0,
            r#"{"decision":true,"context":{"usage":{"units":2}}}"#,
            false,
            failed.clone(),
        ),
        (
            "usage units -1",
            0,
            r#"{"decision":true,"context":{"usage":{"units":-1}}}"#,
            false,
            failed.clone(),
        ),
        (
            "usage units 1.0",
            0,
            r#"{"decision":true,"context":{"usage":{"units":1.0}}}"#,
            false,
            failed.clone(),
        ),
        (
            "usage units is a string",
            0,
            r#"{"decision":true,"context":{"usage":{"units":"1"}}}"#,
            false,
            failed.clone(),
        ),
        (
            "usage is an array",
            0,
            r#"{"decision":true,"context":{"usage":[]}}"#,
            false,
            failed.clone(),
        ),
        (
            "use: true with units 1",
            0,
            r#"{"decision":true,"context":{"usage":{"units":1}}}"#,
            true,
            Answer {
                units: Some(1),
                ..Answer::allow()
            },
        ),
        (
            "use: true with units 0",
            0,
            r#"{"decision":true,"context":{"usage":{"units":0}}}"#,
            true,
            Answer {
                units: Some(0),
                ..Answer::allow()
            },
        ),
        (
            "use: true with units and limits",
            0,
            r#"{"decision":true,"context":{"usage":{"units":1},"limits":{"max_object_size":9}}}"#,
            true,
            Answer {
                units: Some(1),
                limits: limits(&[("max_object_size", 9)]),
                ..Answer::allow()
            },
        ),
        (
            "use: true without units is false",
            0,
            r#"{"decision":true}"#,
            true,
            Answer::default(),
        ),
        (
            "use: true with context and no units is false",
            0,
            r#"{"decision":true,"context":{"limits":{"max_object_size":9}}}"#,
            true,
            Answer::default(),
        ),
        ("use: false", 0, r#"{"decision":false}"#, true, Answer::default()),
        (
            "use: budget_exceeded with retry_after 0",
            0,
            r#"{"decision":false,"context":{"reason":"budget_exceeded","retry_after":0}}"#,
            true,
            failed.clone(),
        ),
        (
            "use: units 2",
            0,
            r#"{"decision":true,"context":{"usage":{"units":2}}}"#,
            true,
            failed.clone(),
        ),
        ("use: status 503", 503, "", true, failed.clone()),
        ("use: bad JSON", 0, "nope", true, failed.clone()),
    ];
    for (name, status, body, usage, want) in cases {
        let fake = bound_fake();
        if status != 0 {
            fake.set_status(status);
        }
        if status == 0 || !body.is_empty() {
            fake.set_raw(body.as_bytes());
        }
        let got = if usage {
            use_one(&fake, "alice", &write("a")).await
        } else {
            decide_one(&fake, "alice", &read("a")).await
        };
        assert_eq!(got, want, "{name}");
        assert_eq!(fake.requests(), 1, "{name}: no retry, no redirect");
    }
}

#[tokio::test]
async fn a_bad_item_of_a_batch_fails_the_call() {
    let fake = bound_fake();
    fake.set_raw(
        br#"{"evaluations":[{"decision":true},{"decision":"true"},{"decision":false,"context":{"reason":"budget_exceeded","retry_after":3}}]}"#,
    );
    let got = display(&fake, "alice", &[read("a"), read("b"), read("c")]).await;
    assert_eq!(got, vec![Answer::failure(); 3]);
    assert_eq!(fake.requests(), 1);
}

#[tokio::test]
async fn a_wrong_count_of_items_fails_the_call() {
    for body in [
        r#"{"evaluations":[{"decision":true},{"decision":true}]}"#,
        r#"{"evaluations":[{"decision":true},{"decision":true},{"decision":true},{"decision":true}]}"#,
        r#"{"evaluations":[]}"#,
        r#"{"decision":true}"#,
        r#"{"evaluations":null}"#,
    ] {
        let fake = bound_fake();
        fake.configure(|settings| settings.max_evaluations = 3);
        fake.set_raw(body.as_bytes());
        let got = display(&fake, "alice", &[read("a"), read("b"), read("c"), read("d")]).await;
        assert!(got.iter().all(|answer| answer.failed && !answer.decision), "{body}");
        assert_eq!(fake.requests(), 1, "{body}: a failed request stops the call");
    }
}

#[tokio::test]
async fn a_call_splits_at_max_evaluations() {
    let fake = bound_fake();
    fake.configure(|settings| settings.max_evaluations = 2);
    fake.set_answer(|q| json!({"decision": q.resource_id == "b"}));
    let got = display(&fake, "alice", &[read("a"), read("b"), read("c")]).await;
    assert_eq!(
        got.iter().map(|a| a.decision).collect::<Vec<_>>(),
        vec![false, true, false]
    );
    let requests = fake.raw_requests();
    assert_eq!(
        requests.iter().map(|r| r.path).collect::<Vec<_>>(),
        vec![EVALUATIONS_PATH, EVALUATIONS_PATH]
    );
    let questions = fake.questions();
    assert_eq!(
        questions.iter().map(|q| q.batch).collect::<Vec<_>>(),
        vec![true, true, true]
    );
}

#[tokio::test]
async fn a_repeated_question_goes_one_time() {
    let fake = bound_fake();
    fake.set_answer(|q| json!({"decision": q.resource_id == "a"}));
    let got = display(&fake, "alice", &[read("a"), read("b"), read("a")]).await;
    assert_eq!(
        got.iter().map(|a| a.decision).collect::<Vec<_>>(),
        vec![true, false, true]
    );
    assert_eq!((fake.questions().len(), fake.requests()), (2, 1));
    let got = fake.decide("req-1", &who("alice"), &[read("a"), read("a")]).await;
    assert_eq!(got.len(), 2);
    assert_eq!((fake.questions().len(), fake.requests()), (3, 2));
    // No question: no request.
    assert!(display(&fake, "alice", &[]).await.is_empty());
    assert!(fake.decide("req-1", &who("alice"), &[]).await.is_empty());
    assert_eq!(fake.requests(), 2);
}

#[tokio::test]
async fn one_deadline_covers_the_call() {
    let four = [read("a"), read("b"), read("c"), read("d")];
    // A slow PDP fails the call, and the second chunk is never sent.
    let fake = bound_fake();
    fake.configure(|settings| {
        settings.max_evaluations = 2;
        settings.timeout = Duration::from_millis(200);
    });
    fake.set_delay(Duration::from_secs(5));
    let got = display(&fake, "alice", &four).await;
    assert!(got.iter().all(|answer| answer.failed));
    assert_eq!(fake.requests(), 1);
    // The deadline is for the whole call: the second request has the time that remains, and its failure fails
    // each question of the call.
    let fake = bound_fake();
    fake.configure(|settings| {
        settings.max_evaluations = 2;
        settings.timeout = Duration::from_millis(700);
    });
    fake.set_delay(Duration::from_millis(400));
    let got = display(&fake, "alice", &four).await;
    assert!(got.iter().all(|answer| answer.failed));
    assert_eq!(fake.requests(), 2);
    // A deadline that is past sends no request.
    let fake = bound_fake();
    fake.configure(|settings| {
        settings.max_evaluations = 1;
        settings.timeout = Duration::from_millis(400);
    });
    fake.set_delay(Duration::from_millis(400));
    let got = display(&fake, "alice", &four).await;
    assert!(got.iter().all(|answer| answer.failed));
    assert_eq!(fake.requests(), 1);
}

#[tokio::test]
async fn a_usage_question_is_never_sent_again() {
    // The PDP closes the connection after the request.
    let fake = bound_fake();
    fake.set_close_connection(true);
    assert!(use_one(&fake, "alice", &write("a")).await.failed);
    assert_eq!(fake.requests(), 1);
    // The PDP is slower than the wait of a usage question.
    let fake = bound_fake();
    fake.configure(|settings| settings.usage_timeout = Duration::from_millis(200));
    fake.set_delay(Duration::from_secs(5));
    assert!(use_one(&fake, "alice", &write("a")).await.failed);
    assert_eq!(fake.requests(), 1);
    // The wait of a usage question is usage_timeout, not timeout.
    let fake = bound_fake();
    fake.configure(|settings| settings.timeout = Duration::from_millis(100));
    fake.set_delay(Duration::from_millis(300));
    fake.set_answer(|_| json!({"decision": true, "context": {"usage": {"units": 1}}}));
    let got = use_one(&fake, "alice", &write("a")).await;
    assert!(!got.failed && got.decision);
}

#[tokio::test]
async fn a_question_without_usage_is_never_sent_again() {
    let fake = bound_fake();
    fake.set_close_connection(true);
    assert!(decide_one(&fake, "alice", &read("a")).await.failed);
    assert_eq!(fake.requests(), 1);
}

#[tokio::test]
async fn the_wait_of_a_usage_question_is_longer_than_the_time_that_the_pdp_publishes() {
    let fake = bound_fake();
    fake.configure(|settings| {
        settings.usage_timeout = Duration::from_secs(6);
        settings.usage_max_seconds = Some(8);
    });
    fake.set_delay(Duration::from_millis(8500));
    fake.set_answer(|_| json!({"decision": true, "context": {"usage": {"units": 1}}}));
    assert!(!use_one(&fake, "alice", &write("a")).await.failed);
    fake.set_delay(Duration::from_millis(9500));
    assert!(use_one(&fake, "alice", &write("a")).await.failed);
    // Without the time of the PDP, the wait is usage_timeout.
    let fake = bound_fake();
    fake.set_answer(|_| json!({"decision": true, "context": {"usage": {"units": 1}}}));
    fake.set_delay(Duration::from_millis(5900));
    assert!(!use_one(&fake, "alice", &write("a")).await.failed);
    fake.set_delay(Duration::from_millis(6100));
    assert!(use_one(&fake, "alice", &write("a")).await.failed);
}

#[tokio::test]
async fn a_kept_answer_serves_the_same_question() {
    let fake = kept_fake();
    fake.set_answer(|_| json!({"decision": true, "context": {"limits": {"max_object_size": 100}}}));
    let first = decide_one(&fake, "alice", &read("a")).await;
    let second = decide_one(&fake, "alice", &read("a")).await;
    assert_eq!(first, second);
    assert_eq!(second.limits["max_object_size"], 100);
    assert_eq!(fake.requests(), 1);
    // A false answer with a reason is kept too.
    fake.set_answer(|_| json!({"decision": false, "context": {"reason": "budget_exceeded", "retry_after": 12}}));
    decide_one(&fake, "alice", &read("b")).await;
    let hit = decide_one(&fake, "alice", &read("b")).await;
    assert_eq!((hit.reason.as_str(), hit.retry_after), ("budget_exceeded", 12));
    assert_eq!(fake.requests(), 2);
}

#[tokio::test]
async fn the_key_of_a_kept_answer_has_each_part() {
    let fake = kept_fake();
    decide_one(&fake, "alice", &read("a")).await;
    let other_chain = Ask {
        action: "object.read".to_owned(),
        resource: key_resource("svc", "other", "a/x").path(),
    };
    let steps: Vec<(&str, &str, Ask, &str)> = vec![
        ("another subject", "bob", read("a"), "node"),
        ("another action", "alice", write("a"), "node"),
        ("another resource", "alice", read("b"), "node"),
        ("another chain", "alice", other_chain, "node"),
        ("another match", "alice", read("a"), "subtree"),
        ("an other permission", "alice", read("a"), "other"),
        (
            "a subject that looks like a key part",
            "alice\x1fobject.read",
            read("a"),
            "node",
        ),
    ];
    for (name, subject, ask, kind) in steps {
        fake.reset();
        match kind {
            "subtree" => {
                display(&fake, subject, std::slice::from_ref(&ask)).await;
            }
            "other" => {
                fake.operation("req-1", &who(subject), std::slice::from_ref(&ask), &write("z"), false)
                    .await;
            }
            _ => {
                decide_one(&fake, subject, &ask).await;
            }
        }
        let sent = fake
            .questions()
            .iter()
            .any(|question| question.action == ask.action && question.path == ask.resource);
        assert!(sent, "{name}: no kept answer serves it");
    }
}

#[tokio::test]
async fn a_cache_ttl_of_zero_keeps_nothing() {
    let fake = bound_fake();
    decide_one(&fake, "alice", &read("a")).await;
    decide_one(&fake, "alice", &read("a")).await;
    use_one(&fake, "alice", &write("a")).await;
    fake.set_answer(|_| json!({"decision": true, "context": {"usage": {"units": 0}}}));
    use_one(&fake, "alice", &write("b")).await;
    use_one(&fake, "alice", &write("b")).await;
    assert_eq!(fake.requests(), 5);
    assert_eq!(fake.kept(), 0);
}

#[tokio::test]
async fn a_kept_answer_expires_after_cache_ttl() {
    let fake = kept_fake();
    decide_one(&fake, "alice", &read("a")).await;
    fake.advance(Duration::from_secs(29));
    decide_one(&fake, "alice", &read("a")).await;
    assert_eq!(fake.requests(), 1);
    fake.advance(Duration::from_secs(1));
    decide_one(&fake, "alice", &read("a")).await;
    assert_eq!(fake.requests(), 2);
}

#[tokio::test]
async fn a_failure_is_never_kept() {
    let fake = kept_fake();
    fake.set_status(500);
    assert!(decide_one(&fake, "alice", &read("a")).await.failed);
    fake.reset();
    let got = decide_one(&fake, "alice", &read("a")).await;
    assert!(!got.failed && got.decision);
    assert_eq!(fake.requests(), 1);
    // A batch with a failed item keeps nothing.
    fake.set_raw(br#"{"evaluations":[{"decision":true},{"decision":"x"}]}"#);
    let got = display(&fake, "alice", &[read("b"), read("c")]).await;
    assert!(got[0].failed && got[1].failed);
    fake.reset();
    let again = display(&fake, "alice", &[read("b"), read("c")]).await;
    assert!(!again[0].failed && !again[1].failed);
    assert_eq!(fake.questions().len(), 2, "b and c go again");
    // A failed use is not kept.
    fake.set_status(503);
    assert!(use_one(&fake, "alice", &write("a")).await.failed);
    fake.reset();
    fake.set_answer(|_| json!({"decision": true, "context": {"usage": {"units": 0}}}));
    assert!(!use_one(&fake, "alice", &write("a")).await.failed);
    assert_eq!(fake.requests(), 1);
}

#[tokio::test]
async fn the_kept_answers_of_a_usage_question() {
    // A true answer with units 1 is never kept.
    let fake = kept_fake();
    fake.set_answer(|_| json!({"decision": true, "context": {"usage": {"units": 1}}}));
    for _ in 0..3 {
        assert_eq!(use_one(&fake, "alice", &write("a")).await.units, Some(1));
    }
    assert_eq!(fake.requests(), 3);

    // A true answer with units 0 is kept for cache_ttl.
    let fake = kept_fake();
    fake.set_answer(
        |_| json!({"decision": true, "context": {"usage": {"units": 0}, "limits": {"max_object_size": 5}}}),
    );
    use_one(&fake, "alice", &write("a")).await;
    let got = use_one(&fake, "alice", &write("a")).await;
    assert_eq!(got.units, Some(0));
    assert_eq!(got.limits["max_object_size"], 5);
    assert_eq!(fake.requests(), 1);
    use_one(&fake, "bob", &write("a")).await;
    assert_eq!(fake.requests(), 2, "another subject has no hit");
    fake.advance(Duration::from_secs(30));
    use_one(&fake, "alice", &write("a")).await;
    assert_eq!(fake.requests(), 3);

    // A false answer without budget_exceeded counted nothing: it serves as the answer without usage, and a kept
    // false answer refuses the next use with no question (ProcurAuth 10.1). A true answer without units is not kept.
    let fake = kept_fake();
    fake.set_answer(|_| json!({"decision": false}));
    use_one(&fake, "alice", &write("a")).await;
    assert!(!use_one(&fake, "alice", &write("a")).await.decision);
    assert_eq!(fake.requests(), 1);
    fake.set_answer(|_| json!({"decision": true}));
    assert!(!use_one(&fake, "alice", &write("b")).await.decision);
    use_one(&fake, "alice", &write("b")).await;
    assert_eq!(fake.requests(), 3);
}

#[tokio::test]
async fn a_used_budget_is_kept_and_gives_the_time_that_remains() {
    let fake = kept_fake();
    fake.set_answer(|_| json!({"decision": false, "context": {"reason": "budget_exceeded", "retry_after": 12}}));
    assert_eq!(use_one(&fake, "alice", &write("a")).await.retry_after, 12);
    assert_eq!(use_one(&fake, "alice", &write("a")).await.retry_after, 12);
    fake.advance(Duration::from_secs(5));
    assert_eq!(use_one(&fake, "alice", &write("a")).await.retry_after, 7);
    fake.advance(Duration::from_millis(6500));
    assert_eq!(use_one(&fake, "alice", &write("a")).await.retry_after, 1);
    fake.advance(Duration::from_millis(500));
    use_one(&fake, "alice", &write("a")).await;
    assert_eq!(fake.requests(), 2);

    // The answer stays for the lower of retry_after and cache_ttl. A hit gives the seconds to the end of the window
    // of the budget.
    let fake = kept_fake();
    fake.set_answer(|_| json!({"decision": false, "context": {"reason": "budget_exceeded", "retry_after": 100}}));
    use_one(&fake, "alice", &write("a")).await;
    fake.advance(Duration::from_secs(10));
    assert_eq!(use_one(&fake, "alice", &write("a")).await.retry_after, 90);
    fake.advance(Duration::from_secs(20));
    use_one(&fake, "alice", &write("a")).await;
    assert_eq!(fake.requests(), 2);
}

#[tokio::test]
async fn a_plain_answer_never_answers_a_usage_question_and_the_reverse() {
    let fake = kept_fake();
    fake.set_answer(|q| {
        if q.usage {
            json!({"decision": true, "context": {"usage": {"units": 0}}})
        } else {
            json!({"decision": true})
        }
    });
    decide_one(&fake, "alice", &write("a")).await;
    assert_eq!(use_one(&fake, "alice", &write("a")).await.units, Some(0));
    use_one(&fake, "alice", &write("b")).await;
    decide_one(&fake, "alice", &write("b")).await;
    assert_eq!(fake.requests(), 4);
    assert_eq!(
        fake.questions().iter().map(|q| q.usage).collect::<Vec<_>>(),
        vec![false, true, true, false]
    );
}

#[tokio::test]
async fn the_kept_answers_are_bounded() {
    let fake = kept_fake();
    fake.configure(|settings| settings.max_entries = 2);
    decide_one(&fake, "alice", &read("a")).await;
    decide_one(&fake, "alice", &read("b")).await;
    decide_one(&fake, "alice", &read("c")).await;
    decide_one(&fake, "alice", &read("c")).await;
    assert_eq!(fake.requests(), 4, "c is not kept in a full table");
    decide_one(&fake, "alice", &read("a")).await;
    assert_eq!(fake.requests(), 4, "a stays");
    // When full, the expired entries leave first.
    fake.advance(Duration::from_secs(31));
    decide_one(&fake, "alice", &read("c")).await;
    decide_one(&fake, "alice", &read("c")).await;
    assert_eq!(fake.requests(), 5);
    assert_eq!(fake.kept(), 1);
}

#[tokio::test]
async fn the_body_of_a_question_has_the_form_of_authzen() {
    let fake = bound_fake();
    display(
        &fake,
        "alice",
        &[Ask {
            action: "object.read".to_owned(),
            resource: bucket_resource("svc", "logs").path(),
        }],
    )
    .await;
    fake.operation("rid", &who("alice"), &[read("a"), read("b")], &write("c"), true)
        .await;
    let raw = fake.raw_requests();
    assert_eq!(raw[0].path, EVALUATION_PATH);
    assert_eq!(
        raw[0].body,
        json!({
            "subject": {"type": "user", "id": "alice"},
            "action": {"name": "object.read"},
            "resource": {"type": "bucket", "id": "logs", "properties": {"ancestors": [{"type": "service", "id": "svc"}]}},
            "context": {"match": "subtree"},
        })
    );
    assert_eq!(raw[1].path, EVALUATIONS_PATH);
    assert_eq!(raw[1].body["context"], json!({"permission_only": true}));
    assert_eq!(raw[1].body["evaluations"].as_array().unwrap().len(), 2);
    assert!(raw[1].body["evaluations"][0].get("subject").is_none());
    assert_eq!(raw[2].path, EVALUATION_PATH);
    assert_eq!(raw[2].body["context"], json!({"usage": {"units": 1}}));
    // Each request has the request id of the call.
    assert!(
        fake.questions()[1..]
            .iter()
            .all(|question| question.request_id == "rid")
    );
}

#[test]
fn the_fake_checks_the_token_of_its_header_only() {
    let fake = FakePdp::new();
    fake.accept_token("good", "user-1", "boss");
    fake.refuse_token("old", "expired");
    let headers = |values: &[&str]| {
        let mut headers = HeaderMap::new();
        for value in values {
            headers.append("x-identity-token", http::HeaderValue::from_str(value).unwrap());
        }
        headers
    };
    assert_eq!(
        fake.authenticate(&headers(&["good"])),
        Ok(Some(Identity {
            subject: "user-1".to_owned(),
            owner: "boss".to_owned(),
            issued_at: 1_800_000_000,
            expires_at: 1_800_000_300,
        }))
    );
    assert_eq!(fake.authenticate(&headers(&[])), Err("missing".to_owned()));
    assert_eq!(
        fake.authenticate(&headers(&["good", "good"])),
        Err("malformed".to_owned())
    );
    assert_eq!(fake.authenticate(&headers(&["old"])), Err("expired".to_owned()));
    assert_eq!(fake.authenticate(&headers(&["other"])), Err("malformed".to_owned()));
}

#[tokio::test]
async fn a_fake_without_a_configuration_gives_failures() {
    let fake = FakePdp::new();
    assert!(decide_one(&fake, "alice", &read("a")).await.failed);
    assert_eq!(fake.requests(), 0);
}
