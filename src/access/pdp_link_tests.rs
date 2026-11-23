// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tests of the transport of the guard: the request id, the waits, the deadline of a call and the journal.

use std::sync::Mutex;

use procurauth_pep::clock::ManualClock;
use serde_json::json;

use super::*;

/// One request: the URL, the headers and the wait.
type Sent = (String, Vec<(String, String)>, Duration);

/// A transport that records each request and gives one answer.
struct Recorder {
    sent: Mutex<Vec<Sent>>,
    answer: Result<HttpResponse, TransportError>,
    clock: ManualClock,
    delay_ms: u64,
}

impl Recorder {
    fn new(status: u16, body: &str) -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            answer: Ok(HttpResponse {
                status,
                headers: Vec::new(),
                body: body.as_bytes().to_vec(),
            }),
            clock: ManualClock::at_seconds(1000),
            delay_ms: 0,
        }
    }

    fn sent(&self) -> Vec<Sent> {
        self.sent.lock().unwrap().clone()
    }
}

impl PdpTransport for Recorder {
    fn supports_scheme(&self, scheme: &str) -> bool {
        scheme == "http"
    }

    fn post_json(
        &self,
        url: &str,
        headers: &[(String, String)],
        _body: &[u8],
        timeout: Duration,
    ) -> Result<HttpResponse, TransportError> {
        self.sent
            .lock()
            .unwrap()
            .push((url.to_owned(), headers.to_vec(), timeout));
        self.clock.advance_millis(self.delay_ms);
        self.answer.clone()
    }

    fn get_json(
        &self,
        url: &str,
        headers: &[(String, String)],
        timeout: Duration,
    ) -> Result<HttpResponse, TransportError> {
        self.sent
            .lock()
            .unwrap()
            .push((url.to_owned(), headers.to_vec(), timeout));
        self.answer.clone()
    }
}

fn link(recorder: &Arc<Recorder>) -> LinkTransport {
    LinkTransport::new(
        Arc::clone(recorder) as Arc<dyn PdpTransport>,
        Arc::new(recorder.clock.clone()),
        Duration::from_millis(500),
        Duration::from_secs(6),
    )
}

fn single(context: serde_json::Value) -> Vec<u8> {
    json!({
        "subject": {"type": "user", "id": "alice"},
        "action": {"name": "object.read"},
        "resource": {"type": "folder", "id": "team a", "properties": {"ancestors": [
            {"type": "service", "id": "svc"}, {"type": "bucket", "id": "b"}
        ]}},
        "context": context,
    })
    .to_string()
    .into_bytes()
}

fn batch(count: usize) -> Vec<u8> {
    let items: Vec<serde_json::Value> = (0..count)
        .map(|index| {
            json!({"action": {"name": "object.read"}, "resource": {"type": "bucket", "id": format!("b{index}"),
                "properties": {"ancestors": [{"type": "service", "id": "svc"}]}}})
        })
        .collect();
    json!({"subject": {"type": "user", "id": "alice"}, "context": {"permission_only": true}, "evaluations": items})
        .to_string()
        .into_bytes()
}

fn ask(action: &str, resource: &str) -> Ask {
    Ask {
        action: action.to_owned(),
        resource: resource.to_owned(),
    }
}

#[test]
fn the_body_of_a_request_gives_its_kind_and_its_questions() {
    let body: Value = serde_json::from_slice(&single(json!({"match": "subtree"}))).unwrap();
    let (kind, questions, batched) = describe(&body);
    assert_eq!(
        kind,
        Kind {
            subtree: true,
            ..Kind::default()
        }
    );
    assert!(!batched);
    assert_eq!(
        questions,
        vec![Asked {
            action: "object.read".to_owned(),
            resource: "service:svc/bucket:b/folder:team%20a".to_owned(),
        }]
    );
    let body: Value = serde_json::from_slice(&batch(2)).unwrap();
    let (kind, questions, batched) = describe(&body);
    assert!(kind.permission_only && !kind.usage && batched);
    assert_eq!(questions[1].resource, "service:svc/bucket:b1");
    let body: Value = serde_json::from_slice(&single(json!({"usage": {"units": 1}}))).unwrap();
    assert!(describe(&body).0.usage);
    // The service node has no ancestors.
    let body = json!({"action": {"name": "access"}, "resource": {"type": "service", "id": "svc"}});
    assert_eq!(describe(&body).1[0].resource, "service:svc");
    assert!(describe(&body).0.is_plain_node());
}

#[test]
fn an_answer_follows_the_rules_of_the_library() {
    assert_eq!(parse_answer(&json!({"decision": true}), false), Some(Answer::allow()));
    assert_eq!(parse_answer(&json!({"decision": true}), true), Some(Answer::default()));
    assert_eq!(
        parse_answer(&json!({"decision": false, "context": {"limits": "x"}}), false),
        Some(Answer::default())
    );
    assert_eq!(
        parse_answer(
            &json!({"decision": false, "context": {"reason": "budget_exceeded", "retry_after": 4}}),
            true
        ),
        Some(Answer {
            retry_after: 4,
            ..Answer::deny("budget_exceeded")
        })
    );
    assert_eq!(parse_answer(&json!({"decision": "true"}), false), None);
    assert_eq!(
        parse_answer(&json!({"decision": true, "context": {"usage": {"units": 2}}}), true),
        None
    );
}

#[test]
fn each_request_of_a_call_has_the_request_id_and_goes_in_the_journal() {
    let recorder = Arc::new(Recorder::new(
        200,
        r#"{"decision":false,"context":{"reason":"approval_required"}}"#,
    ));
    let transport = link(&recorder);
    let ((), journal) = journaled("rid-1", || {
        let _ = transport.post_json(
            "http://pdp/access/v1/evaluation",
            &[],
            &single(json!({"permission_only": true})),
            Duration::from_millis(500),
        );
        let _ = transport.get_json(
            "http://pdp/.well-known/authzen-configuration",
            &[],
            Duration::from_secs(1),
        );
    });
    let sent = recorder.sent();
    assert_eq!(sent.len(), 2);
    for (_, headers, _) in &sent {
        assert!(headers.contains(&("X-Request-ID".to_owned(), "rid-1".to_owned())));
    }
    assert_eq!(
        journal.records.len(),
        1,
        "a metadata document with the status 200 is no failure"
    );
    let other = ask("object.read", "service:svc/bucket:b/folder:team%20a");
    assert_eq!(
        journal.answer(&other, |kind| kind.permission_only),
        Some(Some(Answer::deny("approval_required")))
    );
    assert_eq!(journal.answer(&other, |kind| !kind.permission_only), None);
    assert!(!journal.asked(&ask("object.write", &other.resource), |_| true));
    // Outside a call: no request id and no journal.
    let _ = transport.post_json(
        "http://pdp/access/v1/evaluation",
        &[],
        &single(json!({})),
        Duration::from_millis(500),
    );
    assert!(recorder.sent()[2].1.is_empty());
}

#[test]
fn a_usage_question_waits_at_least_usage_timeout() {
    let recorder = Arc::new(Recorder::new(
        200,
        r#"{"decision":true,"context":{"usage":{"units":1}}}"#,
    ));
    let transport = link(&recorder);
    let usage = single(json!({"usage": {"units": 1}}));
    let ((), _) = journaled("rid", || {
        let _ = transport.post_json("http://pdp/e", &[], &usage, Duration::from_secs(2));
        let _ = transport.post_json("http://pdp/e", &[], &usage, Duration::from_secs(9));
    });
    let waits: Vec<Duration> = recorder.sent().iter().map(|(_, _, wait)| *wait).collect();
    assert_eq!(waits, vec![Duration::from_secs(6), Duration::from_secs(9)]);
}

#[test]
fn one_deadline_covers_the_requests_of_one_kind_in_a_call() {
    let mut recorder = Recorder::new(200, r#"{"evaluations":[{"decision":true},{"decision":true}]}"#);
    recorder.delay_ms = 300;
    let recorder = Arc::new(recorder);
    let transport = link(&recorder);
    let ((), journal) = journaled("rid", || {
        let first = transport.post_json("http://pdp/es", &[], &batch(2), Duration::from_millis(500));
        assert!(first.is_ok());
        let second = transport.post_json("http://pdp/es", &[], &batch(2), Duration::from_millis(500));
        assert!(second.is_ok());
        // The deadline is past: the request does not leave.
        let third = transport.post_json("http://pdp/es", &[], &batch(2), Duration::from_millis(500));
        assert_eq!(third, Err(TransportError::Timeout));
        // Another kind has its own deadline.
        let other = transport.post_json(
            "http://pdp/e",
            &[],
            &single(json!({"match": "subtree"})),
            Duration::from_millis(500),
        );
        assert!(other.is_ok());
    });
    let waits: Vec<Duration> = recorder.sent().iter().map(|(_, _, wait)| *wait).collect();
    assert_eq!(
        waits,
        vec![
            Duration::from_millis(500),
            Duration::from_millis(200),
            Duration::from_millis(500)
        ]
    );
    assert_eq!(journal.records.len(), 4);
    assert!(matches!(
        journal.records[2].outcome,
        Outcome::Failed { status: None, .. }
    ));
}

#[test]
fn the_journal_reads_each_failure() {
    let cases: Vec<(Result<HttpResponse, TransportError>, Vec<u8>, bool)> = vec![
        (Err(TransportError::Lost("x".to_owned())), batch(2), false),
        (
            Ok(HttpResponse {
                status: 401,
                headers: Vec::new(),
                body: Vec::new(),
            }),
            batch(2),
            false,
        ),
        (
            Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: br#"{"evaluations":[{"decision":true}]}"#.to_vec(),
            }),
            batch(2),
            false,
        ),
        (
            Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: b"nope".to_vec(),
            }),
            single(json!({})),
            false,
        ),
        (
            Ok(HttpResponse {
                status: 200,
                headers: Vec::new(),
                body: br#"{"evaluations":[{"decision":true},{"decision":7}]}"#.to_vec(),
            }),
            batch(2),
            true,
        ),
    ];
    for (index, (answer, body, items)) in cases.into_iter().enumerate() {
        let mut recorder = Recorder::new(200, "");
        recorder.answer = answer;
        let recorder = Arc::new(recorder);
        let transport = link(&recorder);
        let ((), journal) = journaled("rid", || {
            let _ = transport.post_json("http://pdp/x", &[], &body, Duration::from_millis(500));
        });
        match &journal.records[0].outcome {
            Outcome::Answers(answers) => {
                assert!(items, "case {index}");
                assert_eq!(answers, &vec![Some(Answer::allow()), None]);
            }
            Outcome::Failed { status, .. } => {
                assert!(!items, "case {index}");
                assert_eq!(*status, (index == 1).then_some(401), "case {index}");
            }
        }
    }
    // A metadata read that fails goes in the journal.
    let recorder = Arc::new(Recorder::new(500, ""));
    let transport = link(&recorder);
    let ((), journal) = journaled("rid", || {
        let _ = transport.get_json("http://pdp/m", &[], Duration::from_secs(1));
    });
    assert_eq!(
        journal.records[0].outcome,
        Outcome::Failed {
            status: Some(500),
            error: "metadata: HTTP status 500".to_owned()
        }
    );
    // 404 means a PDP without metadata: no failure.
    let recorder = Arc::new(Recorder::new(404, ""));
    let transport = link(&recorder);
    let ((), journal) = journaled("rid", || {
        let _ = transport.get_json("http://pdp/m", &[], Duration::from_secs(1));
    });
    assert!(journal.records.is_empty());
}
