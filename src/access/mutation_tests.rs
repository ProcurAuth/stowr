//! The tests of the operations of the change routes, of the jobs and of the continuations.

use serde_json::json;

use super::*;
use crate::access::test_support::*;
use crate::access::{ACTION_LOCK, Ask};
use crate::jobs::IntegrityRequest;

fn ask(action: &str, path: &str) -> Ask {
    Ask {
        action: action.to_owned(),
        resource: path.to_owned(),
    }
}

#[test]
fn each_change_route_has_its_others_and_its_use() {
    let env = Env::new();
    let layer = &env.layer;
    let rw = &env.rw;
    let other = folder("other");
    let cases: Vec<(&str, Operation, Vec<Ask>, Ask)> = vec![
        (
            "put",
            layer.use_operation(ACTION_WRITE, rw, "other/new.txt"),
            vec![],
            ask(ACTION_WRITE, &other),
        ),
        (
            "put of a folder",
            layer.use_operation(ACTION_WRITE, rw, "other/sub/"),
            vec![],
            ask(ACTION_WRITE, &format!("{other}/subfolder:sub")),
        ),
        (
            "delete",
            layer.use_operation(ACTION_DELETE, rw, "folder/direct.txt"),
            vec![],
            ask(ACTION_DELETE, FOLDER),
        ),
        (
            "copy",
            layer.copy_operation(rw, "folder/direct.txt", "other/copy.txt"),
            vec![ask(ACTION_READ, FOLDER)],
            ask(ACTION_WRITE, &other),
        ),
        (
            "copy of a prefix",
            layer.copy_operation(rw, "folder/nested/", "copied/"),
            vec![ask(ACTION_READ, SUBFOLDER)],
            ask(ACTION_WRITE, &folder("copied")),
        ),
        (
            "rename",
            layer.move_operation(rw, "folder/direct.txt", "other/moved.txt"),
            vec![ask(ACTION_READ, FOLDER), ask(ACTION_WRITE, &other)],
            ask(ACTION_DELETE, FOLDER),
        ),
        (
            "rename of a prefix",
            layer.move_operation(rw, "folder/nested/", "moved/"),
            vec![ask(ACTION_READ, SUBFOLDER), ask(ACTION_WRITE, &folder("moved"))],
            ask(ACTION_DELETE, SUBFOLDER),
        ),
        (
            "delete prefix",
            layer.delete_prefix_operation(rw, "folder/nested/"),
            vec![ask(ACTION_READ, SUBFOLDER)],
            ask(ACTION_DELETE, SUBFOLDER),
        ),
        (
            "versions restore",
            layer.restore_operation(rw, "folder/direct.txt"),
            vec![ask(ACTION_READ, FOLDER)],
            ask(ACTION_WRITE, FOLDER),
        ),
        (
            "tags bulk",
            layer.write_prefix_operation(rw, "folder/"),
            vec![ask(ACTION_READ, FOLDER)],
            ask(ACTION_WRITE, FOLDER),
        ),
        (
            "object lock",
            layer.use_operation(ACTION_LOCK, rw, "folder/direct.txt"),
            vec![],
            ask(ACTION_LOCK, FOLDER),
        ),
        (
            "lifecycle",
            layer.lifecycle_operation(rw),
            vec![ask(ACTION_READ, BUCKET), ask(ACTION_DELETE, BUCKET)],
            ask(ACTION_BUCKET_ADMIN, BUCKET),
        ),
        (
            "abort of a list of uploads",
            layer.abort_uploads_operation(rw, &["folder/a.bin".to_owned(), "other/b.bin".to_owned()]),
            vec![ask(ACTION_WRITE, &other)],
            ask(ACTION_WRITE, FOLDER),
        ),
        (
            "archive extract",
            layer.extract_operation(rw, "folder/a.zip", rw, "extracted/"),
            vec![ask(ACTION_READ, FOLDER), ask(ACTION_READ, &folder("extracted"))],
            ask(ACTION_WRITE, &folder("extracted")),
        ),
    ];
    for (name, operation, others, use_ask) in cases {
        assert_eq!(operation.others, others, "{name}");
        assert_eq!(operation.use_ask, use_ask, "{name}");
        assert!(!operation.continuation, "{name}");
    }
    assert_eq!(
        layer.abort_uploads_operation(rw, &[]).use_ask,
        ask(ACTION_WRITE, BUCKET)
    );
}

#[tokio::test]
async fn a_change_route_asks_its_others_then_its_use_with_usage() {
    let env = Env::new();
    env.fake.set_answer(usage_answer(true));
    env.layer
        .authorize(
            &env.ctx("rid"),
            env.layer
                .move_operation(&env.rw, "folder/direct.txt", "other/moved.txt"),
        )
        .await
        .unwrap();
    assert_eq!(
        summarize(&env.fake.questions()),
        vec![
            summary(ACTION_READ, FOLDER, false, true, true),
            summary(ACTION_WRITE, &folder("other"), false, true, true),
            summary(ACTION_DELETE, FOLDER, true, false, false),
        ]
    );

    // A refusal of the use with usage gives 403 with the action of the use.
    env.fake.reset();
    env.fake.set_answer(|q| {
        if q.usage {
            json!({"decision": false})
        } else {
            json!({"decision": true})
        }
    });
    let error = env
        .layer
        .authorize(&env.ctx("rid"), env.layer.lifecycle_operation(&env.rw))
        .await
        .unwrap_err();
    assert_eq!(error.as_api().unwrap().action.as_deref(), Some(ACTION_BUCKET_ADMIN));
    assert!(is_forbidden_error(&error));
}

#[tokio::test]
async fn a_continuation_asks_the_use_without_usage() {
    let env = Env::new();
    assert!(env.layer.document.lists_budget(ACTION_WRITE));
    env.fake.set_answer(usage_answer(true));
    let operation = Operation {
        others: vec![env.ask(ACTION_READ, "a/x")],
        use_ask: env.ask(ACTION_WRITE, "b/y"),
        continuation: false,
    };
    env.layer
        .authorize_continuation(&env.ctx("rid-c1"), operation.clone())
        .await
        .unwrap();
    assert_eq!(
        summarize(&env.fake.questions()),
        vec![
            summary(ACTION_READ, &folder("a"), false, false, true),
            summary(ACTION_WRITE, &folder("b"), false, false, false),
        ]
    );
    assert_eq!(env.fake.requests(), 2);

    // Without others: one question, not a batch, no usage.
    env.fake.reset();
    let alone = Operation {
        others: Vec::new(),
        ..operation.clone()
    };
    env.layer
        .authorize_continuation(&env.ctx("rid-c2"), alone.clone())
        .await
        .unwrap();
    assert_eq!(
        summarize(&env.fake.questions()),
        vec![summary(ACTION_WRITE, &folder("b"), false, false, false)]
    );

    // A use that is not a continuation still asks usage.
    env.fake.reset();
    env.layer.authorize(&env.ctx("rid-c3"), alone).await.unwrap();
    assert_eq!(
        summarize(&env.fake.questions()),
        vec![summary(ACTION_WRITE, &folder("b"), true, false, false)]
    );
}

#[tokio::test]
async fn an_upload_asks_one_usage_question_and_its_continuations_ask_none() {
    let env = Env::new();
    env.fake.set_answer(usage_answer(true));
    env.layer
        .authorize_upload(&env.ctx("rid"), &env.rw, "other/up.bin", false)
        .await
        .unwrap();
    env.layer
        .authorize_upload(&env.ctx("rid"), &env.rw, "other/up.bin", true)
        .await
        .unwrap();
    assert_eq!(
        summarize(&env.fake.questions()),
        vec![
            summary(ACTION_WRITE, &folder("other"), true, false, false),
            summary(ACTION_WRITE, &folder("other"), false, false, false),
        ]
    );
    // A refusal of a continuation keeps its status: 403, 429 or 503.
    env.fake
        .set_answer(|_| json!({"decision": false, "context": {"reason": "budget_exceeded", "retry_after": 4}}));
    let error = env
        .layer
        .authorize_upload(&env.ctx("rid"), &env.rw, "other/up.bin", true)
        .await
        .unwrap_err();
    assert_eq!(error.status(), 429);
    env.fake.set_status(500);
    let error = env
        .layer
        .authorize_upload(&env.ctx("rid"), &env.rw, "other/up.bin", true)
        .await
        .unwrap_err();
    assert_eq!(error.status(), 503);
}

#[test]
fn each_job_type_has_the_operation_of_its_route() {
    let env = Env::new();
    let instances = env.instances();
    let readonly_folder = |name: &str| format!("service:svc-1/bucket:readonly/folder:{name}");
    let job = |job_type: &str, source: &str, target: &str, prefix: &str| JobState {
        job_type: job_type.to_owned(),
        instance: "rw".to_owned(),
        source: source.to_owned(),
        target: target.to_owned(),
        prefix: prefix.to_owned(),
        ..JobState::default()
    };
    let integrity = JobState {
        integrity_request: Some(IntegrityRequest {
            key: "folder/direct.txt".to_owned(),
            ..IntegrityRequest::default()
        }),
        ..job(job_type::INTEGRITY, "", "", "")
    };
    let extraction = JobState {
        target_instance: "readonly".to_owned(),
        ..job(job_type::EXTRACT_ARCHIVE, "folder/a.zip", "out/", "")
    };
    let cases: Vec<(&str, JobState, Vec<Ask>, Ask)> = vec![
        (
            "copy prefix",
            job(job_type::COPY_PREFIX, "folder/nested/", "copied/", ""),
            vec![ask(ACTION_READ, SUBFOLDER)],
            ask(ACTION_WRITE, &folder("copied")),
        ),
        (
            "copy object",
            job(job_type::COPY_OBJECT, "folder/a.bin", "copied/a.bin", ""),
            vec![ask(ACTION_READ, FOLDER)],
            ask(ACTION_WRITE, &folder("copied")),
        ),
        (
            "move prefix",
            job(job_type::MOVE_PREFIX, "folder/nested/", "moved/", ""),
            vec![ask(ACTION_READ, SUBFOLDER), ask(ACTION_WRITE, &folder("moved"))],
            ask(ACTION_DELETE, SUBFOLDER),
        ),
        (
            "move object",
            job(job_type::MOVE_OBJECT, "folder/a.bin", "moved/a.bin", ""),
            vec![ask(ACTION_READ, FOLDER), ask(ACTION_WRITE, &folder("moved"))],
            ask(ACTION_DELETE, FOLDER),
        ),
        (
            "delete prefix",
            job(job_type::DELETE_PREFIX, "", "", "folder/"),
            vec![ask(ACTION_READ, FOLDER)],
            ask(ACTION_DELETE, FOLDER),
        ),
        (
            "bulk tags",
            job(job_type::TAG_PREFIX, "", "", "folder/"),
            vec![ask(ACTION_READ, FOLDER)],
            ask(ACTION_WRITE, FOLDER),
        ),
        (
            "abort of incomplete uploads",
            job(job_type::ABORT_MULTIPARTS, "", "", "folder/"),
            vec![ask(ACTION_READ, FOLDER)],
            ask(ACTION_WRITE, FOLDER),
        ),
        (
            "stats of the root",
            job(job_type::STATS_PREFIX, "", "", ""),
            vec![],
            ask(ACTION_READ, BUCKET),
        ),
        ("integrity", integrity, vec![], ask(ACTION_READ, FOLDER)),
        (
            "archive extraction to another instance",
            extraction,
            vec![ask(ACTION_READ, FOLDER), ask(ACTION_READ, &readonly_folder("out"))],
            ask(ACTION_WRITE, &readonly_folder("out")),
        ),
    ];
    for (name, job, others, use_ask) in cases {
        let operation = job_operation_in(&env.layer, &instances, &job).expect(name);
        assert_eq!(operation.others, others, "{name}");
        assert_eq!(operation.use_ask, use_ask, "{name}");
    }
}

#[test]
fn a_job_without_a_rule_has_no_operation() {
    let env = Env::new();
    let instances = env.instances();
    let job = |job_type: &str, instance: &str| JobState {
        job_type: job_type.to_owned(),
        instance: instance.to_owned(),
        ..JobState::default()
    };
    for case in [
        job("mystery", "rw"),
        job(job_type::STATS_PREFIX, "gone"),
        job(job_type::INTEGRITY, "rw"),
        job(job_type::ARCHIVE_ENTRY_INTEGRITY, "rw"),
        JobState {
            target_instance: "gone".to_owned(),
            ..job(job_type::EXTRACT_ARCHIVE, "rw")
        },
    ] {
        assert!(
            job_operation_in(&env.layer, &instances, &case).is_none(),
            "{}",
            case.job_type
        );
    }
}

#[test]
fn a_pair_of_keys_is_cleaned_and_checked() {
    assert_eq!(
        clean_object_pair("/a/x", "b\0/y").unwrap(),
        ("a/x".to_owned(), "b/y".to_owned())
    );
    let error = clean_object_pair("", "b").unwrap_err();
    assert!(error.has_code("invalid_path"));
    assert_eq!(error.public_message(), "src and dst are required");
    let error = clean_object_pair("/a", "a").unwrap_err();
    assert!(error.has_code("same_path"));
    assert_eq!(error.status(), 400);
}

#[test]
fn only_the_refusal_of_the_pdp_is_a_forbidden_error() {
    assert!(is_forbidden_error(&crate::access::forbidden(ACTION_READ)));
    assert!(!is_forbidden_error(&crate::access::pdp_unavailable(ACTION_READ)));
    assert!(!is_forbidden_error(&crate::access::approval_cannot_wait()));
    assert!(!is_forbidden_error(&Error::api(403, "permission_denied", "no")));
}
