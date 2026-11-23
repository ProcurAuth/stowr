//! The tests of the access policy of the job routes in mode `authzen`: a read and a control of a job ask the
//! operation of the job again as a continuation, a refusal gives the answer of an unknown job, and Insights asks
//! each request.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::testing::{Called, call_with};
use super::*;
use crate::access::fake::FakePdp;
use crate::access::test_support::{
    Env, FOLDER, SERVICE, SUBFOLDER, SUBJECT, answer_all, authzen_config, ctx_of, folder,
};
use crate::access::{ACTION_READ, ACTION_WRITE};
use crate::common::app::App;
use crate::common::ctx::OpCtx;
use crate::common::http::Handler;
use crate::common::time::Timestamp;
use crate::instance::budget::Budget;

/// The application in mode `authzen` over the instances of the access tests, and its fake guard.
fn authzen_app() -> (Arc<App>, Arc<FakePdp>) {
    let env = Env::new();
    let config = authzen_config(SERVICE, vec![env.readonly.cfg.clone(), env.rw.cfg.clone()], Vec::new());
    let instances = env.instances();
    let Env { layer, fake, .. } = env;
    let app = Arc::new_cyclic(|weak| App {
        config: Arc::new(config),
        instances,
        auths: BTreeMap::new(),
        jobs: JobManager::new(weak.clone(), 10),
        uploads: crate::uploads::UploadManager::new(),
        sqlite: crate::pv_data::SqliteSessions::new(),
        access: layer,
        resume_token_key: [0; 32],
    });
    (app, fake)
}

async fn call_as(app: &Arc<App>, subject: &str, method: &str, target: &str) -> Called {
    let path = target.split_once('?').map_or(target, |(path, _)| path);
    let handler: Handler = if path == "/api/stats" {
        handle_stats
    } else {
        handle_jobs
    };
    let ctx = OpCtx {
        budget: Some(Arc::new(Budget::for_request(&app.config.runtime))),
        ..ctx_of(subject, "rid-job")
    };
    call_with(handler, app, method, target, None, ctx).await
}

/// A copy job of `folder/nested/` to `copied/`, as `/api/copy` makes it. The job waits: it does not run.
fn copy_job(app: &App) -> String {
    let now = Timestamp::now();
    let job = JobState {
        id: "job_copy".to_owned(),
        job_type: job_type::COPY_PREFIX.to_owned(),
        instance: "rw".to_owned(),
        source: "folder/nested/".to_owned(),
        target: "copied/".to_owned(),
        status: job_status::PAUSED.to_owned(),
        created_at: now,
        updated_at: now,
        ..JobState::default()
    };
    app.jobs.put(job).unwrap();
    "job_copy".to_owned()
}

/// The action, the path and the usage flag of each question of the fake.
fn questions(fake: &FakePdp) -> Vec<(String, String, bool)> {
    fake.questions()
        .into_iter()
        .map(|question| (question.action, question.path, question.usage))
        .collect()
}

fn code(called: &Called) -> String {
    called.json()["error"]["code"].as_str().unwrap_or("").to_owned()
}

#[tokio::test]
async fn a_read_and_a_control_of_a_job_ask_its_operation_without_usage() {
    let (app, fake) = authzen_app();
    let id = copy_job(&app);
    let want = vec![
        (ACTION_READ.to_owned(), SUBFOLDER.to_owned(), false),
        (ACTION_WRITE.to_owned(), folder("copied"), false),
    ];
    let read = call_as(&app, SUBJECT, "GET", &format!("/api/jobs/{id}")).await;
    assert_eq!(read.status, 200, "{}", read.text);
    assert_eq!(questions(&fake), want);

    fake.reset();
    let cancel = call_as(&app, SUBJECT, "POST", &format!("/api/jobs/{id}/cancel")).await;
    assert_eq!(cancel.status, 200, "{}", cancel.text);
    assert_eq!(questions(&fake), want);
}

#[tokio::test]
async fn a_refused_job_answers_as_an_unknown_job() {
    let (app, fake) = authzen_app();
    let id = copy_job(&app);
    let unknown = call_as(&app, SUBJECT, "GET", "/api/jobs/job_nothing").await;
    assert_eq!((unknown.status, code(&unknown).as_str()), (404, "unknown_job"));
    assert!(fake.questions().is_empty(), "an unknown job asks no question");

    fake.set_answer(answer_all(false));
    for (method, target) in [
        ("GET", format!("/api/jobs/{id}")),
        ("POST", format!("/api/jobs/{id}/pause")),
        ("POST", format!("/api/jobs/{id}/resume")),
        ("POST", format!("/api/jobs/{id}/cancel")),
    ] {
        let refused = call_as(&app, SUBJECT, method, &target).await;
        assert_eq!(refused.status, 404, "{method} {target}: {}", refused.text);
        assert_eq!(refused.json(), unknown.json(), "{method} {target}");
    }
    assert!(fake.questions().iter().all(|question| !question.usage));
    assert_eq!(app.jobs.get(&id).unwrap().status, job_status::PAUSED);

    // A failure of the PDP stays 503. A budget answer stays 429.
    fake.reset();
    fake.set_status(500);
    let failure = call_as(&app, SUBJECT, "GET", &format!("/api/jobs/{id}")).await;
    assert_eq!(failure.status, 503, "{}", failure.text);
    fake.reset();
    fake.set_answer(
        |_| serde_json::json!({"decision": false, "context": {"reason": "budget_exceeded", "retry_after": 7}}),
    );
    let budget = call_as(&app, SUBJECT, "GET", &format!("/api/jobs/{id}")).await;
    assert_eq!(budget.status, 429, "{}", budget.text);
    assert_eq!(budget.headers.get("retry-after").unwrap(), "7");
}

#[tokio::test]
async fn the_job_of_another_subject_is_refused() {
    let (app, fake) = authzen_app();
    let id = copy_job(&app);
    fake.set_answer(|question| serde_json::json!({"decision": question.subject == SUBJECT}));
    let other = call_as(&app, "user-2", "GET", &format!("/api/jobs/{id}")).await;
    assert_eq!((other.status, code(&other).as_str()), (404, "unknown_job"));
    let owner = call_as(&app, SUBJECT, "GET", &format!("/api/jobs/{id}")).await;
    assert_eq!(owner.status, 200, "{}", owner.text);
    let cancel = call_as(&app, "user-2", "POST", &format!("/api/jobs/{id}/cancel")).await;
    assert_eq!(cancel.status, 404);
    assert_ne!(app.jobs.get(&id).unwrap().status, job_status::CANCELED);
}

#[tokio::test]
async fn a_job_without_a_rule_is_refused_without_a_question() {
    let (app, fake) = authzen_app();
    let now = Timestamp::now();
    for (id, kind, instance) in [
        ("job_mystery", "mystery", "rw"),
        ("job_noinstance", job_type::STATS_PREFIX, "gone"),
        ("job_norequest", job_type::INTEGRITY, "rw"),
    ] {
        app.jobs
            .put(JobState {
                id: id.to_owned(),
                job_type: kind.to_owned(),
                instance: instance.to_owned(),
                status: job_status::COMPLETED.to_owned(),
                created_at: now,
                updated_at: now,
                ..JobState::default()
            })
            .unwrap();
        fake.reset();
        fake.set_answer(answer_all(true));
        let refused = call_as(&app, SUBJECT, "GET", &format!("/api/jobs/{id}")).await;
        assert_eq!((refused.status, code(&refused).as_str()), (404, "unknown_job"), "{id}");
        assert!(fake.questions().is_empty(), "{id}");
    }
}

#[tokio::test]
async fn insights_ask_each_request_even_when_they_reuse_a_job() {
    let (app, fake) = authzen_app();
    fake.set_answer(answer_all(true));
    for round in 0..2 {
        let answer = call_as(&app, SUBJECT, "GET", "/api/stats?instance=rw&prefix=folder%2F").await;
        assert!(
            answer.status == 200 || answer.status == 202,
            "round {round}: {}",
            answer.text
        );
    }
    let asked = questions(&fake);
    assert_eq!(asked.len(), 2);
    for (action, path, usage) in asked {
        assert_eq!((action.as_str(), path.as_str(), usage), (ACTION_READ, FOLDER, false));
    }
}
