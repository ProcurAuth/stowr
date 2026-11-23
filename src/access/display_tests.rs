//! The tests of the display questions: the list of the instances, the member `access` of a listing and the
//! navigation listing.

use std::collections::BTreeSet;

use serde_json::json;

use super::*;
use crate::access::test_support::*;
use crate::access::{AccessLayer, CODE_APPROVAL_CANNOT_WAIT};
use crate::common::config::Config;
use crate::common::storage::{CapabilityState, CapabilityStateName};

fn allowed(source: &str) -> CapabilityState {
    CapabilityState {
        state: CapabilityStateName::Allowed,
        allowed: true,
        verified: true,
        source: source.to_owned(),
        ..CapabilityState::default()
    }
}

fn caps() -> Capabilities {
    Capabilities {
        read: allowed("configuration"),
        write: allowed("configuration"),
        delete: allowed("configuration"),
        ..Capabilities::default()
    }
}

#[tokio::test]
async fn the_instances_show_only_the_buckets_with_one_true_answer() {
    let env = Env::new();
    env.fake
        .set_answer(|q| json!({"decision": q.action == ACTION_READ && q.match_mode == "subtree" && q.path == BUCKET}));
    let (visible, default) = env
        .layer
        .visible_instances(&env.ctx("rid"), &env.instances())
        .await
        .unwrap();
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].instance.cfg.id, "rw");
    assert_eq!(default, "rw");
    let held = visible[0].held.clone().unwrap();
    assert_eq!(held, BTreeSet::from([ACTION_READ]));

    let shown = with_access_capabilities(&caps(), &held);
    assert_ne!(shown.read.source, "access");
    assert!(shown.read.allowed);
    for state in [&shown.write, &shown.delete] {
        assert_eq!(state.state, CapabilityStateName::Denied);
        assert_eq!(state.source, "access");
        assert!(!state.allowed);
    }
    assert_eq!(
        shown.write.reason,
        "the access policy does not give object.write in this bucket"
    );
    let operations = operations_of(&shown);
    for name in [
        "upload",
        "overwrite",
        "createFolder",
        "copy",
        "move",
        "rename",
        "delete",
    ] {
        assert_eq!(operations[name].state, CapabilityStateName::Denied, "{name}");
    }
    for name in ["upload", "delete"] {
        assert_eq!(operations[name].source, "access", "{name}");
    }
    for name in ["list", "preview", "download"] {
        assert_ne!(operations[name].state, CapabilityStateName::Denied, "{name}");
    }

    // The questions: the five actions on the bucket node of each instance, match subtree, no usage, one batch.
    let questions = env.fake.questions();
    assert_eq!(questions.len(), 10);
    let mut seen = BTreeSet::new();
    for question in &questions {
        assert_eq!(question.match_mode, "subtree");
        assert!(!question.usage && !question.permission_only && question.batch);
        assert_eq!(question.subject, SUBJECT);
        assert!(question.path == BUCKET || question.path == "service:svc-1/bucket:readonly");
        seen.insert((question.action.clone(), question.path.clone()));
    }
    assert_eq!(seen.len(), 10);
    let actions: BTreeSet<&str> = questions.iter().map(|q| q.action.as_str()).collect();
    assert_eq!(
        actions,
        BTreeSet::from([
            ACTION_BUCKET_ADMIN,
            ACTION_DELETE,
            ACTION_LOCK,
            ACTION_READ,
            ACTION_WRITE
        ])
    );
    assert_eq!(env.fake.requests(), 1);
}

#[tokio::test]
async fn the_instances_are_empty_when_each_answer_is_false() {
    let env = Env::new();
    env.fake.set_answer(answer_all(false));
    let (visible, default) = env
        .layer
        .visible_instances(&env.ctx("rid"), &env.instances())
        .await
        .unwrap();
    assert!(visible.is_empty());
    assert_eq!(default, "");
}

#[tokio::test]
async fn the_first_visible_instance_is_the_default() {
    let env = Env::new();
    env.fake
        .set_answer(|q| json!({"decision": q.action == ACTION_LOCK && q.path == "service:svc-1/bucket:readonly"}));
    let (visible, default) = env
        .layer
        .visible_instances(&env.ctx("rid"), &env.instances())
        .await
        .unwrap();
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0].instance.cfg.id, "readonly");
    assert_eq!(default, "readonly");
    // This person holds only object.lock: read, write and delete show the source access.
    let shown = with_access_capabilities(&caps(), visible[0].held.as_ref().unwrap());
    for state in [&shown.read, &shown.write, &shown.delete] {
        assert_eq!(state.state, CapabilityStateName::Denied);
        assert_eq!(state.source, "access");
    }
}

#[tokio::test]
async fn the_instances_give_503_when_the_pdp_fails() {
    let env = Env::new();
    env.fake.set_status(500);
    let error = env
        .layer
        .visible_instances(&env.ctx("rid"), &env.instances())
        .await
        .unwrap_err();
    let api = error.as_api().unwrap();
    assert_eq!((api.status, api.code.as_str()), (503, "pdp_unavailable"));
    assert_eq!(error.envelope().error.retryable, Some(true));
}

#[tokio::test]
async fn the_list_gives_the_access_member_when_the_node_is_readable() {
    let env = Env::new();
    env.fake.set_answer(|q| json!({"decision": q.action != ACTION_DELETE}));
    let display = env
        .layer
        .list_display(&env.ctx("rid"), &env.rw, "folder/")
        .await
        .unwrap();
    assert_eq!(
        display,
        ListDisplay {
            access: Some(ListAccess {
                read: true,
                write: true,
                delete: false
            }),
            navigation: false
        }
    );
    assert_eq!(
        serde_json::to_string(&display.access).unwrap(),
        r#"{"read":true,"write":true,"delete":false}"#
    );
    let questions = env.fake.questions();
    assert_eq!(questions.len(), 3);
    assert_eq!(env.fake.requests(), 1);
    for (question, action) in questions.iter().zip([ACTION_READ, ACTION_WRITE, ACTION_DELETE]) {
        assert_eq!(question.action, action);
        assert_eq!(question.path, FOLDER);
        assert_eq!(question.match_mode, "node");
        assert!(!question.usage && !question.permission_only);
    }
}

#[tokio::test]
async fn the_list_shows_the_folders_only_when_the_person_cannot_read_the_bucket() {
    let env = Env::new();
    put_object(&env.rw_backend, "tenant/root.txt", "root");
    env.fake
        .set_answer(|q| match (q.action.as_str(), q.match_mode.as_str()) {
            (ACTION_READ, "subtree") => json!({"decision": q.path == FOLDER}),
            (ACTION_WRITE, "node") => json!({"decision": true}),
            _ => json!({"decision": false}),
        });
    let display = env.layer.list_display(&env.ctx("rid"), &env.rw, "").await.unwrap();
    assert!(display.navigation);
    assert_eq!(
        display.access,
        Some(ListAccess {
            read: false,
            write: true,
            delete: false
        })
    );
    // The items of the listing: two folders and one object.
    let items = [Some("a/"), Some("folder/"), None, Some("folder/")];
    let kept = env
        .layer
        .navigation_items(&env.ctx("rid"), &env.rw, &items)
        .await
        .unwrap();
    assert_eq!(kept, vec![false, true, false, true]);

    // The questions: three on the node of the bucket, then one subtree question for each distinct folder.
    let questions = env.fake.questions();
    assert_eq!(questions.len(), 5);
    for question in &questions[..3] {
        assert_eq!((question.path.as_str(), question.match_mode.as_str()), (BUCKET, "node"));
    }
    let subtree: BTreeSet<&str> = questions[3..]
        .iter()
        .map(|q| {
            assert_eq!(
                (q.action.as_str(), q.match_mode.as_str(), q.usage),
                (ACTION_READ, "subtree", false)
            );
            q.path.as_str()
        })
        .collect();
    assert_eq!(subtree, BTreeSet::from([FOLDER, folder("a").as_str()]));
    assert_eq!(env.fake.requests(), 2);
}

#[tokio::test]
async fn the_navigation_keeps_nothing_when_no_folder_is_readable() {
    let env = Env::new();
    env.fake.set_answer(answer_all(false));
    let display = env.layer.list_display(&env.ctx("rid"), &env.rw, "").await.unwrap();
    assert!(display.navigation && !display.access.unwrap().read);
    let kept = env
        .layer
        .navigation_items(&env.ctx("rid"), &env.rw, &[Some("folder/"), None])
        .await
        .unwrap();
    assert_eq!(kept, vec![false, false]);
    // A listing of objects only asks nothing.
    env.fake.reset();
    let kept = env
        .layer
        .navigation_items(&env.ctx("rid"), &env.rw, &[None, None])
        .await
        .unwrap();
    assert_eq!(kept, vec![false, false]);
    assert_eq!(env.fake.requests(), 0);
}

#[tokio::test]
async fn the_list_gives_403_at_a_subfolder_that_the_person_cannot_read() {
    let env = Env::new();
    env.fake.set_answer(answer_all(false));
    let error = env
        .layer
        .list_display(&env.ctx("rid"), &env.rw, "folder/nested/")
        .await
        .unwrap_err();
    let api = error.as_api().unwrap();
    assert_eq!(
        (api.status, api.code.as_str(), api.action.as_deref()),
        (403, "forbidden", Some(ACTION_READ))
    );
    assert!(env.fake.questions().iter().all(|q| q.match_mode == "node"));
}

#[tokio::test]
async fn the_list_gives_a_navigation_listing_at_a_folder() {
    // A folder has a deeper type: a false answer gives a navigation listing, not a 403.
    let env = Env::new();
    env.fake.set_answer(answer_all(false));
    let display = env
        .layer
        .list_display(&env.ctx("rid"), &env.rw, "folder/")
        .await
        .unwrap();
    assert!(display.navigation);
    assert!(!display.access.unwrap().read);
}

#[tokio::test]
async fn the_list_gives_503_when_the_pdp_fails() {
    let env = Env::new();
    env.fake.set_status(500);
    let error = env.layer.list_display(&env.ctx("rid"), &env.rw, "").await.unwrap_err();
    assert!(error.has_code("pdp_unavailable"));
    let error = env
        .layer
        .navigation_items(&env.ctx("rid"), &env.rw, &[Some("folder/")])
        .await
        .unwrap_err();
    assert!(error.has_code("pdp_unavailable"));
}

#[tokio::test]
async fn the_list_checks_the_ceilings_of_a_true_read() {
    let env = Env::new();
    env.fake
        .set_answer(|_| json!({"decision": true, "context": {"limits": {"max_rows": 3}}}));
    let error = env
        .layer
        .list_display(&env.ctx("rid"), &env.rw, "folder/")
        .await
        .unwrap_err();
    assert!(error.has_code("forbidden"));
    env.fake
        .set_answer(|_| json!({"decision": true, "context": {"limits": {"max_object_size": 3}}}));
    let ctx = env.ctx("rid");
    env.layer.list_display(&ctx, &env.rw, "folder/").await.unwrap();
    assert_eq!(
        ctx.access
            .as_ref()
            .unwrap()
            .ceilings
            .get(ACTION_READ, "max_object_size"),
        Some(3)
    );
}

#[tokio::test]
async fn a_list_read_that_needs_an_approval_gives_the_fixed_403() {
    let env = Env::new();
    env.fake.set_answer(|q| {
        if q.action == ACTION_READ {
            json!({"decision": false, "context": {"reason": "approval_required"}})
        } else {
            json!({"decision": false})
        }
    });
    for prefix in ["", "folder/", "folder/nested/"] {
        let error = env
            .layer
            .list_display(&env.ctx("rid"), &env.rw, prefix)
            .await
            .unwrap_err();
        assert!(error.has_code(CODE_APPROVAL_CANNOT_WAIT), "{prefix:?}");
    }
}

#[tokio::test]
async fn the_open_mode_keeps_the_answers_without_access_member() {
    let env = Env::new();
    let layer = AccessLayer::new(&Config::default()).unwrap();
    assert_eq!(
        layer.list_display(&env.ctx("rid"), &env.rw, "").await.unwrap(),
        ListDisplay::default()
    );
    let (visible, default) = layer
        .visible_instances(&env.ctx("rid"), &env.instances())
        .await
        .unwrap();
    assert_eq!(visible.len(), 2);
    assert_eq!(default, "readonly");
    assert!(visible.iter().all(|instance| instance.held.is_none()));
}

#[test]
fn the_combination_of_states_gives_the_first_denial() {
    let denied_state = CapabilityState {
        state: CapabilityStateName::Denied,
        source: "provider".to_owned(),
        reason: "no".to_owned(),
        verified: true,
        ..CapabilityState::default()
    };
    let unknown = CapabilityState {
        state: CapabilityStateName::Unknown,
        allowed: true,
        source: "runtime".to_owned(),
        reason: "untested".to_owned(),
        ..CapabilityState::default()
    };
    let ok = allowed("configuration");
    assert_eq!(combine_states(&[&ok, &denied_state]).source, "provider");
    assert!(!combine_states(&[&ok, &denied_state]).allowed);
    let mixed = combine_states(&[&ok, &unknown, &unknown]);
    assert_eq!(mixed.state, CapabilityStateName::Unknown);
    assert_eq!((mixed.source.as_str(), mixed.reason.as_str()), ("derived", "untested"));
    let both = combine_states(&[&ok, &ok]);
    assert_eq!(both.state, CapabilityStateName::Allowed);
    assert!(both.verified);
    assert_eq!(combine_states(&[]).source, "application");
}
