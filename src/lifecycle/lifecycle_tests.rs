// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tests of the lifecycle rules: the editor, the save, the read back, the probes and the facts of the bucket.

use std::sync::Arc;
use std::time::{Duration, Instant};

use http::HeaderMap;
use serde_json::{Value, json};

use super::editor::{BUCKET_FACTS_TTL, lifecycle_document_for};
use super::fakes::{FakeS3, FakeState, WireBackend, application, call, instance, instance_config, with_versions};
use super::rules::{
    EditRule, FIELD_ABORT, FIELD_DELETE_MARKER, FIELD_NONCURRENT, FIELD_TAG, FIELDS, FLAVOUR_AWS, FLAVOUR_GARAGE,
    FLAVOUR_MINIO, FLAVOUR_SEAWEEDFS, LIFECYCLE_NAMESPACE, MAX_LIFECYCLE_DAYS, MAX_LIFECYCLE_ID_CHARS,
    edit_rule_from_node, lifecycle_hash, lifecycle_rule_xml, parse_lifecycle_rules, split_lifecycle_document,
};
use super::{Tag, s3_provider_flavour};
use crate::common::app::App;
use crate::common::config::{PERMISSION_READ, PERMISSION_WRITE};
use crate::common::ctx::OpCtx;
use crate::common::storage::Backend;
use crate::testkit::MemoryBackend;

struct Rig {
    app: Arc<App>,
    wire: Arc<FakeS3>,
}

/// The application with the fake behind the instance "rw" (root prefix `tenant/`) and the instance "readonly". The two
/// instances have versioning and tags.
fn rig_with(server: &str, body: &str, rw_permissions: Option<&[&str]>) -> Rig {
    let wire = FakeS3::new(server, body);
    let make = |id: &str, root: &str, permissions: Option<&[&str]>| {
        let backend = Arc::new(WireBackend::new(wire.clone()));
        let made = instance(instance_config(id, root, permissions), backend);
        with_versions(&made);
        made
    };
    let rw = make("rw", "tenant/", rw_permissions);
    let readonly = make("readonly", "", Some(&[PERMISSION_READ]));
    Rig {
        app: application(vec![rw, readonly]),
        wire,
    }
}

fn rig(server: &str, body: &str) -> Rig {
    rig_with(server, body, None)
}

async fn get_lifecycle(rig: &Rig, instance: &str) -> Value {
    let got = call(&rig.app, "GET", &format!("/api/lifecycle?instance={instance}"), None).await;
    assert_eq!(got.status, 200, "get = {}", got.text);
    let body = got.json();
    assert!(body.get("editor").is_some(), "the answer has no editor: {}", got.text);
    body
}

async fn editor_of(rig: &Rig, instance: &str) -> Value {
    get_lifecycle(rig, instance).await["editor"].clone()
}

async fn put_lifecycle(rig: &Rig, instance: &str, hash: &str, rules: Value) -> crate::lifecycle::fakes::Called {
    call(
        &rig.app,
        "PUT",
        "/api/lifecycle",
        Some(json!({"instance": instance, "hash": hash, "rules": rules})),
    )
    .await
}

async fn saved(rig: &Rig, instance: &str, hash: &str, rules: Value) -> Value {
    let got = put_lifecycle(rig, instance, hash, rules).await;
    assert_eq!(got.status, 200, "status = {}", got.text);
    got.json()
}

fn hash_of(editor: &Value) -> String {
    editor["hash"].as_str().unwrap().to_owned()
}

const KEPT_TRANSITION: &str = "<Rule>
    <ID>to-cold</ID><Status>Enabled</Status>
    <Filter><And><Prefix>tenant/archive/</Prefix><ObjectSizeGreaterThan>1024</ObjectSizeGreaterThan></And></Filter>
    <Transition><Days>30</Days><StorageClass>GLACIER</StorageClass></Transition>
  </Rule>";

const KEPT_OUTSIDE: &str = "<Rule><ID>other-tenant</ID><Filter><Prefix>other/</Prefix></Filter><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule>";

const EDITABLE_LOGS: &str = "<Rule><ID>logs</ID><Filter><Prefix>tenant/logs/</Prefix></Filter><Status>Enabled</Status><Expiration><Days>30</Days></Expiration></Rule>";

fn config_of(rules: &str) -> String {
    format!("<LifecycleConfiguration>{rules}</LifecycleConfiguration>")
}

// --- Helpers that change a written document, as a provider that drops a setting ------------------------------------

/// Remove each element from its start text to its end text, with the two texts.
fn remove_between(text: &str, start: &str, end: &str) -> String {
    let mut out = text.to_owned();
    while let Some(from) = out.find(start) {
        let Some(length) = out[from..].find(end) else {
            break;
        };
        out.replace_range(from..from + length + end.len(), "");
    }
    out
}

/// Remove the tag filters of a written document, as Garage v2.4.1 does: `<And>` with a prefix and a tag becomes the
/// prefix, and a filter with a tag only disappears.
fn drop_tags(_state: &mut FakeState, body: Vec<u8>) -> Vec<u8> {
    let mut text = String::from_utf8(body).unwrap();
    while let Some(from) = text.find("<And><Prefix>") {
        let prefix_end = text[from..].find("</Prefix>").unwrap() + from + "</Prefix>".len();
        let and_end = text[prefix_end..].find("</Tag></And>").unwrap() + prefix_end + "</Tag></And>".len();
        let prefix = text[from + "<And>".len()..prefix_end].to_owned();
        text.replace_range(from..and_end, &prefix);
    }
    remove_between(&text, "<Filter><Tag>", "</Tag></Filter>").into_bytes()
}

fn drop_abort_and_gone(_state: &mut FakeState, body: Vec<u8>) -> Vec<u8> {
    let text = String::from_utf8(body).unwrap();
    let text = remove_between(
        &text,
        "<AbortIncompleteMultipartUpload>",
        "</AbortIncompleteMultipartUpload>",
    );
    remove_between(&text, "<Rule><ID>gone</ID>", "</Rule>").into_bytes()
}

fn add_extra_element(_state: &mut FakeState, body: Vec<u8>) -> Vec<u8> {
    String::from_utf8(body)
        .unwrap()
        .replacen("</Rule>", "<Extra>1</Extra></Rule>", 1)
        .into_bytes()
}

fn break_the_next_read(state: &mut FakeState, body: Vec<u8>) -> Vec<u8> {
    state.lifecycle = 500;
    body
}

// --- The save --------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_save_keeps_the_other_rules_byte_for_byte() {
    let document = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<LifecycleConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n  {KEPT_TRANSITION}\n  {EDITABLE_LOGS}\n  {KEPT_OUTSIDE}\n  <FutureElement a=\"1\">kept</FutureElement>\n</LifecycleConfiguration>"
    );
    let rig = rig("SeaweedFS 30GB 4.41", &document);
    let response = get_lifecycle(&rig, "rw").await;
    let editor = &response["editor"];
    assert_eq!(editor["hash"], lifecycle_hash(document.as_bytes(), &[1]));
    assert_eq!(editor["provider"], FLAVOUR_SEAWEEDFS);
    assert_eq!(editor["writable"], true);
    assert_eq!(editor["rootPrefix"], "tenant/");
    assert_eq!(editor["entries"].as_array().unwrap().len(), 3);
    assert_eq!(response["rules"].as_array().unwrap().len(), 3);
    let first = &editor["entries"][0];
    assert_eq!(first["editable"], false);
    assert_eq!(first["xml"], KEPT_TRANSITION);
    assert_eq!(first["reason"], "It moves objects to another storage class.");
    assert_eq!(
        editor["entries"][1],
        json!({"editable": true, "rule": {"id": "logs", "enabled": true, "prefix": "logs/", "expirationDays": 30}})
    );
    let third = &editor["entries"][2];
    assert_eq!(third["editable"], false);
    assert_eq!(third["reason"], "It applies outside of the folder of this instance.");
    assert!(
        third.get("xml").is_none(),
        "the person of this instance does not see the XML of the other rule"
    );
    assert_eq!(response["rules"][2], json!({"enabled": true}));
    for field in FIELDS {
        assert_eq!(
            editor["fields"][field], true,
            "SeaweedFS with versioning and tags offers {field}: {}",
            editor["hidden"]
        );
    }
    let rules = json!([
        {"id": "logs", "enabled": false, "prefix": "logs/", "tag": {"key": "retention", "value": "30d"}, "expirationDays": 10, "noncurrentDays": 5},
        {"id": "uploads", "enabled": true, "prefix": "tmp/<a&b>", "abortMultipartDays": 3},
    ]);
    let answer = saved(&rig, "rw", &hash_of(editor), rules).await;
    assert!(answer.get("warnings").is_none(), "warnings = {}", answer["warnings"]);
    let written = rig.wire.stored();
    assert!(
        written.starts_with("<LifecycleConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">")
            && written.ends_with("</LifecycleConfiguration>"),
        "root of the written document: {written}"
    );
    for kept in [
        KEPT_TRANSITION,
        KEPT_OUTSIDE,
        "<FutureElement a=\"1\">kept</FutureElement>",
    ] {
        assert_eq!(
            written.matches(kept).count(),
            1,
            "the written document does not keep {kept:?} byte for byte:\n{written}"
        );
    }
    for part in [
        "<Rule><ID>logs</ID><Filter><And><Prefix>tenant/logs/</Prefix><Tag><Key>retention</Key><Value>30d</Value></Tag></And></Filter><Status>Disabled</Status><Expiration><Days>10</Days></Expiration><NoncurrentVersionExpiration><NoncurrentDays>5</NoncurrentDays></NoncurrentVersionExpiration></Rule>",
        "<Rule><ID>uploads</ID><Filter><Prefix>tenant/tmp/&lt;a&amp;b&gt;</Prefix></Filter><Status>Enabled</Status><AbortIncompleteMultipartUpload><DaysAfterInitiation>3</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule>",
    ] {
        assert!(written.contains(part), "the written document has no {part}:\n{written}");
    }
    assert_eq!(
        written.matches("<ID>logs</ID>").count(),
        1,
        "the edited rule is twice:\n{written}"
    );
    assert_eq!(answer["editor"]["hash"], lifecycle_hash(written.as_bytes(), &[0, 1]));
    assert_eq!(answer["editor"]["entries"].as_array().unwrap().len(), 4);
    let rule = &answer["editor"]["entries"][1]["rule"];
    assert_eq!(rule["prefix"], "tmp/<a&b>");
    assert_eq!(rule["abortMultipartDays"], 3);
    assert!(rig.wire.with(|state| state.problems.clone()).is_empty());
}

#[tokio::test]
async fn a_save_is_refused_when_the_configuration_changed_after_the_read() {
    let rig = rig("MinIO", &config_of(EDITABLE_LOGS));
    let hash = hash_of(&editor_of(&rig, "rw").await);
    rig.wire
        .set_stored(&config_of(&format!("{EDITABLE_LOGS}{KEPT_OUTSIDE}")));
    let rules = json!([{"id": "logs", "enabled": true, "prefix": "logs/", "expirationDays": 7}]);
    let got = put_lifecycle(&rig, "rw", &hash, rules.clone()).await;
    assert_eq!(got.status, 409, "status = {}", got.text);
    assert_eq!(got.code(), "lifecycle_changed");
    assert!(
        rig.wire.with(|state| state.puts.is_empty() && state.deletes == 0),
        "the refused save wrote"
    );
    // The page reads the rules again: the new hash works.
    let hash = hash_of(&editor_of(&rig, "rw").await);
    saved(&rig, "rw", &hash, rules).await;
    assert!(rig.wire.stored().contains(KEPT_OUTSIDE));
    assert!(rig.wire.stored().contains("<Days>7</Days>"));
    // A hash that is not a hash is refused before any read.
    let got = put_lifecycle(&rig, "rw", "abc", json!([])).await;
    assert_eq!(got.status, 400, "status = {}", got.text);
    assert_eq!(got.code(), "invalid_lifecycle");
}

#[tokio::test]
async fn a_save_tells_what_the_provider_dropped() {
    // A provider that Stowr does not know. A rule of the bucket uses a tag filter, so the editor offers it.
    let tagged = "<Rule><ID>tagged</ID><Filter><And><Prefix>tenant/logs/</Prefix><Tag><Key>retention</Key><Value>30d</Value></Tag></And></Filter><Status>Enabled</Status><Expiration><Days>30</Days></Expiration></Rule>";
    let rig = rig("", &config_of(tagged));
    rig.wire.with(|state| state.keep = Some(drop_tags));
    let editor = editor_of(&rig, "rw").await;
    assert_eq!(editor["provider"], "");
    assert_eq!(editor["fields"][FIELD_TAG], true, "{}", editor["hidden"]);
    assert_eq!(editor["fields"][FIELD_ABORT], false);
    assert_eq!(editor["fields"][FIELD_NONCURRENT], false);
    let rules = json!([
        {"id": "tagged", "enabled": true, "prefix": "logs/", "tag": {"key": "retention", "value": "30d"}, "expirationDays": 30},
        {"id": "only-tag", "enabled": true, "prefix": "", "tag": {"key": "tmp", "value": "yes"}, "expirationDays": 2},
    ]);
    let answer = saved(&rig, "rw", &hash_of(&editor), rules.clone()).await;
    let warnings: Vec<String> = answer["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .map(|value| value.as_str().unwrap().to_owned())
        .collect();
    let joined = warnings.join("\n");
    assert_eq!(warnings.len(), 2, "warnings = {warnings:?}");
    assert!(
        joined.contains("The storage provider dropped the tag filter retention=30d of the rule \"tagged\". The rule now applies to every object under tenant/logs/"),
        "warnings = {warnings:?}"
    );
    assert!(
        joined.contains("The storage provider dropped the tag filter tmp=yes of the rule \"only-tag\". The rule now applies to every object under tenant/:"),
        "warnings = {warnings:?}"
    );
    // The field is no longer offered, with the reason, and a save with it is refused.
    let after = &answer["editor"];
    assert_eq!(after["fields"][FIELD_TAG], false);
    assert!(
        after["hidden"][0]["reason"]
            .as_str()
            .unwrap()
            .contains("dropped this setting")
    );
    let got = put_lifecycle(&rig, "rw", &hash_of(after), rules).await;
    assert_eq!(got.status, 400, "status = {}", got.text);
    assert_eq!(got.code(), "lifecycle_field_unsupported");
}

#[tokio::test]
async fn a_save_tells_about_a_dropped_action_and_a_missing_rule() {
    let rig = rig("SeaweedFS 30GB 4.41", "");
    rig.wire.with(|state| state.keep = Some(drop_abort_and_gone));
    let editor = editor_of(&rig, "rw").await;
    assert_eq!(editor["hash"], lifecycle_hash(&[], &[]));
    assert_eq!(editor["entries"].as_array().unwrap().len(), 0);
    let rules = json!([
        {"id": "both", "enabled": true, "prefix": "a/", "expirationDays": 3, "abortMultipartDays": 2},
        {"id": "gone", "enabled": true, "prefix": "b/", "expirationDays": 4},
    ]);
    let answer = saved(&rig, "rw", &hash_of(&editor), rules).await;
    assert_eq!(
        answer["warnings"],
        json!([
            "The storage provider dropped the abort of incomplete multipart uploads of the rule \"both\".",
            "The storage provider did not keep the rule \"gone\"."
        ])
    );
    assert_eq!(
        answer["editor"]["fields"][FIELD_ABORT], false,
        "the dropped field is still offered"
    );
}

#[tokio::test]
async fn the_fields_follow_the_provider_the_versioning_and_the_tags() {
    struct Case {
        name: &'static str,
        server: &'static str,
        garage: bool,
        versioning: &'static str,
        tags_off: bool,
        provider: &'static str,
        want: Vec<&'static str>,
    }
    let cases = vec![
        Case {
            name: "aws",
            server: "AmazonS3",
            garage: false,
            versioning: "Enabled",
            tags_off: false,
            provider: FLAVOUR_AWS,
            want: FIELDS.to_vec(),
        },
        Case {
            name: "seaweedfs",
            server: "SeaweedFS 30GB 4.41",
            garage: false,
            versioning: "Suspended",
            tags_off: false,
            provider: FLAVOUR_SEAWEEDFS,
            want: FIELDS.to_vec(),
        },
        Case {
            name: "minio",
            server: "MinIO",
            garage: false,
            versioning: "Enabled",
            tags_off: false,
            provider: FLAVOUR_MINIO,
            want: vec![FIELD_TAG, FIELD_NONCURRENT, FIELD_DELETE_MARKER],
        },
        Case {
            name: "garage",
            server: "",
            garage: true,
            versioning: "",
            tags_off: false,
            provider: FLAVOUR_GARAGE,
            want: vec![FIELD_ABORT],
        },
        Case {
            name: "unknown",
            server: "",
            garage: false,
            versioning: "Enabled",
            tags_off: false,
            provider: "",
            want: vec![],
        },
        Case {
            name: "minio, no versioning",
            server: "MinIO",
            garage: false,
            versioning: "",
            tags_off: false,
            provider: FLAVOUR_MINIO,
            want: vec![FIELD_TAG],
        },
        Case {
            name: "aws, no tags",
            server: "AmazonS3",
            garage: false,
            versioning: "Enabled",
            tags_off: true,
            provider: FLAVOUR_AWS,
            want: vec![FIELD_NONCURRENT, FIELD_ABORT, FIELD_DELETE_MARKER],
        },
    ];
    for case in cases {
        let rig = rig(case.server, "");
        rig.wire.with(|state| {
            state.garage = case.garage;
            state.versioning = case.versioning.to_owned();
        });
        rig.app
            .instance("rw")
            .unwrap()
            .tags
            .off
            .store(case.tags_off, std::sync::atomic::Ordering::SeqCst);
        let editor = editor_of(&rig, "rw").await;
        assert_eq!(editor["provider"], case.provider, "{}", case.name);
        for field in FIELDS {
            assert_eq!(
                editor["fields"][field] == json!(true),
                case.want.contains(&field),
                "{}: fields = {}, hidden = {}",
                case.name,
                editor["fields"],
                editor["hidden"]
            );
        }
        assert_eq!(
            editor["hidden"].as_array().unwrap().len(),
            FIELDS.len() - case.want.len(),
            "{}: hidden = {}",
            case.name,
            editor["hidden"]
        );
    }
    // MinIO: a rule with the abort of incomplete uploads is refused before the write, with the reason.
    let rig = rig("MinIO", "");
    let editor = editor_of(&rig, "rw").await;
    let got = put_lifecycle(
        &rig,
        "rw",
        &hash_of(&editor),
        json!([{"id": "abort", "enabled": true, "abortMultipartDays": 3}]),
    )
    .await;
    assert_eq!(got.status, 400, "status = {}", got.text);
    assert_eq!(got.code(), "lifecycle_field_unsupported");
    assert!(got.text.contains("MinIO does not keep"), "{}", got.text);
    assert!(
        rig.wire.with(|state| state.puts.is_empty()),
        "the refused rule reached the provider"
    );
}

#[tokio::test]
async fn a_rule_of_a_field_that_is_not_offered_is_kept_as_it_is() {
    let abort = "<Rule><ID>abort</ID><Filter><Prefix>tenant/</Prefix></Filter><Status>Enabled</Status><AbortIncompleteMultipartUpload><DaysAfterInitiation>2</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule>";
    let rig = rig("MinIO", &config_of(&format!("{abort}{EDITABLE_LOGS}")));
    let editor = editor_of(&rig, "rw").await;
    assert_eq!(editor["entries"][0]["editable"], false);
    assert_eq!(
        editor["entries"][0]["reason"],
        "It uses the abort of incomplete multipart uploads, which the editor does not offer here."
    );
    assert_eq!(editor["entries"][1]["editable"], true);
    saved(&rig, "rw", &hash_of(&editor), json!([])).await;
    assert_eq!(rig.wire.stored(), config_of(abort));
}

#[tokio::test]
async fn a_save_without_rules_deletes_the_configuration() {
    let rig = rig("MinIO", &config_of(EDITABLE_LOGS));
    let editor = editor_of(&rig, "rw").await;
    let answer = saved(&rig, "rw", &hash_of(&editor), Value::Null).await;
    assert!(rig.wire.with(|state| state.deletes == 1 && state.puts.is_empty()));
    assert_eq!(rig.wire.stored(), "");
    assert_eq!(answer["editor"]["entries"].as_array().unwrap().len(), 0);
    assert!(answer.get("warnings").is_none());
}

#[tokio::test]
async fn a_refused_write_makes_the_editor_read_only() {
    let one = json!([{"id": "a", "enabled": true, "expirationDays": 1}]);
    for (status, code, reason) in [
        (
            403u16,
            "lifecycle_write_denied",
            "The storage provider refused the change (HTTP 403 AccessDenied): the credentials of this instance cannot change the lifecycle rules.",
        ),
        (
            501,
            "lifecycle_write_unsupported",
            "The storage provider does not let Stowr change the lifecycle rules (HTTP 501 NotImplemented).",
        ),
    ] {
        let rig = rig("AmazonS3", "");
        rig.wire.with(|state| state.refuse = status);
        let editor = editor_of(&rig, "rw").await;
        let got = put_lifecycle(&rig, "rw", &hash_of(&editor), one.clone()).await;
        assert_eq!(got.status, status, "status = {}", got.text);
        assert_eq!(got.code(), code);
        let after = editor_of(&rig, "rw").await;
        assert_eq!(after["writable"], false);
        assert!(after["readOnlyReason"].as_str().unwrap().starts_with(reason), "{after}");
        // A write that works clears the refusal.
        rig.wire.with(|state| state.refuse = 0);
        saved(&rig, "rw", &hash_of(&after), one.clone()).await;
        assert_eq!(
            editor_of(&rig, "rw").await["writable"],
            true,
            "the editor stayed read only after a write"
        );
    }
    // A refusal of the rules (400) does not change the editor.
    let rig = rig("AmazonS3", "");
    rig.wire.with(|state| state.refuse = 400);
    let editor = editor_of(&rig, "rw").await;
    let got = put_lifecycle(&rig, "rw", &hash_of(&editor), one).await;
    assert_eq!(got.status, 400, "status = {}", got.text);
    assert_eq!(got.code(), "lifecycle_refused");
    assert!(got.text.contains("HTTP 400 InvalidArgument"), "{}", got.text);
    assert_eq!(editor_of(&rig, "rw").await["writable"], true);
}

#[tokio::test]
async fn an_instance_without_the_write_permission_has_a_read_only_editor() {
    let rig = rig("MinIO", &config_of(EDITABLE_LOGS));
    let editor = editor_of(&rig, "readonly").await;
    assert_eq!(editor["writable"], false);
    assert_eq!(editor["readOnlyReason"], "This instance has no write permission.");
    assert_eq!(editor["rootPrefix"], "");
    let got = put_lifecycle(&rig, "readonly", &hash_of(&editor), Value::Null).await;
    assert_eq!(got.status, 403, "status = {}", got.text);
    assert!(rig.wire.with(|state| state.puts.is_empty() && state.deletes == 0));
    assert!(!PERMISSION_WRITE.is_empty());
}

#[tokio::test]
async fn the_rules_of_a_save_are_checked() {
    let rig = rig("SeaweedFS 30GB 4.41", &config_of(KEPT_OUTSIDE));
    let editor = editor_of(&rig, "rw").await;
    let long_id = "i".repeat(MAX_LIFECYCLE_ID_CHARS + 1);
    let cases: Vec<(&str, Value, &str)> = vec![
        (
            "no ID",
            json!([{"enabled": true, "expirationDays": 1}]),
            "each rule needs an ID",
        ),
        ("no action", json!([{"id": "a", "enabled": true}]), "has no action"),
        (
            "ID of a kept rule",
            json!([{"id": "other-tenant", "enabled": true, "expirationDays": 1}]),
            "is on more than one rule",
        ),
        (
            "ID twice",
            json!([{"id": "a", "expirationDays": 1}, {"id": "a", "expirationDays": 2}]),
            "is on more than one rule",
        ),
        (
            "days out of range",
            json!([{"id": "a", "expirationDays": MAX_LIFECYCLE_DAYS + 1}]),
            "whole number from 1 to 36500",
        ),
        (
            "negative days",
            json!([{"id": "a", "noncurrentDays": -1, "expirationDays": 1}]),
            "whole number from 1 to 36500",
        ),
        (
            "days and delete markers",
            json!([{"id": "a", "expirationDays": 1, "expiredDeleteMarker": true}]),
            "use two rules",
        ),
        (
            "tag and abort",
            json!([{"id": "a", "tag": {"key": "k", "value": "v"}, "expirationDays": 1, "abortMultipartDays": 1}]),
            "has a tag filter",
        ),
        (
            "tag and delete markers",
            json!([{"id": "a", "tag": {"key": "k", "value": "v"}, "expiredDeleteMarker": true}]),
            "has a tag filter",
        ),
        (
            "reserved tag",
            json!([{"id": "a", "tag": {"key": "aws:x", "value": "v"}, "expirationDays": 1}]),
            "reserved prefix aws:",
        ),
        (
            "control character in prefix",
            json!([{"id": "a", "prefix": "a\nb", "expirationDays": 1}]),
            "control character",
        ),
        (
            "space around the ID",
            json!([{"id": " a", "expirationDays": 1}]),
            "starts or ends with a space",
        ),
        (
            "long ID",
            json!([{"id": long_id, "expirationDays": 1}]),
            "at most 255 characters",
        ),
    ];
    for (name, rules, want) in cases {
        let got = put_lifecycle(&rig, "rw", &hash_of(&editor), rules).await;
        assert!(
            got.status == 400 && got.code() == "invalid_lifecycle" && got.text.contains(want),
            "{name}: status = {} {}",
            got.status,
            got.text
        );
    }
    assert!(
        rig.wire.with(|state| state.puts.is_empty()),
        "a refused rule reached the provider"
    );
}

#[tokio::test]
async fn a_rule_that_deletes_needs_the_delete_permission() {
    let rig = rig_with(
        "SeaweedFS 30GB 4.41",
        &config_of(EDITABLE_LOGS),
        Some(&[PERMISSION_READ, PERMISSION_WRITE]),
    );
    let editor = editor_of(&rig, "rw").await;
    let logs = editor["entries"][0]["rule"].clone();
    // A new rule that deletes objects, or a change of the days, needs the delete permission.
    let refused = [
        json!([logs.clone(), {"id": "new", "enabled": true, "prefix": "x/", "expirationDays": 1}]),
        json!([{"id": "logs", "enabled": true, "prefix": "logs/", "expirationDays": 1}]),
        json!([logs.clone(), {"id": "versions", "enabled": true, "prefix": "x/", "noncurrentDays": 1}]),
    ];
    for rules in refused {
        let got = put_lifecycle(&rig, "rw", &hash_of(&editor), rules).await;
        assert_eq!(got.status, 403, "status = {}", got.text);
    }
    assert!(
        rig.wire.with(|state| state.puts.is_empty() && state.deletes == 0),
        "a refused save wrote"
    );
    // A rule that becomes disabled, the removal of a rule and the abort of incomplete uploads need write only.
    let mut disabled = logs;
    disabled["enabled"] = json!(false);
    let answer = saved(
        &rig,
        "rw",
        &hash_of(&editor),
        json!([disabled, {"id": "abort", "enabled": true, "prefix": "x/", "abortMultipartDays": 2}]),
    )
    .await;
    saved(&rig, "rw", &hash_of(&answer["editor"]), Value::Null).await;
}

#[tokio::test]
async fn a_change_of_the_editable_rules_stops_the_save() {
    // The hash also covers which rules the editor shows: a rule that becomes "kept as it is" stops a save of the page.
    let abort = "<Rule><ID>abort</ID><Filter><Prefix>tenant/</Prefix></Filter><Status>Enabled</Status><AbortIncompleteMultipartUpload><DaysAfterInitiation>2</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule>";
    let rig = rig("SeaweedFS 30GB 4.41", &config_of(abort));
    let editor = editor_of(&rig, "rw").await;
    rig.app.instance("rw").unwrap().mark_lifecycle_dropped(FIELD_ABORT);
    let got = put_lifecycle(
        &rig,
        "rw",
        &hash_of(&editor),
        json!([{"id": "renamed", "enabled": true, "prefix": "", "abortMultipartDays": 2}]),
    )
    .await;
    assert_eq!(got.status, 409, "status = {}", got.text);
    assert_eq!(got.code(), "lifecycle_changed");
}

#[tokio::test]
async fn a_read_back_of_an_unknown_shape_marks_no_field() {
    let rig = rig("SeaweedFS 30GB 4.41", "");
    // The provider adds an element that the editor does not know: the rule comes back in another shape.
    rig.wire.with(|state| state.keep = Some(add_extra_element));
    let editor = editor_of(&rig, "rw").await;
    let answer = saved(
        &rig,
        "rw",
        &hash_of(&editor),
        json!([{"id": "t", "enabled": true, "prefix": "a/", "tag": {"key": "k", "value": "v"}, "expirationDays": 3}]),
    )
    .await;
    assert_eq!(
        answer["warnings"],
        json!(["The storage provider changed the rule \"t\": it has settings that the editor does not show."])
    );
    assert_eq!(
        answer["editor"]["fields"][FIELD_TAG], true,
        "a rule of another shape marked the tag filter as dropped"
    );
}

#[tokio::test]
async fn a_save_whose_read_back_fails_says_that_the_rules_are_saved() {
    let rig = rig("SeaweedFS 30GB 4.41", "");
    let editor = editor_of(&rig, "rw").await;
    rig.wire.with(|state| state.keep = Some(break_the_next_read));
    let answer = saved(
        &rig,
        "rw",
        &hash_of(&editor),
        json!([{"id": "a", "enabled": true, "expirationDays": 3}]),
    )
    .await;
    assert!(answer.get("editor").is_none(), "answer = {answer}");
    assert_eq!(answer["rules"], json!([]));
    let warnings = answer["warnings"].as_array().unwrap();
    assert_eq!(warnings.len(), 1);
    assert!(
        warnings[0]
            .as_str()
            .unwrap()
            .starts_with("The rules are saved, but Stowr cannot read them again"),
        "answer = {answer}"
    );
    assert!(
        rig.wire.stored().contains("<ID>a</ID>"),
        "the rule did not reach the provider"
    );
}

#[tokio::test]
async fn rules_that_the_page_cannot_show_exactly_are_kept_as_they_are() {
    let padded = "<Rule><ID>padded</ID><Filter><Prefix>tenant/logs </Prefix></Filter><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule>";
    let equals = "<Rule><ID>equals</ID><Filter><And><Prefix>tenant/</Prefix><Tag><Key>a=b</Key><Value>c</Value></Tag></And></Filter><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule>";
    let comma = "<Rule><ID>comma</ID><Filter><Tag><Key>k</Key><Value>a,b</Value></Tag></Filter><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule>";
    // A rule that the editor shows, with spaces between the elements: a save that does not change it keeps its bytes.
    let pretty = "<Rule>\n  <ID>pretty</ID>\n  <Filter><Prefix>tenant/a/</Prefix></Filter>\n  <Status>Enabled</Status>\n  <Expiration><Days>5</Days></Expiration>\n</Rule>";
    let rig = rig(
        "SeaweedFS 30GB 4.41",
        &config_of(&format!("{padded}{equals}{comma}{pretty}")),
    );
    let editor = editor_of(&rig, "rw").await;
    for index in 0..3 {
        assert_eq!(
            editor["entries"][index]["editable"], false,
            "entry {index}: {}",
            editor["entries"][index]
        );
    }
    assert_eq!(
        editor["entries"][3]["editable"], true,
        "the rule with spaces between its elements is not editable: {}",
        editor["entries"][3]
    );
    saved(
        &rig,
        "rw",
        &hash_of(&editor),
        json!([editor["entries"][3]["rule"], {"id": "new", "enabled": true, "prefix": "b/", "expirationDays": 2}]),
    )
    .await;
    for part in [padded, equals, comma, pretty] {
        assert!(
            rig.wire.stored().contains(part),
            "the save changed {part:?}:\n{}",
            rig.wire.stored()
        );
    }
    // A change of the rule writes it again.
    let editor = editor_of(&rig, "rw").await;
    let mut changed = editor["entries"][0]["rule"].clone();
    changed["expirationDays"] = json!(6);
    saved(
        &rig,
        "rw",
        &hash_of(&editor),
        json!([changed, editor["entries"][1]["rule"]]),
    )
    .await;
    let stored = rig.wire.stored();
    assert!(!stored.contains(pretty), "stored = {stored}");
    assert!(
        stored.contains("<ID>pretty</ID><Filter><Prefix>tenant/a/</Prefix></Filter><Status>Enabled</Status><Expiration><Days>6</Days>"),
        "stored = {stored}"
    );
}

#[tokio::test]
async fn a_configuration_with_a_namespace_prefix_is_read_only() {
    let document = format!(
        "<s3:LifecycleConfiguration xmlns:s3=\"{LIFECYCLE_NAMESPACE}\"><s3:Rule><s3:ID>logs</s3:ID><s3:Filter><s3:Prefix>tenant/logs/</s3:Prefix></s3:Filter><s3:Status>Enabled</s3:Status><s3:Expiration><s3:Days>30</s3:Days></s3:Expiration></s3:Rule></s3:LifecycleConfiguration>"
    );
    let rig = rig("MinIO", &document);
    let editor = editor_of(&rig, "rw").await;
    assert_eq!(editor["writable"], false);
    assert_eq!(
        editor["readOnlyReason"],
        "The configuration uses an XML namespace prefix that the editor does not write."
    );
    assert_eq!(
        editor["entries"][0]["editable"], true,
        "the elements are read without their prefix"
    );
    let got = put_lifecycle(&rig, "rw", &hash_of(&editor), json!([editor["entries"][0]["rule"]])).await;
    assert_eq!(got.status, 409, "status = {}", got.text);
    assert_eq!(got.code(), "lifecycle_read_only");
}

#[tokio::test]
async fn an_invalid_configuration_of_the_provider_gives_a_bad_gateway() {
    let rig = rig("MinIO", "<Other/>");
    let got = call(&rig.app, "GET", "/api/lifecycle?instance=rw", None).await;
    assert_eq!(got.status, 502, "status = {}", got.text);
    assert_eq!(got.code(), "lifecycle_invalid");
    rig.wire.set_stored("<LifecycleConfiguration><Rule>");
    let got = call(&rig.app, "GET", "/api/lifecycle?instance=rw", None).await;
    assert_eq!(got.code(), "lifecycle_invalid");
    assert_eq!(call(&rig.app, "DELETE", "/api/lifecycle", None).await.status, 405);
    assert_eq!(
        call(&rig.app, "GET", "/api/lifecycle?instance=nope", None).await.status,
        404
    );
}

// --- The rules as /api/lifecycle gives them ------------------------------------------------------------------------

#[test]
fn the_rules_of_a_configuration_have_all_their_fields() {
    let document = "<LifecycleConfiguration>
<Rule><ID>expire-logs</ID><Status>Enabled</Status><Filter><And><Prefix>logs/</Prefix><Tag><Key>retention</Key><Value>30d</Value></Tag><ObjectSizeGreaterThan>1024</ObjectSizeGreaterThan></And></Filter>
<Expiration><Days>30</Days></Expiration><Transition><Days>7</Days><StorageClass>COLD</StorageClass></Transition>
<NoncurrentVersionExpiration><NoncurrentDays>5</NoncurrentDays></NoncurrentVersionExpiration>
<AbortIncompleteMultipartUpload><DaysAfterInitiation>2</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule>
<Rule><ID>top-prefix</ID><Status>Disabled</Status><Prefix>tmp/</Prefix><Expiration><Days>1</Days></Expiration></Rule>
</LifecycleConfiguration>";
    let rules = parse_lifecycle_rules(document.as_bytes()).unwrap();
    assert_eq!(rules.len(), 2);
    let first = &rules[0];
    assert_eq!(first.id, "expire-logs");
    assert!(first.enabled);
    assert_eq!(first.prefix, "logs/");
    assert_eq!(first.tags, vec![Tag::new("retention", "30d")]);
    assert_eq!(first.size_greater_than, 1024);
    assert_eq!(first.expiration_days, 30);
    assert_eq!(first.transitions.len(), 1);
    assert_eq!(first.transitions[0].storage_class, "COLD");
    assert_eq!(first.transitions[0].days, 7);
    assert_eq!(first.noncurrent_expiration_days, 5);
    assert_eq!(first.abort_incomplete_multipart_days, 2);
    assert!(!rules[1].enabled);
    assert_eq!(rules[1].prefix, "tmp/");
    assert_eq!(rules[1].expiration_days, 1);
    let json = serde_json::to_value(first).unwrap();
    assert_eq!(
        json,
        json!({
            "id": "expire-logs", "enabled": true, "prefix": "logs/", "tags": [{"key": "retention", "value": "30d"}],
            "sizeGreaterThan": 1024, "expirationDays": 30, "transitions": [{"days": 7, "storageClass": "COLD"}],
            "noncurrentExpirationDays": 5, "abortIncompleteMultipartDays": 2
        })
    );
    assert_eq!(serde_json::to_value(&rules[1]).unwrap()["enabled"], false);
}

#[test]
fn the_rules_of_a_configuration_with_a_single_tag_filter_and_a_marker() {
    let document = "<LifecycleConfiguration><Rule><ID>m</ID><Status>Enabled</Status><Filter><Tag><Key>k</Key><Value>v</Value></Tag></Filter><Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration></Rule></LifecycleConfiguration>";
    let rules = parse_lifecycle_rules(document.as_bytes()).unwrap();
    assert_eq!(rules[0].tags, vec![Tag::new("k", "v")]);
    assert!(rules[0].expired_object_delete_marker);
    assert!(parse_lifecycle_rules(b"").unwrap().is_empty());
    assert!(parse_lifecycle_rules(b"  \n").unwrap().is_empty());
    assert!(
        parse_lifecycle_rules(
            b"<LifecycleConfiguration><Rule><Expiration><Days>x</Days></Expiration></Rule></LifecycleConfiguration>"
        )
        .is_err()
    );
    assert!(parse_lifecycle_rules(b"<LifecycleConfiguration><Rule>").is_err());
}

#[tokio::test]
async fn a_bucket_without_a_configuration_gives_an_empty_list_of_rules() {
    let rig = rig("MinIO", "");
    let backend = WireBackend::new(rig.wire.clone());
    let rules = backend
        .bucket_rules()
        .unwrap()
        .lifecycle_rules(&OpCtx::default())
        .await
        .unwrap();
    assert!(rules.is_empty());
    let body = get_lifecycle(&rig, "rw").await;
    assert_eq!(body["rules"], json!([]));
    // A 404 of another code is an error of the provider.
    rig.wire.with(|state| state.lifecycle = 404);
    let error = backend
        .bucket_rules()
        .unwrap()
        .read_lifecycle(&OpCtx::default())
        .await
        .unwrap_err();
    assert_eq!(error.status(), 404);
}

#[tokio::test]
async fn the_instance_gives_the_rules_of_a_reader() {
    let rig = rig("MinIO", &config_of(EDITABLE_LOGS));
    let rw = rig.app.instance("rw").unwrap().clone();
    let rules = rw.lifecycle(&OpCtx::default()).await.unwrap();
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].expiration_days, 30);
    rig.wire.with(|state| state.lifecycle = 501);
    let error = rw.lifecycle(&OpCtx::default()).await.unwrap_err();
    assert_eq!(error.code(), "lifecycle_unsupported");
    assert!(!rw.lifecycle_available(), "a 501 turns the lifecycle off");
}

// --- The probes and the facts of the bucket ------------------------------------------------------------------------

#[tokio::test]
async fn the_probe_hides_the_editor_of_a_provider_without_it() {
    let rig = rig("", "");
    rig.wire.with(|state| state.garage = true);
    let rw = rig.app.instance("rw").unwrap().clone();
    rw.probe_lifecycle(&OpCtx::default()).await;
    assert!(rw.rules.inner.lock().unwrap().flavour_known);
    assert!(rw.lifecycle_available());
    assert_eq!(rw.lifecycle_flavour(&OpCtx::default()).await, FLAVOUR_GARAGE);
    assert_eq!(rw.known_flavour(), FLAVOUR_GARAGE);

    let refusing = self::rig("", "");
    refusing.wire.with(|state| state.lifecycle = 501);
    let other = refusing.app.instance("rw").unwrap().clone();
    other.probe_lifecycle(&OpCtx::default()).await;
    assert!(
        !other.lifecycle_available(),
        "a provider that answers 501 has no lifecycle"
    );
    let got = call(&refusing.app, "GET", "/api/lifecycle?instance=rw", None).await;
    assert_eq!(got.status, 501, "status = {}", got.text);
    assert_eq!(got.code(), "lifecycle_unsupported");

    // A back end without the lifecycle functions (the memory back end, the GCS back end) answers unsupported.
    let plain = instance(instance_config("plain", "", None), Arc::new(MemoryBackend::default()));
    plain.probe_lifecycle(&OpCtx::default()).await;
    assert!(!plain.lifecycle_available());
    assert_eq!(
        plain.read_lifecycle_state(&OpCtx::default()).await.unwrap_err().code(),
        "lifecycle_unsupported"
    );
}

#[tokio::test]
async fn an_instance_without_the_read_permission_is_not_probed() {
    let wire = FakeS3::new("MinIO", "");
    let made = instance(
        instance_config("w", "", Some(&[PERMISSION_WRITE])),
        Arc::new(WireBackend::new(wire.clone())),
    );
    made.probe_lifecycle(&OpCtx::default()).await;
    assert!(made.lifecycle_rule_count().is_none());
    assert_eq!(made.known_flavour(), "");
    assert!(wire.with(|state| state.problems.is_empty()));
}

#[tokio::test]
async fn the_facts_of_the_bucket_follow_the_probe_the_reads_and_the_background_read() {
    let rig = rig(
        "SeaweedFS 30GB 4.41",
        &config_of(&format!("{KEPT_OUTSIDE}{KEPT_TRANSITION}")),
    );
    rig.wire.with(|state| state.versioning = "Suspended".to_owned());
    let rw = rig.app.instance("rw").unwrap().clone();
    // No read in the background until the test asks for it.
    rw.mark_bucket_facts_read();
    // Before a read, the server tells nothing.
    assert!(rw.versioning.status.lock().unwrap().is_none());
    assert!(rw.lifecycle_rule_count().is_none());
    rw.probe_lifecycle(&OpCtx::default()).await;
    assert_eq!(rw.lifecycle_rule_count(), Some(2));
    // A read of the editor gives the versioning, and a later change of the rules gives the new count.
    let editor = editor_of(&rig, "rw").await;
    assert_eq!(editor["versioning"], "Suspended");
    assert_eq!(rw.versioning.status.lock().unwrap().as_deref(), Some("Suspended"));
    rig.wire.with(|state| {
        state.body = Some(config_of(KEPT_OUTSIDE).into_bytes());
        state.versioning = "Enabled".to_owned();
    });
    get_lifecycle(&rig, "rw").await;
    assert_eq!(rw.lifecycle_rule_count(), Some(1));
    assert_eq!(rw.versioning.status.lock().unwrap().as_deref(), Some("Enabled"));
    // A change outside Stowr: a request of /api/instances reads the facts again in the background, after the age of
    // the facts, one time.
    rig.wire.with(|state| {
        state.body = None;
        state.versioning = "Suspended".to_owned();
    });
    rw.mark_bucket_facts_read();
    rw.refresh_bucket_facts();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(rw.lifecycle_rule_count(), Some(1), "a recent read must not run again");
    rw.rules.inner.lock().unwrap().facts_at = Some(Instant::now() - 2 * BUCKET_FACTS_TTL);
    rw.refresh_bucket_facts();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let count = rw.lifecycle_rule_count();
        let status = rw.versioning.status.lock().unwrap().clone();
        if count == Some(0) && status.as_deref() == Some("Suspended") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "the background read gave {count:?} rules and {status:?}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // One read at a time: the mark of the read in flight is gone after the read.
    let wait = Instant::now() + Duration::from_secs(5);
    while rw.rules.inner.lock().unwrap().facts_running {
        assert!(Instant::now() < wait);
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    // An instance without lifecycle rules gives no count.
    rw.rules.off.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(rw.lifecycle_rule_count().is_none());
}

#[tokio::test]
async fn a_background_read_needs_the_start_probe_and_the_read_permission() {
    let rig = rig("MinIO", &config_of(EDITABLE_LOGS));
    let rw = rig.app.instance("rw").unwrap().clone();
    // Before the probe at start, nothing is read.
    rw.refresh_bucket_facts();
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(rw.lifecycle_rule_count().is_none());
    let write_only = instance(
        instance_config("w", "", Some(&[PERMISSION_WRITE])),
        Arc::new(WireBackend::new(rig.wire.clone())),
    );
    write_only.mark_bucket_facts_read();
    write_only.rules.inner.lock().unwrap().facts_at = Some(Instant::now() - 2 * BUCKET_FACTS_TTL);
    write_only.refresh_bucket_facts();
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert!(write_only.lifecycle_rule_count().is_none());
}

// --- The flavour of the provider -----------------------------------------------------------------------------------

fn headers_of(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
        headers.insert(
            http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
    }
    headers
}

#[test]
fn the_provider_is_known_from_the_endpoint_the_headers_and_the_error_document() {
    let endpoint = "http://storage.local:9000";
    let aws = "https://s3.eu-west-1.amazonaws.com";
    let garage_error = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>NoSuchKey</Code><Message>Key not found</Message><Resource>/b/k</Resource><Region>garage</Region></Error>";
    let aws_error =
        "<Error><Code>NoSuchKey</Code><Message>no</Message><RequestId>1</RequestId><HostId>2</HostId></Error>";
    let cases: Vec<(&str, HeaderMap, &str, &str)> = vec![
        (aws, headers_of(&[]), "", FLAVOUR_AWS),
        (endpoint, headers_of(&[("server", "AmazonS3")]), aws_error, FLAVOUR_AWS),
        (endpoint, headers_of(&[("server", "MinIO")]), aws_error, FLAVOUR_MINIO),
        (
            endpoint,
            headers_of(&[("server", "SeaweedFS 30GB 4.41")]),
            aws_error,
            FLAVOUR_SEAWEEDFS,
        ),
        (endpoint, headers_of(&[]), garage_error, FLAVOUR_GARAGE),
        (endpoint, headers_of(&[("x-amz-request-id", "1")]), garage_error, ""),
        (endpoint, headers_of(&[("server", "nginx")]), garage_error, ""),
        (endpoint, headers_of(&[]), aws_error, ""),
        (endpoint, headers_of(&[]), "not xml", ""),
        (
            "https://user:pass@S3.Amazonaws.com:443/path",
            headers_of(&[]),
            "",
            FLAVOUR_AWS,
        ),
        ("http://[::1]:9000", headers_of(&[]), "", ""),
        ("https://amazonaws.com.example.net", headers_of(&[]), "", ""),
    ];
    for (endpoint, headers, body, want) in cases {
        assert_eq!(
            s3_provider_flavour(endpoint, &headers, body.as_bytes()),
            want,
            "flavour({endpoint}, {headers:?}, {body})"
        );
    }
}

#[tokio::test]
async fn the_probe_of_the_flavour_reads_a_key_under_the_root_prefix() {
    let wire = FakeS3::new("MinIO", "");
    let flavour = super::s3::provider_flavour(&*wire, &OpCtx::default()).await.unwrap();
    assert_eq!(flavour, FLAVOUR_MINIO);
    assert!(wire.with(|state| state.problems.is_empty()));
}

// --- The elements of a configuration -------------------------------------------------------------------------------

#[test]
fn the_split_of_a_document_keeps_the_bytes_of_each_element() {
    let document = "<?xml version=\"1.0\"?>\n<!-- a comment -->\n<LifecycleConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\n<Rule><ID>a</ID><Filter/><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule>  <Rule><ID>b &amp; c</ID></Rule>\n</LifecycleConfiguration>\n";
    let config = split_lifecycle_document(document.as_bytes()).unwrap();
    assert_eq!(
        String::from_utf8_lossy(&config.root_start),
        "<LifecycleConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"
    );
    assert_eq!(config.root_name, "LifecycleConfiguration");
    assert_eq!(config.items.len(), 2);
    assert_eq!(
        String::from_utf8_lossy(&config.items[0].raw),
        "<Rule><ID>a</ID><Filter/><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule>"
    );
    assert_eq!(
        String::from_utf8_lossy(&config.items[1].raw),
        "<Rule><ID>b &amp; c</ID></Rule>"
    );
    assert_eq!(config.items[1].node.child("ID").unwrap().text(), "b & c");
    // An empty filter is a rule of the whole bucket that the editor shows.
    let (rule, reason) = edit_rule_from_node(&config.items[0].node, "");
    assert_eq!(reason, "");
    assert_eq!(
        rule,
        EditRule {
            id: "a".to_owned(),
            enabled: true,
            expiration_days: 1,
            ..EditRule::default()
        }
    );
    for invalid in ["<LifecycleConfiguration><Rule>", "<Other/>", "not xml"] {
        assert!(
            split_lifecycle_document(invalid.as_bytes()).is_err(),
            "{invalid:?} is accepted"
        );
    }
    let empty = split_lifecycle_document(b"<LifecycleConfiguration/>").unwrap();
    assert!(empty.items.is_empty());
    assert!(empty.root_start.is_empty());
    assert!(split_lifecycle_document(b"").unwrap().items.is_empty());
}

#[test]
fn two_elements_with_other_order_and_other_spaces_have_the_same_canonical_form() {
    let left = split_lifecycle_document(b"<LifecycleConfiguration><Rule><ID>x</ID><Filter><And><Prefix>p/</Prefix><ObjectSizeGreaterThan>1</ObjectSizeGreaterThan></And></Filter></Rule></LifecycleConfiguration>").unwrap();
    let right = split_lifecycle_document(
        format!("<LifecycleConfiguration xmlns=\"{LIFECYCLE_NAMESPACE}\"><Rule>\n <Filter><And><ObjectSizeGreaterThan>1</ObjectSizeGreaterThan><Prefix>p/</Prefix></And></Filter><ID>x</ID></Rule></LifecycleConfiguration>").as_bytes(),
    )
    .unwrap();
    assert_eq!(left.items[0].node.canonical(), right.items[0].node.canonical());
    let other =
        split_lifecycle_document(b"<LifecycleConfiguration><Rule><ID>y</ID></Rule></LifecycleConfiguration>").unwrap();
    assert_ne!(left.items[0].node.canonical(), other.items[0].node.canonical());
}

#[test]
fn the_xml_of_a_rule_has_the_filter_that_its_prefix_and_tag_need() {
    let rule = EditRule {
        id: "t".to_owned(),
        enabled: true,
        tag: Some(Tag::new("k", "v")),
        expiration_days: 2,
        ..EditRule::default()
    };
    assert_eq!(
        lifecycle_rule_xml(&rule, ""),
        "<Rule><ID>t</ID><Filter><Tag><Key>k</Key><Value>v</Value></Tag></Filter><Status>Enabled</Status><Expiration><Days>2</Days></Expiration></Rule>"
    );
    assert_eq!(
        lifecycle_rule_xml(&rule, "a/"),
        "<Rule><ID>t</ID><Filter><And><Prefix>a/</Prefix><Tag><Key>k</Key><Value>v</Value></Tag></And></Filter><Status>Enabled</Status><Expiration><Days>2</Days></Expiration></Rule>"
    );
    let marker = EditRule {
        id: "m".to_owned(),
        expired_delete_marker: true,
        noncurrent_days: 4,
        ..EditRule::default()
    };
    assert_eq!(
        lifecycle_rule_xml(&marker, ""),
        "<Rule><ID>m</ID><Filter><Prefix></Prefix></Filter><Status>Disabled</Status><Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration><NoncurrentVersionExpiration><NoncurrentDays>4</NoncurrentDays></NoncurrentVersionExpiration></Rule>"
    );
}

#[test]
fn the_document_of_a_save_opens_a_new_root_for_an_empty_configuration() {
    let state = super::editor::LifecycleState::default();
    assert!(lifecycle_document_for(&state, &[], "").is_none());
    let rule = EditRule {
        id: "a".to_owned(),
        enabled: true,
        prefix: "p/".to_owned(),
        expiration_days: 1,
        ..EditRule::default()
    };
    let document = String::from_utf8(lifecycle_document_for(&state, &[rule], "root/").unwrap()).unwrap();
    assert_eq!(
        document,
        format!(
            "<LifecycleConfiguration xmlns=\"{LIFECYCLE_NAMESPACE}\"><Rule><ID>a</ID><Filter><Prefix>root/p/</Prefix></Filter><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>"
        )
    );
}

#[test]
fn a_rule_with_values_outside_the_limits_is_kept_with_all_its_fields() {
    let document = "<LifecycleConfiguration><Rule><ID>p</ID><Filter><Prefix>a</Prefix></Filter><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>";
    let config = split_lifecycle_document(document.as_bytes()).unwrap();
    let (_, outside) = edit_rule_from_node(&config.items[0].node, "tenant/");
    assert_eq!(outside, "It applies outside of the folder of this instance.");
    let long = format!(
        "<LifecycleConfiguration><Rule><ID>p</ID><Filter><Prefix>{}</Prefix></Filter><Status>Enabled</Status><Expiration><Days>1</Days></Expiration></Rule></LifecycleConfiguration>",
        "a".repeat(2000)
    );
    let config = split_lifecycle_document(long.as_bytes()).unwrap();
    let (rule, values) = edit_rule_from_node(&config.items[0].node, "");
    assert_eq!(values, "Its values are outside of the limits of the editor.");
    assert_eq!(rule.expiration_days, 1);
}

#[test]
fn the_reasons_of_a_rule_that_the_editor_keeps_tell_which_element_causes_it() {
    let cases = [
        (
            "<Rule><ID>a</ID><Status>Enabled</Status><NoncurrentVersionTransition><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionTransition></Rule>",
            "It moves objects to another storage class.",
        ),
        (
            "<Rule><ID>a</ID><Status>Enabled</Status><Expiration><Date>2030-01-01T00:00:00Z</Date></Expiration></Rule>",
            "It expires the objects on a date.",
        ),
        (
            "<Rule><ID>a</ID><Status>Enabled</Status><Filter><ObjectSizeLessThan>5</ObjectSizeLessThan></Filter></Rule>",
            "It filters the objects by size.",
        ),
        (
            "<Rule><ID>a</ID><Status>Enabled</Status><NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays><NewerNoncurrentVersions>2</NewerNoncurrentVersions></NoncurrentVersionExpiration></Rule>",
            "It keeps a number of noncurrent versions.",
        ),
        (
            "<Rule><Status>Enabled</Status><Prefix>x</Prefix></Rule>",
            "It has the old Prefix element outside of a filter.",
        ),
        ("<Rule><Status>Enabled</Status></Rule>", "It has no ID."),
        (
            "<Rule><ID>a</ID><Status>Enabled</Status><Filter><And><Tag><Key>a</Key></Tag><Tag><Key>b</Key></Tag></And></Filter></Rule>",
            "It filters by more than one tag.",
        ),
        (
            "<Rule><ID>a</ID><Status>Enabled</Status><Surprise/></Rule>",
            "It has settings that the editor does not show.",
        ),
    ];
    for (rule, want) in cases {
        let config =
            split_lifecycle_document(format!("<LifecycleConfiguration>{rule}</LifecycleConfiguration>").as_bytes())
                .unwrap();
        let (_, reason) = edit_rule_from_node(&config.items[0].node, "");
        assert_eq!(reason, want, "{rule}");
    }
}

#[test]
fn the_hash_covers_the_document_and_the_indexes_of_the_editable_rules() {
    let body = b"<LifecycleConfiguration/>";
    let base = lifecycle_hash(body, &[]);
    assert_eq!(base.len(), 64);
    assert_ne!(base, lifecycle_hash(body, &[0]));
    assert_ne!(lifecycle_hash(body, &[0, 1]), lifecycle_hash(body, &[1, 0]));
    assert_ne!(
        base,
        lifecycle_hash(b"<LifecycleConfiguration></LifecycleConfiguration>", &[])
    );
    // The reference value: the SHA-256 of an empty document.
    assert_eq!(
        lifecycle_hash(b"", &[]),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}
