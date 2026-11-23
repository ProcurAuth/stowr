//! The tests of the action document: the published actions, the limits, the exact bytes and the rules of the
//! linter of ProcurAuth (5.2, 5.3c and 6.1).

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use super::*;
use crate::access::test_support::{authzen_config, bucket, volume};
use crate::common::config::{AccessMode, BucketConfig, VolumeConfig};
use crate::common::http::read_limited;

fn config(buckets: Vec<BucketConfig>, volumes: Vec<VolumeConfig>) -> Config {
    authzen_config("stowr-test", buckets, volumes)
}

fn is_type_name(name: &str) -> bool {
    let mut chars = name.chars();
    name.len() <= 32
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

fn is_action_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.split('.').all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        })
}

fn is_encoded_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == b'%' {
            let hex = |b: Option<&u8>| b.is_some_and(|b| b.is_ascii_digit() || (b'A'..=b'F').contains(b));
            if !hex(bytes.get(index + 1)) || !hex(bytes.get(index + 2)) {
                return false;
            }
            index += 3;
        } else if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) {
            index += 1;
        } else {
            return false;
        }
    }
    !bytes.is_empty()
}

/// A copy of the rules of the linter of ProcurAuth (5.2, 5.3c and 6.1). One text for each broken rule.
fn lint(raw: &[u8]) -> Vec<String> {
    let mut problems = Vec::new();
    let mut fail = |text: String| problems.push(text);
    let chars = |text: &str| text.chars().count();
    if raw.len() > 65536 {
        fail(format!("document has {} bytes, the most is 65536", raw.len()));
    }
    let document: Value = match serde_json::from_slice(raw) {
        Ok(value) => value,
        Err(error) => {
            fail(format!("bad_json: {error}"));
            return problems;
        }
    };
    let Some(members) = document.as_object() else {
        fail("bad_json: not an object".to_owned());
        return problems;
    };
    for name in members.keys() {
        if !["server", "resource_types", "actions", "resources", "limits"].contains(&name.as_str()) {
            fail(format!("unknown member {name:?}"));
        }
    }
    for name in ["server", "resource_types", "actions"] {
        if !members.contains_key(name) {
            fail(format!("member {name:?} is absent"));
        }
    }
    let server = members.get("server").and_then(Value::as_str).unwrap_or_default();
    if server.is_empty() || server.len() > 256 || crate::access::tree::has_control_character(server) {
        fail(format!("bad_server: {server:?}"));
    }
    let empty = Vec::new();
    let list = |name: &str| members.get(name).and_then(Value::as_array).unwrap_or(&empty);
    let text = |value: &Value, name: &str| value.get(name).and_then(Value::as_str).unwrap_or_default().to_owned();

    let mut parents: BTreeMap<String, String> = BTreeMap::new();
    for item in list("resource_types") {
        let name = text(item, "name");
        if name == "service" {
            fail("reserved_type_name".to_owned());
        } else if !is_type_name(&name) {
            fail(format!("bad_type_name {name:?}"));
        }
        if parents.insert(name.clone(), text(item, "parent")).is_some() {
            fail(format!("duplicate_type_name {name:?}"));
        }
        if chars(&text(item, "description")) > 300 {
            fail(format!("description of type {name:?} is longer than 300 characters"));
        }
    }
    for (name, parent) in &parents {
        if parent != "service" && !parents.contains_key(parent) {
            fail(format!("undeclared_parent {parent:?} of {name:?}"));
        }
        let (mut steps, mut current) = (0, name.clone());
        while current != "service" {
            let Some(next) = parents.get(&current) else {
                break;
            };
            steps += 1;
            current = next.clone();
            if steps > parents.len() + 1 {
                fail(format!("type_cycle at {name:?}"));
                break;
            }
        }
        if steps > 4 {
            fail(format!("type_too_deep {name:?}"));
        }
    }

    let mut kinds: BTreeMap<String, String> = BTreeMap::new();
    for limit in list("limits") {
        let name = text(limit, "name");
        if !is_type_name(&name) {
            fail(format!("bad_limit_name {name:?}"));
        }
        let kind = text(limit, "kind");
        if kinds.insert(name.clone(), kind.clone()).is_some() {
            fail(format!("duplicate_limit_name {name:?}"));
        }
        for (member, most) in [("label", 60), ("description", 300), ("unit", 20)] {
            let value = text(limit, member);
            if value.is_empty() || chars(&value) > most {
                fail(format!("{member} of limit {name:?} has {} characters", chars(&value)));
            }
        }
        let (min, max) = (limit.get("min"), limit.get("max"));
        match kind.as_str() {
            "budget" => {
                if min.is_some() || max.is_some() {
                    fail(format!("budget {name:?} has min or max"));
                }
                if name.starts_with("max_") {
                    fail(format!("budget_name_max {name:?}"));
                }
            }
            "ceiling" => {
                if !name.starts_with("max_") || name.len() == 4 {
                    fail(format!("ceiling_name {name:?}"));
                }
                match (min.and_then(Value::as_i64), max.and_then(Value::as_i64)) {
                    (Some(low), Some(high)) => {
                        if low < 0 || high < 0 {
                            fail(format!("bad_bound of {name:?}"));
                        } else if low > high {
                            fail(format!("min_above_max of {name:?}"));
                        } else if high >= 1 << 53 {
                            fail(format!("max of {name:?} is not below 2^53"));
                        }
                    }
                    _ if min.is_none() || max.is_none() => fail(format!("ceiling {name:?} without a bound")),
                    _ => fail(format!("bad_bound of {name:?}")),
                }
            }
            other => fail(format!("bad_kind {other:?}")),
        }
    }

    let mut action_names = BTreeSet::new();
    for action in list("actions") {
        let name = text(action, "name");
        if !is_action_name(&name) {
            fail(format!("bad_action_name {name:?}"));
        }
        if name == "access" {
            fail("access_in_list".to_owned());
        }
        if !action_names.insert(name.clone()) {
            fail(format!("duplicate_action_name {name:?}"));
        }
        let description = text(action, "description");
        if description.is_empty() || chars(&description) > 300 {
            fail(format!(
                "description of action {name:?} has {} characters",
                chars(&description)
            ));
        }
        let types: Vec<String> = action
            .get("resource_types")
            .and_then(Value::as_array)
            .unwrap_or(&empty)
            .iter()
            .map(|v| v.as_str().unwrap_or_default().to_owned())
            .collect();
        if types.is_empty() {
            fail(format!("action {name:?} has no type"));
        }
        let mut seen = BTreeSet::new();
        for kind in &types {
            if kind != "service" && !parents.contains_key(kind) {
                fail(format!("undeclared_type {kind:?} in action {name:?}"));
            }
            if !seen.insert(kind.clone()) {
                fail(format!("duplicate_type {kind:?} in action {name:?}"));
            }
        }
        let mut seen = BTreeSet::new();
        for limit in action.get("limits").and_then(Value::as_array).unwrap_or(&empty) {
            let limit = limit.as_str().unwrap_or_default().to_owned();
            if !kinds.contains_key(&limit) {
                fail(format!("undeclared_limit {limit:?} in action {name:?}"));
            }
            if !seen.insert(limit.clone()) {
                fail(format!("duplicate_limit {limit:?} in action {name:?}"));
            }
        }
    }
    if list("actions").len() > 64 {
        fail(format!("{} actions, the most is 64", list("actions").len()));
    }
    for resource in list("resources") {
        let path = text(resource, "path");
        let segments: Vec<&str> = path.split('/').collect();
        if segments.len() > 4 {
            fail(format!("type_too_deep path {path:?}"));
        }
        let mut previous = "service".to_owned();
        for segment in segments {
            let Some((kind, id)) = segment.split_once(':') else {
                fail(format!("bad_path {path:?}"));
                break;
            };
            if !is_encoded_id(id) {
                fail(format!("bad_path {path:?}"));
                break;
            }
            let Some(parent) = parents.get(kind) else {
                fail(format!("undeclared_type {kind:?} in path {path:?}"));
                break;
            };
            if *parent != previous {
                fail(format!("wrong_parent in path {path:?}"));
                break;
            }
            previous = kind.to_owned();
        }
        if let Some(label) = resource.get("label").and_then(Value::as_str)
            && !(1..=60).contains(&chars(label))
        {
            fail(format!("label of {path:?} has {} characters", chars(label)));
        }
    }
    if list("resources").len() > 256 {
        fail(format!("{} resources, the most is 256", list("resources").len()));
    }
    problems
}

fn build(config: &Config) -> ActionDocument {
    let document = ActionDocument::build(config).unwrap();
    let problems = lint(document.json());
    assert!(
        problems.is_empty(),
        "the document breaks the rules of the linter: {problems:?}\n{}",
        String::from_utf8_lossy(document.json())
    );
    document
}

fn limit_names(document: &ActionDocument) -> Vec<String> {
    let body: Value = serde_json::from_slice(document.json()).unwrap();
    body["limits"]
        .as_array()
        .map(|limits| {
            limits
                .iter()
                .map(|limit| limit["name"].as_str().unwrap().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

const ALL: [&str; 5] = [
    ACTION_READ,
    ACTION_WRITE,
    ACTION_DELETE,
    ACTION_LOCK,
    ACTION_BUCKET_ADMIN,
];

#[test]
fn the_document_publishes_only_the_actions_that_the_configuration_serves() {
    let read_only = |mut config: Config| {
        config.runtime.access_mode = AccessMode::ForceReadOnly;
        config
    };
    let both = vec![LIMIT_WRITES, LIMIT_MAX_OBJECT_SIZE];
    type Case<'a> = (&'a str, Config, Vec<&'a str>, Vec<&'a str>, bool);
    let cases: Vec<Case> = vec![
        (
            "all permissions, one bucket and one volume",
            config(
                vec![bucket("docs", "Docs", None)],
                vec![volume("scratch", "Scratch", None)],
            ),
            ALL.to_vec(),
            both.clone(),
            true,
        ),
        (
            "force_read_only",
            read_only(config(
                vec![bucket("docs", "Docs", None)],
                vec![volume("scratch", "Scratch", None)],
            )),
            vec![ACTION_READ],
            vec![LIMIT_MAX_OBJECT_SIZE],
            false,
        ),
        (
            "one volume with read only",
            config(vec![], vec![volume("scratch", "Scratch", Some(&["read"]))]),
            vec![ACTION_READ],
            vec![LIMIT_MAX_OBJECT_SIZE],
            false,
        ),
        (
            "one volume with read, write and delete, and no bucket",
            config(
                vec![],
                vec![volume("scratch", "Scratch", Some(&["read", "write", "delete"]))],
            ),
            vec![ACTION_READ, ACTION_WRITE, ACTION_DELETE],
            both.clone(),
            true,
        ),
        (
            "one bucket with read and delete",
            config(vec![bucket("docs", "Docs", Some(&["read", "delete"]))], vec![]),
            vec![ACTION_READ, ACTION_DELETE],
            both.clone(),
            true,
        ),
        (
            "a bucket with read and a volume with write",
            config(
                vec![bucket("docs", "Docs", Some(&["read"]))],
                vec![volume("scratch", "Scratch", Some(&["write"]))],
            ),
            vec![ACTION_READ, ACTION_WRITE],
            both.clone(),
            true,
        ),
        (
            "a bucket with write only: no Object Lock and no lifecycle, because both need read too",
            config(vec![bucket("docs", "Docs", Some(&["write"]))], vec![]),
            vec![ACTION_WRITE],
            both.clone(),
            true,
        ),
        (
            "a bucket with read and write",
            config(vec![bucket("docs", "Docs", Some(&["read", "write"]))], vec![]),
            vec![ACTION_READ, ACTION_WRITE, ACTION_LOCK, ACTION_BUCKET_ADMIN],
            both.clone(),
            true,
        ),
        (
            "force_read_only with a bucket that has no permissions key",
            read_only(config(vec![bucket("docs", "Docs", None)], vec![])),
            vec![ACTION_READ],
            vec![LIMIT_MAX_OBJECT_SIZE],
            false,
        ),
        (
            "an empty list of permissions",
            config(vec![bucket("docs", "Docs", Some(&[]))], vec![]),
            vec![],
            vec![],
            false,
        ),
    ];
    for (name, config, actions, limits, has_budget) in cases {
        let document = build(&config);
        assert_eq!(document.published_actions(), actions, "{name}");
        assert_eq!(limit_names(&document), limits, "{name}");
        for action in &actions {
            assert_eq!(
                document.lists_budget(action),
                *action != ACTION_READ,
                "{name}: {action}"
            );
        }
        assert!(
            !document.lists_budget(ACTION_READ) && !document.lists_budget("unknown.action"),
            "{name}"
        );
        for action in ALL {
            let want = (action == ACTION_READ || action == ACTION_WRITE) && document.published(action);
            assert_eq!(
                document.lists_ceiling(action, LIMIT_MAX_OBJECT_SIZE),
                want,
                "{name}: {action}"
            );
            assert!(!document.lists_ceiling(action, LIMIT_WRITES), "{name}: {action}");
        }
        assert_eq!(document.is_budget(LIMIT_WRITES), has_budget, "{name}");
        assert!(
            !document.is_budget(LIMIT_MAX_OBJECT_SIZE) && !document.is_budget("unknown"),
            "{name}"
        );
        for row in ACTION_ROWS {
            if let Some(action) = document.action(row.name) {
                assert_eq!(action.limits, row.limits, "{name}: {}", row.name);
            }
        }
    }
}

#[test]
fn the_table_of_the_actions_matches_the_contract() {
    for row in ACTION_ROWS {
        let want: &[&str] = if row.name == ACTION_BUCKET_ADMIN {
            &["service", "bucket"]
        } else {
            &ALL_TYPES
        };
        assert_eq!(row.resource_types, want, "{}", row.name);
        assert!(!row.limits.contains(&"max_objects"), "{}", row.name);
    }
    let document = build(&config(vec![bucket("docs", "Docs", None)], vec![]));
    for action in [ACTION_WRITE, ACTION_DELETE, ACTION_LOCK, ACTION_BUCKET_ADMIN] {
        assert!(document.lists_budget(action), "{action}");
    }
    assert!(document.lists_ceiling(ACTION_READ, LIMIT_MAX_OBJECT_SIZE));
    assert!(document.lists_ceiling(ACTION_WRITE, LIMIT_MAX_OBJECT_SIZE));
    assert!(!document.lists_ceiling(ACTION_DELETE, LIMIT_MAX_OBJECT_SIZE));
    // Each declared limit is listed by a published action, and each limit of an action is declared.
    let declared: BTreeSet<String> = limit_names(&document).into_iter().collect();
    let listed: BTreeSet<String> = document
        .published_actions()
        .iter()
        .flat_map(|name| {
            document
                .action(name)
                .unwrap()
                .limits
                .iter()
                .map(|limit| (*limit).to_owned())
        })
        .collect();
    assert_eq!(declared, listed);
    // A budget has a singular noun as unit, a ceiling a plural noun.
    let units: Vec<(&str, &str)> = document
        .declared_limits()
        .iter()
        .map(|limit| (limit.name, limit.unit))
        .collect();
    assert_eq!(
        units,
        vec![(LIMIT_WRITES, "operation"), (LIMIT_MAX_OBJECT_SIZE, "bytes")]
    );
}

#[test]
fn the_document_is_the_same_at_each_build() {
    let config = config(
        vec![bucket("docs", "Docs", None), bucket("logs", "Logs", Some(&["read"]))],
        vec![volume("scratch", "Scratch", None)],
    );
    assert_eq!(build(&config).json(), build(&config).json());
}

#[test]
fn the_document_has_its_exact_bytes() {
    let document = build(&config(
        vec![bucket("docs", "Documents", None)],
        vec![volume("scratch", "Scratch folder", Some(&["read"]))],
    ));
    let all_types = r#"["service","bucket","folder","subfolder"]"#;
    let want = [
        r#"{"server":"stowr-test","#,
        r#""resource_types":["#,
        r#"{"name":"bucket","parent":"service","description":"One bucket block or one volume block of the configuration. The id is the label of the block."},"#,
        r#"{"name":"folder","parent":"bucket","description":"One top-level folder of a bucket or a volume, below its root prefix. The id is the first part of the object key."},"#,
        r#"{"name":"subfolder","parent":"folder","description":"One folder in a top-level folder. The id is the second part of the object key."}],"#,
        r#""actions":["#,
        &format!(r#"{{"name":"object.read","resource_types":{all_types},"description":"List, preview, inspect and download objects. Show versions, tags, metadata, usage and archive entries. Check the integrity of an object.","limits":["max_object_size"]}},"#),
        &format!(r#"{{"name":"object.write","resource_types":{all_types},"description":"Upload objects, make folders, restore versions, and change tags and metadata. Be the destination of a copy, a move or an extraction.","limits":["writes","max_object_size"]}},"#),
        &format!(r#"{{"name":"object.delete","resource_types":{all_types},"description":"Delete objects, versions and folders. Be the source of a move or a rename.","limits":["writes"]}},"#),
        &format!(r#"{{"name":"object.lock","resource_types":{all_types},"description":"Set or remove a legal hold. Set, extend or shorten the retention of an object version.","limits":["writes"]}},"#),
        r#"{"name":"bucket.admin","resource_types":["service","bucket"],"description":"Change the lifecycle rules of a bucket.","limits":["writes"]}],"#,
        r#""resources":[{"path":"bucket:docs","label":"Documents"},{"path":"bucket:scratch","label":"Scratch folder"}],"#,
        r#""limits":["#,
        r#"{"name":"writes","label":"Writes","description":"Operations that change objects or bucket settings.","unit":"operation","kind":"budget"},"#,
        r#"{"name":"max_object_size","label":"Largest object","description":"The largest object that one use reads or writes, in bytes.","unit":"bytes","kind":"ceiling","min":1,"max":5497558138880}]}"#,
    ]
    .concat();
    assert_eq!(String::from_utf8_lossy(document.json()), want);
}

#[test]
fn the_resources_encode_the_ids_and_keep_the_order() {
    let document = build(&config(
        vec![bucket("b-2", "Second", None), bucket("a b/é", "Third", None)],
        vec![volume("vol", "Volume", None)],
    ));
    let body: Value = serde_json::from_slice(document.json()).unwrap();
    assert_eq!(
        body["resources"],
        serde_json::json!([
            {"path": "bucket:b-2", "label": "Second"},
            {"path": "bucket:a%20b%2F%C3%A9", "label": "Third"},
            {"path": "bucket:vol", "label": "Volume"},
        ])
    );
}

#[test]
fn the_label_follows_the_rules_of_a_name() {
    let cases = [
        ("a".repeat(60), true),
        ("a".repeat(61), false),
        ("é".repeat(60), true),
        ("é".repeat(61), false),
        ("日".repeat(60), true),
        (String::new(), false),
        ("two\nlines".to_owned(), false),
        ("tab\there".to_owned(), false),
        ("delete\u{7f}here".to_owned(), false),
        ("next\u{85}line".to_owned(), false),
        ("Plain name".to_owned(), true),
    ];
    for (name, want) in cases {
        let document = build(&config(vec![bucket("docs", &name, None)], vec![]));
        let body: Value = serde_json::from_slice(document.json()).unwrap();
        let label = body["resources"][0].get("label");
        assert_eq!(label.is_some(), want, "{name:?}");
        if let Some(label) = label {
            assert_eq!(label, &Value::String(name.clone()));
        }
    }
}

#[test]
fn the_document_keeps_the_html_characters_as_they_are() {
    let document = build(&config(vec![bucket("docs", "R&D <team>", None)], vec![]));
    let text = String::from_utf8_lossy(document.json()).into_owned();
    assert!(text.contains(r#""label":"R&D <team>""#), "{text}");
    let document = build(&config(vec![bucket("docs", "line\u{2028}break", None)], vec![]));
    assert!(String::from_utf8_lossy(document.json()).contains("\"label\":\"line\\u2028break\""));
}

#[test]
fn a_document_above_64_kib_stops_the_start() {
    let buckets: Vec<BucketConfig> = (0..250)
        .map(|index| bucket(&format!("{index:03}{}", "x".repeat(253)), &"n".repeat(60), None))
        .collect();
    let error = ActionDocument::build(&config(buckets.clone(), vec![]))
        .unwrap_err()
        .to_string();
    for part in ["bytes", "65536", "5.3c"] {
        assert!(error.contains(part), "{error}");
    }
    let mut open = config(buckets, vec![]);
    open.access = Default::default();
    assert!(ActionDocument::build(&open).unwrap().json().is_empty());
}

#[test]
fn a_document_at_the_minimum_of_a_reader_is_good() {
    let buckets: Vec<BucketConfig> = (0..256)
        .map(|index| bucket(&format!("bucket-{index:03}"), &"é".repeat(60), None))
        .collect();
    let document = build(&config(buckets, vec![]));
    assert!(document.json().len() <= 65536);
}

#[test]
fn the_document_of_mode_open_is_empty() {
    let mut open = config(vec![bucket("docs", "Docs", None)], vec![]);
    open.access = Default::default();
    let document = ActionDocument::build(&open).unwrap();
    assert!(document.json().is_empty());
    for row in ACTION_ROWS {
        assert!(!document.published(row.name));
        assert!(!document.lists_budget(row.name));
        assert!(!document.lists_ceiling(row.name, LIMIT_MAX_OBJECT_SIZE));
    }
    assert!(!document.is_budget(LIMIT_WRITES));
}

#[test]
fn the_linter_finds_the_broken_rules() {
    let good = String::from_utf8(
        build(&config(vec![bucket("docs", "Docs", None)], vec![]))
            .json()
            .to_vec(),
    )
    .unwrap();
    let cases = [
        (
            "action access",
            r#""name":"object.read""#,
            r#""name":"access""#,
            "access_in_list",
        ),
        (
            "cycle",
            r#"{"name":"bucket","parent":"service""#,
            r#"{"name":"bucket","parent":"subfolder""#,
            "type_cycle",
        ),
        (
            "type service",
            r#"{"name":"bucket","parent":"service""#,
            r#"{"name":"service","parent":"service""#,
            "reserved_type_name",
        ),
        (
            "budget with min",
            r#""unit":"operation","kind":"budget""#,
            r#""unit":"operation","kind":"budget","min":1"#,
            "has min or max",
        ),
        (
            "ceiling above 2^53",
            r#""max":5497558138880"#,
            r#""max":9007199254740992"#,
            "2^53",
        ),
        (
            "undeclared limit",
            r#""limits":["writes"]"#,
            r#""limits":["writes","max_rows"]"#,
            "undeclared_limit",
        ),
        (
            "bad path",
            r#""path":"bucket:docs""#,
            r#""path":"bucket:do cs""#,
            "bad_path",
        ),
        (
            "wrong parent",
            r#""path":"bucket:docs""#,
            r#""path":"folder:docs""#,
            "wrong_parent",
        ),
        (
            "unknown member",
            r#"{"server":"#,
            r#"{"extra":1,"server":"#,
            "unknown member",
        ),
        (
            "lower case hex",
            r#""path":"bucket:docs""#,
            r#""path":"bucket:a%2f""#,
            "bad_path",
        ),
    ];
    for (name, from, to, want) in cases {
        assert!(good.contains(from), "{name}: the good document has no {from}");
        let problems = lint(good.replacen(from, to, 1).as_bytes()).join("\n");
        assert!(problems.contains(want), "{name}: {problems}");
    }
    assert!(lint(good.as_bytes()).is_empty());
}

#[tokio::test]
async fn the_route_serves_the_bytes_of_the_document() {
    let document = build(&config(vec![bucket("docs", "Docs", None)], vec![]));

    let response = document.response(true, &Method::GET);
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers().get(CONTENT_TYPE).unwrap(), "application/json");
    assert_eq!(response.headers().get(CACHE_CONTROL).unwrap(), "no-store");
    assert_eq!(
        response.headers().get(CONTENT_LENGTH).unwrap(),
        document.json().len().to_string().as_str()
    );
    let (bytes, _) = read_limited(response.into_body(), 1 << 20).await.unwrap();
    assert_eq!(&bytes[..], document.json());

    let response = document.response(true, &Method::HEAD);
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers().get(CONTENT_TYPE).unwrap(), "application/json");
    assert_eq!(
        response.headers().get(CONTENT_LENGTH).unwrap(),
        document.json().len().to_string().as_str()
    );
    let (bytes, _) = read_limited(response.into_body(), 1 << 20).await.unwrap();
    assert!(bytes.is_empty());

    for method in [
        Method::POST,
        Method::PUT,
        Method::DELETE,
        Method::PATCH,
        Method::OPTIONS,
    ] {
        let response = document.response(true, &method);
        assert_eq!(response.status(), 405, "{method}");
        assert_eq!(response.headers().get("allow").unwrap(), "GET, HEAD");
    }
    let open = ActionDocument::default();
    for method in [Method::GET, Method::HEAD] {
        assert_eq!(open.response(false, &method).status(), 404);
    }
}
