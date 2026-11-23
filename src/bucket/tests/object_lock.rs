//! The tests of Object Lock: the S3 requests and documents, the probe, the validation of a request, the rules of the
//! retention, the route, and the explanation of a refused delete.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use http::{HeaderMap, Method};
use serde_json::json;

use crate::bucket::object_lock::{
    COMPLIANCE, GOVERNANCE, MAX_OBJECT_LOCK_DAYS, MAX_OBJECT_LOCK_VERSION_BYTES, ObjectLockRequest, RetentionRequest,
    handle_object_lock, is_object_locked, lock_date, read_configuration, read_legal_hold, read_retention,
    retention_change, validate_object_lock_request, write_legal_hold, write_retention,
};
use crate::bucket::testing::{
    FakeBackend, FakeS3, Recorded, Reply, answer_of, app_of, bucket_config, instance_of, object_response, request,
};
use crate::bucket::{ObjectLockDefaultJson, Retention};
use crate::common::ctx::OpCtx;
use crate::common::error::Error;
use crate::common::time::Timestamp;
use crate::instance::Instance;

const NAMESPACE: &str = "http://s3.amazonaws.com/doc/2006-03-01/";

fn at(base: Timestamp, minutes: i64) -> Timestamp {
    base.plus_secs(minutes * 60)
}

fn retention(mode: &str, until: Timestamp) -> Retention {
    Retention {
        mode: mode.to_owned(),
        retain_until: Some(until),
    }
}

// --- The fake provider with Object Lock ---------------------------------------------------------------------------

#[derive(Default)]
struct LockVersion {
    data: String,
    retention: Option<Retention>,
    hold: bool,
}

#[derive(Default)]
struct LockState {
    versions: BTreeMap<String, LockVersion>,
    current: BTreeMap<String, String>,
    order: u32,
    config: String,
    default_mode: String,
    minio_style: bool,
    retention_puts: Vec<HeaderMap>,
    hold_puts: u32,
}

impl LockState {
    fn put(&mut self, key: &str, data: &str) -> String {
        self.order += 1;
        let version = format!("v{}", self.order);
        self.versions.insert(
            format!("{key}?{version}"),
            LockVersion {
                data: data.to_owned(),
                ..LockVersion::default()
            },
        );
        self.current.insert(key.to_owned(), version.clone());
        version
    }

    fn version_mut(&mut self, key: &str, version: &str) -> Option<&mut LockVersion> {
        let version = if version.is_empty() {
            self.current.get(key).cloned().unwrap_or_default()
        } else {
            version.to_owned()
        };
        self.versions.get_mut(&format!("{key}?{version}"))
    }
}

type Shared = Arc<Mutex<LockState>>;

fn refuse(minio_style: bool) -> Reply {
    if minio_style {
        Reply::new(
            400,
            "<Error><Code>InvalidRequest</Code><Message>Object is WORM protected and cannot be overwritten</Message></Error>",
        )
    } else {
        Reply::new(
            403,
            "<Error><Code>AccessDenied</Code><Message>Access Denied.</Message></Error>",
        )
    }
}

fn no_such_key() -> Reply {
    Reply::new(404, "<Error><Code>NoSuchKey</Code></Error>")
}

fn serve_lock(state: &mut LockState, recorded: &Recorded) -> Reply {
    let (key, version) = (recorded.key.as_str(), recorded.value("versionId"));
    if key.is_empty() && recorded.has("object-lock") {
        return match state.config.as_str() {
            "unsupported" => Reply::new(
                501,
                "<Error><Code>NotImplemented</Code><Message>Unimplemented action: GetObjectLockConfiguration</Message></Error>",
            ),
            "none" => Reply::new(
                404,
                "<Error><Code>ObjectLockConfigurationNotFoundError</Code><Message>Object Lock configuration does not exist for this bucket</Message></Error>",
            ),
            _ => {
                let rule = if state.default_mode.is_empty() {
                    String::new()
                } else {
                    format!(
                        "<Rule><DefaultRetention><Mode>{}</Mode><Days>30</Days></DefaultRetention></Rule>",
                        state.default_mode
                    )
                };
                Reply::new(
                    200,
                    &format!(
                        "<ObjectLockConfiguration xmlns=\"{NAMESPACE}\"><ObjectLockEnabled>Enabled</ObjectLockEnabled>{rule}</ObjectLockConfiguration>"
                    ),
                )
            }
        };
    }
    let minio_style = state.minio_style;
    if recorded.has("retention") && recorded.method == Method::GET {
        let Some(object) = state.version_mut(key, version) else {
            return no_such_key();
        };
        let Some(held) = &object.retention else {
            // MinIO answers 400 NoSuchObjectLockConfiguration, SeaweedFS 404 ObjectLockConfigurationNotFoundError.
            return if minio_style {
                Reply::new(
                    400,
                    "<Error><Code>NoSuchObjectLockConfiguration</Code><Message>The specified object does not have a ObjectLock configuration</Message></Error>",
                )
            } else {
                Reply::new(
                    404,
                    "<Error><Code>ObjectLockConfigurationNotFoundError</Code><Message>Object Lock configuration does not exist for this bucket</Message></Error>",
                )
            };
        };
        let until = held.retain_until.map(|value| value.utc().rfc3339()).unwrap();
        return Reply::new(
            200,
            &format!(
                "<Retention xmlns=\"{NAMESPACE}\"><Mode>{}</Mode><RetainUntilDate>{}.000Z</RetainUntilDate></Retention>",
                held.mode,
                until.trim_end_matches('Z')
            ),
        );
    }
    if recorded.has("legal-hold") && recorded.method == Method::GET {
        let Some(object) = state.version_mut(key, version) else {
            return no_such_key();
        };
        if !object.hold && minio_style {
            return Reply::new(400, "<Error><Code>NoSuchObjectLockConfiguration</Code></Error>");
        }
        if !object.hold {
            return Reply::new(404, "<Error><Code>NoSuchObjectLegalHold</Code></Error>");
        }
        return Reply::new(
            200,
            &format!("<LegalHold xmlns=\"{NAMESPACE}\"><Status>ON</Status></LegalHold>"),
        );
    }
    if recorded.has("retention") && recorded.method == Method::PUT {
        state.retention_puts.push(recorded.headers.clone());
        assert!(
            !recorded.header("content-md5").is_empty(),
            "PutObjectRetention without Content-MD5"
        );
        let document = crate::bucket::support::parse_xml(recorded.body.as_bytes())
            .ok()
            .flatten();
        let (mode, until_text) = document.map_or((String::new(), String::new()), |node| {
            (
                node.text_at(&["Mode"]).to_owned(),
                node.text_at(&["RetainUntilDate"]).to_owned(),
            )
        });
        let until = Timestamp::parse_rfc3339(&until_text);
        assert!(until.is_some(), "retain-until date {until_text:?}");
        let until = until.unwrap();
        let bypass = recorded.header("x-amz-bypass-governance-retention") == "true";
        let Some(object) = state.version_mut(key, version) else {
            return no_such_key();
        };
        if let Some(held) = &object.retention
            && held.active(Timestamp::now())
        {
            let held_secs = held.retain_until.map_or(0, |value| value.secs);
            if (until.secs < held_secs || mode != held.mode) && (held.mode == COMPLIANCE || !bypass) {
                return refuse(minio_style);
            }
        }
        object.retention = Some(Retention {
            mode,
            retain_until: Some(until),
        });
        return Reply::new(200, "");
    }
    if recorded.has("legal-hold") && recorded.method == Method::PUT {
        state.hold_puts += 1;
        let on = recorded.body.contains("<Status>ON</Status>");
        if let Some(object) = state.version_mut(key, version) {
            object.hold = on;
        }
        return Reply::new(200, "");
    }
    if recorded.method == Method::HEAD {
        let current = state.current.get(key).cloned().unwrap_or_default();
        let Some(object) = state.version_mut(key, version) else {
            return Reply::new(404, "");
        };
        let size = object.data.len();
        let version = if version.is_empty() {
            current
        } else {
            version.to_owned()
        };
        return Reply::new(200, "")
            .with_header("x-amz-version-id", &version)
            .with_header("etag", "\"e\"")
            .with_header("content-length", &size.to_string());
    }
    Reply::new(501, "<Error><Code>NotImplemented</Code></Error>")
}

fn lock_s3(state: &Shared) -> Arc<FakeS3> {
    let shared = state.clone();
    FakeS3::new(move |recorded| match shared.lock() {
        Ok(mut state) => serve_lock(&mut state, recorded),
        Err(_) => Reply::new(500, ""),
    })
}

fn new_state(config: &str) -> Shared {
    Arc::new(Mutex::new(LockState {
        config: config.to_owned(),
        ..LockState::default()
    }))
}

fn with_state<T>(state: &Shared, action: impl FnOnce(&mut LockState) -> T) -> T {
    let mut guard = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    action(&mut guard)
}

/// An instance `rw` (root prefix `tenant/`) over the fake provider with Object Lock, after the probe.
async fn lock_instance(state: &Shared) -> Arc<Instance> {
    let backend = FakeBackend::new(lock_s3(state));
    let instance = instance_of(bucket_config("rw"), backend);
    instance.probe_object_lock(&OpCtx::default()).await;
    instance
}

fn seconds_text(minutes: i64) -> String {
    at(Timestamp::now(), minutes).utc().rfc3339()
}

// --- The S3 requests and documents --------------------------------------------------------------------------------

#[tokio::test]
async fn the_s3_requests_of_object_lock_send_the_right_queries_and_documents() {
    let fake = FakeS3::new(|recorded| {
        if recorded.has("object-lock") {
            return Reply::new(
                200,
                "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled><Rule><DefaultRetention><Mode>COMPLIANCE</Mode><Years>2</Years></DefaultRetention></Rule></ObjectLockConfiguration>",
            );
        }
        if recorded.has("retention") && recorded.method == Method::GET {
            // MinIO sends the milliseconds.
            return Reply::new(
                200,
                "<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>2026-10-20T15:56:31.000Z</RetainUntilDate></Retention>",
            );
        }
        if recorded.has("legal-hold") && recorded.method == Method::GET {
            return Reply::new(200, "<LegalHold><Status>ON</Status></LegalHold>");
        }
        Reply::new(200, "")
    });
    let ctx = OpCtx::default();
    let config = read_configuration(fake.as_ref(), &ctx).await.unwrap();
    assert!(config.enabled);
    assert_eq!(config.default_mode, COMPLIANCE);
    assert_eq!((config.default_days, config.default_years), (0, 2));
    let held = read_retention(fake.as_ref(), &ctx, "dir/a file.txt", "v 1").await;
    let held = held.ok().flatten().unwrap();
    assert_eq!(held.mode, GOVERNANCE);
    assert_eq!(held.retain_until, Timestamp::parse_rfc3339("2026-10-20T15:56:31Z"));
    assert!(
        read_legal_hold(fake.as_ref(), &ctx, "dir/a file.txt", "v 1")
            .await
            .unwrap_or(false)
    );
    let until = Timestamp::parse_rfc3339("2027-01-02T03:04:05Z").unwrap();
    let ok = write_retention(
        fake.as_ref(),
        &ctx,
        "dir/a file.txt",
        "v 1",
        &retention(COMPLIANCE, until),
        false,
    )
    .await;
    assert!(ok.is_ok());
    assert!(
        write_retention(fake.as_ref(), &ctx, "k", "", &retention(GOVERNANCE, until), true)
            .await
            .is_ok()
    );
    assert!(write_legal_hold(fake.as_ref(), &ctx, "k", "v2", false).await.is_ok());
    let requests = fake.requests();
    assert_eq!(requests.len(), 6);
    assert_eq!(requests[1].key, "dir/a file.txt");
    assert_eq!(requests[1].value("versionId"), "v 1");
    assert!(requests[1].has("retention"));
    let put = &requests[3];
    assert_eq!(put.method, Method::PUT);
    assert_eq!(put.value("versionId"), "v 1");
    assert_eq!(put.header("x-amz-bypass-governance-retention"), "");
    assert_eq!(put.header("content-type"), "application/xml");
    assert_eq!(
        put.body,
        format!(
            "<Retention xmlns=\"{NAMESPACE}\"><Mode>COMPLIANCE</Mode><RetainUntilDate>2027-01-02T03:04:05Z</RetainUntilDate></Retention>"
        )
    );
    use base64::Engine as _;
    let digest = base64::engine::general_purpose::STANDARD.encode(crate::bucket::support::md5(put.body.as_bytes()));
    assert_eq!(put.header("content-md5"), digest);
    let bypass = &requests[4];
    assert_eq!(bypass.header("x-amz-bypass-governance-retention"), "true");
    assert!(!bypass.has("versionId"));
    let hold = &requests[5];
    assert!(hold.has("legal-hold"));
    assert_eq!(hold.value("versionId"), "v2");
    assert!(!hold.header("content-md5").is_empty());
    assert_eq!(
        hold.body,
        format!("<LegalHold xmlns=\"{NAMESPACE}\"><Status>OFF</Status></LegalHold>")
    );
}

#[tokio::test]
async fn the_s3_reads_find_no_lock_in_the_answers_of_each_provider() {
    let cases = [
        ("SeaweedFS retention", 404, "ObjectLockConfigurationNotFoundError"),
        ("SeaweedFS hold", 404, "NoSuchObjectLegalHold"),
        ("MinIO", 400, "NoSuchObjectLockConfiguration"),
        ("AWS", 404, "NoSuchObjectLockConfiguration"),
    ];
    let ctx = OpCtx::default();
    for (name, status, code) in cases {
        let fake = FakeS3::constant(
            status,
            &format!("<Error><Code>{code}</Code><Message>none</Message></Error>"),
        );
        let held = read_retention(fake.as_ref(), &ctx, "k", "v").await;
        assert!(matches!(held, Ok(None)), "{name}: retention = {held:?}");
        let hold = read_legal_hold(fake.as_ref(), &ctx, "k", "v").await;
        assert!(matches!(hold, Ok(false)), "{name}: hold = {hold:?}");
    }
    let missing = FakeS3::constant(
        404,
        "<Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>",
    );
    let error = read_retention(missing.as_ref(), &ctx, "k", "").await;
    assert!(
        error.err().is_some_and(|error| error.is_not_found()),
        "a missing key must stay an error"
    );
}

// --- The probe ---------------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_probe_shows_object_lock_only_for_an_enabled_bucket() {
    for (config, want) in [("enabled", true), ("none", false), ("unsupported", false)] {
        let state = new_state(config);
        let backend = FakeBackend::new(lock_s3(&state));
        let instance = instance_of(bucket_config("rw"), backend);
        assert!(!instance.object_lock_available(), "the function shows before the probe");
        instance.probe_object_lock(&OpCtx::default()).await;
        assert_eq!(instance.object_lock_available(), want, "{config}");
        let (status, _, _, text) = answer_of(
            handle_object_lock(
                app_of(vec![instance.clone()]),
                request(Method::GET, "/api/object-lock?instance=rw&key=a.txt", None),
            )
            .await,
        )
        .await;
        if !want {
            assert_eq!(status, 501, "{config}");
            assert!(text.contains("object_lock_unsupported"), "{config}: {text}");
        }
    }
    // A back end without Object Lock (the memory back end, the GCS back end) has none.
    let backend = FakeBackend::flags(FakeS3::constant(200, ""), false, false, false, None);
    let instance = instance_of(bucket_config("rw"), backend);
    instance.probe_object_lock(&OpCtx::default()).await;
    assert!(!instance.object_lock_available());
}

#[tokio::test]
async fn an_instance_without_the_read_permission_is_not_probed() {
    let state = new_state("enabled");
    let backend = FakeBackend::new(lock_s3(&state));
    let mut cfg = bucket_config("rw");
    cfg.permissions_defined = true;
    cfg.permissions = vec!["write".to_owned()];
    let instance = instance_of(cfg, backend.clone());
    instance.probe_object_lock(&OpCtx::default()).await;
    assert!(!instance.object_lock_available());
    assert!(backend.s3.requests().is_empty());
}

#[tokio::test]
async fn the_instance_gives_the_default_retention_of_the_bucket() {
    let cases: [(&str, &str, Option<ObjectLockDefaultJson>); 4] = [
        (
            "enabled",
            GOVERNANCE,
            Some(ObjectLockDefaultJson {
                mode: GOVERNANCE.to_owned(),
                days: Some(30),
                years: None,
            }),
        ),
        (
            "enabled",
            COMPLIANCE,
            Some(ObjectLockDefaultJson {
                mode: COMPLIANCE.to_owned(),
                days: Some(30),
                years: None,
            }),
        ),
        ("enabled", "", None),
        ("none", GOVERNANCE, None),
    ];
    for (config, mode, want) in cases {
        let state = new_state(config);
        with_state(&state, |state| state.default_mode = mode.to_owned());
        let instance = lock_instance(&state).await;
        assert_eq!(instance.object_lock_default_info(), want, "{config} {mode:?}");
    }
    let value = serde_json::to_string(&ObjectLockDefaultJson {
        mode: GOVERNANCE.to_owned(),
        days: Some(30),
        years: None,
    });
    assert_eq!(value.unwrap(), "{\"mode\":\"GOVERNANCE\",\"days\":30}");
}

// --- The validation of a request ---------------------------------------------------------------------------------

fn lock_request(version: &str, hold: Option<bool>, retention: Option<(&str, &str)>) -> ObjectLockRequest {
    ObjectLockRequest {
        version: version.to_owned(),
        legal_hold: hold,
        retention: retention.map(|(mode, until)| RetentionRequest {
            mode: mode.to_owned(),
            retain_until: until.to_owned(),
        }),
        ..ObjectLockRequest::default()
    }
}

#[test]
fn a_request_of_object_lock_is_validated_before_the_provider() {
    let now = Timestamp::parse_rfc3339("2026-10-20T12:00:00Z").unwrap();
    let long_version = "v".repeat(MAX_OBJECT_LOCK_VERSION_BYTES + 1);
    let cases: Vec<(&str, ObjectLockRequest, bool)> = vec![
        ("legal hold", lock_request("v1", Some(true), None), true),
        (
            "retention",
            lock_request("v1", None, Some((GOVERNANCE, "2026-10-21T00:00:00Z"))),
            true,
        ),
        (
            "offset date",
            lock_request("v1", None, Some((COMPLIANCE, "2026-10-21T02:00:00+02:00"))),
            true,
        ),
        ("no version", lock_request("", Some(true), None), false),
        ("control in version", lock_request("v\n1", Some(true), None), false),
        ("long version", lock_request(&long_version, Some(true), None), false),
        ("nothing to change", lock_request("v1", None, None), false),
        (
            "lowercase mode",
            lock_request("v1", None, Some(("governance", "2026-10-21T00:00:00Z"))),
            false,
        ),
        (
            "unknown mode",
            lock_request("v1", None, Some(("LEGAL", "2026-10-21T00:00:00Z"))),
            false,
        ),
        (
            "not a date",
            lock_request("v1", None, Some((GOVERNANCE, "tomorrow"))),
            false,
        ),
        (
            "date only",
            lock_request("v1", None, Some((GOVERNANCE, "2026-10-21"))),
            false,
        ),
        (
            "past date",
            lock_request("v1", None, Some((GOVERNANCE, "2026-10-20T11:59:59Z"))),
            false,
        ),
        (
            "now",
            lock_request("v1", None, Some((GOVERNANCE, "2026-10-20T12:00:00Z"))),
            false,
        ),
        (
            "too far",
            lock_request("v1", None, Some((GOVERNANCE, "2126-10-21T00:00:00Z"))),
            false,
        ),
    ];
    for (name, request, ok) in cases {
        let result = validate_object_lock_request(&request, now);
        assert_eq!(result.is_ok(), ok, "{name}: {result:?}");
    }
    assert_eq!(MAX_OBJECT_LOCK_DAYS, 36500);
}

#[test]
fn the_offset_date_of_a_request_becomes_a_date_in_utc_without_a_fraction() {
    let now = Timestamp::parse_rfc3339("2026-10-20T12:00:00Z").unwrap();
    let request = lock_request("v1", None, Some((COMPLIANCE, "2026-10-21T02:00:00.750+02:00")));
    let change = validate_object_lock_request(&request, now).unwrap();
    let until = change.retention.and_then(|value| value.retain_until).unwrap();
    assert_eq!(until.rfc3339_nano(), "2026-10-21T00:00:00Z");
}

// --- The rules of the retention ----------------------------------------------------------------------------------

#[test]
fn the_rules_of_a_change_of_retention() {
    let now = Timestamp::parse_rfc3339("2026-10-20T12:00:00Z").unwrap();
    let governance = Retention {
        mode: GOVERNANCE.to_owned(),
        retain_until: Some(Timestamp {
            nanos: 400_000_000,
            ..at(now, 60)
        }),
    };
    let compliance = retention(COMPLIANCE, at(now, 60));
    let expired = retention(COMPLIANCE, at(now, -1));
    struct Case {
        name: &'static str,
        current: Option<Retention>,
        next: Retention,
        bypass: bool,
        refused: bool,
    }
    let cases = vec![
        Case {
            name: "first retention",
            current: None,
            next: retention(COMPLIANCE, at(now, 5)),
            bypass: false,
            refused: false,
        },
        Case {
            name: "after the end of a lock",
            current: Some(expired),
            next: retention(GOVERNANCE, at(now, 5)),
            bypass: false,
            refused: false,
        },
        Case {
            name: "governance extended",
            current: Some(governance.clone()),
            next: retention(GOVERNANCE, at(now, 90)),
            bypass: false,
            refused: false,
        },
        Case {
            name: "governance same second",
            current: Some(governance.clone()),
            next: retention(GOVERNANCE, at(now, 60)),
            bypass: false,
            refused: false,
        },
        Case {
            name: "governance shortened",
            current: Some(governance.clone()),
            next: retention(GOVERNANCE, at(now, 30)),
            bypass: true,
            refused: false,
        },
        Case {
            name: "governance to compliance",
            current: Some(governance),
            next: retention(COMPLIANCE, at(now, 90)),
            bypass: true,
            refused: false,
        },
        Case {
            name: "compliance extended",
            current: Some(compliance.clone()),
            next: retention(COMPLIANCE, at(now, 90)),
            bypass: false,
            refused: false,
        },
        Case {
            name: "compliance same date",
            current: Some(compliance.clone()),
            next: retention(COMPLIANCE, at(now, 60)),
            bypass: false,
            refused: false,
        },
        Case {
            name: "compliance shortened",
            current: Some(compliance.clone()),
            next: retention(COMPLIANCE, at(now, 30)),
            bypass: false,
            refused: true,
        },
        Case {
            name: "compliance to governance",
            current: Some(compliance.clone()),
            next: retention(GOVERNANCE, at(now, 90)),
            bypass: false,
            refused: true,
        },
        Case {
            name: "compliance shortened again",
            current: Some(compliance),
            next: retention(COMPLIANCE, at(now, 59)),
            bypass: false,
            refused: true,
        },
    ];
    for case in cases {
        let result = retention_change(case.current.as_ref(), &case.next, now);
        match result {
            Ok(bypass) => {
                assert!(!case.refused, "{}: the change is not refused", case.name);
                assert_eq!(bypass, case.bypass, "{}", case.name);
            }
            Err(error) => {
                assert!(case.refused, "{}: refused with {error}", case.name);
                let text = error.to_string();
                assert!(
                    text.contains("Compliance") && text.contains("nobody can"),
                    "{}: the refusal does not say why: {text}",
                    case.name
                );
            }
        }
    }
}

#[test]
fn a_date_in_the_messages_has_the_form_of_the_messages() {
    let date = Timestamp::parse_rfc3339("2026-10-21T09:28:00+02:00").unwrap();
    assert_eq!(lock_date(date), "2026-10-21 07:28:00 UTC");
}

// --- The route ---------------------------------------------------------------------------------------------------

async fn lock_call(
    app: &Arc<crate::common::app::App>,
    method: Method,
    target: &str,
    body: Option<serde_json::Value>,
) -> (u16, serde_json::Value, String) {
    let (status, _, value, text) =
        answer_of(handle_object_lock(app.clone(), request(method, target, body)).await).await;
    (status, value, text)
}

#[tokio::test]
async fn the_route_reads_and_changes_the_legal_hold_of_a_version() {
    let state = new_state("enabled");
    with_state(&state, |state| state.default_mode = GOVERNANCE.to_owned());
    let version = with_state(&state, |state| state.put("tenant/doc.txt", "data"));
    let instance = lock_instance(&state).await;
    let mut read_only = bucket_config("readonly");
    read_only.permissions_defined = true;
    read_only.permissions = vec!["read".to_owned()];
    let read_only = instance_of(read_only, FakeBackend::new(lock_s3(&state)));
    let app = app_of(vec![instance, read_only]);
    let (status, value, text) = lock_call(&app, Method::GET, "/api/object-lock?instance=rw&key=doc.txt", None).await;
    assert_eq!(status, 200, "{text}");
    assert_eq!(value["version"], version);
    assert!(value["retention"].is_null());
    assert_eq!(value["legalHold"], false);
    assert_eq!(value["bucketDefault"], json!({"mode": "GOVERNANCE", "days": 30}));
    assert_eq!(value["maxRetentionDays"], MAX_OBJECT_LOCK_DAYS);
    assert!(value["now"].as_str().is_some_and(|now| now.ends_with('Z')));
    let body = json!({"instance": "rw", "key": "doc.txt", "version": version, "legalHold": true});
    let (status, value, text) = lock_call(&app, Method::PUT, "/api/object-lock", Some(body.clone())).await;
    assert_eq!(status, 200, "{text}");
    assert_eq!(value["legalHold"], true);
    assert_eq!(value["version"], version);
    // The same state again sends nothing to the provider.
    let (status, _, _) = lock_call(&app, Method::PUT, "/api/object-lock", Some(body)).await;
    assert_eq!(status, 200);
    assert_eq!(with_state(&state, |state| state.hold_puts), 1);
    // A change names the version, and the read-only instance cannot change a lock.
    let without_version = json!({"instance": "rw", "key": "doc.txt", "legalHold": true});
    let (status, _, _) = lock_call(&app, Method::PUT, "/api/object-lock", Some(without_version)).await;
    assert_eq!(status, 400);
    let forbidden = json!({"instance": "readonly", "key": "readonly.txt", "version": "v1", "legalHold": true});
    let (status, _, _) = lock_call(&app, Method::PUT, "/api/object-lock", Some(forbidden)).await;
    assert_eq!(status, 403);
}

#[tokio::test]
async fn the_route_answers_the_errors_of_the_request() {
    let state = new_state("enabled");
    let instance = lock_instance(&state).await;
    let app = app_of(vec![instance]);
    let cases = [
        (Method::GET, "/api/object-lock?instance=rw", None, 400),
        (
            Method::GET,
            "/api/object-lock?instance=rw&key=a.txt&version=v%0A1",
            None,
            400,
        ),
        (Method::GET, "/api/object-lock?instance=missing&key=a.txt", None, 404),
        (
            Method::PUT,
            "/api/object-lock",
            Some(json!({"instance": "rw", "key": ""})),
            400,
        ),
        (
            Method::PUT,
            "/api/object-lock",
            Some(json!({"instance": "rw", "key": "a", "other": 1})),
            400,
        ),
        (Method::POST, "/api/object-lock", None, 405),
        (Method::DELETE, "/api/object-lock", None, 405),
    ];
    for (method, target, body, want) in cases {
        let (status, _, text) = lock_call(&app, method.clone(), target, body).await;
        assert_eq!(status, want, "{method} {target}: {text}");
    }
}

#[tokio::test]
async fn the_route_applies_the_rules_of_the_retention() {
    let state = new_state("enabled");
    let version = with_state(&state, |state| state.put("tenant/doc.txt", "data"));
    let app = app_of(vec![lock_instance(&state).await]);
    let put = |mode: &str, date: String, bypass: bool| {
        json!({"instance": "rw", "key": "doc.txt", "version": version,
               "retention": {"mode": mode, "retainUntil": date}, "bypassGovernance": bypass})
    };
    let retention_puts = || with_state(&state, |state| state.retention_puts.clone());
    let (status, value, text) = lock_call(
        &app,
        Method::PUT,
        "/api/object-lock",
        Some(put(GOVERNANCE, seconds_text(60), false)),
    )
    .await;
    assert_eq!(status, 200, "{text}");
    assert_eq!(value["retention"]["mode"], GOVERNANCE);
    assert_eq!(value["retention"]["active"], true);
    let (status, _, text) = lock_call(
        &app,
        Method::PUT,
        "/api/object-lock",
        Some(put(GOVERNANCE, seconds_text(120), false)),
    )
    .await;
    assert_eq!(status, 200, "{text}");
    // A shorter Governance retention needs the bypass: without it, the request does not reach the provider.
    let (status, value, _) = lock_call(
        &app,
        Method::PUT,
        "/api/object-lock",
        Some(put(GOVERNANCE, seconds_text(1), false)),
    )
    .await;
    assert_eq!(status, 409);
    assert_eq!(value["error"]["code"], "governance_bypass_required");
    let sent = retention_puts();
    assert_eq!(sent.len(), 2);
    assert!(
        sent.iter()
            .all(|headers| headers.get("x-amz-bypass-governance-retention").is_none())
    );
    let (status, value, text) = lock_call(
        &app,
        Method::PUT,
        "/api/object-lock",
        Some(put(GOVERNANCE, seconds_text(1), true)),
    )
    .await;
    assert_eq!(status, 200, "{text}");
    let sent = retention_puts();
    assert_eq!(sent.len(), 3);
    assert_eq!(
        sent[2]
            .get("x-amz-bypass-governance-retention")
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );
    let until = value["retention"]["retainUntil"]
        .as_str()
        .and_then(Timestamp::parse_rfc3339)
        .unwrap();
    assert!(until.secs - Timestamp::now().secs <= 120, "the date is {until}");
    // Governance to Compliance with the bypass, and then no request can shorten the Compliance retention or change it.
    let (status, _, text) = lock_call(
        &app,
        Method::PUT,
        "/api/object-lock",
        Some(put(COMPLIANCE, seconds_text(2), true)),
    )
    .await;
    assert_eq!(status, 200, "{text}");
    for (mode, minutes) in [(COMPLIANCE, 1), (GOVERNANCE, 60)] {
        let (status, value, _) = lock_call(
            &app,
            Method::PUT,
            "/api/object-lock",
            Some(put(mode, seconds_text(minutes), true)),
        )
        .await;
        assert_eq!(status, 409, "{mode}");
        assert_eq!(value["error"]["code"], "compliance_retention");
        assert!(
            value["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains("nobody can"))
        );
    }
    assert_eq!(retention_puts().len(), 4, "a refused change reached the provider");
    let (status, value, text) = lock_call(
        &app,
        Method::PUT,
        "/api/object-lock",
        Some(put(COMPLIANCE, seconds_text(3), false)),
    )
    .await;
    assert_eq!(status, 200, "{text}");
    assert_eq!(value["retention"]["mode"], COMPLIANCE);
    // A request with a bad date does not reach the provider.
    let (status, _, _) = lock_call(
        &app,
        Method::PUT,
        "/api/object-lock",
        Some(put(GOVERNANCE, seconds_text(-1), true)),
    )
    .await;
    assert_eq!(status, 400);
    assert_eq!(retention_puts().len(), 5);
}

#[tokio::test]
async fn a_provider_that_refuses_a_change_gives_the_error_of_the_lock() {
    let state = new_state("enabled");
    let version = with_state(&state, |state| state.put("tenant/doc.txt", "data"));
    let instance = lock_instance(&state).await;
    // The provider refuses a change that the rules of the server let through (for example a lock of another policy).
    with_state(&state, |state| {
        let object = state.version_mut("tenant/doc.txt", &version);
        if let Some(object) = object {
            object.retention = Some(retention(COMPLIANCE, at(Timestamp::now(), 60)));
        }
    });
    let ctx = OpCtx::default();
    let change = crate::bucket::ObjectLockChange {
        retention: Some(retention(COMPLIANCE, at(Timestamp::now(), 30))),
        ..crate::bucket::ObjectLockChange::default()
    };
    let error = instance
        .change_object_lock(&ctx, "tenant/doc.txt", &version, &change)
        .await;
    assert!(error.err().is_some_and(|error| error.has_code("compliance_retention")));
    let mut cfg = bucket_config("rw");
    cfg.id = "rw2".to_owned();
    let refusing = FakeS3::new(|recorded| {
        if recorded.method == Method::PUT {
            return refuse(false);
        }
        if recorded.has("object-lock") {
            return Reply::new(
                200,
                "<ObjectLockConfiguration><ObjectLockEnabled>Enabled</ObjectLockEnabled></ObjectLockConfiguration>",
            );
        }
        if recorded.has("retention") {
            return Reply::new(404, "<Error><Code>ObjectLockConfigurationNotFoundError</Code></Error>");
        }
        Reply::new(404, "<Error><Code>NoSuchObjectLegalHold</Code></Error>")
    });
    let second = instance_of(cfg, FakeBackend::new(refusing));
    second.probe_object_lock(&ctx).await;
    let change = crate::bucket::ObjectLockChange {
        legal_hold: Some(true),
        ..crate::bucket::ObjectLockChange::default()
    };
    let error = second.change_object_lock(&ctx, "tenant/doc.txt", "v1", &change).await;
    let error = error.err().unwrap_or_else(|| Error::internal("no error"));
    assert!(error.has_code("object_lock_refused"), "{error}");
    assert_eq!(error.status(), 409);
    assert!(error.to_string().contains("HTTP 403 AccessDenied"));
}

// --- A refused delete --------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_refused_delete_of_a_locked_version_names_the_lock() {
    for minio_style in [false, true] {
        let state = new_state("enabled");
        with_state(&state, |state| state.minio_style = minio_style);
        let version = with_state(&state, |state| state.put("tenant/doc.txt", "data"));
        let instance = lock_instance(&state).await;
        with_state(&state, |state| {
            if let Some(object) = state.version_mut("tenant/doc.txt", &version) {
                object.hold = true;
                object.retention = Some(retention(GOVERNANCE, at(Timestamp::now(), 60)));
            }
        });
        let ctx = OpCtx::default();
        let refusal = if minio_style {
            Error::upstream(
                400,
                "InvalidRequest",
                "Object is WORM protected and cannot be overwritten",
            )
        } else {
            Error::upstream(403, "AccessDenied", "Access Denied.")
        };
        let error = instance
            .explain_lock_refusal(&ctx, "tenant/doc.txt", &version, refusal.clone())
            .await;
        assert!(is_object_locked(&error), "minio = {minio_style}: {error}");
        assert_eq!(error.status(), 409);
        let message = error.to_string();
        assert!(message.contains("legal hold is on"), "{message}");
        assert!(message.contains("Governance retention keeps it until"), "{message}");
        assert!(message.contains("\"doc.txt\""), "{message}");
        assert!(message.contains(&format!("the version {version} of")), "{message}");
        // Without a lock, the same refusal stays the error of the provider.
        with_state(&state, |state| {
            if let Some(object) = state.version_mut("tenant/doc.txt", &version) {
                object.hold = false;
                object.retention = None;
            }
        });
        let error = instance
            .explain_lock_refusal(
                &ctx,
                "tenant/doc.txt",
                &version,
                Error::upstream(403, "AccessDenied", ""),
            )
            .await;
        assert!(
            !is_object_locked(&error),
            "minio = {minio_style}: an object without a lock is locked: {error}"
        );
        assert_eq!(error.status(), 403);
    }
}

#[tokio::test]
async fn only_a_refusal_that_a_lock_can_give_makes_the_provider_read_the_lock() {
    let state = new_state("enabled");
    let version = with_state(&state, |state| state.put("tenant/doc.txt", "data"));
    let instance = lock_instance(&state).await;
    with_state(&state, |state| {
        if let Some(object) = state.version_mut("tenant/doc.txt", &version) {
            object.hold = true;
        }
    });
    let ctx = OpCtx::default();
    let other = instance
        .explain_lock_refusal(&ctx, "tenant/doc.txt", &version, Error::upstream(404, "NoSuchKey", ""))
        .await;
    assert!(!is_object_locked(&other));
    let by_message = instance
        .explain_lock_refusal(
            &ctx,
            "tenant/doc.txt",
            &version,
            Error::upstream(409, "Conflict", "the object lock keeps it"),
        )
        .await;
    assert!(is_object_locked(&by_message));
    let canceled = ctx.clone();
    canceled.cancel.cancel();
    let error = instance
        .explain_lock_refusal(
            &canceled,
            "tenant/doc.txt",
            &version,
            Error::upstream(403, "AccessDenied", ""),
        )
        .await;
    assert!(!is_object_locked(&error), "a canceled request reads no lock");
    // An instance without Object Lock leaves the error as it is.
    let plain = instance_of(
        bucket_config("rw"),
        FakeBackend::flags(FakeS3::constant(200, ""), false, false, false, None),
    );
    let error = plain
        .explain_lock_refusal(&ctx, "tenant/doc.txt", "", Error::upstream(403, "AccessDenied", ""))
        .await;
    assert!(!is_object_locked(&error));
}

#[tokio::test]
async fn the_head_of_the_current_version_gives_the_version_of_the_lock() {
    let state = new_state("enabled");
    let version = with_state(&state, |state| state.put("tenant/doc.txt", "data"));
    let instance = lock_instance(&state).await;
    let head = instance.head(&OpCtx::default(), "tenant/doc.txt").await;
    let value = head.ok().and_then(|response| {
        response
            .headers
            .get("x-amz-version-id")
            .and_then(|value| value.to_str().ok().map(str::to_owned))
    });
    assert_eq!(value, Some(version));
    assert_eq!(object_response(200, HeaderMap::new(), "").status, 200);
}
