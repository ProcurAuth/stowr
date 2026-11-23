//! The tests of the edit of the metadata: the validation, the S3 copy, the probe and the route.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, Method};
use serde_json::json;

use crate::bucket::metadata::{
    MAX_ETAG_BYTES, MAX_STANDARD_HEADER_BYTES, MAX_USER_METADATA_BYTES, MetadataEntry, ObjectHeaders, handle_metadata,
    is_precondition_failed, kept_object_headers, metadata_request_headers, replace_object_metadata, stored_metadata,
    validate_etag, validate_object_headers, validate_user_metadata,
};
use crate::bucket::testing::{
    FakeBackend, FakeS3, Recorded, Reply, answer_of, app_of, bucket_config, instance_of, request,
};
use crate::common::ctx::OpCtx;
use crate::instance::Instance;

fn headers(
    content_type: &str,
    cache_control: &str,
    disposition: &str,
    encoding: &str,
    language: &str,
    expires: &str,
) -> ObjectHeaders {
    ObjectHeaders {
        content_type: content_type.to_owned(),
        cache_control: cache_control.to_owned(),
        content_disposition: disposition.to_owned(),
        content_encoding: encoding.to_owned(),
        content_language: language.to_owned(),
        expires: expires.to_owned(),
    }
}

fn only(field: &str, value: &str) -> ObjectHeaders {
    let mut result = ObjectHeaders::default();
    match field {
        "type" => result.content_type = value.to_owned(),
        "cache" => result.cache_control = value.to_owned(),
        "disposition" => result.content_disposition = value.to_owned(),
        "encoding" => result.content_encoding = value.to_owned(),
        "language" => result.content_language = value.to_owned(),
        _ => result.expires = value.to_owned(),
    }
    result
}

#[test]
fn the_standard_headers_are_checked_against_their_syntax() {
    let long = format!("max-age=1, x={}", "a".repeat(MAX_STANDARD_HEADER_BYTES));
    let cases: Vec<(&str, ObjectHeaders, bool)> = vec![
        ("none", ObjectHeaders::default(), true),
        (
            "all",
            headers(
                "text/csv; charset=utf-8",
                "public, max-age=3600, stale-while-revalidate=\"60\"",
                "attachment; filename=\"r.csv\"",
                "gzip, br",
                "fr-CA, en",
                "Wed, 21 Oct 2026 07:28:00 GMT",
            ),
            true,
        ),
        ("type without slash", only("type", "text"), false),
        ("type with bad params", only("type", "text/plain; ="), false),
        ("non ASCII", only("type", "text/plain; name=é"), false),
        ("space at the end", only("cache", "no-cache "), false),
        ("control character", only("cache", "no-cache\r\nX-Evil: 1"), false),
        ("bad cache directive", only("cache", "max-age=1,,no-store"), false),
        ("bad disposition", only("disposition", "download"), false),
        ("aws-chunked", only("encoding", "aws-chunked"), false),
        ("bad encoding", only("encoding", "gzip;q=1"), false),
        ("bad language", only("language", "french language"), false),
        ("wildcard language", only("language", "*"), true),
        ("RFC 3339 expires", only("expires", "2026-10-21T07:28:00Z"), false),
        (
            "expires not in GMT",
            only("expires", "Wed, 21 Oct 2026 07:28:00 UTC"),
            false,
        ),
        ("too long", only("cache", &long), false),
    ];
    for (name, value, ok) in cases {
        let result = validate_object_headers(&value);
        assert_eq!(result.is_ok(), ok, "{name}: {result:?}");
        if let Err(error) = result {
            assert!(error.has_code("invalid_metadata"), "{name}");
        }
    }
}

#[test]
fn a_media_type_follows_the_rules_of_a_media_type_with_parameters() {
    let valid = [
        "text/plain",
        "application/json; charset=utf-8",
        "text/plain; charset=\"utf-8\"",
        "multipart/form-data; boundary=abc",
        "text/plain;",
        "text/plain; a=b; a=b",
        "text/plain; filename*=utf-8''a%20b",
    ];
    for value in valid {
        assert!(validate_object_headers(&only("type", value)).is_ok(), "{value}");
    }
    let invalid = [
        "text/",
        "/plain",
        "text/plain/x",
        "text/plain; a=b; a=c",
        "text/plain; a",
        "text/plain; =b",
        "te xt/plain",
    ];
    for value in invalid {
        assert!(validate_object_headers(&only("type", value)).is_err(), "{value}");
    }
    assert!(validate_object_headers(&only("disposition", "inline")).is_ok());
    assert!(validate_object_headers(&only("disposition", "attachment; filename=a.txt")).is_ok());
    assert!(validate_object_headers(&only("disposition", "form-data")).is_err());
}

#[test]
fn the_user_metadata_is_checked() {
    let big = "v".repeat(MAX_USER_METADATA_BYTES - 1);
    let cases: Vec<(&str, Vec<MetadataEntry>, bool)> = vec![
        ("none", vec![], true),
        (
            "simple",
            vec![
                MetadataEntry::new("owner", "ada"),
                MetadataEntry::new("build.id", "a-1_2"),
            ],
            true,
        ),
        ("upper case key", vec![MetadataEntry::new("Owner", "ada")], false),
        ("key with a space", vec![MetadataEntry::new("my key", "v")], false),
        ("key with a colon", vec![MetadataEntry::new("a:b", "v")], false),
        ("key starts with -", vec![MetadataEntry::new("-a", "v")], false),
        (
            "duplicate key",
            vec![MetadataEntry::new("a", "1"), MetadataEntry::new("a", "2")],
            false,
        ),
        ("empty value", vec![MetadataEntry::new("a", "")], false),
        ("non ASCII value", vec![MetadataEntry::new("a", "données")], false),
        ("new line in value", vec![MetadataEntry::new("a", "x\ny")], false),
        ("2 KiB exactly", vec![MetadataEntry::new("k", &big)], true),
        (
            "above 2 KiB",
            vec![MetadataEntry::new("k", &big), MetadataEntry::new("x", "y")],
            false,
        ),
    ];
    for (name, entries, ok) in cases {
        assert_eq!(validate_user_metadata(&entries).is_ok(), ok, "{name}");
    }
}

#[test]
fn the_etag_of_a_request_is_checked() {
    let long = "a".repeat(MAX_ETAG_BYTES + 1);
    for etag in ["", "\"abc\"", "a b", "a,b", long.as_str()] {
        assert!(validate_etag(etag).is_err(), "the ETag {etag:?} is accepted");
    }
    assert!(validate_etag("66f827ff4c27058d46432a4ee1974b78-2").is_ok());
}

#[test]
fn the_request_headers_have_the_standard_headers_and_the_user_metadata() {
    let built = metadata_request_headers(
        &headers("application/json", "max-age=60", "", "", "", ""),
        &[MetadataEntry::new("owner", "ada")],
    );
    assert_eq!(
        built.get("content-type").and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    assert_eq!(
        built.get("cache-control").and_then(|value| value.to_str().ok()),
        Some("max-age=60")
    );
    assert_eq!(
        built.get("x-amz-meta-owner").and_then(|value| value.to_str().ok()),
        Some("ada")
    );
    assert!(built.get("content-disposition").is_none());
    assert!(built.get("expires").is_none());
}

#[test]
fn the_stored_metadata_is_read_from_the_head_answer() {
    let mut stored = HeaderMap::new();
    stored.insert("content-type", HeaderValue::from_static("text/plain"));
    stored.append("cache-control", HeaderValue::from_static("private"));
    stored.append("cache-control", HeaderValue::from_static("max-age=60"));
    stored.insert("x-amz-meta-origin", HeaderValue::from_static("seed"));
    stored.insert("x-amz-meta-a", HeaderValue::from_static("1"));
    let (standard, entries) = stored_metadata(&stored);
    assert_eq!(standard.content_type, "text/plain");
    assert_eq!(standard.cache_control, "private, max-age=60");
    assert_eq!(
        entries,
        vec![MetadataEntry::new("a", "1"), MetadataEntry::new("origin", "seed")]
    );
}

#[test]
fn the_kept_headers_of_the_source_are_the_encryption_the_storage_class_and_the_redirect() {
    let mut source = HeaderMap::new();
    source.insert("x-amz-server-side-encryption", HeaderValue::from_static("aws:kms"));
    source.insert("x-amz-storage-class", HeaderValue::from_static(" STANDARD_IA "));
    source.insert("x-amz-website-redirect-location", HeaderValue::from_static("/other"));
    source.insert("content-type", HeaderValue::from_static("text/plain"));
    let kept = kept_object_headers(&source);
    assert_eq!(kept.len(), 3);
    assert_eq!(
        kept.get("x-amz-storage-class").and_then(|value| value.to_str().ok()),
        Some("STANDARD_IA")
    );
}

// --- The S3 copy -------------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_s3_edit_sends_the_headers_of_the_copy() {
    let fake = FakeS3::new(|recorded| {
        if recorded.header("x-amz-copy-source-if-match") != "\"etag-1\"" {
            return Reply::new(
                412,
                "<Error><Code>PreconditionFailed</Code><Message>no</Message></Error>",
            );
        }
        Reply::new(200, "<CopyObjectResult/>")
    });
    let built = metadata_request_headers(
        &headers("application/json", "max-age=60", "", "", "", ""),
        &[MetadataEntry::new("owner", "ada")],
    );
    let ctx = OpCtx::default();
    replace_object_metadata(fake.as_ref(), &ctx, "dir/a file.json", "v 1", "etag-1", &built)
        .await
        .unwrap();
    let sent = &fake.requests()[0];
    assert_eq!(sent.method, Method::PUT);
    assert_eq!(sent.key, "dir/a file.json");
    assert!(sent.query.is_empty());
    assert_eq!(
        sent.header("x-amz-copy-source"),
        "/bucket/dir/a%20file.json?versionId=v+1"
    );
    assert_eq!(sent.header("x-amz-metadata-directive"), "REPLACE");
    assert_eq!(sent.header("x-amz-tagging-directive"), "COPY");
    assert_eq!(sent.header("content-type"), "application/json");
    assert_eq!(sent.header("cache-control"), "max-age=60");
    assert_eq!(sent.header("x-amz-meta-owner"), "ada");
    assert_eq!(sent.header("content-disposition"), "");
    assert_eq!(sent.header("expires"), "");
    assert!(
        built.get("x-amz-copy-source").is_none(),
        "the call changed the headers of the caller"
    );
    let error = replace_object_metadata(fake.as_ref(), &ctx, "k", "", "other", &HeaderMap::new()).await;
    assert!(error.err().is_some_and(|error| is_precondition_failed(&error)));
}

#[tokio::test]
async fn an_error_in_a_successful_answer_of_the_copy_is_an_error() {
    let fake = FakeS3::constant(200, "<Error><Code>InternalError</Code><Message>no</Message></Error>");
    let error = replace_object_metadata(fake.as_ref(), &OpCtx::default(), "k", "", "e", &HeaderMap::new()).await;
    let error = error.err().and_then(|error| error.as_upstream());
    assert_eq!(
        error.map(|value| (value.status, value.code)),
        Some((502, "InternalError".to_owned()))
    );
}

// --- The fake provider with objects ------------------------------------------------------------------------------

struct StoredObject {
    data: String,
    headers: HeaderMap,
    tags: String,
    /// The size that the HEAD answer gives, when it is not the size of the data.
    claimed_size: Option<u64>,
}

#[derive(Default)]
struct CopyState {
    objects: BTreeMap<String, StoredObject>,
    versions: BTreeMap<String, StoredObject>,
    copy_headers: Vec<HeaderMap>,
    fail_copy_with_412: bool,
    copy_status: Option<u16>,
}

type Shared = Arc<Mutex<CopyState>>;

fn set(headers: &mut HeaderMap, name: &str, value: &str) {
    if let (Ok(name), Ok(value)) = (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(value)) {
        headers.insert(name, value);
    }
}

impl CopyState {
    fn put(&mut self, key: &str, data: &str, content_type: &str, tags: &str) {
        let mut headers = HeaderMap::new();
        set(&mut headers, "content-type", content_type);
        set(&mut headers, "cache-control", "max-age=60");
        set(&mut headers, "x-amz-meta-origin", "seed");
        set(&mut headers, "last-modified", "Tue, 20 Oct 2026 14:09:42 GMT");
        self.objects.insert(
            key.to_owned(),
            StoredObject {
                data: data.to_owned(),
                headers,
                tags: tags.to_owned(),
                claimed_size: None,
            },
        );
    }
}

fn serve_copy(state: &mut CopyState, recorded: &Recorded) -> Reply {
    if recorded.method == Method::HEAD {
        let object = match recorded.value("versionId") {
            "" => state.objects.get(&recorded.key),
            version => state.versions.get(&format!("{}?{version}", recorded.key)),
        };
        let Some(object) = object else {
            return Reply::new(404, "");
        };
        let mut reply = Reply::new(200, "");
        reply.headers = object.headers.clone();
        set(&mut reply.headers, "etag", &format!("\"etag-{}\"", recorded.key));
        let size = object.claimed_size.unwrap_or(object.data.len() as u64);
        set(&mut reply.headers, "content-length", &size.to_string());
        return reply;
    }
    if recorded.method == Method::PUT && !recorded.header("x-amz-copy-source").is_empty() {
        state.copy_headers.push(recorded.headers.clone());
        if state.fail_copy_with_412 {
            return Reply::new(
                412,
                "<Error><Code>PreconditionFailed</Code><Message>no</Message></Error>",
            );
        }
        if let Some(status) = state.copy_status {
            return Reply::new(
                status,
                "<Error><Code>NotImplemented</Code><Message>Unimplemented action: CopyObject</Message></Error>",
            );
        }
        let source = recorded
            .header("x-amz-copy-source")
            .trim_start_matches("/bucket/")
            .to_owned();
        let (source, version) = match source.split_once("?versionId=") {
            Some((path, version)) => (path.to_owned(), version.to_owned()),
            None => (source, String::new()),
        };
        let found = if version.is_empty() {
            state.objects.get(&source)
        } else {
            state.versions.get(&format!("{source}?{version}"))
        };
        let Some(object) = found else {
            return Reply::new(404, "<Error><Code>NoSuchKey</Code></Error>");
        };
        if recorded.header("x-amz-copy-source-if-match") != format!("\"etag-{source}\"") {
            return Reply::new(
                412,
                "<Error><Code>PreconditionFailed</Code><Message>no</Message></Error>",
            );
        }
        let data = object.data.clone();
        let tags = object.tags.clone();
        let mut headers = HeaderMap::new();
        for (name, value) in &recorded.headers {
            let name = name.as_str();
            let keep = matches!(
                name,
                "content-type"
                    | "cache-control"
                    | "content-disposition"
                    | "content-encoding"
                    | "content-language"
                    | "expires"
            ) || name.starts_with("x-amz-meta-");
            if keep && let Ok(text) = value.to_str() {
                set(&mut headers, name, text);
            }
        }
        set(&mut headers, "last-modified", "Tue, 20 Oct 2026 15:00:00 GMT");
        let stored = StoredObject {
            data,
            headers,
            tags,
            claimed_size: None,
        };
        state.objects.insert(recorded.key.clone(), stored);
        return Reply::new(200, "<CopyObjectResult/>");
    }
    Reply::new(501, "<Error><Code>NotImplemented</Code></Error>")
}

fn copy_backend(state: &Shared) -> Arc<FakeBackend> {
    let shared = state.clone();
    let fake = FakeS3::new(move |recorded| match shared.lock() {
        Ok(mut state) => serve_copy(&mut state, recorded),
        Err(_) => Reply::new(500, ""),
    });
    FakeBackend::flags(fake, false, false, true, None)
}

fn copy_instance(state: &Shared) -> Arc<Instance> {
    instance_of(bucket_config("rw"), copy_backend(state))
}

fn new_copy_state() -> Shared {
    let mut state = CopyState::default();
    state.put("tenant/doc.txt", "small", "text/plain", "team=data");
    Arc::new(Mutex::new(state))
}

fn with_copy<T>(state: &Shared, action: impl FnOnce(&mut CopyState) -> T) -> T {
    let mut guard = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    action(&mut guard)
}

async fn metadata_call(
    app: &Arc<crate::common::app::App>,
    method: Method,
    target: &str,
    body: Option<serde_json::Value>,
) -> (u16, serde_json::Value, String) {
    let (status, _, value, text) = answer_of(handle_metadata(app.clone(), request(method, target, body)).await).await;
    (status, value, text)
}

#[tokio::test]
async fn the_route_gives_the_stored_values() {
    let state = new_copy_state();
    let app = app_of(vec![copy_instance(&state)]);
    let (status, value, text) = metadata_call(&app, Method::GET, "/api/metadata?instance=rw&key=doc.txt", None).await;
    assert_eq!(status, 200, "{text}");
    assert_eq!(
        value["headers"],
        json!({"contentType": "text/plain", "cacheControl": "max-age=60"})
    );
    assert_eq!(value["metadata"], json!([{"key": "origin", "value": "seed"}]));
    assert_eq!(value["etag"], "etag-tenant/doc.txt");
    assert_eq!(value["size"], 5);
    assert_eq!(value["multipartETag"], false);
    assert_eq!(value["copyInParts"], false);
    assert_eq!(value["maxMetadataBytes"], MAX_USER_METADATA_BYTES);
    assert_eq!(value["lastModified"], "2026-10-20T14:09:42Z");
    assert!(value.get("version").is_none());
}

#[tokio::test]
async fn the_route_replaces_the_metadata_and_keeps_the_tags() {
    let state = new_copy_state();
    let app = app_of(vec![copy_instance(&state)]);
    let body = json!({
        "instance": "rw", "key": "doc.txt", "etag": "etag-tenant/doc.txt",
        "headers": {"contentType": "application/json", "contentLanguage": "fr"},
        "metadata": [{"key": "owner", "value": "grace"}],
    });
    let (status, value, text) = metadata_call(&app, Method::PUT, "/api/metadata", Some(body)).await;
    assert_eq!(status, 200, "{text}");
    // The cache control and the metadata origin are not in the request: they are removed.
    assert_eq!(
        value["headers"],
        json!({"contentType": "application/json", "contentLanguage": "fr"})
    );
    assert_eq!(value["metadata"], json!([{"key": "owner", "value": "grace"}]));
    with_copy(&state, |state| {
        assert_eq!(state.copy_headers.len(), 1);
        let sent = &state.copy_headers[0];
        let text = |name: &str| {
            sent.get(name)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .to_owned()
        };
        assert_eq!(text("x-amz-copy-source"), "/bucket/tenant/doc.txt");
        assert_eq!(text("x-amz-copy-source-if-match"), "\"etag-tenant/doc.txt\"");
        assert_eq!(text("x-amz-metadata-directive"), "REPLACE");
        assert_eq!(text("x-amz-tagging-directive"), "COPY");
        let object = &state.objects["tenant/doc.txt"];
        assert_eq!(object.tags, "team=data");
        assert_eq!(object.data, "small");
    });
}

#[tokio::test]
async fn the_route_refuses_the_edit_of_an_object_that_changed() {
    let state = new_copy_state();
    let app = app_of(vec![copy_instance(&state)]);
    let mut body = json!({"instance": "rw", "key": "doc.txt", "etag": "etag-of-an-older-object", "headers": {"contentType": "text/csv"}});
    let (status, value, text) = metadata_call(&app, Method::PUT, "/api/metadata", Some(body.clone())).await;
    assert_eq!(status, 412, "{text}");
    assert_eq!(value["error"]["code"], "object_changed");
    // A change of the metadata only keeps the ETag: the date of the object is not the date that the form read.
    body["etag"] = json!("etag-tenant/doc.txt");
    body["lastModified"] = json!("2026-10-20T14:09:41Z");
    let (status, value, text) = metadata_call(&app, Method::PUT, "/api/metadata", Some(body.clone())).await;
    assert_eq!(status, 412, "{text}");
    assert_eq!(value["error"]["code"], "object_changed");
    body["lastModified"] = json!("20 Oct 2026");
    let (status, ..) = metadata_call(&app, Method::PUT, "/api/metadata", Some(body.clone())).await;
    assert_eq!(status, 400);
    // The object changes between the HEAD request and the copy: the provider refuses the copy with 412.
    body["lastModified"] = json!("2026-10-20T14:09:42Z");
    with_copy(&state, |state| state.fail_copy_with_412 = true);
    let (status, value, text) = metadata_call(&app, Method::PUT, "/api/metadata", Some(body)).await;
    assert_eq!(status, 412, "{text}");
    assert_eq!(value["error"]["code"], "object_changed");
    with_copy(&state, |state| {
        let object = &state.objects["tenant/doc.txt"];
        assert_eq!(
            object.headers.get("content-type").and_then(|value| value.to_str().ok()),
            Some("text/plain")
        );
        assert_eq!(state.copy_headers.len(), 1);
    });
}

#[tokio::test]
async fn the_route_validates_the_request_before_the_provider() {
    let state = new_copy_state();
    let mut read_only = bucket_config("readonly");
    read_only.permissions_defined = true;
    read_only.permissions = vec!["read".to_owned()];
    let second = instance_of(
        read_only,
        FakeBackend::flags(FakeS3::constant(200, ""), false, false, true, None),
    );
    let app = app_of(vec![copy_instance(&state), second]);
    let long = "x".repeat(MAX_USER_METADATA_BYTES);
    let cases = [
        ("no etag", json!({"instance": "rw", "key": "doc.txt", "headers": {}})),
        (
            "no key",
            json!({"instance": "rw", "key": "", "etag": "e", "headers": {}}),
        ),
        (
            "unknown header",
            json!({"instance": "rw", "key": "doc.txt", "etag": "e", "headers": {"xAmzAcl": "public-read"}}),
        ),
        (
            "unknown field",
            json!({"instance": "rw", "key": "doc.txt", "etag": "e", "acl": "public-read"}),
        ),
        (
            "bad type",
            json!({"instance": "rw", "key": "doc.txt", "etag": "e", "headers": {"contentType": "plain"}}),
        ),
        (
            "bad metadata",
            json!({"instance": "rw", "key": "doc.txt", "etag": "e", "metadata": [{"key": "Owner", "value": "ada"}]}),
        ),
        (
            "long metadata",
            json!({"instance": "rw", "key": "doc.txt", "etag": "e", "metadata": [{"key": "a", "value": long}]}),
        ),
        (
            "bad version",
            json!({"instance": "rw", "key": "doc.txt", "etag": "e", "version": "v\n1"}),
        ),
    ];
    for (name, body) in cases {
        let (status, _, text) = metadata_call(&app, Method::PUT, "/api/metadata", Some(body)).await;
        assert_eq!(status, 400, "{name}: {text}");
    }
    let body = json!({"instance": "readonly", "key": "readonly.txt", "etag": "e"});
    let (status, ..) = metadata_call(&app, Method::PUT, "/api/metadata", Some(body)).await;
    assert_eq!(status, 403, "read-only instance");
    let (status, ..) = metadata_call(&app, Method::DELETE, "/api/metadata", None).await;
    assert_eq!(status, 405);
    let (status, ..) = metadata_call(&app, Method::GET, "/api/metadata?instance=rw", None).await;
    assert_eq!(status, 400);
    assert_eq!(
        with_copy(&state, |state| state.copy_headers.len()),
        0,
        "a refused request reached the provider"
    );
}

#[tokio::test]
async fn the_route_accepts_null_for_the_optional_members() {
    let state = new_copy_state();
    let app = app_of(vec![copy_instance(&state)]);
    let body = json!({"instance": "rw", "key": "doc.txt", "etag": "etag-tenant/doc.txt", "headers": null, "metadata": null, "version": null, "lastModified": null});
    let (status, _, text) = metadata_call(&app, Method::PUT, "/api/metadata", Some(body)).await;
    assert_eq!(status, 200, "{text}");
}

#[tokio::test]
async fn the_route_answers_501_without_the_edit() {
    // The memory back end, as the GCS back end, has no edit of the metadata.
    let backend = FakeBackend::flags(FakeS3::constant(200, ""), false, false, false, None);
    let instance = instance_of(bucket_config("rw"), backend);
    assert!(!instance.metadata_edit_available());
    let app = app_of(vec![instance]);
    let (status, value, text) = metadata_call(
        &app,
        Method::GET,
        "/api/metadata?instance=rw&key=folder/direct.txt",
        None,
    )
    .await;
    assert_eq!(status, 501, "{text}");
    assert_eq!(value["error"]["code"], "metadata_unsupported");
    let body = json!({"instance": "rw", "key": "folder/direct.txt", "etag": "e"});
    let (status, value, text) = metadata_call(&app, Method::PUT, "/api/metadata", Some(body)).await;
    assert_eq!(status, 501, "{text}");
    assert_eq!(value["error"]["code"], "metadata_unsupported");
}

// --- The probe ---------------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_probe_marks_a_provider_without_copy_object() {
    let state = new_copy_state();
    let instance = copy_instance(&state);
    instance.probe_metadata_edit(&OpCtx::default()).await;
    assert!(
        instance.metadata_edit_available(),
        "a provider that answers no such key keeps the edit"
    );
    let refusing = FakeS3::new(|recorded| {
        assert_eq!(recorded.header("x-amz-copy-source-if-match"), "\"stowr-probe\"");
        assert_eq!(recorded.header("x-amz-metadata-directive"), "REPLACE");
        Reply::new(
            501,
            "<Error><Code>NotImplemented</Code><Message>Unimplemented action: CopyObject</Message></Error>",
        )
    });
    let backend = FakeBackend::flags(refusing.clone(), false, false, true, None);
    let instance = instance_of(bucket_config("rw"), backend.clone());
    instance.probe_metadata_edit(&OpCtx::default()).await;
    assert!(
        !instance.metadata_edit_available(),
        "a provider that answers 501 has no edit"
    );
    let requests = refusing.requests();
    assert_eq!(requests[0].key, "tenant/.stowr-metadata-probe");
    let app = app_of(vec![instance]);
    let (status, ..) = metadata_call(&app, Method::GET, "/api/metadata?instance=rw&key=doc.txt", None).await;
    assert_eq!(status, 501);
    // An instance without the write permission is not probed.
    let mut cfg = bucket_config("readonly");
    cfg.permissions_defined = true;
    cfg.permissions = vec!["read".to_owned()];
    let read_only = instance_of(cfg, backend);
    let before = refusing.requests().len();
    read_only.probe_metadata_edit(&OpCtx::default()).await;
    assert!(
        read_only.metadata_edit_available(),
        "the probe ran on an instance without the write permission"
    );
    assert_eq!(refusing.requests().len(), before);
}

#[tokio::test]
async fn a_refusal_of_the_edit_makes_the_edit_unavailable() {
    let state = new_copy_state();
    with_copy(&state, |state| state.copy_status = Some(501));
    let instance = copy_instance(&state);
    let app = app_of(vec![instance.clone()]);
    let body = json!({"instance": "rw", "key": "doc.txt", "etag": "etag-tenant/doc.txt", "headers": {"contentType": "text/csv"}});
    let (status, value, _) = metadata_call(&app, Method::PUT, "/api/metadata", Some(body.clone())).await;
    assert_eq!(status, 501);
    assert_eq!(value["error"]["code"], "metadata_unsupported");
    assert!(!instance.metadata_edit_available());
    let (status, ..) = metadata_call(&app, Method::PUT, "/api/metadata", Some(body)).await;
    assert_eq!(status, 501);
    assert_eq!(with_copy(&state, |state| state.copy_headers.len()), 1);
}

// --- The copy in parts and the copy of an older version ----------------------------------------------------------

// The decision to copy in parts and the copy in parts are functions of the instance work package: these tests
// need them.
#[tokio::test]
async fn the_route_copies_a_large_object_in_parts_with_the_new_metadata() {
    let state = new_copy_state();
    with_copy(&state, |state| {
        state.put("tenant/big.bin", "0123456789", "application/octet-stream", "keep=1");
        if let Some(object) = state.objects.get_mut("tenant/big.bin") {
            object.claimed_size = Some(6_000_000_000);
        }
    });
    let backend = copy_backend(&state);
    let app = app_of(vec![instance_of(bucket_config("rw"), backend.clone())]);
    let (status, value, text) = metadata_call(&app, Method::GET, "/api/metadata?instance=rw&key=big.bin", None).await;
    assert_eq!(status, 200, "{text}");
    assert_eq!(value["copyInParts"], true);
    let body = json!({
        "instance": "rw", "key": "big.bin", "etag": value["etag"],
        "headers": {"contentType": "application/x-big", "cacheControl": "no-cache"},
        "metadata": [{"key": "owner", "value": "ops"}],
    });
    let (status, _, text) = metadata_call(&app, Method::PUT, "/api/metadata", Some(body)).await;
    assert_eq!(status, 200, "{text}");
    let copies = backend.copies.lock().unwrap().clone();
    assert_eq!(copies.len(), 1);
    let (source, destination, options) = &copies[0];
    assert_eq!(
        (source.as_str(), destination.as_str()),
        ("tenant/big.bin", "tenant/big.bin")
    );
    assert_eq!(options.expected_etag, "etag-tenant/big.bin");
    let metadata = options.metadata.clone().unwrap();
    let text = |name: &str| {
        metadata
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_owned()
    };
    assert_eq!(text("content-type"), "application/x-big");
    assert_eq!(text("cache-control"), "no-cache");
    assert_eq!(text("x-amz-meta-owner"), "ops");
    assert_eq!(text("x-amz-meta-origin"), "");
    assert_eq!(
        with_copy(&state, |state| state.copy_headers.len()),
        0,
        "a copy in parts sends no CopyObject"
    );
    // A wrong ETag stops the copy in parts before any upload.
    let body = json!({"instance": "rw", "key": "big.bin", "etag": "old", "headers": {}});
    let (status, ..) = metadata_call(&app, Method::PUT, "/api/metadata", Some(body)).await;
    assert_eq!(status, 412);
    assert_eq!(backend.copies.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn the_route_copies_an_older_version_onto_the_key() {
    let state = new_copy_state();
    with_copy(&state, |state| {
        let mut headers = HeaderMap::new();
        set(&mut headers, "content-type", "text/old");
        state.versions.insert(
            "tenant/doc.txt?v1".to_owned(),
            StoredObject {
                data: "old".to_owned(),
                headers,
                tags: "age=old".to_owned(),
                claimed_size: None,
            },
        );
    });
    let app = app_of(vec![copy_instance(&state)]);
    let body = json!({
        "instance": "rw", "key": "doc.txt", "version": "v1", "etag": "etag-tenant/doc.txt",
        "headers": {"contentType": "text/markdown"},
    });
    let (status, _, text) = metadata_call(&app, Method::PUT, "/api/metadata", Some(body)).await;
    assert_eq!(status, 200, "{text}");
    with_copy(&state, |state| {
        let source = state.copy_headers[0]
            .get("x-amz-copy-source")
            .and_then(|value| value.to_str().ok());
        assert_eq!(source, Some("/bucket/tenant/doc.txt?versionId=v1"));
        let object = &state.objects["tenant/doc.txt"];
        assert_eq!(object.data, "old");
        assert_eq!(
            object.headers.get("content-type").and_then(|value| value.to_str().ok()),
            Some("text/markdown")
        );
        assert_eq!(object.tags, "age=old");
    });
}
