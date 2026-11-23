//! The tests of the encryption: the headers of the writes, the default encryption of the bucket, the probe, the route,
//! and the objects with a key of the client.

use std::sync::Arc;

use http::header::{HeaderName, HeaderValue};
use http::{HeaderMap, Method};
use serde_json::json;

use crate::bucket::BucketEncryption;
use crate::bucket::encryption::{
    ENCRYPTION_APPLIED_NO, ENCRYPTION_APPLIED_UNKNOWN, ENCRYPTION_APPLIED_YES, SSE_BUCKET_KEY_HEADER,
    SSE_CUSTOMER_ALGORITHM_HEADER, SSE_HEADER, SSE_KMS_KEY_HEADER, customer_key_media_info, customer_key_refusal,
    handle_encryption, kept_encryption_headers, read_bucket_encryption, write_encryption_headers,
};
use crate::bucket::metadata::{kept_object_headers, replace_object_metadata};
use crate::bucket::testing::{
    FakeBackend, FakeS3, Reply, answer_of, app_of, bucket_config, instance_of, object_response, request,
};
use crate::common::config::{BucketConfig, Encryption};
use crate::common::ctx::OpCtx;
use crate::common::error::Error;
use crate::common::storage::{ListPage, ObjectInfo};
use crate::common::time::Timestamp;
use crate::instance::Instance;

fn headers_of(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
        if let (Ok(name), Ok(value)) = (HeaderName::from_bytes(name.as_bytes()), HeaderValue::from_str(value)) {
            headers.insert(name, value);
        }
    }
    headers
}

fn text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|value| value.to_str().ok())
}

fn sse_s3(mode: Encryption) -> BucketConfig {
    BucketConfig {
        encryption: mode,
        ..bucket_config("rw")
    }
}

const BUCKET_ENCRYPTION_KMS: &str = "<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>aws:kms</SSEAlgorithm><KMSMasterKeyID>arn:k</KMSMasterKeyID></ApplyServerSideEncryptionByDefault><BucketKeyEnabled>true</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>";
const BUCKET_ENCRYPTION_AES: &str = "<ServerSideEncryptionConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault><BucketKeyEnabled>false</BucketKeyEnabled></Rule></ServerSideEncryptionConfiguration>";
const BUCKET_ENCRYPTION_GARAGE: &str = "<Error><Code>NotImplemented</Code><Message>Unimplemented action: GetBucketEncryption</Message><Resource>/default</Resource><Region>garage</Region></Error>";
const NO_ENCRYPTION: &str = "<Error><Code>ServerSideEncryptionConfigurationNotFoundError</Code><Message>The server side encryption configuration was not found</Message></Error>";

// --- The headers of the writes -----------------------------------------------------------------------------------

#[test]
fn a_bucket_with_sse_s3_adds_the_header_to_a_write_without_an_encryption() {
    let mut headers = HeaderMap::new();
    write_encryption_headers(&sse_s3(Encryption::SseS3), &mut headers);
    assert_eq!(text(&headers, SSE_HEADER), Some("AES256"));
    let mut none = HeaderMap::new();
    write_encryption_headers(&sse_s3(Encryption::None), &mut none);
    assert!(none.is_empty());
}

#[test]
fn a_write_that_already_names_an_encryption_keeps_it() {
    let mut kms = headers_of(&[(SSE_HEADER, "aws:kms"), (SSE_KMS_KEY_HEADER, "arn:k")]);
    write_encryption_headers(&sse_s3(Encryption::SseS3), &mut kms);
    assert_eq!(kms.get_all(SSE_HEADER).iter().count(), 1);
    assert_eq!(text(&kms, SSE_HEADER), Some("aws:kms"));
    let mut customer = headers_of(&[(SSE_CUSTOMER_ALGORITHM_HEADER, "AES256")]);
    write_encryption_headers(&sse_s3(Encryption::SseS3), &mut customer);
    assert!(customer.get(SSE_HEADER).is_none());
    let mut empty = headers_of(&[]);
    empty.insert(HeaderName::from_static(SSE_HEADER), HeaderValue::from_static(""));
    write_encryption_headers(&sse_s3(Encryption::SseS3), &mut empty);
    assert_eq!(text(&empty, SSE_HEADER), Some("AES256"));
}

#[test]
fn the_kept_headers_are_the_sse_s3_and_sse_kms_headers_without_a_space_at_the_ends() {
    let source = headers_of(&[
        (SSE_HEADER, " aws:kms "),
        (SSE_KMS_KEY_HEADER, "arn:k"),
        (SSE_CUSTOMER_ALGORITHM_HEADER, "AES256"),
        ("x-amz-server-side-encryption-customer-key-md5", "abc"),
        ("content-type", "text/plain"),
    ]);
    let kept = kept_encryption_headers(&source);
    assert_eq!(kept.len(), 2);
    assert_eq!(text(&kept, SSE_HEADER), Some("aws:kms"));
    assert_eq!(text(&kept, SSE_KMS_KEY_HEADER), Some("arn:k"));
    assert!(kept_encryption_headers(&HeaderMap::new()).is_empty());
}

#[test]
fn a_copy_keeps_the_encryption_of_the_version_and_adds_the_encryption_of_the_instance_when_it_has_none() {
    struct Case {
        name: &'static str,
        mode: Encryption,
        version: Vec<(&'static str, &'static str)>,
        want: Option<&'static str>,
        want_key: Option<&'static str>,
    }
    let cases = vec![
        Case {
            name: "version AES256, instance none",
            mode: Encryption::None,
            version: vec![(SSE_HEADER, "AES256")],
            want: Some("AES256"),
            want_key: None,
        },
        Case {
            name: "version none, instance none",
            mode: Encryption::None,
            version: vec![],
            want: None,
            want_key: None,
        },
        Case {
            name: "version none, instance sse-s3",
            mode: Encryption::SseS3,
            version: vec![],
            want: Some("AES256"),
            want_key: None,
        },
        Case {
            name: "version KMS, instance sse-s3",
            mode: Encryption::SseS3,
            version: vec![(SSE_HEADER, "aws:kms"), (SSE_KMS_KEY_HEADER, "arn:k")],
            want: Some("aws:kms"),
            want_key: Some("arn:k"),
        },
        Case {
            name: "version KMS, instance none",
            mode: Encryption::None,
            version: vec![(SSE_HEADER, "aws:kms"), (SSE_KMS_KEY_HEADER, "arn:k")],
            want: Some("aws:kms"),
            want_key: Some("arn:k"),
        },
    ];
    for case in cases {
        let mut headers = kept_encryption_headers(&headers_of(&case.version));
        write_encryption_headers(&sse_s3(case.mode), &mut headers);
        assert_eq!(text(&headers, SSE_HEADER), case.want, "{}", case.name);
        assert_eq!(text(&headers, SSE_KMS_KEY_HEADER), case.want_key, "{}", case.name);
        assert!(headers.get_all(SSE_HEADER).iter().count() <= 1, "{}", case.name);
    }
}

#[tokio::test]
async fn the_edit_of_the_metadata_sends_the_header_with_sse_s3_and_none_without() {
    for (mode, want) in [(Encryption::SseS3, Some("AES256")), (Encryption::None, None)] {
        let fake = FakeS3::with_config(sse_s3(mode), |_| {
            Reply::new(200, "<CopyObjectResult><ETag>\"e\"</ETag></CopyObjectResult>")
        });
        let headers = headers_of(&[("content-type", "text/csv")]);
        let result = replace_object_metadata(fake.as_ref(), &OpCtx::default(), "a.txt", "", "e", &headers).await;
        assert!(result.is_ok());
        let requests = fake.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(text(&requests[0].headers, SSE_HEADER), want, "{mode:?}");
    }
}

#[tokio::test]
async fn the_edit_of_the_metadata_keeps_the_kms_encryption_of_the_source() {
    let source = headers_of(&[
        (SSE_HEADER, "aws:kms"),
        (SSE_KMS_KEY_HEADER, "arn:k"),
        (SSE_BUCKET_KEY_HEADER, "true"),
        ("x-amz-storage-class", "STANDARD_IA"),
        ("x-amz-checksum-crc32", "ignored"),
    ]);
    for mode in [Encryption::SseS3, Encryption::None] {
        let fake = FakeS3::with_config(sse_s3(mode), |_| Reply::new(200, "<CopyObjectResult/>"));
        let mut headers = kept_object_headers(&source);
        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("text/csv"),
        );
        assert!(
            replace_object_metadata(fake.as_ref(), &OpCtx::default(), "a.txt", "", "e", &headers)
                .await
                .is_ok()
        );
        let requests = fake.requests();
        assert_eq!(requests.len(), 1);
        let header = &requests[0].headers;
        let values: Vec<&str> = header
            .get_all(SSE_HEADER)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect();
        assert_eq!(values, vec!["aws:kms"], "{mode:?}");
        assert_eq!(text(header, SSE_KMS_KEY_HEADER), Some("arn:k"));
        assert_eq!(text(header, SSE_BUCKET_KEY_HEADER), Some("true"));
        assert_eq!(text(header, "x-amz-storage-class"), Some("STANDARD_IA"));
        assert!(header.get("x-amz-checksum-crc32").is_none());
    }
}

// --- The default encryption of the bucket ------------------------------------------------------------------------

#[tokio::test]
async fn the_default_encryption_of_the_bucket_is_read() {
    let cases: Vec<(&str, u16, &str, Option<BucketEncryption>)> = vec![
        (
            "kms",
            200,
            BUCKET_ENCRYPTION_KMS,
            Some(BucketEncryption {
                algorithm: "aws:kms".to_owned(),
                kms_key_id: "arn:k".to_owned(),
                bucket_key_enabled: true,
            }),
        ),
        (
            "aes256",
            200,
            BUCKET_ENCRYPTION_AES,
            Some(BucketEncryption {
                algorithm: "AES256".to_owned(),
                ..BucketEncryption::default()
            }),
        ),
        ("empty answer", 200, "", None),
        ("no rule", 200, "<ServerSideEncryptionConfiguration/>", None),
        ("not found", 404, NO_ENCRYPTION, None),
    ];
    for (name, status, body, want) in cases {
        let fake = FakeS3::constant(status, body);
        let got = read_bucket_encryption(fake.as_ref(), &OpCtx::default()).await;
        assert_eq!(got.ok().flatten(), want, "{name}");
        let requests = fake.requests();
        assert_eq!(requests.len(), 1, "{name}");
        assert_eq!(requests[0].method, Method::GET);
        assert_eq!(requests[0].key, "");
        assert_eq!(requests[0].query, vec![("encryption".to_owned(), String::new())]);
    }
}

#[tokio::test]
async fn a_provider_without_the_request_gives_an_error() {
    // Garage answers 501.
    let fake = FakeS3::constant(501, BUCKET_ENCRYPTION_GARAGE);
    let got = read_bucket_encryption(fake.as_ref(), &OpCtx::default()).await;
    assert!(got.is_err());
}

#[test]
fn the_default_encryption_has_the_json_form_of_the_answers() {
    let kms = BucketEncryption {
        algorithm: "aws:kms".to_owned(),
        kms_key_id: "arn:k".to_owned(),
        bucket_key_enabled: true,
    };
    assert_eq!(
        serde_json::to_string(&kms).unwrap(),
        "{\"algorithm\":\"aws:kms\",\"kmsKeyId\":\"arn:k\",\"bucketKeyEnabled\":true}"
    );
    let aes = BucketEncryption {
        algorithm: "AES256".to_owned(),
        ..BucketEncryption::default()
    };
    assert_eq!(serde_json::to_string(&aes).unwrap(), "{\"algorithm\":\"AES256\"}");
}

// --- The probe ----------------------------------------------------------------------------------------------------

async fn probed(cfg: BucketConfig, status: u16, body: &str, flavour: Option<&str>) -> Arc<Instance> {
    let fake = FakeS3::constant(status, body);
    let backend = FakeBackend::flags(fake, false, true, false, flavour);
    let instance = instance_of(cfg, backend);
    assert!(
        !instance.bucket_encryption_available(),
        "the bucket encryption must be hidden before the probe"
    );
    instance.probe_bucket_encryption(&OpCtx::default()).await;
    instance
}

#[tokio::test]
async fn the_probe_shows_or_hides_the_bucket_encryption() {
    let cases = [
        ("configuration", 200, BUCKET_ENCRYPTION_KMS, true),
        ("not found", 404, NO_ENCRYPTION, true),
        ("not implemented", 501, BUCKET_ENCRYPTION_GARAGE, false),
        ("server error", 500, "<Error><Code>InternalError</Code></Error>", false),
    ];
    for (name, status, body, want) in cases {
        let instance = probed(bucket_config("rw"), status, body, None).await;
        assert_eq!(instance.bucket_encryption_available(), want, "{name}");
    }
}

#[tokio::test]
async fn an_instance_without_the_read_permission_does_not_probe_the_encryption() {
    let mut cfg = bucket_config("rw");
    cfg.permissions_defined = true;
    cfg.permissions = vec!["write".to_owned()];
    let fake = FakeS3::constant(200, BUCKET_ENCRYPTION_KMS);
    let instance = instance_of(cfg, FakeBackend::flags(fake.clone(), false, true, false, None));
    instance.probe_bucket_encryption(&OpCtx::default()).await;
    assert!(!instance.bucket_encryption_available());
    assert!(fake.requests().is_empty());
}

#[tokio::test]
async fn the_instance_gives_the_encryption_of_the_bucket_and_what_the_provider_does_with_the_key() {
    struct Case {
        name: &'static str,
        mode: Encryption,
        flavour: Option<&'static str>,
        status: u16,
        body: &'static str,
        algorithm: &'static str,
        applied: &'static str,
    }
    let cases = vec![
        Case {
            name: "no key and no default",
            mode: Encryption::None,
            flavour: Some("minio"),
            status: 404,
            body: NO_ENCRYPTION,
            algorithm: "",
            applied: "",
        },
        Case {
            name: "default of the bucket",
            mode: Encryption::None,
            flavour: Some("minio"),
            status: 200,
            body: BUCKET_ENCRYPTION_AES,
            algorithm: "AES256",
            applied: "",
        },
        Case {
            name: "default with KMS",
            mode: Encryption::None,
            flavour: Some("seaweedfs"),
            status: 200,
            body: BUCKET_ENCRYPTION_KMS,
            algorithm: "aws:kms",
            applied: "",
        },
        Case {
            name: "key on MinIO",
            mode: Encryption::SseS3,
            flavour: Some("minio"),
            status: 404,
            body: NO_ENCRYPTION,
            algorithm: "",
            applied: ENCRYPTION_APPLIED_YES,
        },
        Case {
            name: "key on SeaweedFS",
            mode: Encryption::SseS3,
            flavour: Some("seaweedfs"),
            status: 404,
            body: NO_ENCRYPTION,
            algorithm: "",
            applied: ENCRYPTION_APPLIED_YES,
        },
        Case {
            name: "key on AWS",
            mode: Encryption::SseS3,
            flavour: Some("aws"),
            status: 404,
            body: NO_ENCRYPTION,
            algorithm: "",
            applied: ENCRYPTION_APPLIED_YES,
        },
        Case {
            name: "key on Garage",
            mode: Encryption::SseS3,
            flavour: Some("garage"),
            status: 501,
            body: BUCKET_ENCRYPTION_GARAGE,
            algorithm: "",
            applied: ENCRYPTION_APPLIED_NO,
        },
        Case {
            name: "key on an unknown provider",
            mode: Encryption::SseS3,
            flavour: None,
            status: 404,
            body: NO_ENCRYPTION,
            algorithm: "",
            applied: ENCRYPTION_APPLIED_UNKNOWN,
        },
        Case {
            name: "key on a provider with an empty flavour",
            mode: Encryption::SseS3,
            flavour: Some(""),
            status: 404,
            body: NO_ENCRYPTION,
            algorithm: "",
            applied: ENCRYPTION_APPLIED_UNKNOWN,
        },
    ];
    for case in cases {
        // The probe of the instance has a GetBucketEncryption answer that a 501 makes an error, but the state is set.
        let instance = probed(sse_s3(case.mode), case.status, case.body, case.flavour).await;
        let (algorithm, applied) = instance.encryption_state();
        assert_eq!(
            (algorithm.as_str(), applied.as_str()),
            (case.algorithm, case.applied),
            "{}",
            case.name
        );
    }
}

// --- The route ----------------------------------------------------------------------------------------------------

async fn encryption_call(
    app: &Arc<crate::common::app::App>,
    method: Method,
    target: &str,
) -> (u16, http::HeaderMap, serde_json::Value, String) {
    answer_of(handle_encryption(app.clone(), request(method, target, None)).await).await
}

#[tokio::test]
async fn the_route_gives_the_defaults_of_the_bucket() {
    let instance = probed(sse_s3(Encryption::SseS3), 200, BUCKET_ENCRYPTION_KMS, Some("minio")).await;
    let app = app_of(vec![instance]);
    let (status, headers, value, text) = encryption_call(&app, Method::GET, "/api/encryption?instance=rw").await;
    assert_eq!(status, 200, "{text}");
    assert_eq!(
        value,
        json!({"instance": "rw", "uploads": "sse-s3",
               "bucketDefault": {"algorithm": "aws:kms", "kmsKeyId": "arn:k", "bucketKeyEnabled": true}})
    );
    assert_eq!(text_of(&headers, "cache-control"), "no-store");
    let (status, ..) = encryption_call(&app, Method::POST, "/api/encryption?instance=rw").await;
    assert_eq!(status, 405);
}

fn text_of(headers: &HeaderMap, name: &str) -> String {
    text(headers, name).unwrap_or("").to_owned()
}

#[tokio::test]
async fn the_route_gives_null_for_a_bucket_without_a_default_encryption() {
    let instance = probed(bucket_config("rw"), 404, NO_ENCRYPTION, None).await;
    let app = app_of(vec![instance]);
    let (status, _, value, text) = encryption_call(&app, Method::GET, "/api/encryption?instance=rw").await;
    assert_eq!(status, 200, "{text}");
    assert!(
        value.get("bucketDefault").is_some_and(serde_json::Value::is_null),
        "{text}"
    );
    assert_eq!(value["uploads"], "");
}

#[tokio::test]
async fn the_route_answers_501_when_the_provider_has_no_request() {
    let instance = probed(bucket_config("rw"), 501, BUCKET_ENCRYPTION_GARAGE, None).await;
    let app = app_of(vec![instance]);
    let (status, _, value, text) = encryption_call(&app, Method::GET, "/api/encryption?instance=rw").await;
    assert_eq!(status, 501, "{text}");
    assert_eq!(value["error"]["code"], "bucket_encryption_unsupported");
}

#[tokio::test]
async fn the_route_needs_the_read_permission_and_a_known_instance() {
    let mut cfg = bucket_config("rw");
    cfg.permissions_defined = true;
    cfg.permissions = vec!["write".to_owned()];
    let fake = FakeS3::constant(200, BUCKET_ENCRYPTION_KMS);
    let instance = instance_of(cfg, FakeBackend::flags(fake.clone(), false, true, false, None));
    let app = app_of(vec![instance]);
    let (status, ..) = encryption_call(&app, Method::GET, "/api/encryption?instance=rw").await;
    assert_eq!(status, 403);
    assert!(fake.requests().is_empty());
    let (status, ..) = encryption_call(&app, Method::GET, "/api/encryption?instance=missing").await;
    assert_eq!(status, 404);
}

// --- Objects with a key of the client (SSE-C) --------------------------------------------------------------------

const CUSTOMER_KEY_SEAWEEDFS: &str =
    "Requests specifying Server Side Encryption with Customer provided keys must provide the customer key.";
const CUSTOMER_KEY_GARAGE: &str = "Bad request: Object is encrypted";

#[test]
fn a_refusal_for_a_key_of_the_client_needs_a_400_with_the_right_text() {
    let cases: Vec<(Error, bool)> = vec![
        (
            Error::upstream(400, "InvalidRequest", "Bad request: Object is encrypted"),
            true,
        ),
        (
            Error::upstream(
                400,
                "InvalidArgument",
                "Server Side Encryption with Customer provided keys",
            ),
            true,
        ),
        (Error::upstream(400, "InvalidArgument", "bad range"), false),
        (Error::upstream(400, "", "400 Bad Request"), false),
        (Error::upstream(403, "AccessDenied", "encrypted"), false),
        (Error::internal("encrypted"), false),
    ];
    for (error, want) in cases {
        assert_eq!(customer_key_refusal(&error), want, "{error:?}");
    }
}

fn secret_listing(page: &mut ListPage) {
    page.objects.push(ObjectInfo {
        key: "tenant/secret.txt".to_owned(),
        size: 6,
        etag: "abc".to_owned(),
        last_modified: Timestamp::parse_rfc3339("2026-10-20T10:00:00Z"),
        ..ObjectInfo::default()
    });
}

fn customer_instance(get: Result<(), Error>) -> Arc<Instance> {
    let backend = FakeBackend::flags(FakeS3::constant(200, ""), false, false, false, None);
    if let Ok(mut slot) = backend.list_fn.lock() {
        *slot = Some(Arc::new(|_| {
            let mut page = ListPage::default();
            secret_listing(&mut page);
            Ok(page)
        }));
    }
    if let Ok(mut slot) = backend.get_fn.lock() {
        *slot = Some(Arc::new(move |_| match &get {
            Ok(()) => Ok(object_response(200, HeaderMap::new(), "x")),
            Err(error) => Err(error.clone()),
        }));
    }
    instance_of(bucket_config("rw"), backend)
}

#[tokio::test]
async fn an_object_with_a_key_of_the_client_is_told_with_its_size_from_the_listing() {
    for (name, text) in [("SeaweedFS", CUSTOMER_KEY_SEAWEEDFS), ("Garage", CUSTOMER_KEY_GARAGE)] {
        // The provider refuses the HEAD (400 without a text) and the ranged GET (400 with a text about the key).
        let instance = customer_instance(Err(Error::upstream(400, "InvalidArgument", text)));
        let head = Error::upstream(400, "", "");
        let info = customer_key_media_info(&OpCtx::default(), &instance, "secret.txt", &head).await;
        let info = info.unwrap_or_else(|| panic!("{name}: no customer key"));
        assert_eq!(info.size, 6, "{name}");
        assert_eq!(info.headers.get("etag").map(String::as_str), Some("\"abc\""), "{name}");
        assert_eq!(
            info.headers.get("last-modified").map(String::as_str),
            Some("Tue, 20 Oct 2026 10:00:00 GMT"),
            "{name}"
        );
    }
}

#[tokio::test]
async fn a_head_that_already_names_the_key_of_the_client_needs_no_ranged_get() {
    let instance = customer_instance(Ok(()));
    let head = Error::upstream(400, "InvalidRequest", CUSTOMER_KEY_GARAGE);
    let info = customer_key_media_info(&OpCtx::default(), &instance, "secret.txt", &head).await;
    assert_eq!(info.map(|value| value.size), Some(6));
}

#[tokio::test]
async fn another_refusal_of_a_read_is_not_the_key_of_the_client() {
    let cases = [
        (
            "unrelated text",
            Err(Error::upstream(400, "InvalidArgument", "bad range")),
        ),
        ("ranged get works", Ok(())),
        (
            "forbidden",
            Err(Error::upstream(403, "InvalidRequest", CUSTOMER_KEY_GARAGE)),
        ),
    ];
    for (name, get) in cases {
        let instance = customer_instance(get);
        let head = Error::upstream(400, "", "");
        let info = customer_key_media_info(&OpCtx::default(), &instance, "secret.txt", &head).await;
        assert!(info.is_none(), "{name}");
    }
    let instance = customer_instance(Ok(()));
    let not_400 = Error::upstream(403, "AccessDenied", "encrypted");
    assert!(
        customer_key_media_info(&OpCtx::default(), &instance, "secret.txt", &not_400)
            .await
            .is_none()
    );
    assert!(
        customer_key_media_info(&OpCtx::default(), &instance, "secret.txt", &Error::internal("x"))
            .await
            .is_none()
    );
}

#[tokio::test]
async fn an_object_with_a_key_of_the_client_names_its_version() {
    let instance = customer_instance(Err(Error::upstream(400, "InvalidArgument", CUSTOMER_KEY_SEAWEEDFS)));
    let ctx = OpCtx::default().with_version(Some("v7"));
    let head = Error::upstream(400, "", "");
    let info = customer_key_media_info(&ctx, &instance, "secret.txt", &head)
        .await
        .unwrap();
    assert_eq!(info.headers.get("x-amz-version-id").map(String::as_str), Some("v7"));
}
