//! The tests of the usage. They check the readers of Garage, SeaweedFS and MinIO, and the limits and the failures of
//! the admin requests. They also check the cache, the single read, the levels, the answers and the route.

use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http::Method;
use serde_json::json;
use tokio::sync::{Semaphore, mpsc};

use crate::bucket::testing::{
    AdminReply, FakeAdmin, FakeBackend, FakeS3, answer_of, app_of, bucket_config, instance_of, request,
};
use crate::bucket::usage::{
    USAGE_CACHE_TTL, USAGE_RETRY_INTERVAL, USAGE_SOURCE_GARAGE, USAGE_SOURCE_MINIO, USAGE_SOURCE_SEAWEEDFS,
    handle_usage, usage_answer, usage_answer_of, usage_approximate_reason, usage_level,
};
use crate::bucket::usage_admin::{
    AdminCredentials, AdminError, AdminFailure, AdminTransport, AdminUrl, get_usage_json,
};
use crate::bucket::usage_garage::{GarageUsageReader, MAX_GARAGE_USAGE_BYTES};
use crate::bucket::usage_minio::MinioUsageReader;
use crate::bucket::usage_seaweedfs::SeaweedFsUsageReader;
use crate::bucket::{BucketUsage, BucketUsageReader, StorageCapacity, new_usage_reader};
use crate::common::BoxFuture;
use crate::common::config::{AuthConfig, UsageConfig, UsageSource};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::time::Timestamp;
use crate::instance::Instance;

// --- The helpers -------------------------------------------------------------------------------------------------

pub(super) const GARAGE_TOKEN: &str = "garage-admin-token-value";
const GARAGE_ANSWER: &str = r#"{"id":"7a9c1f","globalAliases":["default"],"localAliases":[],"websiteAccess":false,"keys":[],"objects":3,"bytes":1500,"unfinishedUploads":0,"unfinishedMultipartUploads":0,"unfinishedMultipartUploadParts":0,"unfinishedMultipartUploadBytes":0,"quotas":{"maxSize":21474836480,"maxObjects":100000}}"#;

pub(super) fn garage_reader(admin: Arc<FakeAdmin>) -> GarageUsageReader {
    GarageUsageReader {
        endpoint: AdminUrl::parse("usage", "http://admin.test:3903").unwrap(),
        transport: admin,
        token: GARAGE_TOKEN.to_owned(),
    }
}

/// An error text must show neither a URL nor a secret.
fn check_no_secret(error: &str, forbidden: &[&str]) {
    for text in forbidden {
        assert!(
            text.is_empty() || !error.contains(text),
            "the error shows {text:?}: {error}"
        );
    }
    assert!(
        !error.contains("http://") && !error.contains("admin.test"),
        "the error shows a URL: {error}"
    );
}

fn json_answer(status: u16, body: &str) -> Arc<FakeAdmin> {
    FakeAdmin::answer(status, body)
}

fn ctx() -> OpCtx {
    OpCtx::default()
}

// --- Garage ------------------------------------------------------------------------------------------------------

#[tokio::test]
async fn the_garage_reader_reads_the_usage_and_the_quota() {
    let admin = json_answer(200, GARAGE_ANSWER);
    let usage = garage_reader(admin.clone()).usage(&ctx(), "default").await.unwrap();
    assert_eq!(usage.used_bytes, 1500);
    assert_eq!(usage.used_objects, 3);
    assert_eq!(usage.limit_bytes, 21_474_836_480);
    assert_eq!(usage.limit_objects, 100_000);
    assert!(!usage.approximate);
    assert!(usage.as_of.is_some(), "as_of is not set");
    let requests = admin.seen();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/v2/GetBucketInfo");
    assert_eq!(requests[0].query, "globalAlias=default");
    let authorization = requests[0]
        .headers
        .get("authorization")
        .and_then(|value| value.to_str().ok());
    assert_eq!(authorization, Some(format!("Bearer {GARAGE_TOKEN}").as_str()));
}

#[tokio::test]
async fn the_garage_reader_escapes_the_name_of_the_bucket() {
    let admin = json_answer(200, GARAGE_ANSWER);
    garage_reader(admin.clone()).usage(&ctx(), "a&b=c d").await.unwrap();
    assert_eq!(admin.seen()[0].query, "globalAlias=a%26b%3Dc+d");
}

#[tokio::test]
async fn the_garage_reader_without_a_quota_gives_no_limit_and_a_missing_counter_is_minus_one() {
    let bodies = [
        ("null quotas", r#"{"objects":3,"bytes":1500,"quotas":null}"#),
        (
            "null limits",
            r#"{"objects":3,"bytes":1500,"quotas":{"maxSize":null,"maxObjects":null}}"#,
        ),
        (
            "zero limits",
            r#"{"objects":3,"bytes":1500,"quotas":{"maxSize":0,"maxObjects":0}}"#,
        ),
        ("no quotas", r#"{"objects":3,"bytes":1500}"#),
    ];
    for (name, body) in bodies {
        let usage = garage_reader(json_answer(200, body))
            .usage(&ctx(), "default")
            .await
            .unwrap();
        assert_eq!(
            (
                usage.limit_bytes,
                usage.limit_objects,
                usage.used_bytes,
                usage.used_objects
            ),
            (0, 0, 1500, 3),
            "{name}"
        );
    }
    let usage = garage_reader(json_answer(200, "{}"))
        .usage(&ctx(), "default")
        .await
        .unwrap();
    assert_eq!((usage.used_bytes, usage.used_objects), (-1, -1));
}

#[tokio::test]
async fn a_refusal_of_the_garage_admin_api_names_the_step_and_the_status_and_hides_the_url_and_the_token() {
    let cases = [
        (
            403,
            format!(r#"{{"code":"AccessDenied","message":"token {GARAGE_TOKEN}"}}"#),
            "HTTP 403",
        ),
        (401, String::new(), "HTTP 401"),
        (
            404,
            r#"{"code":"NoSuchBucket","message":"Bucket not found"}"#.to_owned(),
            "HTTP 404",
        ),
        (500, "oops".to_owned(), "HTTP 500"),
    ];
    for (status, body, want) in cases {
        let error = garage_reader(json_answer(status, &body))
            .usage(&ctx(), "default")
            .await
            .err();
        let error = error.unwrap_or_else(|| panic!("{status}: no error"));
        let text = error.to_string();
        assert!(
            text.contains(want) && text.contains("GetBucketInfo"),
            "{status}: {text}"
        );
        check_no_secret(&text, &[GARAGE_TOKEN]);
        assert!(
            matches!(error, AdminError::Http { status: found, .. } if found == status),
            "{status}: {error:?}"
        );
    }
}

#[test]
fn the_error_texts_of_an_admin_answer() {
    let cases = [
        (401, "refused the credentials (HTTP 401)"),
        (403, "refused the credentials (HTTP 403)"),
        (404, "does not know the bucket (HTTP 404)"),
        (502, "answered HTTP 502"),
    ];
    for (status, want) in cases {
        let text = AdminError::Http {
            step: "step".to_owned(),
            status,
            code: String::new(),
        }
        .to_string();
        assert!(text.starts_with("step: ") && text.contains(want), "{status}: {text}");
    }
}

// --- SeaweedFS ---------------------------------------------------------------------------------------------------

const SEAWEED_VOLUMES: &str = concat!(
    r#"{"Version":"30GB 4.41","Volumes":{"DataCenters":{"DefaultDataCenter":{"DefaultRack":{"127.0.0.1:8080":["#,
    r#"{"Id":2,"Size":1000120,"Collection":"default","FileCount":1,"DeleteCount":1,"DeletedByteCount":1000045,"ReadOnly":false},"#,
    r#"{"Id":3,"Size":1000088,"Collection":"default","FileCount":1,"DeleteCount":0,"DeletedByteCount":0,"ReadOnly":false},"#,
    r#"{"Id":9,"Size":8,"Collection":"","FileCount":1,"DeleteCount":0,"DeletedByteCount":0},"#,
    r#"{"Id":10,"Size":777,"Collection":"other","FileCount":1,"DeleteCount":0,"DeletedByteCount":0}"#,
    r#"]}}},"Free":23,"Max":30}}"#
);

const SEAWEED_BUCKET_ENTRY: &str = r#"{"FullPath":"/buckets/default","Mtime":"2026-10-21T10:00:00Z","Crtime":"2026-10-21T10:00:00Z","Mode":2147484141,"Uid":0,"Gid":0,"Mime":"","Replication":"","Collection":"default","TtlSec":0,"UserName":"","GroupNames":null,"SymlinkTarget":"","Md5":null,"FileSize":0,"Extended":null,"HardLinkId":null,"HardLinkCounter":0,"Content":null,"Remote":null,"Quota":21474836480}"#;

/// A master and a filer on two hosts. The answers are the arguments.
fn seaweed(
    volumes: &str,
    volume_status: u16,
    entry: &str,
    entry_status: u16,
) -> (SeaweedFsUsageReader, Arc<FakeAdmin>) {
    let (volumes, entry) = (volumes.to_owned(), entry.to_owned());
    let admin = FakeAdmin::new(move |recorded| match recorded.path.as_str() {
        "/vol/status" => AdminReply::Answer(volume_status, volumes.clone()),
        path if path.starts_with("/buckets/") => AdminReply::Answer(entry_status, entry.clone()),
        _ => AdminReply::Answer(404, String::new()),
    });
    let reader = SeaweedFsUsageReader {
        master: AdminUrl::parse("usage", "http://master.test:9333").unwrap(),
        filer: Some(AdminUrl::parse("usage", "http://filer.test:8888").unwrap()),
        transport: admin.clone(),
    };
    (reader, admin)
}

#[tokio::test]
async fn the_seaweedfs_reader_reads_the_volumes_and_the_quota() {
    let (reader, admin) = seaweed(SEAWEED_VOLUMES, 200, SEAWEED_BUCKET_ENTRY, 200);
    let usage = reader.usage(&ctx(), "default").await.unwrap();
    // (1000120 - 1000045) + 1000088. The collections "other" and "" are not counted.
    assert_eq!(usage.used_bytes, 75 + 1_000_088);
    assert_eq!(usage.used_objects, -1);
    assert_eq!((usage.limit_bytes, usage.limit_objects), (21_474_836_480, 0));
    assert!(usage.approximate);
    assert!(usage.as_of.is_some());
    let requests = admin.seen();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].url, "http://master.test:9333/vol/status");
    assert_eq!(requests[1].url, "http://filer.test:8888/buckets/default?metadata=true");
    assert!(
        requests
            .iter()
            .all(|request| request.headers.get("authorization").is_none()),
        "a request has a credential"
    );
}

#[tokio::test]
async fn the_seaweedfs_reader_counts_a_replica_one_time() {
    let volumes = concat!(
        r#"{"Volumes":{"DataCenters":{"dc1":{"rack1":{"10.0.0.1:8080":[{"Id":2,"Size":1000,"Collection":"default","DeletedByteCount":100}]},"#,
        r#""rack2":{"10.0.0.2:8080":[{"Id":2,"Size":1000,"Collection":"default","DeletedByteCount":100},{"Id":4,"Size":50,"Collection":"default","DeletedByteCount":0}]}},"#,
        r#""dc2":{"rack1":{"10.0.1.1:8080":[{"Id":2,"Size":1000,"Collection":"default","DeletedByteCount":100}]}}}}}"#
    );
    let (reader, _) = seaweed(volumes, 200, SEAWEED_BUCKET_ENTRY, 200);
    assert_eq!(reader.usage(&ctx(), "default").await.unwrap().used_bytes, 900 + 50);
}

#[tokio::test]
async fn the_seaweedfs_reader_accepts_empty_volume_lists() {
    let bodies = [
        (
            "null node list",
            r#"{"Volumes":{"DataCenters":{"dc":{"rack":{"127.0.0.1:8080":null}}}}}"#,
        ),
        ("no node", r#"{"Volumes":{"DataCenters":{"dc":{"rack":{}}}}}"#),
        ("no data center", r#"{"Volumes":{"DataCenters":{}}}"#),
        ("null centers", r#"{"Volumes":{"DataCenters":null}}"#),
        ("no volumes", r#"{"Version":"30GB 4.41"}"#),
    ];
    for (name, body) in bodies {
        let (reader, _) = seaweed(body, 200, SEAWEED_BUCKET_ENTRY, 200);
        let usage = reader
            .usage(&ctx(), "default")
            .await
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!((usage.used_bytes, usage.limit_bytes), (0, 21_474_836_480), "{name}");
    }
}

#[tokio::test]
async fn the_seaweedfs_reader_does_not_count_a_negative_volume() {
    let volumes = r#"{"Volumes":{"DataCenters":{"dc":{"rack":{"n":[{"Id":1,"Size":10,"Collection":"default","DeletedByteCount":50},{"Id":2,"Size":5,"Collection":"default"}]}}}}}"#;
    let (reader, _) = seaweed(volumes, 200, SEAWEED_BUCKET_ENTRY, 200);
    assert_eq!(reader.usage(&ctx(), "default").await.unwrap().used_bytes, 5);
}

#[tokio::test]
async fn the_seaweedfs_quota_values() {
    // 0 is no quota. A negative value is a quota that "s3.bucket.quota -op=disable" turned off.
    let cases = [
        ("set", r#"{"FullPath":"/buckets/default","Quota":1048576}"#, 1_048_576),
        ("zero", r#"{"FullPath":"/buckets/default","Quota":0}"#, 0),
        ("negative", r#"{"FullPath":"/buckets/default","Quota":-1048576}"#, 0),
        ("absent", r#"{"FullPath":"/buckets/default"}"#, 0),
    ];
    for (name, entry, want) in cases {
        let (reader, _) = seaweed(SEAWEED_VOLUMES, 200, entry, 200);
        let usage = reader.usage(&ctx(), "default").await.unwrap();
        assert_eq!(
            (usage.limit_bytes, usage.used_objects, usage.approximate),
            (want, -1, true),
            "{name}"
        );
    }
}

#[tokio::test]
async fn the_seaweedfs_errors_hide_the_url() {
    // The filer does not know the bucket.
    let (reader, admin) = seaweed(SEAWEED_VOLUMES, 200, "", 404);
    let error = reader.usage(&ctx(), "default").await.err().unwrap().to_string();
    assert!(error.contains("bucket entry") && error.contains("HTTP 404"), "{error}");
    check_no_secret(&error, &["filer.test", "master.test"]);
    assert_eq!(admin.seen().len(), 2);
    // The master fails: the reader does not call the filer.
    let (reader, admin) = seaweed("boom", 500, SEAWEED_BUCKET_ENTRY, 200);
    let error = reader.usage(&ctx(), "default").await.err().unwrap().to_string();
    assert!(error.contains("volume status") && error.contains("HTTP 500"), "{error}");
    check_no_secret(&error, &["filer.test", "master.test"]);
    assert_eq!(admin.seen().len(), 1, "the filer got a request");
}

// --- MinIO -------------------------------------------------------------------------------------------------------

pub(super) const MINIO_KEY: &str = "AKIATESTKEY";
const MINIO_SECRET: &str = "minio-secret-value";
const MINIO_QUOTA_OK: &str = r#"{"quota":21474836480,"size":0,"rate":0,"requests":0,"quotatype":"hard"}"#;
const MINIO_USAGE_OK: &str = r#"{"lastUpdate":"2026-10-21T10:52:20.457354406Z","objectsCount":1,"bucketsCount":3,"bucketsUsageInfo":{"default":{"size":500000,"objectsCount":1,"versionsCount":0},"other":{"size":7,"objectsCount":1}}}"#;
const MINIO_NOT_SET: &str = r#"{"Code":"XMinioAdminBucketQuotaNotConfigured","Message":"Quota not configured","Resource":"","RequestId":"1","HostId":"h"}"#;
const MINIO_NO_COUNT_YET: &str =
    r#"{"lastUpdate":"0001-01-01T00:00:00Z","objectsCount":0,"bucketsCount":0,"bucketsUsageInfo":{}}"#;

pub(super) fn minio_reader(admin: Arc<FakeAdmin>) -> MinioUsageReader {
    MinioUsageReader {
        endpoint: AdminUrl::parse("usage", "http://admin.test:9000").unwrap(),
        transport: admin,
        credentials: AdminCredentials {
            access_key_id: MINIO_KEY.to_owned(),
            secret_access_key: MINIO_SECRET.to_owned(),
            session_token: String::new(),
        },
        region: "us-east-1".to_owned(),
    }
}

/// A fake admin API of MinIO. The two answers are the status and the body of each request.
fn minio(quota: (u16, &str), usage: (u16, &str)) -> (MinioUsageReader, Arc<FakeAdmin>) {
    let (quota, usage) = ((quota.0, quota.1.to_owned()), (usage.0, usage.1.to_owned()));
    let admin = FakeAdmin::new(move |recorded| match recorded.path.as_str() {
        "/minio/admin/v3/get-bucket-quota" => AdminReply::Answer(quota.0, quota.1.clone()),
        "/minio/admin/v3/datausageinfo" => AdminReply::Answer(usage.0, usage.1.clone()),
        other => panic!("unexpected request {other}"),
    });
    (minio_reader(admin.clone()), admin)
}

#[tokio::test]
async fn the_minio_reader_signs_and_reads_the_usage_and_the_quota() {
    let (reader, admin) = minio((200, MINIO_QUOTA_OK), (200, MINIO_USAGE_OK));
    let usage = reader.usage(&ctx(), "default").await.unwrap();
    let want_as_of = Timestamp::parse_rfc3339("2026-10-21T10:52:20.457354406Z").unwrap();
    assert_eq!((usage.used_bytes, usage.used_objects), (500_000, 1));
    assert_eq!((usage.limit_bytes, usage.limit_objects), (21_474_836_480, 0));
    assert!(usage.approximate);
    assert_eq!(
        usage.as_of.map(|value| (value.secs, value.nanos)),
        Some((want_as_of.secs, want_as_of.nanos))
    );
    let requests = admin.seen();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        (requests[0].path.as_str(), requests[0].query.as_str()),
        ("/minio/admin/v3/get-bucket-quota", "bucket=default")
    );
    assert_eq!(
        (requests[1].path.as_str(), requests[1].query.as_str()),
        ("/minio/admin/v3/datausageinfo", "")
    );
    for request in requests {
        let authorization = request
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("");
        assert!(
            authorization.starts_with(&format!("AWS4-HMAC-SHA256 Credential={MINIO_KEY}/"))
                && authorization.contains("/us-east-1/s3/aws4_request")
                && authorization.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date")
                && authorization.contains("Signature="),
            "{authorization}"
        );
        assert!(!authorization.contains(MINIO_SECRET), "the secret is in the header");
        assert!(request.headers.get("x-amz-date").is_some() && request.headers.get("x-amz-content-sha256").is_some());
    }
}

#[tokio::test]
async fn the_minio_signature_includes_the_session_token_when_there_is_one() {
    let (mut reader, admin) = minio((200, MINIO_QUOTA_OK), (200, MINIO_USAGE_OK));
    reader.credentials.session_token = "session-token-value".to_owned();
    reader.usage(&ctx(), "default").await.unwrap();
    let request = &admin.seen()[0];
    assert_eq!(
        request
            .headers
            .get("x-amz-security-token")
            .and_then(|value| value.to_str().ok()),
        Some("session-token-value")
    );
    let authorization = request
        .headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    assert!(authorization.contains("SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token"));
}

#[tokio::test]
async fn the_minio_quota_fields() {
    // The field "size" wins when it is more than 0. Else "quota" gives the limit.
    let cases = [
        ("quota", 200, r#"{"quota":1000,"size":0,"quotatype":"hard"}"#, 1000),
        (
            "size wins",
            200,
            r#"{"quota":1000,"size":2000,"quotatype":"hard"}"#,
            2000,
        ),
        ("size only", 200, r#"{"size":2000}"#, 2000),
        ("no quota", 200, r#"{"quota":0,"size":0}"#, 0),
        ("negative quota", 200, r#"{"quota":-5,"size":0}"#, 0),
        ("not configured", 404, MINIO_NOT_SET, 0),
    ];
    for (name, status, body, want) in cases {
        let (reader, _) = minio((status, body), (200, MINIO_USAGE_OK));
        let usage = reader
            .usage(&ctx(), "default")
            .await
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        assert_eq!((usage.limit_bytes, usage.used_bytes), (want, 500_000), "{name}");
    }
}

#[tokio::test]
async fn the_minio_quota_errors() {
    // Another 404, a refusal or a bad answer are errors. Only the code "not configured" is no limit.
    let cases = [
        (
            "other 404",
            404,
            r#"{"Code":"NoSuchBucket","Message":"The specified bucket does not exist"}"#,
            "HTTP 404",
        ),
        ("404 no document", 404, "", "HTTP 404"),
        (
            "403",
            403,
            r#"{"Code":"XMinioAccessDenied","Message":"Access Denied."}"#,
            "HTTP 403",
        ),
        ("500", 500, "oops", "HTTP 500"),
        ("not JSON", 200, "<html>", "not the expected JSON"),
    ];
    for (name, status, body, want) in cases {
        let (reader, admin) = minio((status, body), (200, MINIO_USAGE_OK));
        let error = reader
            .usage(&ctx(), "default")
            .await
            .err()
            .unwrap_or_else(|| panic!("{name}: no error"))
            .to_string();
        assert!(
            error.contains(want) && error.contains("get-bucket-quota"),
            "{name}: {error}"
        );
        check_no_secret(&error, &[MINIO_SECRET]);
        assert_eq!(admin.seen().len(), 1, "{name}: the reader went on after the error");
    }
}

#[tokio::test]
async fn the_minio_usage_errors() {
    let cases = [
        ("zero lastUpdate", 200, MINIO_NO_COUNT_YET, "has not counted the usage"),
        (
            "no lastUpdate",
            200,
            r#"{"bucketsUsageInfo":{"default":{"size":5}}}"#,
            "has not counted the usage",
        ),
        ("403", 403, r#"{"Code":"XMinioAccessDenied"}"#, "HTTP 403"),
        ("not JSON", 200, "nope", "not the expected JSON"),
        (
            "bad time",
            200,
            r#"{"lastUpdate":"yesterday"}"#,
            "not the expected JSON",
        ),
    ];
    for (name, status, body, want) in cases {
        let (reader, _) = minio((200, MINIO_QUOTA_OK), (status, body));
        let error = reader
            .usage(&ctx(), "default")
            .await
            .err()
            .unwrap_or_else(|| panic!("{name}: no error"))
            .to_string();
        assert!(
            error.contains(want) && error.contains("datausageinfo"),
            "{name}: {error}"
        );
        check_no_secret(&error, &[MINIO_SECRET]);
    }
}

#[tokio::test]
async fn a_bucket_that_the_last_minio_count_does_not_know_is_empty() {
    let (reader, _) = minio((200, MINIO_QUOTA_OK), (200, MINIO_USAGE_OK));
    let usage = reader.usage(&ctx(), "new-bucket").await.unwrap();
    assert_eq!(
        (
            usage.used_bytes,
            usage.used_objects,
            usage.limit_bytes,
            usage.approximate
        ),
        (0, 0, 21_474_836_480, true)
    );
    let other = reader.usage(&ctx(), "other").await.unwrap();
    assert_eq!((other.used_bytes, other.used_objects), (7, 1));
}

#[tokio::test]
async fn the_minio_reader_refuses_an_unsignable_request() {
    let (mut reader, admin) = minio((200, MINIO_QUOTA_OK), (200, MINIO_USAGE_OK));
    reader.region = String::new();
    let error = reader.usage(&ctx(), "default").await.err().unwrap().to_string();
    assert!(error.contains("cannot sign the request"), "{error}");
    assert!(admin.seen().is_empty(), "the reader sent an unsigned request");
}

// --- The limits and the failures of the admin requests ----------------------------------------------------------

#[tokio::test]
async fn the_reader_refuses_an_answer_over_the_limit() {
    let padding = "a".repeat(MAX_GARAGE_USAGE_BYTES);
    let admin = json_answer(200, &format!(r#"{{"objects":1,"bytes":2,"pad":"{padding}"}}"#));
    let error = garage_reader(admin)
        .usage(&ctx(), "default")
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("longer than"), "{error}");
    check_no_secret(&error, &[GARAGE_TOKEN]);
}

#[tokio::test]
async fn the_size_limit_of_an_admin_answer_is_exact() {
    let body = format!(r#"{{"a":"{}"}}"#, "x".repeat(20));
    let admin = json_answer(200, &body);
    let get = |limit: usize| {
        let admin = admin.clone();
        async move {
            get_usage_json::<std::collections::BTreeMap<String, String>>(
                admin.as_ref(),
                &ctx(),
                "http://admin.test/x",
                http::HeaderMap::new(),
                "step",
                limit,
            )
            .await
        }
    };
    assert!(get(body.len()).await.is_ok(), "an answer of exactly the limit");
    let error = get(body.len() - 1).await.err().unwrap().to_string();
    assert!(error.contains("longer than"), "an answer over the limit: {error}");
}

#[tokio::test]
async fn the_status_of_a_long_error_answer_comes_first() {
    let admin = json_answer(403, &"e".repeat(4096));
    let error = get_usage_json::<std::collections::BTreeMap<String, String>>(
        admin.as_ref(),
        &ctx(),
        "http://admin.test/x",
        http::HeaderMap::new(),
        "step",
        10,
    )
    .await
    .err()
    .unwrap();
    assert!(matches!(error, AdminError::Http { status: 403, .. }), "{error:?}");
}

#[tokio::test]
async fn the_code_of_the_error_document_is_kept() {
    for (name, body) in [("upper", r#"{"Code":"MyCode"}"#), ("lower", r#"{"code":"MyCode"}"#)] {
        let admin = json_answer(404, body);
        let error = get_usage_json::<std::collections::BTreeMap<String, String>>(
            admin.as_ref(),
            &ctx(),
            "http://admin.test/x",
            http::HeaderMap::new(),
            "step",
            1024,
        )
        .await
        .err()
        .unwrap();
        assert!(
            matches!(&error, AdminError::Http { code, .. } if code == "MyCode"),
            "{name}: {error:?}"
        );
    }
}

#[tokio::test]
async fn the_reader_refuses_an_answer_that_is_not_json() {
    let bodies = [
        ("html", "<html>login</html>"),
        ("empty", ""),
        ("truncated", r#"{"objects":"#),
        ("wrong type", r#"{"objects":"three"}"#),
    ];
    for (name, body) in bodies {
        let error = garage_reader(json_answer(200, body))
            .usage(&ctx(), "default")
            .await
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("not the expected JSON"), "{name}: {error}");
        check_no_secret(&error, &[GARAGE_TOKEN]);
    }
}

#[tokio::test]
async fn a_server_slower_than_the_deadline_gives_the_did_not_answer_error_without_the_url() {
    let admin = FakeAdmin::new(|_| AdminReply::Hang);
    let deadline = ctx().with_timeout(Duration::from_millis(50));
    let error = garage_reader(admin)
        .usage(&deadline, "default")
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(
        error.contains("did not answer") && error.contains("GetBucketInfo"),
        "{error}"
    );
    check_no_secret(&error, &[GARAGE_TOKEN]);
}

#[tokio::test]
async fn a_canceled_request_gives_the_canceled_error_without_the_url() {
    let canceled = ctx();
    canceled.cancel.cancel();
    let admin = FakeAdmin::new(|_| AdminReply::Hang);
    let error = garage_reader(admin)
        .usage(&canceled, "default")
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("canceled"), "{error}");
    check_no_secret(&error, &[GARAGE_TOKEN]);
}

#[tokio::test]
async fn a_failed_connection_gives_the_cannot_connect_error_without_the_url() {
    let admin = FakeAdmin::new(|_| AdminReply::Failure(AdminFailure::Connect));
    let error = garage_reader(admin)
        .usage(&ctx(), "default")
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("cannot connect to the admin API"), "{error}");
    check_no_secret(&error, &[GARAGE_TOKEN]);
}

#[tokio::test]
async fn an_untrusted_certificate_gives_the_certificate_error_without_the_url() {
    let admin = FakeAdmin::new(|_| AdminReply::Failure(AdminFailure::Certificate));
    let error = garage_reader(admin)
        .usage(&ctx(), "default")
        .await
        .err()
        .unwrap()
        .to_string();
    assert!(
        error.contains("TLS certificate of the admin API is not valid"),
        "{error}"
    );
    check_no_secret(&error, &[GARAGE_TOKEN]);
}

// --- The reader of an auth block ---------------------------------------------------------------------------------

#[test]
fn the_reader_of_an_auth_block_follows_the_source_of_the_usage_block() {
    let transport: Arc<dyn AdminTransport> = FakeAdmin::answer(200, "{}");
    let credentials = AdminCredentials {
        access_key_id: "k".to_owned(),
        secret_access_key: "s".to_owned(),
        session_token: String::new(),
    };
    let auth = |usage: Option<UsageConfig>| AuthConfig {
        id: "a".to_owned(),
        region: "eu".to_owned(),
        usage,
        ..AuthConfig::default()
    };
    let usage = |source: UsageSource, endpoint: &str, filer: &str| UsageConfig {
        source,
        endpoint: endpoint.to_owned(),
        filer_endpoint: filer.to_owned(),
        token: "t".to_owned(),
    };
    assert!(
        new_usage_reader(&auth(None), transport.clone(), credentials.clone())
            .unwrap()
            .is_none()
    );
    let garage = new_usage_reader(
        &auth(Some(usage(UsageSource::Garage, "http://g:3903", ""))),
        transport.clone(),
        credentials.clone(),
    );
    assert_eq!(garage.unwrap().map(|reader| reader.source()), Some(USAGE_SOURCE_GARAGE));
    let weed = new_usage_reader(
        &auth(Some(usage(UsageSource::SeaweedFs, "http://m:9333", "http://f:8888"))),
        transport.clone(),
        credentials.clone(),
    );
    assert_eq!(
        weed.unwrap().map(|reader| reader.source()),
        Some(USAGE_SOURCE_SEAWEEDFS)
    );
    let minio = new_usage_reader(
        &auth(Some(usage(UsageSource::MinIo, "http://minio:9000", ""))),
        transport.clone(),
        credentials.clone(),
    );
    assert_eq!(minio.unwrap().map(|reader| reader.source()), Some(USAGE_SOURCE_MINIO));
    let wrong = new_usage_reader(
        &auth(Some(usage(UsageSource::SeaweedFs, "http://m:9333", "ftp://f"))),
        transport,
        credentials,
    );
    assert!(wrong.is_err(), "a wrong filer endpoint must give an error");
}

// --- The cache and the single read -------------------------------------------------------------------------------

type Behavior = Box<dyn FnMut(usize) -> Result<BucketUsage> + Send>;

/// A usage reader that counts its calls. A call runs its behavior, after it waits for the gate when there is one.
pub(super) struct FakeReader {
    calls: AtomicUsize,
    buckets: Mutex<Vec<String>>,
    deadlines: Mutex<Vec<bool>>,
    canceled: Mutex<Vec<bool>>,
    entered: Option<mpsc::UnboundedSender<()>>,
    gate: Option<Arc<Semaphore>>,
    behavior: Mutex<Option<Behavior>>,
    capacity: Mutex<Option<Result<StorageCapacity>>>,
}

impl FakeReader {
    pub(super) fn new() -> Self {
        Self {
            calls: AtomicUsize::new(0),
            buckets: Mutex::new(Vec::new()),
            deadlines: Mutex::new(Vec::new()),
            canceled: Mutex::new(Vec::new()),
            entered: None,
            gate: None,
            behavior: Mutex::new(None),
            capacity: Mutex::new(None),
        }
    }

    pub(super) fn with_behavior(self, behavior: impl FnMut(usize) -> Result<BucketUsage> + Send + 'static) -> Self {
        if let Ok(mut slot) = self.behavior.lock() {
            *slot = Some(Box::new(behavior));
        }
        self
    }

    pub(super) fn with_capacity(self, capacity: Result<StorageCapacity>) -> Self {
        self.set_capacity(capacity);
        self
    }

    pub(super) fn set_capacity(&self, capacity: Result<StorageCapacity>) {
        if let Ok(mut slot) = self.capacity.lock() {
            *slot = Some(capacity);
        }
    }

    /// The result of each call is the same: a value, or an error.
    pub(super) fn with_behavior_result(self, result: Result<BucketUsage>) -> Self {
        self.with_behavior(move |_| result.clone())
    }

    fn gated(mut self) -> (Self, mpsc::UnboundedReceiver<()>, Arc<Semaphore>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        let gate = Arc::new(Semaphore::new(0));
        self.entered = Some(sender);
        self.gate = Some(gate.clone());
        (self, receiver, gate)
    }

    pub(super) fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl BucketUsageReader for FakeReader {
    fn bucket_usage<'a>(&'a self, ctx: &'a OpCtx, bucket: &'a str) -> BoxFuture<'a, Result<BucketUsage>> {
        Box::pin(async move {
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if let Ok(mut list) = self.buckets.lock() {
                list.push(bucket.to_owned());
            }
            if let Ok(mut list) = self.deadlines.lock() {
                list.push(
                    ctx.deadline
                        .is_some_and(|deadline| deadline > std::time::Instant::now()),
                );
            }
            if let Some(entered) = &self.entered {
                let _ = entered.send(());
            }
            if let Some(gate) = &self.gate
                && let Ok(permit) = gate.acquire().await
            {
                permit.forget();
            }
            if let Ok(mut list) = self.canceled.lock() {
                list.push(ctx.check().is_err());
            }
            let mut behavior = self.behavior.lock().map_err(|_| Error::internal("lock"))?;
            match behavior.as_mut() {
                Some(behavior) => behavior(call),
                None => Ok(BucketUsage {
                    used_bytes: i64::try_from(call).unwrap_or(0),
                    used_objects: -1,
                    limit_bytes: 1000,
                    ..BucketUsage::default()
                }),
            }
        })
    }

    fn storage_capacity<'a>(&'a self, _ctx: &'a OpCtx) -> BoxFuture<'a, Result<Option<StorageCapacity>>> {
        let capacity = self.capacity.lock().ok().and_then(|slot| slot.clone());
        Box::pin(async move {
            match capacity {
                Some(Ok(capacity)) => Ok(Some(capacity)),
                Some(Err(error)) => Err(error),
                None => Ok(None),
            }
        })
    }
}

/// A clock that a test moves, in seconds.
#[derive(Clone)]
pub(super) struct Clock(Arc<AtomicI64>);

impl Clock {
    pub(super) fn new() -> Self {
        // 2026-10-21T12:00:00Z
        Self(Arc::new(AtomicI64::new(1_792_584_000)))
    }

    pub(super) fn advance(&self, duration: Duration) {
        self.0
            .fetch_add(i64::try_from(duration.as_secs()).unwrap_or(0), Ordering::SeqCst);
    }

    pub(super) fn install(&self, instance: &Instance) {
        let shared = self.0.clone();
        instance
            .usage
            .set_clock(Arc::new(move || Timestamp::from_unix(shared.load(Ordering::SeqCst), 0)));
    }
}

/// An instance with a reader of the source `garage`: the bucket `the-bucket`, the root prefix `tenant/`.
pub(super) fn usage_instance(reader: Arc<FakeReader>, quota: i64) -> Arc<Instance> {
    let mut cfg = bucket_config("inst");
    cfg.bucket = "the-bucket".to_owned();
    cfg.quota_bytes = quota;
    let backend = FakeBackend::flags(FakeS3::constant(200, ""), false, false, false, None);
    let instance = instance_of(cfg, backend);
    instance.usage.set_reader(reader, USAGE_SOURCE_GARAGE);
    instance
}

fn plain_reader() -> Arc<FakeReader> {
    Arc::new(FakeReader::new())
}

#[tokio::test]
async fn an_instance_without_a_reader_has_no_usage() {
    let backend = FakeBackend::flags(FakeS3::constant(200, ""), false, false, false, None);
    let instance = instance_of(bucket_config("inst"), backend);
    assert!(
        !instance.usage_available(),
        "an instance without a reader must not offer the usage"
    );
    let error = instance.bucket_usage(&ctx(), false).await.err().unwrap();
    assert!(error.has_code("usage_unsupported"));
    assert_eq!(error.status(), 501);
}

#[tokio::test]
async fn the_usage_is_read_for_the_bucket_with_a_deadline() {
    let reader = plain_reader();
    let instance = usage_instance(reader.clone(), 0);
    Clock::new().install(&instance);
    let value = instance.bucket_usage(&ctx(), false).await.unwrap();
    assert_eq!((value.source.as_str(), value.used_bytes), (USAGE_SOURCE_GARAGE, 1));
    assert_eq!(reader.buckets.lock().unwrap().clone(), vec!["the-bucket".to_owned()]);
    assert_eq!(reader.deadlines.lock().unwrap().clone(), vec![true]);
}

#[tokio::test]
async fn concurrent_requests_make_one_read_and_get_the_same_result() {
    const CALLERS: usize = 12;
    let (reader, mut entered, gate) = FakeReader::new().gated();
    let reader = Arc::new(reader);
    let instance = usage_instance(reader.clone(), 0);
    Clock::new().install(&instance);
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..CALLERS {
        let instance = instance.clone();
        tasks.spawn(async move { instance.bucket_usage(&OpCtx::default(), false).await });
    }
    entered.recv().await;
    // The other callers wait for the read. A short pause lets them reach the wait.
    tokio::time::sleep(Duration::from_millis(50)).await;
    gate.add_permits(CALLERS * 2);
    let mut done = 0;
    while let Some(joined) = tasks.join_next().await {
        let value = joined.unwrap().unwrap();
        assert_eq!((value.used_bytes, value.source.as_str()), (1, USAGE_SOURCE_GARAGE));
        done += 1;
    }
    assert_eq!(done, CALLERS);
    assert_eq!(reader.call_count(), 1);
}

#[tokio::test]
async fn a_result_lives_60_seconds() {
    let reader = plain_reader();
    let instance = usage_instance(reader.clone(), 0);
    let clock = Clock::new();
    clock.install(&instance);
    let read = |calls: usize, bytes: i64| {
        let (instance, reader) = (instance.clone(), reader.clone());
        async move {
            let value = instance.bucket_usage(&OpCtx::default(), false).await.unwrap();
            assert_eq!((reader.call_count(), value.used_bytes), (calls, bytes));
        }
    };
    read(1, 1).await;
    clock.advance(Duration::from_secs(30));
    read(1, 1).await;
    clock.advance(Duration::from_secs(29));
    read(1, 1).await;
    clock.advance(Duration::from_secs(2)); // 61 s after the read
    read(2, 2).await;
    clock.advance(Duration::from_secs(59));
    read(2, 2).await;
    clock.advance(Duration::from_secs(2));
    read(3, 3).await;
    assert_eq!(USAGE_CACHE_TTL, Duration::from_secs(60));
}

#[tokio::test]
async fn a_failure_lives_10_seconds_and_a_failed_result_has_no_value() {
    let failure = Error::internal("GetBucketInfo: the admin API refused the credentials (HTTP 403)");
    let expected = failure.clone();
    let reader = Arc::new(FakeReader::new().with_behavior(move |call| {
        if call == 1 {
            Err(failure.clone())
        } else {
            Ok(BucketUsage {
                used_bytes: 5,
                ..BucketUsage::default()
            })
        }
    }));
    let instance = usage_instance(reader.clone(), 0);
    let clock = Clock::new();
    clock.install(&instance);
    let result = instance.usage_read(&ctx(), false).await;
    assert_eq!(result.error, Some(expected.clone()));
    assert_eq!(result.value, BucketUsage::default());
    clock.advance(Duration::from_secs(9));
    assert_eq!(instance.bucket_usage(&ctx(), false).await.err(), Some(expected.clone()));
    assert_eq!(reader.call_count(), 1);
    // fresh = true does not read again inside the 10 s.
    assert_eq!(instance.bucket_usage(&ctx(), true).await.err(), Some(expected));
    assert_eq!(reader.call_count(), 1);
    clock.advance(Duration::from_secs(2));
    let value = instance.bucket_usage(&ctx(), false).await.unwrap();
    assert_eq!((value.used_bytes, reader.call_count()), (5, 2));
    // The success lives 60 s again.
    clock.advance(Duration::from_secs(50));
    let value = instance.bucket_usage(&ctx(), false).await.unwrap();
    assert_eq!((value.used_bytes, reader.call_count()), (5, 2));
    assert_eq!(USAGE_RETRY_INTERVAL, Duration::from_secs(10));
}

#[tokio::test]
async fn fresh_reads_again_only_a_result_older_than_10_seconds() {
    let reader = plain_reader();
    let instance = usage_instance(reader.clone(), 0);
    let clock = Clock::new();
    clock.install(&instance);
    let bytes = |fresh: bool| {
        let instance = instance.clone();
        async move {
            instance
                .bucket_usage(&OpCtx::default(), fresh)
                .await
                .map(|value| value.used_bytes)
        }
    };
    assert!(bytes(true).await.is_ok());
    assert_eq!(reader.call_count(), 1);
    clock.advance(Duration::from_secs(5));
    assert_eq!((bytes(true).await.unwrap(), reader.call_count()), (1, 1), "5 s");
    clock.advance(Duration::from_secs(6)); // 11 s
    assert_eq!(
        (bytes(false).await.unwrap(), reader.call_count()),
        (1, 1),
        "11 s without fresh"
    );
    assert_eq!(
        (bytes(true).await.unwrap(), reader.call_count()),
        (2, 2),
        "11 s with fresh"
    );
    clock.advance(Duration::from_secs(1));
    assert_eq!(
        (bytes(true).await.unwrap(), reader.call_count()),
        (2, 2),
        "1 s after a fresh read"
    );
}

#[tokio::test]
async fn a_caller_that_stops_while_another_call_reads_gets_its_own_error_and_the_read_goes_on() {
    let (reader, mut entered, gate) = FakeReader::new().gated();
    let reader = Arc::new(reader);
    let instance = usage_instance(reader.clone(), 0);
    Clock::new().install(&instance);
    let first = {
        let instance = instance.clone();
        tokio::spawn(async move { instance.bucket_usage(&OpCtx::default(), false).await })
    };
    entered.recv().await;
    let waiting = OpCtx::default();
    let second = {
        let (instance, ctx) = (instance.clone(), waiting.clone());
        tokio::spawn(async move { instance.bucket_usage(&ctx, false).await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    waiting.cancel.cancel();
    assert_eq!(second.await.unwrap().err(), Some(Error::Canceled));
    gate.add_permits(4);
    assert!(first.await.unwrap().is_ok());
    assert_eq!(reader.call_count(), 1);
    assert_eq!(reader.canceled.lock().unwrap().clone(), vec![false]);
    // The result is in the cache.
    let value = instance.bucket_usage(&ctx(), false).await.unwrap();
    assert_eq!((value.used_bytes, reader.call_count()), (1, 1));
}

#[tokio::test]
async fn the_caller_that_starts_the_read_can_stop_too_and_the_result_goes_to_the_cache() {
    let (reader, mut entered, gate) = FakeReader::new().gated();
    let reader = Arc::new(reader);
    let instance = usage_instance(reader.clone(), 0);
    Clock::new().install(&instance);
    let starting = OpCtx::default();
    let done = {
        let (instance, ctx) = (instance.clone(), starting.clone());
        tokio::spawn(async move { instance.bucket_usage(&ctx, false).await })
    };
    entered.recv().await;
    starting.cancel.cancel();
    gate.add_permits(4);
    assert!(done.await.unwrap().is_ok(), "the read stopped with the caller");
    assert_eq!(
        reader.canceled.lock().unwrap().clone(),
        vec![false],
        "the context of the read was canceled"
    );
    let value = instance.bucket_usage(&ctx(), false).await.unwrap();
    assert_eq!((value.used_bytes, reader.call_count()), (1, 1));
}

#[tokio::test]
async fn a_read_that_is_dropped_does_not_stop_the_read_for_the_others() {
    let (reader, mut entered, gate) = FakeReader::new().gated();
    let reader = Arc::new(reader);
    let instance = usage_instance(reader.clone(), 0);
    Clock::new().install(&instance);
    let first = {
        let instance = instance.clone();
        tokio::spawn(async move { instance.bucket_usage(&OpCtx::default(), false).await })
    };
    entered.recv().await;
    // The client of the first request goes: its future is dropped.
    first.abort();
    let _ = first.await;
    let second = {
        let instance = instance.clone();
        tokio::spawn(async move { instance.bucket_usage(&OpCtx::default(), false).await })
    };
    tokio::time::sleep(Duration::from_millis(50)).await;
    gate.add_permits(4);
    assert!(second.await.unwrap().is_ok());
    assert_eq!(reader.call_count(), 1);
}

#[tokio::test]
async fn the_waiters_get_the_error_of_the_read() {
    let failure = Error::internal("GetBucketInfo: cannot connect to the admin API");
    let expected = failure.clone();
    let (reader, mut entered, gate) = FakeReader::new().gated();
    let reader = Arc::new(reader.with_behavior(move |_| Err(failure.clone())));
    let instance = usage_instance(reader.clone(), 0);
    Clock::new().install(&instance);
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..4 {
        let instance = instance.clone();
        tasks.spawn(async move { instance.bucket_usage(&OpCtx::default(), false).await });
    }
    entered.recv().await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    gate.add_permits(8);
    while let Some(joined) = tasks.join_next().await {
        assert_eq!(joined.unwrap().err(), Some(expected.clone()));
    }
    assert_eq!(reader.call_count(), 1);
}

// --- The levels and the answers ----------------------------------------------------------------------------------

fn usage_of(used_bytes: i64, used_objects: i64, limit_bytes: i64, limit_objects: i64) -> BucketUsage {
    BucketUsage {
        used_bytes,
        used_objects,
        limit_bytes,
        limit_objects,
        ..BucketUsage::default()
    }
}

#[test]
fn the_level_of_the_used_part_of_the_limit() {
    let cases = [
        ("no limit", usage_of(500, 5, 0, 0), 0.0, ""),
        ("zero limits", usage_of(500, 0, 0, 0), 0.0, ""),
        ("empty", usage_of(0, 0, 1000, 0), 0.0, "ok"),
        ("79.9 percent", usage_of(799, 0, 1000, 0), 79.9, "ok"),
        ("80 percent", usage_of(800, 0, 1000, 0), 80.0, "warning"),
        ("94.9 percent", usage_of(949, 0, 1000, 0), 94.9, "warning"),
        ("95 percent", usage_of(950, 0, 1000, 0), 95.0, "error"),
        ("full", usage_of(1000, 0, 1000, 0), 100.0, "error"),
        ("over the limit", usage_of(1500, 0, 1000, 0), 150.0, "error"),
        ("rounded down", usage_of(1234, 0, 10000, 0), 12.3, "ok"),
        ("rounded down, not up", usage_of(99999, 0, 100_000, 0), 99.9, "error"),
        ("one third", usage_of(1, 0, 3, 0), 33.3, "ok"),
        ("just under warning", usage_of(7999, 0, 10000, 0), 79.9, "ok"),
        ("objects only", usage_of(10, 90, 0, 100), 90.0, "warning"),
        ("objects ratio is larger", usage_of(100, 96, 1000, 100), 96.0, "error"),
        ("bytes ratio is larger", usage_of(900, 10, 1000, 100), 90.0, "warning"),
        ("unknown used bytes", usage_of(-1, -1, 1000, 100), 0.0, ""),
        ("unknown objects", usage_of(100, -1, 1000, 100), 10.0, "ok"),
    ];
    for (name, value, percent, level) in cases {
        assert_eq!(usage_level(&value), (percent, level), "{name}");
    }
}

#[test]
fn the_percent_is_exact_for_round_values() {
    // A float error must not lower a round value.
    for used in 0..=1000 {
        let (percent, _) = usage_level(&usage_of(used, 0, 1000, 0));
        assert_eq!(percent, used as f64 / 10.0, "used {used} of 1000");
    }
}

fn answer_instance(quota: i64) -> Arc<Instance> {
    usage_instance(plain_reader(), quota)
}

#[test]
fn the_source_of_the_limit_in_an_answer() {
    let as_of = Timestamp::parse_rfc3339("2026-10-21T10:00:00+01:00").unwrap();
    struct Case {
        name: &'static str,
        quota: i64,
        value: BucketUsage,
        limit_bytes: i64,
        limit_source: &'static str,
        percent: f64,
        level: &'static str,
    }
    let case = |name, quota, value, limit_bytes, limit_source, percent, level| Case {
        name,
        quota,
        value,
        limit_bytes,
        limit_source,
        percent,
        level,
    };
    let cases = vec![
        case("no limit anywhere", 0, usage_of(100, 1, 0, 0), 0, "", 0.0, ""),
        case(
            "provider limit",
            0,
            usage_of(100, 0, 1000, 0),
            1000,
            "provider",
            10.0,
            "ok",
        ),
        case(
            "provider wins",
            500,
            usage_of(100, 0, 1000, 0),
            1000,
            "provider",
            10.0,
            "ok",
        ),
        case(
            "config without limit",
            200,
            usage_of(100, 0, 0, 0),
            200,
            "config",
            50.0,
            "ok",
        ),
        case(
            "config limit is full",
            200,
            usage_of(199, 0, 0, 0),
            200,
            "config",
            99.5,
            "error",
        ),
        case(
            "config and objects",
            1000,
            usage_of(100, 9, 0, 10),
            1000,
            "config",
            90.0,
            "warning",
        ),
        case(
            "unknown used with config",
            200,
            usage_of(-1, -1, 0, 0),
            200,
            "config",
            0.0,
            "",
        ),
    ];
    for case in cases {
        let mut value = case.value.clone();
        value.source = USAGE_SOURCE_GARAGE.to_owned();
        value.as_of = Some(as_of);
        let answer = usage_answer(&answer_instance(case.quota), &value);
        assert!(
            answer.supported && answer.available && answer.error.is_none(),
            "{}",
            case.name
        );
        assert_eq!(
            (
                answer.instance.as_str(),
                answer.bucket.as_str(),
                answer.root_prefix.as_str()
            ),
            ("inst", "the-bucket", "tenant/")
        );
        assert_eq!(answer.source, USAGE_SOURCE_GARAGE);
        assert_eq!(
            (
                answer.limit_bytes,
                answer.limit_source.as_str(),
                answer.percent,
                answer.level.as_str()
            ),
            (case.limit_bytes, case.limit_source, case.percent, case.level),
            "{}",
            case.name
        );
        assert_eq!(
            answer.as_of.map(|value| (value.secs, value.offset)),
            Some((as_of.secs, 0)),
            "{}",
            case.name
        );
    }
}

#[test]
fn the_approximate_reason_comes_with_an_approximate_source() {
    let instance = answer_instance(0);
    for (source, approximate) in [
        (USAGE_SOURCE_GARAGE, false),
        (USAGE_SOURCE_SEAWEEDFS, true),
        (USAGE_SOURCE_MINIO, true),
    ] {
        let value = BucketUsage {
            source: source.to_owned(),
            approximate,
            ..BucketUsage::default()
        };
        let answer = usage_answer(&instance, &value);
        assert_eq!(answer.approximate, approximate, "{source}");
        assert_eq!(!answer.approximate_reason.is_empty(), approximate, "{source}");
    }
    // Each source with a reason has a text in the table.
    for source in [USAGE_SOURCE_SEAWEEDFS, USAGE_SOURCE_MINIO] {
        assert!(
            !usage_approximate_reason(source).is_empty(),
            "no approximate reason for {source}"
        );
    }
}

#[test]
fn the_answer_has_the_json_form_of_the_page() {
    let value = BucketUsage {
        used_bytes: 850,
        used_objects: 7,
        limit_bytes: 1000,
        approximate: true,
        source: USAGE_SOURCE_MINIO.to_owned(),
        as_of: Timestamp::parse_rfc3339("2026-10-21T10:52:20Z"),
        ..BucketUsage::default()
    };
    let answer = usage_answer(&answer_instance(0), &value);
    let text = serde_json::to_value(&answer).unwrap();
    assert_eq!(text["asOf"], "2026-10-21T10:52:20Z");
    assert_eq!(text["percent"], 85.0);
    assert_eq!(text["level"], "warning");
    assert!(text.get("selfBytes").is_none() && text.get("storage").is_none() && text.get("error").is_none());
    let none = usage_answer(&answer_instance(0), &BucketUsage::default());
    assert_eq!(serde_json::to_value(&none).unwrap()["asOf"], "0001-01-01T00:00:00Z");
}

#[test]
fn the_count_of_the_files_of_a_volume_goes_to_the_self_members() {
    let value = BucketUsage {
        used_bytes: 1200,
        used_objects: 1,
        self_state: "ready".to_owned(),
        ..BucketUsage::default()
    };
    let answer = usage_answer(&answer_instance(0), &value);
    assert_eq!((answer.self_bytes, answer.self_state.as_str()), (Some(1200), "ready"));
}

#[test]
fn a_failed_part_of_the_read_gives_its_error_text_for_a_bucket_and_for_a_volume() {
    let result = crate::bucket::UsageResult {
        error: Some(Error::internal("GetBucketInfo: down")),
        ..crate::bucket::UsageResult::default()
    };
    let answer = usage_answer_of(&answer_instance(0), &result);
    assert!(answer.supported && !answer.available);
    assert_eq!(
        answer.error.as_ref().map(|value| value.code.as_str()),
        Some("usage_unavailable")
    );
    assert_eq!(
        answer.error.map(|value| value.message),
        Some("The usage of the bucket is unavailable: GetBucketInfo: down.".to_owned())
    );
    let mut cfg = bucket_config("vol");
    cfg.provider = "fs".to_owned();
    let volume = instance_of(
        cfg,
        FakeBackend::flags(FakeS3::constant(200, ""), false, false, false, None),
    );
    let answer = usage_answer_of(&volume, &result);
    assert!(
        answer
            .error
            .is_some_and(|value| value.message.starts_with("The usage of the volume is unavailable"))
    );
}

// --- The route ---------------------------------------------------------------------------------------------------

async fn usage_call(
    app: &Arc<crate::common::app::App>,
    method: Method,
    target: &str,
) -> (u16, http::HeaderMap, serde_json::Value, String) {
    answer_of(handle_usage(app.clone(), request(method, target, None)).await).await
}

fn route_instance(reader: Option<Arc<FakeReader>>) -> Arc<Instance> {
    let mut cfg = bucket_config("rw");
    cfg.bucket = "rw-bucket".to_owned();
    let backend = FakeBackend::flags(FakeS3::constant(200, ""), false, false, false, None);
    let instance = instance_of(cfg, backend);
    if let Some(reader) = reader {
        instance.usage.set_reader(reader, USAGE_SOURCE_MINIO);
    }
    instance
}

#[tokio::test]
async fn the_route_without_a_usage_block_says_that_it_is_not_supported() {
    let app = app_of(vec![route_instance(None)]);
    let (status, headers, value, text) = usage_call(&app, Method::GET, "/api/usage?instance=rw").await;
    assert_eq!(status, 200, "{text}");
    assert_eq!(value, json!({"supported": false}));
    assert_eq!(
        headers.get("cache-control").and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
}

#[tokio::test]
async fn the_route_gives_the_usage_of_the_bucket() {
    let as_of = Timestamp::parse_rfc3339("2026-10-21T10:52:20Z");
    let reader = Arc::new(FakeReader::new().with_behavior(move |_| {
        Ok(BucketUsage {
            used_bytes: 850,
            used_objects: 7,
            limit_bytes: 1000,
            approximate: true,
            as_of,
            ..BucketUsage::default()
        })
    }));
    let instance = route_instance(Some(reader.clone()));
    Clock::new().install(&instance);
    let app = app_of(vec![instance]);
    let (status, headers, value, text) = usage_call(&app, Method::GET, "/api/usage?instance=rw").await;
    assert_eq!(status, 200, "{text}");
    let want = json!({
        "supported": true, "available": true, "instance": "rw", "bucket": "rw-bucket", "rootPrefix": "tenant/", "source": "minio",
        "usedBytes": 850, "usedObjects": 7, "limitBytes": 1000, "limitObjects": 0, "limitSource": "provider",
        "approximate": true, "percent": 85.0, "level": "warning", "asOf": "2026-10-21T10:52:20Z",
        "constraint": "quota", "quotaPercent": 85.0, "quotaLevel": "warning",
    });
    for (key, expected) in want.as_object().unwrap() {
        match expected.as_f64() {
            Some(number) => assert_eq!(value[key].as_f64(), Some(number), "{key}"),
            None => assert_eq!(&value[key], expected, "{key}"),
        }
    }
    assert!(
        value["approximateReason"]
            .as_str()
            .is_some_and(|reason| !reason.is_empty()),
        "{text}"
    );
    assert!(value.get("error").is_none(), "{text}");
    assert_eq!(
        headers.get("cache-control").and_then(|value| value.to_str().ok()),
        Some("no-store")
    );
    // A second request comes from the cache.
    usage_call(&app, Method::GET, "/api/usage?instance=rw").await;
    assert_eq!(reader.call_count(), 1);
}

#[tokio::test]
async fn the_route_gives_the_limit_of_the_operator() {
    let reader = Arc::new(FakeReader::new().with_behavior(|_| {
        Ok(BucketUsage {
            used_bytes: 100,
            used_objects: -1,
            ..BucketUsage::default()
        })
    }));
    let mut cfg = bucket_config("rw");
    cfg.bucket = "rw-bucket".to_owned();
    cfg.quota_bytes = 400;
    let instance = instance_of(
        cfg,
        FakeBackend::flags(FakeS3::constant(200, ""), false, false, false, None),
    );
    instance.usage.set_reader(reader, USAGE_SOURCE_GARAGE);
    let app = app_of(vec![instance]);
    let (_, _, value, text) = usage_call(&app, Method::GET, "/api/usage?instance=rw").await;
    assert_eq!(value["limitBytes"], 400, "{text}");
    assert_eq!(value["limitSource"], "config");
    assert_eq!(value["percent"], 25.0);
    assert_eq!(value["level"], "ok");
    assert_eq!(value["approximate"], false);
    assert!(value.get("approximateReason").is_none());
}

#[tokio::test]
async fn the_route_answers_200_with_available_false_for_a_failed_read() {
    // A failed read gives HTTP 200: an answer 502 would tell the page that the server does not answer.
    let reader = Arc::new(FakeReader::new().with_behavior(|_| {
        Err(AdminError::Http {
            step: "GetBucketInfo".to_owned(),
            status: 403,
            code: String::new(),
        }
        .into())
    }));
    let app = app_of(vec![route_instance(Some(reader))]);
    let (status, _, value, text) = usage_call(&app, Method::GET, "/api/usage?instance=rw").await;
    assert_eq!(status, 200, "{text}");
    assert_eq!(value["supported"], true);
    assert_eq!(value["available"], false);
    assert_eq!(value["instance"], "rw");
    assert_eq!(value["source"], "minio");
    assert_eq!(value["usedBytes"], 0);
    assert_eq!(value["error"]["code"], "usage_unavailable");
    assert!(
        value["error"]["message"]
            .as_str()
            .is_some_and(|message| message.contains("HTTP 403")),
        "{text}"
    );
}

#[tokio::test]
async fn the_route_accepts_only_get_and_a_known_instance() {
    let app = app_of(vec![route_instance(Some(plain_reader()))]);
    for method in [Method::POST, Method::PUT, Method::DELETE] {
        let (status, headers, ..) = usage_call(&app, method.clone(), "/api/usage?instance=rw").await;
        assert_eq!(status, 405, "{method}");
        assert_eq!(
            headers.get("allow").and_then(|value| value.to_str().ok()),
            Some("GET"),
            "{method}"
        );
    }
    let (status, ..) = usage_call(&app, Method::GET, "/api/usage?instance=missing").await;
    assert!(
        (400..500).contains(&status),
        "an unknown instance gives status {status}"
    );
}

#[tokio::test]
async fn the_route_needs_the_read_permission() {
    let reader = plain_reader();
    let mut cfg = bucket_config("rw");
    cfg.permissions_defined = true;
    cfg.permissions = vec!["write".to_owned()];
    let instance = instance_of(
        cfg,
        FakeBackend::flags(FakeS3::constant(200, ""), false, false, false, None),
    );
    instance.usage.set_reader(reader.clone(), USAGE_SOURCE_GARAGE);
    let app = app_of(vec![instance]);
    let (status, ..) = usage_call(&app, Method::GET, "/api/usage?instance=rw").await;
    assert_eq!(status, 403);
    assert_eq!(reader.call_count(), 0, "the reader ran without the read permission");
}

#[tokio::test]
async fn fresh_in_the_query_reads_again_a_result_that_is_older_than_10_seconds() {
    let reader = plain_reader();
    let instance = route_instance(Some(reader.clone()));
    let clock = Clock::new();
    clock.install(&instance);
    let app = app_of(vec![instance]);
    let get = |target: &'static str| {
        let app = app.clone();
        async move {
            usage_call(&app, Method::GET, target).await.2["usedBytes"]
                .as_f64()
                .unwrap_or(-1.0)
        }
    };
    assert_eq!(get("/api/usage?instance=rw").await, 1.0);
    clock.advance(Duration::from_secs(5));
    assert_eq!(
        (get("/api/usage?instance=rw&fresh=1").await, reader.call_count()),
        (1.0, 1)
    );
    clock.advance(Duration::from_secs(6));
    assert_eq!((get("/api/usage?instance=rw").await, reader.call_count()), (1.0, 1));
    assert_eq!(
        (get("/api/usage?instance=rw&fresh=1").await, reader.call_count()),
        (2.0, 2)
    );
    // Only fresh=1 asks for a new read.
    clock.advance(Duration::from_secs(11));
    assert_eq!(
        (get("/api/usage?instance=rw&fresh=true").await, reader.call_count()),
        (2.0, 2)
    );
}

#[tokio::test]
async fn the_instance_tells_if_the_usage_is_supported() {
    let with = route_instance(Some(plain_reader()));
    let without = route_instance(None);
    assert!(with.usage_available());
    assert!(!without.usage_available());
}

#[tokio::test]
async fn the_probe_of_the_usage_makes_no_admin_request() {
    let reader = plain_reader();
    let fake = FakeS3::constant(200, "");
    let backend = FakeBackend::flags(fake, false, false, false, Some("minio"));
    let instance = instance_of(bucket_config("rw"), backend);
    instance.usage.set_reader(reader.clone(), USAGE_SOURCE_GARAGE);
    // The source of the file differs from the provider: a warning in the log, no request.
    instance.probe_usage(&ctx()).await;
    assert_eq!(reader.call_count(), 0, "the probe read the usage");
    // An instance without a usage reader has nothing to probe.
    route_instance(None).probe_usage(&ctx()).await;
}
