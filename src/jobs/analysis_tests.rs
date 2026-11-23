//! The tests of the integrity, of the technical inspection and of the version routes.

use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::HeaderValue;
use serde_json::json;

use super::testing::{Called, call, rig, rig_over};
use super::*;
use crate::common::BoxFuture;
use crate::common::ctx::OpCtx;
use crate::common::error::Result;
use crate::common::storage::{Backend, ObjectResponse};
use crate::common::time::Timestamp;
use crate::testkit::{MemoryBackend, MemoryLayer, MemoryVersion};

/// The job of an answer of an analysis route: the answer itself when it is `200`, else the job after its end.
async fn wait_analysis_job(app: &crate::common::app::App, answer: &Called) -> serde_json::Value {
    let job = answer.json();
    if answer.status == 200 {
        return job;
    }
    assert_eq!(answer.status, 202, "{}", answer.text);
    let id = job["id"].as_str().unwrap();
    let done = app.jobs.wait_for_terminal(id, Duration::from_secs(5)).await.unwrap();
    assert_eq!(done.status, job_status::COMPLETED, "{:?}", done.error);
    serde_json::to_value(done.public()).unwrap()
}

/// Each range must be exact: `bytes=<start>-<end>` with two numbers.
fn require_exact_byte_ranges(ranges: &[String]) {
    assert!(!ranges.is_empty(), "expected at least one byte-range request");
    for value in ranges {
        let bounds = value
            .strip_prefix("bytes=")
            .unwrap_or_else(|| panic!("{value:?} is not a byte range"));
        let (start, end) = bounds
            .split_once('-')
            .unwrap_or_else(|| panic!("{value:?} is malformed"));
        let start: i64 = start
            .trim()
            .parse()
            .unwrap_or_else(|_| panic!("{value:?} is open-ended"));
        let end: i64 = end.trim().parse().unwrap_or_else(|_| panic!("{value:?} is open-ended"));
        assert!(start >= 0 && end >= start, "{value:?} is invalid");
    }
}

fn error_code(called: &Called) -> String {
    called.json()["error"]["code"].as_str().unwrap_or("").to_owned()
}

#[tokio::test]
async fn the_integrity_and_the_inspection_of_objects() {
    let rig = rig();
    let now = Timestamp::now();
    rig.backend.insert_modified(
        "tenant/analysis/check.bin",
        "same-content",
        "application/octet-stream",
        now,
    );
    let mut pdf = b"%PDF-1.7\n".to_vec();
    pdf.extend(std::iter::repeat_n(b'x', 140 << 10));
    rig.backend
        .insert_modified("tenant/analysis/large.pdf", pdf, "application/pdf", now);

    let integrity = call(
        &rig.app,
        "POST",
        "/api/integrity",
        Some(json!({"instance": "rw", "key": "analysis/check.bin"})),
    )
    .await;
    let job = wait_analysis_job(&rig.app, &integrity).await;
    let entries = job["integrity"]["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry["key"], "analysis/check.bin");
    assert_eq!(entry["size"], 12);
    assert_eq!(
        entry["sha256"],
        "cae1b3faaa5e4ac7c3306bd164b36dcfdff98294b8024c9c949639b4c480bf6b"
    );
    assert_eq!(entry["sha256Base64"], "yuGz+qpeSsfDMGvRZLNtz9/5gpS4AkyclJY5tMSAv2s=");
    assert_eq!(entry["md5"], "f8aeb3a8368e8d146968c49124a2dd98");
    assert_eq!(entry["md5Base64"], "+K6zqDaOjRRpaMSRJKLdmA==");
    assert_eq!(entry["crc32"], "8a6c0fe8");
    assert_eq!(entry["crc32c"], "0917ce5a");
    assert_eq!(entry["etag"], "etag-tenant/analysis/check.bin");
    assert_eq!(entry["contentType"], "application/octet-stream");
    assert!(entry.get("matches").is_none(), "{entry}");

    rig.backend.state().get_ranges.clear();
    let inspect = call(
        &rig.app,
        "GET",
        "/api/inspect?instance=rw&key=analysis%2Flarge.pdf",
        None,
    )
    .await;
    assert_eq!(inspect.status, 200, "{}", inspect.text);
    let inspected = inspect.json();
    assert_eq!(
        inspected["detectedKind"],
        crate::server::detect_kind("analysis/large.pdf", "application/pdf")
    );
    assert_eq!(inspected["detectedMime"], "application/pdf");
    assert_eq!(inspected["declaredMime"], "application/pdf");
    assert_eq!(inspected["structure"]["PDF version"], "1.7");
    let probes = inspected["probes"].as_array().unwrap();
    assert_eq!(probes.len(), 2);
    assert_eq!(probes[0]["name"], "Header");
    assert_eq!(probes[0]["range"], "bytes=0-65535");
    assert_eq!(probes[1]["name"], "Trailer");
    assert_eq!(probes[0]["hex"].as_str().unwrap().len(), 512);
    assert!(
        inspected["headers"].get("Set-Cookie").is_none(),
        "{}",
        inspected["headers"]
    );
    assert_eq!(inspected["headers"]["X-Amz-Meta-Test"], "visible");
    assert_eq!(inspected["resources"]["storageRequests"], 3);
    assert_eq!(inspected["resources"]["storageBytes"], 2 * 65536);
    let ranges = rig.backend.state().get_ranges.clone();
    require_exact_byte_ranges(&ranges);
    assert_eq!(ranges.len(), 2, "{ranges:?}");
}

/// A back end whose HEAD answers carry checksums of the provider.
struct Checksums {
    memory: MemoryBackend,
    headers: Vec<(&'static str, String)>,
}

impl MemoryLayer for Checksums {
    fn memory(&self) -> &MemoryBackend {
        &self.memory
    }

    fn head<'a>(&'a self, ctx: &'a OpCtx, key: &'a str) -> BoxFuture<'a, Result<ObjectResponse>> {
        Box::pin(async move {
            let mut response = self.memory.head(ctx, key).await?;
            for (name, value) in &self.headers {
                response.headers.insert(*name, HeaderValue::from_str(value).unwrap());
            }
            Ok(response)
        })
    }
}

#[tokio::test]
async fn the_integrity_compares_the_checksums_of_the_provider() {
    let backend = Arc::new(Checksums {
        memory: MemoryBackend::with_objects(&[("tenant/sum.bin", "same-content")]),
        headers: vec![
            (
                "x-amz-checksum-sha256",
                "yuGz+qpeSsfDMGvRZLNtz9/5gpS4AkyclJY5tMSAv2s=".to_owned(),
            ),
            ("x-amz-checksum-crc32c", "CRfOWg==".to_owned()),
            ("x-amz-checksum-crc32", "AAAAAA==-3".to_owned()),
            ("etag", "\"f8aeb3a8368e8d146968c49124a2dd98\"".to_owned()),
            ("content-md5", "AAAAAAAAAAAAAAAAAAAAAA==".to_owned()),
        ],
    });
    let app = rig_over(backend);
    let answer = call(
        &app,
        "POST",
        "/api/integrity",
        Some(json!({"key": "/sum.bin", "instance": "rw"})),
    )
    .await;
    let job = wait_analysis_job(&app, &answer).await;
    let entry = &job["integrity"]["entries"][0];
    assert_eq!(entry["key"], "sum.bin");
    assert_eq!(
        entry["matches"],
        json!({"crc32c": true, "etagMd5": true, "md5": false, "sha256": true})
    );
    assert_eq!(entry["providerChecksums"]["crc32"], "AAAAAA==-3");
    assert_eq!(entry["etag"], "f8aeb3a8368e8d146968c49124a2dd98");
}

#[test]
fn the_checksum_comparison_skips_composite_provider_values() {
    assert_eq!(checksum_matches("not-base64-3", b"value"), (false, false));
    assert_eq!(checksum_matches("dmFsdWU=", b"value"), (true, true));
    assert_eq!(checksum_matches("\"76616C7565 \"", b"value"), (true, true));
    // The quotes go first, then the spaces: a quote inside the spaces stays.
    assert_eq!(checksum_matches(" \"76616c7565\" ", b"value"), (false, false));
    assert_eq!(checksum_matches("dmFsdWY=", b"value"), (false, true));
    assert_eq!(checksum_matches("dmFsdWU", b"value"), (false, false));
    assert_eq!(checksum_matches("", b"value"), (false, false));
}

#[tokio::test]
async fn the_integrity_route_checks_its_request() {
    let rig = rig();
    assert_eq!(call(&rig.app, "GET", "/api/integrity", None).await.status, 405);
    let no_key = call(
        &rig.app,
        "POST",
        "/api/integrity",
        Some(json!({"instance": "rw", "key": "/"})),
    )
    .await;
    assert_eq!(
        (no_key.status, error_code(&no_key).as_str()),
        (400, "invalid_integrity_request")
    );
    assert_eq!(no_key.json()["error"]["message"], "an object key is required");
    let unknown = call(
        &rig.app,
        "POST",
        "/api/integrity",
        Some(json!({"key": "a", "other": 1})),
    )
    .await;
    assert_eq!((unknown.status, error_code(&unknown).as_str()), (400, "invalid_json"));
    let denied = call(
        &rig.app,
        "POST",
        "/api/integrity",
        Some(json!({"instance": "nothing", "key": "a"})),
    )
    .await;
    assert_eq!(denied.status, 404);
    let missing = call(
        &rig.app,
        "POST",
        "/api/integrity",
        Some(json!({"instance": "rw", "key": "missing.bin", "version": null})),
    )
    .await;
    assert_eq!(
        (missing.status, error_code(&missing).as_str()),
        (422, "analysis_failed")
    );
    assert_eq!(
        missing.json()["error"]["message"],
        "the storage provider returned HTTP 404 (NotFound)"
    );
}

#[tokio::test]
async fn the_inspection_checks_its_request_and_the_ranges_of_the_provider() {
    let rig = rig();
    assert_eq!(
        call(&rig.app, "POST", "/api/inspect?instance=rw&key=a", None)
            .await
            .status,
        405
    );
    let no_key = call(&rig.app, "GET", "/api/inspect?instance=rw", None).await;
    assert_eq!((no_key.status, error_code(&no_key).as_str()), (400, "invalid_key"));
    rig.backend.state().ignore_ranges = true;
    let ignored = call(
        &rig.app,
        "GET",
        "/api/inspect?instance=rw&key=folder%2Fdirect.txt",
        None,
    )
    .await;
    assert_eq!(
        (ignored.status, error_code(&ignored).as_str()),
        (502, "range_not_honored")
    );
    rig.backend.state().ignore_ranges = false;
    rig.backend.state().range_body_full = true;
    rig.backend
        .insert("tenant/big.bin", vec![b'z'; 70_000], "application/octet-stream");
    // The provider answers 206 with the whole object: its length is not the length of the range.
    let full = call(&rig.app, "GET", "/api/inspect?instance=rw&key=big.bin", None).await;
    assert_eq!(
        (full.status, error_code(&full).as_str()),
        (502, "invalid_content_length")
    );
    rig.backend.state().range_body_full = false;
    rig.backend.state().range_status_ok = true;
    let ok = call(&rig.app, "GET", "/api/inspect?instance=rw&key=big.bin", None).await;
    assert_eq!((ok.status, error_code(&ok).as_str()), (502, "range_not_honored"));
}

#[tokio::test]
async fn the_inspection_of_a_small_text_object_reads_one_range() {
    let rig = rig();
    rig.backend
        .insert("tenant/data.json", "{\"a\": 1}", "application/octet-stream");
    rig.backend.state().get_ranges.clear();
    let inspect = call(&rig.app, "GET", "/api/inspect?instance=rw&key=data.json", None).await;
    assert_eq!(inspect.status, 200, "{}", inspect.text);
    let inspected = inspect.json();
    assert_eq!(inspected["detectedMime"], "application/json");
    assert_eq!(inspected["size"], 8);
    assert_eq!(inspected["provider"], "s3");
    assert_eq!(inspected["etag"], "etag-tenant/data.json");
    assert_eq!(inspected["probes"].as_array().unwrap().len(), 1);
    assert_eq!(inspected["probes"][0]["ascii"], "{\"a\": 1}");
    assert_eq!(inspected["structure"], json!({"Object length": "8"}));
    assert_eq!(rig.backend.state().get_ranges, vec!["bytes=0-7"]);
    assert!(inspected.get("version").is_none());
}

fn versioned_rig() -> super::testing::Rig {
    let rig = rig();
    rig.backend.state().versioned = true;
    let now = Timestamp::now();
    let version = |id: &str, data: &'static str, modified: Timestamp, current: bool, marker: bool| MemoryVersion {
        id: id.to_owned(),
        data: Bytes::from_static(data.as_bytes()),
        content_type: "text/plain".to_owned(),
        modified: Some(modified),
        current,
        delete_marker: marker,
    };
    rig.backend
        .add_version("tenant/versioned.txt", version("v2", "current", now, true, false));
    rig.backend.add_version(
        "tenant/versioned.txt",
        version("v1", "previous", now.plus_secs(-3600), false, false),
    );
    rig.backend.add_version(
        "tenant/versioned.txt",
        version("delete-marker", "", now.plus_secs(-7200), false, true),
    );
    rig.app.instance("rw").unwrap().set_versioning_available(true);
    rig
}

#[tokio::test]
async fn the_version_routes_list_count_restore_and_delete() {
    let rig = versioned_rig();
    let versions = call(&rig.app, "GET", "/api/versions?instance=rw&key=versioned.txt", None).await;
    assert_eq!(versions.status, 200, "{}", versions.text);
    let page = versions.json();
    let list = page["versions"].as_array().unwrap();
    assert_eq!(list.len(), 3);
    assert_eq!(list[0]["version"], "v2");
    assert_eq!(list[2]["deleteMarker"], true);
    assert_eq!(page["instance"], "rw");
    assert_eq!(page["key"], "versioned.txt");
    assert_eq!(page["nextPageToken"], "");

    let one = call(
        &rig.app,
        "GET",
        "/api/versions?instance=rw&key=versioned.txt&max=1",
        None,
    )
    .await;
    assert_eq!(one.json()["versions"].as_array().unwrap().len(), 1);

    let counts = call(
        &rig.app,
        "POST",
        "/api/version-counts",
        Some(json!({"instance": "rw", "keys": ["versioned.txt", "/versioned.txt", ""]})),
    )
    .await;
    assert_eq!(counts.status, 200, "{}", counts.text);
    assert_eq!(
        counts.text,
        "{\"counts\":{\"versioned.txt\":{\"count\":2,\"currentVersion\":\"v2\"}},\"instance\":\"rw\"}\n"
    );

    let restore = call(
        &rig.app,
        "POST",
        "/api/versions/restore",
        Some(json!({"instance": "rw", "key": "versioned.txt", "version": "v1"})),
    )
    .await;
    assert_eq!(restore.status, 200, "{}", restore.text);
    assert_eq!(
        restore.text,
        "{\"key\":\"versioned.txt\",\"restored\":true,\"version\":\"v1\"}\n"
    );
    assert_eq!(rig.backend.object("tenant/versioned.txt").unwrap().data, "previous");

    let remove = call(
        &rig.app,
        "DELETE",
        "/api/versions?instance=rw&key=versioned.txt&version=delete-marker",
        None,
    )
    .await;
    assert_eq!(remove.status, 204, "{}", remove.text);
    assert_eq!(
        rig.backend.state().deleted_versions,
        vec!["tenant/versioned.txt@delete-marker"]
    );
}

#[tokio::test]
async fn an_empty_page_of_versions_has_no_list() {
    let rig = versioned_rig();
    let empty = call(&rig.app, "GET", "/api/versions?instance=rw&key=other.txt", None).await;
    assert_eq!(empty.status, 200);
    assert_eq!(
        empty.text,
        "{\"instance\":\"rw\",\"key\":\"other.txt\",\"nextPageToken\":\"\",\"versions\":null}\n"
    );
}

#[tokio::test]
async fn the_version_routes_check_their_requests() {
    let rig = versioned_rig();
    let no_key = call(&rig.app, "GET", "/api/versions?instance=rw", None).await;
    assert_eq!((no_key.status, error_code(&no_key).as_str()), (400, "invalid_key"));
    let put = call(&rig.app, "PUT", "/api/versions?instance=rw&key=a", None).await;
    assert_eq!(put.status, 405);
    assert_eq!(put.headers.get("allow").unwrap(), "GET, DELETE");
    let no_version = call(&rig.app, "DELETE", "/api/versions?instance=rw&key=a", None).await;
    assert_eq!(
        (no_version.status, error_code(&no_version).as_str()),
        (400, "version_required")
    );
    let no_keys = call(
        &rig.app,
        "POST",
        "/api/version-counts",
        Some(json!({"instance": "rw", "keys": []})),
    )
    .await;
    assert_eq!((no_keys.status, error_code(&no_keys).as_str()), (400, "invalid_keys"));
    let many: Vec<String> = (0..101).map(|index| format!("k{index}")).collect();
    let too_many = call(
        &rig.app,
        "POST",
        "/api/version-counts",
        Some(json!({"instance": "rw", "keys": many})),
    )
    .await;
    assert_eq!(
        too_many.json()["error"]["message"],
        "between 1 and 100 object keys are required"
    );
    assert_eq!(call(&rig.app, "GET", "/api/version-counts", None).await.status, 405);
    let restore = call(
        &rig.app,
        "POST",
        "/api/versions/restore",
        Some(json!({"instance": "rw", "key": "versioned.txt", "version": " "})),
    )
    .await;
    assert_eq!(
        (restore.status, error_code(&restore).as_str()),
        (400, "invalid_version")
    );
    assert_eq!(call(&rig.app, "GET", "/api/versions/restore", None).await.status, 405);
    // A count that fails gives an error for its key only.
    rig.backend.state().version_list_error = Some(crate::common::error::Error::upstream(500, "InternalError", "x"));
    let failed = call(
        &rig.app,
        "POST",
        "/api/version-counts",
        Some(json!({"instance": "rw", "keys": ["a"]})),
    )
    .await;
    assert_eq!(failed.status, 200);
    assert_eq!(
        failed.json()["errors"]["a"],
        "the storage provider returned HTTP 500 (InternalError)"
    );
}

#[tokio::test]
async fn the_version_routes_answer_501_without_the_versions() {
    let rig = rig();
    let list = call(&rig.app, "GET", "/api/versions?instance=rw&key=versioned.txt", None).await;
    assert_eq!(
        (list.status, error_code(&list).as_str()),
        (501, "versioning_unavailable")
    );
    assert_eq!(
        list.json()["error"]["message"],
        "object versioning is not available for this storage bucket"
    );
    let counts = call(
        &rig.app,
        "POST",
        "/api/version-counts",
        Some(json!({"instance": "rw", "keys": ["a"]})),
    )
    .await;
    assert_eq!(counts.status, 501);
    let restore = call(
        &rig.app,
        "POST",
        "/api/versions/restore",
        Some(json!({"instance": "rw", "key": "a", "version": "v1"})),
    )
    .await;
    assert_eq!(restore.status, 501);
    // A probe that found no versions also hides them.
    let instance = rig.app.instance("rw").unwrap();
    instance.set_versioning_available(false);
    assert_eq!(
        call(&rig.app, "GET", "/api/versions?instance=rw&key=a", None)
            .await
            .status,
        501
    );
}

#[tokio::test]
async fn the_inspection_and_the_integrity_read_a_named_version() {
    let rig = versioned_rig();
    let inspect = call(
        &rig.app,
        "GET",
        "/api/inspect?instance=rw&key=versioned.txt&version=v1",
        None,
    )
    .await;
    assert_eq!(inspect.status, 200, "{}", inspect.text);
    let inspected = inspect.json();
    assert_eq!(inspected["version"], "v1");
    assert_eq!(inspected["size"], 8);
    assert_eq!(inspected["probes"][0]["ascii"], "previous");
    let integrity = call(
        &rig.app,
        "POST",
        "/api/integrity",
        Some(json!({"instance": "rw", "key": "versioned.txt", "version": "v1"})),
    )
    .await;
    let job = wait_analysis_job(&rig.app, &integrity).await;
    let entry = &job["integrity"]["entries"][0];
    assert_eq!(entry["version"], "v1");
    assert_eq!(entry["size"], 8);
    assert_eq!(entry["etag"], "version-v1");
}
