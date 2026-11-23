// SPDX-License-Identifier: MIT OR Apache-2.0
//! The checks of the rules that docs/ARCHITECTURE.md, docs/SECURITY-MODEL.md, docs/PREVIEWS.md and docs/CONFIGURATION.md
//! give with a number or a fixed value. Each test names the section of the document that it checks.

use std::path::Path;
use std::time::Duration;

use super::testing::{TestRequest, memory_app};

/// CONFIGURATION.md, "Server block": the default of each key of the table.
#[test]
fn the_defaults_of_the_server_block_are_the_documented_values() {
    let text = r#"
access {
  mode = "open"
}
auth "primary" {
  provider = "s3"
  mode     = "anonymous"
  endpoint = "http://127.0.0.1:9"
  region   = "test"
}
bucket "archive" {
  auth   = "primary"
  bucket = "archive"
}
"#;
    let config = crate::config::decode(text, Path::new("/stowr-test/config.hcl"), Path::new("/stowr-test")).unwrap();
    assert_eq!(config.listen, ":8080");
    assert_eq!(config.job_history_limit, 10);
    let runtime = &config.runtime;
    assert_eq!(runtime.access_mode.as_str(), "inherit_credentials");
    assert!(!runtime.allow_full_object_fallback);
    assert_eq!(runtime.memory_limit_bytes, 0);
    assert_eq!(runtime.max_storage_bytes_per_request, 256 << 30);
    assert_eq!(runtime.max_storage_requests_per_request, 4096);
    assert_eq!(runtime.max_range_cache_bytes, 8 << 20);
    assert_eq!(runtime.max_concurrent_storage_requests, 4);
    assert_eq!(runtime.max_concurrent_requests_per_storage, 2);
    assert_eq!(runtime.session_ttl_seconds, 1200);
    assert_eq!(runtime.max_stats_folders, 1000);
    assert_eq!(runtime.max_archive_entries, 10_000);
    assert_eq!(runtime.max_background_storage_bytes, 256 << 30);
    assert_eq!(runtime.max_background_storage_requests, 100_000);
    let bucket = &config.buckets[0];
    assert_eq!(
        bucket.name, "archive",
        "the name of a bucket is its block id by default"
    );
    assert_eq!(bucket.max_scan_pages, 1);
    assert_eq!(bucket.root_prefix, "");
}

/// ARCHITECTURE.md, "Background jobs" and "Stateless state model"; SECURITY-MODEL.md, "Resource limits".
#[test]
fn the_limits_of_the_jobs_are_the_documented_values() {
    assert_eq!(crate::jobs::MAX_ACTIVE_JOBS, 4);
    assert_eq!(crate::jobs::STATS_INLINE_WAIT, Duration::from_millis(100));
    assert_eq!(crate::jobs::STATS_RESULT_REUSE_TTL, Duration::from_secs(30));
    assert_eq!(crate::jobs::ANALYSIS_INLINE_WAIT, Duration::from_millis(100));
    assert_eq!(crate::jobs::PAUSED_JOB_TTL, Duration::from_secs(30 * 60));
    assert_eq!(crate::jobs::MAX_LOCKED_KEYS, 20);
    assert_eq!(crate::instance::ops::MAX_DELETE_BATCH, 1000);
}

/// SECURITY-MODEL.md, "Resource limits": the idle limits of the transfers, the wait for a storage slot and the life of an
/// idle upload session.
#[test]
fn the_limits_of_the_transfers_are_the_documented_values() {
    assert_eq!(super::middleware::STREAM_IDLE_TIMEOUT, Duration::from_secs(30));
    assert_eq!(super::runtime::WRITE_IDLE_TIMEOUT, Duration::from_secs(30));
    assert_eq!(crate::archive::stream::STREAM_IDLE_TIMEOUT, Duration::from_secs(30));
    assert_eq!(crate::instance::gate::GATE_WAIT, Duration::from_secs(30));
    assert_eq!(crate::uploads::UPLOAD_IDLE_TTL, Duration::from_secs(30 * 60));
}

/// ARCHITECTURE.md, "Upload resume protocol" and "Object tags and lifecycle": the active upload sessions of the
/// process and the tags of an object.
#[test]
fn the_limits_of_the_uploads_and_of_the_tags_are_the_documented_values() {
    assert_eq!(crate::uploads::MAX_IN_MEMORY_UPLOAD_SESSIONS, 4);
    assert_eq!(crate::lifecycle::MAX_OBJECT_TAGS, 10);
}

/// ARCHITECTURE.md, "Copy in parts": the threshold, the part size, the parallel parts and the time of the abort.
#[test]
fn the_values_of_the_copy_in_parts_are_the_documented_values() {
    use crate::provider::s3::copy;
    assert_eq!(copy::DEFAULT_MULTIPART_COPY_THRESHOLD, (5 << 30) - (256 << 20));
    assert_eq!(copy::DEFAULT_MULTIPART_COPY_PART_SIZE, 256 << 20);
    assert_eq!(copy::MULTIPART_COPY_PARALLEL, 4);
    assert_eq!(copy::MAX_MULTIPART_PARTS, 10_000);
    assert_eq!(copy::MULTIPART_ABORT_TIMEOUT, Duration::from_secs(30));
}

/// SECURITY-MODEL.md, "Browser isolation": each route that gives the bytes of an object carries the sandbox policy, also an
/// answer of the gateway and of the original.
#[tokio::test]
async fn the_routes_that_give_object_bytes_carry_the_sandbox_policy() {
    let (app, _, _) = memory_app();
    for target in [
        "/s3?instance=rw&key=folder%2Fdirect.txt",
        "/open/direct.txt?instance=rw&key=folder%2Fdirect.txt",
    ] {
        let answer = TestRequest::get(target).send(&app).await;
        assert_eq!(answer.status, 200, "{target}: {}", answer.text());
        assert!(
            answer.header("content-security-policy").contains("sandbox"),
            "{target}: {:?}",
            answer.header("content-security-policy")
        );
        assert_eq!(answer.header("x-content-type-options"), "nosniff", "{target}");
    }
}

/// PREVIEWS.md, "Per-object integrity": the routes of the global analyses do not exist.
#[tokio::test]
async fn the_global_analyses_have_no_route() {
    let (app, _, _) = memory_app();
    for target in [
        "/api/compare?instance=rw",
        "/api/duplicates?instance=rw",
        "/api/checksum-manifest?instance=rw",
    ] {
        assert_eq!(TestRequest::get(target).send(&app).await.status, 404, "{target}");
    }
}
