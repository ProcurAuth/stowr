// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tests of the SHA-256 checksums: the header, the composite checksum, the chunks of an upload and the direct upload.

use std::sync::Arc;

use base64::Engine as _;
use http::HeaderMap;
use http::header::HeaderValue;

use super::checksum::{
    CHECKSUM_HEADER, checksum_confirmed, composite_checksum, parse_checksum_header, same_composite_checksum,
    sha256_base64, standard_base64, verify_upload_checksum, with_checksum_transfer,
};
use super::manager::{ChunkInput, CreateUploadRequest, UploadManager};
use super::session::{STATUS_COMPLETED, UploadPartState, UploadSession};
use super::target::NoCheck;
use super::test_fakes::{FakeTarget, FakeTargets};
use crate::common::ctx::OpCtx;
use crate::common::error::{Error, Result};
use crate::common::http::{Body, read_limited};

struct Fixture {
    manager: UploadManager,
    targets: FakeTargets,
    target: Arc<FakeTarget>,
}

fn fixture() -> Fixture {
    let target = Arc::new(FakeTarget::new("rw", "s3", "tenant/"));
    target.with_store(|store| store.checksum_provider = true);
    Fixture {
        manager: UploadManager::new(),
        targets: FakeTargets::new(vec![target.clone()]),
        target,
    }
}

impl Fixture {
    async fn create(&self, key: &str, size: i64, checksum: &str) -> Result<UploadSession> {
        self.manager
            .create_checked(
                &self.targets,
                &OpCtx::default(),
                CreateUploadRequest {
                    instance: "rw".to_owned(),
                    key: key.to_owned(),
                    size,
                    content_type: "application/octet-stream".to_owned(),
                    checksum: checksum.to_owned(),
                    tags: Vec::new(),
                },
                &NoCheck,
            )
            .await
    }

    async fn put_chunk(
        &self,
        token: &str,
        data: &[u8],
        start: i64,
        total: i64,
        digest: Option<&str>,
    ) -> Result<UploadSession> {
        let ctx = OpCtx::default();
        let upload = self
            .manager
            .resume_checked(&self.targets, &ctx, token, &NoCheck)
            .await?;
        let mut headers = HeaderMap::new();
        let end = start + data.len() as i64 - 1;
        headers.insert(
            "Content-Range",
            HeaderValue::from_str(&format!("bytes {start}-{end}/{total}")).unwrap(),
        );
        if let Some(digest) = digest {
            headers.insert(CHECKSUM_HEADER, HeaderValue::from_str(digest).unwrap());
        }
        let input = ChunkInput {
            headers,
            content_length: data.len() as i64,
            body: crate::common::http::full(data.to_vec()),
        };
        let upload = self
            .manager
            .upload_chunk(&self.targets, &ctx, &upload.id, input)
            .await?;
        self.manager.release_terminal(&upload);
        Ok(upload)
    }
}

fn status_and_code(error: &Error) -> (u16, String) {
    (error.status(), error.code())
}

#[tokio::test]
async fn a_checksum_upload_sends_each_part_digest_and_confirms_the_composite_checksum() {
    let fixture = fixture();
    let total = (16 << 20) + 17;
    let created = fixture.create("sum.bin", total, "sha256").await.unwrap();
    assert_eq!(created.checksum, "sha256");
    assert!(fixture.target.with_store(|store| store.algorithm_requested));
    let first = vec![b'a'; created.chunk_size as usize];
    fixture
        .put_chunk(&created.resume_token, &first, 0, total, Some(&sha256_base64(&first)))
        .await
        .unwrap();
    let last = vec![b'b'; (total - first.len() as i64) as usize];
    let done = fixture
        .put_chunk(
            &created.resume_token,
            &last,
            first.len() as i64,
            total,
            Some(&sha256_base64(&last)),
        )
        .await
        .unwrap();
    assert_eq!(done.status, STATUS_COMPLETED);
    assert!(done.verified && done.checksum_verified, "{done:?}");
    let completed = fixture.target.with_store(|store| store.completed.clone());
    assert_eq!(completed.len(), 2);
    assert_eq!(completed[0].checksum_sha256, sha256_base64(&first));
    assert_eq!(completed[1].checksum_sha256, sha256_base64(&last));
}

#[tokio::test]
async fn a_checksum_upload_refuses_a_chunk_without_or_with_a_wrong_digest() {
    let fixture = fixture();
    let total = 6 << 20;
    let created = fixture.create("bad.bin", total, "sha256").await.unwrap();
    let data = vec![b'x'; total as usize];
    let token = &created.resume_token;
    let missing = fixture.put_chunk(token, &data, 0, total, None).await.unwrap_err();
    assert_eq!(status_and_code(&missing), (400, "checksum_required".to_owned()));
    let encoding = fixture
        .put_chunk(token, &data, 0, total, Some("not-base64!"))
        .await
        .unwrap_err();
    assert_eq!(status_and_code(&encoding), (400, "invalid_checksum".to_owned()));
    let short = standard_base64().encode(b"short");
    let short = fixture
        .put_chunk(token, &data, 0, total, Some(&short))
        .await
        .unwrap_err();
    assert_eq!(short.status(), 400);
    let wrong = sha256_base64(b"other bytes");
    let refused = fixture.put_chunk(token, &data, 0, total, Some(&wrong)).await;
    assert!(
        refused.is_err(),
        "the server accepts a digest that does not match the part"
    );
    let accepted = fixture
        .put_chunk(token, &data, 0, total, Some(&sha256_base64(&data)))
        .await
        .unwrap();
    assert_eq!(accepted.status, STATUS_COMPLETED);
}

#[tokio::test]
async fn an_upload_without_a_checksum_keeps_working_and_refuses_unknown_algorithms() {
    let fixture = fixture();
    let created = fixture.create("plain.bin", 6 << 20, "").await.unwrap();
    assert_eq!(created.checksum, "");
    assert!(!fixture.target.with_store(|store| store.algorithm_requested));
    let data = vec![b'p'; 6 << 20];
    let done = fixture
        .put_chunk(&created.resume_token, &data, 0, 6 << 20, None)
        .await
        .unwrap();
    assert!(done.verified && !done.checksum_verified);
    let error = fixture.create("md5.bin", 6 << 20, "md5").await.unwrap_err();
    assert_eq!(error.status(), 400);
}

#[tokio::test]
async fn a_checksum_upload_is_not_verified_when_the_provider_stores_no_checksum() {
    let fixture = fixture();
    fixture.target.with_store(|store| store.silent = true);
    let total = 6 << 20;
    let created = fixture.create("silent.bin", total, "sha256").await.unwrap();
    let data = vec![b's'; total as usize];
    let done = fixture
        .put_chunk(&created.resume_token, &data, 0, total, Some(&sha256_base64(&data)))
        .await
        .unwrap();
    assert_eq!(done.status, STATUS_COMPLETED);
    assert!(!done.checksum_verified);
}

fn parts_with_digests() -> Vec<UploadPartState> {
    vec![
        UploadPartState {
            part_number: 1,
            checksum_sha256: sha256_base64(b"one"),
            checksum_stored: true,
            ..UploadPartState::default()
        },
        UploadPartState {
            part_number: 2,
            checksum_sha256: sha256_base64(b"two"),
            checksum_stored: true,
            ..UploadPartState::default()
        },
    ]
}

fn headers_with_object_checksum(value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("x-amz-checksum-sha256", HeaderValue::from_str(value).unwrap());
    headers
}

#[test]
fn a_composite_checksum_that_differs_is_detected() {
    let mut upload = UploadSession {
        checksum: "sha256".to_owned(),
        parts: parts_with_digests(),
        ..UploadSession::default()
    };
    let (digest, count) = composite_checksum(&upload.parts).unwrap();
    // S3 writes the digest and the number of parts. Garage writes the digest only.
    for good in [format!("{digest}-{count}"), digest.clone()] {
        upload.checksum_verified = false;
        verify_upload_checksum(&headers_with_object_checksum(&good), &mut upload).unwrap();
        assert!(upload.checksum_verified, "good composite {good:?}");
    }
    let other_count = headers_with_object_checksum(&format!("{digest}-3"));
    assert!(verify_upload_checksum(&other_count, &mut upload).is_err());
    assert!(
        !upload.checksum_verified,
        "the server accepts a composite with another part count"
    );
    let different = headers_with_object_checksum(&format!("{}-2", sha256_base64(b"x")));
    assert!(verify_upload_checksum(&different, &mut upload).is_err());
    assert!(!upload.checksum_verified, "the server accepts a different composite");
    verify_upload_checksum(&HeaderMap::new(), &mut upload).unwrap();
    assert!(upload.checksum_verified, "a provider that reports no object checksum");
}

#[test]
fn a_part_that_the_provider_did_not_confirm_stops_the_verification() {
    let mut upload = UploadSession {
        checksum: "sha256".to_owned(),
        parts: parts_with_digests(),
        ..UploadSession::default()
    };
    upload.parts[1].checksum_stored = false;
    verify_upload_checksum(&HeaderMap::new(), &mut upload).unwrap();
    assert!(!upload.checksum_verified);
}

#[test]
fn the_composite_checksum_needs_a_valid_digest_for_each_part() {
    let mut parts = parts_with_digests();
    parts[1].checksum_sha256 = "not a digest".to_owned();
    assert_eq!(composite_checksum(&parts), Err(2));
    assert!(same_composite_checksum("abc-2", "abc", 2));
    assert!(same_composite_checksum(" abc ", "abc", 2));
    assert!(!same_composite_checksum("abc-3", "abc", 2));
}

#[tokio::test]
async fn a_resumed_checksum_upload_keeps_its_algorithm_and_part_digests() {
    let mut fixture = fixture();
    let total = 10 << 20;
    let created = fixture.create("resume-sum.bin", total, "sha256").await.unwrap();
    let first = vec![b'r'; 5 << 20];
    fixture
        .put_chunk(&created.resume_token, &first, 0, total, Some(&sha256_base64(&first)))
        .await
        .unwrap();
    // The process loses its memory: the token carries the algorithm, and the provider lists the digests of the parts.
    fixture.manager = UploadManager::new();
    let resumed = fixture
        .manager
        .resume_checked(&fixture.targets, &OpCtx::default(), &created.resume_token, &NoCheck)
        .await
        .unwrap();
    assert_eq!(resumed.checksum, "sha256");
    assert_eq!(resumed.uploaded_bytes, first.len() as i64);
    let second = vec![b's'; 5 << 20];
    let done = fixture
        .put_chunk(
            &created.resume_token,
            &second,
            first.len() as i64,
            total,
            Some(&sha256_base64(&second)),
        )
        .await
        .unwrap();
    assert_eq!(done.status, STATUS_COMPLETED);
    assert!(done.checksum_verified);
    let completed = fixture.target.with_store(|store| store.completed.clone());
    assert_eq!(completed.len(), 2);
    assert_eq!(completed[0].checksum_sha256, sha256_base64(&first));
}

#[tokio::test]
async fn a_checksum_upload_keeps_the_part_digests_that_a_provider_does_not_list() {
    let fixture = fixture();
    fixture.target.with_store(|store| store.no_part_checksums = true);
    let total = 10 << 20;
    let created = fixture.create("keep.bin", total, "sha256").await.unwrap();
    let first = vec![b'k'; 5 << 20];
    fixture
        .put_chunk(&created.resume_token, &first, 0, total, Some(&sha256_base64(&first)))
        .await
        .unwrap();
    // A status request reads the parts of the provider again. The provider lists no digest: the server keeps its own.
    fixture
        .manager
        .resume_checked(&fixture.targets, &OpCtx::default(), &created.resume_token, &NoCheck)
        .await
        .unwrap();
    let second = vec![b'l'; 5 << 20];
    let done = fixture
        .put_chunk(
            &created.resume_token,
            &second,
            first.len() as i64,
            total,
            Some(&sha256_base64(&second)),
        )
        .await
        .unwrap();
    assert_eq!(done.status, STATUS_COMPLETED);
    assert!(done.checksum_verified);
}

#[test]
fn the_header_is_empty_or_a_base64_digest_of_32_bytes() {
    let header = |value: &str| {
        let mut headers = HeaderMap::new();
        headers.insert(CHECKSUM_HEADER, HeaderValue::from_str(value).unwrap());
        headers
    };
    assert_eq!(parse_checksum_header(&HeaderMap::new()).unwrap(), "");
    assert_eq!(parse_checksum_header(&header("  ")).unwrap(), "");
    let digest = sha256_base64(b"x");
    assert_eq!(parse_checksum_header(&header(&format!(" {digest} "))).unwrap(), digest);
    for bad in [
        "%%%",
        "not-base64!",
        &standard_base64().encode(b"short"),
        &digest[..digest.len() - 1],
    ] {
        let error = parse_checksum_header(&header(bad)).unwrap_err();
        assert_eq!(status_and_code(&error), (400, "invalid_checksum".to_owned()), "{bad:?}");
        assert_eq!(
            error.public_message(),
            "X-Checksum-Sha256 must be the base64 encoding of a 32-byte SHA-256 digest"
        );
    }
    // The name of the header has no case.
    let mut lower = HeaderMap::new();
    lower.insert("x-checksum-sha256", HeaderValue::from_str(&digest).unwrap());
    assert_eq!(parse_checksum_header(&lower).unwrap(), digest);
}

// --- The direct upload (PUT /s3) -------------------------------------------------------------------------------------

/// A write that behaves like a provider with SHA-256 checksums: it refuses a body with another digest and echoes the
/// digest that it checked.
async fn checked_put(ctx: &OpCtx, body: Body, silent: bool) -> Result<()> {
    let (data, _) = read_limited(body, usize::MAX).await?;
    if let Some(transfer) = &ctx.checksum
        && !silent
    {
        if transfer.sha256 != sha256_base64(&data) {
            return Err(Error::upstream(
                400,
                "BadDigest",
                "the checksum does not match the object",
            ));
        }
        if let Ok(mut echoed) = transfer.echoed.lock() {
            echoed.clone_from(&transfer.sha256);
        }
    }
    Ok(())
}

/// The steps of the route `PUT /s3` that use the helpers of the checksum: the answer is the status and the value of
/// `X-Checksum-Sha256-Verified`.
async fn gateway_put(body: &[u8], digest: Option<&str>, silent: bool) -> (u16, Option<&'static str>) {
    let mut headers = HeaderMap::new();
    if let Some(digest) = digest {
        headers.insert(CHECKSUM_HEADER, HeaderValue::from_str(digest).unwrap());
    }
    let digest = match parse_checksum_header(&headers) {
        Ok(digest) => digest,
        Err(error) => return (error.status(), None),
    };
    let (ctx, transfer) = with_checksum_transfer(&OpCtx::default(), &digest);
    if let Err(error) = checked_put(&ctx, crate::common::http::full(body.to_vec()), silent).await {
        return (error.status(), None);
    }
    let verified = transfer.as_ref().is_some_and(|transfer| checksum_confirmed(transfer));
    (204, verified.then_some("true"))
}

#[tokio::test]
async fn a_direct_upload_checksum_is_checked_and_confirmed() {
    let body = b"small file";
    assert_eq!(
        gateway_put(body, Some(&sha256_base64(body)), false).await,
        (204, Some("true"))
    );
    assert_eq!(gateway_put(body, None, false).await, (204, None));
    let wrong = gateway_put(body, Some(&sha256_base64(b"other")), false).await;
    assert_ne!(wrong.0, 204, "the server accepts a wrong digest");
    assert_eq!(gateway_put(body, Some("%%%"), false).await.0, 400);
    // A provider without checksums gives no confirmation. The upload still works.
    assert_eq!(gateway_put(body, Some(&sha256_base64(body)), true).await, (204, None));
}

#[test]
fn a_transfer_without_a_digest_needs_no_context() {
    let (ctx, transfer) = with_checksum_transfer(&OpCtx::default(), "");
    assert!(ctx.checksum.is_none() && transfer.is_none());
}
