// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tests of the upload sessions: the S3 multipart flow, the resume, the cancel, the limits and the idle sessions.

use std::sync::Arc;

use http::HeaderMap;
use http::header::HeaderValue;

use super::checksum::sha256_base64;
use super::manager::{ChunkInput, CreateUploadRequest, UploadManager};
use super::session::{STATUS_CANCELED, STATUS_COMPLETED, STATUS_UPLOADING, UploadSession};
use super::target::{NoCheck, Targets, UploadTarget};
use super::test_fakes::{FakeTarget, FakeTargets, test_cipher_key};
use super::token::open_resume_token;
use super::upload_id_from_token;
use crate::common::config::{PERMISSION_READ, PERMISSION_WRITE};
use crate::common::ctx::OpCtx;
use crate::common::error::Result;
use crate::common::http::full;
use crate::common::time::Timestamp;

fn setup() -> (UploadManager, Arc<FakeTargets>, Arc<FakeTarget>) {
    let target = Arc::new(FakeTarget::new("rw", "s3", "tenant/"));
    let targets = Arc::new(FakeTargets::new(vec![target.clone()]));
    (UploadManager::new(), targets, target)
}

fn request(key: &str, size: i64, checksum: &str) -> CreateUploadRequest {
    CreateUploadRequest {
        instance: "rw".to_owned(),
        key: key.to_owned(),
        size,
        content_type: "application/octet-stream".to_owned(),
        checksum: checksum.to_owned(),
        tags: Vec::new(),
    }
}

/// The step of a route after each answer: a session that ended leaves the memory.
fn answered(manager: &UploadManager, upload: UploadSession) -> UploadSession {
    manager.release_terminal(&upload);
    upload
}

async fn create(
    manager: &UploadManager,
    targets: &FakeTargets,
    key: &str,
    size: i64,
    checksum: &str,
) -> Result<UploadSession> {
    manager
        .create_checked(targets, &OpCtx::default(), request(key, size, checksum), &NoCheck)
        .await
        .map(|upload| answered(manager, upload))
}

/// The route `PUT /api/uploads`: open the token, then send the chunk.
async fn put_chunk(
    manager: &UploadManager,
    targets: &FakeTargets,
    token: &str,
    data: &[u8],
    start: i64,
    total: i64,
    digest: Option<&str>,
) -> Result<UploadSession> {
    let ctx = OpCtx::default();
    let upload = manager.resume_checked(targets, &ctx, token, &NoCheck).await?;
    let mut headers = HeaderMap::new();
    let end = start + data.len() as i64 - 1;
    headers.insert(
        "Content-Range",
        HeaderValue::from_str(&format!("bytes {start}-{end}/{total}")).unwrap(),
    );
    if let Some(digest) = digest {
        headers.insert("X-Checksum-Sha256", HeaderValue::from_str(digest).unwrap());
    }
    let input = ChunkInput {
        headers,
        content_length: data.len() as i64,
        body: full(data.to_vec()),
    };
    manager
        .upload_chunk(targets, &ctx, &upload.id, input)
        .await
        .map(|upload| answered(manager, upload))
}

async fn resume(manager: &UploadManager, targets: &FakeTargets, token: &str) -> Result<UploadSession> {
    manager
        .resume_checked(targets, &OpCtx::default(), token, &NoCheck)
        .await
        .map(|upload| answered(manager, upload))
}

const TOTAL_TWO_CHUNKS: i64 = (16 << 20) + 17;

#[tokio::test]
async fn an_s3_multipart_upload_uses_an_opaque_client_token_and_frees_the_terminal_state() {
    let (manager, targets, target) = setup();
    let created = create(&manager, &targets, "large.bin", TOTAL_TWO_CHUNKS, "")
        .await
        .unwrap();
    assert!(
        created.resume_token.starts_with("stowr1."),
        "token = {}",
        created.resume_token
    );
    let encoded = serde_json::to_string(&created.public()).unwrap();
    assert!(!encoded.contains("provider_upload_id"), "{encoded}");
    assert!(!encoded.contains("session_url"), "{encoded}");
    assert!(!encoded.contains("upload-1"), "{encoded}");
    assert_eq!(created.chunk_size, 16 << 20);

    let first = vec![b'a'; created.chunk_size as usize];
    let progress = put_chunk(
        &manager,
        &targets,
        &created.resume_token,
        &first,
        0,
        TOTAL_TWO_CHUNKS,
        None,
    )
    .await
    .unwrap();
    assert_eq!(progress.status, STATUS_UPLOADING);
    assert_eq!(progress.uploaded_bytes, first.len() as i64);
    let last = vec![b'b'; (TOTAL_TWO_CHUNKS - first.len() as i64) as usize];
    let completed = put_chunk(
        &manager,
        &targets,
        &created.resume_token,
        &last,
        first.len() as i64,
        TOTAL_TWO_CHUNKS,
        None,
    )
    .await
    .unwrap();
    assert_eq!(completed.status, STATUS_COMPLETED);
    assert!(completed.verified);
    assert_eq!(completed.uploaded_bytes, TOTAL_TWO_CHUNKS);
    assert!(
        manager.get(&upload_id_from_token(&created.resume_token)).is_none(),
        "a completed upload remained in server memory"
    );
    let (size, content_type) = target.with_store(|store| {
        let object = &store.objects["tenant/large.bin"];
        (object.data.len(), object.content_type.clone())
    });
    assert_eq!(size as i64, TOTAL_TWO_CHUNKS);
    assert_eq!(content_type, "application/octet-stream");
}

#[tokio::test]
async fn a_resume_token_rebuilds_the_provider_state_without_server_memory() {
    let (manager, targets, target) = setup();
    let total = 20 << 20;
    let created = create(&manager, &targets, "resume.bin", total, "").await.unwrap();
    let (descriptor, _) = open_resume_token(&created.resume_token, &*targets, Timestamp::now()).unwrap();
    let part = vec![b'r'; 5 << 20];
    target
        .upload_part(
            &OpCtx::default(),
            "tenant/resume.bin",
            &descriptor.provider_upload_id,
            1,
            full(part.clone()),
            part.len() as i64,
        )
        .await
        .unwrap();

    // The process loses its memory. The token and the provider session are the only data that remain.
    let manager = UploadManager::new();
    let resumed = resume(&manager, &targets, &created.resume_token).await.unwrap();
    assert_eq!(resumed.uploaded_bytes, part.len() as i64);
    assert_eq!(resumed.parts.len(), 1);
    assert_eq!(resumed.status, STATUS_UPLOADING);

    // The key of the token comes from the credentials: a new registry with the same credentials opens the token.
    let fresh = FakeTargets::new(vec![Arc::new(FakeTarget::new("rw", "s3", "tenant/"))]);
    assert!(open_resume_token(&created.resume_token, &fresh, Timestamp::now()).is_ok());
}

#[tokio::test]
async fn a_canceled_upload_aborts_the_provider_and_frees_memory() {
    let (manager, targets, target) = setup();
    let created = create(&manager, &targets, "cancel.bin", 8 << 20, "").await.unwrap();
    assert_eq!(target.with_store(|store| store.open_multiparts().len()), 1);
    let ctx = OpCtx::default();
    let upload = manager
        .resume_checked(&*targets, &ctx, &created.resume_token, &NoCheck)
        .await
        .unwrap();
    let canceled = manager.cancel(&*targets, &ctx, &upload.id).await.unwrap();
    assert_eq!(canceled.status, STATUS_CANCELED);
    manager.release_terminal(&canceled);
    assert!(
        target.with_store(|store| store.open_multiparts().is_empty()),
        "the server does not abort the provider multipart session"
    );
    assert!(
        manager.get(&upload_id_from_token(&created.resume_token)).is_none(),
        "a canceled upload remained in server memory"
    );
}

#[tokio::test]
async fn the_memory_limit_refuses_additional_sessions() {
    let (manager, targets, _) = setup();
    let now = Timestamp::now();
    for index in 0..4 {
        manager
            .put(UploadSession {
                id: format!("upload-active-{index}"),
                instance: "rw".to_owned(),
                key: format!("upload-{index}.bin"),
                provider: "s3".to_owned(),
                status: STATUS_UPLOADING.to_owned(),
                total_size: 8 << 20,
                chunk_size: 8 << 20,
                created_at: now,
                updated_at: now,
                ..UploadSession::default()
            })
            .unwrap();
    }
    let error = create(&manager, &targets, "one-too-many.bin", 8 << 20, "")
        .await
        .unwrap_err();
    let api = error.as_api().unwrap();
    assert_eq!(api.status, 429);
    assert_eq!(api.code, "upload_session_limit_reached");
}

#[tokio::test]
async fn idle_sessions_are_aborted_and_free_capacity() {
    let (manager, targets, target) = setup();
    let mut created = Vec::new();
    for index in 0..4 {
        created.push(
            create(&manager, &targets, &format!("abandoned-{index}.bin"), 8 << 20, "")
                .await
                .unwrap(),
        );
    }
    assert!(
        create(&manager, &targets, "extra.bin", 8 << 20, "").await.is_err(),
        "expected the session table to be full"
    );
    let now = Timestamp::now();
    let half = (manager.idle_ttl().as_secs() / 2) as i64;
    assert_eq!(manager.reap_idle(&*targets, now.plus_secs(half)).await, 0);
    // A session that is mid-request keeps its slot however long it has been idle.
    let busy = manager.upload_lock(&upload_id_from_token(&created[0].resume_token));
    let guard = busy.lock().await;
    let late = now.plus_secs(manager.idle_ttl().as_secs() as i64 + 60);
    assert_eq!(manager.reap_idle(&*targets, late).await, 3);
    drop(guard);
    assert_eq!(manager.reap_idle(&*targets, late).await, 1);
    assert!(
        target.with_store(|store| store.open_multiparts().is_empty()),
        "the server leaves provider multipart sessions open"
    );
    create(&manager, &targets, "after-reap.bin", 8 << 20, "").await.unwrap();
}

#[tokio::test]
async fn a_resume_does_not_probe_keys_on_a_read_denied_instance() {
    let existing = Arc::new(FakeTarget::new("wo", "s3", "").with_permissions(&[PERMISSION_WRITE]));
    existing.with_store(|store| {
        store.objects.insert(
            "present.bin".to_owned(),
            super::test_fakes::FakeObject {
                data: vec![b'x'; 8 << 20],
                content_type: String::new(),
            },
        );
    });
    let targets = FakeTargets::new(vec![existing.clone()]);
    let manager = UploadManager::new();
    let ctx = OpCtx::default();
    let probe = |key: &'static str| {
        let manager = manager.clone();
        let targets = &targets;
        let ctx = ctx.clone();
        async move {
            let created = manager
                .create_checked(
                    targets,
                    &ctx,
                    CreateUploadRequest {
                        instance: "wo".to_owned(),
                        key: key.to_owned(),
                        size: 8 << 20,
                        content_type: "application/octet-stream".to_owned(),
                        ..CreateUploadRequest::default()
                    },
                    &NoCheck,
                )
                .await
                .unwrap();
            // Abort the provider session, then resume with the same token.
            let upload = manager
                .resume_checked(targets, &ctx, &created.resume_token, &NoCheck)
                .await
                .unwrap();
            let canceled = manager.cancel(targets, &ctx, &upload.id).await.unwrap();
            manager.release_terminal(&canceled);
            let resumed = manager
                .resume_checked(targets, &ctx, &created.resume_token, &NoCheck)
                .await
                .unwrap();
            manager.release_terminal(&resumed);
            resumed
        }
    };
    let present = probe("present.bin").await;
    let absent = probe("absent.bin").await;
    assert_eq!(present.status, absent.status);
    assert_eq!(present.verified, absent.verified);
    assert_eq!(present.error, absent.error);
    assert_ne!(
        present.status, STATUS_COMPLETED,
        "the server treats a vanished session as completed"
    );
    assert!(!present.verified);
}

#[tokio::test]
async fn a_session_that_has_vanished_counts_as_completed_when_the_object_can_be_read() {
    let (manager, targets, target) = setup();
    let total = 6 << 20;
    let created = create(&manager, &targets, "done.bin", total, "").await.unwrap();
    let data = vec![b'd'; total as usize];
    put_chunk(&manager, &targets, &created.resume_token, &data, 0, total, None)
        .await
        .unwrap();
    // The provider keeps the object and has no multipart session any more.
    assert_eq!(
        target.with_store(|store| store.objects["tenant/done.bin"].data.len()),
        total as usize
    );
    let resumed = resume(&manager, &targets, &created.resume_token).await.unwrap();
    assert_eq!(resumed.status, STATUS_COMPLETED);
    assert!(resumed.verified);
    assert_eq!(resumed.uploaded_bytes, total);
}

#[tokio::test]
async fn an_empty_object_is_written_at_once_and_has_no_token() {
    let (manager, targets, target) = setup();
    let created = create(&manager, &targets, "empty.txt", 0, "").await.unwrap();
    assert_eq!(created.status, STATUS_COMPLETED);
    assert!(created.verified);
    assert!(created.resume_token.is_empty());
    assert!(created.id.starts_with("upl_") && created.id.len() == 36);
    assert!(target.with_store(|store| store.objects.contains_key("tenant/empty.txt")));
    assert!(manager.get(&created.id).is_none());
}

#[tokio::test]
async fn a_create_request_is_validated_before_the_first_call_to_the_storage() {
    let (manager, targets, target) = setup();
    let cases: Vec<(CreateUploadRequest, u16, &str)> = vec![
        (
            CreateUploadRequest {
                instance: "nope".to_owned(),
                ..request("a", 10, "")
            },
            404,
            "unknown_instance",
        ),
        (request("", 10, ""), 400, "invalid_key"),
        (request("/", 10, ""), 400, "invalid_key"),
        (request("a", -1, ""), 400, "invalid_size"),
        (request("a", (5_i64 << 40) + 1, ""), 400, "invalid_size"),
        (request("a", 10, "md5"), 400, "invalid_checksum"),
        (
            CreateUploadRequest {
                tags: vec![crate::lifecycle::Tag {
                    key: "aws:x".to_owned(),
                    value: "y".to_owned(),
                }],
                ..request("a", 10, "")
            },
            400,
            "invalid_tags",
        ),
    ];
    for (request, status, code) in cases {
        let error = manager
            .create_checked(&*targets, &OpCtx::default(), request, &NoCheck)
            .await
            .unwrap_err();
        let api = error.as_api().unwrap();
        assert_eq!((api.status, api.code.as_str()), (status, code), "{error}");
    }
    assert!(target.with_store(|store| store.open_multiparts().is_empty()));
}

#[tokio::test]
async fn tags_are_refused_for_a_target_that_keeps_none() {
    let mut target = FakeTarget::new("rw", "s3", "tenant/");
    target.tags_supported = false;
    let targets = FakeTargets::new(vec![Arc::new(target)]);
    let manager = UploadManager::new();
    let error = manager
        .create_checked(
            &targets,
            &OpCtx::default(),
            CreateUploadRequest {
                tags: vec![crate::lifecycle::Tag {
                    key: "a".to_owned(),
                    value: "b".to_owned(),
                }],
                ..request("a", 10, "")
            },
            &NoCheck,
        )
        .await
        .unwrap_err();
    assert_eq!(error.code(), "tagging_unsupported");
    assert_eq!(error.status(), 501);
}

#[tokio::test]
async fn a_create_request_needs_the_write_permission() {
    let target = FakeTarget::new("rw", "s3", "tenant/").with_permissions(&[PERMISSION_READ]);
    let targets = FakeTargets::new(vec![Arc::new(target)]);
    let error = UploadManager::new()
        .create_checked(&targets, &OpCtx::default(), request("a", 10, ""), &NoCheck)
        .await
        .unwrap_err();
    assert_eq!(error.status(), 403);
    assert_eq!(error.code(), "permission_denied");
}

#[tokio::test]
async fn a_chunk_is_checked_against_the_session_before_it_goes_to_the_provider() {
    let (manager, targets, target) = setup();
    let total = 8 << 20;
    let created = create(&manager, &targets, "chunks.bin", total, "").await.unwrap();
    let ctx = OpCtx::default();
    let upload = manager
        .resume_checked(&*targets, &ctx, &created.resume_token, &NoCheck)
        .await
        .unwrap();
    let send = |range: Option<&str>, length: i64| {
        let mut headers = HeaderMap::new();
        if let Some(range) = range {
            headers.insert("Content-Range", HeaderValue::from_str(range).unwrap());
        }
        let input = ChunkInput {
            headers,
            content_length: length,
            body: full(vec![b'c'; 10]),
        };
        manager.upload_chunk(&*targets, &ctx, &upload.id, input)
    };
    let range = format!("bytes 0-{}/{total}", 10 - 1);
    let cases: Vec<(Option<&str>, i64, u16, &str)> = vec![
        (None, 10, 400, "invalid_content_range"),
        (Some("items 0-9/10"), 10, 400, "invalid_content_range"),
        (Some("bytes 5-2/10"), 10, 400, "invalid_content_range"),
        (Some("bytes 0-9/9"), 10, 400, "invalid_content_range"),
        (Some("bytes 0-9/10"), 10, 409, "size_mismatch"),
        (Some(range.as_str()), -1, 411, "content_length_required"),
        (Some(range.as_str()), 9, 400, "content_length_mismatch"),
        (Some(range.as_str()), 10, 400, "part_too_small"),
    ];
    for (range, length, status, code) in cases {
        let error = send(range, length).await.unwrap_err();
        let api = error.as_api().unwrap();
        assert_eq!((api.status, api.code.as_str()), (status, code), "{range:?}: {error}");
    }
    let mut headers = HeaderMap::new();
    headers.insert(
        "Content-Range",
        HeaderValue::from_str(&format!("bytes 100-109/{total}")).unwrap(),
    );
    let input = ChunkInput {
        headers,
        content_length: 10,
        body: full(vec![b'c'; 10]),
    };
    let error = manager
        .upload_chunk(&*targets, &ctx, &upload.id, input)
        .await
        .unwrap_err();
    assert_eq!(error.code(), "offset_mismatch");
    assert_eq!(error.public_message(), "upload must resume at byte 0");
    assert!(target.with_store(|store| store.objects.is_empty()));
}

#[tokio::test]
async fn a_chunk_for_a_session_that_does_not_exist_is_refused() {
    let (manager, targets, _) = setup();
    let error = manager
        .upload_chunk(
            &*targets,
            &OpCtx::default(),
            "upl_none",
            ChunkInput {
                headers: HeaderMap::new(),
                content_length: 0,
                body: full(Vec::new()),
            },
        )
        .await
        .unwrap_err();
    assert_eq!((error.status(), error.code().as_str()), (404, "upload_not_found"));
    assert!(manager.status(&*targets, &OpCtx::default(), "upl_none").await.is_err());
}

#[tokio::test]
async fn a_resumable_provider_uploads_in_chunks_and_verifies_the_object() {
    let target = Arc::new(FakeTarget::new("vol", "fs", ""));
    let targets = FakeTargets::new(vec![target.clone()]);
    let manager = UploadManager::new();
    let total: i64 = (8 << 20) + 5;
    let created = manager
        .create_checked(
            &targets,
            &OpCtx::default(),
            CreateUploadRequest {
                instance: "vol".to_owned(),
                key: "dir/file.bin".to_owned(),
                size: total,
                ..CreateUploadRequest::default()
            },
            &NoCheck,
        )
        .await
        .unwrap();
    assert_eq!(created.chunk_size, 8 << 20);
    assert!(
        manager
            .active_provider_uploads("vol")
            .contains(&super::volume_session_upload_id(&created.session_url))
    );
    let first = vec![b'1'; 8 << 20];
    let first_done = send_chunk(&manager, &targets, &created.resume_token, &first, 0, total)
        .await
        .unwrap();
    assert_eq!(first_done.uploaded_bytes, 8 << 20);
    assert_eq!(first_done.status, STATUS_UPLOADING);
    let last = send_chunk(&manager, &targets, &created.resume_token, b"12345", 8 << 20, total)
        .await
        .unwrap();
    assert_eq!(last.status, STATUS_COMPLETED);
    assert!(last.verified);
    assert_eq!(
        target.with_store(|store| store.objects["dir/file.bin"].data.len()) as i64,
        total
    );
    assert!(manager.active_provider_uploads("vol").is_empty());
}

async fn send_chunk(
    manager: &UploadManager,
    targets: &FakeTargets,
    token: &str,
    data: &[u8],
    start: i64,
    total: i64,
) -> Result<UploadSession> {
    put_chunk(manager, targets, token, data, start, total, None).await
}

#[tokio::test]
async fn a_resumable_upload_reads_its_offset_again_after_a_lost_answer() {
    let target = Arc::new(FakeTarget::new("vol", "gcs", ""));
    let targets = FakeTargets::new(vec![target.clone()]);
    let manager = UploadManager::new();
    let total: i64 = 16 << 20;
    let created = manager
        .create_checked(
            &targets,
            &OpCtx::default(),
            CreateUploadRequest {
                instance: "vol".to_owned(),
                key: "big.bin".to_owned(),
                size: total,
                ..CreateUploadRequest::default()
            },
            &NoCheck,
        )
        .await
        .unwrap();
    let chunk = vec![b'g'; 8 << 20];
    send_chunk(&manager, &targets, &created.resume_token, &chunk, 0, total)
        .await
        .unwrap();
    // The client lost the answer and sends the first chunk again: the server reads the offset of the provider and
    // refuses the old offset.
    let error = send_chunk(&manager, &targets, &created.resume_token, &chunk, 0, total)
        .await
        .unwrap_err();
    assert_eq!(error.code(), "offset_mismatch");
    assert_eq!(
        error.public_message(),
        format!("upload must resume at byte {}", 8 << 20)
    );
    let done = send_chunk(&manager, &targets, &created.resume_token, &chunk, 8 << 20, total)
        .await
        .unwrap();
    assert_eq!(done.status, STATUS_COMPLETED);
}

#[tokio::test]
async fn an_object_with_a_wrong_size_is_not_verified() {
    let (manager, targets, target) = setup();
    let total = 6 << 20;
    let created = create(&manager, &targets, "short.bin", total, "").await.unwrap();
    target.with_store(|store| store.head_size_override = Some(5));
    let data = vec![b's'; total as usize];
    let error = put_chunk(&manager, &targets, &created.resume_token, &data, 0, total, None)
        .await
        .unwrap_err();
    assert_eq!(error.status(), 502);
    let kept = manager.get(&upload_id_from_token(&created.resume_token)).unwrap();
    assert!(!kept.verified);
    assert_eq!(
        kept.error,
        format!("the upload completed but the provider reports 5 bytes instead of {total}")
    );
}

#[test]
fn the_digest_helper_matches_a_known_value() {
    assert_eq!(sha256_base64(b""), "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
}

#[tokio::test]
async fn the_cipher_key_of_the_tests_matches_a_known_key() {
    let key = test_cipher_key();
    assert_eq!(
        crate::common::misc::hex(&key),
        "e1d943c734e601b1d7b1dcab52f76ea80a33206ecae52d868690ef626b584b84"
    );
    let (_, targets, _) = setup();
    assert!(targets.target("rw").is_some() && targets.target("other").is_none());
}

#[tokio::test]
async fn the_reaper_aborts_a_session_that_stays_idle() {
    use std::time::Duration;
    let target = Arc::new(FakeTarget::new("rw", "s3", "tenant/"));
    let targets = Arc::new(FakeTargets::new(vec![target.clone()]));
    let manager = UploadManager::with_timings(
        Duration::from_millis(100),
        Duration::from_millis(20),
        Duration::from_secs(5),
    );
    let created = create(&manager, &targets, "idle.bin", 8 << 20, "").await.unwrap();
    let registry: Arc<dyn Targets> = targets.clone();
    manager.ensure_reaper(Arc::downgrade(&registry));
    // The call a second time does not start a second task.
    manager.ensure_reaper(Arc::downgrade(&registry));
    let id = upload_id_from_token(&created.resume_token);
    assert!(manager.get(&id).is_some());
    for _ in 0..100 {
        if manager.get(&id).is_none() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(manager.get(&id).is_none(), "the reaper kept an idle session");
    assert!(target.with_store(|store| store.open_multiparts().is_empty()));
    manager.close();
}

#[tokio::test]
async fn the_reaper_stops_with_the_manager() {
    use std::time::Duration;
    let targets = Arc::new(FakeTargets::new(vec![Arc::new(FakeTarget::new("rw", "s3", "tenant/"))]));
    let manager = UploadManager::with_timings(
        Duration::from_millis(10),
        Duration::from_millis(10),
        Duration::from_secs(5),
    );
    let registry: Arc<dyn Targets> = targets.clone();
    manager.ensure_reaper(Arc::downgrade(&registry));
    manager.close();
    let created = create(&manager, &targets, "late.bin", 8 << 20, "").await.unwrap();
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(manager.get(&upload_id_from_token(&created.resume_token)).is_some());
}
