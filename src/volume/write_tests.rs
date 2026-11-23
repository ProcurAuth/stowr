//! The tests of the writes, the copies, the moves, the deletes and the uploads of a volume.

use std::fs;
use std::os::unix::fs::{MetadataExt, symlink};
use std::path::Path;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use aws_lc_rs::digest::{SHA256, digest};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use bytes::Bytes;

use super::VolumeBackend;
use super::tests::{
    TestDir, body_of, code_of, ctx, list, open_volume, page_keys, put_text, read_volume_file, temporary_files,
    volume_tree, write_volume_file,
};
use crate::common::ctx::OpCtx;
use crate::common::error::Result;
use crate::common::http::channel;
use crate::common::storage::{Backend, ListOptions, MultipartCopyOptions, ResumableApi};
use crate::provider::ChecksumTransfer;
use crate::uploads::MultipartCursor;

fn status_of(result: Result<()>) -> u16 {
    match result {
        Ok(()) => 0,
        Err(error) => error.status(),
    }
}

fn digest_of(text: &str) -> String {
    STANDARD.encode(digest(&SHA256, text.as_bytes()).as_ref())
}

fn context_with_checksum(sum: &str) -> (OpCtx, Arc<ChecksumTransfer>) {
    let transfer = Arc::new(ChecksumTransfer {
        sha256: sum.to_owned(),
        echoed: Mutex::new(String::new()),
    });
    let ctx = OpCtx {
        checksum: Some(Arc::clone(&transfer)),
        ..OpCtx::default()
    };
    (ctx, transfer)
}

/// The keys of the tree under a prefix, in the order of the listing.
async fn keys_under(backend: &VolumeBackend, prefix: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let mut token = String::new();
    loop {
        let page = list(
            backend,
            ListOptions {
                prefix: prefix.to_owned(),
                page_token: token.clone(),
                ..ListOptions::default()
            },
        )
        .await
        .expect("a page");
        keys.extend(page_keys(&page));
        token = page.next_page_token;
        if token.is_empty() {
            return keys;
        }
    }
}

/// The copy of a folder, as the job of the server does it: one copy for each key of the tree.
async fn copy_prefix(backend: &VolumeBackend, from: &str, to: &str) -> usize {
    let keys = keys_under(backend, from).await;
    for key in &keys {
        let destination = format!("{to}{}", &key[from.len()..]);
        backend.copy(&ctx(), key, &destination).await.expect("a copy");
    }
    keys.len()
}

async fn move_prefix(backend: &VolumeBackend, from: &str, to: &str) -> usize {
    let keys = keys_under(backend, from).await;
    let mover = backend.mover().expect("a mover");
    for key in &keys {
        let destination = format!("{to}{}", &key[from.len()..]);
        mover.move_object(&ctx(), key, &destination).await.expect("a move");
    }
    backend
        .folder_remover()
        .expect("a folder remover")
        .remove_empty_folders(&ctx(), from)
        .await
        .expect("the removal of the folders");
    keys.len()
}

async fn delete_prefix(backend: &VolumeBackend, prefix: &str) -> usize {
    let keys = keys_under(backend, prefix).await;
    for key in &keys {
        backend.delete(&ctx(), key).await.expect("a delete");
    }
    backend
        .folder_remover()
        .expect("a folder remover")
        .remove_empty_folders(&ctx(), prefix)
        .await
        .expect("the removal of the folders");
    keys.len()
}

/// Write a file from a body that comes in blocks, as a request does.
async fn put_blocks(backend: &VolumeBackend, ctx: &OpCtx, key: &str, size: i64, blocks: Vec<Bytes>) -> Result<()> {
    let (sender, body) = channel(2);
    let feeder = async move {
        for block in blocks {
            if sender.send(block).await.is_err() {
                break;
            }
        }
    };
    let (result, ()) = tokio::join!(backend.put(ctx, key, body, size, ""), feeder);
    result
}

#[tokio::test]
async fn writes_replace_a_file_atomically() {
    let (base, root) = volume_tree();
    fs::remove_file(root.join(".stowr-tmp-0123456789abcdef0123456789abcdef-upload.bin")).expect("remove the file");
    let backend = open_volume(&root, false);
    put_text(&backend, "new/deep/file.txt", "first").await.expect("a write");
    assert_eq!(read_volume_file(&root, "new/deep/file.txt"), "first");
    let before = fs::metadata(root.join("new/deep/file.txt")).expect("the file");
    put_text(&backend, "new/deep/file.txt", "second write")
        .await
        .expect("a second write");
    let after = fs::metadata(root.join("new/deep/file.txt")).expect("the file");
    assert_eq!(read_volume_file(&root, "new/deep/file.txt"), "second write");
    assert_ne!(
        before.ino(),
        after.ino(),
        "the second write did not replace the file with a new file"
    );
    let sum = digest_of("checked");
    let (checked, transfer) = context_with_checksum(&sum);
    backend
        .put(&checked, "checked.txt", body_of("checked"), 7, "")
        .await
        .expect("a write with the checksum");
    assert_eq!(*transfer.echoed.lock().expect("the digest"), sum);
    let (wrong, transfer) = context_with_checksum(&sum);
    let refused = backend
        .put(&wrong, "new/deep/file.txt", body_of("changed bytes"), 13, "")
        .await;
    assert_eq!(code_of(refused), (400, "bad_digest".to_owned()));
    assert_eq!(*transfer.echoed.lock().expect("the digest"), "");
    assert_eq!(
        read_volume_file(&root, "new/deep/file.txt"),
        "second write",
        "a write with a wrong checksum changed the file"
    );
    backend
        .put(&ctx(), "new/folder/", body_of(""), 0, "")
        .await
        .expect("a folder key");
    assert!(root.join("new/folder").is_dir(), "the folder key made no folder");
    let long = format!("{}.x", "n".repeat(256));
    let cases = [
        ("new/deep", 409),
        ("a0/inside.txt", 409),
        ("link-out/x.txt", 403),
        ("x/../../escape.txt", 400),
        ("x/.stowr-tmp-mine", 400),
        ("link-dangling/inside/file.txt", 403),
        (long.as_str(), 400),
    ];
    for (key, status) in cases {
        assert_eq!(status_of(put_text(&backend, key, "x").await), status, "PUT {key:?}");
    }
    assert!(
        !base.path().join("outside").join("x.txt").exists(),
        "a write went out of the volume"
    );
    assert!(
        !base.path().join("escape.txt").exists(),
        "a write went out of the volume"
    );
    // A symbolic link to a file in the root: the write goes to its target, and the link stays.
    put_text(&backend, "link-file", "through the link")
        .await
        .expect("a write through a link");
    assert_eq!(read_volume_file(&root, "a0"), "through the link");
    assert!(
        fs::symlink_metadata(root.join("link-file"))
            .expect("the link")
            .file_type()
            .is_symlink(),
        "the write replaced the link"
    );
    assert!(
        temporary_files(&root).is_empty(),
        "temporary files stay: {:?}",
        temporary_files(&root)
    );
}

#[tokio::test]
async fn a_folder_key_takes_no_content_and_the_root_is_not_a_file() {
    let base = TestDir::new();
    let backend = open_volume(base.path(), false);
    let content = backend.put(&ctx(), "folder/", body_of("x"), 1, "").await;
    assert_eq!(code_of(content), (400, "invalid_key".to_owned()));
    let root = backend.put(&ctx(), "", body_of(""), 0, "").await;
    assert_eq!(code_of(root), (400, "invalid_key".to_owned()));
    let deleted = backend.delete(&ctx(), "").await;
    assert_eq!(code_of(deleted), (400, "invalid_key".to_owned()));
}

#[tokio::test]
async fn a_body_in_blocks_is_written_with_a_known_or_an_unknown_size() {
    let base = TestDir::new();
    let backend = open_volume(base.path(), false);
    let blocks: Vec<Bytes> = (0..50u8)
        .map(|index| Bytes::from(vec![b'a' + index % 26; 10_000]))
        .collect();
    let expected: Vec<u8> = blocks.iter().flat_map(|block| block.to_vec()).collect();
    put_blocks(&backend, &ctx(), "known.bin", 500_000, blocks.clone())
        .await
        .expect("a known size");
    assert_eq!(fs::read(base.path().join("known.bin")).expect("the file"), expected);
    put_blocks(&backend, &ctx(), "unknown.bin", -1, blocks.clone())
        .await
        .expect("an unknown size");
    assert_eq!(fs::read(base.path().join("unknown.bin")).expect("the file"), expected);
    // The bytes after the declared size are not written.
    put_blocks(&backend, &ctx(), "cut.txt", 3, vec![Bytes::from("abcdef")])
        .await
        .expect("a cut body");
    assert_eq!(read_volume_file(base.path(), "cut.txt"), "abc");
    assert!(temporary_files(base.path()).is_empty());
}

#[tokio::test]
async fn a_body_that_is_too_short_writes_nothing() {
    let base = TestDir::new();
    write_volume_file(base.path(), "kept.txt", "kept");
    let backend = open_volume(base.path(), false);
    let short = put_blocks(&backend, &ctx(), "kept.txt", 1000, vec![Bytes::from(vec![b'x'; 600])]).await;
    assert_eq!(code_of(short), (400, "incomplete_body".to_owned()));
    assert_eq!(
        read_volume_file(base.path(), "kept.txt"),
        "kept",
        "a short body changed the file"
    );
    let new = put_blocks(&backend, &ctx(), "new.txt", 10, vec![]).await;
    assert_eq!(status_of(new), 400);
    assert!(!base.path().join("new.txt").exists());
    assert!(
        temporary_files(base.path()).is_empty(),
        "{:?}",
        temporary_files(base.path())
    );
}

#[tokio::test]
async fn a_canceled_write_removes_its_temporary_file() {
    let base = TestDir::new();
    let backend = open_volume(base.path(), false);
    let ctx = ctx();
    let token = ctx.cancel.clone();
    let (sender, body) = channel(2);
    let feeder = async move {
        let _ = sender.send(Bytes::from(vec![1u8; 1000])).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        token.cancel();
        sender
    };
    let (result, _sender) = tokio::join!(backend.put(&ctx, "c/cancel.bin", body, 1 << 20, ""), feeder);
    assert_eq!(
        result.expect_err("a canceled write"),
        crate::common::error::Error::Canceled
    );
    assert!(!base.path().join("c").join("cancel.bin").exists());
    assert!(
        temporary_files(base.path()).is_empty(),
        "{:?}",
        temporary_files(base.path())
    );
}

#[tokio::test]
async fn a_write_that_creates_only_stops_on_an_existing_file() {
    let base = TestDir::new();
    write_volume_file(base.path(), "there.txt", "there");
    let backend = open_volume(base.path(), false);
    let writer = backend.conditional_writer().expect("a conditional writer");
    let refused = writer.put_if_absent(&ctx(), "there.txt", body_of("other"), 5, "").await;
    assert_eq!(code_of(refused), (409, "object_exists".to_owned()));
    assert_eq!(read_volume_file(base.path(), "there.txt"), "there");
    writer
        .put_if_absent(&ctx(), "here/new.txt", body_of("new"), 3, "")
        .await
        .expect("a new file");
    assert_eq!(read_volume_file(base.path(), "here/new.txt"), "new");
    assert!(
        temporary_files(base.path()).is_empty(),
        "{:?}",
        temporary_files(base.path())
    );
}

#[tokio::test]
async fn a_delete_removes_files_and_empty_folders() {
    let (base, root) = volume_tree();
    let backend = open_volume(&root, false);
    for key in ["link-file", "a0", "missing.txt", "missing/x.txt", "empty/", "a/", "a"] {
        backend
            .delete(&ctx(), key)
            .await
            .unwrap_or_else(|error| panic!("DELETE {key}: {error}"));
    }
    let exists = [("a0", false), ("empty", false), ("a/b.txt", true), ("link-file", false)];
    for (relative, wanted) in exists {
        assert_eq!(
            fs::symlink_metadata(root.join(relative)).is_ok(),
            wanted,
            "{relative} exists"
        );
    }
    let link = backend.delete(&ctx(), "link-out").await;
    assert_eq!(code_of(link).0, 403, "a delete of a link that leaves the root");
    assert_eq!(read_volume_file(base.path(), "outside/secret.txt"), "secret");
}

#[tokio::test]
async fn copy_move_and_delete_work_on_files_and_on_folders() {
    let base = TestDir::new();
    let root = base.path();
    write_volume_file(root, "docs/a.txt", "a");
    write_volume_file(root, "docs/sub/b.txt", "bb");
    fs::create_dir_all(root.join("docs/sub/void")).expect("make the folders");
    let backend = open_volume(root, false);

    backend
        .copy(&ctx(), "docs/a.txt", "copies/a.txt")
        .await
        .expect("a copy");
    assert_eq!(read_volume_file(root, "copies/a.txt"), "a");
    assert_eq!(read_volume_file(root, "docs/a.txt"), "a");
    let before = fs::metadata(root.join("copies/a.txt")).expect("the copy");
    backend
        .mover()
        .expect("a mover")
        .move_object(&ctx(), "copies/a.txt", "renamed/a.txt")
        .await
        .expect("a move");
    let after = fs::metadata(root.join("renamed/a.txt")).expect("the moved file");
    assert_eq!(
        (before.dev(), before.ino()),
        (after.dev(), after.ino()),
        "the move is not one rename of the file"
    );
    assert!(!root.join("copies/a.txt").exists(), "the source of the move stays");

    assert_eq!(copy_prefix(&backend, "docs/", "backup/").await, 3);
    assert_eq!(read_volume_file(root, "backup/sub/b.txt"), "bb");
    assert!(
        root.join("backup/sub/void").is_dir(),
        "the copy of the folder lost its empty folder"
    );

    assert_eq!(move_prefix(&backend, "backup/", "archive/").await, 3);
    assert_eq!(read_volume_file(root, "archive/sub/b.txt"), "bb");
    assert!(
        !root.join("backup").exists(),
        "the move of a folder left the source folder"
    );
    assert!(
        root.join("archive/sub/void").is_dir(),
        "the move of the folder lost its empty folder"
    );

    assert_eq!(delete_prefix(&backend, "archive/").await, 3);
    assert!(!root.join("archive").exists(), "the delete of a folder left the folder");
    // A folder with only an empty folder is a folder to delete too.
    fs::create_dir_all(root.join("hollow/inner")).expect("make the folders");
    delete_prefix(&backend, "hollow/").await;
    assert!(
        !root.join("hollow").exists(),
        "the delete of a folder with an empty folder left the folder"
    );
}

#[tokio::test]
async fn a_copy_goes_from_a_file_to_a_file_or_from_a_folder_to_a_folder() {
    let base = TestDir::new();
    write_volume_file(base.path(), "f.txt", "f");
    fs::create_dir(base.path().join("d")).expect("make a folder");
    let backend = open_volume(base.path(), false);
    assert_eq!(status_of(backend.copy(&ctx(), "f.txt", "g/").await), 400);
    assert_eq!(status_of(backend.copy(&ctx(), "d/", "g").await), 400);
    assert_eq!(status_of(backend.copy(&ctx(), "missing.txt", "g").await), 404);
    backend
        .copy(&ctx(), "f.txt", "f.txt")
        .await
        .expect("a copy onto itself");
    assert_eq!(read_volume_file(base.path(), "f.txt"), "f");
    let mover = backend.mover().expect("a mover");
    assert_eq!(status_of(mover.move_object(&ctx(), "f.txt", "g/").await), 400);
    mover
        .move_object(&ctx(), "f.txt", "f.txt")
        .await
        .expect("a move onto itself");
    assert!(base.path().join("f.txt").exists());
    assert!(temporary_files(base.path()).is_empty());
}

#[tokio::test]
async fn the_delete_of_a_folder_keeps_a_link_that_leaves_the_root() {
    let base = TestDir::new();
    let root = base.path().join("volume");
    write_volume_file(base.path(), "outside/secret.txt", "secret");
    write_volume_file(&root, "mixed/file.txt", "file");
    symlink(base.path().join("outside"), root.join("mixed").join("escape")).expect("make a link");
    let backend = open_volume(&root, false);
    delete_prefix(&backend, "mixed/").await;
    assert!(!root.join("mixed/file.txt").exists(), "the file stays");
    assert!(
        fs::symlink_metadata(root.join("mixed/escape")).is_ok(),
        "the delete removed the link that leaves the root"
    );
    assert_eq!(read_volume_file(base.path(), "outside/secret.txt"), "secret");
}

#[tokio::test]
async fn a_large_copy_reports_its_progress_and_a_large_move_is_one_rename() {
    let base = TestDir::new();
    let content = "0123456789abcdef".repeat(1 << 20);
    write_volume_file(base.path(), "big.bin", &content);
    let backend = open_volume(base.path(), false);
    let copied = Arc::new(AtomicI64::new(0));
    let reports = Arc::new(AtomicI64::new(0));
    let (sum, count) = (Arc::clone(&copied), Arc::clone(&reports));
    let options = MultipartCopyOptions {
        progress: Some(Arc::new(move |bytes| {
            sum.fetch_add(bytes, Ordering::SeqCst);
            count.fetch_add(1, Ordering::SeqCst);
        })),
        ..MultipartCopyOptions::default()
    };
    backend
        .multipart_copier()
        .expect("a copier")
        .copy_multipart(&ctx(), "big.bin", "copy/big.bin", options)
        .await
        .expect("a large copy");
    assert_eq!(copied.load(Ordering::SeqCst), content.len() as i64);
    assert_eq!(
        reports.load(Ordering::SeqCst),
        2,
        "one report for each 8 MiB, and the last bytes"
    );
    assert_eq!(read_volume_file(base.path(), "copy/big.bin"), content);
    let before = fs::metadata(base.path().join("copy/big.bin")).expect("the copy");
    backend
        .mover()
        .expect("a mover")
        .move_object(&ctx(), "copy/big.bin", "moved.bin")
        .await
        .expect("a move of a large file");
    let after = fs::metadata(base.path().join("moved.bin")).expect("the moved file");
    assert_eq!(before.ino(), after.ino());
}

#[tokio::test]
async fn a_copy_in_parts_refuses_the_options_that_a_volume_cannot_keep() {
    let base = TestDir::new();
    write_volume_file(base.path(), "f.txt", "f");
    let backend = open_volume(base.path(), false);
    let copier = backend.multipart_copier().expect("a copier");
    let tags = MultipartCopyOptions {
        tags: Some("a=b".to_owned()),
        ..MultipartCopyOptions::default()
    };
    let version = MultipartCopyOptions {
        source_version: "v1".to_owned(),
        ..MultipartCopyOptions::default()
    };
    let etag = MultipartCopyOptions {
        expected_etag: "\"x\"".to_owned(),
        ..MultipartCopyOptions::default()
    };
    let metadata = MultipartCopyOptions {
        metadata: Some(http::HeaderMap::new()),
        ..MultipartCopyOptions::default()
    };
    for options in [tags, version, etag, metadata] {
        let refused = copier.copy_multipart(&ctx(), "f.txt", "g.txt", options).await;
        assert_eq!(code_of(refused), (501, "volume_unsupported".to_owned()));
    }
    assert!(!base.path().join("g.txt").exists());
}

#[tokio::test]
async fn a_resumable_upload_writes_a_temporary_file() {
    let base = TestDir::new();
    let root = base.path();
    let backend = open_volume(root, false);
    let content = "upload-".repeat((9 << 20) / 7 + 11);
    let total = content.len() as i64;
    let session = backend
        .initiate_resumable(&ctx(), "up/big.bin", total, "")
        .await
        .expect("a session");
    let found = temporary_files(root);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].parent(), Some(root.join("up").as_path()));
    assert!(found[0].to_string_lossy().ends_with("-big.bin"), "{found:?}");
    let name = found[0].file_name().expect("a name").to_string_lossy().into_owned();
    assert_eq!(super::uploads::session_upload_id(&session), name);
    let lister = backend.multipart_lister().expect("a lister");
    let listed = lister
        .list_uploads(&ctx(), &MultipartCursor::default(), 0)
        .await
        .expect("a list");
    assert_eq!(listed.uploads.len(), 1);
    assert_eq!(
        (listed.uploads[0].key.as_str(), listed.uploads[0].upload_id.as_str()),
        ("up/big.bin", name.as_str())
    );
    assert!(listed.next.is_none());
    let chunk = 8 << 20;
    let bytes = content.as_bytes();
    let first = backend
        .upload_chunk(
            &ctx(),
            &session,
            super::tests::body_of(&content[..chunk]),
            0,
            chunk as i64,
            total,
            "",
        )
        .await
        .expect("the first chunk");
    assert_eq!(first, (chunk as i64, false));
    // The client asks where to resume: the size of the temporary file.
    let asked = backend.query_resumable(&ctx(), &session, total).await.expect("a query");
    assert_eq!(asked, (chunk as i64, false));
    let gap = backend
        .upload_chunk(&ctx(), &session, body_of("x"), chunk as i64 + 5, 1, total, "")
        .await;
    assert_eq!(code_of(gap), (409, "offset_mismatch".to_owned()));
    let rest = &bytes[chunk..];
    let done = backend
        .upload_chunk(
            &ctx(),
            &session,
            super::tests::body_of(&content[chunk..]),
            chunk as i64,
            rest.len() as i64,
            total,
            "",
        )
        .await
        .expect("the last chunk");
    assert_eq!(done, (total, true));
    assert_eq!(read_volume_file(root, "up/big.bin"), content);
    assert!(temporary_files(root).is_empty(), "temporary files stay");
    // The temporary file is gone and the target has the size of the upload: the upload is complete.
    assert_eq!(
        backend.query_resumable(&ctx(), &session, total).await.expect("a query"),
        (total, true)
    );
    let other = backend.query_resumable(&ctx(), &session, total + 1).await;
    assert_eq!(code_of(other), (404, "nosuchupload".to_owned()));
    // A cancel removes the temporary file.
    let second = backend
        .initiate_resumable(&ctx(), "up/other.bin", total, "")
        .await
        .expect("a session");
    assert_eq!(temporary_files(root).len(), 1);
    backend.abort_resumable(&ctx(), &second).await.expect("an abort");
    assert!(temporary_files(root).is_empty(), "the cancel left temporary files");
    backend
        .abort_resumable(&ctx(), &second)
        .await
        .expect("an abort of a file that is gone");
}

#[tokio::test]
async fn a_chunk_that_a_lost_connection_cut_is_cut_back_and_sent_again() {
    let base = TestDir::new();
    let backend = open_volume(base.path(), false);
    let session = backend
        .initiate_resumable(&ctx(), "p/part.bin", 100, "")
        .await
        .expect("a session");
    let first = "a".repeat(60);
    // The connection breaks after 40 bytes of a chunk of 60.
    let cut = put_chunk(&backend, &session, &first[..40], 0, 60, 100).await;
    assert_eq!(code_of(cut), (400, "incomplete_body".to_owned()));
    assert_eq!(
        backend.query_resumable(&ctx(), &session, 100).await.expect("a query"),
        (40, false)
    );
    let second = "b".repeat(60);
    let done = put_chunk(&backend, &session, &second, 40, 60, 100)
        .await
        .expect("the rest");
    assert_eq!(done, (100, true));
    assert_eq!(
        read_volume_file(base.path(), "p/part.bin"),
        format!("{}{second}", &first[..40])
    );
    // A chunk that starts before the end of the file cuts the file back.
    let session = backend
        .initiate_resumable(&ctx(), "p/again.bin", 20, "")
        .await
        .expect("a session");
    assert_eq!(
        put_chunk(&backend, &session, "0123456789", 0, 10, 20)
            .await
            .expect("a chunk"),
        (10, false)
    );
    assert_eq!(
        put_chunk(&backend, &session, "abcdefghij", 5, 10, 20)
            .await
            .expect("a chunk"),
        (15, false)
    );
    assert_eq!(
        put_chunk(&backend, &session, "ABCDE", 15, 5, 20)
            .await
            .expect("a chunk"),
        (20, true)
    );
    assert_eq!(read_volume_file(base.path(), "p/again.bin"), "01234abcdefghijABCDE");
    let bad = put_chunk(&backend, &session, "x", 0, 0, 20).await;
    assert_eq!(bad.expect_err("an invalid range").status(), 502);
}

async fn put_chunk(
    backend: &VolumeBackend,
    session: &str,
    text: &str,
    start: i64,
    size: i64,
    total: i64,
) -> Result<(i64, bool)> {
    backend
        .upload_chunk(&ctx(), session, body_of(text), start, size, total, "")
        .await
}

#[tokio::test]
async fn a_session_that_is_not_one_of_this_volume_is_refused() {
    let base = TestDir::new();
    write_volume_file(base.path(), "f.txt", "f");
    let backend = open_volume(base.path(), false);
    let name = ".stowr-tmp-0123456789abcdef0123456789abcdef";
    let cases = [
        String::new(),
        "no-separator".to_owned(),
        "\0f.txt".to_owned(),
        format!("/etc/{name}\0f.txt"),
        "f.txt\0f.txt".to_owned(),
        format!("../{name}\0f.txt"),
    ];
    for session in cases {
        let got = backend.query_resumable(&ctx(), &session, 1).await;
        assert_eq!(code_of(got), (400, "invalid_resume_token".to_owned()), "{session:?}");
        assert_eq!(
            status_of(backend.abort_resumable(&ctx(), &session).await),
            400,
            "{session:?}"
        );
    }
}

fn set_age(path: &Path, age: Duration) {
    let time = SystemTime::now() - age;
    let file = fs::OpenOptions::new().write(true).open(path).expect("open the file");
    file.set_modified(time).expect("set the time");
}

#[tokio::test]
async fn the_incomplete_uploads_are_the_temporary_files_with_their_date_and_size() {
    let base = TestDir::new();
    let root = base.path();
    let hour = Duration::from_secs(3600);
    let files = [
        ("logs/.stowr-tmp-00000000000000000000000000000001-old.log", 72 * hour),
        ("logs/.stowr-tmp-00000000000000000000000000000002-new.log", hour),
        ("logs/.stowr-tmp-00000000000000000000000000000003", 48 * hour),
        ("other/.stowr-tmp-00000000000000000000000000000004-x.bin", 72 * hour),
    ];
    for (relative, age) in files {
        write_volume_file(root, relative, "part");
        set_age(&root.join(relative), age);
    }
    write_volume_file(root, "logs/kept.log", "kept");
    let backend = open_volume(root, false);
    let lister = backend.multipart_lister().expect("a lister");
    let mut all = Vec::new();
    let mut cursor = MultipartCursor::default();
    for pages in 0.. {
        assert!(pages <= 50, "the list does not end");
        let page = lister.list_uploads(&ctx(), &cursor, 1).await.expect("a page");
        all.extend(page.uploads);
        match page.next {
            Some(next) => cursor = next,
            None => break,
        }
    }
    let mut names: Vec<String> = all
        .iter()
        .map(|upload| format!("{}#{}", upload.key, upload.upload_id))
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "logs/.stowr-tmp-00000000000000000000000000000003#.stowr-tmp-00000000000000000000000000000003",
            "logs/new.log#.stowr-tmp-00000000000000000000000000000002-new.log",
            "logs/old.log#.stowr-tmp-00000000000000000000000000000001-old.log",
            "other/x.bin#.stowr-tmp-00000000000000000000000000000004-x.bin",
        ]
    );
    for upload in &all {
        let initiated = upload.initiated.expect("a date");
        assert!(initiated.secs > 0);
        let parts = lister
            .upload_parts(&ctx(), &upload.key, &upload.upload_id, 1000)
            .await
            .expect("the parts");
        assert_eq!((parts.parts, parts.bytes), (1, 4), "{upload:?}");
    }
    let old = all
        .iter()
        .find(|upload| upload.key == "logs/old.log")
        .expect("the old upload");
    let new = all
        .iter()
        .find(|upload| upload.key == "logs/new.log")
        .expect("the new upload");
    let age = |upload: &crate::uploads::MultipartUpload| {
        crate::common::time::Timestamp::now().secs - upload.initiated.map_or(0, |time| time.secs)
    };
    assert!(
        age(old) > 71 * 3600 && age(new) < 2 * 3600,
        "the date is the last write"
    );
    // The abort of one listed upload works at any age. An id that is not a temporary name is refused.
    let remover = backend.incomplete_upload_remover().expect("a remover");
    remover
        .remove_incomplete_upload(
            &ctx(),
            "logs/new.log",
            ".stowr-tmp-00000000000000000000000000000002-new.log",
        )
        .await
        .expect("an abort");
    assert!(
        !root
            .join("logs/.stowr-tmp-00000000000000000000000000000002-new.log")
            .exists()
    );
    remover
        .remove_incomplete_upload(
            &ctx(),
            "logs/new.log",
            ".stowr-tmp-00000000000000000000000000000002-new.log",
        )
        .await
        .expect("an abort of a file that is gone");
    let refused = remover
        .remove_incomplete_upload(&ctx(), "logs/kept.log", "kept.log")
        .await;
    assert_eq!(code_of(refused), (400, "invalid_multipart_request".to_owned()));
    let nested = remover
        .remove_incomplete_upload(&ctx(), "logs/kept.log", "../kept.log")
        .await;
    assert_eq!(code_of(nested), (400, "invalid_multipart_request".to_owned()));
    let no_folder = remover
        .remove_incomplete_upload(&ctx(), "nowhere/x.bin", ".stowr-tmp-00000000000000000000000000000009")
        .await;
    assert_eq!(code_of(no_folder), (404, "nosuchupload".to_owned()));
    assert_eq!(
        read_volume_file(root, "logs/kept.log"),
        "kept",
        "an abort removed a file that is not a temporary file"
    );
    let gone = lister
        .upload_parts(
            &ctx(),
            "logs/new.log",
            ".stowr-tmp-00000000000000000000000000000002-new.log",
            10,
        )
        .await;
    assert_eq!(code_of(gone), (404, "nosuchupload".to_owned()));
}
