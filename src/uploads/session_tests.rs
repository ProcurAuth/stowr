// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tests of the size of a chunk, of `Content-Range`, of the body limit and of the form that the client sees.

use bytes::Bytes;

use super::limit::limit_body;
use super::session::{PublicUpload, UploadSession, parse_content_range, upload_chunk_size};
use super::volume_session_upload_id;
use crate::common::http::{channel, full, read_limited};
use crate::common::json;
use crate::common::time::Timestamp;

#[test]
fn the_chunk_of_an_s3_upload_is_16_mib_and_grows_with_the_part_limit() {
    assert_eq!(upload_chunk_size("s3", 0), Ok(16 << 20));
    assert_eq!(upload_chunk_size("s3", 1), Ok(16 << 20));
    assert_eq!(upload_chunk_size("s3", (16 << 20) * 10_000), Ok(16 << 20));
    assert_eq!(upload_chunk_size("s3", (16 << 20) * 10_000 + 1), Ok(17 << 20));
    // 5 TiB: the chunk is the size of the object divided by 10000, rounded up to a whole MiB.
    assert_eq!(upload_chunk_size("s3", 5 << 40), Ok(525 << 20));
}

#[test]
fn the_chunk_of_another_provider_is_8_mib_and_the_size_is_bounded() {
    assert_eq!(upload_chunk_size("gcs", 1), Ok(8 << 20));
    assert_eq!(upload_chunk_size("fs", 5 << 40), Ok(8 << 20));
    for provider in ["s3", "gcs", "fs"] {
        for total in [-1, (5_i64 << 40) + 1] {
            assert_eq!(
                upload_chunk_size(provider, total),
                Err("object size must be between 0 and 5497558138880 bytes".to_owned()),
                "{provider} {total}"
            );
        }
    }
}

#[test]
fn content_range_has_the_form_bytes_start_end_total() {
    assert_eq!(parse_content_range("bytes 0-9/10"), Ok((0, 9, 10)));
    assert_eq!(parse_content_range("  bytes 5-5/6 "), Ok((5, 5, 6)));
    assert_eq!(parse_content_range("bytes +1-2/3"), Ok((1, 2, 3)));
    let form = "Content-Range must use bytes start-end/total";
    for bad in [
        "",
        "0-9/10",
        "bytes",
        "bytes 0-9",
        "bytes 09",
        "items 0-9/10",
        "bytes  0-9/10",
    ] {
        let message = parse_content_range(bad).unwrap_err();
        assert!(
            message == form || message == "invalid Content-Range start",
            "{bad:?}: {message}"
        );
    }
    assert_eq!(parse_content_range("bytes -1-5/10"), Err("invalid Content-Range start"));
    assert_eq!(parse_content_range("bytes x-5/10"), Err("invalid Content-Range start"));
    assert_eq!(parse_content_range("bytes 1-y/10"), Err("invalid Content-Range end"));
    assert_eq!(parse_content_range("bytes 1-2/z"), Err("invalid Content-Range total"));
    assert_eq!(
        parse_content_range("bytes 5-2/10"),
        Err("Content-Range is outside the object size")
    );
    assert_eq!(
        parse_content_range("bytes 0-10/10"),
        Err("Content-Range is outside the object size")
    );
}

#[tokio::test]
async fn a_limited_body_ends_after_the_bytes_that_it_may_carry() {
    let read = |body| async move { read_limited(body, usize::MAX).await.unwrap().0 };
    assert_eq!(&read(limit_body(full("abcdefghi"), 5)).await[..], b"abcde");
    assert_eq!(&read(limit_body(full("abc"), 5)).await[..], b"abc");
    assert_eq!(&read(limit_body(full("abc"), 0)).await[..], b"");
    assert_eq!(&read(limit_body(full("abc"), -4)).await[..], b"");
    let (sender, body) = channel(4);
    tokio::spawn(async move {
        for part in ["abc", "defg", "hi"] {
            let _ = sender.send(Bytes::from(part)).await;
        }
    });
    assert_eq!(&read(limit_body(body, 5)).await[..], b"abcde");
}

#[test]
fn the_name_of_the_temporary_file_of_a_volume_session_is_the_upload_id() {
    assert_eq!(
        volume_session_upload_id("dir/sub/.stowr-tmp-ab12-name\0dir/sub/name"),
        ".stowr-tmp-ab12-name"
    );
    assert_eq!(volume_session_upload_id(".stowr-tmp-x-y\0y"), ".stowr-tmp-x-y");
    assert_eq!(volume_session_upload_id("name"), "name");
    assert_eq!(volume_session_upload_id(""), ".");
    assert_eq!(volume_session_upload_id("/"), "/");
    assert_eq!(volume_session_upload_id("dir/"), "dir");
}

fn session() -> UploadSession {
    UploadSession {
        id: "upl_1".to_owned(),
        instance: "rw".to_owned(),
        key: "k.bin".to_owned(),
        provider: "s3".to_owned(),
        status: "uploading".to_owned(),
        content_type: "text/plain".to_owned(),
        total_size: 10,
        uploaded_bytes: 4,
        chunk_size: 5,
        provider_upload_id: "secret-upload-id".to_owned(),
        session_url: "secret-session".to_owned(),
        created_at: Timestamp::parse_rfc3339("2026-11-20T10:00:00Z").unwrap(),
        updated_at: Timestamp::parse_rfc3339("2026-11-20T10:00:01.5Z").unwrap(),
        ..UploadSession::default()
    }
}

#[test]
fn the_form_for_the_client_keeps_the_provider_coordinates_hidden_and_omits_empty_members() {
    let text = String::from_utf8(json::to_vec(&session().public()).unwrap()).unwrap();
    assert_eq!(
        text,
        r#"{"id":"upl_1","instance":"rw","key":"k.bin","provider":"s3","status":"uploading","contentType":"text/plain","totalSize":10,"uploadedBytes":4,"nextOffset":4,"chunkSize":5,"createdAt":"2026-11-20T10:00:00Z","updatedAt":"2026-11-20T10:00:01.5Z"}"#
    );
    let mut full_session = session();
    full_session.parts = vec![Default::default(), Default::default()];
    full_session.error = "the provider failed".to_owned();
    full_session.completed_at = Some(full_session.updated_at);
    full_session.verified = true;
    full_session.checksum = "sha256".to_owned();
    full_session.checksum_verified = true;
    full_session.resume_token = "stowr1.x.y".to_owned();
    let text = String::from_utf8(json::to_vec(&full_session.public()).unwrap()).unwrap();
    assert_eq!(
        text,
        r#"{"id":"upl_1","instance":"rw","key":"k.bin","provider":"s3","status":"uploading","contentType":"text/plain","totalSize":10,"uploadedBytes":4,"nextOffset":4,"chunkSize":5,"partCount":2,"error":"the provider failed","createdAt":"2026-11-20T10:00:00Z","updatedAt":"2026-11-20T10:00:01.5Z","completedAt":"2026-11-20T10:00:01.5Z","verified":true,"checksum":"sha256","checksumVerified":true,"resumeToken":"stowr1.x.y"}"#
    );
    assert_eq!(PublicUpload::default().next_offset, 0);
}
