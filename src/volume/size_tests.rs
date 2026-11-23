// SPDX-License-Identifier: MIT OR Apache-2.0
//! The tests of the count of the size of a volume and of its usage.

use std::fs;
use std::os::unix::fs::symlink;
use std::sync::Arc;

use super::size::{SIZE_TIME, SizeState, VolumeSizer};
use super::statfs::FileSystemSize;
use super::tests::{TestDir, body_of, ctx, open_volume, write_volume_file};
use super::usage::DELAYED_REASON;
use crate::common::storage::Backend;

#[test]
fn the_sizer_counts_the_files_in_the_background() {
    let base = TestDir::new();
    let root = base.path().join("volume");
    write_volume_file(base.path(), "outside/big.bin", &"x".repeat(5000));
    write_volume_file(&root, "a.txt", "12345");
    write_volume_file(&root, "deep/b.txt", "1234567890");
    write_volume_file(&root, "deep/.hidden", "123");
    write_volume_file(
        &root,
        "deep/.stowr-tmp-0123456789abcdef0123456789abcdef-part.bin",
        &"t".repeat(1000),
    );
    symlink(base.path().join("outside"), root.join("escape")).expect("make a link");
    symlink("a.txt", root.join("again")).expect("make a link");
    let sizer = VolumeSizer::new(root.clone());
    let walks = sizer.walks();
    let first = sizer.snapshot();
    assert_eq!(first.state, SizeState::Computing, "the first read = {first:?}");
    sizer.wait_after(walks);
    let count = sizer.snapshot();
    // The links are not followed, and the temporary file of an upload is not counted.
    assert_eq!(
        (count.state, count.bytes, count.files),
        (SizeState::Ready, 18, 3),
        "count = {count:?}"
    );
    assert!(count.at.is_some());
    // The count stays: no new walk without a change.
    assert_eq!(sizer.snapshot().state, SizeState::Ready);
    assert_eq!(sizer.walks(), walks + 1);
    // A write makes the count old: the next read starts a new walk.
    write_volume_file(&root, "c.txt", "1234567");
    let walks = sizer.walks();
    sizer.invalidate();
    assert_eq!(sizer.snapshot().state, SizeState::Computing);
    sizer.wait_after(walks);
    let count = sizer.snapshot();
    assert_eq!((count.bytes, count.files), (25, 4), "count after a change = {count:?}");
    // A walk that reaches its budget gives "partial": at least the count.
    let small = VolumeSizer::with_limits(root, 3, SIZE_TIME);
    small.snapshot();
    small.wait_after(0);
    let count = small.snapshot();
    assert_eq!(count.state, SizeState::Partial, "count with a budget = {count:?}");
    assert!(count.files < 4);
}

#[test]
fn a_walk_that_takes_too_long_gives_a_partial_count() {
    let base = TestDir::new();
    write_volume_file(base.path(), "a.txt", "1");
    let sizer = VolumeSizer::with_limits(base.path().to_path_buf(), 1_000_000, std::time::Duration::ZERO);
    sizer.snapshot();
    sizer.wait_after(0);
    assert_eq!(sizer.snapshot().state, SizeState::Partial);
}

#[tokio::test]
async fn the_usage_gives_the_folder_and_its_file_system() {
    let base = TestDir::new();
    write_volume_file(base.path(), "report.txt", &"r".repeat(1200));
    let backend = open_volume(base.path(), false);
    let reader = backend.usage_reader().with_statfs(Arc::new(|_| {
        Ok(FileSystemSize {
            total: 1000,
            available: 90,
            delayed: true,
        })
    }));
    let walks = backend.sizer().walks();
    backend.sizer().snapshot();
    backend.sizer().wait_after(walks);
    let usage = reader.volume_usage();
    assert_eq!(
        (usage.used_bytes, usage.used_objects, usage.state),
        (1200, 1, SizeState::Ready),
        "usage = {usage:?}"
    );
    let capacity = reader.capacity().expect("a capacity");
    assert_eq!(
        (capacity.total_bytes, capacity.used_bytes, capacity.free_bytes),
        (1000, 910, 90)
    );
    assert!(capacity.approximate);
    assert_eq!(capacity.approximate_reason, DELAYED_REASON);
    // An upload makes the count of the folder old.
    let walks = backend.sizer().walks();
    backend
        .put(&ctx(), "more.txt", body_of("12345"), 5, "")
        .await
        .expect("a write");
    assert_eq!(
        reader.volume_usage().state,
        SizeState::Computing,
        "the count after a write"
    );
    backend.sizer().wait_after(walks);
    assert_eq!(reader.volume_usage().used_bytes, 1205);
    assert!(fs::metadata(base.path().join("more.txt")).is_ok());
}
