//! The tests of the symbolic links of a volume. The tree is the one of `tests::volume_tree`: `link-in` is a link to
//! a folder in the root, `link-file` a link to a file in the root, `link-out` a link to a folder outside the root,
//! and `link-dangling` a link that does not resolve.

use std::fs;

use super::VolumeBackend;
use super::tests::{body_of, ctx, list, open_volume, page_keys, put_text, read_volume_file, volume_tree};
use crate::common::error::{Error, Result};
use crate::common::storage::{Backend, ListOptions, ResumableApi};
use http::HeaderMap;

fn is_link_refused<T>(result: &Result<T>) -> bool {
    matches!(result, Err(error) if error.has_code("volume_link_refused"))
}

fn describe<T: std::fmt::Debug>(result: &Result<T>) -> String {
    match result {
        Ok(value) => format!("{value:?}"),
        Err(error) => format!("{error}"),
    }
}

fn delimited(prefix: &str) -> ListOptions {
    ListOptions {
        prefix: prefix.to_owned(),
        delimiter: "/".to_owned(),
        ..ListOptions::default()
    }
}

#[tokio::test]
async fn refuse_links_refuses_each_link_for_a_read() {
    let (_base, root) = volume_tree();
    let backend = open_volume(&root, true);
    for key in [
        "link-file",
        "link-in",
        "link-in/b.txt",
        "link-out",
        "link-out/secret.txt",
        "link-dangling",
    ] {
        let got = backend.get(&ctx(), key, &HeaderMap::new()).await;
        assert!(is_link_refused(&got), "get {key:?}: {}", describe(&got));
        let head = backend.head(&ctx(), key).await;
        assert!(is_link_refused(&head), "head {key:?}: {}", describe(&head));
    }
    // A file that is not a link, in a folder that is not a link, stays readable.
    backend
        .get(&ctx(), "a/b.txt", &HeaderMap::new())
        .await
        .expect("a file that is not a link");
}

#[tokio::test]
async fn refuse_links_refuses_each_link_for_a_write_a_delete_a_move_and_a_copy() {
    let (base, root) = volume_tree();
    let backend: VolumeBackend = open_volume(&root, true);
    let writer = backend.conditional_writer().expect("a conditional writer");
    for key in [
        "link-file",
        "link-in/new.txt",
        "link-in/b.txt",
        "link-out/new.txt",
        "link-out/secret.txt",
        "link-dangling",
    ] {
        let put = put_text(&backend, key, "changed").await;
        assert!(is_link_refused(&put), "put {key:?}: {}", describe(&put));
        let absent = writer.put_if_absent(&ctx(), key, body_of("changed"), 7, "").await;
        assert!(is_link_refused(&absent), "put if absent {key:?}: {}", describe(&absent));
    }
    assert_eq!(read_volume_file(&root, "a0"), "zero");
    assert_eq!(read_volume_file(&root, "a/b.txt"), "0123456789");
    assert!(
        !root.join("a").join("new.txt").exists(),
        "a write went through a link to a folder in the root"
    );
    assert!(
        !base.path().join("outside").join("new.txt").exists(),
        "a write went through a link that leaves the root"
    );
    for key in ["link-file", "link-in/b.txt", "link-out/secret.txt"] {
        let deleted = backend.delete(&ctx(), key).await;
        assert!(is_link_refused(&deleted), "delete {key:?}: {}", describe(&deleted));
    }
    for link in ["link-in", "link-file", "link-out"] {
        assert!(
            fs::symlink_metadata(root.join(link)).is_ok(),
            "the delete removed the link {link:?}"
        );
    }
    assert_eq!(read_volume_file(&root, "a/b.txt"), "0123456789");
    assert_eq!(read_volume_file(base.path(), "outside/secret.txt"), "secret");
    let mover = backend.mover().expect("a mover");
    let pairs = [
        ("link-file", "moved"),
        ("link-in/b.txt", "moved"),
        ("a0", "link-file"),
        ("a0", "link-in/moved"),
        ("a0", "link-out/moved"),
        ("link-out/secret.txt", "moved"),
    ];
    for (from, to) in pairs {
        let moved = mover.move_object(&ctx(), from, to).await;
        assert!(is_link_refused(&moved), "move {from:?} to {to:?}: {}", describe(&moved));
        let copied = backend.copy(&ctx(), from, to).await;
        assert!(
            is_link_refused(&copied),
            "copy {from:?} to {to:?}: {}",
            describe(&copied)
        );
    }
    assert!(
        fs::symlink_metadata(root.join("moved")).is_err(),
        "a move or a copy made a file from a link"
    );
    assert_eq!(read_volume_file(&root, "a0"), "zero");
    let started = backend.initiate_resumable(&ctx(), "link-out/upload.bin", 1, "").await;
    assert!(
        is_link_refused(&started),
        "start of an upload through a link: {}",
        describe(&started)
    );
    let remover = backend.folder_remover().expect("a folder remover");
    let removed = remover.remove_empty_folders(&ctx(), "link-in/").await;
    assert!(
        removed.is_ok() || is_link_refused(&removed),
        "remove empty folders: {}",
        describe(&removed)
    );
    assert!(
        root.join("a").join("b.txt").exists(),
        "the removal of empty folders went through a link"
    );
}

#[tokio::test]
async fn refuse_links_shows_links_as_unreadable_and_the_walks_leave_them_out() {
    let (_base, root) = volume_tree();
    let backend = open_volume(&root, true);
    let page = list(&backend, delimited("")).await.expect("a listing");
    for name in ["link-in", "link-file", "link-out", "link-dangling"] {
        let object = page.objects.iter().find(|object| object.key == name);
        assert!(
            object.is_some_and(|object| object.unreadable),
            "{name:?} is not shown as unreadable"
        );
    }
    for prefix in &page.prefixes {
        assert!(
            !prefix.starts_with("link-"),
            "the listing shows the link {prefix:?} as a folder"
        );
    }
    for name in ["a0", ".hidden"] {
        let object = page
            .objects
            .iter()
            .find(|object| object.key == name)
            .expect("an object");
        assert!(!object.unreadable, "{name:?} is unreadable");
    }
    assert!(page.prefixes.iter().any(|prefix| prefix == "a/"), "{:?}", page.prefixes);
    let tree = list(&backend, ListOptions::default()).await.expect("the tree");
    let keys = page_keys(&tree);
    for key in &keys {
        assert!(!key.starts_with("link-"), "the walk gives the link {key:?}");
    }
    assert!(keys.iter().any(|key| key == "a/b.txt"), "the walk keys = {keys:?}");
    let through = list(&backend, delimited("link-in/")).await;
    assert!(
        is_link_refused(&through),
        "a listing through a link: {}",
        describe(&through)
    );
}

#[tokio::test]
async fn a_volume_without_refuse_links_follows_a_link_inside_the_root() {
    let (_base, root) = volume_tree();
    let backend = open_volume(&root, false);
    backend
        .get(&ctx(), "link-file", &HeaderMap::new())
        .await
        .expect("a link to a file in the root");
    backend
        .head(&ctx(), "link-in/b.txt")
        .await
        .expect("a HEAD through a link to a folder in the root");
    put_text(&backend, "link-in/new.txt", "new")
        .await
        .expect("a write through a link to a folder in the root");
    assert_eq!(
        read_volume_file(&root, "a/new.txt"),
        "new",
        "the write did not reach the target of the link"
    );
    let outside = backend.head(&ctx(), "link-out/secret.txt").await;
    assert!(
        is_link_refused(&outside),
        "a HEAD through a link that leaves the root: {}",
        describe(&outside)
    );
    let page = list(&backend, delimited("")).await.expect("a listing");
    assert!(
        page.prefixes.iter().any(|prefix| prefix == "link-in/"),
        "{:?}",
        page.prefixes
    );
}

#[test]
fn the_error_of_a_link_has_the_status_and_the_code_of_the_api() {
    let error: Error = super::path::link_refused();
    assert_eq!((error.status(), error.code().as_str()), (403, "volume_link_refused"));
}
