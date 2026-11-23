//! The tests of the volume back end: the keys, the listing, the reads, the root prefix, the instance and the usage.
//!
//! These tests need a real folder. Each test makes its own folder under a folder of the tests. The tests run on a
//! FUSE mount when the environment variable `STOWR_TEST_VOLUME_DIR` names a folder of the mount (the script
//! `test/volume-fuse/run.sh` does it): each test then makes its folder in a new folder of it.

use std::fs;
use std::io;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::HeaderMap;
use http::header::{HeaderName, HeaderValue};

use super::content_type::FOLDER_CONTENT_TYPE;
use super::path::{TEMPORARY_PREFIX, link_refused, parse_key, parse_temporary_name, resolve_inside, volume_error};
use super::size::{SizeState, VolumeSizer};
use super::statfs::FileSystemSize;
use super::usage::{DELAYED_REASON, SCOPE_FILESYSTEM, VolumeUsageReader};
use super::{VolumeBackend, new_volume_instance};
use crate::common::config::{RuntimePolicy, VolumeConfig};
use crate::common::ctx::OpCtx;
use crate::common::error::Result;
use crate::common::http::{Body, full, read_limited};
use crate::common::storage::{Backend, CapabilityStateName, ListOptions, ListPage, ObjectResponse};
use crate::instance::gate::Gate;

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// A new empty folder for a test. The folder goes away when the value is dropped.
pub(super) struct TestDir {
    path: PathBuf,
}

impl TestDir {
    pub(super) fn new() -> Self {
        let base = match std::env::var("STOWR_TEST_VOLUME_DIR") {
            Ok(value) if !value.is_empty() => PathBuf::from(value),
            _ => std::env::temp_dir().join("stowr-volume-tests"),
        };
        let unique = format!("t-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::SeqCst));
        let path = base.join(unique);
        fs::create_dir_all(&path).expect("make the folder of the test");
        Self {
            path: fs::canonicalize(&path).expect("resolve the folder of the test"),
        }
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// The configuration of a volume block "vol" on `root`.
pub(super) fn volume_config(root: &Path) -> VolumeConfig {
    VolumeConfig {
        id: "vol".to_owned(),
        name: "vol".to_owned(),
        path: root.to_path_buf(),
        ..VolumeConfig::default()
    }
}

/// The back end of a volume on `root`, with `refuse_links` as the argument gives it.
pub(super) fn open_volume(root: &Path, refuse_links: bool) -> VolumeBackend {
    let mut config = volume_config(root);
    config.refuse_links = refuse_links;
    VolumeBackend::open(&config, false).expect("open the volume")
}

pub(super) fn ctx() -> OpCtx {
    OpCtx::default()
}

pub(super) fn write_volume_file(root: &Path, relative: &str, content: &str) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().expect("a folder")).expect("make the folders");
    fs::write(path, content).expect("write the file");
}

pub(super) fn read_volume_file(root: &Path, relative: &str) -> String {
    fs::read_to_string(root.join(relative)).unwrap_or_else(|error| panic!("read {relative}: {error}"))
}

/// The test tree of a volume, and a folder outside it with a secret file. The first value keeps the folders; the
/// second is the root.
pub(super) fn volume_tree() -> (TestDir, PathBuf) {
    let base = TestDir::new();
    let root = base.path().join("volume");
    let outside = base.path().join("outside");
    write_volume_file(&outside, "secret.txt", "secret");
    write_volume_file(&root, "a-b/x.txt", "x");
    write_volume_file(&root, "a/b.txt", "0123456789");
    write_volume_file(&root, "a0", "zero");
    write_volume_file(&root, ".hidden", "hidden");
    write_volume_file(&root, ".stowr-tmp-0123456789abcdef0123456789abcdef-upload.bin", "part");
    fs::create_dir(root.join("empty")).expect("make a folder");
    symlink("a", root.join("link-in")).expect("make a link");
    symlink("a0", root.join("link-file")).expect("make a link");
    symlink(&outside, root.join("link-out")).expect("make a link");
    symlink("missing", root.join("link-dangling")).expect("make a link");
    (base, root)
}

pub(super) fn body_of(text: &str) -> Body {
    full(Bytes::from(text.to_owned()))
}

pub(super) async fn put_text(backend: &VolumeBackend, key: &str, text: &str) -> Result<()> {
    backend.put(&ctx(), key, body_of(text), text.len() as i64, "").await
}

pub(super) async fn body_text(body: Body) -> String {
    let (bytes, _) = read_limited(body, 1 << 30).await.expect("read the body");
    String::from_utf8_lossy(&bytes).into_owned()
}

pub(super) fn headers_of(pairs: &[(&str, &str)]) -> HeaderMap {
    let mut headers = HeaderMap::new();
    for (name, value) in pairs {
        headers.insert(
            HeaderName::from_bytes(name.as_bytes()).expect("a header name"),
            HeaderValue::from_str(value).expect("a header value"),
        );
    }
    headers
}

pub(super) fn header_value(response: &ObjectResponse, name: &str) -> String {
    response
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("")
        .to_owned()
}

pub(super) fn page_keys(page: &ListPage) -> Vec<String> {
    let mut keys: Vec<String> = page.prefixes.clone();
    keys.extend(page.objects.iter().map(|object| object.key.clone()));
    keys
}

pub(super) async fn list(backend: &VolumeBackend, options: ListOptions) -> Result<ListPage> {
    backend.list(&ctx(), &options).await
}

/// The temporary files of the server in the tree of `root`.
pub(super) fn temporary_files(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut folders = vec![root.to_path_buf()];
    while let Some(folder) = folders.pop() {
        let Ok(reader) = fs::read_dir(&folder) else {
            continue;
        };
        for entry in reader.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(TEMPORARY_PREFIX) {
                found.push(entry.path());
            }
            if entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                folders.push(entry.path());
            }
        }
    }
    found
}

pub(super) fn code_of<T: std::fmt::Debug>(result: Result<T>) -> (u16, String) {
    let error = result.expect_err("an error");
    (error.status(), error.code())
}

#[test]
fn keys_refuse_path_tricks() {
    let long = "n".repeat(256);
    for key in [
        "../etc/passwd",
        "a/../../b",
        "a//b",
        "./a",
        "a/.",
        "a/\0b",
        long.as_str(),
    ] {
        let error = parse_key(key, false).expect_err(key);
        assert!(error.to_string().contains("a "), "key {key:?}: error = {error}");
    }
    let error = parse_key("a/.stowr-tmp-x", true).expect_err("a write of a temporary name");
    assert!(error.to_string().contains("temporary files"), "{error}");
    assert!(parse_key("a/.stowr-tmp-x", false).is_ok());
    let key = parse_key("a/b/", false).expect("a folder key");
    assert!(key.folder);
    assert_eq!(key.parts, ["a", "b"]);
    assert_eq!(key.name(), "b");
    assert_eq!(key.parent(), ["a"]);
    let root = parse_key("", false).expect("the root");
    assert!(root.parts.is_empty() && !root.folder);
}

#[test]
fn temporary_names_have_a_random_part_and_a_target() {
    assert_eq!(
        parse_temporary_name(".stowr-tmp-0123456789abcdef0123456789abcdef-report.pdf"),
        Some("report.pdf")
    );
    assert_eq!(
        parse_temporary_name(".stowr-tmp-0123456789abcdef0123456789abcdef"),
        Some("")
    );
    for name in [
        ".stowr-tmp-0123",
        ".stowr-tmp-0123456789ABCDEF0123456789abcdef",
        ".stowr-tmp-0123456789abcdef0123456789abcdef-",
        "file.txt",
    ] {
        assert_eq!(parse_temporary_name(name), None, "{name:?} is not a temporary name");
    }
    let name = super::path::temporary_name("report.pdf").expect("a name");
    assert_eq!(parse_temporary_name(&name), Some("report.pdf"));
    let long = "x".repeat(250);
    let name = super::path::temporary_name(&long).expect("a name");
    assert_eq!(
        parse_temporary_name(&name),
        Some(""),
        "a target that does not fit is left out"
    );
    assert!(name.len() <= 255);
}

#[test]
fn errors_of_the_file_system_have_the_codes_of_the_api() {
    let error = |errno: i32| volume_error(&io::Error::from_raw_os_error(errno));
    assert_eq!(
        (error(libc::ENOENT).status(), error(libc::ENOENT).code()),
        (404, "nosuchkey".to_owned())
    );
    assert_eq!(error(libc::ENOTDIR).status(), 404);
    assert_eq!(error(libc::EACCES).status(), 403);
    assert_eq!(error(libc::ELOOP), link_refused());
    assert_eq!(error(libc::ENOSPC).status(), 507);
    assert_eq!(error(libc::EDQUOT).code(), "volume_full");
    assert_eq!(error(libc::EROFS).code(), "volume_read_only");
    assert_eq!(error(libc::ENOTEMPTY).code(), "volume_folder_not_empty");
    assert_eq!(error(libc::EISDIR).code(), "volume_folder_exists");
    assert_eq!(error(libc::ENAMETOOLONG).code(), "invalid_key");
    let other = error(libc::EIO);
    assert_eq!((other.status(), other.code()), (502, "volume_error".to_owned()));
    assert!(
        other.public_message().ends_with("input/output error"),
        "{}",
        other.public_message()
    );
}

#[test]
fn resolve_inside_follows_a_link_that_stays_in_the_root() {
    let (_base, root) = volume_tree();
    let real = fs::canonicalize(&root).expect("the root");
    assert_eq!(resolve_inside(&real, "a").expect("a folder"), real.join("a"));
    assert_eq!(resolve_inside(&real, "link-in").expect("a link"), real.join("a"));
    assert_eq!(
        resolve_inside(&real, "link-in/b.txt").expect("a file"),
        real.join("a").join("b.txt")
    );
    assert_eq!(resolve_inside(&real, "link-out"), Err(link_refused()));
    assert_eq!(resolve_inside(&real, "link-dangling"), Err(link_refused()));
    let missing = resolve_inside(&real, "missing").expect_err("a path that does not exist");
    assert!(
        missing.to_string().ends_with(": no such file or directory"),
        "{missing}"
    );
    for relative in ["a//b", "./a", "a/../b", ""] {
        let error = resolve_inside(&real, relative).expect_err(relative);
        assert_eq!(
            error.to_string(),
            "the path must not have an empty, \".\" or \"..\" part"
        );
    }
}

#[tokio::test]
async fn listing_with_the_delimiter_reads_one_folder_in_the_order_of_s3() {
    let (_base, root) = volume_tree();
    let backend = open_volume(&root, false);
    let page = list(
        &backend,
        ListOptions {
            delimiter: "/".to_owned(),
            ..ListOptions::default()
        },
    )
    .await
    .expect("a listing");
    assert_eq!(page.prefixes, ["a-b/", "a/", "empty/", "link-in/"]);
    let objects: std::collections::BTreeMap<_, _> = page
        .objects
        .iter()
        .map(|object| (object.key.clone(), object.clone()))
        .collect();
    assert_eq!(objects.len(), 5, "{:?}", page.objects);
    assert_eq!(objects[".hidden"].size, 6);
    assert_eq!(objects["a0"].size, 4);
    assert_eq!(objects["link-file"].size, 4);
    assert!(objects["link-out"].unreadable);
    assert!(objects["link-dangling"].unreadable);
    assert!(!objects["a0"].unreadable);
    assert!(
        objects["a0"].etag.starts_with("W/\"4-"),
        "ETag = {}",
        objects["a0"].etag
    );
    // Three keys for each page: the token is the last key, and the pages give each key one time in the order of S3.
    let mut all = Vec::new();
    let mut token = String::new();
    for pages in 0.. {
        let page = list(
            &backend,
            ListOptions {
                delimiter: "/".to_owned(),
                max_results: 3,
                page_token: token.clone(),
                ..ListOptions::default()
            },
        )
        .await
        .expect("a page");
        let keys = page_keys(&page);
        assert!(pages <= 5 && keys.len() <= 3, "page {pages} = {keys:?}");
        all.extend(keys.clone());
        token = page.next_page_token.clone();
        if token.is_empty() {
            break;
        }
        assert!(
            Some(&token) == keys.last() || Some(&token) == page.prefixes.last(),
            "token = {token:?}, page = {keys:?}"
        );
    }
    all.sort();
    let want = [
        ".hidden",
        "a-b/",
        "a/",
        "a0",
        "empty/",
        "link-dangling",
        "link-file",
        "link-in/",
        "link-out",
    ];
    assert_eq!(all, want);
    // A symbolic link to a folder in the root is followed.
    let page = list(
        &backend,
        ListOptions {
            prefix: "link-in/".to_owned(),
            delimiter: "/".to_owned(),
            ..ListOptions::default()
        },
    )
    .await
    .expect("the listing of a link");
    assert_eq!(page.objects.len(), 1);
    assert_eq!(page.objects[0].key, "link-in/b.txt");
    // A prefix that does not exist gives an empty page; a link that leaves the root is refused.
    let missing = list(
        &backend,
        ListOptions {
            prefix: "missing/".to_owned(),
            delimiter: "/".to_owned(),
            ..ListOptions::default()
        },
    )
    .await
    .expect("an empty page");
    assert!(page_keys(&missing).is_empty());
    let refused = list(
        &backend,
        ListOptions {
            prefix: "link-out/".to_owned(),
            delimiter: "/".to_owned(),
            ..ListOptions::default()
        },
    )
    .await
    .expect_err("a link that leaves the root");
    assert!(refused.to_string().contains("leaves the volume"), "{refused}");
    let delimiter = list(
        &backend,
        ListOptions {
            delimiter: "|".to_owned(),
            ..ListOptions::default()
        },
    )
    .await;
    assert_eq!(code_of(delimiter), (400, "invalid_delimiter".to_owned()));
}

#[tokio::test]
async fn listing_without_the_delimiter_reads_the_tree_in_the_order_of_s3() {
    let (_base, root) = volume_tree();
    write_volume_file(&root, "a/deep/c.txt", "c");
    fs::create_dir_all(root.join("a").join("deep").join("void")).expect("make the folders");
    let backend = open_volume(&root, false);
    let want = [
        ".hidden",
        "a-b/x.txt",
        "a/b.txt",
        "a/deep/c.txt",
        "a/deep/void/",
        "a0",
        "empty/",
        "link-file",
    ];
    let page = list(&backend, ListOptions::default()).await.expect("the tree");
    assert_eq!(page_keys(&page), want);
    assert_eq!(page.next_page_token, "");
    for object in &page.objects {
        if object.key == "empty/" {
            assert_eq!(object.size, 0);
            assert_eq!(object.content_type, FOLDER_CONTENT_TYPE);
        }
    }
    let mut all = Vec::new();
    let mut token = String::new();
    for _ in 0..10 {
        let page = list(
            &backend,
            ListOptions {
                max_results: 3,
                page_token: token.clone(),
                ..ListOptions::default()
            },
        )
        .await
        .expect("a page");
        all.extend(page_keys(&page));
        token = page.next_page_token;
        if token.is_empty() {
            break;
        }
    }
    assert_eq!(all, want);
    let prefixes: [(&str, &[&str]); 5] = [
        ("a", &["a-b/x.txt", "a/b.txt", "a/deep/c.txt", "a/deep/void/", "a0"]),
        ("a/", &["a/b.txt", "a/deep/c.txt", "a/deep/void/"]),
        ("empty/", &["empty/"]),
        ("a/deep/v", &["a/deep/void/"]),
        ("missing/", &[]),
    ];
    for (prefix, keys) in prefixes {
        let page = list(
            &backend,
            ListOptions {
                prefix: prefix.to_owned(),
                ..ListOptions::default()
            },
        )
        .await
        .expect("a listing");
        assert_eq!(page_keys(&page), keys, "prefix {prefix:?}");
    }
    let page = list(
        &backend,
        ListOptions {
            start_after: "a/b.txt".to_owned(),
            ..ListOptions::default()
        },
    )
    .await
    .expect("a listing");
    assert_eq!(page_keys(&page), &want[3..]);
}

#[tokio::test]
async fn listing_shows_folders_hidden_files_and_unreadable_links_but_no_temporary_file() {
    let (_base, root) = volume_tree();
    let backend = open_volume(&root, false);
    let page = list(
        &backend,
        ListOptions {
            delimiter: "/".to_owned(),
            ..ListOptions::default()
        },
    )
    .await
    .expect("a listing");
    let keys = page_keys(&page);
    for name in [
        "a/",
        "a-b/",
        "empty/",
        "link-in/",
        ".hidden",
        "a0",
        "link-file",
        "link-out",
    ] {
        assert!(
            keys.iter().any(|key| key == name),
            "the listing has no {name:?}: {keys:?}"
        );
    }
    let find = |name: &str| {
        page.objects
            .iter()
            .find(|object| object.key == name)
            .expect("an object")
    };
    assert!(find("link-out").unreadable);
    assert!(!find("a0").unreadable);
    assert!(!find("a0").content_type.is_empty());
    assert!(find("a0").last_modified.is_some());
    for key in &keys {
        assert!(
            !key.starts_with(TEMPORARY_PREFIX),
            "the listing shows the temporary file {key:?}"
        );
    }
}

/// A case of a read: the request headers, the status, the body and the `Content-Range` that the read gives.
type ReadCase<'a> = (Vec<(&'a str, &'a str)>, u16, &'a str, &'a str);

/// Read a key with request headers: the status, the body and the `Content-Range`. An error gives its status.
async fn read_with(backend: &VolumeBackend, key: &str, pairs: &[(&str, &str)]) -> (u16, String, String) {
    match backend.get(&ctx(), key, &headers_of(pairs)).await {
        Ok(response) => {
            let range = header_value(&response, "content-range");
            (response.status, body_text(response.body).await, range)
        }
        Err(error) => (error.status(), String::new(), String::new()),
    }
}

#[tokio::test]
async fn reads_honour_ranges_and_conditions() {
    let (_base, root) = volume_tree();
    let backend = open_volume(&root, false);
    let head = backend.head(&ctx(), "a/b.txt").await.expect("a HEAD");
    assert_eq!(head.status, 200);
    assert_eq!(header_value(&head, "content-length"), "10");
    assert!(header_value(&head, "content-type").starts_with("text/plain"));
    assert!(header_value(&head, "etag").starts_with("W/\"10-"));
    assert!(header_value(&head, "last-modified").ends_with(" GMT"));
    assert_eq!(header_value(&head, "accept-ranges"), "bytes");
    let etag = header_value(&head, "etag");
    let strong = etag.trim_start_matches("W/").to_owned();
    let modified = header_value(&head, "last-modified");
    #[rustfmt::skip]
    let cases: Vec<ReadCase> = vec![
        (vec![], 200, "0123456789", ""),
        (vec![("Range", "bytes=2-4")], 206, "234", "bytes 2-4/10"),
        (vec![("Range", "bytes=-3")], 206, "789", "bytes 7-9/10"),
        (vec![("Range", "bytes=8-")], 206, "89", "bytes 8-9/10"),
        (vec![("Range", "bytes=8-100")], 206, "89", "bytes 8-9/10"),
        (vec![("Range", "bytes=10-")], 416, "", ""),
        (vec![("Range", "bytes=0-1,4-5")], 200, "0123456789", ""),
        (vec![("Range", "bytes=5-2")], 200, "0123456789", ""),
        (vec![("Range", "lines=1-2")], 200, "0123456789", ""),
        (vec![("If-Match", &etag), ("Range", "bytes=0-0")], 206, "0", "bytes 0-0/10"),
        (vec![("If-Match", &strong)], 200, "0123456789", ""),
        (vec![("If-Match", "W/\"10-1\"")], 412, "", ""),
        (vec![("If-None-Match", &etag)], 304, "", ""),
        (vec![("If-Range", &etag), ("Range", "bytes=0-0")], 200, "0123456789", ""),
        (vec![("If-Range", &modified), ("Range", "bytes=0-0")], 206, "0", "bytes 0-0/10"),
        (vec![("If-Modified-Since", &modified)], 304, "", ""),
        (vec![("If-Unmodified-Since", "Mon, 02 Jan 2006 15:04:05 GMT")], 412, "", ""),
    ];
    for (headers, status, body, range) in cases {
        let got = read_with(&backend, "a/b.txt", &headers).await;
        assert_eq!(got.0, status, "GET {headers:?}");
        if status < 300 {
            assert_eq!(got.1, body, "GET {headers:?}");
        }
        assert_eq!(got.2, range, "GET {headers:?}");
    }
    // The range reader of the previews asks each range with If-Match: the weak ETag matches.
    let ranged = |range: &'static str| [("If-Match", etag.as_str()), ("Range", range)].to_vec();
    assert_eq!(read_with(&backend, "a/b.txt", &ranged("bytes=3-6")).await.1, "3456");
    assert_eq!(read_with(&backend, "a/b.txt", &ranged("bytes=8-11")).await.1, "89");
    let linked = read_with(&backend, "link-file", &[]).await;
    assert_eq!((linked.0, linked.1.as_str()), (200, "zero"));
    for key in ["link-out", "link-out/secret.txt", "link-dangling"] {
        let got = backend.get(&ctx(), key, &HeaderMap::new()).await;
        let error = got.expect_err(key);
        assert_eq!(error.status(), 403, "GET {key}");
        assert!(!error.public_message().contains("secret"));
    }
    for key in ["missing.txt", "a", "a0/x"] {
        assert_eq!(read_with(&backend, key, &[]).await.0, 404, "GET {key}");
    }
    let folder = backend.head(&ctx(), "empty/").await.expect("HEAD of a folder key");
    assert_eq!(folder.status, 200);
    assert_eq!(header_value(&folder, "content-length"), "0");
    assert_eq!(header_value(&folder, "content-type"), FOLDER_CONTENT_TYPE);
    assert_eq!(read_with(&backend, "a/../../etc/passwd", &[]).await.0, 400);
    let empty = backend
        .get(&ctx(), "empty/", &HeaderMap::new())
        .await
        .expect("GET of a folder key");
    assert_eq!(body_text(empty.body).await, "");
}

#[tokio::test]
async fn an_empty_file_has_no_range() {
    let base = TestDir::new();
    write_volume_file(base.path(), "empty.txt", "");
    let backend = open_volume(base.path(), false);
    let got = read_with(&backend, "empty.txt", &[("Range", "bytes=0-0")]).await;
    assert_eq!(got, (200, String::new(), String::new()));
}

#[tokio::test]
async fn the_root_prefix_is_the_root_of_the_keys() {
    let base = TestDir::new();
    write_volume_file(base.path(), "published/report.txt", "report");
    write_volume_file(base.path(), "private.txt", "private");
    symlink("../private.txt", base.path().join("published").join("up")).expect("make a link");
    let mut config = volume_config(base.path());
    config.root_prefix = "published/".to_owned();
    let backend = VolumeBackend::open(&config, false).expect("open the volume");
    let page = list(
        &backend,
        ListOptions {
            prefix: "published/".to_owned(),
            delimiter: "/".to_owned(),
            ..ListOptions::default()
        },
    )
    .await
    .expect("a listing");
    assert_eq!(page_keys(&page), ["published/report.txt", "published/up"]);
    let got = read_with(&backend, "published/report.txt", &[]).await;
    assert_eq!((got.0, got.1.as_str()), (200, "report"));
    // A link that leaves root_prefix is refused, also when its target is in path.
    assert_eq!(read_with(&backend, "published/up", &[]).await.0, 403);
    // A key that does not start with the root prefix is outside the volume.
    let outside = backend.get(&ctx(), "private.txt", &HeaderMap::new()).await;
    assert_eq!(code_of(outside), (403, "volume_outside_root".to_owned()));
    // The root prefix must name a folder that exists.
    config.root_prefix = "missing/".to_owned();
    let error = VolumeBackend::open(&config, false)
        .err()
        .expect("a missing root prefix");
    assert!(
        error
            .to_string()
            .starts_with("volume \"vol\": root_prefix \"missing/\""),
        "{error}"
    );
}

#[test]
fn the_volume_instance_has_the_facts_of_a_folder() {
    let (_base, root) = volume_tree();
    let instance = new_volume_instance(&volume_config(&root), Arc::new(RuntimePolicy::default()), Gate::new(4))
        .expect("an instance");
    let info = instance.public_info();
    assert_eq!(
        (info.id.as_str(), info.host.as_str(), info.provider.as_str()),
        ("vol", "volume", "fs")
    );
    let capabilities = instance.capabilities();
    for state in [&capabilities.read, &capabilities.write, &capabilities.delete] {
        assert_eq!(state.state, CapabilityStateName::Allowed);
        assert!(state.allowed && state.verified);
    }
    assert!(instance.backend.resumable().is_some());
    assert!(instance.backend.mover().is_some());
    assert!(instance.backend.folder_remover().is_some());
    assert!(instance.backend.conditional_writer().is_some());
    assert!(instance.backend.multipart_copier().is_some());
    assert!(instance.backend.multipart_lister().is_some());
    assert!(instance.backend.incomplete_upload_remover().is_some());
    assert!(instance.backend.version_store().is_none());
    assert!(instance.backend.tagger().is_none());
    assert!(instance.backend.multipart_upload().is_none());
    assert!(instance.moves_objects());
    assert!(instance.usage.reader.lock().expect("the reader").is_some());
    assert!(
        temporary_files(&root).len() == 1,
        "the probe of the write leaves no temporary file"
    );
}

#[test]
fn a_read_only_volume_is_not_probed_and_denies_the_writes() {
    let base = TestDir::new();
    write_volume_file(base.path(), "file.txt", "file");
    let mut config = volume_config(base.path());
    config.permissions = vec!["read".to_owned()];
    config.permissions_defined = true;
    let instance = new_volume_instance(&config, Arc::new(RuntimePolicy::default()), Gate::new(2)).expect("an instance");
    let capabilities = instance.capabilities();
    assert_eq!(capabilities.read.state, CapabilityStateName::Allowed);
    for state in [&capabilities.write, &capabilities.delete] {
        assert_eq!(state.state, CapabilityStateName::Denied);
        assert_eq!(state.source, "configuration");
        assert!(state.verified && !state.allowed);
    }
    assert!(
        temporary_files(base.path()).is_empty(),
        "a read only volume has no temporary file"
    );
    assert_eq!(read_volume_file(base.path(), "file.txt"), "file");
    // The policy force_read_only has the same effect on a volume that allows the writes.
    let policy = RuntimePolicy {
        access_mode: crate::common::config::AccessMode::ForceReadOnly,
        ..RuntimePolicy::default()
    };
    let forced = new_volume_instance(&volume_config(base.path()), Arc::new(policy), Gate::new(2)).expect("an instance");
    assert_eq!(forced.capabilities().write.source, "runtime");
    assert_eq!(forced.capabilities().read.state, CapabilityStateName::Allowed);
}

#[test]
fn a_volume_that_the_process_cannot_write_stops_the_start() {
    let base = TestDir::new();
    let missing = base.path().join("missing");
    let error = VolumeBackend::open(&volume_config(&missing), false)
        .err()
        .expect("a missing folder");
    assert!(
        error.to_string().contains("cannot resolve the symbolic links"),
        "{error}"
    );
    assert!(error.to_string().starts_with("volume \"vol\": path"), "{error}");
}

#[test]
fn the_capacity_is_the_size_of_the_file_system() {
    let measured = |total: u64, available: u64, delayed: bool| {
        VolumeUsageReader::new(PathBuf::from("/x"), VolumeSizer::new(PathBuf::from("/x"))).with_statfs(Arc::new(
            move |_| {
                Ok(FileSystemSize {
                    total,
                    available,
                    delayed,
                })
            },
        ))
    };
    let capacity = measured(1000, 40, false).capacity().expect("a capacity");
    assert_eq!(
        (capacity.used_bytes, capacity.total_bytes, capacity.free_bytes),
        (960, 1000, 40)
    );
    assert_eq!(capacity.scope, SCOPE_FILESYSTEM);
    assert!(!capacity.approximate);
    let delayed = measured(1000, 40, true).capacity().expect("a capacity");
    assert!(delayed.approximate);
    assert_eq!(delayed.approximate_reason, DELAYED_REASON);
    let empty = measured(0, 0, true).capacity().expect_err("a file system of size 0");
    assert!(empty.to_string().contains("size of 0"), "{empty}");
    let failing = VolumeUsageReader::new(PathBuf::from("/x"), VolumeSizer::new(PathBuf::from("/x")))
        .with_statfs(Arc::new(|_| Err(io::Error::from(io::ErrorKind::PermissionDenied))))
        .capacity()
        .expect_err("a failure");
    assert!(!failing.to_string().contains("/x"), "{failing}");
    let named = VolumeUsageReader::new(PathBuf::from("/x"), VolumeSizer::new(PathBuf::from("/x")))
        .with_statfs(Arc::new(|_| Err(io::Error::from_raw_os_error(libc::EIO))))
        .capacity()
        .expect_err("a failure");
    assert!(named.to_string().ends_with("input/output error"), "{named}");
    assert!(!named.to_string().contains("/x"), "{named}");
}

#[tokio::test]
async fn the_usage_of_a_real_folder_has_a_file_system_and_a_state() {
    let base = TestDir::new();
    let backend = open_volume(base.path(), false);
    let reader = backend.usage_reader();
    let capacity = reader.capacity().expect("a capacity");
    assert!(capacity.total_bytes > 0);
    assert!(capacity.used_bytes >= 0 && capacity.used_bytes <= capacity.total_bytes);
    assert_ne!(reader.volume_usage().state, SizeState::None);
}

/// The number of open descriptors of this process that point to `path`.
fn open_descriptors(path: &Path) -> usize {
    fs::read_dir("/proc/self/fd")
        .map(|folder| {
            folder
                .flatten()
                .filter_map(|entry| fs::read_link(entry.path()).ok())
                .filter(|target| target == path)
                .count()
        })
        .unwrap_or(0)
}

async fn wait_for_descriptors(path: &Path, wanted: usize) -> usize {
    for _ in 0..100 {
        if open_descriptors(path) == wanted {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    open_descriptors(path)
}

#[tokio::test]
async fn the_reader_closes_the_file() {
    let base = TestDir::new();
    write_volume_file(base.path(), "f.txt", "content");
    let big = "0123456789abcdef".repeat(1 << 18);
    write_volume_file(base.path(), "big.bin", &big);
    let backend = open_volume(base.path(), false);
    let response = backend
        .get(&ctx(), "f.txt", &headers_of(&[("Range", "bytes=1-3")]))
        .await
        .expect("a read");
    assert_eq!(response.status, 206);
    assert_eq!(body_text(response.body).await, "ont");
    assert_eq!(
        wait_for_descriptors(&base.path().join("f.txt"), 0).await,
        0,
        "the file is still open after the end"
    );
    // A client that goes away before the end of the body closes the file too.
    let response = backend.get(&ctx(), "big.bin", &HeaderMap::new()).await.expect("a read");
    assert_eq!(wait_for_descriptors(&base.path().join("big.bin"), 1).await, 1);
    drop(response);
    assert_eq!(
        wait_for_descriptors(&base.path().join("big.bin"), 0).await,
        0,
        "the file is still open after the drop"
    );
}

#[tokio::test]
async fn a_link_to_a_folder_outside_the_root_is_listed_as_unreadable_and_refused_by_a_read() {
    let base = TestDir::new();
    write_volume_file(base.path(), "plain.txt", "plain");
    // A symbolic link to a folder that leaves the root is an entry that no operation reads.
    symlink("/", base.path().join("to-root")).expect("make a link");
    let backend = open_volume(base.path(), false);
    let page = list(
        &backend,
        ListOptions {
            delimiter: "/".to_owned(),
            ..ListOptions::default()
        },
    )
    .await
    .expect("a listing");
    let entry = page
        .objects
        .iter()
        .find(|object| object.key == "to-root")
        .expect("the link");
    assert!(entry.unreadable);
    assert_eq!(read_with(&backend, "to-root", &[]).await.0, 403);
}
