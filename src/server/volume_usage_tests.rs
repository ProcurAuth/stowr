// SPDX-License-Identifier: MIT OR Apache-2.0
//! The usage of a volume after a change: a write marks the count of the folder old, and the next reads of
//! `/api/usage` give the state of the new count (`computing`, then `ready`) and the new size of the folder.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

use super::testing::{TestRequest, app_of, get};
use crate::common::app::App;
use crate::common::config::{RuntimePolicy, VolumeConfig};
use crate::instance::gate::Gate;
use crate::uploads::RESUME_TOKEN_HEADER;

static FOLDER_COUNTER: AtomicU64 = AtomicU64::new(0);

/// A new empty folder of a test. The folder goes away when the value is dropped.
struct TestFolder {
    path: PathBuf,
}

impl TestFolder {
    fn new() -> Self {
        let path = std::env::temp_dir().join("stowr-volume-usage-tests").join(format!(
            "t-{}-{}",
            std::process::id(),
            FOLDER_COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self {
            path: std::fs::canonicalize(&path).unwrap(),
        }
    }
}

impl Drop for TestFolder {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// The application with the volume `vol` on a folder, with the three permissions.
fn volume_app(root: &Path) -> Arc<App> {
    let cfg = VolumeConfig {
        id: "vol".to_owned(),
        name: "vol".to_owned(),
        path: root.to_path_buf(),
        ..VolumeConfig::default()
    };
    let instance = crate::volume::new_volume_instance(&cfg, Arc::new(RuntimePolicy::default()), Gate::new(4)).unwrap();
    app_of(vec![Arc::new(instance)])
}

/// Read `/api/usage` until the answer passes the check, for 15 seconds at most. Gives the last answer.
async fn usage_until(app: &Arc<App>, check: impl Fn(&Value) -> bool) -> Value {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let answer = get(app, "/api/usage?instance=vol").await;
        assert_eq!(answer.status, 200, "{}", answer.text());
        let usage = answer.json();
        if check(&usage) || Instant::now() >= deadline {
            return usage;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn the_usage_of_a_volume_counts_a_resumable_upload_after_its_end() {
    let folder = TestFolder::new();
    std::fs::write(folder.path.join("first.txt"), "first").unwrap();
    let app = volume_app(&folder.path);
    let before = usage_until(&app, |usage| usage["selfState"] == "ready").await;
    assert_eq!(before["selfState"], "ready", "{before}");
    assert_eq!(
        (before["selfBytes"].as_i64(), before["usedObjects"].as_i64()),
        (Some(5), Some(1)),
        "{before}"
    );

    let content = b"the content of a resumable upload".to_vec();
    let total = content.len() as i64;
    let created = TestRequest::new("POST", "/api/uploads")
        .header("content-type", "application/json")
        .body(
            serde_json::to_vec(&json!({
                "instance": "vol", "key": "folder/upload.bin", "size": total, "contentType": "application/octet-stream"
            }))
            .unwrap(),
        )
        .send(&app)
        .await;
    assert_eq!(created.status, 201, "{}", created.text());
    let token = created.json()["resumeToken"].as_str().unwrap_or("").to_owned();
    let chunk = TestRequest::new("PUT", "/api/uploads")
        .header("content-type", "application/octet-stream")
        .header("content-range", &format!("bytes 0-{}/{total}", total - 1))
        .header(RESUME_TOKEN_HEADER, &token)
        .body(content.clone())
        .send(&app)
        .await;
    assert_eq!(chunk.status, 200, "{}", chunk.text());
    assert_eq!(std::fs::read(folder.path.join("folder/upload.bin")).unwrap(), content);

    // The end of the upload makes the count old: the next reads count again, and the answer shows the new size.
    let after = usage_until(&app, |usage| {
        usage["selfState"] == "ready" && usage["selfBytes"].as_i64() == Some(5 + total)
    })
    .await;
    assert_eq!(after["selfState"], "ready", "{after}");
    assert_eq!(after["selfBytes"].as_i64(), Some(5 + total), "{after}");
    assert_eq!(after["usedObjects"].as_i64(), Some(2), "{after}");
}

#[tokio::test]
async fn the_usage_of_a_volume_gives_the_state_of_its_count() {
    let folder = TestFolder::new();
    let app = volume_app(&folder.path);
    let usage = get(&app, "/api/usage?instance=vol").await.json();
    let state = usage["selfState"].as_str().unwrap_or("");
    assert!(matches!(state, "computing" | "ready"), "{usage}");
    assert!(usage["selfBytes"].is_i64(), "{usage}");
    assert_eq!(usage["source"], "statfs", "{usage}");
}
