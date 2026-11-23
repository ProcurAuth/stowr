//! The tests of the Insights statistics: the bounded lists, the folder totals, the treemap and the public form.

use std::collections::BTreeMap;

use super::*;
use crate::common::time::Timestamp;

fn aggregate(count: i64, bytes: i64) -> Aggregate {
    Aggregate { count, bytes }
}

fn entry(path: &str, bytes: i64, kind: &str) -> StatsEntry {
    StatsEntry {
        path: path.to_owned(),
        bytes,
        entry_type: kind.to_owned(),
        ..StatsEntry::default()
    }
}

#[test]
fn the_treemap_groups_small_entries_and_contracts_single_child_folders() {
    let stats = StatsResponse {
        prefix: "Home/".to_owned(),
        count: 5,
        total_bytes: 10_000,
        by_folder: BTreeMap::from([
            ("prometheus/".to_owned(), aggregate(2, 9_000)),
            ("prometheus/binaries/".to_owned(), aggregate(2, 9_000)),
            ("tiny/".to_owned(), aggregate(2, 90)),
        ]),
        largest: vec![
            entry("Home/prometheus/binaries/a.tgz", 5_000, "archive"),
            entry("Home/prometheus/binaries/b.tgz", 4_000, "archive"),
            entry("Home/tiny/x.bin", 50, "other"),
            entry("Home/tiny/y.bin", 40, "other"),
        ],
        ..StatsResponse::default()
    };
    let (threshold, tree) = build_stats_treemap(&stats);
    assert_eq!(threshold, 100);
    assert_eq!(tree.children.len(), 2, "{:?}", tree.children);
    let prometheus = tree
        .children
        .iter()
        .find(|child| child.kind == "folder")
        .expect("the prometheus node");
    let others = tree
        .children
        .iter()
        .find(|child| child.kind == "other")
        .expect("the Others node");
    assert_eq!(prometheus.name, "prometheus");
    assert_eq!(prometheus.children.len(), 2);
    for child in &prometheus.children {
        assert_ne!(child.name, "binaries", "the single-child folder must be contracted");
        assert_eq!(child.kind, "file");
    }
    assert_eq!((others.bytes, others.count), (1_000, 3));
}

#[test]
fn the_treemap_removes_a_sole_others_node() {
    let stats = StatsResponse {
        prefix: "only/".to_owned(),
        count: 3,
        total_bytes: 300,
        ..StatsResponse::default()
    };
    let (_, tree) = build_stats_treemap(&stats);
    assert!(tree.children.is_empty(), "{:?}", tree.children);
    assert_eq!((tree.bytes, tree.count), (300, 3));
}

#[test]
fn the_treemap_threshold_keeps_an_exact_one_percent() {
    assert_eq!(stats_treemap_threshold(1_000), 10);
    assert_eq!(stats_treemap_threshold(1_001), 11);
    assert_eq!(stats_treemap_threshold(0), 0);
}

#[test]
fn a_treemap_with_one_file_shows_that_file_at_its_root() {
    let stats = StatsResponse {
        prefix: "docs/".to_owned(),
        count: 1,
        total_bytes: 42,
        largest: vec![StatsEntry {
            mime: "application/pdf".to_owned(),
            ..entry("docs/report.pdf", 42, "pdf")
        }],
        ..StatsResponse::default()
    };
    let (_, tree) = build_stats_treemap(&stats);
    assert_eq!(tree.name, "report.pdf");
    assert_eq!(tree.path, "docs/report.pdf");
    assert_eq!(tree.kind, "file");
    assert_eq!(tree.mime, "application/pdf");
    assert_eq!((tree.bytes, tree.count), (42, 1));
    assert!(tree.children.is_empty());
    let root = build_stats_treemap(&StatsResponse::default()).1;
    assert_eq!(root.name, "/");
}

#[test]
fn the_largest_entries_stay_bounded_and_sorted_in_the_public_form() {
    let mut entries = Vec::new();
    for index in 0..MAX_STATS_LARGEST_ENTRIES + 25 {
        let name = char::from(b'a' + (index % 26) as u8).to_string();
        add_largest_stats_entry(&mut entries, entry(&name, index as i64, "other"));
    }
    assert_eq!(entries.len(), MAX_STATS_LARGEST_ENTRIES);
    let job = JobState {
        stats: Some(Box::new(StatsResponse {
            largest: entries,
            ..StatsResponse::default()
        })),
        ..JobState::default()
    }
    .public();
    let largest = &job.stats.as_ref().unwrap().largest;
    assert_eq!(largest.len(), MAX_STATS_LARGEST_ENTRIES);
    for pair in largest.windows(2) {
        assert!(pair[0].bytes >= pair[1].bytes, "not sorted: {pair:?}");
    }
    assert_eq!(largest[0].bytes, (MAX_STATS_LARGEST_ENTRIES + 24) as i64);
}

#[test]
fn the_recent_entries_stay_bounded_and_sorted_in_the_public_form() {
    let base = Timestamp::parse_rfc3339("2026-07-25T08:00:00Z").unwrap();
    let mut entries = Vec::new();
    for index in 0..MAX_STATS_RECENT_ENTRIES + 25 {
        add_recent_stats_entry(
            &mut entries,
            StatsEntry {
                last_modified: base.plus_secs(index as i64 * 60).rfc3339_nano(),
                ..entry(&format!("file-{index:03}.bin"), index as i64, "other")
            },
        );
    }
    assert_eq!(entries.len(), MAX_STATS_RECENT_ENTRIES);
    let job = JobState {
        stats: Some(Box::new(StatsResponse {
            recent: entries,
            ..StatsResponse::default()
        })),
        ..JobState::default()
    }
    .public();
    let recent = &job.stats.as_ref().unwrap().recent;
    assert_eq!(recent.len(), MAX_STATS_RECENT_ENTRIES);
    for pair in recent.windows(2) {
        assert!(pair[0].last_modified >= pair[1].last_modified, "not sorted: {pair:?}");
    }
    let newest = base
        .plus_secs((MAX_STATS_RECENT_ENTRIES as i64 + 24) * 60)
        .rfc3339_nano();
    assert_eq!(recent[0].last_modified, newest);
}

#[test]
fn an_entry_without_a_path_or_a_time_is_not_kept() {
    let mut entries = Vec::new();
    add_recent_stats_entry(&mut entries, entry("a", 1, "other"));
    add_recent_stats_entry(
        &mut entries,
        StatsEntry {
            last_modified: "2026-01-01T00:00:00Z".to_owned(),
            ..entry("", 1, "other")
        },
    );
    assert!(entries.is_empty());
    add_largest_stats_entry(&mut entries, entry("a", -1, "other"));
    add_largest_stats_entry(&mut entries, entry("", 1, "other"));
    assert!(entries.is_empty());
}

#[test]
fn the_folder_totals_keep_five_exact_levels() {
    let mut stats = new_stats_response("instance", "root/", 0);
    add_stats_folder_aggregates(
        &mut stats,
        "root/",
        "root/a/b/c/d/e/f/file.bin",
        42,
        DEFAULT_MAX_STATS_FOLDERS,
    );
    for key in ["a/", "a/b/", "a/b/c/", "a/b/c/d/", "a/b/c/d/e/"] {
        assert_eq!(stats.by_folder.get(key), Some(&aggregate(1, 42)), "{key}");
    }
    assert!(!stats.by_folder.contains_key("a/b/c/d/e/f/"));
    assert_eq!(stats.layout_version, STATS_LAYOUT_VERSION);
    assert_eq!(stats.folder_limit, DEFAULT_MAX_STATS_FOLDERS);
}

#[test]
fn the_folder_limit_counts_the_folders_that_it_leaves_out() {
    let mut stats = new_stats_response("instance", "", 2);
    add_stats_folder_aggregates(&mut stats, "", "a/b/c/file.bin", 7, 2);
    add_stats_folder_aggregates(&mut stats, "", "a/x.bin", 3, 2);
    assert_eq!(stats.by_folder.len(), 2);
    assert_eq!(stats.by_folder["a/"], aggregate(2, 10));
    assert_eq!(stats.by_folder["a/b/"], aggregate(1, 7));
    assert!(stats.folders_truncated);
    assert_eq!(stats.folder_aggregates_omitted, 1);
    add_stats_folder_aggregates(&mut stats, "", "top.bin", 1, 2);
    assert_eq!(stats.folder_aggregates_omitted, 1);
}

#[test]
fn the_statistics_have_the_json_form_of_the_answers() {
    let stats = StatsResponse {
        instance: "rw".to_owned(),
        prefix: "p/".to_owned(),
        ..StatsResponse::default()
    };
    let text = String::from_utf8(crate::common::json::to_vec(&stats).unwrap()).unwrap();
    assert_eq!(
        text,
        r#"{"instance":"rw","prefix":"p/","count":0,"totalBytes":0,"tookMs":0,"byType":{},"byFolder":{}}"#
    );
    let full = new_stats_response("rw", "p/", 0);
    let text = String::from_utf8(crate::common::json::to_vec(&full).unwrap()).unwrap();
    assert!(text.contains(r#""layoutVersion":4,"prefix":"p/""#), "{text}");
    assert!(text.contains(r#""folderLimit":1000"#), "{text}");
}

#[test]
fn a_job_without_times_shows_the_zero_time() {
    let job = JobState {
        id: "job_x".to_owned(),
        job_type: job_type::STATS_PREFIX.to_owned(),
        instance: "rw".to_owned(),
        status: job_status::QUEUED.to_owned(),
        ..JobState::default()
    };
    let text = String::from_utf8(crate::common::json::to_vec(&job.public()).unwrap()).unwrap();
    assert_eq!(
        text,
        r#"{"id":"job_x","type":"stats_prefix","instance":"rw","status":"queued","processed":0,"createdAt":"0001-01-01T00:00:00Z","updatedAt":"0001-01-01T00:00:00Z"}"#
    );
}

#[test]
fn the_public_form_shows_the_copied_parts_and_hides_a_partial_result() {
    let created = Timestamp::parse_rfc3339("2026-11-23T12:00:00Z").unwrap();
    let mut job = JobState {
        id: "job_1".to_owned(),
        job_type: job_type::COPY_OBJECT.to_owned(),
        instance: "rw".to_owned(),
        source: "big.bin".to_owned(),
        target: "copy/big.bin".to_owned(),
        status: job_status::RUNNING.to_owned(),
        copied_bytes: 10,
        copying_bytes: 5,
        total_bytes: 100,
        locked_keys: vec!["k".to_owned()],
        locked: 1,
        created_at: created,
        updated_at: created,
        started_at: Some(created),
        ..JobState::default()
    };
    let text = String::from_utf8(crate::common::json::to_vec(&job.public()).unwrap()).unwrap();
    assert_eq!(
        text,
        r#"{"id":"job_1","type":"copy_object","instance":"rw","source":"big.bin","target":"copy/big.bin","status":"running","processed":0,"copiedBytes":15,"totalBytes":100,"locked":1,"lockedKeys":["k"],"createdAt":"2026-11-23T12:00:00Z","updatedAt":"2026-11-23T12:00:00Z","startedAt":"2026-11-23T12:00:00Z"}"#
    );
    job.job_type = job_type::ABORT_MULTIPARTS.to_owned();
    job.multipart_abort = Some(crate::uploads::MultipartAbortJob {
        older_than_days: 5,
        ..Default::default()
    });
    job.multipart_result = Some(crate::uploads::MultipartAbortResult::default());
    let text = String::from_utf8(crate::common::json::to_vec(&job.public()).unwrap()).unwrap();
    assert!(
        text.contains(r#""olderThanDays":5,"multipartAbort":{"aborted":0,"skippedUndated":0,"skippedRecent":0,"skippedActive":0,"failed":0}"#),
        "{text}"
    );
}

#[test]
fn a_running_analysis_job_does_not_show_a_partial_result() {
    let mut job = JobState {
        id: "job-analysis-public-contract".to_owned(),
        job_type: job_type::INTEGRITY.to_owned(),
        instance: "rw".to_owned(),
        status: job_status::RUNNING.to_owned(),
        integrity: Some(IntegrityResult {
            entries: vec![IntegrityEntry {
                key: "large-object.bin".to_owned(),
                sha256: "a".repeat(64),
                ..IntegrityEntry::default()
            }],
        }),
        ..JobState::default()
    };
    assert!(
        job.public().integrity.is_none(),
        "a running job showed a partial result"
    );
    job.status = job_status::COMPLETED.to_owned();
    assert_eq!(job.public().integrity.map(|result| result.entries.len()), Some(1));
}
