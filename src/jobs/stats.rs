//! The Insights statistics of a prefix: the counts by type and by folder, the largest and the most recent objects in
//! bounded heaps, and the treemap that the job builds at its end (docs/ARCHITECTURE.md, "Insights treemap
//! normalization").
//!
//! The job keeps the largest and the most recent objects in two min-heaps of 100 entries: a prefix of any size
//! needs a bounded memory. The public form of a job sorts a copy of each heap.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use serde::Serialize;

use crate::common::misc::clean_relative_key;
use crate::common::storage::ObjectInfo;
use crate::common::time::Timestamp;

/// The most entries of the list of the largest objects.
pub const MAX_STATS_LARGEST_ENTRIES: usize = 100;
/// The most entries of the list of the most recent objects.
pub const MAX_STATS_RECENT_ENTRIES: usize = 100;
/// The most folder levels below the prefix that have exact totals.
pub const MAX_STATS_FOLDER_DEPTH: usize = 5;
/// The version of the layout of the statistics. A job with another version starts again.
pub const STATS_LAYOUT_VERSION: u32 = 4;
/// The most folders with exact totals when the configuration gives no limit.
pub const DEFAULT_MAX_STATS_FOLDERS: u32 = 1000;

/// The count and the bytes of a group of objects.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Aggregate {
    /// The objects.
    pub count: i64,
    /// The bytes.
    pub bytes: i64,
}

/// One object of the list of the largest or of the most recent objects.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct StatsEntry {
    /// The relative key.
    pub path: String,
    /// The size.
    pub bytes: i64,
    /// The kind of the object (`image`, `pdf`, ...).
    #[serde(rename = "type")]
    pub entry_type: String,
    /// The media type of the listing.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub mime: String,
    /// The ETag.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub etag: String,
    /// The last change, RFC 3339 in UTC with seconds.
    #[serde(rename = "lastModified", skip_serializing_if = "String::is_empty")]
    pub last_modified: String,
}

/// One rectangle of the treemap: a folder, a file, or the group `Others`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct StatsTreemapNode {
    /// The label.
    pub name: String,
    /// The relative path of the folder or of the file.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub path: String,
    /// The bytes.
    pub bytes: i64,
    /// The objects.
    pub count: i64,
    /// `folder`, `file` or `other`.
    pub kind: String,
    /// The kind of a file, or `folder` or `other`.
    #[serde(rename = "type", skip_serializing_if = "String::is_empty")]
    pub node_type: String,
    /// The media type of a file.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub mime: String,
    /// The ETag of a file.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub etag: String,
    /// The last change of a file.
    #[serde(rename = "lastModified", skip_serializing_if = "String::is_empty")]
    pub last_modified: String,
    /// The rectangles inside.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<StatsTreemapNode>,
}

fn is_zero_i64(value: &i64) -> bool {
    *value == 0
}

fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}

/// The Insights statistics of a prefix.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct StatsResponse {
    /// The instance.
    pub instance: String,
    /// The version of the layout ([`STATS_LAYOUT_VERSION`]).
    #[serde(rename = "layoutVersion", skip_serializing_if = "is_zero_u32")]
    pub layout_version: u32,
    /// The prefix.
    pub prefix: String,
    /// The objects.
    pub count: i64,
    /// The bytes.
    #[serde(rename = "totalBytes")]
    pub total_bytes: i64,
    /// The time of the scan, in milliseconds.
    #[serde(rename = "tookMs")]
    pub took_ms: i64,
    /// The totals by kind.
    #[serde(rename = "byType")]
    pub by_type: BTreeMap<String, Aggregate>,
    /// The totals of each folder of the five levels below the prefix, by relative folder (`a/`, `a/b/`).
    #[serde(rename = "byFolder")]
    pub by_folder: BTreeMap<String, Aggregate>,
    /// The most folders with exact totals.
    #[serde(rename = "folderLimit", skip_serializing_if = "is_zero_u32")]
    pub folder_limit: u32,
    /// True when a folder did not get exact totals because of the limit.
    #[serde(rename = "foldersTruncated", skip_serializing_if = "std::ops::Not::not")]
    pub folders_truncated: bool,
    /// The folder totals that the limit left out.
    #[serde(rename = "folderAggregatesOmitted", skip_serializing_if = "is_zero_i64")]
    pub folder_aggregates_omitted: i64,
    /// The size from which a rectangle is not in `Others`: one percent of the total, rounded up.
    #[serde(rename = "treemapThresholdBytes", skip_serializing_if = "is_zero_i64")]
    pub treemap_threshold_bytes: i64,
    /// The treemap, after the end of the scan.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub treemap: Option<StatsTreemapNode>,
    /// The largest objects (a heap in the job; sorted in the public form).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub largest: Vec<StatsEntry>,
    /// The most recent objects (a heap in the job; sorted in the public form).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub recent: Vec<StatsEntry>,
    /// The newest change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub newest: Option<Timestamp>,
    /// The oldest change.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oldest: Option<Timestamp>,
}

/// New statistics for a prefix, with a limit of the folders with exact totals (0: the default limit).
pub fn new_stats_response(instance: &str, prefix: &str, folder_limit: u32) -> StatsResponse {
    StatsResponse {
        instance: instance.to_owned(),
        prefix: prefix.to_owned(),
        layout_version: STATS_LAYOUT_VERSION,
        folder_limit: if folder_limit == 0 {
            DEFAULT_MAX_STATS_FOLDERS
        } else {
            folder_limit
        },
        ..StatsResponse::default()
    }
}

// --- Bounded heaps ------------------------------------------------------------------------------------------------

/// The order of the heap of the largest objects: the smallest object at the top; for an equal size, the larger path.
fn largest_less(left: &StatsEntry, right: &StatsEntry) -> bool {
    if left.bytes != right.bytes {
        return left.bytes < right.bytes;
    }
    left.path > right.path
}

/// The order of the heap of the recent objects: the oldest object at the top; for an equal time, the larger path.
fn recent_less(left: &StatsEntry, right: &StatsEntry) -> bool {
    if left.last_modified != right.last_modified {
        return left.last_modified < right.last_modified;
    }
    left.path > right.path
}

type Less = fn(&StatsEntry, &StatsEntry) -> bool;

fn heap_up(heap: &mut [StatsEntry], mut child: usize, less: Less) {
    while child > 0 {
        let parent = (child - 1) / 2;
        if !less(&heap[child], &heap[parent]) {
            break;
        }
        heap.swap(parent, child);
        child = parent;
    }
}

fn heap_down(heap: &mut [StatsEntry], start: usize, length: usize, less: Less) {
    let mut parent = start;
    loop {
        let left = 2 * parent + 1;
        if left >= length {
            break;
        }
        let mut child = left;
        let right = left + 1;
        if right < length && less(&heap[right], &heap[left]) {
            child = right;
        }
        if !less(&heap[child], &heap[parent]) {
            break;
        }
        heap.swap(parent, child);
        parent = child;
    }
}

fn heap_push(heap: &mut Vec<StatsEntry>, entry: StatsEntry, less: Less) {
    heap.push(entry);
    let last = heap.len() - 1;
    heap_up(heap, last, less);
}

fn heap_pop(heap: &mut Vec<StatsEntry>, less: Less) {
    let Some(last) = heap.len().checked_sub(1) else {
        return;
    };
    heap.swap(0, last);
    heap_down(heap, 0, last, less);
    heap.pop();
}

fn heap_init(heap: &mut [StatsEntry], less: Less) {
    let length = heap.len();
    for index in (0..length / 2).rev() {
        heap_down(heap, index, length, less);
    }
}

/// Give the heap order to the list of the largest objects (at the start of each run of a job).
pub(crate) fn init_largest_heap(entries: &mut [StatsEntry]) {
    heap_init(entries, largest_less);
}

/// Give the heap order to the list of the recent objects (at the start of each run of a job).
pub(crate) fn init_recent_heap(entries: &mut [StatsEntry]) {
    heap_init(entries, recent_less);
}

/// Keep an object in the heap of the recent objects when it is one of the [`MAX_STATS_RECENT_ENTRIES`] most recent.
/// An entry without a path or without a time is not kept.
pub fn add_recent_stats_entry(entries: &mut Vec<StatsEntry>, entry: StatsEntry) {
    if entry.path.is_empty() || entry.last_modified.is_empty() {
        return;
    }
    if entries.len() < MAX_STATS_RECENT_ENTRIES {
        heap_push(entries, entry, recent_less);
        return;
    }
    let Some(oldest) = entries.first() else {
        return;
    };
    if entry.last_modified < oldest.last_modified
        || (entry.last_modified == oldest.last_modified && entry.path >= oldest.path)
    {
        return;
    }
    heap_pop(entries, recent_less);
    heap_push(entries, entry, recent_less);
}

/// Keep an object in the heap of the largest objects when it is one of the [`MAX_STATS_LARGEST_ENTRIES`] largest. An
/// entry with a negative size or without a path is not kept.
pub fn add_largest_stats_entry(entries: &mut Vec<StatsEntry>, entry: StatsEntry) {
    if entry.bytes < 0 || entry.path.is_empty() {
        return;
    }
    if entries.len() < MAX_STATS_LARGEST_ENTRIES {
        heap_push(entries, entry, largest_less);
        return;
    }
    let Some(minimum) = entries.first() else {
        return;
    };
    if entry.bytes < minimum.bytes || (entry.bytes == minimum.bytes && entry.path >= minimum.path) {
        return;
    }
    heap_pop(entries, largest_less);
    heap_push(entries, entry, largest_less);
}

// --- Folder totals ------------------------------------------------------------------------------------------------

/// Add the size of an object to the exact totals of each folder above it, for the five levels below the prefix. The
/// keys are relative to the prefix. A new folder over `limit` folders is left out and counted (`limit` 0: no limit).
pub fn add_stats_folder_aggregates(stats: &mut StatsResponse, prefix: &str, relative: &str, size: i64, limit: u32) {
    let remaining = relative.strip_prefix(prefix).unwrap_or(relative);
    let parts: Vec<&str> = remaining.split('/').collect();
    let folder_count = (parts.len() - 1).min(MAX_STATS_FOLDER_DEPTH);
    for depth in 1..=folder_count {
        let folder = format!("{}/", parts[..depth].join("/"));
        let exists = stats.by_folder.contains_key(&folder);
        if !exists && limit > 0 && stats.by_folder.len() >= limit as usize {
            stats.folders_truncated = true;
            stats.folder_aggregates_omitted += 1;
            continue;
        }
        let value = stats.by_folder.entry(folder).or_default();
        value.count += 1;
        value.bytes += size;
    }
}

/// True for "no time": no value, or the zero time of the answers.
fn is_zero_time(value: Option<Timestamp>) -> bool {
    match value {
        None => true,
        Some(time) => time.secs == ZERO_TIME_SECS && time.nanos == 0,
    }
}

/// The seconds of `0001-01-01T00:00:00Z` since 1970.
const ZERO_TIME_SECS: i64 = -62_135_596_800;

/// Add one listed object to the statistics. A folder marker (a key that ends with `/` and has no byte) is not
/// counted. `kind` is the kind of the object.
pub(crate) fn record_object(stats: &mut StatsResponse, prefix: &str, relative: &str, object: &ObjectInfo, kind: &str) {
    if relative.ends_with('/') && object.size == 0 {
        return;
    }
    stats.count += 1;
    stats.total_bytes += object.size;
    let by_type = stats.by_type.entry(kind.to_owned()).or_default();
    by_type.count += 1;
    by_type.bytes += object.size;
    let modified = if is_zero_time(object.last_modified) {
        None
    } else {
        object.last_modified
    };
    let entry = StatsEntry {
        path: relative.to_owned(),
        bytes: object.size,
        entry_type: kind.to_owned(),
        mime: object.content_type.clone(),
        etag: object.etag.clone(),
        last_modified: modified.map(|time| time.utc().rfc3339()).unwrap_or_default(),
    };
    add_largest_stats_entry(&mut stats.largest, entry.clone());
    add_recent_stats_entry(&mut stats.recent, entry);
    let limit = stats.folder_limit;
    add_stats_folder_aggregates(stats, prefix, relative, object.size, limit);
    if let Some(time) = modified {
        if stats.newest.is_none_or(|newest| time > newest) {
            stats.newest = Some(time);
        }
        if stats.oldest.is_none_or(|oldest| time < oldest) {
            stats.oldest = Some(time);
        }
    }
}

/// A copy of the statistics for the public form: the largest objects first, then the most recent objects first.
pub(crate) fn public_stats(stats: &StatsResponse) -> StatsResponse {
    let mut copy = stats.clone();
    copy.largest
        .sort_by(|left, right| right.bytes.cmp(&left.bytes).then_with(|| left.path.cmp(&right.path)));
    copy.recent.sort_by(|left, right| {
        right
            .last_modified
            .cmp(&left.last_modified)
            .then_with(|| left.path.cmp(&right.path))
    });
    copy
}

// --- Treemap ------------------------------------------------------------------------------------------------------

/// A prefix with one `/` at its end and none at its start. An empty prefix stays empty.
pub(crate) fn normalize_prefix(value: &str) -> String {
    let trimmed = value.trim_start_matches('/');
    if trimmed.is_empty() {
        return String::new();
    }
    format!("{}/", trimmed.trim_end_matches('/'))
}

struct TreemapBuilder {
    node: StatsTreemapNode,
    children: BTreeMap<String, TreemapBuilder>,
    folder: bool,
    aggregate_known: bool,
}

impl TreemapBuilder {
    fn folder(name: &str, path: &str) -> Self {
        Self {
            node: StatsTreemapNode {
                name: name.to_owned(),
                path: path.to_owned(),
                kind: "folder".to_owned(),
                node_type: "folder".to_owned(),
                ..StatsTreemapNode::default()
            },
            children: BTreeMap::new(),
            folder: true,
            aggregate_known: false,
        }
    }
}

/// The label of the root of the treemap: the last part of the prefix, or `/`.
fn treemap_root_name(prefix: &str) -> String {
    let trimmed = prefix.trim().trim_matches('/');
    if trimmed.is_empty() {
        return "/".to_owned();
    }
    trimmed.rsplit('/').next().unwrap_or(trimmed).to_owned()
}

/// A folder key of the statistics, relative to the prefix, with one `/` at its end.
fn normalized_treemap_path(value: &str, prefix: &str) -> String {
    let mut clean = value.trim().trim_start_matches('/');
    if clean.is_empty() || clean == "(root)" {
        return String::new();
    }
    let clean_prefix = normalize_prefix(&clean_relative_key(prefix));
    if !clean_prefix.is_empty()
        && let Some(rest) = clean.strip_prefix(clean_prefix.as_str())
    {
        clean = rest;
    }
    normalize_prefix(clean)
}

fn ensure_treemap_folder<'a>(root: &'a mut TreemapBuilder, parts: &[&str], prefix: &str) -> &'a mut TreemapBuilder {
    let mut parent = root;
    let mut path = normalize_prefix(&clean_relative_key(prefix));
    for part in parts {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        path.push_str(part);
        path.push('/');
        parent = parent
            .children
            .entry(format!("folder:{part}"))
            .or_insert_with(|| TreemapBuilder::folder(part, &path));
    }
    parent
}

fn finalize_treemap(node: &mut TreemapBuilder) {
    let mut child_bytes = 0i64;
    let mut child_count = 0i64;
    for child in node.children.values_mut() {
        finalize_treemap(child);
        child_bytes += child.node.bytes.max(0);
        child_count += child.node.count.max(0);
    }
    if node.folder {
        if node.aggregate_known {
            node.node.bytes = node.node.bytes.max(child_bytes);
            node.node.count = node.node.count.max(child_count);
        } else {
            node.node.bytes = child_bytes;
            node.node.count = child_count;
        }
    }
}

/// One percent of the total, rounded up: an object of exactly one percent stays visible. Integer arithmetic gives
/// the same value to each client.
pub fn stats_treemap_threshold(total_bytes: i64) -> i64 {
    if total_bytes <= 0 {
        return 0;
    }
    (total_bytes + 99) / 100
}

fn by_bytes_then_name(left: &StatsTreemapNode, right: &StatsTreemapNode) -> Ordering {
    right.bytes.cmp(&left.bytes).then_with(|| left.name.cmp(&right.name))
}

fn materialize_treemap(node: &TreemapBuilder, threshold: i64) -> StatsTreemapNode {
    let mut result = node.node.clone();
    if !node.folder {
        return result;
    }
    let mut children: Vec<&TreemapBuilder> = node.children.values().filter(|child| child.node.bytes > 0).collect();
    children.sort_by(|left, right| by_bytes_then_name(&left.node, &right.node));
    let listed_bytes: i64 = children.iter().map(|child| child.node.bytes.max(0)).sum();
    let listed_count: i64 = children.iter().map(|child| child.node.count.max(0)).sum();
    let mut other_bytes = (result.bytes - listed_bytes).max(0);
    let mut other_count = (result.count - listed_count).max(0);
    let mut visible: Vec<StatsTreemapNode> = Vec::with_capacity(children.len() + 1);
    for child in children {
        if threshold == 0 || child.node.bytes >= threshold {
            visible.push(materialize_treemap(child, threshold));
            continue;
        }
        other_bytes += child.node.bytes.max(0);
        other_count += child.node.count.max(0);
    }
    if other_bytes > 0 || other_count > 0 {
        visible.push(StatsTreemapNode {
            name: "Others".to_owned(),
            path: result.path.clone(),
            bytes: other_bytes,
            count: other_count,
            kind: "other".to_owned(),
            node_type: "other".to_owned(),
            ..StatsTreemapNode::default()
        });
    }
    visible.sort_by(by_bytes_then_name);

    // A folder chain without a real branch becomes its content: each client gets the same tree, without single-child
    // rectangles.
    while visible.len() == 1 {
        let only = visible.remove(0);
        if only.kind == "folder" && !only.children.is_empty() {
            visible = only.children;
        } else if only.kind == "file" {
            // Keep the only file name and its target instead of a root rectangle without information.
            result.name = only.name;
            result.path = only.path;
            result.kind = only.kind;
            result.node_type = only.node_type;
            result.mime = only.mime;
            result.etag = only.etag;
            result.last_modified = only.last_modified;
            result.children = Vec::new();
            return result;
        } else {
            // A sole Others rectangle adds no information: the parent has the exact totals.
            visible = Vec::new();
        }
    }
    result.children = visible;
    result
}

/// Build the treemap of complete statistics: the threshold and the tree.
pub fn build_stats_treemap(stats: &StatsResponse) -> (i64, StatsTreemapNode) {
    let prefix = normalize_prefix(&clean_relative_key(&stats.prefix));
    let mut root = TreemapBuilder::folder(&treemap_root_name(&prefix), &prefix);
    root.node.bytes = stats.total_bytes.max(0);
    root.node.count = stats.count.max(0);
    root.aggregate_known = true;

    let mut folders: Vec<(&String, String)> = stats
        .by_folder
        .keys()
        .map(|folder| (folder, normalized_treemap_path(folder, &prefix)))
        .collect();
    folders.sort_by(|left, right| {
        let left_depth = left.1.matches('/').count();
        let right_depth = right.1.matches('/').count();
        left_depth.cmp(&right_depth).then_with(|| left.1.cmp(&right.1))
    });
    for (folder, relative) in folders {
        if relative.is_empty() {
            continue;
        }
        let parts: Vec<&str> = relative.trim_matches('/').split('/').collect();
        let node = ensure_treemap_folder(&mut root, &parts, &prefix);
        let aggregate = stats.by_folder.get(folder).copied().unwrap_or_default();
        node.node.bytes = aggregate.bytes.max(0);
        node.node.count = aggregate.count.max(0);
        node.aggregate_known = true;
    }

    for entry in &stats.largest {
        let full_path = entry.path.trim().trim_start_matches('/');
        if full_path.is_empty() || (!prefix.is_empty() && !full_path.starts_with(prefix.as_str())) {
            continue;
        }
        let relative = full_path.strip_prefix(prefix.as_str()).unwrap_or(full_path);
        let parts: Vec<&str> = relative.trim_matches('/').split('/').collect();
        if parts[0].is_empty() {
            continue;
        }
        let file_name = parts[parts.len() - 1];
        let parent = ensure_treemap_folder(&mut root, &parts[..parts.len() - 1], &prefix);
        parent.children.insert(
            format!("file:{file_name}"),
            TreemapBuilder {
                node: StatsTreemapNode {
                    name: file_name.to_owned(),
                    path: full_path.to_owned(),
                    bytes: entry.bytes.max(0),
                    count: 1,
                    kind: "file".to_owned(),
                    node_type: entry.entry_type.clone(),
                    mime: entry.mime.clone(),
                    etag: entry.etag.clone(),
                    last_modified: entry.last_modified.clone(),
                    children: Vec::new(),
                },
                children: BTreeMap::new(),
                folder: false,
                aggregate_known: false,
            },
        );
    }

    finalize_treemap(&mut root);
    let threshold = stats_treemap_threshold(root.node.bytes);
    (threshold, materialize_treemap(&root, threshold))
}
