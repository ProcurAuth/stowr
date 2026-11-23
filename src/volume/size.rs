// SPDX-License-Identifier: MIT OR Apache-2.0
//! The size of the files of a volume. The usage of a volume says what the folder holds: the sum of the sizes of its
//! regular files (the size of each file, not the blocks of the disk). A request never walks the tree: a sizer walks
//! it in the background, one walk at a time, and the request gets the last count.
//!
//! A walk reads at most `SIZE_ENTRIES` entries in `SIZE_TIME`: a larger tree gives `partial` (at least the count).
//! The count stays for `SIZE_TTL`. A write of the server in the volume makes the count old, so that the next read
//! starts a new walk. A walk does not follow a symbolic link, and does not count the temporary files of the server.

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use super::path::parse_temporary_name;
use crate::common::time::Timestamp;

/// The largest number of entries that one walk reads.
pub const SIZE_ENTRIES: i64 = 1_000_000;

/// The longest time of one walk.
pub const SIZE_TIME: Duration = Duration::from_secs(20);

/// The life of a complete count when nothing changes through the server.
pub const SIZE_TTL: Duration = Duration::from_secs(5 * 60);

/// The number of entries between two reports of the progress of a walk.
const PROGRESS_STEP: i64 = 1024;

/// The state of a count.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SizeState {
    /// No count yet.
    #[default]
    None,
    /// A walk runs: the numbers are at least the files that it counted.
    Computing,
    /// The last walk reached its budget: the numbers are at least the size of the folder.
    Partial,
    /// The last walk ended.
    Ready,
}

impl SizeState {
    /// The text of the state in `/api/usage`: `computing`, `partial`, `ready`, or an empty text.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "",
            Self::Computing => "computing",
            Self::Partial => "partial",
            Self::Ready => "ready",
        }
    }
}

/// A count of the size of the files of a volume: the bytes, the files, the state and the time.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SizeCount {
    /// The sum of the sizes of the files.
    pub bytes: i64,
    /// The number of files.
    pub files: i64,
    /// The state of the count.
    pub state: SizeState,
    /// The time of the count.
    pub at: Option<Timestamp>,
}

#[derive(Debug, Default)]
struct SizerState {
    last: SizeCount,
    running: bool,
    /// The count of the walk that runs.
    progress: SizeCount,
    /// Set by a write: the next read starts a new walk.
    stale: bool,
    /// The number of walks that ended. A test waits for it.
    finished: u64,
    /// The time of the end of the last complete count, for the life of the count.
    counted: Option<Instant>,
}

#[derive(Debug)]
struct SizerShared {
    root: PathBuf,
    entries: i64,
    timeout: Duration,
    state: Mutex<SizerState>,
    ended: Condvar,
}

impl SizerShared {
    fn lock(&self) -> MutexGuard<'_, SizerState> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The sizer of one volume. A clone shares the count.
#[derive(Clone, Debug)]
pub struct VolumeSizer {
    shared: Arc<SizerShared>,
}

impl VolumeSizer {
    /// A sizer for the folder `root`, with the standard budget of a walk.
    pub fn new(root: PathBuf) -> Self {
        Self::with_limits(root, SIZE_ENTRIES, SIZE_TIME)
    }

    /// A sizer with its own budget of entries and of time. The tests use small values.
    pub fn with_limits(root: PathBuf, entries: i64, timeout: Duration) -> Self {
        Self {
            shared: Arc::new(SizerShared {
                root,
                entries,
                timeout,
                state: Mutex::new(SizerState::default()),
                ended: Condvar::new(),
            }),
        }
    }

    /// Make the count old: a write changed the files.
    pub fn invalidate(&self) {
        self.shared.lock().stale = true;
    }

    /// The count for a read of the usage. It starts a walk when the count is old and no walk runs. While a walk
    /// runs, the count is its progress: `computing`, at least these bytes.
    pub fn snapshot(&self) -> SizeCount {
        let mut state = self.shared.lock();
        let expired = state.counted.is_none_or(|counted| counted.elapsed() >= SIZE_TTL);
        let old = state.last.state == SizeState::None || state.stale || expired;
        if old && !state.running {
            state.running = true;
            state.stale = false;
            state.progress = SizeCount {
                state: SizeState::Computing,
                at: Some(Timestamp::now()),
                ..SizeCount::default()
            };
            let shared = Arc::clone(&self.shared);
            let started = std::thread::Builder::new()
                .name("volume-size".to_owned())
                .spawn(move || walk(&shared));
            if started.is_err() {
                // No thread: the count stays unknown, and the next read tries again.
                state.running = false;
                state.stale = true;
            }
        }
        if state.running { state.progress } else { state.last }
    }

    /// The number of walks that ended. A test reads it before a change, and waits for a larger number.
    #[cfg(test)]
    pub fn walks(&self) -> u64 {
        self.shared.lock().finished
    }

    /// Wait until the number of walks that ended is larger than `walks`.
    #[cfg(test)]
    pub fn wait_after(&self, walks: u64) {
        let mut state = self.shared.lock();
        let deadline = Instant::now() + Duration::from_secs(30);
        while state.finished <= walks {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            state = self
                .shared
                .ended
                .wait_timeout(state, left)
                .map(|(guard, _)| guard)
                .unwrap_or_else(|poisoned| poisoned.into_inner().0);
        }
    }
}

/// Why a walk stopped before its end.
enum Stop {
    Budget,
}

/// Count the files of the root and keep the count.
fn walk(shared: &SizerShared) {
    let deadline = Instant::now() + shared.timeout;
    let mut visited = 0i64;
    let mut count = SizeCount {
        state: SizeState::Computing,
        ..SizeCount::default()
    };
    let result = walk_folders(shared, deadline, &mut visited, &mut count);
    count.at = Some(Timestamp::now());
    count.state = if result.is_err() {
        SizeState::Partial
    } else {
        SizeState::Ready
    };
    let mut state = shared.lock();
    state.last = count;
    state.running = false;
    state.counted = Some(Instant::now());
    state.finished += 1;
    drop(state);
    shared.ended.notify_all();
}

fn report(shared: &SizerShared, count: &SizeCount) {
    shared.lock().progress = SizeCount {
        bytes: count.bytes,
        files: count.files,
        state: SizeState::Computing,
        at: Some(Timestamp::now()),
    };
}

/// Walk the tree with a stack of folders: no folder depth can use up the stack of the thread.
fn walk_folders(shared: &SizerShared, deadline: Instant, visited: &mut i64, count: &mut SizeCount) -> Result<(), Stop> {
    let mut folders = vec![shared.root.clone()];
    while let Some(real) = folders.pop() {
        // A folder that the process cannot read counts nothing: the count stays complete for what it can read.
        let Ok(reader) = fs::read_dir(&real) else {
            continue;
        };
        for item in reader {
            let Ok(item) = item else {
                break;
            };
            if Instant::now() >= deadline {
                return Err(Stop::Budget);
            }
            *visited += 1;
            if *visited > shared.entries {
                return Err(Stop::Budget);
            }
            if *visited % PROGRESS_STEP == 0 {
                report(shared, count);
            }
            let Ok(kind) = item.file_type() else {
                continue;
            };
            if kind.is_dir() {
                folders.push(item.path());
            } else if kind.is_file() {
                if item
                    .file_name()
                    .to_str()
                    .is_some_and(|name| parse_temporary_name(name).is_some())
                {
                    continue;
                }
                if let Ok(info) = item.metadata() {
                    count.bytes = count
                        .bytes
                        .saturating_add(i64::try_from(info.len()).unwrap_or(i64::MAX));
                    count.files += 1;
                }
            }
        }
        report(shared, count);
    }
    Ok(())
}
