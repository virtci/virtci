// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

//! Keeps the long-term cache within the user's disk limits by evicting least-recently-used slots.
//!
//! Two independent limits, both interpreted as GiB (`×1024³`):
//! - `VIRTCI_CACHE_BUDGET_GB` — a hard cap on the cache set's own on-disk size. Unset or `0` = no
//!   cap.
//! - `VIRTCI_CACHE_RETAIN_GB` — a floor on the cache filesystem's *free* space. Unset = a sensible
//!   tiered default scaled to the disk (the safety net that protects users who never touch a knob);
//!   `0` = disabled; a positive value = that floor exactly.
//!
//! Recency is the mtime of each slot's `cache.json`, touched on every consume (see [`touch_slot`]).
//! Eviction takes each candidate slot's *exclusive* flock (the same protocol the orphan reaper
//! uses), so a live consumer holding the shared lock or a producer mid-write is never deleted — it
//! is skipped, best effort, and the next-oldest slot is tried instead.

use std::path::Path;

use crate::file_lock::FileLock;
use crate::global_paths::TargetPath;

use super::disk_usage;
use super::metadata::CacheMetadata;
use super::slot_lock_filename;

const GIB: u64 = 1024 * 1024 * 1024;

/// Disk usage limits for the long-term cache, resolved from the environment. `None` means that
/// limit is off.
#[derive(Debug, Clone, Copy, Default)]
pub struct CacheLimits {
    pub budget_bytes: Option<u64>,
    pub retain_bytes: Option<u64>,
}

impl CacheLimits {
    /// Resolve limits for the cache rooted at `cache_root` from the environment, computing the
    /// default retain floor from that filesystem's total capacity when the knob is unset.
    pub fn from_env(cache_root: &TargetPath) -> Self {
        let budget_bytes = match parse_gb_env("VIRTCI_CACHE_BUDGET_GB") {
            // Unset or an explicit 0 both mean "no size cap".
            None | Some(0) => None,
            Some(gb) => Some(gb.saturating_mul(GIB)),
        };

        let retain_bytes = match parse_gb_env("VIRTCI_CACHE_RETAIN_GB") {
            // Explicit 0 disables the floor.
            Some(0) => None,
            Some(gb) => Some(gb.saturating_mul(GIB)),
            // Unset: fall back to the tiered default so there is always a backstop.
            None => default_retain_bytes(cache_root),
        };

        Self {
            budget_bytes,
            retain_bytes,
        }
    }

    fn is_off(&self) -> bool {
        self.budget_bytes.is_none() && self.retain_bytes.is_none()
    }
}

/// Default free-space floor when `VIRTCI_CACHE_RETAIN_GB` is unset: 1/8 of total disk below ~2 TB,
/// 1/16 at or above it. The 1800 GiB threshold sits in the gap between a "1 TB" (~931 GiB) and a
/// "2 TB" (~1862 GiB) drive, so the tier is robust to GiB/GB reporting differences. `None` when the
/// disk can't be measured (no basis for a fraction, so no floor).
fn default_retain_bytes(cache_root: &TargetPath) -> Option<u64> {
    const THRESHOLD_BYTES: u64 = 1800 * GIB;
    let total = disk_usage::filesystem_total_bytes(cache_root)?;
    let divisor = if total < THRESHOLD_BYTES { 8 } else { 16 };
    Some(total / divisor)
}

/// Parse an integer-GB environment variable. Lenient like the rest of virtci's env handling: an
/// unparseable value warns and is treated as unset (`None`).
fn parse_gb_env(name: &str) -> Option<u64> {
    let raw = std::env::var(name).ok()?;
    match raw.trim().parse::<u64>() {
        Ok(gb) => Some(gb),
        Err(_) => {
            eprintln!(
                "VirtCI Warning: ignoring invalid {name}={raw:?} (want an integer number of GB)."
            );
            None
        }
    }
}

/// Would a cache of `cache_size` bytes, with `free_after` bytes free on its filesystem, and
/// `incoming` additional bytes about to be retained, satisfy `limits`? Pure so the arithmetic is
/// unit-testable without touching a real disk.
fn fits(cache_size: u64, free_after: Option<u64>, incoming: u64, limits: &CacheLimits) -> bool {
    let budget_ok = limits
        .budget_bytes
        .is_none_or(|budget| cache_size.saturating_add(incoming) <= budget);
    let retain_ok = match (limits.retain_bytes, free_after) {
        (Some(retain), Some(free)) => free >= retain,
        // Can't measure free space: don't evict for a floor we can't check.
        (Some(_), None) => true,
        (None, _) => true,
    };
    budget_ok && retain_ok
}

/// A committed cache slot: a leaf directory holding a `cache.json`.
struct SlotEntry {
    dir: TargetPath,
    /// Path relative to the cache root, `/`-joined — the key both the writer and the reaper hash
    /// into the slot's lock filename.
    rel: String,
    /// mtime of `cache.json`, in unix seconds. The LRU clock.
    mtime: u64,
    /// Allocated (on-disk) size of the whole slot.
    size: u64,
}

/// Enforce `limits` on the cache at `cache_root` by evicting least-recently-used slots. Best effort:
/// a slot whose exclusive lock can't be taken (in use) is skipped. `host_temp` is where the slot
/// flocks live (the host temp dir, never the cache drive).
pub fn enforce_limits(cache_root: &TargetPath, host_temp: &Path, limits: &CacheLimits) {
    if limits.is_off() {
        return;
    }
    evict_to_fit(cache_root, host_temp, limits, 0);
}

/// Decide, at produce time, whether a freshly-produced slot of `incoming_bytes` may be retained,
/// evicting older slots to make room first. Returns `true` if it fits (the caller should commit),
/// `false` if it must be skipped to respect the limits.
///
/// The incoming bytes already occupy the staging area on the same filesystem, so committing is a
/// rename that doesn't change free space; *not* caching is what lets the reaper reclaim them. Hence
/// a single fresh slot larger than the whole budget, or one that would hold free space below the
/// retain floor even after evicting everything evictable, is refused.
pub fn make_room_for(
    cache_root: &TargetPath,
    host_temp: &Path,
    limits: &CacheLimits,
    incoming_bytes: u64,
) -> bool {
    // A single slot bigger than the entire budget can never be retained.
    if let Some(budget) = limits.budget_bytes
        && incoming_bytes > budget
    {
        return false;
    }
    if limits.is_off() {
        return true;
    }
    evict_to_fit(cache_root, host_temp, limits, incoming_bytes)
}

/// Shared core: evict oldest-first until the cache (plus `incoming` about-to-be-added bytes) fits
/// `limits`, then report whether it actually fits. Used with `incoming = 0` for plain enforcement.
fn evict_to_fit(
    cache_root: &TargetPath,
    host_temp: &Path,
    limits: &CacheLimits,
    incoming: u64,
) -> bool {
    let mut slots = collect_slots(cache_root);
    slots.sort_by_key(|s| s.mtime); // oldest first

    let mut cache_size: u64 = slots.iter().map(|s| s.size).sum();
    let mut free_after = disk_usage::filesystem_avail_bytes(cache_root);

    for slot in &slots {
        if fits(cache_size, free_after, incoming, limits) {
            break;
        }
        if evict_slot(slot, host_temp) {
            cache_size = cache_size.saturating_sub(slot.size);
            // Reclaimed bytes raise the filesystem's free space.
            if let Some(free) = free_after.as_mut() {
                *free = free.saturating_add(slot.size);
            }
        }
        // A locked slot (in use) just gets skipped; move on to the next oldest.
    }

    fits(cache_size, free_after, incoming, limits)
}

/// Delete a slot after taking its exclusive flock. Returns whether it was actually removed (a slot
/// held by a live consumer/producer can't be locked and is left alone).
fn evict_slot(slot: &SlotEntry, host_temp: &Path) -> bool {
    let lock_path = host_temp.join(slot_lock_filename(&slot.rel));
    let Ok(lock) = FileLock::try_new(&lock_path) else {
        return false;
    };
    let removed = std::fs::remove_dir_all(&slot.dir.path).is_ok();
    let _ = std::fs::remove_file(lock.get_path());
    drop(lock);
    removed
}

/// Walk `cache_root` and collect every committed slot (a directory containing `cache.json`). Slots
/// are leaves, so recursion stops at one.
fn collect_slots(cache_root: &TargetPath) -> Vec<SlotEntry> {
    let mut slots = Vec::new();
    collect_into(cache_root, &cache_root.path, &mut slots);
    slots
}

fn collect_into(cache_root: &TargetPath, dir: &Path, out: &mut Vec<SlotEntry>) {
    let cache_json = dir.join(CacheMetadata::FILENAME);
    if cache_json.exists() {
        let Ok(rel) = dir.strip_prefix(&cache_root.path) else {
            return;
        };
        let rel = rel.to_string_lossy().replace('\\', "/");
        let dir_target = TargetPath {
            path: dir.to_path_buf(),
            #[cfg(target_os = "windows")]
            wsl_distro: cache_root.wsl_distro.clone(),
        };
        out.push(SlotEntry {
            mtime: mtime_secs(&cache_json).unwrap_or(0),
            size: disk_usage::path_allocated_bytes(&dir_target),
            rel,
            dir: dir_target,
        });
        return;
    }

    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if entry.path().is_dir() {
            collect_into(cache_root, &entry.path(), out);
        }
    }
}

fn mtime_secs(path: &Path) -> Option<u64> {
    std::fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

/// Mark a slot as just-used by bumping its `cache.json` mtime — the LRU recency signal. Best effort:
/// a failure only costs a slightly-stale recency ordering, never correctness.
pub fn touch_slot(slot: &TargetPath) {
    let cache_json = slot.join(CacheMetadata::FILENAME);
    if let Ok(file) = std::fs::OpenOptions::new()
        .write(true)
        .open(&cache_json.path)
    {
        let _ = file.set_modified(std::time::SystemTime::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::cache::metadata::{CACHE_FORMAT_VERSION, CachedVm, Fingerprint};
    use crate::run::cache::{slot_dir, slot_rel};
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime};

    fn tp(p: PathBuf) -> TargetPath {
        TargetPath {
            path: p,
            #[cfg(target_os = "windows")]
            wsl_distro: None,
        }
    }

    fn scratch(tag: &str) -> PathBuf {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(".ci/temp")
            .join(format!("cache_lru_{tag}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Create a committed slot with `bytes` of disk content and a specific `cache.json` mtime (unix
    /// secs) so tests control the LRU ordering deterministically.
    fn make_slot(cache_root: &TargetPath, job: &str, bytes: usize, mtime: u64) {
        let slot = slot_dir(cache_root, "ns", job, "img");
        std::fs::create_dir_all(&slot.path).unwrap();
        std::fs::write(&slot.join("disk.qcow2").path, vec![0u8; bytes]).unwrap();
        let meta = CacheMetadata {
            format_version: CACHE_FORMAT_VERSION,
            namespace: "ns".to_string(),
            job: job.to_string(),
            image_id: "img".to_string(),
            created_at: mtime,
            ttl_secs: None,
            fingerprint: Fingerprint::default(),
            vm: CachedVm::Qemu { artifacts: vec![] },
        };
        meta.write_into_slot(&slot).unwrap();
        let cache_json = slot.join(CacheMetadata::FILENAME);
        let when = SystemTime::UNIX_EPOCH + Duration::from_secs(mtime);
        std::fs::OpenOptions::new()
            .write(true)
            .open(&cache_json.path)
            .unwrap()
            .set_modified(when)
            .unwrap();
    }

    #[test]
    fn fits_enforces_budget_and_retain_independently() {
        let budget_only = CacheLimits {
            budget_bytes: Some(100),
            retain_bytes: None,
        };
        assert!(fits(80, Some(0), 0, &budget_only), "under budget");
        assert!(fits(80, Some(0), 20, &budget_only), "exactly at budget");
        assert!(
            !fits(80, Some(0), 21, &budget_only),
            "incoming busts budget"
        );

        let retain_only = CacheLimits {
            budget_bytes: None,
            retain_bytes: Some(50),
        };
        assert!(fits(u64::MAX, Some(50), 0, &retain_only), "free at floor");
        assert!(!fits(0, Some(49), 0, &retain_only), "free below floor");
        assert!(
            fits(0, None, 0, &retain_only),
            "unmeasurable free never forces eviction"
        );
    }

    #[test]
    fn budget_evicts_oldest_first_under_lock() {
        let root = tp(scratch("budget"));
        let host_temp = scratch("budget_locks");

        // Three slots, oldest -> newest, each ~8 KiB on disk.
        make_slot(&root, "old", 8192, 1000);
        make_slot(&root, "mid", 8192, 2000);
        make_slot(&root, "new", 8192, 3000);

        let one = disk_usage::path_allocated_bytes(&slot_dir(&root, "ns", "new", "img"));
        // Budget that fits only the single newest slot.
        let limits = CacheLimits {
            budget_bytes: Some(one),
            retain_bytes: None,
        };
        enforce_limits(&root, &host_temp, &limits);

        assert!(
            !slot_dir(&root, "ns", "old", "img").path.exists(),
            "oldest evicted"
        );
        assert!(
            !slot_dir(&root, "ns", "mid", "img").path.exists(),
            "next-oldest evicted"
        );
        assert!(
            slot_dir(&root, "ns", "new", "img").path.exists(),
            "newest (most-recently-used) survives"
        );

        let _ = std::fs::remove_dir_all(&root.path);
        let _ = std::fs::remove_dir_all(&host_temp);
    }

    #[test]
    fn a_locked_slot_is_skipped_and_the_next_oldest_goes() {
        let root = tp(scratch("locked"));
        let host_temp = scratch("locked_locks");

        make_slot(&root, "old", 8192, 1000);
        make_slot(&root, "mid", 8192, 2000);
        make_slot(&root, "new", 8192, 3000);

        // A live consumer holds the oldest slot's shared lock: it must not be evicted.
        let old_rel = slot_rel("ns", "old", "img");
        let old_lock = host_temp.join(slot_lock_filename(&old_rel));
        let Ok(held) = FileLock::try_new_shared(&old_lock) else {
            panic!("take shared lock on oldest");
        };

        // Budget fits a single slot; eviction should skip the locked oldest and take "mid" instead.
        let one = disk_usage::path_allocated_bytes(&slot_dir(&root, "ns", "new", "img"));
        let limits = CacheLimits {
            budget_bytes: Some(one),
            retain_bytes: None,
        };
        enforce_limits(&root, &host_temp, &limits);

        assert!(
            slot_dir(&root, "ns", "old", "img").path.exists(),
            "locked oldest is skipped, not deleted"
        );
        assert!(
            !slot_dir(&root, "ns", "mid", "img").path.exists(),
            "next-oldest evictable slot is taken instead"
        );

        drop(held);
        let _ = std::fs::remove_dir_all(&root.path);
        let _ = std::fs::remove_dir_all(&host_temp);
    }

    #[test]
    fn make_room_for_refuses_a_slot_bigger_than_budget() {
        let root = tp(scratch("oversized"));
        let host_temp = scratch("oversized_locks");
        let limits = CacheLimits {
            budget_bytes: Some(10 * GIB),
            retain_bytes: None,
        };
        assert!(
            !make_room_for(&root, &host_temp, &limits, 11 * GIB),
            "a single fresh slot over the budget is refused"
        );
        assert!(
            make_room_for(&root, &host_temp, &limits, 5 * GIB),
            "a slot within budget on an empty cache is accepted"
        );
        let _ = std::fs::remove_dir_all(&root.path);
        let _ = std::fs::remove_dir_all(&host_temp);
    }

    #[test]
    fn touch_slot_advances_recency() {
        let root = tp(scratch("touch"));
        make_slot(&root, "job", 1024, 1000);
        let slot = slot_dir(&root, "ns", "job", "img");
        let before = mtime_secs(&slot.join(CacheMetadata::FILENAME).path).unwrap();
        touch_slot(&slot);
        let after = mtime_secs(&slot.join(CacheMetadata::FILENAME).path).unwrap();
        assert!(after > before, "touch bumps cache.json mtime (recency)");
        let _ = std::fs::remove_dir_all(&root.path);
    }

    #[test]
    fn from_env_default_retain_scales_to_the_disk() {
        // With the knob unset, a real floor is derived from the disk holding the temp dir.
        let root = tp(scratch("env_default"));
        // SAFETY: single-threaded unit test.
        unsafe {
            std::env::remove_var("VIRTCI_CACHE_RETAIN_GB");
            std::env::remove_var("VIRTCI_CACHE_BUDGET_GB");
        }
        let limits = CacheLimits::from_env(&root);
        assert!(
            limits.retain_bytes.is_some_and(|r| r > 0),
            "unset retain yields a positive tiered default"
        );
        assert!(limits.budget_bytes.is_none(), "unset budget means no cap");
        let _ = std::fs::remove_dir_all(&root.path);
    }
}
