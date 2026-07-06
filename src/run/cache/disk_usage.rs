// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

//! Cross-platform disk accounting for the cache: free/total space of the filesystem holding the
//! cache, and the *allocated* (on-disk, sparse-aware) size of cache slots.
//!
//! Where the cache lives on a locally-mounted filesystem we go through native calls
//! (`statvfs` / `GetDiskFreeSpaceExW`, and `st_blocks` via std / `GetCompressedFileSizeW`). The WSL2
//! cache lives *inside the distro* on ext4, which the Windows host can only see through the 9p
//! `\\wsl.localhost\...` bridge where those calls report the bridge, not the real ext4 numbers, so
//! for that case we shell into the distro with `df` / `du` instead.

use std::path::Path;

use crate::global_paths::TargetPath;

unsafe extern "C" {
    /// `src/run/cache/disk_usage.c`. Bytes available to a non-root user, or -1 on error.
    fn vci_fs_avail_bytes_native(path: *const u8, path_len: usize) -> i64;
    /// `src/run/cache/disk_usage.c`. Total bytes of the filesystem, or -1 on error.
    fn vci_fs_total_bytes_native(path: *const u8, path_len: usize) -> i64;
    /// `src/run/cache/disk_usage.c`. Allocated (on-disk) size of a single file, or -1 on error.
    #[cfg(target_os = "windows")]
    fn vci_file_allocated_bytes_native(path: *const u8, path_len: usize) -> i64;
}

/// Bytes available (to this user) on the filesystem that holds `path`. `None` if it can't be
/// measured. Resolves to the nearest existing ancestor so it still works before `.cache` exists.
pub fn filesystem_avail_bytes(path: &TargetPath) -> Option<u64> {
    fs_query(path, Query::Avail)
}

/// Total capacity of the filesystem that holds `path`. `None` if it can't be measured.
pub fn filesystem_total_bytes(path: &TargetPath) -> Option<u64> {
    fs_query(path, Query::Total)
}

/// Allocated (on-disk, sparse-aware) bytes of a file or directory tree. Thin qcow2 overlays report
/// far less here than their logical length, which is exactly what we want to budget against. `0`
/// if it can't be read (best effort).
pub fn path_allocated_bytes(path: &TargetPath) -> u64 {
    #[cfg(target_os = "windows")]
    if let Some(distro) = &path.wsl_distro {
        return wsl_du_bytes(distro, &path.native_path()).unwrap_or(0);
    }

    if path.path.is_dir() {
        walk_allocated(&path.path)
    } else {
        file_allocated_native(&path.path)
    }
}

#[derive(Clone, Copy)]
enum Query {
    Avail,
    Total,
}

fn fs_query(path: &TargetPath, query: Query) -> Option<u64> {
    // statvfs/GetDiskFreeSpaceExW/df all need an existing path; walk up until one exists so the
    // query works even before the cache directory itself has been created.
    let target = existing_ancestor(path);

    #[cfg(target_os = "windows")]
    if let Some(distro) = &target.wsl_distro {
        return wsl_df_bytes(distro, &target.native_path(), query);
    }

    let s = target.path.to_string_lossy();
    let bytes = s.as_bytes();
    let result = unsafe {
        match query {
            Query::Avail => vci_fs_avail_bytes_native(bytes.as_ptr(), bytes.len()),
            Query::Total => vci_fs_total_bytes_native(bytes.as_ptr(), bytes.len()),
        }
    };
    (result >= 0).then_some(result as u64)
}

/// The nearest ancestor of `path` (including itself) that exists on disk. `stat` works fine over a
/// `\\wsl.localhost\...` UNC path, so this is correct for WSL targets too.
fn existing_ancestor(path: &TargetPath) -> TargetPath {
    let mut current = path.clone();
    loop {
        if current.path.exists() {
            return current;
        }
        match current.path.parent() {
            Some(parent) => {
                current = TargetPath {
                    path: parent.to_path_buf(),
                    #[cfg(target_os = "windows")]
                    wsl_distro: path.wsl_distro.clone(),
                }
            }
            None => return current,
        }
    }
}

/// Recursively sum the allocated size of every regular file under `dir`.
fn walk_allocated(dir: &Path) -> u64 {
    let mut total = 0u64;
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    for entry in entries.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            total = total.saturating_add(walk_allocated(&entry.path()));
        } else if file_type.is_file() {
            total = total.saturating_add(file_allocated_native(&entry.path()));
        }
    }
    total
}

#[cfg(not(target_os = "windows"))]
fn file_allocated_native(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    // `st_blocks` counts 512-byte blocks actually allocated, so a sparse/thin file measures its
    // real on-disk footprint rather than its logical length.
    std::fs::symlink_metadata(path).map_or(0, |m| m.blocks().saturating_mul(512))
}

#[cfg(target_os = "windows")]
fn file_allocated_native(path: &Path) -> u64 {
    let s = path.to_string_lossy();
    let bytes = s.as_bytes();
    let result = unsafe { vci_file_allocated_bytes_native(bytes.as_ptr(), bytes.len()) };
    if result >= 0 {
        result as u64
    } else {
        // Fall back to logical length; over-counts thin overlays but never under-counts, so limits
        // still hold (we just evict slightly earlier).
        std::fs::metadata(path).map_or(0, |m| m.len())
    }
}

/// Parse the "available"/"total" byte count for a path from `df` run inside a WSL2 distro.
/// `-P` gives the stable POSIX one-line-per-fs format; `-B1` reports raw bytes.
#[cfg(target_os = "windows")]
fn wsl_df_bytes(distro: &str, in_distro_path: &str, query: Query) -> Option<u64> {
    let output = std::process::Command::new("wsl")
        .args(["-d", distro, "--", "df", "-P", "-B1", in_distro_path])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Skip the header; the data row is: Filesystem 1B-blocks Used Available Capacity Mounted-on.
    let fields: Vec<&str> = stdout.lines().nth(1)?.split_whitespace().collect();
    let idx = match query {
        Query::Total => 1,
        Query::Avail => 3,
    };
    fields.get(idx)?.parse::<u64>().ok()
}

/// Allocated size of a path inside a WSL2 distro via `du -s -B1` (summary, raw bytes). `du`
/// reports actual allocated blocks, matching the unix `st_blocks` path.
#[cfg(target_os = "windows")]
fn wsl_du_bytes(distro: &str, in_distro_path: &str) -> Option<u64> {
    let output = std::process::Command::new("wsl")
        .args(["-d", distro, "--", "du", "-s", "-B1", in_distro_path])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<u64>().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

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
            .join(format!("cache_disk_usage_{tag}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn filesystem_space_is_measurable_and_sane() {
        let root = scratch("space");
        let avail = filesystem_avail_bytes(&tp(root.clone())).expect("avail measurable");
        let total = filesystem_total_bytes(&tp(root.clone())).expect("total measurable");
        assert!(total > 0, "total capacity is positive");
        assert!(avail <= total, "available never exceeds total");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn avail_resolves_through_a_missing_leaf() {
        // Query a path that doesn't exist yet; it must resolve up to an existing ancestor.
        let root = scratch("missing_leaf");
        let missing = tp(root.join("does/not/exist/yet"));
        assert!(
            filesystem_avail_bytes(&missing).is_some(),
            "resolves to an existing ancestor filesystem"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn allocated_size_sums_a_tree_and_tracks_written_bytes() {
        let root = scratch("alloc");
        let empty = path_allocated_bytes(&tp(root.clone()));

        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("a.bin"), vec![0u8; 8192]).unwrap();
        std::fs::write(root.join("sub/b.bin"), vec![0u8; 8192]).unwrap();

        let after = path_allocated_bytes(&tp(root.clone()));
        assert!(
            after >= empty + 16384,
            "tree allocation grew by at least the written bytes (empty={empty}, after={after})"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
