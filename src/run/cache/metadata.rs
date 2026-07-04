// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::time::UNIX_EPOCH;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::{global_paths::TargetPath, yaml};

/// On-disk metadata format version. Bump on any breaking change to [`CacheMetadata`] so a cache
/// written by an older virtci is treated as a miss rather than misread.
pub const CACHE_FORMAT_VERSION: u32 = 1;

/// Persisted metadata describing a workflow cache, written alongside the disk (QEMU overlay) in
/// the slot. The run will compare against this, so the format needs to be consistent.
/// Bump [`CACHE_FORMAT_VERSION`] on a breaking schema change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMetadata {
    pub format_version: u32,
    pub namespace: String,
    pub job: String,
    pub image_id: String,
    /// Unix seconds when this artifact was written.
    pub created_at: u64,
    /// TTL in seconds from `created_at`, if `cache.max_age` was set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    /// Disk artifact filename within the slot (e.g. `disk.qcow2`).
    pub disk_artifact: String,
    /// blake3 of the persisted disk artifact, for future integrity/verification on consume.
    pub disk_hash: String,
    /// Captured invalidation inputs (the consume side recomputes the live values and compares).
    pub fingerprint: Fingerprint,
}

pub enum CachedVm {
    Qemu {},
    Tart {},
}

pub struct CachedArtifact {
    /// Just the name of the file, not its path.
    filename: String,
    kind: ArtifactKind,
    /// Cheap integrity marker for the artifact. See [`file_marker`]. Not a content hash.
    marker: String,
}

impl CachedArtifact {}

pub enum ArtifactKind {}

/// Snapshot of every input that can invalidate a cache, captured when the cache is produced.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Fingerprint {
    /// blake3 of the workflow YAML (whole file).
    pub workflow_hash: String,
    /// Cheap identity (`<len>:<mtime_secs`) of the base image. Since QEMU can use overlays,
    /// this ensures integrity of the base qcow2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_image_marker: Option<String>,
    /// file path -> blake3(contents). If the file isn't present, use `"missing"` when CREATING
    /// the cache.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files_modified: Vec<InputHash>,
    /// Glob -> blake3(sorted matching paths). Tracks any files added / removed.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files_list: Vec<InputHash>,
    /// var name -> blake3(value). Values are hashed, never stored, since they may be
    /// secrets. unset variables record `"unset"`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<InputHash>,
    /// The run command as is. It's re-executed on consume.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run: Option<String>,
}

impl Fingerprint {
    /// Best effort to get every possible invalidation input. Any failure just leaves a sentinel.
    pub fn capture(
        cfg: &yaml::Cache,
        root_dir: &TargetPath,
        workflow_hash: String,
        base_image_marker: Option<String>,
    ) -> Self {
        let files_modified = cfg
            .files_modified
            .iter()
            .map(|path: &String| InputHash {
                input: path.clone(),
                // Resolve each configured file relative to the run's working dir; `join` carries the
                // WSL distro through so a WSL2 repo file is hashed inside the distro via `wsl cat`.
                hash: super::file::hash_file(&root_dir.join(path))
                    .unwrap_or_else(|_| "missing".to_string()),
            })
            .collect();

        let files_list = cfg
            .files_list
            .iter()
            .map(|pattern| InputHash {
                input: pattern.clone(),
                hash: super::file::hash_file_list(root_dir, pattern),
            })
            .collect();

        let env = cfg
            .env
            .iter()
            .map(|name| InputHash {
                input: name.clone(),
                hash: match std::env::var(name) {
                    Ok(value) => super::short_hash(value.as_bytes()),
                    Err(_) => "unset".to_string(),
                },
            })
            .collect();

        Fingerprint {
            workflow_hash,
            base_image_marker,
            files_modified,
            files_list,
            env,
            run: cfg.run.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputHash {
    /// For a modified file, it's path.
    /// For a files list, the glob pattern / directory / etc.
    /// For environment variables, just the name, never the value.
    pub input: String,
    /// For a modified file, it's blake3 hashed contents.
    /// For a files list, all the files matched by the glob pattern / directory / etc.
    /// For environment variables, hash of the value.
    pub hash: String,
}

/// A cheap integrity marker for a cached VM artifact: `<byte-length>:<mtime-unix-secs>`.
/// A full content hash is deliberately avoided. These artifacts can be many gigabytes, and hashing
/// their contents would cost a full read on every write nand every consume-time verification.
/// Not really worth a full read.
/// `std::fs::metadata` reads through the `\\wsl.localhost\<distro>\...` UNC path, so a WSL2 artifact
/// needs no shelling into the distro.
pub fn file_marker(path: &TargetPath) -> anyhow::Result<String> {
    let meta: std::fs::Metadata = std::fs::metadata(&path.path)
        .with_context(|| format!("file to stat cache artifact {}", path.path.display()))?;
    let mtime = meta
        .modified()
        .context("file mtime unavailable")?
        .duration_since(UNIX_EPOCH)
        .context("file mtime is before the unix epoch")?
        .as_secs();

    Ok(format!("{}:{mtime}", meta.len()))
}
