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
    pub vm: CachedVm,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CachedVm {
    Qemu {},
    Tart {},
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedArtifact {
    /// Just the name of the file, not its path.
    filename: String,
    kind: ArtifactKind,
    /// Cheap integrity marker for the artifact. See [`file_marker`]. Not a content hash.
    marker: String,
}

impl CachedArtifact {}

#[derive(Debug, Clone, Serialize, Deserialize)]
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

// TESTS

#[cfg(test)]
mod fingerprint_tests {
    use super::{super::image_id, super::parse_max_age, Fingerprint, file_marker};
    use crate::global_paths::TargetPath;
    use crate::util::cpu_arch::Arch;
    use crate::vm_image::{BackendConfig, GuestOs, ImageDescription, QemuConfig, SshConfig};
    use std::path::{Path, PathBuf};

    fn tp(p: &Path) -> TargetPath {
        TargetPath {
            path: p.to_path_buf(),
            #[cfg(target_os = "windows")]
            wsl_distro: None,
        }
    }

    /// Fresh scratch dir under the gitignored `.ci/temp/`, matching the per-test isolation the
    /// system tests in `tests/` use.
    fn scratch(tag: &str) -> PathBuf {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(".ci/temp")
            .join(format!("cache_meta_unit_{tag}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn qemu_image(name: &str, disk: &str, arch: Arch) -> ImageDescription {
        ImageDescription {
            name: name.to_string(),
            os: GuestOs::Linux,
            arch,
            backend: BackendConfig::Qemu(QemuConfig {
                image: disk.to_string(),
                uefi: None,
                cpu_model: None,
                additional_drives: None,
                additional_devices: None,
                tpm: false,
                nvme: false,
                readonly_isos: None,
            }),
            ssh: SshConfig {
                user: "root".to_string(),
                pass: None,
                key: None,
            },
            managed: None,
            remote: None,
            #[cfg(target_os = "windows")]
            wsl_distro: None,
        }
    }

    #[test]
    fn image_id_is_stable_and_distinct() {
        let a = image_id(&qemu_image("ubuntu", "/img/a.qcow2", Arch::X64));
        assert_eq!(
            a,
            image_id(&qemu_image("ubuntu", "/img/a.qcow2", Arch::X64))
        );
        assert_ne!(
            a,
            image_id(&qemu_image("ubuntu", "/img/b.qcow2", Arch::X64))
        );
        assert_ne!(
            a,
            image_id(&qemu_image("fedora", "/img/a.qcow2", Arch::X64))
        );
        assert_ne!(
            a,
            image_id(&qemu_image("ubuntu", "/img/a.qcow2", Arch::ARM64))
        );
        assert_eq!(a.len(), super::super::SHORT_HASH_LEN);
    }

    #[test]
    fn max_age_units() {
        assert_eq!(parse_max_age("7").unwrap(), 7 * 86400);
        assert_eq!(parse_max_age("30s").unwrap(), 30);
        assert_eq!(parse_max_age("15M").unwrap(), 15 * 60);
        assert_eq!(parse_max_age("2h").unwrap(), 2 * 3600);
        assert_eq!(parse_max_age("3D").unwrap(), 3 * 86400);
        assert_eq!(parse_max_age(" 1d ").unwrap(), 86400);
    }

    #[test]
    fn max_age_rejects_garbage() {
        assert!(parse_max_age("").is_err());
        assert!(parse_max_age("abc").is_err());
        assert!(parse_max_age("10x").is_err());
        assert!(parse_max_age("d").is_err());
    }

    #[test]
    fn fingerprint_captures_config_in_order_and_hashes_env() {
        // SAFETY: single-threaded test; set a known env var to assert it's hashed (not stored).
        unsafe {
            std::env::set_var("VCI_CACHE_TEST_ENV", "secret-value");
        }
        let cfg = crate::yaml::Cache {
            files_modified: vec![
                "does-not-exist-a".to_string(),
                "does-not-exist-b".to_string(),
            ],
            files_list: vec![],
            run: Some("test -d .".to_string()),
            env: vec![
                "VCI_CACHE_TEST_ENV".to_string(),
                "VCI_CACHE_TEST_UNSET".to_string(),
            ],
            no_write_cache: false,
            max_age: None,
        };

        let root = scratch("capture_env");
        let fp = Fingerprint::capture(
            &cfg,
            &tp(&root),
            "wfhash".to_string(),
            Some("123:456".to_string()),
        );

        assert_eq!(fp.workflow_hash, "wfhash");
        assert_eq!(fp.base_image_marker.as_deref(), Some("123:456"));
        assert_eq!(fp.run.as_deref(), Some("test -d ."));

        // Order preserved, missing files flagged.
        let paths: Vec<&str> = fp.files_modified.iter().map(|i| i.input.as_str()).collect();
        assert_eq!(paths, ["does-not-exist-a", "does-not-exist-b"]);
        assert!(fp.files_modified.iter().all(|i| i.hash == "missing"));

        // Env: set var is hashed (never the raw value), unset var is flagged.
        assert_eq!(fp.env[0].input, "VCI_CACHE_TEST_ENV");
        assert_ne!(fp.env[0].hash, "secret-value");
        assert_ne!(fp.env[0].hash, "unset");
        assert_eq!(fp.env[1].hash, "unset");

        unsafe {
            std::env::remove_var("VCI_CACHE_TEST_ENV");
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn capture_hashes_present_file_relative_to_root() {
        let root = scratch("capture_present");
        std::fs::write(root.join("f.txt"), b"content").unwrap();
        let cfg = crate::yaml::Cache {
            files_modified: vec!["f.txt".to_string()],
            ..Default::default()
        };

        let fp = Fingerprint::capture(&cfg, &tp(&root), "wf".to_string(), None);

        assert_eq!(fp.files_modified[0].input, "f.txt");
        assert_ne!(
            fp.files_modified[0].hash, "missing",
            "a present file resolved under root_dir is hashed, not flagged missing"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn file_marker_is_length_and_mtime() {
        let root = scratch("marker");
        let f = root.join("art");
        std::fs::write(&f, b"0123456789").unwrap(); // 10 bytes

        let marker = file_marker(&tp(&f)).unwrap();
        let (len, mtime) = marker.split_once(':').expect("marker is `len:mtime`");
        assert_eq!(len, "10");
        assert!(mtime.parse::<u64>().is_ok(), "mtime is unix seconds");

        let _ = std::fs::remove_dir_all(&root);
    }
}
