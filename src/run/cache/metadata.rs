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
    /// Captured invalidation inputs (the consume side recomputes the live values and compares).
    pub fingerprint: Fingerprint,
    /// Backend-specific VM files.
    pub vm: CachedVm,
}

impl CacheMetadata {
    /// The metadata file in a cache slot is ALWAYS "cache.json". Note that this works cause the
    /// full cache slot path includes the workflow name.
    pub const FILENAME: &'static str = "cache.json";

    /// This writes the metadata into `slot_dir` as a JSON file [`CacheMetadata::FILENAME`].
    /// This MUST be after writing the actual artifacts.
    pub fn write_into_slot(&self, slot_dir: &TargetPath) -> anyhow::Result<()> {
        std::fs::create_dir_all(&slot_dir.path)
            .with_context(|| format!("failed to create cache slot {}", slot_dir.path.display()))?;

        let json =
            serde_json::to_string_pretty(self).context("failed to serialize cache metadata")?;
        let tmp = slot_dir.join("cache.json.tmp");
        std::fs::write(&tmp.path, json.as_bytes())
            .with_context(|| format!("failed to write {}", tmp.path.display()))?;

        tmp.atomic_file_rename(&slot_dir.join(Self::FILENAME))
            .context("failed to commit cache.json into the slot")
    }

    pub fn read_from_slot(slot_dir: &TargetPath) -> Option<Self> {
        let path = slot_dir.join(Self::FILENAME);
        let bytes = std::fs::read(&path.path).ok()?;
        let meta: Self = serde_json::from_slice(&bytes).ok()?;
        if meta.format_version != CACHE_FORMAT_VERSION {
            return None;
        }
        Some(meta)
    }

    /// Checks all artifacts are actually there.
    pub fn verify_artifacts(&self, slot_dir: &TargetPath) -> bool {
        match &self.vm {
            CachedVm::Qemu { artifacts } => artifacts
                .iter()
                .all(|a| file_marker(&slot_dir.join(&a.filename)).is_ok_and(|m| m == a.marker)),
            // Tart slots aren't produced yet, so nothing valid to consume.
            CachedVm::Tart {} => false,
        }
    }

    pub fn is_fresh_hit(&self, fresh: &Fingerprint, now_secs: u64) -> bool {
        if self.fingerprint != *fresh {
            return false;
        }
        match self.ttl_secs {
            Some(ttl) => now_secs <= self.created_at.saturating_add(ttl),
            None => true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CachedVm {
    Qemu { artifacts: Vec<QemuCachedArtifact> },
    Tart {},
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QemuCachedArtifact {
    /// Just the name of the file within the slot (e.g. `disk.qcow2`), never a path.
    pub filename: String,
    pub kind: QemuArtifactKind,
    /// Cheap integrity marker for the artifact. See [`file_marker`]. Not a content hash.
    pub marker: String,
}

/// The role a [`QemuCachedArtifact`] plays when a run is later reconstructed from the slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QemuArtifactKind {
    /// The main boot disk qcow2 overlay.
    Disk,
    /// The UEFI/OVMF variable store (`VARS.fd`).
    UefiVars,
    /// An additional `-drive` overlay. `index` matches the image's `additional_drives` ordering so
    /// the consume side can re-wire each drive to the right slot.
    AdditionalDrive { index: usize },
}

/// A artifact for QEMU that may be committed into the long term cache storage.
pub struct PlannedQemuArtifact {
    /// Artifact's current path. Must be on the same filesystem as the long term cache storage,
    /// so basically just the cache staging directory.
    pub source: TargetPath,
    pub kind: QemuArtifactKind,
    /// The name it takes within the slot (like `disk.qcow2`).
    pub filename: String,
}

/// Move each temp artifact into the cache `slot_dir` via an atomic rename and return the resulting
/// [`QemuCachedArtifact`] records.
/// This is done first, then [`CacheMetadata::write_into_slot`] after.
/// `slot_dir` must live in the same file system as the `planned` artifacts.
pub fn move_qemu_artifacts_into_slot(
    slot_dir: &TargetPath,
    planned: &[PlannedQemuArtifact],
) -> anyhow::Result<Vec<QemuCachedArtifact>> {
    let mut artifacts = Vec::with_capacity(planned.len());
    for art in planned {
        let dest = slot_dir.join(&art.filename);
        art.source.atomic_file_rename(&dest).with_context(|| {
            format!(
                "failed to move cache artifact {} -> {}",
                art.source.path.display(),
                dest.path.display()
            )
        })?;
        let marker = file_marker(&dest)
            .with_context(|| format!("failed to mark cache artifact {}", dest.path.display()))?;
        artifacts.push(QemuCachedArtifact {
            filename: art.filename.clone(),
            kind: art.kind,
            marker,
        });
    }
    Ok(artifacts)
}

/// Snapshot of every input that can invalidate a cache, captured when the cache is produced.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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
            env: vec![
                "VCI_CACHE_TEST_ENV".to_string(),
                "VCI_CACHE_TEST_UNSET".to_string(),
            ],
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

#[cfg(test)]
mod commit_tests {
    use super::super::slot_dir;
    use super::{
        CACHE_FORMAT_VERSION, CacheMetadata, CachedVm, Fingerprint, PlannedQemuArtifact,
        QemuArtifactKind, move_qemu_artifacts_into_slot,
    };
    use crate::global_paths::VciGlobalPaths;
    use std::path::PathBuf;

    fn test_paths(tag: &str) -> VciGlobalPaths {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join(".ci/temp")
            .join(format!("cache_commit_{tag}"));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        VciGlobalPaths {
            user_home: root.join("home"),
            system_home: root.join("system"),
            temp: root.join("temp"),
            #[cfg(target_os = "windows")]
            wsl: None,
        }
    }

    #[test]
    fn commit_moves_artifacts_into_the_slot_then_writes_metadata_last() {
        let paths = test_paths("full");
        let staging = paths.cache_staging_dir();
        let cache = paths.cache_dir();
        std::fs::create_dir_all(&staging.path).unwrap();

        let disk_src = staging.join("vci-job-00001.qcow2");
        let vars_src = staging.join("vci-job-00001-VARS.fd");
        std::fs::write(&disk_src.path, b"disk-bytes!").unwrap(); // 11 bytes
        std::fs::write(&vars_src.path, b"vars").unwrap();

        let planned = vec![
            PlannedQemuArtifact {
                source: disk_src.clone(),
                kind: QemuArtifactKind::Disk,
                filename: "disk.qcow2".to_string(),
            },
            PlannedQemuArtifact {
                source: vars_src.clone(),
                kind: QemuArtifactKind::UefiVars,
                filename: "vars.fd".to_string(),
            },
        ];

        let slot = slot_dir(&cache, "owner/repo/main", "job", "imgid123");
        let artifacts = move_qemu_artifacts_into_slot(&slot, &planned).unwrap();

        assert!(!disk_src.path.exists(), "disk source was moved, not copied");
        assert!(!vars_src.path.exists());
        assert!(slot.join("disk.qcow2").path.exists());
        assert!(slot.join("vars.fd").path.exists());
        assert!(
            slot.path.ends_with("owner/repo/main/job/imgid123"),
            "slot is <cache>/<namespace>/<job>/<image_id>, got {}",
            slot.path.display()
        );

        assert_eq!(artifacts.len(), 2);
        assert_eq!(artifacts[0].filename, "disk.qcow2");
        assert_eq!(artifacts[0].kind, QemuArtifactKind::Disk);
        assert!(
            artifacts[0].marker.starts_with("11:"),
            "marker is len:mtime for the 11-byte disk, got {}",
            artifacts[0].marker
        );

        assert!(!slot.join(CacheMetadata::FILENAME).path.exists());

        let meta = CacheMetadata {
            format_version: CACHE_FORMAT_VERSION,
            namespace: "owner/repo/main".to_string(),
            job: "job".to_string(),
            image_id: "imgid123".to_string(),
            created_at: 42,
            ttl_secs: Some(3600),
            fingerprint: Fingerprint::default(),
            vm: CachedVm::Qemu { artifacts },
        };
        meta.write_into_slot(&slot).unwrap();

        let json = std::fs::read_to_string(&slot.join(CacheMetadata::FILENAME).path).unwrap();
        let back: CacheMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(back.namespace, "owner/repo/main");
        assert_eq!(back.created_at, 42);
        assert_eq!(back.ttl_secs, Some(3600));
        match back.vm {
            CachedVm::Qemu { artifacts } => {
                assert_eq!(artifacts.len(), 2);
                assert_eq!(artifacts[1].kind, QemuArtifactKind::UefiVars);
            }
            CachedVm::Tart {} => panic!("expected a Qemu slot"),
        }
        assert!(!slot.join("cache.json.tmp").path.exists());

        let _ = std::fs::remove_dir_all(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".ci/temp/cache_commit_full"),
        );
    }

    #[test]
    fn commit_tracks_additional_drive_index_and_errors_on_missing_source() {
        let paths = test_paths("drives");
        let staging = paths.cache_staging_dir();
        let cache = paths.cache_dir();
        std::fs::create_dir_all(&staging.path).unwrap();

        let drive_src = staging.join("vci-job-drive3-00001.qcow2");
        std::fs::write(&drive_src.path, b"x").unwrap();
        let slot = slot_dir(&cache, "ns", "job", "img");

        let arts = move_qemu_artifacts_into_slot(
            &slot,
            &[PlannedQemuArtifact {
                source: drive_src,
                kind: QemuArtifactKind::AdditionalDrive { index: 3 },
                filename: "drive3.qcow2".to_string(),
            }],
        )
        .unwrap();
        assert_eq!(arts[0].kind, QemuArtifactKind::AdditionalDrive { index: 3 });

        let err = move_qemu_artifacts_into_slot(
            &slot,
            &[PlannedQemuArtifact {
                source: staging.join("does-not-exist.qcow2"),
                kind: QemuArtifactKind::Disk,
                filename: "disk.qcow2".to_string(),
            }],
        );
        assert!(err.is_err());

        let _ = std::fs::remove_dir_all(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".ci/temp/cache_commit_drives"),
        );
    }

    #[test]
    fn read_from_slot_round_trips_and_verify_artifacts_detects_tampering() {
        let paths = test_paths("verify");
        let staging = paths.cache_staging_dir();
        let cache = paths.cache_dir();
        std::fs::create_dir_all(&staging.path).unwrap();

        let disk_src = staging.join("vci-job-00001.qcow2");
        std::fs::write(&disk_src.path, b"disk").unwrap();
        let slot = slot_dir(&cache, "ns", "job", "img");
        let artifacts = move_qemu_artifacts_into_slot(
            &slot,
            &[PlannedQemuArtifact {
                source: disk_src,
                kind: QemuArtifactKind::Disk,
                filename: "disk.qcow2".to_string(),
            }],
        )
        .unwrap();
        CacheMetadata {
            format_version: CACHE_FORMAT_VERSION,
            namespace: "ns".to_string(),
            job: "job".to_string(),
            image_id: "img".to_string(),
            created_at: 1,
            ttl_secs: None,
            fingerprint: Fingerprint::default(),
            vm: CachedVm::Qemu { artifacts },
        }
        .write_into_slot(&slot)
        .unwrap();

        let meta = CacheMetadata::read_from_slot(&slot).expect("committed slot is readable");
        assert!(meta.verify_artifacts(&slot), "untouched artifacts verify");

        std::fs::write(&slot.join("disk.qcow2").path, b"tampered-bytes").unwrap();
        assert!(
            !meta.verify_artifacts(&slot),
            "a changed artifact fails its marker"
        );

        std::fs::remove_file(&slot.join("disk.qcow2").path).unwrap();
        assert!(!meta.verify_artifacts(&slot), "a missing artifact fails");

        let _ = std::fs::remove_dir_all(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".ci/temp/cache_commit_verify"),
        );
    }

    #[test]
    fn is_fresh_hit_requires_matching_fingerprint_and_live_ttl() {
        let fp = Fingerprint {
            workflow_hash: "abc".to_string(),
            ..Default::default()
        };
        let other = Fingerprint {
            workflow_hash: "different".to_string(),
            ..Default::default()
        };
        let meta = CacheMetadata {
            format_version: CACHE_FORMAT_VERSION,
            namespace: "ns".to_string(),
            job: "job".to_string(),
            image_id: "img".to_string(),
            created_at: 1000,
            ttl_secs: Some(100),
            fingerprint: fp.clone(),
            vm: CachedVm::Qemu { artifacts: vec![] },
        };

        assert!(meta.is_fresh_hit(&fp, 1050), "same fingerprint, within TTL");
        assert!(
            !meta.is_fresh_hit(&fp, 1101),
            "expired past created_at + ttl"
        );
        assert!(
            !meta.is_fresh_hit(&other, 1050),
            "different fingerprint misses"
        );

        let no_ttl = CacheMetadata {
            ttl_secs: None,
            ..meta
        };
        assert!(no_ttl.is_fresh_hit(&fp, u64::MAX), "no TTL never expires");
    }
}
