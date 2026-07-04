// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

pub mod file;
pub mod metadata;

use std::{io::Read, path::Path, time::UNIX_EPOCH};

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::{
    util::git::{GitInfo, sanitize_git_path},
    vm_image::{BackendConfig, ImageDescription},
    yaml,
};

/// Length (hex chars) of the truncated blake3 digests used for ids and short content hashes. 16 hex
/// chars = 64 bits, far beyond enough to avoid accidental collisions between cache slots/inputs.
const SHORT_HASH_LEN: usize = 16;

#[derive(Clone)]
pub enum CacheNamespace {
    Disabled(DisabledReason),
    Enabled { namespace: String },
}

impl CacheNamespace {
    /// Precedence:
    /// 1. CLI `--no-cache`, arg `no_cache` -> disabled.
    /// 2. `is_fork` (a fork / external pull request) -> disabled, unconditionally. Caches are
    /// never shared with forks so that an untrusted contributor cannot read a trusted cache
    /// nor poison one.
    /// 3. CLI `--cache-namespace` -> try to use, interpolating `{owner}`/`{repo}`/`{ref}` from
    /// `git_info`.
    /// 4. Derive from `git_info`.
    /// 5. No cache.
    ///
    /// `is_fork` is passed in (rather than detected here) so this stays pure and testable; callers
    /// supply it from [`crate::util::git::is_fork_or_external_pr`].
    pub fn resolve(
        no_cache: bool,
        is_fork: bool,
        cache_namespace: Option<&str>,
        git_info: Option<&GitInfo>,
    ) -> Self {
        if no_cache {
            return Self::Disabled(DisabledReason::UserNoCache);
        }

        if is_fork {
            return Self::Disabled(DisabledReason::Fork);
        }

        if let Some(template) = cache_namespace {
            return match interpolate_and_sanitize(template, git_info) {
                Ok(namespace) => Self::Enabled { namespace },
                Err(e) => Self::Disabled(DisabledReason::Invalid {
                    err_msg: e.to_string(),
                }),
            };
        }

        if let Some(gi) = git_info {
            return match gi.as_cache_path() {
                Ok(namespace) => Self::Enabled { namespace },
                Err(e) => Self::Disabled(DisabledReason::Invalid {
                    err_msg: e.to_string(),
                }),
            };
        }

        Self::Disabled(DisabledReason::NoNamespaceSource)
    }
}

#[derive(Clone)]
pub enum DisabledReason {
    UserNoCache,
    /// This run is a fork / external pull request and caches are never shared with forks.
    Fork,
    /// No explicitly provided user namespace, and no git CI provider environment.
    NoNamespaceSource,
    Invalid {
        err_msg: String,
    },
}

impl std::fmt::Display for DisabledReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DisabledReason::UserNoCache => write!(f, "--no-cache was passed"),
            DisabledReason::Fork => write!(
                f,
                "this run is a fork / external pull request, and caches are never shared with forks"
            ),
            DisabledReason::NoNamespaceSource => write!(
                f,
                "no --cache-namespace given and no git CI provider detected to derive one from"
            ),
            DisabledReason::Invalid { err_msg } => write!(f, "namespace is unusable: {err_msg}"),
        }
    }
}

fn interpolate_and_sanitize(template: &str, git_info: Option<&GitInfo>) -> anyhow::Result<String> {
    let interpolated = interpolate_tokens(template, git_info)?;
    sanitize_namespace(&interpolated)
}

/// Sanitize a full cache namespace string which may contain `/` separators.
fn sanitize_namespace(s: &str) -> anyhow::Result<String> {
    sanitize_git_path(s)
}

fn interpolate_tokens(template: &str, git_info: Option<&GitInfo>) -> anyhow::Result<String> {
    let has_token =
        template.contains("{owner}") || template.contains("{repo}") || template.contains("{ref}");
    if !has_token {
        return Ok(template.to_string());
    }

    let gi = git_info.context("cache namespace uses {owner}/{repo}/{ref} tokens, but no CI/git provider was detected to fill them")?;

    Ok(template
        .replace("{owner}", &gi.owner)
        .replace("{repo}", &gi.repo)
        .replace("{ref}", &gi.git_ref))
}

/// Short identity binding a cache slot to a VM image.
pub fn image_id(image: &ImageDescription) -> String {
    let mut h = blake3::Hasher::new();
    h.update(image.name.as_bytes());
    h.update(b"\0");
    h.update(format!("{:?}", image.arch).as_bytes());
    h.update(b"\0");
    match &image.backend {
        BackendConfig::Qemu(q) => {
            h.update(b"qemu\0");
            h.update(q.image.as_bytes());
        }
        BackendConfig::Tart(t) => {
            h.update(b"tart\0");
            h.update(t.vm_name.as_bytes());
        }
    }
    truncate_hex(&h.finalize())
}

/// Parse a `cache.max_age` value into seconds. A bare integer is days.
/// Suffixes `S`/`s` (seconds), `M`/`m` (minutes), `H`/`h` (hours), `D`/`d` (days) override that.
pub fn parse_max_age(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    anyhow::ensure!(!s.is_empty(), "max_age is empty");

    let last = s.chars().last().expect("non-empty checked above");
    let (number, mult) = if last.is_ascii_alphabetic() {
        let mult = match last {
            'S' | 's' => 1,
            'M' | 'm' => 60,
            'H' | 'h' => 3600,
            'D' | 'd' => 86400,
            other => anyhow::bail!("invalid max_age suffix {other:?} (use S/M/H/D)"),
        };
        (&s[..s.len() - last.len_utf8()], mult)
    } else {
        (s, 86400)
    };

    let n: u64 = number
        .trim()
        .parse()
        .with_context(|| format!("invalid max_age number {number:?}"))?;
    n.checked_mul(mult).context("max_age overflows")
}

/// Truncated blake3 of a byte slice, for ids and short content hashes.
fn short_hash(bytes: &[u8]) -> String {
    truncate_hex(&blake3::hash(bytes))
}

fn truncate_hex(hash: &blake3::Hash) -> String {
    hash.to_hex().as_str()[..SHORT_HASH_LEN].to_string()
}

#[cfg(test)]
mod tests {
    use super::{CacheNamespace, DisabledReason};
    use crate::util::git::{GitInfo, GitProvider};

    fn gi(owner: &str, repo: &str, git_ref: &str) -> GitInfo {
        GitInfo {
            provider: GitProvider::GitHub,
            owner: owner.into(),
            repo: repo.into(),
            git_ref: git_ref.into(),
            is_tag: false,
        }
    }

    /// The enums don't derive `Debug`/`PartialEq`, so assert via pattern matching and `Display`.
    fn assert_enabled(scope: CacheNamespace, expected: &str) {
        match scope {
            CacheNamespace::Enabled { namespace } => assert_eq!(namespace, expected),
            CacheNamespace::Disabled(reason) => {
                panic!("expected Enabled({expected:?}), got Disabled: {reason}")
            }
        }
    }

    fn assert_invalid(scope: CacheNamespace) {
        match scope {
            CacheNamespace::Disabled(DisabledReason::Invalid { .. }) => {}
            CacheNamespace::Disabled(reason) => panic!("expected Invalid, got Disabled: {reason}"),
            CacheNamespace::Enabled { namespace } => {
                panic!("expected Invalid, got Enabled({namespace:?})")
            }
        }
    }

    #[test]
    fn no_cache_flag_disables_even_with_a_namespace() {
        assert!(matches!(
            CacheNamespace::resolve(true, false, Some("a/b/c"), Some(&gi("o", "r", "main"))),
            CacheNamespace::Disabled(DisabledReason::UserNoCache)
        ));
    }

    #[test]
    fn fork_disables_even_with_a_namespace() {
        // A fork is disabled regardless of an explicit namespace or available git info.
        assert!(matches!(
            CacheNamespace::resolve(false, true, Some("a/b/c"), Some(&gi("o", "r", "main"))),
            CacheNamespace::Disabled(DisabledReason::Fork)
        ));
    }

    #[test]
    fn no_cache_takes_precedence_over_fork() {
        assert!(matches!(
            CacheNamespace::resolve(true, true, None, None),
            CacheNamespace::Disabled(DisabledReason::UserNoCache)
        ));
    }

    #[test]
    fn auto_derives_from_git_info() {
        assert_enabled(
            CacheNamespace::resolve(
                false,
                false,
                None,
                Some(&gi("gabkhanfig", "virtci", "main")),
            ),
            "gabkhanfig/virtci/main",
        );
    }

    #[test]
    fn no_source_disables() {
        assert!(matches!(
            CacheNamespace::resolve(false, false, None, None),
            CacheNamespace::Disabled(DisabledReason::NoNamespaceSource)
        ));
    }

    #[test]
    fn custom_namespace_interpolates_tokens() {
        assert_enabled(
            CacheNamespace::resolve(
                false,
                false,
                Some("{owner}/{repo}/{ref}"),
                Some(&gi("o", "r", "feature/x")),
            ),
            "o/r/feature/x",
        );
        assert_enabled(
            CacheNamespace::resolve(
                false,
                false,
                Some("team-acme/{ref}"),
                Some(&gi("o", "r", "main")),
            ),
            "team-acme/main",
        );
    }

    #[test]
    fn literal_namespace_without_git_info_is_fine() {
        assert_enabled(
            CacheNamespace::resolve(false, false, Some("my-experiment"), None),
            "my-experiment",
        );
    }

    #[test]
    fn token_without_provider_disables() {
        // A token with no provider to fill it must not silently drop and collapse refs together.
        assert_invalid(CacheNamespace::resolve(false, false, Some("{ref}"), None));
    }

    #[test]
    fn traversal_namespace_disables() {
        assert_invalid(CacheNamespace::resolve(false, false, Some("../evil"), None));
        assert_invalid(CacheNamespace::resolve(false, false, Some("a/../b"), None));
    }

    #[test]
    fn interpolated_unsafe_ref_fails_closed() {
        // A ref that survives interpolation but fails sanitization (a space) disables caching
        // rather than silently mangling the path.
        assert_invalid(CacheNamespace::resolve(
            false,
            false,
            Some("{ref}"),
            Some(&gi("o", "r", "bad ref")),
        ));
    }
}

#[cfg(test)]
mod fingerprint_tests {
    use super::{Fingerprint, image_id, parse_max_age};
    use crate::util::cpu_arch::Arch;
    use crate::vm_image::{BackendConfig, GuestOs, ImageDescription, QemuConfig, SshConfig};

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
        assert_eq!(a.len(), super::SHORT_HASH_LEN);
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

        let fp = Fingerprint::capture(&cfg, "wfhash".to_string(), Some("123:456".to_string()));

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
    }
}
