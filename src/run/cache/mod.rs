// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

pub mod file;
pub mod metadata;

use anyhow::Context;

use crate::{
    global_paths::TargetPath,
    util::git::{GitInfo, sanitize_git_path},
    vm_image::{BackendConfig, ImageDescription},
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

/// `<cache_root>/<namespace>/<job>/<image_id>`.
pub fn slot_dir(cache_root: &TargetPath, namespace: &str, job: &str, image_id: &str) -> TargetPath {
    let mut dir = cache_root.clone();
    for component in namespace
        .split('/')
        .chain([job, image_id])
        .filter(|c| !c.is_empty())
    {
        dir = dir.join(component);
    }
    dir
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
