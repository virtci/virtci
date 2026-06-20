// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use crate::util::git::{GitInfo, sanitize_git_path};

use anyhow::Context;

pub enum CacheNamespace {
    Disabled(DisabledReason),
    Enabled { namespace: String },
}

impl CacheNamespace {
    /// Precedence:
    /// 1. CLI `--no-cache`, arg `no_cache` -> disabled.
    /// 2. CLI `--cache-namespace` -> try to use, interpolating `{owner}`/`{repo}`/`{ref}` from
    /// `git_info`.
    /// 3. Derive from `git_info`.
    /// 4. No cache.
    pub fn resolve(
        no_cache: bool,
        cache_namespace: Option<&str>,
        git_info: Option<&GitInfo>,
    ) -> Self {
        if no_cache {
            return Self::Disabled(DisabledReason::UserNoCache);
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

pub enum DisabledReason {
    UserNoCache,
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
            CacheNamespace::resolve(true, Some("a/b/c"), Some(&gi("o", "r", "main"))),
            CacheNamespace::Disabled(DisabledReason::UserNoCache)
        ));
    }

    #[test]
    fn auto_derives_from_git_info() {
        assert_enabled(
            CacheNamespace::resolve(false, None, Some(&gi("gabkhanfig", "virtci", "main"))),
            "gabkhanfig/virtci/main",
        );
    }

    #[test]
    fn no_source_disables() {
        assert!(matches!(
            CacheNamespace::resolve(false, None, None),
            CacheNamespace::Disabled(DisabledReason::NoNamespaceSource)
        ));
    }

    #[test]
    fn custom_namespace_interpolates_tokens() {
        assert_enabled(
            CacheNamespace::resolve(
                false,
                Some("{owner}/{repo}/{ref}"),
                Some(&gi("o", "r", "feature/x")),
            ),
            "o/r/feature/x",
        );
        assert_enabled(
            CacheNamespace::resolve(false, Some("team-acme/{ref}"), Some(&gi("o", "r", "main"))),
            "team-acme/main",
        );
    }

    #[test]
    fn literal_namespace_without_git_info_is_fine() {
        assert_enabled(
            CacheNamespace::resolve(false, Some("my-experiment"), None),
            "my-experiment",
        );
    }

    #[test]
    fn token_without_provider_disables() {
        // A token with no provider to fill it must not silently drop and collapse refs together.
        assert_invalid(CacheNamespace::resolve(false, Some("{ref}"), None));
    }

    #[test]
    fn traversal_namespace_disables() {
        assert_invalid(CacheNamespace::resolve(false, Some("../evil"), None));
        assert_invalid(CacheNamespace::resolve(false, Some("a/../b"), None));
    }

    #[test]
    fn interpolated_unsafe_ref_fails_closed() {
        // A ref that survives interpolation but fails sanitization (a space) disables caching
        // rather than silently mangling the path.
        assert_invalid(CacheNamespace::resolve(
            false,
            Some("{ref}"),
            Some(&gi("o", "r", "bad ref")),
        ));
    }
}
