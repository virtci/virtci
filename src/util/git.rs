// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

pub enum GitProvider {
    GitHub,
    GitLab,
    /// Also codeberg!
    Forgejo,
    Gitea,
    BitBucket,
}

impl GitProvider {
    pub fn detect_provider() -> Option<Self> {
        if is_github_actions() {
            return Some(Self::GitHub);
        } else if is_gitlab() {
            return Some(Self::GitLab);
        } else if is_forgejo() {
            return Some(Self::Forgejo);
        } else if is_gitea() {
            return Some(Self::Gitea);
        } else if is_bitbucket() {
            return Some(Self::BitBucket);
        }
        None
    }
}

pub struct GitInfo {
    pub provider: GitProvider,
    pub owner: String,
    pub repo: String,
    pub git_ref: String,
    pub is_tag: bool,
}

impl GitInfo {
    pub fn detect() -> Option<Self> {
        let provider = GitProvider::detect_provider()?;
        match provider {
            GitProvider::GitHub | GitProvider::Forgejo | GitProvider::Gitea => Some(GitInfo {
                provider,
                owner: std::env::var("GITHUB_REPOSITORY_OWNER").ok()?,
                repo: std::env::var("GITHUB_REPOSITORY")
                    .ok()?
                    .split('/')
                    .nth(1)?
                    .to_string(),
                git_ref: std::env::var("GITHUB_REF_NAME").ok()?,
                is_tag: std::env::var("GITHUB_REF_TYPE").ok().as_deref() == Some("tag"),
            }),
            GitProvider::GitLab => Some(GitInfo {
                provider,
                owner: std::env::var("CI_PROJECT_NAMESPACE").ok()?,
                repo: std::env::var("CI_PROJECT_NAME").ok()?,
                git_ref: std::env::var("CI_COMMIT_REF_NAME").ok()?,
                is_tag: std::env::var_os("CI_COMMIT_TAG").is_some(),
            }),
            GitProvider::BitBucket => {
                let tag = std::env::var("BITBUCKET_TAG").ok();
                Some(GitInfo {
                    provider,
                    owner: std::env::var("BITBUCKET_WORKSPACE").ok()?,
                    repo: std::env::var("BITBUCKET_REPO_SLUG").ok()?,
                    git_ref: std::env::var("BITBUCKET_BRANCH")
                        .ok()
                        .or_else(|| tag.clone())?,
                    is_tag: tag.is_some(),
                })
            }
        }
    }

    pub fn as_cache_path(&self) -> anyhow::Result<String> {
        anyhow::ensure!(!self.owner.is_empty(), "git owner is empty");
        anyhow::ensure!(!self.repo.is_empty(), "git repo is empty");
        anyhow::ensure!(!self.git_ref.is_empty(), "git ref is empty");

        let owner = sanitize_git_path(&self.owner)?;
        let repo = sanitize_git_path(&self.repo)?;
        let git_ref = sanitize_git_path(&self.git_ref)?;

        Ok(format!("{owner}/{repo}/{git_ref}"))
    }
}

/// Usually 255 is max, but just to be safe.
const MAX_SEGMENT_LEN: usize = 254;

const WINDOWS_RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

/// Sanitize a value that will eventually become a path segment for a cache namespace
/// (`<owner>/<repo>/<ref>`). `/` is permitted as a segment separator as branch and tag names
/// often contain it.
///
/// Each `/` separated semgent must:
/// - Be non-empty, and not precisely `.` or `..` cause that would be directory traversal.
/// - Have only ASCII text.
/// - Not start with a `-`.
/// - Not end with a `.` as Windows can strip it.
/// - Not be a Windows reserved device name.
/// - Be less than [`MAX_SEGMENT_LEN`] bytes.
///
/// A `.` or `_` or `-` inside of a segment is fine cause it will realistically happen, notably
/// with git tags like `v1.2.3`, or a repo like `www.virtci.com`.
pub fn sanitize_git_path(s: &str) -> anyhow::Result<String> {
    for seg in s.split('/') {
        anyhow::ensure!(
            !seg.is_empty(),
            "cache namespace {s:?} has an empty path segment"
        );
        anyhow::ensure!(
            seg != "." && seg != "..",
            "cache namespace segment {seg:?} is a directory traversal"
        );
        anyhow::ensure!(
            seg.len() <= MAX_SEGMENT_LEN,
            "cache namespace segment {seg:?} exceeds {MAX_SEGMENT_LEN} bytes"
        );
        anyhow::ensure!(
            seg.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-')),
            "cache namespace segment {seg:?} has a character unsafe for a path"
        );
        anyhow::ensure!(
            !seg.starts_with('-'),
            "cache namespace segment {seg:?} must not start with '-'"
        );
        anyhow::ensure!(
            !seg.ends_with('.'),
            "cache namespace segment {seg:?} must not end with '.'"
        );
        let stem = seg.split('.').next().unwrap_or(seg);
        anyhow::ensure!(
            !WINDOWS_RESERVED
                .iter()
                .any(|r| r.eq_ignore_ascii_case(stem)),
            "cache namespace segment {seg:?} is a Windows reserved device name"
        );
    }

    Ok(s.to_string())
}

fn is_github_actions() -> bool {
    std::env::var("GITHUB_ACTIONS").is_ok()
}

fn is_gitea() -> bool {
    std::env::var("GITEA_ACTIONS").is_ok()
}

/// Also codeberg!
fn is_forgejo() -> bool {
    std::env::var("FORGEJO_ACTIONS").is_ok()
}

fn is_gitlab() -> bool {
    std::env::var("GITLAB_CI").is_ok()
}

fn is_bitbucket() -> bool {
    std::env::var("BITBUCKET_BUILD_NUMBER").is_ok()
}

#[cfg(test)]
mod tests {
    use super::sanitize_git_path;

    #[test]
    fn accepts_real_world_values() {
        for ok in [
            "gabkhanfig",
            "virtci",
            "main",
            "feature/thing",
            "release/1.2",
            "v1.2.3",
            "docs.gitea.com",
            "group/subgroup",
            "JIRA-123_fix",
        ] {
            assert!(sanitize_git_path(ok).is_ok(), "{ok:?} should be allowed");
        }
    }

    #[test]
    fn rejects_traversal_and_empty_segments() {
        for bad in [
            "",
            ".",
            "..",
            "a/../b",
            "a/./b",
            "/leading",
            "trailing/",
            "a//b",
        ] {
            assert!(
                sanitize_git_path(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_unsafe_characters() {
        for bad in [
            "a b",
            "a:b",
            "a\\b",
            "a*b",
            "a$b",
            "héllo",
            "a\nb",
            "emoji😀",
        ] {
            assert!(
                sanitize_git_path(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn rejects_platform_hostile_segments() {
        for bad in [
            "-flag",
            "feature/-x",
            "foo.",
            "nul",
            "NUL",
            "Nul.txt",
            "com1",
            "lpt9.log",
        ] {
            assert!(
                sanitize_git_path(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn dot_inside_a_segment_is_allowed_but_a_dot_segment_is_not() {
        assert!(sanitize_git_path("v1.2.3").is_ok());
        assert!(sanitize_git_path("..foo").is_ok()); // not the literal `..` path traversal
        assert!(sanitize_git_path("a/..").is_err());
    }
}
