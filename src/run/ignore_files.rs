// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::path::{Path, PathBuf};

use anyhow::Context;

use crate::yaml::IgnoreFileField;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IgnorePlan {
    Disabled,
    Enabled {
        nested_name: Option<String>,
        flat_file: Option<PathBuf>,
        /// Implicitly drop `.git/` from copy or not.
        implicit_git: bool,
    },
}

impl IgnorePlan {
    pub fn is_enabled(&self) -> bool {
        matches!(self, IgnorePlan::Enabled { .. })
    }
}

pub fn resolve_ignore_plan(
    ignore_file: Option<&IgnoreFileField>,
    no_ignore: bool,
    is_host_to_vm: bool,
    cwd: &Path,
) -> IgnorePlan {
    if !is_host_to_vm {
        return IgnorePlan::Disabled;
    }

    if no_ignore {
        let explicitly_requested = matches!(
            ignore_file,
            Some(IgnoreFileField::Str(_) | IgnoreFileField::Bool(true))
        );
        if explicitly_requested {
            eprintln!(
                "[VirtCI] --no-ignore is set so the copy's configured ignore_file is not used."
            );
        }
        return IgnorePlan::Disabled;
    }

    match ignore_file {
        None | Some(IgnoreFileField::Bool(true)) => {
            if cwd.join(".virtciignore").is_file() {
                IgnorePlan::Enabled {
                    nested_name: Some(".virtciignore".to_string()),
                    flat_file: None,
                    implicit_git: false,
                }
            } else {
                IgnorePlan::Disabled
            }
        }
        Some(IgnoreFileField::Bool(false)) => IgnorePlan::Disabled,
        Some(IgnoreFileField::Str(s)) => resolve_named(s, cwd),
    }
}

fn resolve_named(s: &str, cwd: &Path) -> IgnorePlan {
    let p = Path::new(s);
    let is_path = s.contains('/') || s.contains('\\') || p.is_absolute();
    let implicit_git = p.file_name().is_some_and(|n| n == ".gitignore");

    if is_path {
        let resolved = if p.is_absolute() {
            p.to_path_buf()
        } else {
            cwd.join(p)
        };
        IgnorePlan::Enabled {
            nested_name: None,
            flat_file: Some(resolved),
            implicit_git,
        }
    } else {
        IgnorePlan::Enabled {
            nested_name: Some(s.to_string()),
            flat_file: None,
            implicit_git,
        }
    }
}

pub fn walk_filtered(root: &Path, plan: &IgnorePlan) -> anyhow::Result<Vec<String>> {
    let IgnorePlan::Enabled {
        nested_name,
        flat_file,
        implicit_git,
    } = plan
    else {
        anyhow::bail!("walk_filtered called with a disabled ignore plan");
    };

    let mut builder = ignore::WalkBuilder::new(root);
    // configured file does the logic not this.
    builder
        .hidden(false)
        .parents(false)
        .git_ignore(false)
        .git_global(false)
        .git_exclude(false)
        .ignore(false)
        .require_git(false)
        .follow_links(false);

    if let Some(name) = nested_name {
        if name.is_empty() {
            anyhow::bail!("ignore_file name must not be empty");
        }
        builder.add_custom_ignore_filename(name);
    }
    if let Some(file) = flat_file {
        if !file.is_file() {
            anyhow::bail!(format!("Ignore file not found: {}", file.display()));
        }
        if let Some(err) = builder.add_ignore(file) {
            anyhow::bail!(format!(
                "Failed to read ignore file {}: {err}",
                file.display()
            ));
        }
    }

    let skip_git = *implicit_git;
    let mut out = Vec::new();
    for result in builder.build() {
        let entry = result.with_context(|| format!("Failed to walk {}", root.display()))?;

        if !entry.file_type().is_some_and(|ft| ft.is_file()) {
            continue;
        }

        let Ok(rel) = entry.path().strip_prefix(root) else {
            continue;
        };
        // handle `.git/` in any sub directories (generally submodules).
        if skip_git && rel.components().any(|c| c.as_os_str() == ".git") {
            continue;
        }

        let rel_str = rel.to_string_lossy().replace('\\', "/");
        if rel_str.is_empty() || rel_str.contains(['\n', '\r']) {
            continue;
        }
        out.push(format!("./{rel_str}"));
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_tree(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("virtci_ignore_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp tree");
        dir
    }

    fn write(root: &Path, rel: &str, contents: &str) {
        let p = root.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).expect("create parent");
        std::fs::write(p, contents).expect("write fixture file");
    }

    fn nested(name: &str, implicit_git: bool) -> IgnorePlan {
        IgnorePlan::Enabled {
            nested_name: Some(name.to_string()),
            flat_file: None,
            implicit_git,
        }
    }

    fn survivors(root: &Path, plan: &IgnorePlan) -> Vec<String> {
        let mut v = walk_filtered(root, plan).expect("walk_filtered");
        v.sort();
        v
    }

    #[test]
    fn vm_to_host_is_always_disabled() {
        let cwd = temp_tree("res_vmhost");
        write(&cwd, ".virtciignore", "x\n");
        let plan = resolve_ignore_plan(
            Some(&IgnoreFileField::Str(".gitignore".into())),
            false,
            false,
            &cwd,
        );
        assert_eq!(plan, IgnorePlan::Disabled);
    }

    #[test]
    fn no_ignore_switch_disables() {
        let cwd = temp_tree("res_noignore");
        write(&cwd, ".virtciignore", "x\n");
        let plan = resolve_ignore_plan(None, true, true, &cwd);
        assert_eq!(plan, IgnorePlan::Disabled);
    }

    #[test]
    fn default_uses_virtciignore_only_when_present() {
        let cwd = temp_tree("res_default");
        assert_eq!(
            resolve_ignore_plan(None, false, true, &cwd),
            IgnorePlan::Disabled
        );
        write(&cwd, ".virtciignore", "target/\n");
        assert_eq!(
            resolve_ignore_plan(None, false, true, &cwd),
            nested(".virtciignore", false)
        );
        assert_eq!(
            resolve_ignore_plan(Some(&IgnoreFileField::Bool(true)), false, true, &cwd),
            nested(".virtciignore", false)
        );
    }

    #[test]
    fn bool_false_disables() {
        let cwd = temp_tree("res_false");
        write(&cwd, ".virtciignore", "x\n");
        assert_eq!(
            resolve_ignore_plan(Some(&IgnoreFileField::Bool(false)), false, true, &cwd),
            IgnorePlan::Disabled
        );
    }

    #[test]
    fn bare_name_is_nested_and_gitignore_sets_implicit_git() {
        let cwd = temp_tree("res_bare");
        assert_eq!(
            resolve_ignore_plan(
                Some(&IgnoreFileField::Str(".gitignore".into())),
                false,
                true,
                &cwd
            ),
            nested(".gitignore", true)
        );
        assert_eq!(
            resolve_ignore_plan(
                Some(&IgnoreFileField::Str(".virtciignore".into())),
                false,
                true,
                &cwd
            ),
            nested(".virtciignore", false)
        );
        assert_eq!(
            resolve_ignore_plan(
                Some(&IgnoreFileField::Str("custom.ignore".into())),
                false,
                true,
                &cwd
            ),
            nested("custom.ignore", false)
        );
    }

    #[test]
    fn path_value_is_a_flat_file_resolved_against_cwd() {
        let cwd = temp_tree("res_path");
        let plan = resolve_ignore_plan(
            Some(&IgnoreFileField::Str(".ci/my_ignore".into())),
            false,
            true,
            &cwd,
        );
        assert_eq!(
            plan,
            IgnorePlan::Enabled {
                nested_name: None,
                flat_file: Some(cwd.join(".ci/my_ignore")),
                implicit_git: false,
            }
        );
    }

    #[test]
    fn absolute_gitignore_path_is_flat_but_still_implicit_git() {
        let cwd = temp_tree("res_abs");
        let abs = cwd.join("sub").join(".gitignore");
        let plan = resolve_ignore_plan(
            Some(&IgnoreFileField::Str(abs.to_string_lossy().into_owned())),
            false,
            true,
            &cwd,
        );
        assert_eq!(
            plan,
            IgnorePlan::Enabled {
                nested_name: None,
                flat_file: Some(abs),
                implicit_git: true,
            }
        );
    }

    #[test]
    fn nested_ignore_files_apply_per_directory() {
        let root = temp_tree("walk_nested");
        write(&root, "keep.txt", "");
        write(&root, ".virtciignore", "build/\n");
        write(&root, "build/out.o", "");
        write(&root, "sub/ok.txt", "");
        write(&root, "sub/secret.txt", "");
        write(&root, "sub/.virtciignore", "secret.txt\n");

        let got = survivors(&root, &nested(".virtciignore", false));
        assert_eq!(
            got,
            vec![
                "./.virtciignore".to_string(),
                "./keep.txt".to_string(),
                "./sub/.virtciignore".to_string(),
                "./sub/ok.txt".to_string(),
            ]
        );
    }

    #[test]
    fn gitignore_mode_drops_dotgit_but_keeps_other_dotfiles() {
        let root = temp_tree("walk_git");
        write(&root, "src/main.rs", "");
        write(&root, ".gitignore", "target/\n");
        write(&root, "target/debug/bin", "");
        write(&root, ".git/config", "");
        write(&root, ".git/objects/abc", "");
        write(&root, ".github/workflows/ci.yml", "");

        let got = survivors(&root, &nested(".gitignore", true));
        assert_eq!(
            got,
            vec![
                "./.github/workflows/ci.yml".to_string(),
                "./.gitignore".to_string(),
                "./src/main.rs".to_string(),
            ]
        );
    }

    #[test]
    fn flat_file_applies_across_the_whole_tree() {
        let root = temp_tree("walk_flat");
        write(&root, "a.log", "");
        write(&root, "keep.txt", "");
        write(&root, "deep/b.log", "");
        let ignore_dir = temp_tree("walk_flat_cfg");
        write(&ignore_dir, "ignore.txt", "*.log\n");

        let plan = IgnorePlan::Enabled {
            nested_name: None,
            flat_file: Some(ignore_dir.join("ignore.txt")),
            implicit_git: false,
        };
        assert_eq!(survivors(&root, &plan), vec!["./keep.txt".to_string()]);
    }

    #[test]
    fn missing_flat_ignore_file_errors() {
        let root = temp_tree("walk_missing");
        write(&root, "keep.txt", "");
        let plan = IgnorePlan::Enabled {
            nested_name: None,
            flat_file: Some(root.join("does_not_exist.ignore")),
            implicit_git: false,
        };
        assert!(walk_filtered(&root, &plan).is_err());
    }

    #[test]
    fn gitignore_mode_drops_dotgit_at_any_depth() {
        let root = temp_tree("walk_submodule");
        write(&root, "src/main.rs", "");
        write(&root, ".gitignore", "");
        write(&root, "vendor/lib/.git/config", "");
        write(&root, "vendor/lib/src.c", "");

        let got = survivors(&root, &nested(".gitignore", true));
        assert_eq!(
            got,
            vec![
                "./.gitignore".to_string(),
                "./src/main.rs".to_string(),
                "./vendor/lib/src.c".to_string(),
            ]
        );
    }

    #[test]
    fn empty_nested_name_errors() {
        let root = temp_tree("walk_empty_name");
        write(&root, "keep.txt", "");
        assert!(walk_filtered(&root, &nested("", false)).is_err());
    }
}
