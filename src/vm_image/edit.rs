// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::path::{Path, PathBuf};

use anyhow::Context;

use crate::cli::EditArgs;
use crate::file_lock::{FileLock, FileLockError};
use crate::vm_image::{
    ensure_world_readable_file, load_image, permission_hint, validate_image_name, BackendConfig,
    ImageDescription,
};
use crate::VciGlobalPaths;

/// Any image-mutating operations, like edit and reconcile, serialize on THIS lock.
/// Ensures concurrent operations can't delete a `.vci` that's in-flight edit.
/// Lives in the per-user home, not `temp` and never the system home, so editing an image
/// generally doesn't require elevated privileges (should also work if the image is a system wide image).
fn images_lock_path(paths: &VciGlobalPaths) -> PathBuf {
    paths.user_home.join("vci-image-edit.lock")
}

/// Atomically safe.
/// 1. Copy .vci file.
/// 2. Rename directory if managed.
/// 3. Remove old .vci file.
pub fn run_edit(args: &EditArgs, paths: &VciGlobalPaths) -> anyhow::Result<()> {
    let old_name = &args.image;
    let Some(new_name) = args.rename.as_ref() else {
        anyhow::bail!("Nothing to edit. Pass --rename <new_name> to rename the image.");
    };

    anyhow::ensure!(
        old_name != new_name,
        "New name is the same as the current name '{old_name}'"
    );

    std::fs::create_dir_all(&paths.user_home).with_context(|| {
        format!(
            "Failed to create user home dir {}",
            paths.user_home.display()
        )
    })?;
    let _lock = match FileLock::try_new(images_lock_path(paths)) {
        Ok(lock) => lock,
        Err(FileLockError::OtherProcessBlock(meta)) => anyhow::bail!(
            "Another VirtCI process is modifying images ({meta}); try again once it finishes."
        ),
        Err(FileLockError::Other) => anyhow::bail!("Failed to acquire the VirtCI image lock"),
    };

    let home = paths.resolve_image_home(old_name).with_context(|| {
        format!(
            "Image '{old_name}' not found. Looked in {:?}",
            paths.image_homes()
        )
    })?;
    let vci_path = home.path.clone();
    let home_dir = vci_path
        .parent()
        .context("image .vci file has no parent directory")?
        .to_path_buf();
    let system = home_dir == paths.system_home;

    #[cfg_attr(not(target_os = "windows"), allow(unused_mut))]
    let mut desc = load_image(old_name, &vci_path)?;
    #[cfg(target_os = "windows")]
    {
        desc.wsl_distro.clone_from(&home.wsl_distro);
    }

    reap_if_dangling(&home_dir, new_name);

    validate_image_name(new_name, paths).map_err(|e| anyhow::anyhow!("{e}"))?;

    // A file is considered "managed" (VirtCI will remove it on `virtci remove ...` if it lives in
    // the per-vm directory `<home>/<old_name>/`.
    let qemu_dir_backed = matches!(desc.backend, BackendConfig::Qemu(_))
        && (desc.managed == Some(true) || home_dir.join(old_name).exists());

    if !qemu_dir_backed {
        // A virtci-created Tart VM can't be renamed (its underlying `tart` VM name would drift).
        if matches!(desc.backend, BackendConfig::Tart(_)) && desc.managed == Some(true) {
            anyhow::bail!(
                "Renaming Tart-backed images is not yet supported. \
                 Use `virtci clone {old_name} {new_name}` then `virtci remove {old_name}`."
            );
        }
        let new_vci = home_dir.join(format!("{new_name}.vci"));
        std::fs::rename(&vci_path, &new_vci).map_err(|e| {
            anyhow::anyhow!(
                "Failed to rename {} -> {}: {e}{}",
                vci_path.display(),
                new_vci.display(),
                permission_hint(&e)
            )
        })?;
        if system {
            let _ = ensure_world_readable_file(&new_vci);
        }
        println!("Renamed '{old_name}' to '{new_name}'");
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    if home.in_wsl() {
        anyhow::bail!("Renaming WSL2-backed images is not yet supported.");
    }
    rename_managed(&desc, &home_dir, old_name, new_name, system)?;

    println!("Renamed '{old_name}' to '{new_name}'");
    Ok(())
}

/// Must be called when holding image lock.
fn rename_managed(
    old_desc: &ImageDescription,
    home_dir: &Path,
    old_name: &str,
    new_name: &str,
    system: bool,
) -> anyhow::Result<()> {
    let old_dir = home_dir.join(old_name);
    let new_dir = home_dir.join(new_name);
    let old_vci = home_dir.join(format!("{old_name}.vci"));
    let new_vci = home_dir.join(format!("{new_name}.vci"));

    anyhow::ensure!(
        old_dir.exists(),
        "Image '{old_name}' is missing its data directory {} — refusing to rename a half-removed image.",
        old_dir.display()
    );
    anyhow::ensure!(
        !new_dir.exists(),
        "A directory already exists at {} — refusing to overwrite it.",
        new_dir.display()
    );

    // 1. PREPARE -> publish the new .vci (paths rebased onto new_dir). Dangling until step 2.
    let new_desc = rebase_managed_desc(old_desc, &old_dir, &new_dir);
    write_vci_atomic(&new_vci, &new_desc, system)
        .with_context(|| format!("Failed to write {}", new_vci.display()))?;

    // 2. COMMIT -> atomically swing the data directory over. The point of no return.
    if let Err(e) = std::fs::rename(&old_dir, &new_dir) {
        // Roll back the prepared metadata so no dangling .vci is left behind.
        let _ = std::fs::remove_file(&new_vci);
        return Err(anyhow::anyhow!(
            "Failed to rename data directory {} -> {}: {e}{}",
            old_dir.display(),
            new_dir.display(),
            permission_hint(&e)
        ));
    }

    // 3. CLEANUP -> the old .vci now dangles. If this fails the rename has still succeeded, the
    // leftover is reaped by `reconcile` on a future run.
    if let Err(e) = std::fs::remove_file(&old_vci) {
        eprintln!(
            "Warning: renamed image but failed to remove old metadata {}: {e}{}. \
             It will be cleaned up automatically.",
            old_vci.display(),
            permission_hint(&e)
        );
    }

    Ok(())
}

/// `.vci` of a managed image stores absolute paths, so each one must have the `old_dir`
/// swapped to `new_dir`. Any path outside of that is untouched.
fn rebase_managed_desc(
    desc: &ImageDescription,
    old_dir: &Path,
    new_dir: &Path,
) -> ImageDescription {
    let mut new_desc = desc.clone();
    if let BackendConfig::Qemu(ref mut qemu) = new_desc.backend {
        qemu.image = rebase_path(&qemu.image, old_dir, new_dir);
        if let Some(ref mut uefi) = qemu.uefi {
            uefi.code = rebase_path(&uefi.code, old_dir, new_dir);
            uefi.vars = rebase_path(&uefi.vars, old_dir, new_dir);
        }
        if let Some(ref mut drives) = qemu.additional_drives {
            for drive in drives.iter_mut() {
                *drive = rebase_drive(drive, old_dir, new_dir);
            }
        }
        if let Some(ref mut isos) = qemu.readonly_isos {
            for iso in isos.iter_mut() {
                *iso = rebase_path(iso, old_dir, new_dir);
            }
        }
    }
    new_desc
}

fn rebase_path(path: &str, old_dir: &Path, new_dir: &Path) -> String {
    match Path::new(path).strip_prefix(old_dir) {
        Ok(rel) => new_dir.join(rel).to_string_lossy().into_owned(),
        Err(_) => path.to_string(),
    }
}

fn rebase_drive(drive: &str, old_dir: &Path, new_dir: &Path) -> String {
    drive
        .split(',')
        .map(|part| match part.strip_prefix("file=") {
            Some(file) => format!("file={}", rebase_path(file, old_dir, new_dir)),
            None => part.to_string(),
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn write_vci_atomic(vci_path: &Path, desc: &ImageDescription, system: bool) -> anyhow::Result<()> {
    let json =
        serde_json::to_string_pretty(desc).context("Failed to serialize image description")?;
    let tmp = vci_path.with_extension("vci.tmp");

    std::fs::write(&tmp, json.as_bytes()).map_err(|e| {
        anyhow::anyhow!(
            "Failed to write temp file {}: {e}{}",
            tmp.display(),
            permission_hint(&e)
        )
    })?;
    if system {
        let _ = ensure_world_readable_file(&tmp);
    }

    std::fs::rename(&tmp, vci_path).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        anyhow::anyhow!(
            "Failed to publish {}: {e}{}",
            vci_path.display(),
            permission_hint(&e)
        )
    })?;
    Ok(())
}

fn reap_if_dangling(home_dir: &Path, name: &str) {
    let _ = std::fs::remove_file(home_dir.join(format!("{name}.vci.tmp")));

    let vci = home_dir.join(format!("{name}.vci"));
    if is_dangling_managed(&vci, home_dir, name) {
        let _ = std::fs::remove_file(&vci);
    }
}

fn is_dangling_managed(vci: &Path, home_dir: &Path, name: &str) -> bool {
    let Ok(contents) = std::fs::read_to_string(vci) else {
        return false;
    };
    let Ok(desc) = serde_json::from_str::<ImageDescription>(&contents) else {
        return false;
    };
    desc.managed == Some(true) && !home_dir.join(name).exists()
}

pub fn reconcile(paths: &VciGlobalPaths) {
    if std::fs::create_dir_all(&paths.user_home).is_err() {
        return;
    }

    let Ok(_lock) = FileLock::try_new(images_lock_path(paths)) else {
        return;
    };

    for home in paths.image_homes() {
        reap_dangling_in(&home.path);
    }
}

fn reap_dangling_in(home_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(home_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(fname) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };

        if fname.ends_with(".vci.tmp") {
            let _ = std::fs::remove_file(&path);
            continue;
        }

        if path.extension().and_then(|e| e.to_str()) != Some("vci") {
            continue;
        }
        let Some(name) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };

        if is_dangling_managed(&path, home_dir, name) && std::fs::remove_file(&path).is_ok() {
            eprintln!(
                "[VirtCI] Removed dangling image metadata left by an interrupted rename: {}",
                path.display()
            );
        }
    }
}
