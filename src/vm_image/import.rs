// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::io::Read;
use std::path::Path;

use anyhow::Context;

use crate::vm_image::{
    ensure_world_readable_dir, ensure_world_readable_file, permission_hint, BackendConfig,
    ImageDescription,
};
use crate::VciGlobalPaths;

pub fn run_import(archive_path: &Path, paths: &VciGlobalPaths, system: bool) -> anyhow::Result<()> {
    if !archive_path.exists() {
        anyhow::bail!("File not found: {}", archive_path.display());
    }

    println!("Importing from {}", archive_path.display());

    let (name, json) = read_vci_from_archive(archive_path)?;
    let mut desc: ImageDescription =
        serde_json::from_str(&json).context("Failed to parse .vci from archive")?;
    desc.name.clone_from(&name);

    if system && matches!(desc.backend, BackendConfig::Tart(_)) {
        anyhow::bail!("--system is not supported for Tart-backed images. Tart stores VM data in per-user storage (~/.tart/vms/), so the system-wide config would point at data that other users cannot access.");
    }

    if let Some(existing_home) = paths.resolve_image_home(&name) {
        let existing_vci = existing_home.dir.join(format!("{name}.vci"));
        anyhow::bail!(
            "Image '{}' already exists at {}",
            name,
            existing_vci.display()
        );
    }

    // TPM images on Windows live inside the WSL2 ext4 filesystem so QEMU (run through `wsl`)
    // resolves their backing files natively gives full performance and working qcow2 locking.
    #[cfg(target_os = "windows")]
    if let Some(wsl) = wsl_target_for(&desc, paths) {
        if system {
            anyhow::bail!(
                "Importing a TPM image into WSL2 with --system is not yet supported; \
                 import it into the user home (omit --system)."
            );
        }
        return import_into_wsl(archive_path, &mut desc, &name, wsl);
    }

    import_native(archive_path, &mut desc, &name, paths, system)
}

/// Read the root `<name>.vci` member from the archive, returning `(name, json)`.
fn read_vci_from_archive(archive_path: &Path) -> anyhow::Result<(String, String)> {
    let file = std::fs::File::open(archive_path)
        .with_context(|| format!("Failed to open {}", archive_path.display()))?;
    let mut archive = tar::Archive::new(file);
    let entries = archive.entries().context("Failed to read archive")?;

    for entry in entries {
        let mut entry = entry.context("Failed to read archive entry")?;
        let path = entry
            .path()
            .context("Failed to read entry path")?
            .to_path_buf();

        let path_str = path.to_string_lossy();
        if path_str.ends_with(".vci") && !path_str.contains('/') {
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .context("Invalid .vci filename in archive")?
                .to_string();

            let mut contents = String::new();
            entry
                .read_to_string(&mut contents)
                .context("Failed to read .vci from archive")?;
            return Ok((name, contents));
        }
    }

    anyhow::bail!("No .vci file found in archive root");
}

fn import_native(
    archive_path: &Path,
    desc: &mut ImageDescription,
    name: &str,
    paths: &VciGlobalPaths,
    system: bool,
) -> anyhow::Result<()> {
    let home_path = if system {
        paths.system_home.clone()
    } else {
        paths.user_home.clone()
    };

    let dest_vci = home_path.join(format!("{name}.vci"));

    let home_existed = home_path.exists();
    let managed_dir = home_path.join(name);
    std::fs::create_dir_all(&managed_dir).map_err(|e| {
        anyhow::anyhow!(
            "Failed to create {}: {e}{}",
            managed_dir.display(),
            permission_hint(&e)
        )
    })?;
    if system {
        if !home_existed {
            ensure_world_readable_dir(&home_path)
                .with_context(|| format!("Failed to set permissions on {}", home_path.display()))?;
        }
        ensure_world_readable_dir(&managed_dir)
            .with_context(|| format!("Failed to set permissions on {}", managed_dir.display()))?;
    }

    let file = std::fs::File::open(archive_path)
        .with_context(|| format!("Failed to reopen {}", archive_path.display()))?;
    let mut archive = tar::Archive::new(file);
    let entries = archive.entries().context("Failed to read archive")?;

    let prefix = format!("{name}/");
    let mut extracted_files: Vec<String> = Vec::new();

    for entry in entries {
        let mut entry = entry.context("Failed to read archive entry")?;
        let path = entry
            .path()
            .context("Failed to read entry path")?
            .to_path_buf();

        let path_str = path.to_string_lossy().to_string();

        if !path_str.starts_with(&prefix) {
            continue;
        }

        let filename = &path_str[prefix.len()..];
        if filename.is_empty() {
            continue;
        }

        let dest = managed_dir.join(filename);
        println!("  Extracting: {filename}");

        if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory {}", parent.display()))?;
        }

        let mut out_file = std::fs::File::create(&dest).map_err(|e| {
            anyhow::anyhow!(
                "Failed to create {}: {e}{}",
                dest.display(),
                permission_hint(&e)
            )
        })?;
        std::io::copy(&mut entry, &mut out_file)
            .with_context(|| format!("Failed to extract {filename}"))?;
        if system {
            ensure_world_readable_file(&dest)
                .with_context(|| format!("Failed to set permissions on {}", dest.display()))?;
        }

        extracted_files.push(filename.to_string());
    }

    rewrite_paths_to_managed(desc, &managed_dir);

    if let BackendConfig::Tart(ref tart) = desc.backend {
        let tvm_file = extracted_files
            .iter()
            .find(|f| {
                std::path::Path::new(f)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("tvm"))
            })
            .context("No .tvm file found in archive for tart backend")?;
        let tvm_path = managed_dir.join(tvm_file);

        println!(
            "  Running: tart import {} {}",
            tart.vm_name,
            tvm_path.display()
        );

        let output = std::process::Command::new("tart")
            .arg("import")
            .arg(&tart.vm_name)
            .arg(&tvm_path)
            .output()
            .context("Failed to run tart import")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("tart import failed: {}", stderr.trim());
        }

        let _ = std::fs::remove_file(&tvm_path);
    }

    desc.managed = Some(true);
    let vci_out = serde_json::to_string_pretty(&*desc).context("Failed to serialize config")?;

    std::fs::create_dir_all(&home_path).map_err(|e| {
        anyhow::anyhow!(
            "Failed to create {}: {e}{}",
            home_path.display(),
            permission_hint(&e)
        )
    })?;
    std::fs::write(&dest_vci, vci_out).map_err(|e| {
        anyhow::anyhow!(
            "Failed to write {}: {e}{}",
            dest_vci.display(),
            permission_hint(&e)
        )
    })?;
    if system {
        ensure_world_readable_file(&dest_vci)
            .with_context(|| format!("Failed to set permissions on {}", dest_vci.display()))?;
    }

    println!("Import complete: {name}");
    println!("  Config: {}", dest_vci.display());
    println!("  Files:  {}", managed_dir.display());
    Ok(())
}

/// `Some(&WslPaths)` when this image must be imported into WSL2 if a TPM-requiring QEMU image on a
/// Windows host with a usable WSL2 distro configured.
#[cfg(target_os = "windows")]
fn wsl_target_for<'a>(
    desc: &ImageDescription,
    paths: &'a VciGlobalPaths,
) -> Option<&'a crate::global_paths::WslPaths> {
    match &desc.backend {
        BackendConfig::Qemu(qemu) if qemu.tpm => paths.wsl.as_ref(),
        _ => None,
    }
}

/// Import into the WSL2 ext4 filesystem. The archive is streamed into the distro and extracted by
/// the distro's own `tar` (native ext4 write), so the qcow2 never crosses the SUPER slow 9P mount.
/// Only the small `.vci` is written back over 9P (UNC).
#[cfg(target_os = "windows")]
fn import_into_wsl(
    archive_path: &Path,
    desc: &mut ImageDescription,
    name: &str,
    wsl: &crate::global_paths::WslPaths,
) -> anyhow::Result<()> {
    let distro = &wsl.distro;
    let wsl_home = wsl.user_home.trim_end_matches('/');
    let wsl_managed_dir = format!("{wsl_home}/{name}");
    let unc_home = crate::global_paths::wsl_path_to_unc(distro, wsl_home);
    let dest_vci = unc_home.join(format!("{name}.vci"));

    // tar -C needs the parent to exist
    wsl_mkdir_p(distro, wsl_home)?;

    println!("  Extracting '{name}' into WSL distro '{distro}' (ext4)...");
    wsl_tar_extract(archive_path, distro, wsl_home, name)?;

    rewrite_paths_to_managed_wsl(desc, &wsl_managed_dir);

    desc.managed = Some(true);
    let vci_out = serde_json::to_string_pretty(&*desc).context("Failed to serialize config")?;
    std::fs::write(&dest_vci, vci_out).map_err(|e| {
        anyhow::anyhow!(
            "Failed to write {}: {e}{}",
            dest_vci.display(),
            permission_hint(&e)
        )
    })?;

    println!("Import complete: {name}");
    println!("  Config: {}", dest_vci.display());
    println!("  Files:  {wsl_managed_dir} (in WSL distro '{distro}')");
    Ok(())
}

#[cfg(target_os = "windows")]
fn wsl_mkdir_p(distro: &str, wsl_dir: &str) -> anyhow::Result<()> {
    let output = std::process::Command::new("wsl")
        .args(["-d", distro, "--", "mkdir", "-p", wsl_dir])
        .output()
        .with_context(|| format!("Failed to run `wsl mkdir -p {wsl_dir}`"))?;
    if !output.status.success() {
        anyhow::bail!(
            "`wsl mkdir -p {wsl_dir}` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn wsl_tar_extract(
    archive_path: &Path,
    distro: &str,
    dest_dir: &str,
    member: &str,
) -> anyhow::Result<()> {
    let mut archive = std::fs::File::open(archive_path)
        .with_context(|| format!("Failed to open {}", archive_path.display()))?;

    let mut child = std::process::Command::new("wsl")
        .args([
            "-d", distro, "--", "tar", "-x", "-f", "-", "-C", dest_dir, member,
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("Failed to spawn `wsl tar` for extraction")?;

    let mut stdin = child
        .stdin
        .take()
        .context("Failed to capture `wsl tar` stdin")?;
    let copy_res = std::io::copy(&mut archive, &mut stdin);
    drop(stdin); // close stdin so tar sees EOF and finishes

    let output = child
        .wait_with_output()
        .context("Failed to wait on `wsl tar`")?;
    if !output.status.success() {
        anyhow::bail!(
            "`wsl tar` extraction failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    copy_res.context("Failed to stream archive into WSL")?;
    Ok(())
}

fn rewrite_paths_to_managed(desc: &mut ImageDescription, managed_dir: &Path) {
    match &mut desc.backend {
        BackendConfig::Qemu(ref mut qemu) => {
            qemu.image = managed_dir.join(&qemu.image).to_string_lossy().to_string();

            if let Some(ref mut uefi) = qemu.uefi {
                uefi.code = managed_dir.join(&uefi.code).to_string_lossy().to_string();
                uefi.vars = managed_dir.join(&uefi.vars).to_string_lossy().to_string();
            }

            if let Some(ref mut drives) = qemu.additional_drives {
                for drive in drives.iter_mut() {
                    *drive = rewrite_drive_file_to_managed(drive, managed_dir);
                }
            }

            if let Some(ref mut isos) = qemu.readonly_isos {
                for iso in isos.iter_mut() {
                    *iso = managed_dir.join(&*iso).to_string_lossy().to_string();
                }
            }
        }
        BackendConfig::Tart(_) => {
            // vm_name is a logical name, not a path
        }
    }
}

fn rewrite_drive_file_to_managed(drive_str: &str, managed_dir: &Path) -> String {
    let mut parts: Vec<String> = Vec::new();
    for part in drive_str.split(',') {
        if let Some(filename) = part.strip_prefix("file=") {
            let abs_path = managed_dir.join(filename);
            parts.push(format!("file={}", abs_path.to_string_lossy()));
        } else {
            parts.push(part.to_string());
        }
    }
    parts.join(",")
}

/// WSL counterpart of [`rewrite_paths_to_managed`]. Builds WSL-namespace paths with `/`.
/// Never `PathBuf::join`, which would corrupt them on the Windows host).
#[cfg(target_os = "windows")]
fn rewrite_paths_to_managed_wsl(desc: &mut ImageDescription, wsl_managed_dir: &str) {
    let BackendConfig::Qemu(ref mut qemu) = desc.backend else {
        return;
    };
    qemu.image = wsl_join(wsl_managed_dir, &qemu.image);
    if let Some(ref mut uefi) = qemu.uefi {
        uefi.code = wsl_join(wsl_managed_dir, &uefi.code);
        uefi.vars = wsl_join(wsl_managed_dir, &uefi.vars);
    }
    if let Some(ref mut drives) = qemu.additional_drives {
        for drive in drives.iter_mut() {
            *drive = rewrite_drive_file_to_wsl(drive, wsl_managed_dir);
        }
    }
    if let Some(ref mut isos) = qemu.readonly_isos {
        for iso in isos.iter_mut() {
            *iso = wsl_join(wsl_managed_dir, iso);
        }
    }
}

#[cfg(target_os = "windows")]
fn wsl_join(dir: &str, file: &str) -> String {
    format!("{}/{}", dir.trim_end_matches('/'), file)
}

#[cfg(target_os = "windows")]
fn rewrite_drive_file_to_wsl(drive_str: &str, wsl_managed_dir: &str) -> String {
    drive_str
        .split(',')
        .map(|part| match part.strip_prefix("file=") {
            Some(filename) => format!("file={}", wsl_join(wsl_managed_dir, filename)),
            None => part.to_string(),
        })
        .collect::<Vec<_>>()
        .join(",")
}
