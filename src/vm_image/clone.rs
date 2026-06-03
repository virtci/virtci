// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::path::Path;

use anyhow::Context;
#[cfg(not(target_os = "macos"))]
use colored::Colorize;

use crate::backend::qemu::binaries::{qemu_image_binary, target_command};
use crate::cli::CloneArgs;
use crate::vm_image::export::{filename_of, parse_drive_file_path, rewrite_drive_file_path};
use crate::vm_image::import::rewrite_paths_to_managed;
#[cfg(target_os = "macos")]
use crate::vm_image::TartConfig;
use crate::vm_image::{
    ensure_world_readable_dir, ensure_world_readable_file, load_image, permission_hint,
    save_config, validate_image_name, BackendConfig, HostExecTarget, ImageDescription, QemuConfig,
    UefiSplit,
};
use crate::VciGlobalPaths;

pub fn run_clone(args: &CloneArgs, paths: &VciGlobalPaths) -> anyhow::Result<()> {
    let src_name = &args.name;
    let new_name = &args.new_name;

    let home = paths.resolve_image_home(src_name).with_context(|| {
        format!(
            "Image '{}' not found. Looked at {:?}",
            src_name,
            paths.image_homes()
        )
    })?;

    #[cfg_attr(not(target_os = "windows"), allow(unused_mut))]
    let mut src_desc = load_image(src_name, &home.path)?;
    #[cfg(target_os = "windows")]
    {
        src_desc.wsl_distro.clone_from(&home.wsl_distro);
    }

    validate_image_name(new_name, paths).map_err(|e| anyhow::anyhow!("{e}"))?;

    if args.system && matches!(src_desc.backend, BackendConfig::Tart(_)) {
        anyhow::bail!("--system is not supported for Tart-backed images. Tart stores VM data in per-user storage (~/.tart/vms/).");
    }

    println!("Cloning '{src_name}' to '{new_name}'");

    match &src_desc.backend {
        BackendConfig::Tart(tart) => {
            #[cfg(not(target_os = "macos"))]
            {
                let _ = tart;
                eprintln!("{}", "Tart backend is only supported on macOS".red());
                std::process::exit(1);
            }
            #[cfg(target_os = "macos")]
            {
                clone_tart(&src_desc, tart, new_name, paths, args.system)?;
            }
        }
        BackendConfig::Qemu(qemu) => {
            #[cfg(target_os = "windows")]
            if home.in_wsl() {
                if args.system {
                    anyhow::bail!("Cloning a WSL2 image with --system is not yet supported.");
                }
                let wsl = paths
                    .wsl
                    .as_ref()
                    .context("source image lives in WSL2 but no WSL2 distro is configured")?;
                clone_qemu_wsl(&src_desc, qemu, new_name, wsl)?;
                println!("Clone complete: '{new_name}'");
                return Ok(());
            }
            clone_qemu_native(&src_desc, qemu, new_name, paths, args.system)?;
        }
    }

    println!("Clone complete: '{new_name}'");
    Ok(())
}

/// Flatten `src` into a standalone qcow2 at `dst`, both within `exec_target`'s namespace.
fn convert_qcow2(exec_target: &HostExecTarget, src: &str, dst: &str) -> anyhow::Result<()> {
    let qemu_img = qemu_image_binary(exec_target)
        .context("Unable to get qemu-img binary to clone the disk")?
        .0;

    let output = target_command(exec_target, &qemu_img)
        .args(["convert", "-O", "qcow2", src, dst])
        .output()
        .with_context(|| format!("Failed to run {qemu_img}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("qemu-img convert failed for '{src}':\n{}", stderr.trim());
    }
    Ok(())
}

fn copy_native(src: &str, dst: &Path, system: bool) -> anyhow::Result<()> {
    std::fs::copy(src, dst).map_err(|e| {
        anyhow::anyhow!(
            "Failed to copy {src} -> {}: {e}{}",
            dst.display(),
            permission_hint(&e)
        )
    })?;
    if system {
        ensure_world_readable_file(dst)
            .with_context(|| format!("Failed to set permissions on {}", dst.display()))?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn clone_tart(
    src_desc: &ImageDescription,
    tart: &TartConfig,
    new_name: &str,
    paths: &VciGlobalPaths,
    system: bool,
) -> anyhow::Result<()> {
    println!("  Running: tart clone {} {new_name}", tart.vm_name);
    let output = std::process::Command::new("tart")
        .arg("clone")
        .arg(&tart.vm_name)
        .arg(new_name)
        .output()
        .context("Failed to run tart clone")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("tart clone failed: {}", stderr.trim());
    }

    let dest_home = if system {
        paths.system_home.clone()
    } else {
        paths.user_home.clone()
    };

    // An empty managed dir so `virtci remove` cleans up symmetrically with imported tart images.
    let managed_dir = dest_home.join(new_name);
    std::fs::create_dir_all(&managed_dir).map_err(|e| {
        anyhow::anyhow!(
            "Failed to create {}: {e}{}",
            managed_dir.display(),
            permission_hint(&e)
        )
    })?;
    if system {
        ensure_world_readable_dir(&managed_dir)
            .with_context(|| format!("Failed to set permissions on {}", managed_dir.display()))?;
    }

    let mut new_desc = src_desc.clone();
    new_desc.name = new_name.to_string();
    new_desc.managed = Some(true);
    new_desc.remote = None;
    new_desc.backend = BackendConfig::Tart(TartConfig {
        vm_name: new_name.to_string(),
    });

    save_config(&new_desc, &dest_home, system).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

fn clone_qemu_native(
    src_desc: &ImageDescription,
    qemu: &QemuConfig,
    new_name: &str,
    paths: &VciGlobalPaths,
    system: bool,
) -> anyhow::Result<()> {
    let exec_target = HostExecTarget::native();
    let dest_home = if system {
        paths.system_home.clone()
    } else {
        paths.user_home.clone()
    };

    let home_existed = dest_home.exists();
    let managed_dir = dest_home.join(new_name);
    std::fs::create_dir_all(&managed_dir).map_err(|e| {
        anyhow::anyhow!(
            "Failed to create {}: {e}{}",
            managed_dir.display(),
            permission_hint(&e)
        )
    })?;
    if system {
        if !home_existed {
            ensure_world_readable_dir(&dest_home)
                .with_context(|| format!("Failed to set permissions on {}", dest_home.display()))?;
        }
        ensure_world_readable_dir(&managed_dir)
            .with_context(|| format!("Failed to set permissions on {}", managed_dir.display()))?;
    }

    // Main disk to flatten to a standalone qcow2. This drops backing-files / overlays.
    let disk_filename = filename_of(&qemu.image);
    let disk_dst = managed_dir.join(&disk_filename);
    println!("  Cloning disk -> {}", disk_dst.display());
    convert_qcow2(&exec_target, &qemu.image, &disk_dst.to_string_lossy())?;
    if system {
        ensure_world_readable_file(&disk_dst)
            .with_context(|| format!("Failed to set permissions on {}", disk_dst.display()))?;
    }

    let mut new_uefi = qemu.uefi.clone();
    if let Some(uefi) = &qemu.uefi {
        let code_filename = filename_of(&uefi.code);
        let vars_filename = filename_of(&uefi.vars);
        copy_native(&uefi.code, &managed_dir.join(&code_filename), system)?;
        copy_native(&uefi.vars, &managed_dir.join(&vars_filename), system)?;
        new_uefi = Some(UefiSplit {
            code: code_filename,
            vars: vars_filename,
        });
    }

    let mut new_drives = qemu.additional_drives.clone();
    if let Some(drives) = &qemu.additional_drives {
        let mut rewritten = Vec::new();
        for drive in drives {
            if let Some(file_path) = parse_drive_file_path(drive) {
                let fname = filename_of(&file_path);
                copy_native(&file_path, &managed_dir.join(&fname), system)?;
                rewritten.push(rewrite_drive_file_path(drive, &fname));
            } else {
                rewritten.push(drive.clone());
            }
        }
        new_drives = Some(rewritten);
    }

    let mut new_isos = qemu.readonly_isos.clone();
    if let Some(isos) = &qemu.readonly_isos {
        let mut rewritten = Vec::new();
        for iso in isos {
            let fname = filename_of(iso);
            copy_native(iso, &managed_dir.join(&fname), system)?;
            rewritten.push(fname);
        }
        new_isos = Some(rewritten);
    }

    let mut new_desc = src_desc.clone();
    new_desc.name = new_name.to_string();
    new_desc.managed = Some(true);
    new_desc.remote = None;
    new_desc.backend = BackendConfig::Qemu(QemuConfig {
        image: disk_filename,
        uefi: new_uefi,
        cpu_model: qemu.cpu_model.clone(),
        additional_drives: new_drives,
        additional_devices: qemu.additional_devices.clone(),
        tpm: qemu.tpm,
        nvme: qemu.nvme,
        readonly_isos: new_isos,
    });
    rewrite_paths_to_managed(&mut new_desc, &managed_dir);

    save_config(&new_desc, &dest_home, system).map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok(())
}

#[cfg(target_os = "windows")]
fn clone_qemu_wsl(
    src_desc: &ImageDescription,
    qemu: &QemuConfig,
    new_name: &str,
    wsl: &crate::global_paths::WslPaths,
) -> anyhow::Result<()> {
    use crate::global_paths::wsl_path_to_unc;

    let distro = &wsl.distro;
    let exec_target = HostExecTarget::WSL2(distro.clone());
    let wsl_home = wsl.user_home.trim_end_matches('/');
    let wsl_managed_dir = format!("{wsl_home}/{new_name}");

    crate::vm_image::import::wsl_mkdir_p(distro, &wsl_managed_dir)?;

    let disk_filename = filename_of(&qemu.image);
    let disk_dst = format!("{wsl_managed_dir}/{disk_filename}");
    println!("  Cloning disk in WSL distro '{distro}' -> {disk_dst}");
    convert_qcow2(&exec_target, &qemu.image, &disk_dst)?;

    let mut new_uefi = qemu.uefi.clone();
    if let Some(uefi) = &qemu.uefi {
        let code_filename = filename_of(&uefi.code);
        let vars_filename = filename_of(&uefi.vars);
        wsl_copy(
            distro,
            &uefi.code,
            &format!("{wsl_managed_dir}/{code_filename}"),
        )?;
        wsl_copy(
            distro,
            &uefi.vars,
            &format!("{wsl_managed_dir}/{vars_filename}"),
        )?;
        new_uefi = Some(UefiSplit {
            code: code_filename,
            vars: vars_filename,
        });
    }

    let mut new_drives = qemu.additional_drives.clone();
    if let Some(drives) = &qemu.additional_drives {
        let mut rewritten = Vec::new();
        for drive in drives {
            if let Some(file_path) = parse_drive_file_path(drive) {
                let fname = filename_of(&file_path);
                wsl_copy(distro, &file_path, &format!("{wsl_managed_dir}/{fname}"))?;
                rewritten.push(rewrite_drive_file_path(drive, &fname));
            } else {
                rewritten.push(drive.clone());
            }
        }
        new_drives = Some(rewritten);
    }

    let mut new_isos = qemu.readonly_isos.clone();
    if let Some(isos) = &qemu.readonly_isos {
        let mut rewritten = Vec::new();
        for iso in isos {
            let fname = filename_of(iso);
            wsl_copy(distro, iso, &format!("{wsl_managed_dir}/{fname}"))?;
            rewritten.push(fname);
        }
        new_isos = Some(rewritten);
    }

    let mut new_desc = src_desc.clone();
    new_desc.name = new_name.to_string();
    new_desc.managed = Some(true);
    new_desc.remote = None;
    new_desc.backend = BackendConfig::Qemu(QemuConfig {
        image: disk_filename,
        uefi: new_uefi,
        cpu_model: qemu.cpu_model.clone(),
        additional_drives: new_drives,
        additional_devices: qemu.additional_devices.clone(),
        tpm: qemu.tpm,
        nvme: qemu.nvme,
        readonly_isos: new_isos,
    });
    crate::vm_image::import::rewrite_paths_to_managed_wsl(&mut new_desc, &wsl_managed_dir);

    let dest_vci = wsl_path_to_unc(distro, &format!("{wsl_home}/{new_name}.vci"));
    let vci_out = serde_json::to_string_pretty(&new_desc).context("Failed to serialize config")?;
    std::fs::write(&dest_vci, vci_out).map_err(|e| {
        anyhow::anyhow!(
            "Failed to write {}: {e}{}",
            dest_vci.display(),
            permission_hint(&e)
        )
    })?;

    println!("  Config: {}", dest_vci.display());
    println!("  Files:  {wsl_managed_dir} (in WSL distro '{distro}')");
    Ok(())
}

#[cfg(target_os = "windows")]
fn wsl_copy(distro: &str, src: &str, dst: &str) -> anyhow::Result<()> {
    let output = std::process::Command::new("wsl")
        .args(["-d", distro, "--", "cp", "-f", src, dst])
        .output()
        .with_context(|| format!("Failed to run `wsl cp {src} {dst}`"))?;
    if !output.status.success() {
        anyhow::bail!(
            "`wsl cp {src} {dst}` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}
