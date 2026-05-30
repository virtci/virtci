// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::vm_image::progress::ProgressReader;
use crate::vm_image::{BackendConfig, ImageDescription, QemuConfig, TartConfig};
use crate::VciGlobalPaths;

use anyhow::Context;

pub fn run_export(
    name: &str,
    output: Option<PathBuf>,
    paths: &VciGlobalPaths,
) -> anyhow::Result<()> {
    let home = paths.resolve_image_home(name).with_context(|| {
        format!(
            "Image '{}' not found. Looked at {:?}",
            name,
            paths.image_homes()
        )
    })?;

    let desc = super::load_image(name, &home.path)?;
    let output_path = output.unwrap_or_else(|| PathBuf::from(format!("{name}.tar")));

    println!("Exporting '{}' to {}", name, output_path.display());

    let file = std::fs::File::create(&output_path)
        .with_context(|| format!("Failed to create {}", output_path.display()))?;
    let mut archive = tar::Builder::new(file);

    let mut exported_desc = desc.clone();
    exported_desc.managed = Some(true);

    // WSL image file's all live inside of the WSL distro in ext4, so they can be streamed
    // rather than dragging across 9P mount (very slow). Native on-host files read directly.
    #[cfg(target_os = "windows")]
    let wsl_distro: Option<&str> = home.wsl_distro.as_deref();
    #[cfg(not(target_os = "windows"))]
    let wsl_distro: Option<&str> = None;

    match &desc.backend {
        BackendConfig::Qemu(qemu) => {
            export_qemu(name, qemu, &mut archive, &mut exported_desc, wsl_distro)?;
        }
        BackendConfig::Tart(tart) => {
            export_tart(name, tart, &mut archive, &mut exported_desc)?;
        }
    }

    let vci_json =
        serde_json::to_string_pretty(&exported_desc).context("Failed to serialize config")?;
    let vci_bytes = vci_json.as_bytes();
    let mut header = tar::Header::new_gnu();
    header.set_size(vci_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    archive
        .append_data(&mut header, format!("{name}.vci"), vci_bytes)
        .context("Failed to write .vci to archive")?;

    archive.finish().context("Failed to finalize archive")?;

    println!("Export complete: {}", output_path.display());
    Ok(())
}

/// Append a file to the archive. WSL files are streamed through a native `wsl -- cat`
/// (native ext4 read on one side, native NTFS write on the other) instead of being dragged over
/// the slow `\\wsl.localhost` 9P mount. Only the size is read over 9P (metadata, no file data).
///
/// # Arguments
///
/// - `archive` The tar archive to append the file to.
/// - `wsl_distro` Only used on Windows. If the file lives within WSL2, is the distro name.
/// - `raw_path` The path exactly as recorded in the `.vci` image description file. Either is the
///   host path, or the WSL-namespace path.
/// - `archive_name` Name of the tar archive.
fn append_file<W: std::io::Write>(
    archive: &mut tar::Builder<W>,
    wsl_distro: Option<&str>,
    raw_path: &str,
    archive_name: &str,
) -> anyhow::Result<()> {
    let label = filename_of(raw_path);

    match wsl_distro {
        None => {
            let file = std::fs::File::open(raw_path)
                .with_context(|| format!("Failed to open {raw_path}"))?;
            let size = file
                .metadata()
                .with_context(|| format!("Failed to read metadata for {raw_path}"))?
                .len();
            let mut reader = ProgressReader::new(file, size, label);
            append_reader(archive, &mut reader, size, archive_name, raw_path)
        }
        Some(distro) => {
            // The tar header carries the entry size up front, so learn it before streaming.
            // A stat over 9P moves only metadata (no file bytes), so it isn't the slow path.
            let unc = crate::global_paths::wsl_path_to_unc(distro, raw_path);
            let size = std::fs::metadata(&unc)
                .with_context(|| format!("Failed to stat {} in WSL", unc.display()))?
                .len();

            let mut child = std::process::Command::new("wsl")
                .args(["-d", distro, "--", "cat", raw_path])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn()
                .with_context(|| format!("Failed to spawn `wsl cat` for {raw_path}"))?;
            let stdout = child
                .stdout
                .take()
                .with_context(|| format!("Failed to capture `wsl cat` output for {raw_path}"))?;
            let mut reader = ProgressReader::new(stdout, size, label);
            append_reader(archive, &mut reader, size, archive_name, raw_path)?;

            let status = child
                .wait()
                .with_context(|| format!("Failed to wait on `wsl cat` for {raw_path}"))?;
            if !status.success() {
                anyhow::bail!(format!(
                    "`wsl cat` failed for {raw_path} ({status}); the archive may be incomplete"
                ));
            }
            Ok(())
        }
    }
}

fn append_reader<W: std::io::Write, R: Read>(
    archive: &mut tar::Builder<W>,
    reader: &mut R,
    size: u64,
    archive_name: &str,
    raw_path: &str,
) -> anyhow::Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(size);
    header.set_mode(0o644);
    header.set_cksum();

    archive
        .append_data(&mut header, archive_name, reader)
        .with_context(|| format!("Failed to add {raw_path} to archive"))
}

pub fn filename_of(path: &str) -> String {
    Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path)
        .to_string()
}

pub fn parse_drive_file_path(drive_str: &str) -> Option<String> {
    for part in drive_str.split(',') {
        if let Some(path) = part.strip_prefix("file=") {
            if !path.is_empty() {
                return Some(path.to_string());
            }
        }
    }
    None
}

fn rewrite_drive_file_path(drive_str: &str, new_filename: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    for part in drive_str.split(',') {
        if part.starts_with("file=") {
            parts.push(format!("file={new_filename}"));
        } else {
            parts.push(part.to_string());
        }
    }
    parts.join(",")
}

fn export_qemu<W: std::io::Write>(
    name: &str,
    qemu: &QemuConfig,
    archive: &mut tar::Builder<W>,
    exported_desc: &mut ImageDescription,
    wsl_distro: Option<&str>,
) -> anyhow::Result<()> {
    let image_filename = filename_of(&qemu.image);
    append_file(
        archive,
        wsl_distro,
        &qemu.image,
        &format!("{name}/{image_filename}"),
    )?;

    let mut exported_uefi = qemu.uefi.clone();
    if let Some(ref uefi) = qemu.uefi {
        let code_filename = filename_of(&uefi.code);
        append_file(
            archive,
            wsl_distro,
            &uefi.code,
            &format!("{name}/{code_filename}"),
        )?;

        let vars_filename = filename_of(&uefi.vars);
        append_file(
            archive,
            wsl_distro,
            &uefi.vars,
            &format!("{name}/{vars_filename}"),
        )?;

        exported_uefi = Some(crate::vm_image::UefiSplit {
            code: code_filename,
            vars: vars_filename,
        });
    }

    let mut exported_drives = qemu.additional_drives.clone();
    if let Some(ref drives) = qemu.additional_drives {
        let mut rewritten = Vec::new();
        for drive_str in drives {
            if let Some(file_path) = parse_drive_file_path(drive_str) {
                let file_filename = filename_of(&file_path);
                append_file(
                    archive,
                    wsl_distro,
                    &file_path,
                    &format!("{name}/{file_filename}"),
                )?;
                rewritten.push(rewrite_drive_file_path(drive_str, &file_filename));
            } else {
                rewritten.push(drive_str.clone());
            }
        }
        exported_drives = Some(rewritten);
    }

    let mut exported_isos = qemu.readonly_isos.clone();
    if let Some(ref isos) = qemu.readonly_isos {
        let mut rewritten = Vec::new();
        for iso_path in isos {
            let iso_filename = filename_of(iso_path);
            append_file(
                archive,
                wsl_distro,
                iso_path,
                &format!("{name}/{iso_filename}"),
            )?;
            rewritten.push(iso_filename);
        }
        exported_isos = Some(rewritten);
    }

    exported_desc.backend = BackendConfig::Qemu(QemuConfig {
        image: image_filename,
        uefi: exported_uefi,
        cpu_model: qemu.cpu_model.clone(),
        additional_drives: exported_drives,
        additional_devices: qemu.additional_devices.clone(),
        tpm: qemu.tpm,
        nvme: qemu.nvme,
        readonly_isos: exported_isos,
    });

    Ok(())
}

fn export_tart<W: std::io::Write>(
    name: &str,
    tart: &TartConfig,
    archive: &mut tar::Builder<W>,
    exported_desc: &mut ImageDescription,
) -> anyhow::Result<()> {
    let tvm_filename = format!("{}.tvm", tart.vm_name);
    let temp_dir = std::env::temp_dir();
    let tvm_temp_path = temp_dir.join(&tvm_filename);

    println!(
        "  Running: tart export {} {}",
        tart.vm_name,
        tvm_temp_path.display()
    );

    let output = std::process::Command::new("tart")
        .arg("export")
        .arg(&tart.vm_name)
        .arg(&tvm_temp_path)
        .output()
        .context("Failed to run tart export")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Clean up temp file on failure
        let _ = std::fs::remove_file(&tvm_temp_path);
        anyhow::bail!(format!("tart export failed: {}", stderr.trim()));
    }

    let tvm_raw = tvm_temp_path.to_string_lossy();
    append_file(archive, None, &tvm_raw, &format!("{name}/{tvm_filename}"))?;

    let _ = std::fs::remove_file(&tvm_temp_path);

    exported_desc.backend = BackendConfig::Tart(TartConfig {
        vm_name: tart.vm_name.clone(),
    });

    Ok(())
}
