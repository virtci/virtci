// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::io::Read;
use std::path::Path;

use crate::vm_image::{BackendConfig, ImageDescription, VCI_HOME_PATH};

pub fn run_import(archive_path: &Path) -> Result<(), String> {
    if !archive_path.exists() {
        return Err(format!("File not found: {}", archive_path.display()));
    }

    println!("Importing from {}", archive_path.display());

    let file = std::fs::File::open(archive_path)
        .map_err(|e| format!("Failed to open {}: {}", archive_path.display(), e))?;
    let mut archive = tar::Archive::new(file);

    let entries = archive
        .entries()
        .map_err(|e| format!("Failed to read archive: {e}"))?;

    let mut vci_json: Option<String> = None;
    let mut vci_name: Option<String> = None;

    for entry in entries {
        let mut entry = entry.map_err(|e| format!("Failed to read archive entry: {e}"))?;
        let path = entry
            .path()
            .map_err(|e| format!("Failed to read entry path: {e}"))?
            .to_path_buf();

        let path_str = path.to_string_lossy();

        if path_str.ends_with(".vci") && !path_str.contains('/') {
            let name = path
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or("Invalid .vci filename in archive")?
                .to_string();

            let mut contents = String::new();
            entry
                .read_to_string(&mut contents)
                .map_err(|e| format!("Failed to read .vci from archive: {e}"))?;

            vci_name = Some(name);
            vci_json = Some(contents);
            break;
        }
    }

    let name = vci_name.ok_or("No .vci file found in archive root")?;
    let json = vci_json.unwrap();

    let mut desc: ImageDescription = serde_json::from_str(&json)
        .map_err(|e| format!("Failed to parse .vci from archive: {e}"))?;
    desc.name.clone_from(&name);

    let dest_vci = VCI_HOME_PATH.join(format!("{}.vci", &name));
    if dest_vci.exists() {
        return Err(format!(
            "Image '{}' already exists at {}",
            name,
            dest_vci.display()
        ));
    }

    let managed_dir = VCI_HOME_PATH.join(&name);
    std::fs::create_dir_all(&managed_dir)
        .map_err(|e| format!("Failed to create {}: {}", managed_dir.display(), e))?;

    let file = std::fs::File::open(archive_path)
        .map_err(|e| format!("Failed to reopen {}: {}", archive_path.display(), e))?;
    let mut archive = tar::Archive::new(file);
    let entries = archive
        .entries()
        .map_err(|e| format!("Failed to read archive: {e}"))?;

    let prefix = format!("{name}/");
    let mut extracted_files: Vec<String> = Vec::new();

    for entry in entries {
        let mut entry = entry.map_err(|e| format!("Failed to read archive entry: {e}"))?;
        let path = entry
            .path()
            .map_err(|e| format!("Failed to read entry path: {e}"))?
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
                .map_err(|e| format!("Failed to create directory {}: {}", parent.display(), e))?;
        }

        let mut out_file = std::fs::File::create(&dest)
            .map_err(|e| format!("Failed to create {}: {}", dest.display(), e))?;
        std::io::copy(&mut entry, &mut out_file)
            .map_err(|e| format!("Failed to extract {filename}: {e}"))?;

        extracted_files.push(filename.to_string());
    }

    rewrite_paths_to_managed(&mut desc, &managed_dir);

    if let BackendConfig::Tart(ref tart) = desc.backend {
        let tvm_file = extracted_files
            .iter()
            .find(|f| {
                std::path::Path::new(f)
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("tvm"))
            })
            .ok_or("No .tvm file found in archive for tart backend")?;
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
            .map_err(|e| format!("Failed to run tart import: {e}"))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("tart import failed: {}", stderr.trim()));
        }

        let _ = std::fs::remove_file(&tvm_path);
    }

    desc.managed = Some(true);
    let vci_out = serde_json::to_string_pretty(&desc)
        .map_err(|e| format!("Failed to serialize config: {e}"))?;

    std::fs::create_dir_all(&*VCI_HOME_PATH)
        .map_err(|e| format!("Failed to create {}: {}", VCI_HOME_PATH.display(), e))?;
    std::fs::write(&dest_vci, vci_out)
        .map_err(|e| format!("Failed to write {}: {}", dest_vci.display(), e))?;

    println!("Import complete: {name}");
    println!("  Config: {}", dest_vci.display());
    println!("  Files:  {}", managed_dir.display());
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
