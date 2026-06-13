// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::collections::HashSet;
use std::path::Path;

use crate::VciGlobalPaths;
use crate::vm_image::{BackendConfig, ImageDescription};

pub fn run_list(verbose: bool, paths: &VciGlobalPaths) {
    let mut images = load_all_images(paths);

    if images.is_empty() {
        println!(
            "No VM images found in {} or {}",
            paths.user_home.display(),
            paths.system_home.display()
        );
        return;
    }

    images.sort_by(|a, b| a.name.cmp(&b.name));

    if verbose {
        for (i, img) in images.iter().enumerate() {
            if i > 0 {
                println!();
            }
            print_verbose(img);
        }
    } else {
        for img in &images {
            #[cfg(target_os = "windows")]
            if let Some(distro) = &img.wsl_distro {
                println!("{}  (WSL2: {distro})", img.name);
            } else {
                println!("{}", img.name);
            }
            #[cfg(not(target_os = "windows"))]
            println!("{}", img.name);
        }
    }
}

pub fn load_all_images(paths: &VciGlobalPaths) -> Vec<ImageDescription> {
    let mut images: Vec<ImageDescription> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    for home in paths.image_homes() {
        for img in load_images_in(&home.path) {
            if seen.insert(img.name.clone()) {
                #[cfg(target_os = "windows")]
                let img = {
                    let mut img = img;
                    img.wsl_distro.clone_from(&home.wsl_distro);
                    img
                };
                images.push(img);
            }
        }
    }

    images
}

fn load_images_in(home_path: &Path) -> Vec<ImageDescription> {
    let Ok(entries) = std::fs::read_dir(home_path) else {
        return Vec::new();
    };

    let mut images = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("vci") {
            continue;
        }
        let name = match path.file_stem().and_then(|s| s.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };
        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Warning: failed to read {}: {}", path.display(), e);
                continue;
            }
        };
        let mut desc: ImageDescription = match serde_json::from_str(&contents) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("Warning: failed to parse {}: {}", path.display(), e);
                continue;
            }
        };
        desc.name = name;
        images.push(desc);
    }

    images
}

pub fn print_verbose(img: &ImageDescription) {
    println!("{}:", img.name);
    #[cfg(target_os = "windows")]
    if let Some(distro) = &img.wsl_distro {
        println!("  Location: WSL2 distro '{distro}'");
    }
    println!("  OS:   {:?}", img.os);
    println!("  Arch: {:?}", img.arch);
    println!("  SSH user: {}", img.ssh.user);
    if img.ssh.pass.is_some() {
        println!("  SSH auth: password (hidden)");
    } else if img.ssh.key.is_some() {
        println!("  SSH auth: key (hidden)");
    }

    match &img.backend {
        BackendConfig::Qemu(qemu) => {
            println!("  Backend: QEMU");
            println!("    Image: {}", qemu.image);
            if let Some(ref uefi) = qemu.uefi {
                println!("    UEFI code: {}", uefi.code);
                println!("    UEFI vars: {}", uefi.vars);
            }
            println!(
                "    TPM:  {}",
                if qemu.tpm { "enabled" } else { "disabled" }
            );
            println!(
                "    NVMe: {}",
                if qemu.nvme {
                    "enabled"
                } else {
                    "disabled (virtio-blk)"
                }
            );
            if let Some(ref cpu) = qemu.cpu_model {
                println!("    CPU model: {cpu}");
            }
            if let Some(ref drives) = qemu.additional_drives {
                for drive in drives {
                    println!("    Drive: {drive}");
                }
            }
            if let Some(ref devices) = qemu.additional_devices {
                for device in devices {
                    println!("    Device: {device}");
                }
            }
        }
        BackendConfig::Tart(tart) => {
            println!("  Backend: Tart");
            println!("    VM name: {}", tart.vm_name);
        }
    }
}
