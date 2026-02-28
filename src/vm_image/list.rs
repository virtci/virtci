// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use crate::vm_image::{BackendConfig, ImageDescription, VCI_HOME_PATH};

pub fn run_list(verbose: bool) {
    let mut images = load_all_images();

    if images.is_empty() {
        println!("No VM images found in {}", VCI_HOME_PATH.display());
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
            println!("{}", img.name);
        }
    }
}

fn load_all_images() -> Vec<ImageDescription> {
    let entries = match std::fs::read_dir(&*VCI_HOME_PATH) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
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

fn print_verbose(img: &ImageDescription) {
    println!("{}:", img.name);
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
