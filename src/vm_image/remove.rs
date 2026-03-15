use std::path::Path;

use crate::{
    cli::RemoveArgs,
    vm_image::{
        list::print_verbose, setup_qemu::prompt_yes_no, BackendConfig, ImageDescription, QemuConfig,
    },
};

pub fn run_remove(remove_args: &RemoveArgs, home_path: &Path) {
    let desc = ImageDescription::load_from_disk(&remove_args.name, home_path)
        .expect("Failed to load image");
    let name = &desc.name;

    println!("[VirtCI] Removing VM image:");
    print_verbose(&desc);

    let should_delete = if remove_args.force {
        true
    } else {
        prompt_yes_no("Confirm Deletion", true).unwrap()
    };

    if !should_delete {
        return;
    }

    if desc.managed.is_some() && *desc.managed.as_ref().unwrap() {
        match &desc.backend {
            BackendConfig::Qemu(ref qemu) => {
                let res = delete_qemu_managed_files(home_path, &desc.name, qemu)
                    .map_err(|e| format!("Failed to delete QEMU backend files: {e}"));
                if let Err(e) = res {
                    println!("{e}");
                    return;
                }
            }
            BackendConfig::Tart(ref tart) => {
                let output = std::process::Command::new("tart")
                    .arg("delete")
                    .arg(&tart.vm_name)
                    .output()
                    .map_err(|e| format!("Failed to run tart import: {e}"));
                match output {
                    Ok(proc) => {
                        if !proc.status.success() {
                            let stderr = String::from_utf8_lossy(&proc.stderr);
                            println!("tart delete failed: {}", stderr.trim());
                        }
                    }
                    Err(e) => {
                        println!("{e}");
                        return;
                    }
                }
            }
        }

        let vci_image_folder_path = home_path.join(name);
        if let Err(e) = std::fs::remove_dir_all(vci_image_folder_path) {
            println!("Failed to delete VirtCI VM folder: {e}");
        }
    }

    let vci_image_description_path = home_path.join(format!("{name}.vci"));
    if let Err(e) = std::fs::remove_file(vci_image_description_path) {
        println!("Failed to delete VirtCI VM metadata file: {e}");
    }
}

fn delete_qemu_managed_files(
    home_path: &Path,
    name: &str,
    qemu: &QemuConfig,
) -> std::io::Result<()> {
    let vm_dir = home_path.join(name);

    std::fs::remove_file(vm_dir.join(&qemu.image))?;

    if let Some(ref uefi) = qemu.uefi {
        std::fs::remove_file(vm_dir.join(&uefi.code))?;
        std::fs::remove_file(vm_dir.join(&uefi.vars))?;
    }

    if let Some(ref drives) = qemu.additional_drives {
        for drive in drives {
            if let Some(file_path) = super::export::parse_drive_file_path(drive) {
                std::fs::remove_file(vm_dir.join(&file_path))?;
            }
        }
    }

    if let Some(ref isos) = qemu.readonly_isos {
        for iso in isos {
            std::fs::remove_file(vm_dir.join(iso))?;
        }
    }

    Ok(())
}
