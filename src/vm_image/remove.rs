use std::path::Path;

use crate::{
    cli::RemoveArgs,
    vm_image::{
        list::print_verbose, permission_hint, setup_qemu::prompt_yes_no, BackendConfig,
        ImageDescription, QemuConfig,
    },
    VciGlobalPaths,
};

pub fn run_remove(remove_args: &RemoveArgs, paths: &VciGlobalPaths) {
    let home = paths
        .resolve_image_home(&remove_args.name)
        .unwrap_or_else(|| {
            panic!(
                "Failed to load image '{}' (looked at {} and {})",
                remove_args.name,
                paths.user_home.display(),
                paths.system_home.display()
            )
        });
    #[cfg_attr(not(target_os = "windows"), allow(unused_mut))]
    let mut desc = super::load_image(&remove_args.name, &home.path).expect("Failed to load image");
    #[cfg(target_os = "windows")]
    {
        desc.wsl_distro = home.wsl_distro.clone();
    }
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
        let mut home_path = home.path.clone();
        home_path.pop();
        match &desc.backend {
            BackendConfig::Qemu(ref qemu) => {
                if let Err(e) = delete_qemu_managed_files(&home_path, &desc.name, qemu) {
                    println!(
                        "Failed to delete QEMU backend files: {e}{}",
                        permission_hint(&e)
                    );
                    return;
                }
            }
            BackendConfig::Tart(ref tart) => {
                let output = std::process::Command::new("tart")
                    .arg("delete")
                    .arg(&tart.vm_name)
                    .output()
                    .map_err(|e| format!("Failed to run tart remove: {e}"));
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
            println!(
                "Failed to delete VirtCI VM folder: {e}{}",
                permission_hint(&e)
            );
        }
    }

    if let Err(e) = std::fs::remove_file(&home.path) {
        println!(
            "Failed to delete VirtCI VM metadata file: {e}{}",
            permission_hint(&e)
        );
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
