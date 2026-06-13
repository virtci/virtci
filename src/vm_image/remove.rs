use crate::{
    VciGlobalPaths,
    cli::RemoveArgs,
    vm_image::{BackendConfig, list::print_verbose, permission_hint, setup_qemu::prompt_yes_no},
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
        desc.wsl_distro.clone_from(&home.wsl_distro);
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

    #[cfg(target_os = "windows")]
    if let Some(distro) = home.wsl_distro.clone() {
        remove_wsl2_image(&home, name, &distro);
        return;
    }

    let mut home_path = home.path.clone();
    home_path.pop();
    match &desc.backend {
        // Any file inside the `<home>/<name>/` per-VM directory is owned by VirtCI, and thus must
        // be deleted during remove.
        BackendConfig::Qemu(_) => {
            let vm_dir = home_path.join(name);
            if vm_dir.exists()
                && let Err(e) = std::fs::remove_dir_all(&vm_dir)
            {
                println!(
                    "Failed to delete VirtCI VM folder: {e}{}",
                    permission_hint(&e)
                );
            }
        }
        // Tart has no per-VM file dir; the `managed` flag is its ownership signal.
        BackendConfig::Tart(tart) => {
            if desc.managed == Some(true) {
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
    }

    if let Err(e) = std::fs::remove_file(&home.path) {
        println!(
            "Failed to delete VirtCI VM metadata file: {e}{}",
            permission_hint(&e)
        );
    }
}

#[cfg(target_os = "windows")]
fn remove_wsl2_image(home: &crate::global_paths::TargetPath, name: &str, distro: &str) {
    let vci_native = home.native_path(); // e.g. /home/<user>/<name>.vci
    let managed_dir = match vci_native.rsplit_once('/') {
        Some((parent, _)) => format!("{parent}/{name}"),
        None => name.to_string(),
    };

    let output = std::process::Command::new("wsl")
        .args(["-d", distro, "--", "rm", "-rf", &managed_dir, &vci_native])
        .output();

    match output {
        Ok(proc) if proc.status.success() => {}
        Ok(proc) => println!(
            "Failed to delete WSL2 VM files in distro '{distro}': {}",
            String::from_utf8_lossy(&proc.stderr).trim()
        ),
        Err(e) => println!("Failed to run `wsl rm -rf` in distro '{distro}': {e}"),
    }
}
