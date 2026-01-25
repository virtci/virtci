use std::path::PathBuf;

pub fn qemu_binary(arch: crate::job::Arch) -> String {
    if let Ok(custom) = std::env::var("VCI_QEMU_BINARY") {
        return custom;
    }

    let base = match arch {
        crate::job::Arch::X64 => "qemu-system-x86_64",
        crate::job::Arch::ARM64 => "qemu-system-aarch64",
        crate::job::Arch::RISCV64 => "qemu-system-riscv64",
    };

    #[cfg(target_os = "windows")]
    return format!("{}.exe", base);

    #[cfg(not(target_os = "windows"))]
    return base.to_string();
}

pub fn qemu_img_binary() -> String {
    if let Ok(custom) = std::env::var("VCI_QEMU_IMG_BINARY") {
        return custom;
    }

    #[cfg(target_os = "windows")]
    return "qemu-img.exe".to_string();

    #[cfg(not(target_os = "windows"))]
    return "qemu-img".to_string();
}

pub fn find_uefi_firmware(arch: crate::job::Arch) -> Option<PathBuf> {
    let mut search_paths = Vec::new();

    if let Ok(custom_dir) = std::env::var("VCI_UEFI_FIRMWARE_DIR") {
        search_paths.push(PathBuf::from(custom_dir));
    }

    search_paths.extend(get_firmware_search_paths());

    let firmware_names = get_firmware_names(arch);

    for base in &search_paths {
        for name in &firmware_names {
            let path = base.join(name);
            if path.exists() {
                return Some(path);
            }
        }
    }

    return None;
}

fn get_firmware_search_paths() -> Vec<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        return vec![
            PathBuf::from("/opt/homebrew/share/qemu"),
            PathBuf::from("/usr/local/share/qemu"),
        ];
    }

    #[cfg(target_os = "windows")]
    {
        let mut paths = Vec::<PathBuf>::default();
        if let Ok(localappdata) = std::env::var("LOCALAPPDATA") {
            paths.push(
                PathBuf::from(localappdata)
                    .join("Programs")
                    .join("qemu")
                    .join("share"),
            );
        }

        if let Ok(userprofile) = std::env::var("USERPROFILE") {
            paths.push(
                PathBuf::from(&userprofile)
                    .join("scoop")
                    .join("apps")
                    .join("qemu")
                    .join("current")
                    .join("share"),
            );
        }

        if let Ok(programfiles) = std::env::var("ProgramFiles") {
            paths.push(PathBuf::from(programfiles).join("qemu").join("share"));
        }

        paths.push(PathBuf::from("C:\\msys64\\mingw64\\share\\qemu"));
        paths.push(PathBuf::from("C:\\msys64\\usr\\share\\qemu"));

        // Legacy thing
        if let Ok(qemu_dir) = std::env::var("QEMU_DIR") {
            paths.push(PathBuf::from(qemu_dir).join("share"));
        }

        return paths;
    }

    #[cfg(target_os = "linux")]
    {
        return vec![
            PathBuf::from("/usr/share/qemu"),
            PathBuf::from("/usr/share/OVMF"),
            PathBuf::from("/usr/share/edk2"),
            PathBuf::from("/usr/share/edk2-ovmf"),
        ];
    }
}

fn get_firmware_names(arch: crate::job::Arch) -> Vec<&'static str> {
    match arch {
        crate::job::Arch::X64 => return vec!["edk2-x86_64-code.fd", "OVMF_CODE.fd", "OVMF.fd"],
        crate::job::Arch::ARM64 => return vec!["edk2-aarch64-code.fd", "QEMU_EFI.fd"],
        crate::job::Arch::RISCV64 => return vec!["edk2-riscv-code.fd"],
    }
}

#[cfg(target_os = "linux")]
pub fn is_kvm_available() -> bool {
    return std::path::Path::new("/dev/kvm").exists();
}

#[cfg(target_os = "linux")]
pub fn check_kvm_access() -> Result<(), String> {
    let kvm_path = std::path::Path::new("/dev/kvm");

    if !kvm_path.exists() {
        return Err("KVM module not loaded (modprobe kvm_intel or kvm_amd)".to_string());
    }

    match std::fs::File::open(kvm_path) {
        Ok(_) => return Ok(()),
        Err(e) => {
            if e.kind() == std::io::ErrorKind::PermissionDenied {
                return Err(
                    "Permission denied for /dev/kvm (add user to kvm group and re-login)"
                        .to_string(),
                );
            };
            return Err(format!("Cannot access /dev/kvm: {}", e));
        }
    }
}
