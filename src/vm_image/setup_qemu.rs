use core::panic;

use crate::vm_image::{
    expand_path, read_line, read_line_with_default, Arch, BackendConfig, GuestOs, ImageDescription,
    QemuConfig, SshConfig, UefiSplit, VCI_HOME_PATH,
};

/// Interactive QEMU image setup
/// 1. Image name (what to call it)
/// 2. Guest OS selection (will impact some defaults like tpm)
/// 3. Architecture (defaults to host)
/// 4. Path to existing qcow2 file
/// 5. SSH credentials
/// 6. UEFI config (not required)
/// 7. Advanced options (tpm, nvme, cpu model, extra drives/devices)
/// 8. Summary + confirmation
/// 9. Save .vci file
pub fn run_interactive_setup() -> Result<(), String> {
    println!("VCI QEMU Image Setup");
    println!("====================\n");

    let name = prompt_image_name()?;
    let guest_os = prompt_guest_os()?;
    let arch = prompt_architecture()?;
    let image_path = prompt_image_path()?;
    let ssh = prompt_ssh_config()?;
    let uefi = prompt_uefi_config(guest_os, arch)?;
    let (tpm, nvme, cpu_model, additional_drives, additional_devices) =
        prompt_advanced_options(guest_os, arch)?;

    let config = ImageDescription {
        os: guest_os,
        arch,
        ssh,
        backend: BackendConfig::Qemu(QemuConfig {
            image: image_path,
            uefi,
            cpu_model,
            additional_drives,
            additional_devices,
            tpm,
            nvme,
        }),
    };

    print_summary(&name, &config);

    if prompt_confirm("Save this configuration?")? {
        save_config(&name, &config)?;
        println!("\nSaved to {}/{}.vci", VCI_HOME_PATH.display(), name);
        println!("Use in workflows with: image: {}", name);
    } else {
        println!("Setup cancelled.");
    }

    return Ok(());
}

/// Characters that are invalid in filenames across platforms
const INVALID_NAME_CHARS: [char; 12] =
    ['/', '\\', ':', '*', '?', '"', '<', '>', '|', ' ', '.', '\t'];

fn validate_image_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("Name cannot be empty".to_string());
    }

    if let Some(c) = name.chars().find(|c| INVALID_NAME_CHARS.contains(c)) {
        return Err(format!("Name contains invalid character: '{}'", c));
    }

    let vci_path = VCI_HOME_PATH.join(format!("{}.vci", name));
    if vci_path.exists() {
        return Err(format!(
            "VCI image '{}' already exists at {}",
            name,
            vci_path.display()
        ));
    }

    return Ok(());
}

/// Step 1
fn prompt_image_name() -> Result<String, String> {
    println!("Step 1: Image Name");
    println!("  This name will be used in workflow files (e.g., image: win-11-arm64)");

    loop {
        let name = read_line("Image name: ")?;

        match validate_image_name(&name) {
            Ok(()) => {
                println!();
                return Ok(name);
            }
            Err(e) => {
                println!("  Error: {}\n", e);
                continue;
            }
        }
    }
}

/// Step 2
fn prompt_guest_os() -> Result<GuestOs, String> {
    println!("Step 2: Guest OS");
    println!("  1) Linux");
    println!("  2) macOS");
    println!("  3) Windows");
    println!("  4) FreeBSD");
    println!("  5) Other");

    loop {
        let input = read_line("Select OS [1-5]: ")?;

        let os = match input.as_str() {
            "1" => GuestOs::Linux,
            "2" => GuestOs::MacOS,
            "3" => GuestOs::Windows,
            "4" => GuestOs::FreeBSD,
            "5" => GuestOs::Other,
            _ => {
                println!("  Error: Invalid selection. Enter 1-5.\n");
                continue;
            }
        };

        println!();
        return Ok(os);
    }
}

/// Step 3
fn prompt_architecture() -> Result<Arch, String> {
    let default = match std::env::consts::ARCH {
        "x86_64" => Arch::X64,
        "aarch64" => Arch::ARM64,
        "riscv64" => Arch::RISCV64,
        _ => panic!("Unsupported CPU architecture"),
    };

    let default_num = match default {
        Arch::X64 => "1",
        Arch::ARM64 => "2",
        Arch::RISCV64 => "3",
    };

    println!("Step 3: Architecture");
    println!("  1) x64");
    println!("  2) arm64");
    println!("  3) riscv64");

    loop {
        let input = read_line_with_default("Select architecture", default_num)?;

        let arch = match input.as_str() {
            "1" => Arch::X64,
            "2" => Arch::ARM64,
            "3" => Arch::RISCV64,
            _ => {
                println!("  Error: Invalid selection. Enter 1-3.\n");
                continue;
            }
        };

        println!();
        return Ok(arch);
    }
}

/// Step 4
fn prompt_image_path() -> Result<String, String> {
    println!("Step 4: Disk Image Path");
    println!("  Path to the qcow2 disk image file.");

    loop {
        let input = read_line("Image path: ")?;

        if input.is_empty() {
            println!("  Error: Path cannot be empty.\n");
            continue;
        }

        let expanded = expand_path(&input);

        if !expanded.exists() {
            println!("  Error: File does not exist: {}\n", expanded.display());
            continue;
        }

        if !expanded.is_file() {
            println!("  Error: Path is not a file: {}\n", expanded.display());
            continue;
        }

        match validate_qcow2(&expanded) {
            Ok(()) => {}
            Err(e) => {
                println!("  Error: {}\n", e);
                continue;
            }
        }

        let absolute = expanded
            .canonicalize()
            .unwrap_or(expanded)
            .to_string_lossy()
            .to_string();

        println!("  Using: {}\n", absolute);
        return Ok(absolute);
    }
}

/// https://www.qemu.org/docs/master/interop/qcow2.html
fn validate_qcow2(path: &std::path::Path) -> Result<(), String> {
    use std::io::Read;

    let mut file = std::fs::File::open(path).map_err(|e| format!("Cannot open file: {}", e))?;

    let mut header = [0u8; 8];
    file.read_exact(&mut header)
        .map_err(|e| format!("Cannot read file header: {}", e))?;

    // Bytes 0 - 3 "QFI\xfb"
    const QCOW2_MAGIC: [u8; 4] = [0x51, 0x46, 0x49, 0xFB];
    if header[0..4] != QCOW2_MAGIC {
        return Err("Not a valid qcow2 file (invalid magic bytes)".to_string());
    }

    // Bytes 4-7 version number (2 or 3 big-endian u32)
    let version = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    if version != 2 && version != 3 {
        return Err(format!(
            "Unsupported qcow2 version: {} (expected 2 or 3)",
            version
        ));
    }

    return Ok(());
}

/// Step 5
fn prompt_ssh_config() -> Result<SshConfig, String> {
    println!("Step 5: SSH Configuration");
    println!("  1) Password");
    println!("  2) SSH Key");

    let auth_method = loop {
        let input = read_line("Select auth method [1-2]: ")?;
        match input.as_str() {
            "1" => break 1,
            "2" => break 2,
            _ => {
                println!("  Error: Invalid selection. Enter 1 or 2.\n");
                continue;
            }
        }
    };

    println!();

    let user = loop {
        let input = read_line("Username: ")?;
        if input.is_empty() {
            println!("  Error: Username cannot be empty.\n");
            continue;
        }
        break input;
    };

    if auth_method == 1 {
        let pass = loop {
            let input = read_line("Password: ")?;
            if input.is_empty() {
                println!("  Error: Password cannot be empty.\n");
                continue;
            }
            break input;
        };

        println!();
        return Ok(SshConfig {
            user,
            pass: Some(pass),
            key: None,
        });
    } else {
        let key = loop {
            let input = read_line("Private key path: ")?;
            if input.is_empty() {
                println!("  Error: Key path cannot be empty.\n");
                continue;
            }

            let expanded = expand_path(&input);
            if !expanded.exists() {
                println!("  Error: File does not exist: {}\n", expanded.display());
                continue;
            }
            if !expanded.is_file() {
                println!("  Error: Path is not a file: {}\n", expanded.display());
                continue;
            }

            let absolute = expanded
                .canonicalize()
                .unwrap_or(expanded)
                .to_string_lossy()
                .to_string();

            println!("  Using: {}\n", absolute);
            break absolute;
        };

        return Ok(SshConfig {
            user,
            pass: None,
            key: Some(key),
        });
    }
}

/// Step 6
fn prompt_uefi_config(_os: GuestOs, arch: Arch) -> Result<Option<UefiSplit>, String> {
    println!("Step 6: UEFI Configuration");
    println!("  1) No UEFI (legacy BIOS)");
    println!("  2) UEFI (code + vars files)");

    let choice = loop {
        let input = read_line("Select UEFI mode [1-2]: ")?;
        match input.as_str() {
            "1" => break 1,
            "2" => break 2,
            _ => {
                println!("  Error: Invalid selection. Enter 1 or 2.\n");
                continue;
            }
        }
    };

    if choice == 1 {
        println!();
        return Ok(None);
    }

    println!();

    let defaults = find_uefi_firmware(arch);

    let default_code: Option<&str> = {
        if defaults.is_none() {
            None
        } else {
            Some(&defaults.as_ref().unwrap().0)
        }
    };
    let default_vars: Option<&str> = {
        if defaults.is_none() {
            None
        } else {
            Some(&defaults.as_ref().unwrap().1)
        }
    };

    let code = prompt_uefi_file("UEFI code file", default_code)?;
    let vars = prompt_uefi_file("UEFI vars file", default_vars)?;

    println!();
    Ok(Some(UefiSplit { code, vars }))
}

fn prompt_uefi_file(label: &str, default: Option<&str>) -> Result<String, String> {
    loop {
        let input = if let Some(def) = default {
            read_line_with_default(label, def)?
        } else {
            read_line(&format!("{}: ", label))?
        };

        if input.is_empty() {
            println!("  Error: Path cannot be empty.\n");
            continue;
        }

        let expanded = expand_path(&input);

        if !expanded.exists() {
            println!("  Error: File does not exist: {}\n", expanded.display());
            continue;
        }

        if !expanded.is_file() {
            println!("  Error: Path is not a file: {}\n", expanded.display());
            continue;
        }

        let absolute = expanded
            .canonicalize()
            .unwrap_or(expanded)
            .to_string_lossy()
            .to_string();

        return Ok(absolute);
    }
}

/// The 4M variants seem to work best for x64? Maybe? This will try to find the firmware.
fn find_uefi_firmware(arch: Arch) -> Option<(String, String)> {
    let candidates: Vec<(&str, &str)> = match arch {
        Arch::ARM64 => vec![
            // macOS Homebrew
            (
                "/opt/homebrew/share/qemu/edk2-aarch64-code.fd",
                "/opt/homebrew/share/qemu/edk2-arm-vars.fd",
            ),
            // Linux (various distros)
            (
                "/usr/share/AAVMF/AAVMF_CODE.fd",
                "/usr/share/AAVMF/AAVMF_VARS.fd",
            ),
            (
                "/usr/share/edk2/aarch64/QEMU_EFI-pflash.raw",
                "/usr/share/edk2/aarch64/vars-template-pflash.raw",
            ),
        ],
        Arch::X64 => vec![
            // Linux Ubuntu/Debian (4M first)
            (
                "/usr/share/OVMF/OVMF_CODE_4M.fd",
                "/usr/share/OVMF/OVMF_VARS_4M.fd",
            ),
            // Linux Arch (4M)
            (
                "/usr/share/edk2-ovmf/x64/OVMF_CODE.4m.fd",
                "/usr/share/edk2-ovmf/x64/OVMF_VARS.4m.fd",
            ),
            // Linux Ubuntu/Debian (fallback)
            (
                "/usr/share/OVMF/OVMF_CODE.fd",
                "/usr/share/OVMF/OVMF_VARS.fd",
            ),
            // Linux Fedora
            (
                "/usr/share/edk2/ovmf/OVMF_CODE.fd",
                "/usr/share/edk2/ovmf/OVMF_VARS.fd",
            ),
            // macOS Homebrew
            (
                "/opt/homebrew/share/qemu/edk2-x86_64-code.fd",
                "/opt/homebrew/share/qemu/edk2-i386-vars.fd",
            ),
            // Windows
            (
                "C:\\Program Files\\qemu\\share\\edk2-x86_64-code.fd",
                "C:\\Program Files\\qemu\\share\\edk2-i386-vars.fd",
            ),
        ],
        Arch::RISCV64 => vec![(
            "/usr/share/qemu/opensbi-riscv64-generic-fw_dynamic.bin",
            "/usr/share/qemu/opensbi-riscv64-generic-fw_dynamic.bin",
        )],
    };

    for (code, vars) in candidates {
        if std::path::Path::new(code).exists() && std::path::Path::new(vars).exists() {
            return Some((code.to_string(), vars.to_string()));
        }
    }

    return None;
}

/// Step 7
fn prompt_advanced_options(
    os: GuestOs,
    arch: Arch,
) -> Result<
    (
        bool,
        bool,
        Option<String>,
        Option<Vec<String>>,
        Option<Vec<String>>,
    ),
    String,
> {
    todo!("Step 7: Advanced options")
}

fn print_summary(name: &str, config: &ImageDescription) {
    todo!("Print summary")
}

fn prompt_confirm(message: &str) -> Result<bool, String> {
    todo!("Confirm prompt")
}

fn save_config(name: &str, config: &ImageDescription) -> Result<(), String> {
    todo!("Save config")
}
