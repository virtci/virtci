// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use crate::vm_image::{
    expand_path, read_line, read_line_with_default, Arch, BackendConfig, GuestOs, ImageDescription,
    SshConfig, TartConfig, VCI_HOME_PATH,
};

/// Interactive Tart image setup (macOS ARM64 only)
/// 1. Image name (what to call it)
/// 2. Tart VM name (existing VM in tart)
/// 3. Guest OS selection
/// 4. SSH credentials
/// 5. Summary + confirmation
/// 6. Save .vci file
pub fn run_interactive_setup() -> Result<(), String> {
    println!("VCI Tart Image Setup");
    println!("====================\n");

    verify_tart_installed()?;

    let name = prompt_image_name()?;
    let vm_name = prompt_tart_vm_name()?;
    let guest_os = prompt_guest_os()?;
    let ssh = prompt_ssh_config()?;

    let config = ImageDescription {
        name,
        os: guest_os,
        arch: Arch::ARM64,
        ssh,
        managed: None,
        backend: BackendConfig::Tart(TartConfig { vm_name }),
    };

    print_summary(&config);

    if prompt_yes_no("Save this configuration?", true)? {
        save_config(&config)?;
        println!("\nSaved to {}/{}.vci", VCI_HOME_PATH.display(), config.name);
        println!("Use in workflows with: image: {}", config.name);
    } else {
        println!("Setup cancelled.");
    }

    return Ok(());
}

fn verify_tart_installed() -> Result<(), String> {
    match std::process::Command::new("tart").arg("--version").output() {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout);
            println!("  Found tart: {}", version.trim());
            println!();
            Ok(())
        }
        _ => Err("tart is not installed or not in PATH. Install from https://tart.run".to_string()),
    }
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
    println!("  This name will be used in workflow files (e.g., image: macos-sequoia)");

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
fn prompt_tart_vm_name() -> Result<String, String> {
    println!("Step 2: Tart VM Name");
    println!("  The name of an existing tart VM (as shown by `tart list`).");

    let available_vms = list_tart_vms();
    if !available_vms.is_empty() {
        println!("  Available VMs:");
        for vm in &available_vms {
            println!("    - {}", vm);
        }
    }

    loop {
        let vm_name = read_line("Tart VM name: ")?;

        if vm_name.is_empty() {
            println!("  Error: VM name cannot be empty.\n");
            continue;
        }

        if !available_vms.is_empty() && !available_vms.contains(&vm_name) {
            println!(
                "  Warning: '{}' was not found in `tart list`. Proceeding anyway.",
                vm_name
            );
        }

        println!();
        return Ok(vm_name);
    }
}

/// only "local" VMs are relevant. Uses `tart list`
fn list_tart_vms() -> Vec<String> {
    let output = match std::process::Command::new("tart").arg("list").output() {
        Ok(o) if o.status.success() => o,
        _ => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .lines()
        .skip(1) // skip header
        .filter_map(|line| {
            let mut cols = line.split_whitespace();
            let source = cols.next()?;
            let name = cols.next()?;
            if source == "local" && !name.is_empty() {
                Some(name.to_string())
            } else {
                None
            }
        })
        .collect()
}

/// Step 3
fn prompt_guest_os() -> Result<GuestOs, String> {
    println!("Step 3: Guest OS");
    println!("  1) macOS");
    println!("  2) Linux");

    loop {
        let input = read_line_with_default("Select OS", "1")?;

        let os = match input.as_str() {
            "1" => GuestOs::MacOS,
            "2" => GuestOs::Linux,
            _ => {
                println!("  Error: Invalid selection. Enter 1 or 2.\n");
                continue;
            }
        };

        println!();
        return Ok(os);
    }
}

/// Step 4
fn prompt_ssh_config() -> Result<SshConfig, String> {
    println!("Step 4: SSH Configuration");
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

fn prompt_yes_no(prompt: &str, default: bool) -> Result<bool, String> {
    let default_str = if default { "Y/n" } else { "y/N" };
    loop {
        let input = read_line(&format!("{} [{}]: ", prompt, default_str))?;
        match input.to_lowercase().as_str() {
            "" => return Ok(default),
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => {
                println!("  Error: Enter y or n.\n");
                continue;
            }
        }
    }
}

fn print_summary(config: &ImageDescription) {
    println!();
    println!("Configuration Summary");
    println!("=====================");
    println!("  Name: {}", config.name);
    println!("  OS: {:?}", config.os);
    println!("  Architecture: {:?}", config.arch);
    println!();

    if let BackendConfig::Tart(tart) = &config.backend {
        println!("  Tart Backend:");
        println!("    VM name: {}", tart.vm_name);
    }

    println!();
    println!("  SSH:");
    println!("    User: {}", config.ssh.user);
    if config.ssh.pass.is_some() {
        println!("    Auth: password");
    } else if let Some(ref key) = config.ssh.key {
        println!("    Auth: key ({})", key);
    }
    println!();
}

fn save_config(config: &ImageDescription) -> Result<(), String> {
    if !VCI_HOME_PATH.exists() {
        std::fs::create_dir_all(&*VCI_HOME_PATH)
            .map_err(|e| format!("Failed to create VCI home directory: {}", e))?;
    }

    let file_path = VCI_HOME_PATH.join(format!("{}.vci", config.name));

    let json = serde_json::to_string_pretty(config)
        .map_err(|e| format!("Failed to serialize config: {}", e))?;

    std::fs::write(&file_path, json).map_err(|e| format!("Failed to write config file: {}", e))?;

    return Ok(());
}
