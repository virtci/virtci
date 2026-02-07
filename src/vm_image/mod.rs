use std::io::{self, Write};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub mod setup_qemu;

pub(crate) static VCI_HOME_PATH: std::sync::LazyLock<PathBuf> = std::sync::LazyLock::new(|| {
    if let Some(vci_home) = std::env::var_os("VCI_HOME") {
        return PathBuf::from(vci_home);
    }

    #[cfg(target_os = "macos")]
    {
        // ~/.vci/ (kinda matches tart)
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(".vci");
        }
    }

    #[cfg(target_os = "linux")]
    {
        // $XDG_DATA_HOME/vci or ~/.local/share/vci/
        if let Some(xdg_data) = std::env::var_os("XDG_DATA_HOME") {
            return PathBuf::from(xdg_data).join("vci");
        }
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(".local/share/vci");
        }
    }

    #[cfg(target_os = "windows")]
    {
        // %LOCALAPPDATA%\vci\
        if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
            return PathBuf::from(local_app_data).join("vci");
        }
    }

    return PathBuf::from(".vci");
});

// https://www.linux-kvm.org/downloads/lersek/ovmf-whitepaper-c770f8c.txt
// https://github.com/tianocore/tianocore.github.io/wiki/How-to-run-OVMF
// The UEFI firmware can be split into two sections
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UefiSplit {
    pub code: String,
    pub vars: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Arch {
    X64,
    ARM64,
    RISCV64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum GuestOs {
    Linux,
    MacOS,
    Windows,
    FreeBSD,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum BackendConfig {
    Qemu(QemuConfig),
    Tart(TartConfig),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QemuConfig {
    pub image: String,
    pub uefi: Option<UefiSplit>,
    pub cpu_model: Option<String>,
    pub additional_drives: Option<Vec<String>>,
    pub additional_devices: Option<Vec<String>>,
    pub tpm: bool,
    pub nvme: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TartConfig {
    pub vm_name: String,
}

/// Either `pass` or `key` is required.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConfig {
    pub user: String,
    pub pass: Option<String>,
    pub key: Option<String>,
}

pub struct ImageDescription {
    pub os: GuestOs,
    pub arch: Arch,
    pub backend: BackendConfig,
    pub ssh: SshConfig,
}

pub fn read_line(prompt: &str) -> Result<String, String> {
    print!("{}", prompt);
    io::stdout().flush().map_err(|e| e.to_string())?;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| e.to_string())?;

    return Ok(input.trim().to_string());
}

pub fn read_line_with_default(prompt: &str, default: &str) -> Result<String, String> {
    let full_prompt = format!("{} [{}]: ", prompt, default);
    let input = read_line(&full_prompt)?;

    if input.is_empty() {
        return Ok(default.to_string());
    } else {
        return Ok(input);
    }
}

pub fn expand_path(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            return PathBuf::from(home).join(&path[2..]);
        }
    }
    return PathBuf::from(path);
}
