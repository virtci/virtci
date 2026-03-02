// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::io::{self, Write};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub mod export;
pub mod import;
pub mod list;
pub mod setup_qemu;
#[cfg(target_os = "macos")]
pub mod setup_tart;

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

impl BackendConfig {
    pub fn as_qemu(&self) -> Option<&QemuConfig> {
        match self {
            Self::Qemu(config) => Some(config),
            Self::Tart(_) => None,
        }
    }

    pub fn as_tart(&self) -> Option<&TartConfig> {
        match self {
            Self::Tart(config) => Some(config),
            Self::Qemu(_) => None,
        }
    }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readonly_isos: Option<Vec<String>>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshTarget {
    pub ip: String,
    pub port: u16,
    pub cred: SshConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageDescription {
    #[serde(skip)]
    pub name: String,
    pub os: GuestOs,
    pub arch: Arch,
    pub backend: BackendConfig,
    pub ssh: SshConfig,
    /// When true, VirtCI owns the backing files (stored in home_path/<name>/).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub managed: Option<bool>,
}

pub fn read_line(prompt: &str) -> Result<String, String> {
    print!("{prompt}");
    io::stdout().flush().map_err(|e| e.to_string())?;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| e.to_string())?;

    Ok(input.trim().to_string())
}

pub fn read_line_with_default(prompt: &str, default: &str) -> Result<String, String> {
    let full_prompt = format!("{prompt} [{default}]: ");
    let input = read_line(&full_prompt)?;

    if input.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(input)
    }
}

pub fn expand_path(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            return PathBuf::from(home).join(path.strip_prefix("~/").unwrap());
        }
    }
    PathBuf::from(path)
}
