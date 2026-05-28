// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
// https://stackoverflow.com/questions/75527167/serde-deserialize-string-into-u64
use serde_with::{serde_as, DisplayFromStr};

use anyhow::Context;

use crate::VciGlobalPaths;

/// TTL for remote images if 24 hours by default
pub const DEFAULT_REMOTE_TTL_SECS: u32 = 86400;

pub mod boot;
pub mod export;
pub mod import;
pub mod list;
pub mod remove;
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

/// Is the host environment that will be running the stuff. Mostly relevant for Windows / WSL2.
#[derive(Debug, Clone)]
pub enum HostExecTarget {
    Linux,
    MacOS,
    WindowsNative,
    /// Stores the distro
    WSL2(String),
    FreeBSD,
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

// https://stackoverflow.com/a/75527280
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteInfo {
    /// Unix timestamp in seconds of when this image was last pulled / used
    #[serde_as(as = "DisplayFromStr")]
    pub last_used: u64,
    /// Time-to-live in seconds until the cached image is considered stale, and can be removed by
    /// any other virtci runner that does cleanup.
    pub ttl_secs: u32,
    /// Hash of the cached image, used to check if there are any remote changes. Prefixed with the
    /// hash type, such as "sha256:abc123...".
    pub hash: String,
}

impl RemoteInfo {
    pub fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before unix epoch")
            .as_secs()
    }

    pub fn is_expired(&self) -> bool {
        let now_secs = Self::now_secs();
        if now_secs < self.last_used {
            // Someone messing with their time?
            return true;
        }
        let age = now_secs - self.last_used;
        #[allow(clippy::cast_lossless)]
        return age > self.ttl_secs as u64;
    }

    /// Update the last used time.
    pub fn touch(&mut self) {
        self.last_used = Self::now_secs();
    }
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<RemoteInfo>,
    #[cfg(target_os = "windows")]
    #[serde(skip)]
    pub wsl_distro: Option<String>,
}

pub fn read_line(prompt: &str) -> anyhow::Result<String> {
    print!("{prompt}");
    io::stdout().flush()?;

    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    Ok(input.trim().to_string())
}

pub fn read_line_with_default(prompt: &str, default: &str) -> anyhow::Result<String> {
    let full_prompt = format!("{prompt} [{default}]: ");
    let input = read_line(&full_prompt)?;

    if input.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(input)
    }
}

/// If `e` is a permission-denied error, get a space-lead hint string giving the user
/// a useful hint on how to fix it.
pub fn permission_hint(e: &io::Error) -> &'static str {
    if e.kind() != io::ErrorKind::PermissionDenied {
        return "";
    }
    if cfg!(target_os = "windows") {
        " (try running from an elevated shell)"
    } else {
        " (try running with sudo)"
    }
}

#[cfg(unix)]
pub fn ensure_world_readable_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
}
#[cfg(not(unix))]
pub fn ensure_world_readable_dir(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
pub fn ensure_world_readable_file(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644))
}
#[cfg(not(unix))]
pub fn ensure_world_readable_file(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Characters that are invalid in VM image names across platforms.
const INVALID_NAME_CHARS: [char; 12] =
    ['/', '\\', ':', '*', '?', '"', '<', '>', '|', ' ', '.', '\t'];

pub fn validate_image_name(name: &str, paths: &VciGlobalPaths) -> Result<(), String> {
    if name.is_empty() {
        return Err("Name cannot be empty".to_string());
    }

    if let Some(c) = name.chars().find(|c| INVALID_NAME_CHARS.contains(c)) {
        return Err(format!("Name contains invalid character: '{c}'"));
    }

    if let Some(home) = paths.resolve_image_home(name) {
        return Err(format!(
            "VCI image '{}' already exists at {}",
            name,
            home.path.display()
        ));
    }

    Ok(())
}

pub fn save_config(
    config: &ImageDescription,
    home_path: &PathBuf,
    system: bool,
) -> Result<(), String> {
    let needs_create = !home_path.exists();
    if needs_create {
        std::fs::create_dir_all(home_path).map_err(|e| {
            format!(
                "Failed to create VCI home directory {}: {e}{}",
                home_path.display(),
                permission_hint(&e)
            )
        })?;
        if system {
            ensure_world_readable_dir(home_path).map_err(|e| {
                format!("Failed to set permissions on {}: {e}", home_path.display())
            })?;
        }
    }

    let file_path = home_path.join(format!("{}.vci", config.name));

    let json = serde_json::to_string_pretty(config)
        .map_err(|e| format!("Failed to serialize config: {e}"))?;

    std::fs::write(&file_path, json).map_err(|e| {
        format!(
            "Failed to write config file {}: {e}{}",
            file_path.display(),
            permission_hint(&e)
        )
    })?;
    if system {
        ensure_world_readable_file(&file_path)
            .map_err(|e| format!("Failed to set permissions on {}: {e}", file_path.display()))?;
    }

    Ok(())
}

pub fn run_from_file(
    path: &Path,
    paths: &VciGlobalPaths,
    name: Option<&str>,
    system: bool,
) -> Result<(), String> {
    let json =
        std::fs::read_to_string(path).map_err(|e| format!("Cannot read config file: {e}"))?;

    let mut config: ImageDescription =
        serde_json::from_str(&json).map_err(|e| format!("Invalid JSON config: {e}"))?;

    config.name = if let Some(n) = name {
        n.to_string()
    } else {
        path.file_stem()
            .and_then(|s| s.to_str())
            .ok_or_else(|| "Cannot determine image name from filename".to_string())?
            .to_string()
    };

    if system && matches!(config.backend, BackendConfig::Tart(_)) {
        return Err("--system is not supported for Tart-backed images. Tart stores VM data in per-user storage (~/.tart/vms/), so the system-wide config would point at data that other users cannot access.".to_string());
    }

    validate_image_name(&config.name, paths)?;
    resolve_config_paths(&mut config)?;
    let dest_home = if system {
        paths.system_home.clone()
    } else {
        paths.user_home.clone()
    };
    save_config(&config, &dest_home, system)?;

    println!("Registered '{}'.", config.name);
    println!("Use in workflows with: image: {}", config.name);
    Ok(())
}

fn resolve_config_paths(config: &mut ImageDescription) -> Result<(), String> {
    if let Some(ref key) = config.ssh.key {
        config.ssh.key = Some(resolve_path(key, "SSH key")?);
    }

    match &mut config.backend {
        BackendConfig::Qemu(qemu) => {
            qemu.image = resolve_path(&qemu.image, "image")?;

            if let Some(ref uefi) = qemu.uefi {
                let is_auto = uefi.code == "auto" || uefi.vars == "auto";
                let (code, vars) = if is_auto {
                    setup_qemu::find_uefi_firmware(config.arch).ok_or_else(|| {
                        format!(
                            "UEFI set to 'auto' but no firmware found for {:?} on this system",
                            config.arch
                        )
                    })?
                } else {
                    (
                        resolve_path(&uefi.code, "UEFI code")?,
                        resolve_path(&uefi.vars, "UEFI vars")?,
                    )
                };
                qemu.uefi = Some(UefiSplit { code, vars });
            }

            if let Some(ref mut isos) = qemu.readonly_isos {
                for iso in isos.iter_mut() {
                    *iso = resolve_path(iso, "readonly ISO")?;
                }
            }

            if let Some(ref mut drives) = qemu.additional_drives {
                for spec in drives.iter_mut() {
                    *spec = resolve_drive_spec_path(spec)?;
                }
            }
        }
        BackendConfig::Tart(_) => {
            // vm_name is not a filesystem path
        }
    }

    Ok(())
}

fn resolve_path(path_str: &str, label: &str) -> Result<String, String> {
    let expanded = expand_path(path_str);
    if !expanded.exists() {
        return Err(format!(
            "{label} path does not exist: {}",
            expanded.display()
        ));
    }
    expanded
        .canonicalize()
        .map(|p| p.to_string_lossy().to_string())
        .map_err(|e| format!("Cannot resolve {label} path '{}': {e}", expanded.display()))
}

fn resolve_drive_spec_path(spec: &str) -> Result<String, String> {
    let Some(file_start) = spec.find("file=") else {
        return Ok(spec.to_string());
    };
    let after_file = &spec[file_start + 5..];
    let file_path = match after_file.find(',') {
        Some(comma) => &after_file[..comma],
        None => after_file,
    };
    let resolved = resolve_path(file_path, "additional drive")?;
    Ok(spec.replace(&format!("file={file_path}"), &format!("file={resolved}")))
}

pub fn expand_path(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            return PathBuf::from(home).join(path.strip_prefix("~/").unwrap());
        }
    }
    PathBuf::from(path)
}

pub fn load_image(name: &str, file_path: &Path) -> anyhow::Result<ImageDescription> {
    let contents = std::fs::read_to_string(file_path).with_context(|| {
        format!(
            "Failed to load image description '{}' (looked at {})",
            name,
            file_path.display()
        )
    })?;
    let mut desc: ImageDescription = serde_json::from_str(&contents)
        .with_context(|| format!("Failed to parse image description '{name}'"))?;
    desc.name = name.to_string();
    Ok(desc)
}
