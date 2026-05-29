// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::{
    path::{Path, PathBuf},
    str::FromStr,
};

pub mod exec;
pub mod qemu;
pub mod qemu_old;
pub mod tart;

use crate::{
    global_paths::VciGlobalPaths,
    vm_image::{Arch, GuestOs, SshTarget},
};

#[derive(Debug, Clone, Default)]
pub struct VmStartConfig {
    /// `None` leaves the backend's current offline state unchanged. The first
    /// boot defaults to online (network enabled).
    pub offline: Option<bool>,
    /// `None` leaves the backend's current cpu count unchanged.
    pub cpus: Option<u32>,
    /// `None` leaves the backend's current memory unchanged.
    pub memory_mb: Option<u64>,
}

pub trait VmBackend {
    fn start_vm(&mut self, cfg: VmStartConfig) -> anyhow::Result<()>;

    fn is_offline(&self) -> bool {
        false
    }

    fn stop_vm(&mut self);

    fn ssh_target(&self) -> SshTarget;

    fn os(&self) -> GuestOs;

    /// Terrible required workaround for tart, without having to run tart as root.
    /// Tart requires root for Softnet-based isolation.
    fn offline_enforce_cmd(&self) -> Option<&'static str> {
        None
    }

    fn run_name(&self) -> String;

    /// With `virtci boot` the user needs to shut down the VM internally.
    fn wait_for_exit(&mut self) {}

    fn serial_log_path(&self) -> Option<&Path> {
        None
    }
}

impl FromStr for Arch {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, ()> {
        match s.to_lowercase().as_str() {
            "x86_64" | "X86_64" | "x64" | "X64" | "amd64" | "AMD64" => Ok(Arch::X64),
            "aarch64" | "arm64" | "ARM64" => Ok(Arch::ARM64),
            "riscv64" | "RISCV64" => Ok(Arch::RISCV64),
            _ => Err(()),
        }
    }
}

impl Default for Arch {
    fn default() -> Self {
        match std::env::consts::ARCH {
            "x86_64" => Arch::X64,
            "aarch64" => Arch::ARM64,
            "riscv64" => Arch::RISCV64,
            other => panic!("Unsupported host architecture: {other}"),
        }
    }
}

pub fn expand_path(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        // Unix: $HOME, Windows: $USERPROFILE
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            return PathBuf::from(home).join(path.strip_prefix("~/").unwrap());
        }
    }
    PathBuf::from(path)
}

pub fn expand_path_in_string(s: &str) -> String {
    if let Some(idx) = s.find("~/") {
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            let home_str = home.to_string_lossy();
            let before = &s[..idx];
            let after = &s[idx + 2..];
            return format!(
                "{}{}{}{}",
                before,
                home_str,
                std::path::MAIN_SEPARATOR,
                after
            );
        }
    }
    s.to_string()
}
