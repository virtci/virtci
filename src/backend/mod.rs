use std::{path::PathBuf, str::FromStr};

pub mod qemu;

use crate::vm_image::{Arch, GuestOs, SshConfig};

pub struct SshTarget {
    pub ip: String,
    pub port: u16,
    pub cred: SshConfig,
}

pub trait VmBackend {
    fn setup_clone(&mut self) -> Result<(), ()>;

    fn start_vm(&mut self, offline: bool) -> Result<(), ()>;

    fn stop_vm(&mut self);

    fn ssh_target(&self) -> SshTarget;

    fn os(&self) -> GuestOs;
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
            other => panic!("Unsupported host architecture: {}", other),
        }
    }
}

pub fn expand_path(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        // Unix: $HOME, Windows: $USERPROFILE
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            return PathBuf::from(home).join(&path[2..]);
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
