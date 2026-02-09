use std::str::FromStr;

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
