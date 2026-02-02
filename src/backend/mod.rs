use std::str::FromStr;

pub mod qemu;

pub trait VmBackend {
    fn clone_image(&self) -> Result<(), ()>;

    fn start_vm(&mut self, offline: bool);

    fn stop_vm(&mut self);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X64,
    ARM64,
    RISCV64,
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
