use crate::yaml;
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    X64,
    ARM64,
    RISCV64,
}

impl Arch {
    pub fn parse(s: &str) -> Option<Arch> {
        match s.to_lowercase().as_str() {
            "x86_64" | "x64" | "amd64" => Some(Arch::X64),
            "aarch64" | "arm64" => Some(Arch::ARM64),
            "riscv64" => Some(Arch::RISCV64),
            _ => None,
        }
    }

    pub fn qemu_binary(&self) -> &'static str {
        match self {
            Arch::X64 => "qemu-system-x86_64",
            Arch::ARM64 => "qemu-system-aarch64",
            Arch::RISCV64 => "qemu-system-riscv64",
        }
    }

    pub fn default() -> Arch {
        match std::env::consts::ARCH {
            "x86_64" => Arch::X64,
            "aarch64" => Arch::ARM64,
            "riscv64" => Arch::RISCV64,
            other => panic!("Unsupported host architecture: {}", other),
        }
    }
}

pub struct Job {
    pub name: String,
    pub image: String,
    pub arch: Arch,
    pub cpus: u32,
    /// Megabytes
    pub memory: u64,
    pub user: String,
    pub pass: Option<String>,
    pub key: Option<String>,
    /// Port within the VM that SSH accesses.
    pub port: u16,
    pub steps: Vec<Step>,
}

/// I don't see why something would take longer than 2 hours realistically.
/// I have definitely compiled gRPC for over an hour, but 2 hours is some lunacy.
/// If it does, the user can specify it themselves.
pub const MAX_TIMEOUT: u64 = 7200;

pub const DEFAULT_VM_PORT: u16 = 22;

pub struct Step {
    pub name: Option<String>,
    pub kind: StepKind,
    pub workdir: Option<String>,
    /// Seconds
    pub timeout: u64,
    pub env: HashMap<String, String>,
    pub continue_on_error: bool,
}

pub enum StepKind {
    Run(String),
    Copy(yaml::CopySpec),
    Offline(bool),
}
