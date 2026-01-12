use crate::yaml;
use std::collections::HashMap;

pub struct Job {
    pub name: String,
    pub image: String,
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
pub const MAX_TIMEOUT: u64 = 86400;

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
