use crate::ssh::{self, SshAuth, SshCredentials};
use crate::yaml;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Child;

fn expand_path(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        if let Some(home) = std::env::var_os("HOME") {
            return PathBuf::from(home).join(&path[2..]);
        }
    }
    PathBuf::from(path)
}

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

    pub fn qemu_machine(&self) -> &'static str {
        match self {
            Arch::X64 => "q35",
            Arch::ARM64 => "virt",
            Arch::RISCV64 => "virt",
        }
    }

    pub fn qemu_cpu(&self) -> &'static str {
        match self {
            Arch::X64 => "max",
            Arch::ARM64 => "host",
            Arch::RISCV64 => "max",
        }
    }

    /// UEFI firmware needed. UTM does this automatically I believe.
    pub fn uefi_firmware(&self) -> Option<std::path::PathBuf> {
        let base = if cfg!(target_os = "macos") {
            std::path::PathBuf::from("/opt/homebrew/share/qemu")
        } else {
            std::path::PathBuf::from("/usr/share/qemu")
        };

        let firmware = match self {
            Arch::X64 => base.join("edk2-x86_64-code.fd"),
            Arch::ARM64 => base.join("edk2-aarch64-code.fd"),
            Arch::RISCV64 => base.join("edk2-riscv-code.fd"),
        };

        if firmware.exists() {
            Some(firmware)
        } else {
            None
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

/// unique name based on port
pub fn temp_image_name(host_port: u16, job_name: &str) -> String {
    return format!("vci-{}-{}.qcow2", host_port, job_name);
}

/// Linux: /tmp/
/// Mac: /var/folders/.../
/// Windows: C:\Users\NAME\AppData\Local\Temp\
pub fn temp_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(name);
    return path;
}

pub struct JobRunner {
    pub job: Job,
    pub host_port: u16,
    pub temp_image: PathBuf,
    qemu_process: Option<Child>,
    offline: bool,
}

impl JobRunner {
    pub fn new(job: Job, host_port: u16) -> std::io::Result<Self> {
        let name = temp_image_name(host_port, &job.name);
        let temp_image = temp_path(&name);

        let source_image = expand_path(&job.image);
        std::fs::copy(&source_image, &temp_image)?;

        let offline = matches!(job.steps[0].kind, StepKind::Offline(true));

        return Ok(Self {
            job,
            host_port,
            temp_image,
            qemu_process: None,
            offline,
        });
    }

    fn build_qemu_cmd(&self) -> std::process::Command {
        let mut cmd = std::process::Command::new(self.job.arch.qemu_binary());

        cmd.arg("-machine").arg(self.job.arch.qemu_machine());
        cmd.arg("-cpu").arg(self.job.arch.qemu_cpu());
        cmd.arg("-name").arg(&self.job.name);
        cmd.arg("-m").arg(format!("{}M", self.job.memory));
        cmd.arg("-smp").arg(self.job.cpus.to_string());

        if let Some(firmware) = self.job.arch.uefi_firmware() {
            cmd.arg("-bios").arg(firmware);
        }

        cmd.arg("-drive")
            .arg(format!("file={},format=qcow2", self.temp_image.display()));
        cmd.arg("-display").arg("none");

        // hardware accel if possible
        #[cfg(target_os = "linux")]
        cmd.arg("-accel").arg("kvm");
        #[cfg(target_os = "macos")]
        cmd.arg("-accel").arg("hvf");
        #[cfg(target_os = "windows")]
        cmd.arg("-accel").arg("whpx");
        cmd.arg("-accel").arg("tcg");

        let netdev = if self.offline {
            format!(
                "user,id=net0,restrict=yes,hostfwd=tcp::{}-:{}",
                self.host_port, self.job.port
            )
        } else {
            format!(
                "user,id=net0,hostfwd=tcp::{}-:{}",
                self.host_port, self.job.port
            )
        };
        cmd.arg("-netdev").arg(netdev);
        cmd.arg("-device").arg("virtio-net-pci,netdev=net0");

        return cmd;
    }

    pub fn start_vm(&mut self) -> std::io::Result<()> {
        let mut cmd = self.build_qemu_cmd();
        self.qemu_process = Some(cmd.spawn()?);
        return Ok(());
    }

    pub fn stop_vm(&mut self) {
        if let Some(ref mut process) = self.qemu_process {
            let _ = process.kill();
            let _ = process.wait();
        }
        self.qemu_process = None;
    }

    pub fn restart_vm(&mut self, offline: bool) -> std::io::Result<()> {
        self.stop_vm();
        self.offline = offline;
        self.start_vm()
    }

    pub fn is_running(&mut self) -> bool {
        if let Some(ref mut process) = self.qemu_process {
            match process.try_wait() {
                Ok(Some(_)) => {
                    self.qemu_process = None;
                    return false;
                }
                Ok(None) => return true,
                Err(_) => return false,
            }
        } else {
            return false;
        }
    }

    fn cleanup_temp_image(&self) {
        let _ = std::fs::remove_file(&self.temp_image);
    }

    fn get_credentials(&self) -> SshCredentials {
        let auth = if let Some(ref pass) = self.job.pass {
            SshAuth::Password(pass.clone())
        } else if let Some(ref key) = self.job.key {
            SshAuth::Key(key.clone())
        } else {
            panic!("Job must have either password or key");
        };

        SshCredentials {
            user: self.job.user.clone(),
            auth,
        }
    }

    pub async fn run(&mut self) -> Result<(), String> {
        use colored::Colorize;

        let creds = self.get_credentials();

        self.start_vm()
            .map_err(|e| format!("Failed to start VM: {}", e))?;

        println!("{}", format!("Waiting for SSH on port {}...", self.host_port).dimmed());
        match ssh::wait_for_ssh(self.host_port, ssh::SSH_WAIT_TIMEOUT) {
            Some(secs) => println!("{}", format!("SSH ready after {}s", secs).dimmed()),
            None => {
                return Err(format!(
                    "SSH not available after {}s",
                    ssh::SSH_WAIT_TIMEOUT
                ));
            }
        }

        for i in 0..self.job.steps.len() {
            let step_name = self.job.steps[i]
                .name
                .clone()
                .unwrap_or_else(|| format!("Step {}", i + 1));
            let continue_on_error = self.job.steps[i].continue_on_error;

            println!("{}", format!("Step {}: {}", i + 1, step_name).yellow().bold());

            let result = self.run_step(i, &creds).await;

            match result {
                Ok(_) => (),
                Err(ref e) => {
                    if continue_on_error {
                        println!("{}", format!("  Failed (continuing): {}", e).yellow());
                    } else {
                        return Err(format!("Step '{}' failed: {}", step_name, e));
                    }
                }
            }
        }

        return Ok(());
    }

    async fn run_step(&mut self, step_idx: usize, creds: &SshCredentials) -> Result<(), String> {
        use colored::Colorize;

        let step = &self.job.steps[step_idx];

        match &step.kind {
            StepKind::Run(command) => {
                let command = command.clone();
                let workdir = step.workdir.clone();
                let env = step.env.clone();

                let result =
                    ssh::run_command(self.host_port, creds, &command, workdir.as_deref(), &env)
                        .await?;

                // VM output stays default white
                if !result.stdout.is_empty() {
                    print!("{}", result.stdout);
                }
                if !result.stderr.is_empty() {
                    eprint!("{}", result.stderr);
                }

                if result.exit_code != 0 {
                    return Err(format!("Exit code: {}", result.exit_code));
                }

                return Ok(());
            }
            StepKind::Copy(_copy_spec) => {
                // TODO: implement SFTP copy
                println!("{}", "  (copy not yet implemented)".dimmed().italic());
                return Ok(());
            }
            StepKind::Offline(offline) => {
                let offline = *offline;
                println!("{}", format!("  Restarting VM (offline={})...", offline).dimmed());
                self.restart_vm(offline)
                    .map_err(|e| format!("Failed to restart VM: {}", e))?;

                match ssh::wait_for_ssh(self.host_port, ssh::SSH_WAIT_TIMEOUT) {
                    Some(secs) => println!("{}", format!("  SSH ready after {}s", secs).dimmed()),
                    None => return Err("SSH not available after restart".to_string()),
                }

                return Ok(());
            }
        }
    }
}

impl Drop for JobRunner {
    fn drop(&mut self) {
        self.stop_vm();
        self.cleanup_temp_image();
    }
}

pub async fn run_job(job: Job) -> Result<(), String> {
    let host_port =
        ssh::find_available_port().ok_or_else(|| "No available ports in range".to_string())?;

    let mut runner = JobRunner::new(job, host_port)
        .map_err(|e| format!("Failed to create job runner: {}", e))?;

    crate::set_cleanup_path(runner.temp_image.clone());

    let result = runner.run().await;

    // drop runner BEFORE cleaning up path in case something happens while it's doing its thing
    drop(runner);

    crate::clear_cleanup_path();

    result
}
