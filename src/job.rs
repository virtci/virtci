use colored::Colorize;

use crate::ssh::{self, SshAuth, SshCredentials};
use crate::yaml;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Child;

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

/// Neat
fn is_github_actions() -> bool {
    std::env::var("GITHUB_ACTIONS").is_ok()
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

    pub fn qemu_binary(&self) -> String {
        crate::platform::qemu_binary(*self)
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
        crate::platform::find_uefi_firmware(*self)
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
    pub uefi_firmware: Option<PathBuf>,
    pub uefi: Option<yaml::UefiFirmware>,
    pub cpu_model: Option<String>,
    pub additional_drives: Option<Vec<String>>,
    pub additional_devices: Option<Vec<String>>,
    pub qemu_args: Option<Vec<String>>,
    pub tpm: Option<bool>,
    pub host_env: Vec<String>,
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

fn create_backing_file(
    source_path: &std::path::Path,
    dest_path: &std::path::Path,
) -> std::io::Result<()> {
    let qemu_img = crate::platform::qemu_img_binary();

    let output = std::process::Command::new(&qemu_img)
        .args([
            "create",
            "-f",
            "qcow2",
            "-b",
            &source_path.display().to_string(),
            "-F",
            "qcow2",
            &dest_path.display().to_string(),
        ])
        .output()?;

    if !output.status.success() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "Failed to create backing image: {}",
                String::from_utf8_lossy(&output.stderr)
            ),
        ));
    }

    Ok(())
}

pub struct JobRunner {
    pub job: Job,
    pub host_port: u16,
    pub temp_image: PathBuf,
    pub temp_vars: Option<PathBuf>,
    pub temp_additional_drives: Vec<(String, PathBuf)>, // (original_spec, temp_path)
    qemu_process: Option<Child>,
    tpm_process: Option<Child>,
    tpm_state_dir: Option<PathBuf>,
    tpm_socket_path: Option<PathBuf>,
    offline: bool,
    guest_os: Option<ssh::GuestOs>,
    _port_lock: Option<std::fs::File>,
}

impl JobRunner {
    pub fn new(job: Job, host_port: u16, port_lock: std::fs::File) -> std::io::Result<Self> {
        let name = temp_image_name(host_port, &job.name);
        let temp_image = temp_path(&name);

        let source_image = expand_path(&job.image);
        create_backing_file(&source_image, &temp_image)?;

        // Temp UEFI vars if doing the split firmware code + vars
        let temp_vars = if let Some(yaml::UefiFirmware::Split(ref split)) = job.uefi {
            let vars_name = format!("vci-{}-{}-VARS.fd", host_port, &job.name);
            let temp_vars_path = temp_path(&vars_name);
            let source_vars = expand_path(&split.vars);
            std::fs::copy(&source_vars, &temp_vars_path)?;
            Some(temp_vars_path)
        } else {
            None
        };

        // Other additional drives use backing files, like OpenCore.qcow2 on mac
        let mut temp_additional_drives = Vec::new();
        if let Some(ref drives) = job.additional_drives {
            for (idx, drive_spec) in drives.iter().enumerate() {
                if let Some(file_start) = drive_spec.find("file=") {
                    let after_file = &drive_spec[file_start + 5..];
                    let file_path = if let Some(comma_pos) = after_file.find(',') {
                        &after_file[..comma_pos]
                    } else {
                        after_file
                    };

                    let source_path = expand_path(file_path);
                    let temp_name = format!("vci-{}-{}-drive-{}.qcow2", host_port, &job.name, idx);
                    let temp_path = temp_path(&temp_name);
                    create_backing_file(&source_path, &temp_path)?;

                    let updated_spec = drive_spec.replace(
                        &format!("file={}", file_path),
                        &format!("file={}", temp_path.display()),
                    );
                    temp_additional_drives.push((updated_spec, temp_path));
                } else {
                    temp_additional_drives.push((drive_spec.clone(), PathBuf::new()));
                }
            }
        }

        let (tpm_state_dir, tpm_socket_path) = if job.tpm == Some(true) {
            let state_dir = temp_path(&format!("vci-{}-{}-tpm", host_port, &job.name));
            std::fs::create_dir_all(&state_dir)?;
            let socket_path = state_dir.join("swtpm-sock");
            (Some(state_dir), Some(socket_path))
        } else {
            (None, None)
        };

        let offline = matches!(job.steps[0].kind, StepKind::Offline(true));

        return Ok(Self {
            job,
            host_port,
            temp_image,
            temp_vars,
            temp_additional_drives,
            qemu_process: None,
            tpm_process: None,
            tpm_state_dir,
            tpm_socket_path,
            offline,
            guest_os: None,
            _port_lock: Some(port_lock),
        });
    }

    fn build_qemu_cmd(&self) -> std::process::Command {
        let mut cmd = std::process::Command::new(self.job.arch.qemu_binary());

        cmd.arg("-machine").arg(self.job.arch.qemu_machine());

        if let Some(ref cpu_model) = self.job.cpu_model {
            cmd.arg("-cpu").arg(cpu_model);
        } else {
            cmd.arg("-cpu").arg(self.job.arch.qemu_cpu());
        }

        cmd.arg("-name").arg(&self.job.name);
        cmd.arg("-m").arg(format!("{}M", self.job.memory));
        cmd.arg("-smp").arg(self.job.cpus.to_string());

        if let Some(ref uefi) = self.job.uefi {
            match uefi {
                yaml::UefiFirmware::Boolean(_) | yaml::UefiFirmware::Path(_) => {
                    // Monolithic UEFI (use processed uefi_firmware path)
                    if let Some(ref firmware_path) = self.job.uefi_firmware {
                        cmd.arg("-drive").arg(format!(
                            "if=pflash,format=raw,readonly=on,file={}",
                            firmware_path.display()
                        ));
                    }
                }
                yaml::UefiFirmware::Split(split) => {
                    // Split UEFI: code (readonly) + vars (writable)
                    let code_path = expand_path(&split.code);
                    cmd.arg("-drive").arg(format!(
                        "if=pflash,format=raw,unit=0,readonly=on,file={}",
                        code_path.display()
                    ));
                    if let Some(ref temp_vars) = self.temp_vars {
                        cmd.arg("-drive").arg(format!(
                            "if=pflash,format=raw,unit=1,file={}",
                            temp_vars.display()
                        ));
                    }
                }
            }
        }

        // Some VMs need additional drives like OpenCore bootloader for macOS
        for (drive_spec, _) in &self.temp_additional_drives {
            cmd.arg("-drive").arg(drive_spec);
        }

        // main disk
        // if=none only when additional_devices will attach it
        if self.job.additional_devices.is_some() {
            cmd.arg("-drive").arg(format!(
                "id=SystemDisk,if=none,file={},format=qcow2",
                self.temp_image.display()
            ));
        } else {
            cmd.arg("-drive")
                .arg(format!("file={},format=qcow2", self.temp_image.display()));
        }

        cmd.arg("-display").arg("none");

        // hardware accel if possible
        #[cfg(target_os = "linux")]
        {
            if crate::platform::is_kvm_available() {
                cmd.arg("-accel").arg("kvm");
            }
        }
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

        // TPM stuff
        if let Some(ref socket_path) = self.tpm_socket_path {
            cmd.arg("-chardev")
                .arg(format!("socket,id=chrtpm,path={}", socket_path.display()));
            cmd.arg("-tpmdev").arg("emulator,id=tpm0,chardev=chrtpm");
            cmd.arg("-device").arg("tpm-tis,tpmdev=tpm0");
        }

        if let Some(ref additional_devices) = self.job.additional_devices {
            for device in additional_devices {
                let expanded_device = expand_path_in_string(device);
                cmd.arg("-device").arg(expanded_device);
            }
        }

        // edge case raw args
        if let Some(ref qemu_args) = self.job.qemu_args {
            for arg in qemu_args {
                let expanded_arg = expand_path_in_string(arg);
                cmd.arg(expanded_arg);
            }
        }

        return cmd;
    }

    pub fn start_vm(&mut self) -> std::io::Result<()> {
        if let (Some(ref state_dir), Some(ref socket_path)) =
            (&self.tpm_state_dir, &self.tpm_socket_path)
        {
            // Clean up any leftover socket from previous run
            if socket_path.exists() {
                let _ = std::fs::remove_file(socket_path);
            }

            let mut tpm_cmd = std::process::Command::new("swtpm");
            tpm_cmd
                .arg("socket")
                .arg("--tpmstate")
                .arg(format!("dir={}", state_dir.display()))
                .arg("--ctrl")
                .arg(format!("type=unixio,path={}", socket_path.display()))
                .arg("--tpm2")
                .arg("--daemon");

            self.tpm_process = Some(tpm_cmd.spawn()?);

            std::thread::sleep(std::time::Duration::from_millis(500));

            let mut retries = 0;
            while !socket_path.exists() && retries < 10 {
                std::thread::sleep(std::time::Duration::from_millis(100));
                retries += 1;
            }

            if !socket_path.exists() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("TPM socket not created after 1s: {}", socket_path.display()),
                ));
            }
        }

        let mut cmd = self.build_qemu_cmd();
        let fancy_cmd = format!("{:?}", cmd).replace("\"", "");
        println!("{}", (&fancy_cmd as &str).dimmed());
        self.qemu_process = Some(cmd.spawn()?);
        // Keep _port_lock alive for entire job duration
        return Ok(());
    }

    pub fn stop_vm(&mut self) {
        if let Some(ref mut process) = self.qemu_process {
            let _ = process.kill();
            let _ = process.wait();
        }
        self.qemu_process = None;

        // Stop swtpm daemon if it's running
        if let Some(ref mut process) = self.tpm_process {
            let _ = process.kill();
            let _ = process.wait();
        }
        self.tpm_process = None;

        if let Some(ref socket_path) = self.tpm_socket_path {
            if socket_path.exists() {
                let _ = std::fs::remove_file(socket_path);
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    pub fn restart_vm(&mut self, offline: bool) -> std::io::Result<()> {
        if let Some(ref mut process) = self.qemu_process {
            let _ = process.kill();
            let _ = process.wait();
        }
        self.qemu_process = None;

        self.offline = offline;

        let mut cmd = self.build_qemu_cmd();
        let fancy_cmd = format!("{:?}", cmd).replace("\"", "");
        println!("{}", (&fancy_cmd as &str).dimmed());
        self.qemu_process = Some(cmd.spawn()?);

        return Ok(());
    }

    fn cleanup_temp_image(&self) {
        let _ = std::fs::remove_file(&self.temp_image);
        if let Some(ref temp_vars) = self.temp_vars {
            let _ = std::fs::remove_file(temp_vars);
        }
        for (_, temp_path) in &self.temp_additional_drives {
            if !temp_path.as_os_str().is_empty() {
                let _ = std::fs::remove_file(temp_path);
            }
        }
        // Clean up TPM state directory
        if let Some(ref tpm_state_dir) = self.tpm_state_dir {
            let _ = std::fs::remove_dir_all(tpm_state_dir);
        }
    }

    fn cleanup_port_lock(&self) {
        let lock_path = std::env::temp_dir().join(format!("vci-port-{}.lock", self.host_port));
        let _ = std::fs::remove_file(lock_path);
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

        println!(
            "{}",
            format!("Waiting for SSH on port {}...", self.host_port).dimmed()
        );
        match ssh::wait_for_ssh(self.host_port, ssh::SSH_WAIT_TIMEOUT) {
            Some(secs) => println!("{}", format!("SSH ready after {}s", secs).dimmed()),
            None => {
                return Err(format!(
                    "SSH not available after {}s",
                    ssh::SSH_WAIT_TIMEOUT
                ));
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        let os_detect_future = ssh::detect_guest_os(self.host_port, &creds);
        let guest_os = match tokio::time::timeout(
            tokio::time::Duration::from_secs(60),
            os_detect_future,
        )
        .await
        {
            Ok(os) => {
                println!("{}", format!("  Detected OS: {:?}", os).dimmed());
                os
            }
            Err(_) => {
                println!("{}", "  OS detection timed out, assuming Windows".yellow());
                ssh::GuestOs::Windows
            }
        };
        self.guest_os = Some(guest_os);

        for i in 0..self.job.steps.len() {
            let step_name = self.job.steps[i]
                .name
                .clone()
                .unwrap_or_else(|| format!("Step {}", i + 1));
            let continue_on_error = self.job.steps[i].continue_on_error;

            if is_github_actions() {
                println!("::group::VCI Step {}: {}", i + 1, step_name);
            } else {
                println!(
                    "{}",
                    format!("Step {}: {}", i + 1, step_name).yellow().bold()
                );
            }

            let result = self.run_step(i, &creds).await;

            if is_github_actions() {
                println!("::endgroup::");
            }

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
        use std::time::Duration;

        let step = &self.job.steps[step_idx];
        let timeout_duration = Duration::from_secs(step.timeout);

        match &step.kind {
            StepKind::Run(command) => {
                let command = command.clone();
                let workdir = step.workdir.clone();

                let mut env = HashMap::new();

                for var_name in &self.job.host_env {
                    if let Ok(value) = std::env::var(var_name) {
                        env.insert(var_name.clone(), value);
                    }
                }

                for (key, value) in &step.env {
                    if env.contains_key(key) {
                        eprintln!(
                            "{}",
                            format!("Warning: Step env variable '{}' overrides host_env", key)
                                .yellow()
                        );
                    }
                    env.insert(key.clone(), value.clone());
                }

                let ssh_future =
                    ssh::run_command(self.host_port, creds, &command, workdir.as_deref(), &env);

                let result = tokio::time::timeout(timeout_duration, ssh_future)
                    .await
                    .map_err(|_| {
                        use colored::Colorize;
                        eprintln!(
                            "{}",
                            format!("  Command timed out after {}s", step.timeout)
                                .red()
                                .bold()
                        );
                        format!("Timed out after {}s", step.timeout)
                    })??;

                if result.exit_code != 0 {
                    return Err(format!("Exit code: {}", result.exit_code));
                }

                return Ok(());
            }
            StepKind::Copy(copy_spec) => {
                let from = copy_spec.from.clone();
                let to = copy_spec.to.clone();
                let exclude = &copy_spec.exclude;

                // Try tar-over-SSH cause SFTP keeps having issues with windows
                let copy_future =
                    ssh::copy_files_tar(self.host_port, creds, &from, &to, exclude, self.guest_os, Some(timeout_duration));

                tokio::time::timeout(timeout_duration, copy_future)
                    .await
                    .map_err(|_| format!("Copy timed out after {}s", step.timeout))??;

                // Stupid line endings
                if matches!(self.guest_os, Some(ssh::GuestOs::Windows)) {
                    use colored::Colorize;
                    println!(
                        "{}",
                        "  Converting files to Windows encoding (UTF-8 without BOM + CRLF)..."
                            .dimmed()
                    );

                    let target_dir = if to.starts_with("vm:") { &to[3..] } else { &to };

                    let convert_script = r#"
                        $utf8NoBom = New-Object System.Text.UTF8Encoding $false
                        $extensions = '*.c','*.cpp','*.h','*.hpp','*.cc','*.cxx','*.hxx'
                        $files = Get-ChildItem -Recurse -Include $extensions
                        $count = 0
                        $files | ForEach-Object {
                            try {
                                $bytes = [IO.File]::ReadAllBytes($_.FullName)
                                $content = [System.Text.Encoding]::UTF8.GetString($bytes)
                                $content = $content -replace "`r`n","`n" -replace "`r","`n" -replace "`n","`r`n"
                                [IO.File]::WriteAllText($_.FullName, $content, $utf8NoBom)
                                $count++
                            } catch { }
                        }
                        Write-Host "Converted $count files"
                    "#;

                    let convert_result = ssh::run_command_with_os(
                        self.host_port,
                        creds,
                        convert_script,
                        Some(target_dir),
                        &std::collections::HashMap::new(),
                        self.guest_os,
                    )
                    .await;

                    if let Ok(result) = convert_result {
                        if !result.stdout.trim().is_empty() {
                            println!("{}", format!("  {}", result.stdout.trim()).dimmed());
                        }
                    } else {
                        println!("{}", "  Warning: File conversion failed".yellow());
                    }
                }

                return Ok(());
            }
            StepKind::Offline(offline) => {
                let offline = *offline;
                println!(
                    "{}",
                    format!("  Syncing filesystem before restart...",).dimmed()
                );

                // filesystem sync
                let sync_cmd = match self.guest_os {
                    Some(ssh::GuestOs::Windows) => {
                        "Write-VolumeCache -DriveLetter C ; Start-Sleep -Seconds 2"
                    }
                    _ => "sync", // Unix/Linux/macOS
                };

                let empty_env = std::collections::HashMap::new();
                let sync_future = ssh::run_command_with_os(
                    self.host_port,
                    creds,
                    sync_cmd,
                    None,
                    &empty_env,
                    self.guest_os,
                );

                let sync_result =
                    tokio::time::timeout(tokio::time::Duration::from_secs(30), sync_future).await;

                match sync_result {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => println!(
                        "{}",
                        format!("  Warning: sync command failed: {}", e).yellow()
                    ),
                    Err(_) => {
                        println!("{}", "  Warning: sync command timed out after 30s".yellow())
                    }
                }

                let wait_time = match self.guest_os {
                    Some(ssh::GuestOs::Windows) => 3,
                    _ => 1,
                };
                tokio::time::sleep(tokio::time::Duration::from_secs(wait_time)).await;

                println!(
                    "{}",
                    format!("  Restarting VM (offline={})...", offline).dimmed()
                );
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
        self.cleanup_port_lock();
    }
}

pub async fn run_job(job: Job) -> Result<(), String> {
    let (host_port, port_lock) =
        ssh::find_available_port().ok_or_else(|| "No available ports in range".to_string())?;

    let mut runner = JobRunner::new(job, host_port, port_lock)
        .map_err(|e| format!("Failed to create job runner: {}", e))?;

    crate::set_cleanup_path(runner.temp_image.clone());

    let result = runner.run().await;

    // drop runner BEFORE cleaning up path in case something happens while it's doing its thing
    drop(runner);

    crate::clear_cleanup_path();

    result
}
