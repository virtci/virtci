// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

mod command;
mod copy;

use std::{
    collections::HashMap,
    net::TcpStream,
    sync::Arc,
    time::{Duration, Instant},
};

use russh::client;
use russh::keys::ssh_key;
use russh::keys::PrivateKeyWithHashAlg;

use crate::{backend::VmBackend, vm_image::GuestOs, vm_image::SshTarget, yaml};

pub const SSH_WAIT_TIMEOUT: u64 = 300;
pub const SSH_POLL_INTERVAL: u64 = 2;
/// I don't see why something would take longer than 2 hours realistically.
/// I have definitely compiled gRPC for over an hour, but 2 hours is some lunacy.
/// If it does, the user can specify it themselves.
pub const MAX_TIMEOUT: u64 = 7200;

/// Neat
fn is_github_actions() -> bool {
    std::env::var("GITHUB_ACTIONS").is_ok()
}

pub struct Job {
    pub name: String,
    pub backend: Box<dyn VmBackend>,
    pub host_env: Vec<String>,
    pub steps: Vec<Step>,
}

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

impl Job {
    pub async fn run(&mut self) -> Result<(), String> {
        use colored::Colorize;

        let ssh_target = self.backend.ssh_target();

        let start_offline = matches!(self.steps[0].kind, StepKind::Offline(true));
        self.backend
            .start_vm(start_offline)
            .map_err(|()| format!("Failed to start VM: {}", &self.name))?;

        match wait_for_ssh(&ssh_target.ip, ssh_target.port, SSH_WAIT_TIMEOUT) {
            Some(secs) => println!("{}", format!("SSH ready after {secs}s").dimmed()),
            None => {
                return Err(format!("SSH not available after {SSH_WAIT_TIMEOUT}s"));
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        // Normalize Windows clock to UTC. QEMU's RTC presents UTC, but Windows
        // interprets the RTC as local time by default, corrupting its internal clock.
        // We must set the timezone AND correct the system clock from the host's UTC.
        if self.backend.os() == GuestOs::Windows {
            let unix_ts = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let tz_cmd = format!(
                "Set-TimeZone -Id 'UTC'; Set-Date ([DateTimeOffset]::FromUnixTimeSeconds({unix_ts})).UtcDateTime"
            );
            let empty_env = std::collections::HashMap::new();
            let tz_future =
                command::run_command(&ssh_target, &tz_cmd, None, &empty_env, self.backend.os());
            match tokio::time::timeout(tokio::time::Duration::from_secs(30), tz_future).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    eprintln!(
                        "{}",
                        format!("Warning: failed to set timezone/clock to UTC: {e}").yellow()
                    );
                }
                Err(_) => {
                    eprintln!(
                        "{}",
                        "Warning: timezone/clock set timed out after 30s".yellow()
                    );
                }
            }
        }

        println!(
            "{}",
            format!(
                "Connect to this VM while running: virtci shell {}",
                self.backend.run_name()
            )
            .magenta()
        );

        for i in 0..self.steps.len() {
            let step_name = self.steps[i]
                .name
                .clone()
                .unwrap_or_else(|| format!("Step {}", i + 1));
            let continue_on_error = self.steps[i].continue_on_error;

            if is_github_actions() {
                println!("::group::VCI Step {}: {}", i + 1, step_name);
            } else {
                println!(
                    "{}",
                    format!("Step {}: {}", i + 1, step_name).yellow().bold()
                );
            }

            let result = self.run_step(i).await;

            if is_github_actions() {
                println!("::endgroup::");
            }

            match result {
                Ok(()) => (),
                Err(ref e) => {
                    if continue_on_error {
                        println!("{}", format!("  Failed (continuing): {e}").yellow());
                    } else {
                        return Err(format!("Step '{step_name}' failed: {e}"));
                    }
                }
            }
        }

        Ok(())
    }

    async fn run_step(&mut self, step_idx: usize) -> Result<(), String> {
        use colored::Colorize;

        let step = &self.steps[step_idx];
        let timeout_duration = Duration::from_secs(step.timeout);

        match &step.kind {
            StepKind::Run(command) => {
                let mut env = HashMap::new();
                env.insert("TZ".to_string(), "UTC".to_string());
                for var_name in &self.host_env {
                    if let Ok(value) = std::env::var(var_name) {
                        env.insert(var_name.clone(), value);
                    }
                }
                for (key, value) in &step.env {
                    if env.contains_key(key) {
                        eprintln!(
                            "{}",
                            format!("Warning: Step env variable '{key}' overrides host_env")
                                .yellow()
                        );
                    }
                    env.insert(key.clone(), value.clone());
                }

                let ssh = self.backend.ssh_target();
                let command_future = command::run_command(
                    &ssh,
                    command,
                    step.workdir.as_deref(),
                    &env,
                    self.backend.os(),
                );

                let result = tokio::time::timeout(timeout_duration, command_future)
                    .await
                    .map_err(|_| {
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
            }
            StepKind::Copy(copy_spec) => {
                let ssh = self.backend.ssh_target();
                let copy_future = copy::copy_files_tar(
                    &ssh,
                    &copy_spec.from,
                    &copy_spec.to,
                    &copy_spec.exclude,
                    self.backend.os(),
                    Some(timeout_duration),
                );

                tokio::time::timeout(timeout_duration, copy_future)
                    .await
                    .map_err(|_| format!("Copy timed out after {}s", step.timeout))??;

                let is_host_to_vm = copy_spec.to.starts_with("vm:");
                let should_convert_line_endings =
                    is_host_to_vm && self.backend.os() == GuestOs::Windows && copy_spec.crlf;
                if should_convert_line_endings {
                    copy::convert_windows_line_endings(&ssh, &copy_spec.to).await;
                }
            }
            StepKind::Offline(offline) => {
                println!(
                    "{}",
                    "  Syncing filesystem before restart...".to_string().dimmed()
                );

                // filesystem sync
                {
                    let sync_cmd = match self.backend.os() {
                        GuestOs::Windows => {
                            "Write-VolumeCache -DriveLetter C ; Start-Sleep -Seconds 2"
                        }
                        _ => "sync", // Unix/Linux/macOS
                    };
                    let empty_env = std::collections::HashMap::new();
                    let ssh = self.backend.ssh_target();
                    let sync_future =
                        command::run_command(&ssh, sync_cmd, None, &empty_env, self.backend.os());

                    let sync_result =
                        tokio::time::timeout(tokio::time::Duration::from_secs(30), sync_future)
                            .await;

                    match sync_result {
                        Ok(Ok(_)) => {}
                        Ok(Err(e)) => println!(
                            "{}",
                            format!("  Warning: sync command failed: {e}").yellow()
                        ),
                        Err(_) => {
                            println!("{}", "  Warning: sync command timed out after 30s".yellow());
                        }
                    }
                }

                tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

                {
                    println!(
                        "{}",
                        format!("  Restarting VM (offline={offline})...").dimmed()
                    );

                    self.backend.stop_vm();
                    self.backend
                        .start_vm(*offline)
                        .map_err(|()| "Failed to restart VM")?;

                    let ssh = self.backend.ssh_target();
                    match wait_for_ssh(&ssh.ip, ssh.port, SSH_WAIT_TIMEOUT) {
                        Some(secs) => {
                            println!("{}", format!("  SSH ready after {secs}s").dimmed());
                        }
                        None => return Err("SSH not available after restart".to_string()),
                    }

                    if *offline {
                        if let Some(cmd) = self.backend.offline_enforce_cmd() {
                            let empty_env = std::collections::HashMap::new();
                            let enforce_future = command::run_command(
                                &ssh,
                                cmd,
                                None,
                                &empty_env,
                                self.backend.os(),
                            );

                            match tokio::time::timeout(
                                tokio::time::Duration::from_secs(30),
                                enforce_future,
                            )
                            .await
                            {
                                Ok(Ok(_)) => {}
                                Ok(Err(e)) => {
                                    return Err(format!("offline enforcement failed: {e}"))
                                }
                                Err(_) => {
                                    return Err(
                                        "offline enforcement timed out after 30s".to_string()
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

pub fn wait_for_ssh(ip: &str, port: u16, timeout_secs: u64) -> Option<u64> {
    use std::io::{BufRead, BufReader};

    let timeout = Duration::from_secs(timeout_secs);
    let poll_interval = Duration::from_secs(SSH_POLL_INTERVAL);
    let connect_timeout = Duration::from_secs(5);
    let start = Instant::now();

    loop {
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            return None;
        }

        let addr = format!("{ip}:{port}");
        match TcpStream::connect_timeout(&addr.parse().unwrap(), connect_timeout) {
            Ok(stream) => {
                // QEMU can make the SSH "available" even while the VM is still booting.
                // So must check for a "banner" thingy such as "SSH-2.0-OpenSSH_8.9"
                stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                let mut reader = BufReader::new(stream);
                let mut banner = String::new();
                match reader.read_line(&mut banner) {
                    Ok(_n) => {
                        if banner.starts_with("SSH-") {
                            return Some(elapsed.as_secs());
                        }
                    }
                    Err(_e) => {}
                }
                std::thread::sleep(poll_interval);
            }
            Err(_e) => {
                std::thread::sleep(poll_interval);
            }
        }
    }
}

pub struct ClientHandler;

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    fn check_server_key(
        &mut self,
        _key: &ssh_key::PublicKey,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        async { Ok(true) }
    }
}

pub async fn connect(ssh: &SshTarget) -> Result<client::Handle<ClientHandler>, String> {
    let mut config = client::Config {
        inactivity_timeout: None,
        ..Default::default()
    };

    // https://github.com/Eugeny/tabby/issues/10780
    config.preferred.compression = (&[russh::compression::NONE]).into();

    let config = Arc::new(config);

    let addr = format!("{}:{}", ssh.ip, ssh.port);
    let mut handle = client::connect(config, &addr, ClientHandler)
        .await
        .map_err(|e| format!("SSH connection failed: {e}"))?;

    let cred = &ssh.cred;
    let auth_result = {
        if let Some(ref pass) = cred.pass {
            handle
                .authenticate_password(&cred.user, pass)
                .await
                .map_err(|e| format!("Password auth failed: {e}"))?
        } else {
            let key_path = cred.key.as_ref().unwrap();
            let key_data = std::fs::read_to_string(key_path)
                .map_err(|e| format!("Failed to read key file: {e}"))?;
            let key_pair = russh::keys::decode_secret_key(&key_data, None)
                .map_err(|e| format!("Failed to decode key: {e}"))?;
            let key = PrivateKeyWithHashAlg::new(Arc::new(key_pair), None);
            handle
                .authenticate_publickey(&cred.user, key)
                .await
                .map_err(|e| format!("Key auth failed: {e}"))?
        }
    };

    if !matches!(auth_result, russh::client::AuthResult::Success) {
        return Err("Authentication rejected".to_string());
    }

    Ok(handle)
}
