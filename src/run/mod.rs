// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

mod command;
mod copy;
pub mod run_id;

use std::{
    collections::HashMap,
    net::TcpStream,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use russh::client;
use russh::keys::ssh_key;
use russh::keys::PrivateKeyWithHashAlg;

use crate::{
    backend::{VmBackend, VmStartConfig},
    vm_image::{GuestOs, SshTarget},
    yaml, VciGlobalPaths,
};

pub const SSH_WAIT_TIMEOUT: u64 = 300;
pub const SSH_POLL_INTERVAL: u64 = 2;
pub const SSH_AUTH_RETRY_WINDOW: u64 = 30;
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
    Restart(yaml::ResolvedRestart),
}

impl Job {
    pub async fn run(&mut self, _paths: &VciGlobalPaths) -> anyhow::Result<()> {
        use colored::Colorize;

        let (initial_cfg, skip_first) = match &self.steps[0].kind {
            StepKind::Restart(r) => (
                VmStartConfig {
                    offline: r.offline,
                    cpus: r.cpus,
                    memory_mb: r.memory_mb,
                },
                true,
            ),
            _ => (VmStartConfig::default(), false),
        };
        self.backend
            .start_vm(initial_cfg)
            .with_context(|| format!("Failed to start VM: {}", &self.name))?;

        let ssh_target = self.backend.ssh_target();

        match wait_for_ssh(&ssh_target, SSH_WAIT_TIMEOUT).await {
            Some(secs) => {
                let ssh_cmd = match &ssh_target.cred.key {
                    Some(key) => format!(
                        "ssh -i {} {}@{} -p {}",
                        key, ssh_target.cred.user, ssh_target.ip, ssh_target.port
                    ),
                    None => format!(
                        "ssh {}@{} -p {}",
                        ssh_target.cred.user, ssh_target.ip, ssh_target.port
                    ),
                };
                println!(
                    "{}",
                    format!("SSH ready after {secs}s. [{ssh_cmd}]").dimmed()
                );
            }
            None => {
                anyhow::bail!("SSH not available after {SSH_WAIT_TIMEOUT}s");
            }
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        if self.backend.is_offline() {
            if let Some(cmd) = self.backend.offline_enforce_cmd() {
                let empty_env = std::collections::HashMap::new();
                let enforce_future =
                    command::run_command(&ssh_target, cmd, None, &empty_env, self.backend.os());
                match tokio::time::timeout(tokio::time::Duration::from_secs(30), enforce_future)
                    .await
                {
                    Ok(Ok(_)) => {}
                    Ok(Err(e)) => anyhow::bail!("offline enforcement failed: {e}"),
                    Err(_) => {
                        anyhow::bail!("offline enforcement timed out after 30s");
                    }
                }
            }
        }

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
            if i == 0 && skip_first {
                continue;
            }
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
                        anyhow::bail!("Step '{step_name}' failed: {e}");
                    }
                }
            }
        }

        Ok(())
    }

    async fn run_step(&mut self, step_idx: usize) -> anyhow::Result<()> {
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
                        anyhow::anyhow!("Timed out after {}s", step.timeout)
                    })?
                    .map_err(|e| anyhow::anyhow!(e))?;

                if result.exit_code != 0 {
                    anyhow::bail!("Exit code: {}", result.exit_code);
                }
            }
            StepKind::Copy(copy_spec) => {
                let ssh = self.backend.ssh_target();
                let guest_os = self.backend.os();
                let is_host_to_vm = copy_spec.to.starts_with("vm:");
                let host_is_windows = cfg!(target_os = "windows");
                let guest_is_windows = guest_os == GuestOs::Windows;

                // In-flight tar conversion. Host->VM CRLF is still done in-guest
                // by `convert_windows_line_endings` below, not here.
                let line_endings = if !copy_spec.crlf {
                    copy::LineEndingConversion::None
                } else if is_host_to_vm {
                    if host_is_windows && !guest_is_windows {
                        copy::LineEndingConversion::ToLf
                    } else {
                        copy::LineEndingConversion::None
                    }
                } else if guest_is_windows && !host_is_windows {
                    copy::LineEndingConversion::ToLf
                } else if !guest_is_windows && host_is_windows {
                    copy::LineEndingConversion::ToCrlf
                } else {
                    copy::LineEndingConversion::None
                };

                let copy_future = copy::copy_files_tar(
                    &ssh,
                    &copy_spec.from,
                    &copy_spec.to,
                    &copy_spec.exclude,
                    guest_os,
                    Some(timeout_duration),
                    copy_spec.no_mkdir,
                    copy_spec.allow_empty,
                    line_endings,
                );

                tokio::time::timeout(timeout_duration, copy_future)
                    .await
                    .map_err(|_| anyhow::anyhow!("Copy timed out after {}s", step.timeout))?
                    .map_err(|e| anyhow::anyhow!(e))?;

                let convert_to_crlf = is_host_to_vm && guest_is_windows && copy_spec.crlf;
                if convert_to_crlf {
                    copy::convert_windows_line_endings(&ssh, &copy_spec.to).await;
                }
            }
            StepKind::Restart(restart) => {
                println!(
                    "{}",
                    "  Syncing filesystem before restart..."
                        .to_string()
                        .dimmed()
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
                    use std::fmt::Write;
                    let mut details = String::new();
                    if let Some(o) = restart.offline {
                        let _ = write!(details, "offline={o}");
                    }
                    if let Some(c) = restart.cpus {
                        if !details.is_empty() {
                            details.push_str(", ");
                        }
                        let _ = write!(details, "cpus={c}");
                    }
                    if let Some(m) = restart.memory_mb {
                        if !details.is_empty() {
                            details.push_str(", ");
                        }
                        let _ = write!(details, "memory_mb={m}");
                    }
                    if details.is_empty() {
                        details.push_str("no changes");
                    }
                    println!("{}", format!("  Restarting VM ({details})...").dimmed());

                    let cfg = VmStartConfig {
                        offline: restart.offline,
                        cpus: restart.cpus,
                        memory_mb: restart.memory_mb,
                    };

                    self.backend.stop_vm();
                    self.backend.start_vm(cfg).context("Failed to restart VM")?;

                    let ssh = self.backend.ssh_target();
                    match wait_for_ssh(&ssh, SSH_WAIT_TIMEOUT).await {
                        Some(secs) => {
                            println!("{}", format!("  SSH ready after {secs}s").dimmed());
                        }
                        None => anyhow::bail!("SSH not available after restart"),
                    }

                    if self.backend.is_offline() {
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
                                    anyhow::bail!("offline enforcement failed: {e}")
                                }
                                Err(_) => {
                                    anyhow::bail!("offline enforcement timed out after 30s")
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

pub async fn wait_for_ssh(ssh: &SshTarget, timeout_secs: u64) -> Option<u64> {
    use std::io::{BufRead, BufReader};

    let timeout = Duration::from_secs(timeout_secs);
    let poll_interval = Duration::from_secs(SSH_POLL_INTERVAL);
    let connect_timeout = Duration::from_secs(5);
    let start = Instant::now();
    let addr: std::net::SocketAddr = format!("{}:{}", ssh.ip, ssh.port).parse().unwrap();

    loop {
        if start.elapsed() >= timeout {
            return None;
        }
        match TcpStream::connect_timeout(&addr, connect_timeout) {
            Ok(stream) => {
                stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                let mut reader = BufReader::new(stream);
                let mut banner = String::new();
                if reader.read_line(&mut banner).is_ok() && banner.starts_with("SSH-") {
                    break;
                }
                tokio::time::sleep(poll_interval).await;
            }
            Err(_) => {
                tokio::time::sleep(poll_interval).await;
            }
        }
    }

    let auth_deadline = Instant::now() + Duration::from_secs(SSH_AUTH_RETRY_WINDOW);
    loop {
        let attempt = tokio::time::timeout(Duration::from_secs(5), connect(ssh)).await;
        if let Ok(Ok(handle)) = attempt {
            drop(handle);
            return Some(start.elapsed().as_secs());
        }
        if Instant::now() >= auth_deadline {
            return None;
        }
        tokio::time::sleep(poll_interval).await;
    }
}

pub struct ClientHandler;

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    #[allow(clippy::manual_async_fn)]
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
