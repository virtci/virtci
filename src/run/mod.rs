// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

pub mod cache;
mod command;
pub mod copy;
pub mod run_id;
pub mod validate;

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::Context;
use russh::client;
use russh::keys::PrivateKeyWithHashAlg;
use russh::keys::ssh_key;

use crate::{
    VciGlobalPaths,
    backend::{VmBackend, VmStartConfig},
    util::git::{GitInfo, GitProvider},
    vm_image::{GuestOs, SshTarget},
    yaml,
};

pub const SSH_WAIT_TIMEOUT: u64 = 600;
pub const SSH_POLL_INTERVAL: u64 = 2;
/// Default ceiling on a *single* SSH connect+auth attempt before it's treated as a (retryable)
/// transport failure. This is deliberately generous and is **not** a knob for the common case: the
/// failure we actually retry around (sshd refusing/resetting a connection right after restart)
/// returns an error in milliseconds, so retries fire immediately no matter how high this is. The
/// ceiling only ever bounds a connection that was accepted but then goes *silent*. Cutting a
/// legitimate-but-slow handshake short is the one thing retrying can't fix — every attempt re-hits
/// the same slow crypto — so we set it well above the worst-case key exchange on slow, nested-TCG,
/// low-clock hardware, and let `VIRTCI_SSH_CONNECT_TIMEOUT` raise it further for anything more
/// pathological.
pub const DEFAULT_SSH_CONNECT_TIMEOUT: u64 = 60;
/// I don't see why something would take longer than 2 hours realistically.
/// I have definitely compiled gRPC for over an hour, but 2 hours is some lunacy.
/// If it does, the user can specify it themselves.
pub const MAX_TIMEOUT: u64 = 7200;

/// Default boot idle timeout: if neither the serial log grows nor SSH makes progress for this many
/// seconds, the VM is presumed wedged and the boot fails. Overridable with
/// `VIRTCI_VM_START_IDLE_TIMEOUT`. Catches a dead VM in ~2 min instead of waiting out the max.
pub const DEFAULT_VM_START_IDLE_TIMEOUT: u64 = 120;
/// Default boot maximum timeout: the absolute ceiling on how long a single VM boot may take, even
/// while it keeps showing progress. Overridable with `VIRTCI_VM_START_MAX_TIMEOUT`. High enough to
/// let a legitimately slow TCG boot finish, while still bounding a VM that fails *noisily* (one that
/// keeps spewing to serial without ever reaching SSH, so the idle timer never trips).
pub const DEFAULT_VM_START_MAX_TIMEOUT: u64 = 1800;

/// How long to wait for a VM to shut down (disk flush as well) before just SIGKILLing that thing.
/// Overridable via the `VIRTCI_CACHE_SHUTDOWN_TIMEOUT` environment variable (in seconds).
const CACHE_SHUTDOWN_TIMEOUT: u64 = 120;

/// Resolve the graceful cache-shutdown timeout, honoring `VIRTCI_CACHE_SHUTDOWN_TIMEOUT` if set to a
/// valid number of seconds, otherwise falling back to [`CACHE_SHUTDOWN_TIMEOUT`].
fn cache_shutdown_timeout() -> u64 {
    match std::env::var("VIRTCI_CACHE_SHUTDOWN_TIMEOUT") {
        Ok(v) => if let Ok(secs) = v.trim().parse::<u64>() { secs } else {
            eprintln!(
                "VirtCI Warning: ignoring invalid VIRTCI_CACHE_SHUTDOWN_TIMEOUT={v:?} (want an integer \
                 number of seconds) using default of {CACHE_SHUTDOWN_TIMEOUT}s."
            );
            CACHE_SHUTDOWN_TIMEOUT
        },
        Err(_) => CACHE_SHUTDOWN_TIMEOUT,
    }
}

/// How often, while waiting for SSH, to print a "still booting" progress line.
const BOOT_STATUS_INTERVAL: u64 = 30;

/// How often, while waiting for SSH, to sample the VM process's CPU time as a liveness signal.
/// Deliberately coarse: a WSL2 sample shells out to the distro, and the idle timeout it feeds is
/// measured in minutes, so there's no need to sample every poll.
const CPU_SAMPLE_INTERVAL: u64 = 15;
/// Minimum share of one CPU core (`1 / CPU_PROGRESS_DIVISOR`) the VM must burn over a sample
/// interval for it to count as boot progress. Set so an actively-emulating guest (which pegs a
/// core under TCG) clears it easily, while the idle housekeeping of a halted/wedged guest's
/// process does not masquerade as progress. `20` => 5%.
const CPU_PROGRESS_DIVISOR: u64 = 20;

/// Once SSH first becomes functional, we don't trust it immediately: a VM that has *just* reached a
/// usable SSH state is often still finishing first-boot work (cloud-init creating the user and
/// reloading sshd, networking re-converging) and can briefly drop the connection right after. So we
/// require it to stay continuously functional for a short "settle" window before declaring the boot
/// done. The window is scaled off the observed boot time (a live measure of how slow/contended this
/// host is) and clamped to this range: cheap on a fast box, proportionate on a slow one.
const SETTLE_DIVISOR: u64 = 10;
const SETTLE_MIN_SECS: u64 = 3;
const SETTLE_MAX_SECS: u64 = 30;
/// How often, during the settle window, to re-confirm SSH is still functional.
const SETTLE_POLL_INTERVAL: u64 = 3;

/// Floor on [`connect_resilient`]'s wall-clock retry budget when a target carries no boot-derived
/// budget (e.g. ad-hoc connections outside a job's step loop). A running job stamps a scaled budget
/// onto its [`SshTarget`]; see [`scaled_settle_secs`] for the same scaling rationale.
const DEFAULT_CONNECT_RETRY_BUDGET_SECS: u64 = 30;

/// Scale a duration off the observed boot time, clamped to `[min, max]`. Used for both the post-boot
/// settle window and the per-step connect retry budget: a longer boot is direct evidence the host is
/// slow/contended right now, so the windows that absorb that slowness should grow with it.
fn scaled_settle_secs(boot_secs: u64) -> u64 {
    (boot_secs / SETTLE_DIVISOR).clamp(SETTLE_MIN_SECS, SETTLE_MAX_SECS)
}

/// Per-step connect retry budget derived from the observed boot time: `max(boot/10, 30s)`,
/// uncapped above so a pathologically slow host still gets a proportionate window.
fn connect_retry_budget(boot_secs: u64) -> Duration {
    Duration::from_secs((boot_secs / SETTLE_DIVISOR).max(DEFAULT_CONNECT_RETRY_BUDGET_SECS))
}

/// Resolve the boot idle/max timeouts from optional raw env-var strings (the values of
/// `VIRTCI_VM_START_IDLE_TIMEOUT` / `VIRTCI_VM_START_MAX_TIMEOUT`). Pure so it can be unit-tested.
///
/// Lenient, matching the rest of virtci's env handling: an unparseable or zero value falls back to
/// its default rather than erroring. The idle timeout is clamped to never exceed the max, since an
/// idle window larger than the ceiling could never fire.
fn resolve_boot_timeouts(idle_raw: Option<&str>, max_raw: Option<&str>) -> (u64, u64) {
    fn parse(raw: Option<&str>, default: u64) -> u64 {
        raw.and_then(|s| s.trim().parse::<u64>().ok())
            .filter(|n| *n > 0)
            .unwrap_or(default)
    }
    let max = parse(max_raw, DEFAULT_VM_START_MAX_TIMEOUT);
    let idle = parse(idle_raw, DEFAULT_VM_START_IDLE_TIMEOUT).min(max);
    (idle, max)
}

/// Read and resolve the boot idle/max timeouts from the environment, warning (but not failing) on a
/// value that is set but unusable.
pub fn boot_timeouts() -> (u64, u64) {
    static WARNED: std::sync::Once = std::sync::Once::new();

    let idle = std::env::var("VIRTCI_VM_START_IDLE_TIMEOUT").ok();
    let max = std::env::var("VIRTCI_VM_START_MAX_TIMEOUT").ok();

    WARNED.call_once(|| {
        for (name, raw) in [
            ("VIRTCI_VM_START_IDLE_TIMEOUT", &idle),
            ("VIRTCI_VM_START_MAX_TIMEOUT", &max),
        ] {
            if let Some(raw) = raw
                && raw.trim().parse::<u64>().ok().is_none_or(|n| n == 0)
            {
                eprintln!("Warning: {name}={raw:?} is not a positive integer; using the default.");
            }
        }
    });

    resolve_boot_timeouts(idle.as_deref(), max.as_deref())
}

/// Per-attempt SSH connect+auth ceiling, from `VIRTCI_SSH_CONNECT_TIMEOUT` (a positive integer
/// number of seconds) or [`DEFAULT_SSH_CONNECT_TIMEOUT`]. See that constant for why it's generous.
fn ssh_connect_timeout() -> Duration {
    let secs = std::env::var("VIRTCI_SSH_CONNECT_TIMEOUT")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_SSH_CONNECT_TIMEOUT);
    Duration::from_secs(secs)
}

pub fn validate_run_name(name: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!name.is_empty(), "job name must not be empty");
    if let Some(bad) = name
        .chars()
        .find(|c| matches!(c, '/' | '\\' | ',' | '\0') || c.is_control())
    {
        anyhow::bail!(
            "job name {name:?} contains an unsupported character ({bad:?}); it builds run file \
             paths and the QEMU process name, so '/', '\\', ',', and control characters are not \
             allowed"
        );
    }
    anyhow::ensure!(
        !name.contains(".."),
        "job name {name:?} must not contain '..' (it builds run file paths)"
    );
    Ok(())
}

pub struct Job {
    pub name: String,
    pub backend: Box<dyn VmBackend>,
    pub host_env: Vec<String>,
    pub steps: Vec<Step>,
    /// Per-step SSH connect retry budget, derived from the observed boot time and refreshed on every
    /// (re)boot. Stamped onto each [`SshTarget`] the job hands to a step via [`Job::ssh`]. `None`
    /// until the first boot completes.
    pub ssh_retry_budget: Option<Duration>,
    pub git_info: Option<GitInfo>,
    /// Cache inputs captured host-side.
    pub cache_fingerprint: cache::metadata::Fingerprint,
    /// TTL (seconds) for a produced cache, from `cache.max_age`.
    pub cache_ttl_secs: Option<u64>,
}

impl Job {
    /// Fetch the backend's SSH target with this job's current boot-derived retry budget stamped on,
    /// so step execution rides out a transient connection drop proportionate to how slow this host
    /// has proven to be.
    fn ssh(&self) -> SshTarget {
        SshTarget {
            retry_budget: self.ssh_retry_budget,
            ..self.backend.ssh_target()
        }
    }
}

pub struct Step {
    pub name: Option<String>,
    pub kind: StepKind,
    pub workdir: Option<String>,
    /// Seconds
    pub timeout: u64,
    pub env: HashMap<String, String>,
    pub continue_on_error: bool,
    /// Skip this step if the run is running from a cache, thus doesn't need to be executed.
    pub skip_if_cached: bool,
}

pub enum StepKind {
    Run(String),
    Copy(yaml::CopySpec),
    Restart(yaml::ResolvedRestart),
}

impl Job {
    pub async fn run(&mut self, _paths: &VciGlobalPaths) -> anyhow::Result<()> {
        use colored::Colorize;

        // Resolve once per job: the initial boot and every `Restart` step share these.
        let (idle_timeout, max_timeout) = boot_timeouts();

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

        let mut ssh_target = self.backend.ssh_target();

        let secs = wait_for_ssh_watching(
            self.backend.as_mut(),
            &ssh_target,
            idle_timeout,
            max_timeout,
        )
        .await?;
        // Derive the per-step connect retry budget from how long this boot took, and stamp it onto
        // the targets used both here (offline-enforce / clock-set) and by every step (via `ssh()`).
        self.ssh_retry_budget = Some(connect_retry_budget(secs));
        ssh_target.retry_budget = self.ssh_retry_budget;
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

        tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;

        if self.backend.is_offline()
            && let Some(cmd) = self.backend.offline_enforce_cmd()
        {
            let empty_env = std::collections::HashMap::new();
            let enforce_future =
                command::run_command(&ssh_target, cmd, None, &empty_env, self.backend.os());
            match tokio::time::timeout(tokio::time::Duration::from_secs(30), enforce_future).await {
                Ok(Ok(res)) if res.exit_code != 0 => {
                    anyhow::bail!("offline enforcement exited with code {}", res.exit_code)
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => anyhow::bail!("offline enforcement failed: {e}"),
                Err(_) => {
                    anyhow::bail!("offline enforcement timed out after 30s");
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

        let is_cached_run = self.backend.is_cached_run();
        for i in 0..self.steps.len() {
            if i == 0 && skip_first {
                continue;
            }
            let step_name = self.steps[i]
                .name
                .clone()
                .unwrap_or_else(|| format!("Step {}", i + 1));

            if is_cached_run && self.steps[i].skip_if_cached {
                println!(
                    "{}",
                    format!(
                        "Step {}: {step_name} will be skipped (running from cache)",
                        i + 1
                    )
                    .dimmed()
                );
                continue;
            }
            let continue_on_error = self.steps[i].continue_on_error;

            let git_provider = GitProvider::detect_provider();

            if let Some(provider) = &git_provider
                && matches!(provider, GitProvider::GitHub)
            {
                println!("::group::VirtCI Step {}: {}", i + 1, step_name);
            } else {
                println!(
                    "{}",
                    format!("Step {}: {}", i + 1, step_name).yellow().bold()
                );
            }

            let result = self.run_step(i).await;

            if let Some(provider) = &git_provider
                && matches!(provider, GitProvider::GitHub)
            {
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

        let clean_shutdown = self.stop_vm_for_capture().await;
        if clean_shutdown
            && let Err(e) = self
                .backend
                .cache_run_files(&self.cache_fingerprint, self.cache_ttl_secs)
            {
                eprintln!(
                    "{}",
                    format!("Warning: failed to write workflow cache: {e:#}").yellow()
                );
            }

        Ok(())
    }

    /// Stop the VM before its disk is captured into the cache. Needs to gracefully shutdown so the
    /// thing doesn't get corrupted and disk can be flushed. SIGKILL when necessary, but that
    /// means the cache cannot be written.
    /// Returns `true` when it is safe to capture the disk into the cache.
    async fn stop_vm_for_capture(&mut self) -> bool {
        use colored::Colorize;

        if !self.backend.produces_cache() {
            self.backend.stop_vm();
            return false;
        }

        let shutdown_cmd = match self.backend.os() {
            GuestOs::Windows => "Stop-Computer -Force",
            _ => "sudo shutdown -h now",
        };
        println!("{}", "Powering off the VM to cache a good disk...".dimmed());

        {
            let ssh = self.ssh();
            let empty_env = std::collections::HashMap::new();
            let fut = command::run_command(&ssh, shutdown_cmd, None, &empty_env, self.backend.os());
            let _ = tokio::time::timeout(Duration::from_secs(15), fut).await;
        }

        let timeout = cache_shutdown_timeout();
        let deadline = Instant::now() + Duration::from_secs(timeout);
        let mut clean = false;
        loop {
            if self.backend.vm_has_exited() {
                clean = true;
                break;
            }
            if Instant::now() >= deadline {
                eprintln!(
                    "{}",
                    format!(
                        "VirtCI Warning: VM did not power off within {timeout}s so forcing stop and \
                         skipping cache write (disk may be corrupted)."
                    )
                    .yellow()
                );
                break;
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }

        self.backend.stop_vm();
        clean
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

                let ssh = self.ssh();
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
                let ssh = self.ssh();
                let guest_os = self.backend.os();

                let copy_future =
                    copy::run_copy_spec(&ssh, copy_spec, guest_os, Some(timeout_duration));

                tokio::time::timeout(timeout_duration, copy_future)
                    .await
                    .map_err(|_| anyhow::anyhow!("Copy timed out after {}s", step.timeout))?
                    .map_err(|e| anyhow::anyhow!(e))?;
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
                    let ssh = self.ssh();
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

                    let (idle_timeout, max_timeout) = boot_timeouts();
                    let mut ssh = self.backend.ssh_target();
                    let secs = wait_for_ssh_watching(
                        self.backend.as_mut(),
                        &ssh,
                        idle_timeout,
                        max_timeout,
                    )
                    .await
                    .context("after restart")?;
                    // Refresh the retry budget from this (re)boot's timing for subsequent steps.
                    self.ssh_retry_budget = Some(connect_retry_budget(secs));
                    ssh.retry_budget = self.ssh_retry_budget;
                    println!("{}", format!("  SSH ready after {secs}s").dimmed());

                    if self.backend.is_offline()
                        && let Some(cmd) = self.backend.offline_enforce_cmd()
                    {
                        let empty_env = std::collections::HashMap::new();
                        let enforce_future =
                            command::run_command(&ssh, cmd, None, &empty_env, self.backend.os());

                        match tokio::time::timeout(
                            tokio::time::Duration::from_secs(30),
                            enforce_future,
                        )
                        .await
                        {
                            Ok(Ok(res)) if res.exit_code != 0 => {
                                anyhow::bail!(
                                    "offline enforcement exited with code {}",
                                    res.exit_code
                                )
                            }
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

        Ok(())
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum SshProgress {
    Ready,
    /// `SSH-` banner exists, but auth and exec didn't work. Probably still provisioning stuff
    /// internally.
    Listening,
    /// Nothing is answering the forwarded port, or what answered isn't sshd.
    NotReady,
}

/// Checks if SSH is ready, or if it's alive and still provisioning.
async fn probe_ssh(ssh: &SshTarget, os: GuestOs) -> SshProgress {
    if !sshd_listening(ssh).await {
        return SshProgress::NotReady;
    }
    if probe_functional(ssh, os).await {
        SshProgress::Ready
    } else {
        SshProgress::Listening
    }
}

/// Check if SSH TCP connection is even present and if it reports `SSH-` banner.
/// Proves that something is alive, even if it cannot yet be used.
async fn sshd_listening(ssh: &SshTarget) -> bool {
    use tokio::io::{AsyncBufReadExt, BufReader};

    let addr = format!("{}:{}", ssh.ip, ssh.port);
    let connect = tokio::net::TcpStream::connect(&addr);
    let Ok(Ok(stream)) = tokio::time::timeout(Duration::from_secs(10), connect).await else {
        return false;
    };
    let mut reader = BufReader::new(stream);
    let mut banner = String::new();
    matches!(
        tokio::time::timeout(Duration::from_secs(10), reader.read_line(&mut banner)).await,
        Ok(Ok(n)) if n > 0 && banner.starts_with("SSH-")
    )
}

/// Actually see if SSH is fully functional, not just that the TCP connection can be established.
async fn probe_functional(ssh: &SshTarget, os: GuestOs) -> bool {
    let Ok(Ok(handle)) = tokio::time::timeout(ssh_connect_timeout(), connect(ssh)).await else {
        return false;
    };
    let ok = exec_trivial(&handle, os).await;
    handle
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await
        .ok();
    ok
}

/// Run a no-op command over an authenticated "handle". Basically just confirms that SSH connection
/// WORKS, not just appears to work.
async fn exec_trivial(handle: &client::Handle<ClientHandler>, os: GuestOs) -> bool {
    let cmd = if os == GuestOs::Windows {
        "exit 0"
    } else {
        "true"
    };
    let Ok(mut channel) = handle.channel_open_session().await else {
        return false;
    };
    if channel.exec(true, cmd).await.is_err() {
        return false;
    }
    loop {
        match channel.wait().await {
            Some(russh::ChannelMsg::ExitStatus { .. }) => return true,
            None => return false,
            _ => {}
        }
    }
}

/// Returns the seconds until SSH was ready.
/// Wait for SSH to become reachable. Uses idle timeout of `idle_timeout_secs`. If the serial log
/// of the VM is growing, then boot progress is considered "in progress", and the idle timeout
/// resets. There is a hard cap timeout though of `max_timeout_secs`.
pub async fn wait_for_ssh_watching(
    backend: &mut dyn VmBackend,
    ssh: &SshTarget,
    idle_timeout_secs: u64,
    max_timeout_secs: u64,
) -> anyhow::Result<u64> {
    use colored::Colorize;

    let serial_path = backend.serial_log_path().map(std::path::Path::to_path_buf);
    let serial_size = |p: &std::path::Path| std::fs::metadata(p).map(|m| m.len()).ok();

    let mut last_size = serial_path.as_deref().and_then(serial_size).unwrap_or(0);
    let mut status_size = last_size;

    // Two extra liveness signals beyond serial growth, both of which stay active during the
    // serial-silent, CPU-bound late-boot phase that cross-arch TCG makes long enough to trip the
    // idle timeout: the VM process burning CPU, and the guest writing to its disk. A "fingerprint"
    // of `(len, mtime)` catches in-place writes that don't grow the file.
    let disk_path = backend.disk_image_path().map(std::path::Path::to_path_buf);
    let disk_fingerprint = |p: &std::path::Path| {
        std::fs::metadata(p)
            .ok()
            .map(|m| (m.len(), m.modified().ok()))
    };
    let mut last_disk = disk_path.as_deref().and_then(disk_fingerprint);

    let idle_timeout = Duration::from_secs(idle_timeout_secs);
    let max_timeout = Duration::from_secs(max_timeout_secs);
    let poll = Duration::from_secs(SSH_POLL_INTERVAL);
    let cpu_sample_interval = Duration::from_secs(CPU_SAMPLE_INTERVAL);

    let os = backend.os();
    let start = Instant::now();
    let mut last_progress = start;
    let mut last_status = start;
    let mut banner_seen = false;
    let mut last_cpu = backend.vm_cpu_time_ns();
    let mut last_cpu_at = start;

    loop {
        if let Some(err) = backend.vm_exit_error() {
            anyhow::bail!("VM process exited while waiting for SSH: {err}");
        }

        match probe_ssh(ssh, os).await {
            SshProgress::Ready => break,
            SshProgress::Listening => {
                // It's listening which means boot progress should be happening.
                // Can't login yet though.
                if !banner_seen {
                    banner_seen = true;
                    println!(
                        "{}",
                        "[VirtCI] SSH banner detected. Waiting for login to be \
                         accepted (VM likely still provisioning)..."
                            .dimmed()
                    );
                }
                last_progress = Instant::now();
            }
            SshProgress::NotReady => {}
        }

        if let Some(size) = serial_path.as_deref().and_then(serial_size)
            && size > last_size
        {
            last_size = size;
            last_progress = Instant::now();
        }

        // Disk-write liveness: a grown file or a bumped mtime both mean the guest just wrote.
        if let Some(fp) = disk_path.as_deref().and_then(disk_fingerprint)
            && last_disk.as_ref().is_none_or(|prev| fp > *prev)
        {
            last_disk = Some(fp);
            last_progress = Instant::now();
        }

        let now = Instant::now();

        // CPU-time liveness, on a slower cadence (a WSL2 sample shells out to the distro). Counts
        // only if the VM burned a meaningful share of a core since the last sample, so an idle
        // process doesn't keep a wedged guest alive. Only advance the anchor on a successful
        // sample, so a transient read failure just retries rather than skewing the next interval.
        if now.duration_since(last_cpu_at) >= cpu_sample_interval
            && let Some(cpu) = backend.vm_cpu_time_ns()
        {
            if let Some(prev) = last_cpu {
                let cpu_delta = cpu.saturating_sub(prev);
                let wall_ns = u64::try_from(now.duration_since(last_cpu_at).as_nanos())?;
                if cpu_delta.saturating_mul(CPU_PROGRESS_DIVISOR) >= wall_ns {
                    last_progress = now;
                }
            }
            last_cpu = Some(cpu);
            last_cpu_at = now;
        }

        let idle = now.duration_since(last_progress);
        let elapsed = now.duration_since(start);

        if idle >= idle_timeout {
            anyhow::bail!(
                "VM appears stuck. No boot progress for {}s (no serial output, no disk writes, no \
                 CPU activity, and SSH not up). Tune with VIRTCI_VM_START_IDLE_TIMEOUT.\n{}",
                idle.as_secs(),
                serial_tail(serial_path.as_deref()),
            );
        }
        if elapsed >= max_timeout {
            anyhow::bail!(
                "VM did not become SSH-reachable within the {max_timeout_secs}s maximum boot \
                 timeout. Tune with VIRTCI_VM_START_MAX_TIMEOUT.\n{}",
                serial_tail(serial_path.as_deref()),
            );
        }

        if last_status.elapsed() >= Duration::from_secs(BOOT_STATUS_INTERVAL) {
            last_status = now;
            let detail = if last_size > status_size {
                format!("serial +{} bytes, still booting", last_size - status_size)
            } else if banner_seen {
                format!(
                    "sshd up, waiting for login ({}s idle, gives up at {idle_timeout_secs}s)",
                    idle.as_secs()
                )
            } else if serial_path.is_some() {
                format!(
                    "quiet for {}s (no serial/disk/CPU progress; gives up at {idle_timeout_secs}s \
                     idle)",
                    idle.as_secs()
                )
            } else {
                "still waiting for SSH".to_string()
            };
            status_size = last_size;
            println!(
                "{}",
                format!(
                    "[VirtCI] Waiting for VM: {}s elapsed, {detail}...",
                    elapsed.as_secs()
                )
                .dimmed()
            );
        }

        tokio::time::sleep(poll).await;
    }

    // SSH needs to stay functional.
    let settle = Duration::from_secs(scaled_settle_secs(start.elapsed().as_secs()));
    let settle_poll = Duration::from_secs(SETTLE_POLL_INTERVAL);
    println!(
        "{}",
        format!(
            "[VirtCI] SSH functional after {}s. Confirming it stays up for {}s before running \
             steps...",
            start.elapsed().as_secs(),
            settle.as_secs()
        )
        .dimmed()
    );

    let mut healthy_since: Option<Instant> = None;
    loop {
        if let Some(err) = backend.vm_exit_error() {
            anyhow::bail!("VM process exited while waiting for SSH: {err}");
        }
        if start.elapsed() >= max_timeout {
            anyhow::bail!(
                "VM did not stay SSH-reachable within the {max_timeout_secs}s maximum boot \
                 timeout (SSH kept dropping during the post-boot settle window). Tune with \
                 VIRTCI_VM_START_MAX_TIMEOUT.\n{}",
                serial_tail(serial_path.as_deref()),
            );
        }

        if probe_ssh(ssh, os).await == SshProgress::Ready {
            let now = Instant::now();
            let since = *healthy_since.get_or_insert(now);
            if now.duration_since(since) >= settle {
                return Ok(start.elapsed().as_secs());
            }
        } else if healthy_since.take().is_some() {
            println!(
                "{}",
                "[VirtCI] SSH dropped during settle; re-confirming before running steps..."
                    .dimmed()
            );
        }

        tokio::time::sleep(settle_poll).await;
    }
}

pub async fn wait_for_ssh(ssh: &SshTarget, os: GuestOs, timeout_secs: u64) -> Option<u64> {
    let start = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);
    let poll = Duration::from_secs(SSH_POLL_INTERVAL);
    loop {
        if start.elapsed() >= timeout {
            return None;
        }
        if let SshProgress::Ready = probe_ssh(ssh, os).await {
            return Some(start.elapsed().as_secs());
        }
        tokio::time::sleep(poll).await;
    }
}

/// Attempt to get last 4KB of serial log. Formatted for log output. Returns an
/// empty string when there's no log or it can't be read.
fn serial_tail(path: Option<&std::path::Path>) -> String {
    use std::io::{Read, Seek, SeekFrom};

    const TAIL_BYTES: u64 = 4096;
    let Some(path) = path else {
        return String::new();
    };
    let (Ok(mut file), Ok(len)) = (
        std::fs::File::open(path),
        std::fs::metadata(path).map(|m| m.len()),
    ) else {
        return String::new();
    };
    if len == 0 {
        return "\n(serial log is empty — the guest produced no console output)".to_string();
    }
    let from = len.saturating_sub(TAIL_BYTES);
    if file.seek(SeekFrom::Start(from)).is_err() {
        return String::new();
    }
    let mut buf = Vec::new();
    if file.take(TAIL_BYTES).read_to_end(&mut buf).is_err() {
        return String::new();
    }
    let tail = String::from_utf8_lossy(&buf);
    format!(
        "[VirtCI] last {} bytes of serial log:\n{}",
        buf.len(),
        tail.trim_end()
    )
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

#[derive(Debug)]
pub enum ConnectError {
    /// Disconnected, EOF mid-handshake, timed out, etc. Possible to happen during sshd boot.
    Transport(String),
    /// Retrying won't help here.
    Fatal(String),
}

impl ConnectError {
    fn is_retryable(&self) -> bool {
        matches!(self, ConnectError::Transport(_))
    }
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::Transport(m) | ConnectError::Fatal(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for ConnectError {}

/// A single SSH connect and authenticate, with no retry and no timeout of its own. Wrapped by
/// callers.
pub async fn connect(ssh: &SshTarget) -> Result<client::Handle<ClientHandler>, ConnectError> {
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
        .map_err(|e| ConnectError::Transport(format!("SSH connection failed: {e}")))?;

    let cred = &ssh.cred;
    let auth_result = {
        if let Some(ref pass) = cred.pass {
            handle
                .authenticate_password(&cred.user, pass)
                .await
                .map_err(|e| ConnectError::Transport(format!("Password auth failed: {e}")))?
        } else {
            let key_path = cred.key.as_ref().unwrap();
            let key_data = std::fs::read_to_string(key_path)
                .map_err(|e| ConnectError::Fatal(format!("Failed to read key file: {e}")))?;
            let key_pair = russh::keys::decode_secret_key(&key_data, None)
                .map_err(|e| ConnectError::Fatal(format!("Failed to decode key: {e}")))?;
            let key = PrivateKeyWithHashAlg::new(Arc::new(key_pair), None);
            handle
                .authenticate_publickey(&cred.user, key)
                .await
                .map_err(|e| ConnectError::Transport(format!("Key auth failed: {e}")))?
        }
    };

    if !matches!(auth_result, russh::client::AuthResult::Success) {
        return Err(ConnectError::Fatal("Authentication rejected".to_string()));
    }

    Ok(handle)
}

/// SSH connect and authenticate. Re-tries. On success, the VM SSH connection is 100% undeniably
/// ready. Used for command execution and copy step execution, NOT for detecting if the VM has
/// started, as the looping attempts can take a while. For VM start detection, see [`probe_ssh`].
///
/// Retries transient transport failures (the classic one being sshd resetting a connection while a
/// VM's networking/sshd re-converges right after boot or restart) on a wall-clock budget rather than
/// a fixed attempt count: no readiness check can guarantee the system never hiccups *after* it's
/// declared ready, so this is the real backstop that lets a step ride out such a hiccup. The budget
/// comes from `ssh.retry_budget` (scaled off the observed boot time by the running job) and falls
/// back to [`DEFAULT_CONNECT_RETRY_BUDGET_SECS`] when unset.
pub async fn connect_resilient(ssh: &SshTarget) -> anyhow::Result<client::Handle<ClientHandler>> {
    use colored::Colorize;

    const BASE_BACKOFF_MS: u64 = 250;
    const MAX_BACKOFF_MS: u64 = 2000;

    let timeout = ssh_connect_timeout();
    let budget = ssh
        .retry_budget
        .unwrap_or(Duration::from_secs(DEFAULT_CONNECT_RETRY_BUDGET_SECS));
    let start = Instant::now();
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let outcome = match tokio::time::timeout(timeout, connect(ssh)).await {
            Ok(result) => result,
            Err(_) => Err(ConnectError::Transport(format!(
                "connect timed out after {}s",
                timeout.as_secs()
            ))),
        };

        match outcome {
            Ok(handle) => return Ok(handle),
            // Keep retrying a transient failure until the wall-clock budget is spent.
            Err(e) if e.is_retryable() && start.elapsed() < budget => {
                let backoff = Duration::from_millis(
                    (BASE_BACKOFF_MS << (attempt - 1).min(20)).min(MAX_BACKOFF_MS),
                );
                eprintln!(
                    "{}",
                    format!(
                        "[VirtCI] SSH connect attempt {attempt} failed ({e}); retrying in {}ms \
                         ({}s/{}s of retry budget used)",
                        backoff.as_millis(),
                        start.elapsed().as_secs(),
                        budget.as_secs()
                    )
                    .dimmed()
                );
                tokio::time::sleep(backoff).await;
            }
            Err(e) => {
                return Err(anyhow::Error::new(e).context(format!(
                    "SSH connection failed after {attempt} attempt(s) over {}s",
                    start.elapsed().as_secs()
                )));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_CONNECT_RETRY_BUDGET_SECS, DEFAULT_VM_START_IDLE_TIMEOUT,
        DEFAULT_VM_START_MAX_TIMEOUT, SETTLE_MAX_SECS, SETTLE_MIN_SECS, connect_retry_budget,
        resolve_boot_timeouts, scaled_settle_secs,
    };

    #[test]
    fn settle_scales_with_boot_time_within_bounds() {
        // ~10% of boot time once past the floor: a 200s boot settles for 20s.
        assert_eq!(scaled_settle_secs(200), 20);
        assert_eq!(scaled_settle_secs(450), 45.min(SETTLE_MAX_SECS));
    }

    #[test]
    fn settle_clamped_to_floor_and_ceiling() {
        // A fast boot still gets the floor (even fast hosts can flap right after boot)...
        assert_eq!(scaled_settle_secs(0), SETTLE_MIN_SECS);
        assert_eq!(scaled_settle_secs(20), SETTLE_MIN_SECS); // 20/10 = 2 -> floored to 3
        // ...and a pathologically slow boot is capped so settle can't run away.
        assert_eq!(scaled_settle_secs(100_000), SETTLE_MAX_SECS);
    }

    #[test]
    fn retry_budget_floored_then_scales_uncapped() {
        // Below the floor, the fixed minimum applies.
        assert_eq!(
            connect_retry_budget(50).as_secs(),
            DEFAULT_CONNECT_RETRY_BUDGET_SECS
        );
        // max(boot/10, 30): 200/10 = 20 < 30 -> 30.
        assert_eq!(connect_retry_budget(200).as_secs(), 30);
        // Past the floor it scales and is intentionally uncapped: 1800/10 = 180.
        assert_eq!(connect_retry_budget(1800).as_secs(), 180);
    }

    #[test]
    fn boot_timeouts_default_when_unset() {
        assert_eq!(
            resolve_boot_timeouts(None, None),
            (DEFAULT_VM_START_IDLE_TIMEOUT, DEFAULT_VM_START_MAX_TIMEOUT)
        );
    }

    #[test]
    fn boot_timeouts_parse_valid() {
        assert_eq!(resolve_boot_timeouts(Some("60"), Some("900")), (60, 900));
        assert_eq!(resolve_boot_timeouts(Some(" 60 "), Some("900")), (60, 900));
    }

    #[test]
    fn boot_timeouts_garbage_falls_back_to_default() {
        assert_eq!(
            resolve_boot_timeouts(Some("abc"), Some("")),
            (DEFAULT_VM_START_IDLE_TIMEOUT, DEFAULT_VM_START_MAX_TIMEOUT)
        );
        // Zero is not a usable timeout, so it falls back too.
        assert_eq!(
            resolve_boot_timeouts(Some("0"), Some("0")),
            (DEFAULT_VM_START_IDLE_TIMEOUT, DEFAULT_VM_START_MAX_TIMEOUT)
        );
    }

    #[test]
    fn boot_timeouts_idle_clamped_to_max() {
        // An idle window larger than the ceiling could never fire, so it's clamped down.
        assert_eq!(resolve_boot_timeouts(Some("900"), Some("300")), (300, 300));
    }
}

#[cfg(test)]
mod name_tests {
    use super::validate_run_name;

    #[test]
    fn accepts_ordinary_names_including_spaces() {
        for ok in ["ubuntu-x64", "build_job", "test 1", "v0.3.1"] {
            assert!(validate_run_name(ok).is_ok(), "{ok:?} should be allowed");
        }
    }

    #[test]
    fn rejects_path_and_qemu_hostile_names() {
        for bad in [
            "",
            "../../etc/cron.d/x",
            "a/b",
            "a\\b",
            "a,b",
            "a..b",
            "a\nb",
        ] {
            assert!(
                validate_run_name(bad).is_err(),
                "{bad:?} should be rejected"
            );
        }
    }
}
