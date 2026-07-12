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

use std::fmt::Write;

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
        Ok(v) => {
            if let Ok(secs) = v.trim().parse::<u64>() {
                secs
            } else {
                eprintln!(
                    "VirtCI Warning: ignoring invalid VIRTCI_CACHE_SHUTDOWN_TIMEOUT={v:?} (want an integer \
                 number of seconds) using default of {CACHE_SHUTDOWN_TIMEOUT}s."
                );
                CACHE_SHUTDOWN_TIMEOUT
            }
        }
        Err(_) => CACHE_SHUTDOWN_TIMEOUT,
    }
}

/// How often, while waiting for SSH, to print a "still booting" progress line.
const BOOT_STATUS_INTERVAL: u64 = 30;

/// How often, while waiting for SSH, to sample the VM process's CPU time as a liveness signal.
/// Deliberately coarse: a WSL2 sample shells out to the distro, and the idle timeout it feeds is
/// measured in minutes, so there's no need to sample every poll.
const CPU_SAMPLE_INTERVAL: u64 = 15;
/// VM must do 4% CPU time progress to determine that it is making at least some progress.
const CPU_PROGRESS_DIVISOR: u64 = 25;

/// If the VM seems idle, wait `base_idle + (elapsed / IDLE_SCALE_DIVISOR)` amount of time until it's
/// condiered hanged.
const IDLE_SCALE_DIVISOR: u64 = 4;

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
    /// Best in-guest timeout-enforcement mechanism, probed once on the first successful boot (the
    /// guest OS/toolset doesn't change across restarts). `None` until then; a step running before it
    /// is set just relies on the host-side backstop.
    pub timeout_mech: Option<command::TimeoutMechanism>,
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
    pub timeout: Option<u64>,
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
            .with_context(|| format!("Failed to start VM: {}", self.name))?;

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

        // Probe once for the best way to enforce step timeouts *in the guest* (kill the whole
        // process tree, not just abandon the channel). The guest's toolset is stable across
        // restarts, so this need only happen on the first boot.
        if self.timeout_mech.is_none() {
            self.timeout_mech =
                Some(command::probe_timeout_mechanism(&ssh_target, self.backend.os()).await);
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
                Err(e) => {
                    if continue_on_error {
                        println!("{}", format!("  Failed (continuing): {e:#}").yellow());
                    } else {
                        return Err(e).with_context(|| format!("Step '{step_name}' failed"));
                    }
                }
            }
        }

        let clean_shutdown = self.stop_vm_for_capture().await;
        if clean_shutdown {
            if let Err(e) = self
                .backend
                .cache_run_files(&self.cache_fingerprint, self.cache_ttl_secs)
            {
                eprintln!(
                    "{}",
                    format!("Warning: failed to write workflow cache: {e:#}").yellow()
                );
            }
        } else if self.backend.produces_cache() {
            eprintln!(
                "{}",
                "Warning: skipping workflow cache write because the VM was not cleanly shut down \
                 (disk may be inconsistent)."
                    .yellow()
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

        println!("{}", "Powering off the VM to cache a good disk...".dimmed());
        self.graceful_stop_vm().await
    }

    /// Cleanly shut down the VM. sync the file system and stuff, rather than just SIGKILL.
    async fn graceful_stop_vm(&mut self) -> bool {
        use colored::Colorize;

        let shutdown_cmd = match self.backend.os() {
            GuestOs::Windows => "Stop-Computer -Force",
            _ => "sudo shutdown -h now",
        };

        {
            let ssh = self.ssh();
            let empty_env = std::collections::HashMap::new();
            let fut = command::run_command(&ssh, shutdown_cmd, None, &empty_env, self.backend.os());
            // The command may never return (the VM powers off mid-reply), so just fire it and then
            // watch for the process to exit.
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
                        "VirtCI Warning: VM did not power off within {timeout}s; forcing stop."
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
        let explicit_timeout = step.timeout.filter(|&t| t > 0);

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

                let mech = self
                    .timeout_mech
                    .unwrap_or(command::TimeoutMechanism::Unwrapped);
                let in_guest_timeout =
                    explicit_timeout.is_some() && mech != command::TimeoutMechanism::Unwrapped;
                let effective_command = match explicit_timeout {
                    Some(t) if in_guest_timeout => command::wrap_with_timeout(command, t, mech),
                    _ => command.clone(),
                };
                let host_timeout = match explicit_timeout {
                    None => None,
                    Some(t) if in_guest_timeout => {
                        Some(Duration::from_secs(t + std::cmp::max(10, t / 2)))
                    }
                    Some(t) => Some(Duration::from_secs(t)),
                };

                let ssh = self.ssh();
                let command_future = command::run_command(
                    &ssh,
                    &effective_command,
                    step.workdir.as_deref(),
                    &env,
                    self.backend.os(),
                );

                let result = match host_timeout {
                    Some(dur) => tokio::time::timeout(dur, command_future)
                        .await
                        .map_err(|_| {
                            let secs = explicit_timeout.unwrap_or(0);
                            eprintln!(
                                "{}",
                                format!("  Command timed out after {secs}s").red().bold()
                            );
                            anyhow::anyhow!("Timed out after {secs}s")
                        })?
                        .map_err(|e| anyhow::anyhow!(e))?,
                    None => command_future.await.map_err(|e| anyhow::anyhow!(e))?,
                };

                if in_guest_timeout && result.exit_code == command::TIMEOUT_EXIT_CODE {
                    let secs = explicit_timeout.unwrap_or(0);
                    eprintln!(
                        "{}",
                        format!("  Command timed out after {secs}s").red().bold()
                    );
                    anyhow::bail!("Timed out after {secs}s");
                }

                if result.exit_code != 0 {
                    anyhow::bail!("Exit code: {}", result.exit_code);
                }
            }
            StepKind::Copy(copy_spec) => {
                let ssh = self.ssh();
                let guest_os = self.backend.os();

                let copy_timeout = explicit_timeout.map(Duration::from_secs);
                let copy_future = copy::run_copy_spec(&ssh, copy_spec, guest_os, copy_timeout);

                match copy_timeout {
                    Some(dur) => tokio::time::timeout(dur, copy_future)
                        .await
                        .map_err(|_| anyhow::anyhow!("Copy timed out after {}s", dur.as_secs()))?
                        .map_err(|e| anyhow::anyhow!(e))?,
                    None => copy_future.await.map_err(|e| anyhow::anyhow!(e))?,
                }
            }
            StepKind::Restart(restart) => {
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

                {
                    // Gotta file sync and stuff before shutting down the VM.
                    println!(
                        "{}",
                        "Shutting the VM down cleanly before restart...".dimmed()
                    );
                    self.graceful_stop_vm().await;
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

/// Actually count the bytes in the log rather than `stat`ing the file cause Windows seemingly
/// does the writes in bursts? Not sure why.
struct SerialCounter {
    path: Option<std::path::PathBuf>,
    file: Option<std::fs::File>,
    total: u64,
}

impl SerialCounter {
    fn new(path: Option<std::path::PathBuf>) -> Self {
        Self {
            path,
            file: None,
            total: 0,
        }
    }

    fn poll(&mut self) -> u64 {
        if self.file.is_none()
            && let Some(p) = &self.path
        {
            self.file = std::fs::File::open(p).ok();
        }
        if let Some(f) = &mut self.file
            && let Ok(n) = std::io::copy(f, &mut std::io::sink())
        {
            self.total = self.total.saturating_add(n);
        }
        self.total
    }
}

struct BootSignals {
    /// SSH reached at least the banner/listening stage this tick.
    ssh_progress: bool,
    /// Total bytes drained from the serial log so far.
    serial_bytes: u64,
    /// Number of times the qcow2 disk fingerprint has advanced so far.
    disk_changes: u64,
    /// QMP block-layer IO operations count. `None` if not sampled/available this tick.
    io_ops: Option<u64>,
    /// Cumulative QEMU process CPU nanoseconds, `None` if not sampled this tick.
    cpu_ns: Option<u64>,
}

enum BootVerdict {
    Booting,
    Stuck,
    MaxTimeout,
}

struct BootStatus {
    idle: Duration,
    effective_idle: Duration,
    verdict: BootVerdict,
}

struct BootWatch {
    base_idle: Duration,
    max_timeout: Duration,
    cpu_sample_interval: Duration,
    /// Elapsed time at which progress was last observed.
    last_progress: Duration,
    last_serial: u64,
    last_disk_changes: u64,
    last_io_ops: Option<u64>,
    last_cpu: Option<u64>,
    /// Elapsed time of the last successful CPU sample. Re-try on failed read.
    last_cpu_at: Duration,

    // Diagnostic only (does not affect the verdict). Per-signal snapshot so the status line and
    // the failure message can show which liveness signals are alive and how stale each is.
    /// CPU share of a core measured at the most recent CPU sample.
    last_cpu_pct: Option<f64>,
    /// Whether QMP block-IO stats have ever been readable.
    qmp_seen: bool,
    /// Elapsed time each signal last advanced (counted as progress). `None` if never.
    serial_adv: Option<Duration>,
    disk_adv: Option<Duration>,
    io_adv: Option<Duration>,
    cpu_adv: Option<Duration>,
}

impl BootWatch {
    fn new(
        base_idle: Duration,
        max_timeout: Duration,
        cpu_sample_interval: Duration,
        initial_cpu: Option<u64>,
        initial_io: Option<u64>,
    ) -> Self {
        Self {
            base_idle,
            max_timeout,
            cpu_sample_interval,
            last_progress: Duration::ZERO,
            last_serial: 0,
            last_disk_changes: 0,
            last_io_ops: initial_io,
            last_cpu: initial_cpu,
            last_cpu_at: Duration::ZERO,
            last_cpu_pct: None,
            qmp_seen: initial_io.is_some(),
            serial_adv: None,
            disk_adv: None,
            io_adv: None,
            cpu_adv: None,
        }
    }

    /// Whether enough time has passed since the last successful CPU sample to take another.
    fn slow_sample_due(&self, elapsed: Duration) -> bool {
        elapsed.saturating_sub(self.last_cpu_at) >= self.cpu_sample_interval
    }

    /// How long the idle window can be. Scales with progress elapsed boot time.
    fn effective_idle(&self, elapsed: Duration) -> Duration {
        let scaled = self.base_idle + (Duration::from_secs(elapsed.as_secs() / IDLE_SCALE_DIVISOR));
        scaled.min(self.max_timeout)
    }

    fn signals_summary(&self, elapsed: Duration) -> String {
        let since = |adv: Option<Duration>| match adv {
            Some(at) => format!("{}s ago", elapsed.saturating_sub(at).as_secs()),
            None => "never".to_string(),
        };
        let cpu = match self.last_cpu_pct {
            Some(pct) => format!("cpu={pct:.1}% ({})", since(self.cpu_adv)),
            None => "cpu=n/a".to_string(),
        };
        let qmp = if self.qmp_seen {
            format!(
                "qmp_io_ops={} ({})",
                self.last_io_ops.unwrap_or(0),
                since(self.io_adv)
            )
        } else {
            "qmp=unavailable".to_string()
        };
        format!(
            "signals: serial={}B ({}) | disk_changes={} ({}) | {cpu} | {qmp}",
            self.last_serial,
            since(self.serial_adv),
            self.last_disk_changes,
            since(self.disk_adv),
        )
    }

    fn observe(&mut self, elapsed: Duration, sig: &BootSignals) -> BootStatus {
        let mut progress = sig.ssh_progress;

        if sig.serial_bytes > self.last_serial {
            self.last_serial = sig.serial_bytes;
            self.serial_adv = Some(elapsed);
            progress = true;
        }
        if sig.disk_changes > self.last_disk_changes {
            self.last_disk_changes = sig.disk_changes;
            self.disk_adv = Some(elapsed);
            progress = true;
        }
        if let Some(io) = sig.io_ops {
            self.qmp_seen = true;
            if self.last_io_ops.is_some_and(|prev| io > prev) {
                self.io_adv = Some(elapsed);
                progress = true;
            }
            self.last_io_ops = Some(io.max(self.last_io_ops.unwrap_or(0)));
        }
        if let Some(cpu) = sig.cpu_ns {
            if let Some(prev) = self.last_cpu {
                let cpu_delta = cpu.saturating_sub(prev);
                let wall_ns = u64::try_from(elapsed.saturating_sub(self.last_cpu_at).as_nanos())
                    .unwrap_or(u64::MAX);
                if wall_ns > 0 {
                    #[allow(clippy::cast_precision_loss)]
                    let pct = (cpu_delta as f64 / wall_ns as f64) * 100.0;
                    self.last_cpu_pct = Some(pct);
                    if cpu_delta.saturating_mul(CPU_PROGRESS_DIVISOR) >= wall_ns {
                        self.cpu_adv = Some(elapsed);
                        progress = true;
                    }
                }
            }
            self.last_cpu = Some(cpu);
            self.last_cpu_at = elapsed;
        }

        if progress {
            self.last_progress = elapsed;
        }

        let idle = elapsed.saturating_sub(self.last_progress);
        let effective_idle = self.effective_idle(elapsed);
        let verdict = if idle >= effective_idle {
            BootVerdict::Stuck
        } else if elapsed >= self.max_timeout {
            BootVerdict::MaxTimeout
        } else {
            BootVerdict::Booting
        };
        BootStatus {
            idle,
            effective_idle,
            verdict,
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
    let mut serial = SerialCounter::new(serial_path.clone());

    let disk_path = backend.disk_image_path().map(std::path::Path::to_path_buf);
    let disk_fingerprint = |p: &std::path::Path| {
        std::fs::metadata(p)
            .ok()
            .map(|m| (m.len(), m.modified().ok()))
    };
    let mut last_disk = disk_path.as_deref().and_then(disk_fingerprint);
    let mut disk_changes: u64 = 0;

    let idle_timeout = Duration::from_secs(idle_timeout_secs);
    let max_timeout = Duration::from_secs(max_timeout_secs);
    let poll = Duration::from_secs(SSH_POLL_INTERVAL);
    let cpu_sample_interval = Duration::from_secs(CPU_SAMPLE_INTERVAL);

    let os = backend.os();
    let start = Instant::now();
    let mut last_status = start;
    let mut banner_seen = false;
    let mut status_bytes = serial.poll();

    let mut watch = BootWatch::new(
        idle_timeout,
        max_timeout,
        cpu_sample_interval,
        backend.vm_cpu_time_ns(),
        backend.vm_disk_io_ops(),
    );

    loop {
        if let Some(err) = backend.vm_exit_error() {
            anyhow::bail!(
                "VM process exited while waiting for SSH: {err}{}",
                boot_failure_context(serial_path.as_deref(), disk_path.as_deref()),
            );
        }

        let mut ssh_progress = false;
        match probe_ssh(ssh, os).await {
            SshProgress::Ready => break,
            SshProgress::Listening => {
                // Listening means boot progress is happening; can't log in yet though.
                if !banner_seen {
                    banner_seen = true;
                    println!(
                        "{}",
                        "[VirtCI] SSH banner detected. Waiting for login to be \
                         accepted (VM likely still provisioning)..."
                            .dimmed()
                    );
                }
                ssh_progress = true;
            }
            SshProgress::NotReady => {}
        }

        let serial_bytes = serial.poll();

        // Disk-write liveness: a grown file or a bumped mtime both mean the guest just wrote.
        if let Some(fp) = disk_path.as_deref().and_then(disk_fingerprint)
            && last_disk.as_ref().is_none_or(|prev| fp > *prev)
        {
            last_disk = Some(fp);
            disk_changes += 1;
        }

        let elapsed = start.elapsed();

        let (cpu_ns, io_ops) = if watch.slow_sample_due(elapsed) {
            (backend.vm_cpu_time_ns(), backend.vm_disk_io_ops())
        } else {
            (None, None)
        };

        let status = watch.observe(
            elapsed,
            &BootSignals {
                ssh_progress,
                serial_bytes,
                disk_changes,
                io_ops,
                cpu_ns,
            },
        );

        let signals = watch.signals_summary(elapsed);

        match status.verdict {
            BootVerdict::Stuck => anyhow::bail!(
                "VM appears stuck. No boot progress for {}s (no serial output, no disk writes, no \
                 CPU activity, and SSH not up). Change VIRTCI_VM_START_IDLE_TIMEOUT to increase the idle timeout.\n{}{}",
                status.idle.as_secs(),
                signals,
                boot_failure_context(serial_path.as_deref(), disk_path.as_deref()),
            ),
            BootVerdict::MaxTimeout => anyhow::bail!(
                "VM did not become SSH-reachable within the {max_timeout_secs}s maximum boot \
                 timeout. Change VIRTCI_VM_START_MAX_TIMEOUT to increase the max timeout.\n{}{}",
                signals,
                boot_failure_context(serial_path.as_deref(), disk_path.as_deref()),
            ),
            BootVerdict::Booting => {}
        }

        if last_status.elapsed() >= Duration::from_secs(BOOT_STATUS_INTERVAL) {
            last_status = Instant::now();
            let effective_idle = status.effective_idle.as_secs();
            let detail = if serial_bytes > status_bytes {
                format!(
                    "serial +{} bytes, still booting",
                    serial_bytes - status_bytes
                )
            } else if banner_seen {
                format!(
                    "sshd up, waiting for login ({}s idle, gives up at {effective_idle}s)",
                    status.idle.as_secs()
                )
            } else if serial_path.is_some() {
                format!(
                    "quiet for {}s (no serial/disk/CPU progress; gives up at {effective_idle}s \
                     idle)",
                    status.idle.as_secs()
                )
            } else {
                "still waiting for SSH".to_string()
            };
            status_bytes = serial_bytes;
            println!(
                "{}",
                format!(
                    "[VirtCI] Waiting for VM: {}s elapsed, {detail} [{signals}]...",
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
            anyhow::bail!(
                "VM process exited while waiting for SSH: {err}{}",
                boot_failure_context(serial_path.as_deref(), disk_path.as_deref()),
            );
        }
        if start.elapsed() >= max_timeout {
            anyhow::bail!(
                "VM did not stay SSH-reachable within the {max_timeout_secs}s maximum boot \
                 timeout (SSH kept dropping during the post-boot settle window). Tune with \
                 VIRTCI_VM_START_MAX_TIMEOUT.{}",
                boot_failure_context(serial_path.as_deref(), disk_path.as_deref()),
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

/// Attempt to diagnose the serial output issues with some known snippets that appear under certain
/// failure cases.
fn diagnose_serial(path: Option<&std::path::Path>) -> Option<String> {
    use std::io::{Read, Seek, SeekFrom};

    const SCAN_BYTES: u64 = 64 * 1024;
    const DOC: &str = "See CHANGELOG.md for known issues";

    let path = path?;
    let mut file = std::fs::File::open(path).ok()?;
    let len = std::fs::metadata(path).ok()?.len();
    if len == 0 {
        return None;
    }
    let from = len.saturating_sub(SCAN_BYTES);
    file.seek(SeekFrom::Start(from)).ok()?;
    let mut buf = Vec::new();
    file.take(SCAN_BYTES).read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);

    if text.contains("Kernel panic") {
        return Some(format!(
            "DIAGNOSIS: VM KERNEL PANIC in the serial log so the kernel halted, meaning SSH will never \
             come up. {DOC}"
        ));
    }
    if text.contains("UNEXPECTED INCONSISTENCY")
        || text.contains("RUN fsck MANUALLY")
        || text.contains("fsck failed")
    {
        return Some(format!(
            "DIAGNOSIS: filesystem check (fsck) reported problems on boot so the VM disk may be \
             corrupt. Check it with `qemu-img check`. {DOC}"
        ));
    }
    if text.contains("emergency.target")
        || text.contains("emergency mode")
        || text.contains("system maintenance")
    {
        return Some(format!(
            "DIAGNOSIS: VM booted into systemd emergency mode. A boot unit failed, so sshd never \
             starts and the boot cannot complete (the watcher correctly sees no progress). See the \
             guest boot-failure diagnostics below (failed units + journal) for which unit tripped it; \
             a failed/slow mount, device timeout, or a corrupt disk can all cause it. This has so far \
             only been seen on the Windows-host restart path. {DOC}"
        ));
    }
    if text.contains("rescue.target") || text.contains("rescue mode") {
        return Some(format!(
            "DIAGNOSIS: VM booted into systemd rescue mode. Boot did not reach multi-user, so \
             sshd is not running. {DOC}"
        ));
    }
    None
}

fn serial_diag_block(path: Option<&std::path::Path>) -> Option<String> {
    const START: &str = "=== VIRTCI BOOT DIAGNOSTICS";
    const END: &str = "=== END VIRTCI BOOT DIAGNOSTICS";

    let path = path?;
    let bytes = std::fs::read(path).ok()?;
    let text = String::from_utf8_lossy(&bytes);
    let start = text.rfind(START)?;
    let end = match text[start..].find(END) {
        Some(rel) => {
            let marker = start + rel;
            text[marker..]
                .find('\n')
                .map_or(text.len(), |nl| marker + nl)
        }
        None => text.len(),
    };
    Some(text[start..end].trim_end().to_string())
}

fn boot_failure_context(
    serial_path: Option<&std::path::Path>,
    disk_path: Option<&std::path::Path>,
) -> String {
    let mut out = String::new();
    if let Some(diag) = diagnose_serial(serial_path) {
        out.push_str("\n[VirtCI] ");
        out.push_str(&diag);
    }
    if let Some(block) = serial_diag_block(serial_path) {
        out.push_str(
            "\n[VirtCI] guest boot-failure diagnostics (dumped to serial by the guest):\n",
        );
        out.push_str(&block);
    }
    if let Some(disk) = disk_path {
        let _ = write!(
            out,
            "\n[VirtCI] to rule out disk corruption, run: `qemu-img check \"{}\"` (you may want to use virtci shell)",
            disk.display()
        );
    }
    out.push('\n');
    out.push_str(&serial_tail(serial_path));
    out
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
        // make the connection itself a little more resilient from random NAT failures or whatever.
        keepalive_interval: Some(std::time::Duration::from_secs(15)),
        keepalive_max: 6,
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

    use super::{BootSignals, BootVerdict, BootWatch};
    use std::time::Duration;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn serial_only(serial_bytes: u64) -> BootSignals {
        BootSignals {
            ssh_progress: false,
            serial_bytes,
            disk_changes: 0,
            io_ops: None,
            cpu_ns: None,
        }
    }

    fn first_stuck_at(
        base_idle: u64,
        max: u64,
        end: u64,
        mut serial_at: impl FnMut(u64) -> u64,
    ) -> Option<u64> {
        let mut w = BootWatch::new(secs(base_idle), secs(max), secs(15), Some(0), Some(0));
        let mut e = 0;
        while e <= end {
            let st = w.observe(secs(e), &serial_only(serial_at(e)));
            if matches!(st.verdict, BootVerdict::Stuck) {
                return Some(e);
            }
            e += 2;
        }
        None
    }

    #[test]
    fn effective_idle_scales_with_elapsed_and_caps_at_max() {
        let w = BootWatch::new(secs(120), secs(1800), secs(15), None, None);
        assert_eq!(w.effective_idle(secs(0)).as_secs(), 120);
        assert_eq!(w.effective_idle(secs(400)).as_secs(), 220);
        assert_eq!(w.effective_idle(secs(1_000_000)).as_secs(), 1800);
    }

    #[test]
    fn steady_serial_never_trips() {
        assert_eq!(first_stuck_at(120, 1800, 1000, |e| e), None);
    }

    #[test]
    fn genuinely_flat_serial_eventually_trips() {
        let stuck = first_stuck_at(120, 1800, 2000, |e| e.min(100)).expect("must eventually trip");
        assert!((260..=340).contains(&stuck), "expected ~294s, got {stuck}s");
    }

    #[test]
    fn bursty_serial_with_gaps_over_base_idle_survives_when_scaled() {
        let burst = |e: u64| if e < 400 { e } else { 400 + (e / 200) * 4096 };
        assert_eq!(first_stuck_at(120, 1800, 800, burst), None);
    }

    #[test]
    fn cpu_at_or_above_threshold_counts_as_progress() {
        // 4% of a 15s window is 600ms of CPU which is good
        let mut w = BootWatch::new(secs(120), secs(1800), secs(15), Some(0), None);
        let mut s = serial_only(0);
        s.cpu_ns = Some(600_000_000);
        assert_eq!(w.observe(secs(15), &s).idle.as_secs(), 0);
    }

    #[test]
    fn cpu_below_threshold_is_not_progress() {
        // ~3.3% of the 15s window which is under 4%
        let mut w = BootWatch::new(secs(120), secs(1800), secs(15), Some(0), None);
        let mut s = serial_only(0);
        s.cpu_ns = Some(500_000_000);
        assert_eq!(w.observe(secs(15), &s).idle.as_secs(), 15);
    }

    #[test]
    fn qmp_io_ops_advance_resets_idle() {
        let mut w = BootWatch::new(secs(120), secs(1800), secs(15), None, Some(1000));
        let mut s = serial_only(0);
        s.io_ops = Some(1050);
        assert_eq!(w.observe(secs(15), &s).idle.as_secs(), 0);
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
