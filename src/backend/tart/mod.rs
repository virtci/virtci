// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::{
    path::{Path, PathBuf},
    process::Child,
};

use anyhow::Context;
use colored::Colorize;

use crate::{
    backend::{VmBackend, VmStartConfig},
    file_lock::FileLock,
    global_paths::VciGlobalPaths,
    vm_image::{GuestOs, ImageDescription},
};

/// If tart max VMs, retry every 30 seconds.
const CAP_RETRY_INTERVAL_S: u64 = 30;
const CAP_MAX_RETRIES: u32 = 120;

pub struct TartRunner {
    pub is_base_mode: bool,
    /// shared or exclusive `vci_image_{name}.lock`.
    image_lock: FileLock,
    clone_name: String,
    slot_lock: FileLock,
    tart_process: Option<Child>,
    /// IP Address SHOULD be stable for 24-hour DHCP lease period.
    vm_ip: String,
}

pub struct TartBackend {
    pub name: String,
    pub base_image: ImageDescription,
    pub cpus: u32,
    /// Megabytes
    pub memory_mb: u64,
    pub offline: bool,
    pub graphics: bool,
    pub runner: Option<TartRunner>,
    temp: PathBuf,
}

impl TartBackend {
    pub fn new(
        name: String,
        base_image: ImageDescription,
        cpus: u32,
        memory_mb: u64,
        paths: &VciGlobalPaths,
    ) -> anyhow::Result<Self> {
        let mut backend = TartBackend {
            name,
            base_image,
            cpus,
            memory_mb,
            offline: false,
            graphics: false,
            runner: None,
            temp: paths.temp.clone(),
        };

        backend.setup_clone(paths)?;

        Ok(backend)
    }

    /// Boot the base VM directly
    pub fn new_base(
        name: String,
        base_image: ImageDescription,
        cpus: u32,
        memory_mb: u64,
        nographics: bool,
        paths: &VciGlobalPaths,
    ) -> anyhow::Result<Self> {
        let mut backend = TartBackend {
            name,
            base_image,
            cpus,
            memory_mb,
            offline: false,
            graphics: !nographics,
            runner: None,
            temp: paths.temp.clone(),
        };
        backend.setup_base(paths)?;
        Ok(backend)
    }

    fn setup_base(&mut self, paths: &VciGlobalPaths) -> anyhow::Result<()> {
        assert!(self.runner.is_none());

        let temp_path = &paths.temp;

        let image_lock = {
            let lock_path = temp_path.join(format!("vci_image_{}.lock", self.base_image.name));
            FileLock::try_new(lock_path).map_err(|_| {
                anyhow::anyhow!(
                    "Image '{}' is currently in use by another virtci process so it \
                     cannot boot for modification while it is running.",
                    self.base_image.name
                )
            })?
        };

        let tart_config = self.base_image.backend.as_tart().unwrap();
        let vm_name = tart_config.vm_name.clone();
        let (slot_lock, _slot) =
            get_slot_flock(temp_path).context("Failed to acquire tart slot lock")?;

        let output = std::process::Command::new("tart")
            .args([
                "set",
                &vm_name,
                "--cpu",
                &self.cpus.to_string(),
                "--memory",
                &self.memory_mb.to_string(),
            ])
            .output()
            .context("Failed to run tart set")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("tart set failed: {}", stderr.trim());
        }

        // Brief headless boot to resolve DHCP IP (SHOULD be stable for 24h lease).
        // Retries if Tart reports the macOS concurrent-VM cap is reached.
        let ip = resolve_ip_via_temp_boot(&vm_name, temp_path)?;

        self.runner = Some(TartRunner {
            is_base_mode: true,
            image_lock,
            clone_name: vm_name,
            slot_lock,
            tart_process: None,
            vm_ip: ip,
        });

        let ssh_target = self.ssh_target();
        let meta = crate::file_lock::LockMetadata::with_run_info(
            self.run_name(),
            ssh_target,
            self.base_image.os,
            None,
        );
        if let Ok(json) = serde_json::to_string_pretty(&meta) {
            let _ = self
                .runner
                .as_mut()
                .unwrap()
                .slot_lock
                .write_content(json.as_bytes());
        }

        Ok(())
    }

    fn setup_clone(&mut self, paths: &VciGlobalPaths) -> anyhow::Result<()> {
        assert!(self.runner.is_none());

        let temp_path = &paths.temp;

        // Shared lock: multiple CI runs on the same base image are allowed,
        // but an active `virtci boot` holding an exclusive lock will block this.
        let image_lock = {
            let lock_path = temp_path.join(format!("vci_image_{}.lock", self.base_image.name));
            FileLock::try_new_shared(lock_path).map_err(|e| {
                let msg = match e {
                    crate::file_lock::FileLockError::OtherProcessBlock(_) => format!(
                        "Image '{}' is currently being modified by `virtci boot` so \
                         wait for it to finish before starting a new run.",
                        self.base_image.name
                    ),
                    crate::file_lock::FileLockError::Other => format!(
                        "Failed to acquire shared lock for image '{}' so \
                         if `virtci boot` is not running, try `virtci cleanup --force`.",
                        self.base_image.name
                    ),
                };
                anyhow::anyhow!(msg)
            })?
        };

        let tart_config = self.base_image.backend.as_tart().unwrap();
        let (slot_lock, slot) =
            get_slot_flock(temp_path).context("Failed to acquire tart slot lock")?;

        let clone_name = format!("vci-{}-{}", self.name, slot);
        let _ = std::process::Command::new("tart")
            .args(["delete", &clone_name])
            .output();

        let output = std::process::Command::new("tart")
            .args(["clone", &tart_config.vm_name, &clone_name])
            .output()
            .context("Failed to run tart clone")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("tart clone failed: {}", stderr.trim());
        }

        let output = match std::process::Command::new("tart")
            .args([
                "set",
                &clone_name,
                "--cpu",
                &self.cpus.to_string(),
                "--memory",
                &self.memory_mb.to_string(),
            ])
            .output()
        {
            Ok(output) => output,
            Err(e) => {
                let _ = std::process::Command::new("tart")
                    .args(["delete", &clone_name])
                    .output();
                return Err(anyhow::Error::new(e).context("Failed to run tart set"));
            }
        };

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let _ = std::process::Command::new("tart")
                .args(["delete", &clone_name])
                .output();
            anyhow::bail!("tart set failed: {}", stderr.trim());
        }

        // Brief headless boot to resolve DHCP IP. Retries if Tart reports the
        // macOS concurrent-VM cap is reached (booting the same clone, no re-clone).
        let ip = match resolve_ip_via_temp_boot(&clone_name, temp_path) {
            Ok(ip) => ip,
            Err(e) => {
                let _ = std::process::Command::new("tart")
                    .args(["delete", &clone_name])
                    .output();
                return Err(e);
            }
        };

        self.runner = Some(TartRunner {
            is_base_mode: false,
            image_lock,
            clone_name,
            slot_lock,
            tart_process: None,
            vm_ip: ip,
        });

        let ssh_target = self.ssh_target();
        let meta = crate::file_lock::LockMetadata::with_run_info(
            self.run_name(),
            ssh_target,
            self.base_image.os,
            None,
        );
        if let Ok(json) = serde_json::to_string_pretty(&meta) {
            let _ = self
                .runner
                .as_mut()
                .unwrap()
                .slot_lock
                .write_content(json.as_bytes());
        }

        Ok(())
    }

    /// Log file capturing `tart run`'s stdout/stderr. Necessary to check the cap message.
    fn run_log_path(&self, clone_name: &str) -> PathBuf {
        self.temp.join(format!("vci-tart-run-{clone_name}.log"))
    }

    /// Spawn the real `tart run` for `clone_name`, retrying if Tart refuses
    /// because the host is at the macOS concurrent-VM cap.
    fn spawn_tart_run_with_cap_retry(&self, clone_name: &str) -> anyhow::Result<Child> {.
        const SURVIVE_POLLS: u32 = 8;
        const SURVIVE_INTERVAL_MS: u64 = 250;

        let log_path = self.run_log_path(clone_name);
        let mut cap_attempts: u32 = 0;

        loop {
            let log_file =
                std::fs::File::create(&log_path).context("Failed to create tart run log")?;
            let log_file2 = log_file
                .try_clone()
                .context("Failed to create tart run log")?;

            let mut cmd = std::process::Command::new("tart");
            if self.graphics {
                cmd.args(["run", clone_name]);
            } else {
                cmd.args(["run", clone_name, "--no-graphics"]);
            }
            cmd.stdout(log_file).stderr(log_file2);

            let mut child = cmd.spawn().context("Failed to start tart VM")?;

            let mut early_exit = false;
            for _ in 0..SURVIVE_POLLS {
                std::thread::sleep(std::time::Duration::from_millis(SURVIVE_INTERVAL_MS));
                if let Ok(Some(_status)) = child.try_wait() {
                    early_exit = true;
                    break;
                }
            }

            if !early_exit {
                let flag = if self.graphics { "" } else { " --no-graphics" };
                println!("{}", format!("tart run {clone_name}{flag}").dimmed());
                return Ok(child);
            }

            let _ = child.wait();
            let boot_log = std::fs::read_to_string(&log_path).unwrap_or_default();

            if is_vm_cap_error(&boot_log) {
                cap_attempts += 1;
                if cap_attempts > CAP_MAX_RETRIES {
                    let _ = std::fs::remove_file(&log_path);
                    anyhow::bail!(
                        "macOS VM limit still reached after waiting ~{} minutes for a free slot",
                        (u64::from(CAP_MAX_RETRIES) * CAP_RETRY_INTERVAL_S) / 60
                    );
                }
                println!(
                    "{}",
                    format!(
                        "macOS VM limit reached (Apple EULA allows 2 running VMs). Waiting \
                         {CAP_RETRY_INTERVAL_S}s then retrying '{clone_name}' (attempt \
                         {cap_attempts})..."
                    )
                    .yellow()
                );
                std::thread::sleep(std::time::Duration::from_secs(CAP_RETRY_INTERVAL_S));
                continue;
            }

            let _ = std::fs::remove_file(&log_path);
            anyhow::bail!("tart run failed: {}", boot_log.trim());
        }
    }
}

impl VmBackend for TartBackend {
    fn is_cached_run(&self) -> bool {
        false
    }

    fn cache_run_files(
        &self,
        _fingerprint: &crate::run::cache::metadata::Fingerprint,
        _ttl_secs: Option<u64>,
    ) -> anyhow::Result<()> {
        Ok(())
    }

    fn start_vm(&mut self, cfg: VmStartConfig) -> anyhow::Result<()> {
        if let Some(o) = cfg.offline {
            self.offline = o;
        }
        let resize = cfg.cpus.is_some() || cfg.memory_mb.is_some();
        if let Some(c) = cfg.cpus {
            self.cpus = c;
        }
        if let Some(m) = cfg.memory_mb {
            self.memory_mb = m;
        }

        let clone_name = self.runner.as_ref().unwrap().clone_name.clone();

        if resize {
            let output = std::process::Command::new("tart")
                .args([
                    "set",
                    &clone_name,
                    "--cpu",
                    &self.cpus.to_string(),
                    "--memory",
                    &self.memory_mb.to_string(),
                ])
                .output()
                .context("Failed to run tart set")?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                anyhow::bail!("tart set failed: {}", stderr.trim());
            }
        }

        // Tart's network isolation flags (--net-host, --net-softnet) all require
        // root via Softnet. Offline mode is enforced post-boot inside the VM
        // via offline_enforce_cmd() instead.

        let child = self.spawn_tart_run_with_cap_retry(&clone_name)?;
        self.runner.as_mut().unwrap().tart_process = Some(child);

        Ok(())
    }

    fn offline_enforce_cmd(&self) -> Option<&'static str> {
        // Deletes the default route, blocking internet. Still has the subnet route,
        // so SSH should keep working. Route table is in-memory so resets
        // on VM restart, so toggling works. Shoutout tart, but gosh darn tart.
        Some("sudo route -n delete default")
    }

    fn stop_vm(&mut self) {
        let clone_name = self.runner.as_ref().unwrap().clone_name.clone();
        let log_path = self.run_log_path(&clone_name);

        let _ = std::process::Command::new("tart")
            .args(["stop", &clone_name])
            .output();

        if let Some(runner) = self.runner.as_mut() {
            if let Some(ref mut process) = runner.tart_process {
                let _ = process.wait();
            }
            runner.tart_process = None;
        }

        let _ = std::fs::remove_file(&log_path);

        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    fn ssh_target(&self) -> crate::vm_image::SshTarget {
        let runner = self.runner.as_ref().unwrap();
        crate::vm_image::SshTarget {
            ip: runner.vm_ip.clone(),
            port: 22,
            cred: self.base_image.ssh.clone(),
            retry_budget: None,
        }
    }

    fn os(&self) -> GuestOs {
        self.base_image.os
    }

    fn is_offline(&self) -> bool {
        self.offline
    }

    fn run_name(&self) -> String {
        self.runner.as_ref().unwrap().clone_name.clone()
    }

    fn vm_exit_error(&mut self) -> Option<String> {
        let runner = self.runner.as_mut()?;
        let process = runner.tart_process.as_mut()?;
        match process.try_wait() {
            Ok(Some(status)) => Some(format!("tart exited with {status}")),
            _ => None,
        }
    }

    fn wait_for_exit(&mut self) {
        if let Some(ref mut runner) = self.runner {
            if let Some(ref mut process) = runner.tart_process {
                let _ = process.wait();
            }
            runner.tart_process = None;
        }
    }
}

impl Drop for TartBackend {
    fn drop(&mut self) {
        if let Some(mut runner) = self.runner.take() {
            let _ = std::process::Command::new("tart")
                .args(["stop", &runner.clone_name])
                .output();

            if let Some(ref mut process) = runner.tart_process {
                let _ = process.kill();
                let _ = process.wait();
            }

            // **VERY VERY IMPORTANT TO NOT DELETE THE BASE IMAGE**
            if !runner.is_base_mode {
                let _ = std::process::Command::new("tart")
                    .args(["delete", &runner.clone_name])
                    .output();
            }

            let _ = std::fs::remove_file(self.run_log_path(&runner.clone_name));

            let slot_lock_path = runner.slot_lock.get_path().clone();
            let image_lock_path = runner.image_lock.get_path().clone();
            drop(runner);
            let _ = std::fs::remove_file(&image_lock_path);
            let _ = std::fs::remove_file(&slot_lock_path);
        }
    }
}

/// Apple EULA sets a cap of 2 mac VMs per host, and Tart enforces this.
/// The output will contain the substring `"The number of VMs exceeds the system limit"` if that
/// limit is reached, but retrying is cheap and the other VM usage will eventually end
/// realistically.
fn is_vm_cap_error(tart_output: &str) -> bool {
    tart_output.contains("The number of VMs exceeds the system limit")
}

/// Temporarily boots `vm_name` headless to resolve its DHCP IP, then stops it.
fn resolve_ip_via_temp_boot(vm_name: &str, temp_path: &Path) -> anyhow::Result<String> {
    const IP_MAX_RETRIES: u32 = 30;
    const IP_POLL_INTERVAL_S: u64 = 3;

    let log_path = temp_path.join(format!("vci-tart-boot-{vm_name}.log"));
    let mut cap_attempts: u32 = 0;

    let result = loop {
        let log_file =
            std::fs::File::create(&log_path).context("Failed to create tart boot log")?;
        let log_file2 = log_file
            .try_clone()
            .context("Failed to create tart boot log")?;

        let mut boot = std::process::Command::new("tart")
            .args(["run", vm_name, "--no-graphics"])
            .stdout(log_file)
            .stderr(log_file2)
            .spawn()
            .context("Failed to boot tart VM for IP discovery")?;

        let mut resolved_ip: Option<String> = None;
        let mut exited = false;
        for _ in 0..IP_MAX_RETRIES {
            if let Ok(Some(_status)) = boot.try_wait() {
                exited = true;
                break;
            }

            if let Ok(output) = std::process::Command::new("tart")
                .args(["ip", vm_name])
                .output()
                && output.status.success()
            {
                let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !ip.is_empty() {
                    resolved_ip = Some(ip);
                    break;
                }
            }

            std::thread::sleep(std::time::Duration::from_secs(IP_POLL_INTERVAL_S));
        }

        let _ = std::process::Command::new("tart")
            .args(["stop", vm_name])
            .output();
        let _ = boot.wait();

        if let Some(ip) = resolved_ip {
            println!("{}", format!("  VM IP: {ip}").dimmed());
            break Ok(ip);
        }

        let boot_log = std::fs::read_to_string(&log_path).unwrap_or_default();

        if is_vm_cap_error(&boot_log) {
            cap_attempts += 1;
            if cap_attempts > CAP_MAX_RETRIES {
                break Err(anyhow::anyhow!(
                    "macOS VM limit still reached after waiting ~{} minutes for a free slot",
                    (u64::from(CAP_MAX_RETRIES) * CAP_RETRY_INTERVAL_S) / 60
                ));
            }
            println!(
                "{}",
                format!(
                    "macOS VM limit reached (Apple allows 2 running VMs). Waiting \
                     {CAP_RETRY_INTERVAL_S}s then retrying '{vm_name}' (attempt {cap_attempts})..."
                )
                .yellow()
            );
            std::thread::sleep(std::time::Duration::from_secs(CAP_RETRY_INTERVAL_S));
            continue;
        }

        if exited {
            break Err(anyhow::anyhow!("tart run failed: {}", boot_log.trim()));
        }

        break Err(anyhow::anyhow!(
            "Failed to resolve IP for '{}' after {}s",
            vm_name,
            u64::from(IP_MAX_RETRIES) * IP_POLL_INTERVAL_S
        ));
    };

    let _ = std::fs::remove_file(&log_path);
    result
}

fn get_slot_flock(temp_path: &Path) -> anyhow::Result<(FileLock, u32)> {
    const SLOT_RANGE_START: u32 = 0;
    const SLOT_RANGE_END: u32 = 10000;

    for slot in SLOT_RANGE_START..=SLOT_RANGE_END {
        let lock_path = temp_path.join(format!("vci-tart-slot-{slot}.lock"));
        if let Ok(lock) = FileLock::try_new(lock_path) {
            return Ok((lock, slot));
        }
    }
    anyhow::bail!("No free tart slot lock available in range {SLOT_RANGE_START}..={SLOT_RANGE_END}")
}

pub fn cleanup_stale_tart_clones(temp_path: &Path) {
    let entries: Vec<_> = match std::fs::read_dir(temp_path) {
        Ok(e) => e.filter_map(std::result::Result::ok).collect(),
        Err(_) => return,
    };

    for entry in &entries {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        let slot_str = match name_str
            .strip_prefix("vci-tart-slot-")
            .and_then(|s| s.strip_suffix(".lock"))
        {
            Some(s) => s.to_string(),
            None => continue,
        };

        let Ok(lock) = FileLock::try_lock_exist(entry.path()) else {
            continue;
        };

        let suffix = format!("-{slot_str}");
        if let Ok(output) = std::process::Command::new("tart").arg("list").output()
            && output.status.success()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(1) {
                let mut cols = line.split_whitespace();
                let Some(source) = cols.next() else { continue };
                let Some(vm_name) = cols.next() else { continue };

                if source == "local" && vm_name.starts_with("vci-") && vm_name.ends_with(&suffix) {
                    let _ = std::process::Command::new("tart")
                        .args(["stop", vm_name])
                        .output();
                    let _ = std::process::Command::new("tart")
                        .args(["delete", vm_name])
                        .output();
                }
            }
        }

        let lock_path = lock.get_path().clone();
        drop(lock);
        let _ = std::fs::remove_file(&lock_path);
    }
}
