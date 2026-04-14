// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::{path::Path, process::Child};

use colored::Colorize;

use crate::{
    backend::VmBackend,
    file_lock::FileLock,
    vm_image::{GuestOs, ImageDescription},
};

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
    pub graphics: bool,
    pub runner: Option<TartRunner>,
}

impl TartBackend {
    pub fn new(
        name: String,
        base_image: ImageDescription,
        cpus: u32,
        memory_mb: u64,
        temp_path: &Path,
    ) -> Result<Self, ()> {
        let mut backend = TartBackend {
            name,
            base_image,
            cpus,
            memory_mb,
            graphics: false,
            runner: None,
        };

        backend.setup_clone(temp_path)?;

        Ok(backend)
    }

    /// Boot the base VM directly
    pub fn new_base(
        name: String,
        base_image: ImageDescription,
        cpus: u32,
        memory_mb: u64,
        nographics: bool,
        temp_path: &Path,
    ) -> Result<Self, ()> {
        let mut backend = TartBackend {
            name,
            base_image,
            cpus,
            memory_mb,
            graphics: !nographics,
            runner: None,
        };
        backend.setup_base(temp_path)?;
        Ok(backend)
    }

    fn setup_base(&mut self, temp_path: &Path) -> Result<(), ()> {
        assert!(self.runner.is_none());

        let image_lock = {
            let lock_path = temp_path.join(format!("vci_image_{}.lock", self.base_image.name));
            FileLock::try_new(lock_path).map_err(|_| {
                eprintln!(
                    "{}",
                    format!(
                        "Image '{}' is currently in use by another virtci process — \
                         cannot boot for modification while it is running.",
                        self.base_image.name
                    )
                    .red()
                );
            })?
        };

        let tart_config = self.base_image.backend.as_tart().unwrap();
        let vm_name = tart_config.vm_name.clone();
        let (slot_lock, _slot) =
            get_slot_flock(temp_path).expect("Failed to acquire tart slot lock");

        // Brief headless boot to resolve DHCP IP (SHOULD be stable for 24h lease).
        let mut boot_process = std::process::Command::new("tart")
            .args(["run", &vm_name, "--no-graphics"])
            .spawn()
            .map_err(|e| {
                eprintln!(
                    "{}",
                    format!("Failed to boot tart VM for IP discovery: {e}").red()
                );
            })?;

        let Ok(ip) = resolve_tart_ip(&vm_name) else {
            let _ = std::process::Command::new("tart")
                .args(["stop", &vm_name])
                .output();
            let _ = boot_process.wait();
            return Err(());
        };

        let _ = std::process::Command::new("tart")
            .args(["stop", &vm_name])
            .output();
        let _ = boot_process.wait();

        self.runner = Some(TartRunner {
            is_base_mode: true,
            image_lock,
            clone_name: vm_name,
            slot_lock,
            tart_process: None,
            vm_ip: ip,
        });

        let ssh_target = self.ssh_target();
        let meta = crate::file_lock::LockMetadata::with_run_info(self.run_name(), ssh_target);
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
}

impl VmBackend for TartBackend {
    fn setup_clone(&mut self, temp_path: &Path) -> Result<(), ()> {
        assert!(self.runner.is_none());

        // Shared lock: multiple CI runs on the same base image are allowed,
        // but an active `virtci boot` holding an exclusive lock will block this.
        let image_lock = {
            let lock_path = temp_path.join(format!("vci_image_{}.lock", self.base_image.name));
            FileLock::try_new_shared(lock_path).map_err(|e| {
                let msg = match e {
                    crate::file_lock::FileLockError::OtherProcessBlock(_) => format!(
                        "Image '{}' is currently being modified by `virtci boot` — \
                         wait for it to finish before starting a new run.",
                        self.base_image.name
                    ),
                    crate::file_lock::FileLockError::Other => format!(
                        "Failed to acquire shared lock for image '{}' — \
                         if `virtci boot` is not running, try `virtci cleanup --force`.",
                        self.base_image.name
                    ),
                };
                eprintln!("{}", msg.red());
            })?
        };

        let tart_config = self.base_image.backend.as_tart().unwrap();
        let (slot_lock, slot) =
            get_slot_flock(temp_path).expect("Failed to acquire tart slot lock");

        let clone_name = format!("vci-{}-{}", self.name, slot);
        let _ = std::process::Command::new("tart")
            .args(["delete", &clone_name])
            .output();

        let output = std::process::Command::new("tart")
            .args(["clone", &tart_config.vm_name, &clone_name])
            .output()
            .map_err(|e| {
                eprintln!("{}", format!("Failed to run tart clone: {e}").red());
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("{}", format!("tart clone failed: {}", stderr.trim()).red());
            return Err(());
        }

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
            .map_err(|e| {
                eprintln!("{}", format!("Failed to run tart set: {e}").red());
                let _ = std::process::Command::new("tart")
                    .args(["delete", &clone_name])
                    .output();
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("{}", format!("tart set failed: {}", stderr.trim()).red());
            let _ = std::process::Command::new("tart")
                .args(["delete", &clone_name])
                .output();
            return Err(());
        }

        let mut boot_cmd = std::process::Command::new("tart");
        boot_cmd.args(["run", &clone_name, "--no-graphics"]);

        let mut boot_process = boot_cmd.spawn().map_err(|e| {
            eprintln!(
                "{}",
                format!("Failed to boot tart VM for IP discovery: {e}").red()
            );
            let _ = std::process::Command::new("tart")
                .args(["delete", &clone_name])
                .output();
        })?;

        let Ok(ip) = resolve_tart_ip(&clone_name) else {
            let _ = std::process::Command::new("tart")
                .args(["stop", &clone_name])
                .output();
            let _ = boot_process.wait();
            let _ = std::process::Command::new("tart")
                .args(["delete", &clone_name])
                .output();
            return Err(());
        };

        // got ip so just stop the vm
        let _ = std::process::Command::new("tart")
            .args(["stop", &clone_name])
            .output();
        let _ = boot_process.wait();

        self.runner = Some(TartRunner {
            is_base_mode: false,
            image_lock,
            clone_name,
            slot_lock,
            tart_process: None,
            vm_ip: ip,
        });

        let ssh_target = self.ssh_target();
        let meta = crate::file_lock::LockMetadata::with_run_info(self.run_name(), ssh_target);
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

    fn start_vm(&mut self, _offline: bool) -> Result<(), ()> {
        let runner = self.runner.as_mut().unwrap();

        let mut cmd = std::process::Command::new("tart");

        // Tart's network isolation flags (--net-host, --net-softnet) all require
        // root via Softnet. Offline mode is enforced post-boot inside the VM
        // via offline_enforce_cmd() instead.

        if self.graphics {
            cmd.args(["run", &runner.clone_name]);
            println!("{}", format!("tart run {}", &runner.clone_name).dimmed());
        } else {
            cmd.args(["run", &runner.clone_name, "--no-graphics"]);
            println!(
                "{}",
                format!("tart run {} --no-graphics", &runner.clone_name).dimmed()
            );
        }

        runner.tart_process = Some(cmd.spawn().map_err(|e| {
            eprintln!("{}", format!("Failed to start tart VM: {e}").red());
        })?);

        Ok(())
    }

    fn offline_enforce_cmd(&self) -> Option<&'static str> {
        // Deletes the default route, blocking internet. Still has the subnet route,
        // so SSH should keep working. Route table is in-memory so resets
        // on VM restart, so toggling works. Shoutout tart, but gosh darn tart.
        Some("sudo route -n delete default")
    }

    fn stop_vm(&mut self) {
        let runner = self.runner.as_mut().unwrap();

        let _ = std::process::Command::new("tart")
            .args(["stop", &runner.clone_name])
            .output();

        if let Some(ref mut process) = runner.tart_process {
            let _ = process.wait();
        }
        runner.tart_process = None;

        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    fn ssh_target(&self) -> crate::vm_image::SshTarget {
        let runner = self.runner.as_ref().unwrap();
        crate::vm_image::SshTarget {
            ip: runner.vm_ip.clone(),
            port: 22,
            cred: self.base_image.ssh.clone(),
        }
    }

    fn os(&self) -> GuestOs {
        self.base_image.os
    }

    fn run_name(&self) -> String {
        self.runner.as_ref().unwrap().clone_name.clone()
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

            let slot_lock_path = runner.slot_lock.get_path().clone();
            let image_lock_path = runner.image_lock.get_path().clone();
            drop(runner);
            let _ = std::fs::remove_file(&image_lock_path);
            let _ = std::fs::remove_file(&slot_lock_path);
        }
    }
}

fn resolve_tart_ip(clone_name: &str) -> Result<String, ()> {
    const MAX_RETRIES: u32 = 30;
    const POLL_INTERVAL_S: u64 = 3;

    for _ in 0..MAX_RETRIES {
        let output = std::process::Command::new("tart")
            .args(["ip", clone_name])
            .output();

        if let Ok(output) = output {
            if output.status.success() {
                let ip = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !ip.is_empty() {
                    println!("{}", format!("  VM IP: {ip}").dimmed());
                    return Ok(ip);
                }
            }
        }

        std::thread::sleep(std::time::Duration::from_secs(POLL_INTERVAL_S));
    }

    eprintln!(
        "{}",
        format!(
            "Failed to resolve IP for '{}' after {}s",
            clone_name,
            u64::from(MAX_RETRIES) * POLL_INTERVAL_S
        )
        .red()
    );
    Err(())
}

fn get_slot_flock(temp_path: &Path) -> Result<(FileLock, u32), ()> {
    const SLOT_RANGE_START: u32 = 0;
    const SLOT_RANGE_END: u32 = 10000;

    for slot in SLOT_RANGE_START..=SLOT_RANGE_END {
        let lock_path = temp_path.join(format!("vci-tart-slot-{slot}.lock"));
        if let Ok(lock) = FileLock::try_new(lock_path) {
            return Ok((lock, slot));
        }
    }
    Err(())
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
        if let Ok(output) = std::process::Command::new("tart").arg("list").output() {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines().skip(1) {
                    let mut cols = line.split_whitespace();
                    let Some(source) = cols.next() else { continue };
                    let Some(vm_name) = cols.next() else { continue };

                    if source == "local"
                        && vm_name.starts_with("vci-")
                        && vm_name.ends_with(&suffix)
                    {
                        let _ = std::process::Command::new("tart")
                            .args(["stop", vm_name])
                            .output();
                        let _ = std::process::Command::new("tart")
                            .args(["delete", vm_name])
                            .output();
                    }
                }
            }
        }

        let lock_path = lock.get_path().clone();
        drop(lock);
        let _ = std::fs::remove_file(&lock_path);
    }
}
