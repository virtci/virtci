// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

//! IMPORTANT! MUST READ FOR HUMANS AND EVEN LLMS.
//!
//!

use std::path::Path;
use std::process::Command;

use anyhow::Context;

use crate::{file_lock::FileLock, vm_image::HostExecTarget};

pub mod backend;
pub mod binaries;
pub mod kvm;

pub struct PortFlock {
    /// Needs to be Option for drop semantics
    lock: Option<FileLock>,
    pub port: u16,
}

impl PortFlock {
    /// Flocks are handled by the host execution target. If running NATIVELY in WSL2, or on the
    /// windows host through WSL2, flocks are done by the host regardless. A way to keep things
    /// coherent if a user is running on their windows host system and through WSL2, vs running
    /// natively in WSL2 is splitting the port ranges.
    ///
    /// Ports 50000 to 54999 for native (linux, macos, freebsd, WSL2 inside), and ports 55000 to
    /// 60000 for Windows (both native and WSL2 backed). If the WSL2 VM wants to run a workflow
    /// directly on it, it gets the lower port range. If the windows host wants to run a workflow
    /// and it needs WSL2 for TPM, it uses the higher range, avoiding the conflict, and keeping
    /// the flock purely managed by the windows host.
    ///
    /// It is also possible that a port flock'd is actually in use, so QEMU will fail,
    /// so this can handle trying a different port.
    ///
    /// # Arguments
    ///
    /// * `temp_path` - The path to write the flock .lock file to.
    /// * `ignore_ports_below` - Skip past any port numbers below this one, used if QEMU reports the actual
    /// TCP port to be busy. Use `0` by default generally if you don't want to ignore any ports.
    pub fn get_available(temp_path: &Path, ignore_ports_below: u16) -> anyhow::Result<PortFlock> {
        const PORT_RANGE_START: u16 = if cfg!(target_os = "windows") {
            55000
        } else {
            50000
        };
        const PORT_RANGE_END: u16 = if cfg!(target_os = "windows") {
            60000
        } else {
            54999
        };

        let port_actual_start = ignore_ports_below.max(PORT_RANGE_START);
        if port_actual_start > PORT_RANGE_END {
            return Err(anyhow::anyhow!(
                "Exhausted all QEMU forwarded ports through the used range ignore"
            ));
        }

        for port in port_actual_start..=PORT_RANGE_END {
            let lock_path = temp_path.join(format!("vci-qemu-port-{port}.lock"));
            let res = FileLock::try_new(lock_path);
            if let Ok(lock) = res {
                return Ok(PortFlock {
                    lock: Some(lock),
                    port,
                });
            }
        }
        Err(anyhow::anyhow!(
            "Unable to acquire any QEMU forwarded ports"
        ))
    }
}

impl Drop for PortFlock {
    fn drop(&mut self) {
        if let Some(lock) = self.lock.take() {
            let flock_path = lock.get_path().clone();
            drop(lock);
            // probably won't fail, but maybe someone else removed the file
            let _ = std::fs::remove_file(&flock_path);
        }
    }
}

pub fn create_backing_file(
    source_path: &std::path::Path,
    dest_path: &std::path::Path,
    exec_target: HostExecTarget,
) -> anyhow::Result<()> {
    let qemu_img = binaries::qemu_image_binary(exec_target)
        .with_context(|| format!("Unable to get qemu-img binary to create the thin overlay"))?
        .0;

    let output = binaries::target_command(exec_target, &qemu_img)
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
        .output()
        .with_context(|| format!("Failed to run {qemu_img}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "qemu-img failed for '{}':\n{}",
            source_path.display(),
            stderr.trim()
        );
    }

    Ok(())
}

/// Cleans up ALL unused temporary QEMU files.
pub fn cleanup_stale_qemu_files(temp_path: &Path) {
    let entries: Vec<_> = match std::fs::read_dir(temp_path) {
        Ok(e) => e.filter_map(std::result::Result::ok).collect(),
        Err(_) => return,
    };

    for entry in &entries {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        let port_str = match name_str
            .strip_prefix("vci-qemu-port-")
            .and_then(|s| s.strip_suffix(".lock"))
        {
            Some(p) => p.to_string(),
            None => continue,
        };

        let Ok(lock) = FileLock::try_lock_exist(entry.path()) else {
            continue;
        };

        let qcow2_suffix = format!("-{port_str}.qcow2");
        let vars_suffix = format!("-{port_str}-VARS.fd");
        let tpm_lock_suffix = format!("-{port_str}-tpm.lock");
        let tpm_dir_suffix = format!("-{port_str}-tpm");
        let serial_log_suffix = format!("-{port_str}-serial.log");

        if let Ok(assoc_entries) = std::fs::read_dir(temp_path) {
            for assoc in assoc_entries.flatten() {
                let aname = assoc.file_name();
                let aname_str = aname.to_string_lossy();

                if aname_str == *name_str {
                    continue;
                }

                if aname_str.starts_with("vci-")
                    && (aname_str.ends_with(&qcow2_suffix)
                        || aname_str.ends_with(&vars_suffix)
                        || aname_str.ends_with(&tpm_lock_suffix)
                        || aname_str.ends_with(&tpm_dir_suffix)
                        || aname_str.ends_with(&serial_log_suffix))
                {
                    let path = assoc.path();
                    if path.is_dir() {
                        let _ = std::fs::remove_dir_all(&path);
                    } else {
                        let _ = std::fs::remove_file(&path);
                    }
                }
            }
        }

        let _ = std::fs::remove_file(lock.get_path());
        drop(lock);
    }

    let entries: Vec<_> = match std::fs::read_dir(temp_path) {
        Ok(e) => e.filter_map(std::result::Result::ok).collect(),
        Err(_) => return,
    };

    for entry in &entries {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if !name_str.starts_with("vci-") || !name_str.ends_with("-tpm.lock") {
            continue;
        }

        let Ok(lock) = FileLock::try_lock_exist(entry.path()) else {
            continue;
        };

        let dir_name = name_str.strip_suffix(".lock").unwrap();
        let dir_path = temp_path.join(std::path::Path::new(dir_name));
        if dir_path.is_dir() {
            let _ = std::fs::remove_dir_all(&dir_path);
        }

        let _ = std::fs::remove_file(lock.get_path());
        drop(lock);
    }

    // windows specific TCP based TPM
    let entries: Vec<_> = match std::fs::read_dir(temp_path) {
        Ok(e) => e.filter_map(std::result::Result::ok).collect(),
        Err(_) => return,
    };

    for entry in &entries {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if !name_str.starts_with("vci-qemu-tpm-port-") || !name_str.ends_with(".lock") {
            continue;
        }

        let Ok(lock) = FileLock::try_lock_exist(entry.path()) else {
            continue;
        };

        let _ = std::fs::remove_file(lock.get_path());
        drop(lock);
    }

    // stale vci_image_*.lock files from crashed or previous runs
    let entries: Vec<_> = match std::fs::read_dir(temp_path) {
        Ok(e) => e.filter_map(std::result::Result::ok).collect(),
        Err(_) => return,
    };

    for entry in &entries {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if !name_str.starts_with("vci_image_") || !name_str.ends_with(".lock") {
            continue;
        }

        let Ok(lock) = FileLock::try_lock_exist(entry.path()) else {
            continue;
        };

        let _ = std::fs::remove_file(lock.get_path());
        drop(lock);
    }
}
