// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

//! IMPORTANT! MUST READ FOR HUMANS AND EVEN LLMS.
//!
//!

use std::path::{Path, PathBuf};

use anyhow::Context;

use crate::{file_lock::FileLock, global_paths::VciGlobalPaths, vm_image::HostExecTarget};

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

/// Create a thin qcow2 overlay file, backed by `source_exec` and written to `dest_exec`.
/// Both paths are within the namespace of `exec_target`, so may be inside WSL2.
pub fn create_backing_file(
    source_exec: &str,
    dest_exec: &str,
    exec_target: &HostExecTarget,
) -> anyhow::Result<()> {
    let qemu_img = binaries::qemu_image_binary(exec_target)
        .context("Unable to get qemu-img binary to create the thin overlay")?
        .0;

    let output = binaries::target_command(exec_target, &qemu_img)
        .args([
            "create",
            "-f",
            "qcow2",
            "-b",
            source_exec,
            "-F",
            "qcow2",
            dest_exec,
        ])
        .output()
        .with_context(|| format!("Failed to run {qemu_img}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("qemu-img failed for '{source_exec}':\n{}", stderr.trim());
    }

    Ok(())
}

/// Cleanup ALL unused temporary VirtCI files.
/// Authority is on the `.lock` flocks which always live in the host system's temp dir.
/// There are 3 kinds of them:
/// - `vci-active-{id}.lock` A run's stable identifier. See [`crate::run::run_id::ReservedRunId`].
///     Reclaiming one means it's owner died, to any orphaned QEMU/swtpm stuff by the market stored
///     in its metadata shall be used to cleanup.
/// - `vci-qemu-port-{port}.lock` Used to note which VirtCI processes are using which TCP ports.
/// - `vci_image_{name}.lock` Shared / exclusive lock on a VirtCI image file.
pub fn cleanup_stale_qemu_files(paths: &VciGlobalPaths) {
    let lock_dir = paths.temp.as_path();

    #[cfg(target_os = "windows")]
    let payload_dirs: Vec<PathBuf> = {
        let mut dirs = vec![lock_dir.to_path_buf()];
        if let Some(wsl) = &paths.wsl {
            dirs.push(wsl.to_unc(&wsl.temp));
        }
        dirs
    };
    #[cfg(not(target_os = "windows"))]
    let payload_dirs: Vec<PathBuf> = vec![lock_dir.to_path_buf()];

    // 1. Active-run identity locks: reap orphans by marker, then delete payload.
    for entry in dir_entries(lock_dir) {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        let Some(id) = name_str
            .strip_prefix("vci-active-")
            .and_then(|s| s.strip_suffix(".lock"))
        else {
            continue;
        };

        let Ok(lock) = FileLock::try_lock_exist(entry.path()) else {
            continue;
        };

        // The marker (`run_name`) is written before any process spawns, so it is
        // always present whenever there is something to reap.
        if let Some(meta) = lock.read_metadata() {
            if let Some(marker) = meta.run_name.as_deref() {
                #[cfg(target_os = "windows")]
                if let Some(distro) = meta.wsl_distro.as_deref() {
                    crate::backend::exec::reap_wsl2_marker_process(distro, marker);
                }
                #[cfg(unix)]
                reap_host_marker_process(marker);
            }
        }

        // `-{id}.qcow2` also covers the `…-drive{n}-{id}.qcow2` additional drives.
        let suffixes = [
            format!("-{id}.qcow2"),
            format!("-{id}-VARS.fd"),
            format!("-{id}-tpm"),
            format!("-{id}-serial.log"),
        ];
        for dir in &payload_dirs {
            remove_matching(dir, &suffixes);
        }

        let _ = std::fs::remove_file(lock.get_path());
        drop(lock);
    }

    // 2. Port reservations: a reclaimable one is stale, drop the lock file.
    for entry in dir_entries(lock_dir) {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if !name_str.starts_with("vci-qemu-port-") || !name_str.ends_with(".lock") {
            continue;
        }

        let Ok(lock) = FileLock::try_lock_exist(entry.path()) else {
            continue;
        };

        let _ = std::fs::remove_file(lock.get_path());
        drop(lock);
    }

    // 3. Stale vci_image_*.lock files from crashed or previous runs (lock only).
    for entry in dir_entries(lock_dir) {
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

#[cfg(unix)]
fn reap_host_marker_process(marker: &str) {
    let _ = std::process::Command::new("pkill")
        .args(["-9", "-f", marker])
        .status();
}

/// Collects the directory entries of `dir`, or an empty list if it can't be read.
fn dir_entries(dir: &Path) -> Vec<std::fs::DirEntry> {
    match std::fs::read_dir(dir) {
        Ok(e) => e.filter_map(std::result::Result::ok).collect(),
        Err(_) => Vec::new(),
    }
}

/// Removes every `vci-` prefixed entry in `dir` that ends with one of `suffixes`.
fn remove_matching(dir: &Path, suffixes: &[String]) {
    for entry in dir_entries(dir) {
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if !name_str.starts_with("vci-") {
            continue;
        }
        if suffixes.iter().any(|s| name_str.ends_with(s.as_str())) {
            let path = entry.path();
            if path.is_dir() {
                let _ = std::fs::remove_dir_all(&path);
            } else {
                let _ = std::fs::remove_file(&path);
            }
        }
    }
}
