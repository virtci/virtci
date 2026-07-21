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
pub mod qmp;

/// On a Windows host, deciding whether a QEMU image should run natively or inside WSL2 (optionally
/// with KVM) depends on a few factors:
/// - **TPM**: Always on WSL2, not avoidable.
/// - **UEFI**: forces WSL2 ONLY WHEN WSL2 can actually accelerate it. WHPX cannot emulate OVMF
///   `-pflash` MMIO (QEMU GitLab #513), so a native UEFI VM would have to use TCG. That fallback
///   is only worth avoiding if KVM acceleration is present. Cross-arch VM is TCG regardless.
/// - **Legacy BIOS**: Run on the Windows host.
#[cfg(target_os = "windows")]
#[must_use]
pub fn image_runs_in_wsl2(
    tpm: bool,
    has_uefi: bool,
    arch: crate::util::cpu_arch::Arch,
    wsl: Option<&crate::global_paths::WslPaths>,
) -> bool {
    use crate::util::cpu_arch::Arch;
    if tpm {
        return true;
    }
    if !has_uefi {
        return false;
    }

    if arch != Arch::host() {
        // Cross-arch always runs under TCG so KVM in WSL2 would not help. Keep it on the host.
        return false;
    }
    let Some(wsl) = wsl else {
        return false;
    };
    kvm::check_kvm_access(&HostExecTarget::WSL2(wsl.distro.clone())).is_ok()
}

/// Resolve the IPv4 address of a WSL2 distro's primary interface, as seen from the Windows host.
///
/// When the Windows host drives QEMU inside WSL2, QEMU's `hostfwd` binds the forwarded SSH port
/// *inside the WSL2 network namespace*, not on the Windows host. Reaching it via `127.0.0.1`
/// depends on WSL2 localhost forwarding, which is unreliable (and disabled outright in some
/// configurations). The distro's NAT IP is always directly reachable from the host, so we dial
/// that instead. The IP is stable for the lifetime of the distro but can change across a
/// `wsl --shutdown`, so callers resolve it per run rather than caching it on disk.
#[cfg(target_os = "windows")]
pub fn wsl_distro_ip(distro: &str) -> anyhow::Result<String> {
    let output = std::process::Command::new("wsl")
        .args(["-d", distro, "--", "hostname", "-I"])
        .output()
        .context("failed to run `wsl` to resolve the distro IP")?;
    if !output.status.success() {
        anyhow::bail!(
            "`wsl hostname -I` failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    // `hostname -I` lists every address; the first is the primary eth0 NAT IP.
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout
        .split_whitespace()
        .next()
        .map(str::to_string)
        .context("`wsl hostname -I` returned no IP address")
}

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
    ///   TCP port to be busy. Use `0` by default generally if you don't want to ignore any ports.
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
                // Optimistic bind probe. Like 99% of the time, a successful TCP bind means the
                // later QEMU TCP bind will succeed as the ports are rarely in use.
                // A failed bind means the port is DEFINITELY not available though.
                // WinNAT/Hyper-V can reserve ports within the PORT_RANGE_START -> PORT_RANGE_END
                // range.
                if std::net::TcpListener::bind(("127.0.0.1", port)).is_err() {
                    continue;
                }
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

    let mut cmd = binaries::target_command(exec_target, &qemu_img);
    cmd.args(["create", "-f", "qcow2", "-b", source_exec, "-F", "qcow2"]);
    cmd.arg(dest_exec);
    let output = cmd
        .output()
        .with_context(|| format!("Failed to run {qemu_img}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("qemu-img failed for '{source_exec}':\n{}", stderr.trim());
    }

    Ok(())
}

fn require_windows_native(exec_target: &HostExecTarget, what: &str) -> anyhow::Result<()> {
    if !matches!(exec_target, HostExecTarget::WindowsNative) {
        anyhow::bail!("{what} is only valid on a native-Windows exec target");
    }
    Ok(())
}

pub fn materialize_raw(
    source_exec: &str,
    dest_exec: &str,
    exec_target: &HostExecTarget,
) -> anyhow::Result<()> {
    require_windows_native(exec_target, "raw run-disk materialization")?;

    let qemu_img = binaries::qemu_image_binary(exec_target)
        .context("Unable to get qemu-img binary to materialize the raw run-disk")?
        .0;

    let output = binaries::target_command(exec_target, &qemu_img)
        .args(["convert", "-O", "raw", source_exec, dest_exec])
        .output()
        .with_context(|| format!("Failed to run {qemu_img} convert"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "qemu-img convert -O raw failed for '{source_exec}':\n{}",
            stderr.trim()
        );
    }

    Ok(())
}

pub fn writeback_raw_to_qcow2(
    raw_exec: &str,
    base_exec: &str,
    dest_exec: &str,
    exec_target: &HostExecTarget,
) -> anyhow::Result<()> {
    require_windows_native(exec_target, "raw->qcow2 cache write-back")?;

    let qemu_img = binaries::qemu_image_binary(exec_target)
        .context("Unable to get qemu-img binary for the raw->qcow2 write-back")?
        .0;

    let output = binaries::target_command(exec_target, &qemu_img)
        .args([
            "convert", "-f", "raw", "-O", "qcow2", "-B", base_exec, "-F", "qcow2", raw_exec,
            dest_exec,
        ])
        .output()
        .with_context(|| format!("Failed to run {qemu_img} convert (write-back)"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "qemu-img raw->qcow2 write-back failed for '{raw_exec}':\n{}",
            stderr.trim()
        );
    }

    Ok(())
}

pub fn qemu_img_compare_raw_qcow2(
    raw_exec: &str,
    qcow2_exec: &str,
    exec_target: &HostExecTarget,
) -> anyhow::Result<bool> {
    require_windows_native(exec_target, "raw/qcow2 write-back compare gate")?;

    let qemu_img = binaries::qemu_image_binary(exec_target)
        .context("Unable to get qemu-img binary for the write-back compare gate")?
        .0;

    let output = binaries::target_command(exec_target, &qemu_img)
        .args(["compare", "-f", "raw", raw_exec, "-F", "qcow2", qcow2_exec])
        .output()
        .with_context(|| format!("Failed to run {qemu_img} compare"))?;

    // qemu-img compare: 0 == identical, 1 == differ, 2+ == error.
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "qemu-img compare errored for raw '{raw_exec}' vs qcow2 '{qcow2_exec}':\n{}",
                stderr.trim()
            )
        }
    }
}

/// Attempt to get the virtual size of a QEMU disk. Doesn't need to boot.
pub fn base_disk_virtual_size(
    disk_exec: &str,
    exec_target: &HostExecTarget,
) -> anyhow::Result<u64> {
    let qemu_img = binaries::qemu_image_binary(exec_target)
        .context("Unable to get qemu-img binary to read the disk size")?
        .0;

    let output = binaries::target_command(exec_target, &qemu_img)
        .args(["info", "--output=json", disk_exec])
        .output()
        .with_context(|| format!("Failed to run {qemu_img} info"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("qemu-img info failed for '{disk_exec}':\n{}", stderr.trim());
    }

    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("parse `qemu-img info` json")?;
    let bytes = value
        .get("virtual-size")
        .and_then(serde_json::Value::as_u64)
        .context("`qemu-img info` output missing numeric `virtual-size`")?;

    Ok(bytes / (1024 * 1024 * 1024))
}

pub fn qemu_img_resize(
    disk_exec: &str,
    gb: u64,
    exec_target: &HostExecTarget,
) -> anyhow::Result<()> {
    let qemu_img = binaries::qemu_image_binary(exec_target)
        .context("Unable to get qemu-img binary to resize the disk")?
        .0;

    let size = format!("{gb}G");
    let output = binaries::target_command(exec_target, &qemu_img)
        .args(["resize", disk_exec, &size])
        .output()
        .with_context(|| format!("Failed to run {qemu_img} resize"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!(
            "qemu-img resize of '{disk_exec}' to {size} failed:\n{}",
            stderr.trim()
        );
    }

    Ok(())
}

/// Cleanup ALL unused temporary VirtCI files.
/// Authority is on the `.lock` flocks which always live in the host system's temp dir.
/// There are 3 kinds of them:
/// - `vci-active-{id}.lock` A run's stable identifier. See [`crate::run::run_id::ReservedRunId`].
///   Reclaiming one means it's owner died, to any orphaned QEMU/swtpm stuff by the market stored
///   in its metadata shall be used to cleanup.
/// - `vci-qemu-port-{port}.lock` Used to note which VirtCI processes are using which TCP ports.
/// - `vci_image_{name}.lock` Shared / exclusive lock on a VirtCI image file.
pub fn cleanup_stale_qemu_files(paths: &VciGlobalPaths) {
    let lock_dir = paths.temp.as_path();

    // TODO flock over 9p fine if the WSL one doing too? Not sure.
    #[cfg(target_os = "windows")]
    let payload_dirs: Vec<PathBuf> = {
        let mut dirs = vec![lock_dir.to_path_buf(), paths.cache_staging_dir().path];
        if let Some(wsl) = &paths.wsl {
            dirs.push(wsl.to_unc(&wsl.temp));
            dirs.push(paths.wsl_cache_staging_dir().path);
        }
        dirs
    };
    #[cfg(not(target_os = "windows"))]
    let payload_dirs: Vec<PathBuf> = vec![lock_dir.to_path_buf(), paths.cache_staging_dir().path];

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
        if let Some(meta) = lock.read_metadata()
            && let Some(marker) = meta.run_name.as_deref()
        {
            #[cfg(target_os = "windows")]
            if let Some(distro) = meta.wsl_distro.as_deref() {
                crate::backend::exec::reap_wsl2_marker_process(distro, marker);
            }
            #[cfg(unix)]
            reap_host_marker_process(marker);
        }

        // `-{id}.qcow2` also covers the `…-drive{n}-{id}.qcow2` additional drives.
        let suffixes = [
            format!("-{id}.qcow2"),
            format!("-{id}-VARS.fd"),
            format!("-{id}-tpm"),
            format!("-{id}-serial.log"),
            format!("-{id}-qemu.stderr"),
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

    #[cfg(target_os = "windows")]
    let cache_roots: Vec<crate::global_paths::TargetPath> = {
        let mut roots = vec![paths.cache_dir()];
        if paths.wsl.is_some() {
            roots.push(paths.wsl_cache_dir());
        }
        roots
    };
    #[cfg(not(target_os = "windows"))]
    let cache_roots: Vec<crate::global_paths::TargetPath> = vec![paths.cache_dir()];
    for root in &cache_roots {
        reap_partial_cache_slots(&root.path, &root.path, lock_dir);
        let limits = crate::run::cache::lru::CacheLimits::from_env(root);
        crate::run::cache::lru::enforce_limits(root, lock_dir, &limits);
    }
}

fn reap_partial_cache_slots(cache_root: &Path, dir: &Path, host_temp: &Path) {
    if dir.join("disk.qcow2").exists() {
        if dir
            .join(crate::run::cache::metadata::CacheMetadata::FILENAME)
            .exists()
        {
            return;
        }
        let Ok(rel) = dir.strip_prefix(cache_root) else {
            return;
        };
        let rel = rel.to_string_lossy().replace('\\', "/");
        let lock_path = host_temp.join(crate::run::cache::slot_lock_filename(&rel));
        if let Ok(lock) = FileLock::try_new(&lock_path) {
            let _ = std::fs::remove_dir_all(dir);
            let _ = std::fs::remove_file(lock.get_path());
            drop(lock);
        }
        return;
    }

    for entry in dir_entries(dir) {
        if entry.path().is_dir() {
            reap_partial_cache_slots(cache_root, &entry.path(), host_temp);
        }
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
