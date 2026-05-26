// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::{path::Path, process::Command};

use anyhow::Context;

use crate::vm_image::HostExecTarget;

/// Verify that KVM acceleration is usable for the given execution target.
///
/// KVM is Linux-only, so the non-Linux native targets have nothing to check and
/// return `Ok(())` (`WindowsNative` uses WHPX, `MacOS` uses HVF, `FreeBSD` its
/// own accelerator).
///
/// - [`HostExecTarget::Linux`] opens `/dev/kvm` read-write directly. This also
///   covers running *natively inside* a WSL2 distro.
/// - [`HostExecTarget::WSL2`] (the Windows host driving QEMU through WSL2) runs
///   the equivalent probe inside the default distro via `wsl`.
///
/// A read-write open of `/dev/kvm` is also the nested-virtualization check.
/// If nested virt is disabled or the WSL2 kernel lacks KVM, the device is either
/// absent or not openable, so no separate Hyper-V/`.wslconfig` query is needed.
pub fn check_kvm_access(exec_target: HostExecTarget) -> anyhow::Result<()> {
    match exec_target {
        HostExecTarget::WindowsNative | HostExecTarget::FreeBSD | HostExecTarget::MacOS => Ok(()),
        HostExecTarget::Linux => check_kvm_native(),
        HostExecTarget::WSL2 => check_kvm_through_wsl2(),
    }
}

/// Check `/dev/kvm` from the current Linux process (bare metal or inside WSL2).
fn check_kvm_native() -> anyhow::Result<()> {
    let kvm_path = Path::new("/dev/kvm");

    if !kvm_path.exists() {
        if running_inside_wsl() {
            anyhow::bail!(
                "/dev/kvm is missing inside this WSL2 distro — enable nested virtualization \
                 (set `nestedVirtualization=true` in %USERPROFILE%\\.wslconfig, the default on \
                 recent Windows 11) and run `wsl --shutdown` to restart"
            );
        }
        anyhow::bail!(
            "/dev/kvm not present, you likely load the KVM module (modprobe kvm_intel or kvm_amd)"
        );
    }

    // QEMU opens /dev/kvm O_RDWR. A read-only probe can hide a permission problem.
    match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(kvm_path)
    {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => Err(anyhow::anyhow!(
            "permission denied opening /dev/kvm read-write — add your user to the `kvm` group \
             (sudo usermod -aG kvm $USER) and re-login"
        )),
        Err(e) => Err(anyhow::anyhow!("cannot open /dev/kvm read-write: {e}")),
    }
}

/// Probe `/dev/kvm` inside the default WSL2 distro from the Windows host.
fn check_kvm_through_wsl2() -> anyhow::Result<()> {
    // `-r`/`-w` reflect the read-write access QEMU's O_RDWR open needs. The three
    // distinct words map to actionable errors without parsing locale-dependent
    // errno text. Runs through the default distro, matching where swtpm runs.
    const PROBE: &str = "if [ ! -e /dev/kvm ]; then echo MISSING; \
                         elif [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then echo DENIED; \
                         else echo OK; fi";

    let output = Command::new("wsl")
        .args(["--", "sh", "-c", PROBE])
        .output()
        .context("failed to run `wsl` to probe /dev/kvm (is WSL installed and on PATH?)")?;

    if !output.status.success() {
        anyhow::bail!(
            "`wsl` failed while probing /dev/kvm ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let verdict = String::from_utf8_lossy(&output.stdout);
    match verdict.trim() {
        "OK" => Ok(()),
        "MISSING" => Err(anyhow::anyhow!(
            "/dev/kvm is missing inside WSL2. Youu must enable nested virtualization \
             (set `nestedVirtualization=true` in %UserProfile%\\.wslconfig, the default on recent \
             Windows 11) and ensure the WSL2 kernel includes KVM, then run `wsl --shutdown`"
        )),
        "DENIED" => Err(anyhow::anyhow!(
            "/dev/kvm inside WSL2 is not read-write for the WSL user so add it to the `kvm` group \
             (sudo usermod -aG kvm $USER) and restart the distro"
        )),
        other => Err(anyhow::anyhow!(
            "unexpected output from WSL /dev/kvm probe: {other:?} (stderr: {})",
            String::from_utf8_lossy(&output.stderr).trim()
        )),
    }
}

/// Whether the current Linux process is running inside a WSL distro, used to give
/// a nested-virtualization hint instead of a `modprobe` one when `/dev/kvm` is absent.
fn running_inside_wsl() -> bool {
    if std::env::var_os("WSL_DISTRO_NAME").is_some() || std::env::var_os("WSL_INTEROP").is_some() {
        return true;
    }
    std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| {
            let s = s.to_ascii_lowercase();
            s.contains("microsoft") || s.contains("wsl")
        })
        .unwrap_or(false)
}
