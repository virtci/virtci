// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::path::Path;
use std::process::Command;

use anyhow::Context;

use crate::vm_image::{Arch, HostExecTarget};

/// Build a [`Command`] that runs `program` on `exec_target`, wrapping through
/// `wsl --` (default distro) when the target is WSL2.
pub fn target_command(exec_target: HostExecTarget, program: &str) -> Command {
    match exec_target {
        HostExecTarget::WSL2 => {
            let mut cmd = Command::new("wsl");
            cmd.arg("--").arg(program);
            cmd
        }
        _ => Command::new(program),
    }
}

/// Resolve the `qemu-system-<arch>` binary for `exec_target`, confirm it is
/// functional (by reading its version), and optionally require TPM support.
///
/// `exec_target` selects *how* the binary is invoked, not just where it lives:
/// [`HostExecTarget::WSL2`] runs everything through `wsl --` inside the default
/// distro, so this works from a Windows host driving QEMU in WSL2.
///
/// # Returns
///
/// On `Ok`, the first tuple member is the binary to run (a path or bare name,
/// without any `wsl --` prefix, so re-wrap with the same target when launching),
/// and the second is the first line of its version output.
pub fn qemu_system_binary(
    arch: Arch,
    exec_target: HostExecTarget,
    check_tpm: bool,
) -> anyhow::Result<(String, String)> {
    if check_tpm {
        assert_ne!(exec_target, HostExecTarget::WindowsNative);
    }

    let binary = resolve_system_binary(arch, exec_target);
    let version = query_version(&binary, exec_target)
        .with_context(|| format!("QEMU binary '{binary}' is not functional"))?;

    if check_tpm {
        ensure_tpm_support(&binary, exec_target)?;
    }

    Ok((binary, version))
}

/// Resolve the `qemu-img` binary for `exec_target`, and confirm it is functional.
///
/// `exec_target` selects how the binary is invoked, not just where it is.
/// [`HostExecTarget::WSL2`] runs everything through `wsl --` inside the default
/// distro, so this works from a Windows host driving QEMU in WSL2.
///
/// # Returns
///
/// On `Ok`, the first tuple member is the binary to run (a path or bare name,
/// without any `wsl --` prefix, so re-wrap with the same target when launching),
/// and the second is the first line of its version output.
pub fn qemu_image_binary(exec_target: HostExecTarget) -> anyhow::Result<(String, String)> {
    let binary = resolve_img_binary(exec_target);
    let version = query_version(&binary, exec_target)
        .with_context(|| format!("QEMU img binary '{binary}' is not functional"))?;

    Ok((binary, version))
}

pub fn qemu_machine(arch: Arch, exec_target: HostExecTarget) -> &'static str {
    match arch {
        Arch::X64 => {
            // Emulate the APIC for windows hypervisor
            #[cfg(target_os = "windows")]
            if exec_target == HostExecTarget::WindowsNative {
                return "q35,kernel-irqchip=off";
            }
            return "q35";
        }
        Arch::RISCV64 | Arch::ARM64 => "virt",
    }
}

#[allow(clippy::match_same_arms)]
pub fn qemu_cpu(arch: Arch, exec_target: HostExecTarget) -> &'static str {
    match arch {
        Arch::X64 => {
            // WHPX is sensitive to CPUID values set during vCPU initialization.
            // -cpu host (even with stripped flags) passes through host XSAVE
            // feature bits and other CPUID leaves that WHPX cannot handle,
            // causing an immediate triple-fault before the BIOS executes a
            // single instruction. qemu64 uses a fixed minimal CPUID set with
            // no host-derived values, which WHPX initializes correctly.
            #[cfg(target_os = "windows")]
            if exec_target == HostExecTarget::WindowsNative {
                return "qemu64";
            }
            #[cfg(target_arch = "x86_64")]
            return "max";
            #[cfg(not(target_arch = "x86_64"))]
            return "qemu64";
        }
        Arch::RISCV64 => "max",
        Arch::ARM64 => {
            #[cfg(target_arch = "aarch64")]
            return "host";
            #[cfg(not(target_arch = "aarch64"))]
            return "max";
        }
    }
}

fn resolve_system_binary(arch: Arch, exec_target: HostExecTarget) -> String {
    if let Ok(custom) = std::env::var("VIRTCI_QEMU_BINARY") {
        return custom;
    }

    let base = match arch {
        Arch::X64 => "qemu-system-x86_64",
        Arch::ARM64 => "qemu-system-aarch64",
        Arch::RISCV64 => "qemu-system-riscv64",
    };

    if exec_target == HostExecTarget::WindowsNative {
        let exe = format!("{base}.exe");
        let candidates = [
            // MSYS2 UCRT64 (mingw-w64-ucrt-x86_64-qemu) DOES NOT INCLUDE TPM SUPPORT ITS A LIE
            format!("C:\\msys64\\ucrt64\\bin\\{exe}"),
            // MSYS2 MINGW64
            format!("C:\\msys64\\mingw64\\bin\\{exe}"),
            // Official QEMU Windows installer ALSO DOESN'T INCLUDE TPM SUPPORT, LIES
            format!("C:\\Program Files\\qemu\\{exe}"),
        ];
        for candidate in candidates {
            if Path::new(&candidate).exists() {
                return candidate;
            }
        }
        return exe;
    }

    base.to_string()
}

fn resolve_img_binary(exec_target: HostExecTarget) -> String {
    if let Ok(custom) = std::env::var("VIRTCI_QEMU_IMG_BINARY") {
        return custom;
    }

    let base = "qemu-img";

    if exec_target == HostExecTarget::WindowsNative {
        let exe = "qemu-img.exe".to_string();
        let candidates = [
            format!("C:\\msys64\\ucrt64\\bin\\{exe}"),
            format!("C:\\msys64\\mingw64\\bin\\{exe}"),
            format!("C:\\Program Files\\qemu\\{exe}"),
        ];
        for candidate in candidates {
            if std::path::Path::new(&candidate).exists() {
                return candidate;
            }
        }
        return exe;
    }

    return base.to_string();
}

fn query_version(binary: &str, exec_target: HostExecTarget) -> anyhow::Result<String> {
    let output = target_command(exec_target, binary)
        .arg("--version")
        .output()
        .with_context(|| format!("failed to execute QEMU binary '{binary}'"))?;

    if !output.status.success() {
        anyhow::bail!(
            "QEMU binary '{binary}' exited with {} on --version: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let first_line = stdout.lines().next().unwrap_or("").trim();
    if first_line.is_empty() {
        anyhow::bail!("QEMU binary '{binary}' produced no version output");
    }

    Ok(first_line.to_string())
}

fn ensure_tpm_support(binary: &str, exec_target: HostExecTarget) -> anyhow::Result<()> {
    let output = target_command(exec_target, binary)
        .arg("-tpmdev")
        .arg("help")
        .output()
        .with_context(|| format!("failed to query TPM support from '{binary}'"))?;

    let listed = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    if listed.contains("emulator") {
        Ok(())
    } else {
        anyhow::bail!(
            "QEMU binary '{binary}' was not built with TPM (swtpm emulator) support. \
             On Windows, you must install via WSL2."
        )
    }
}
