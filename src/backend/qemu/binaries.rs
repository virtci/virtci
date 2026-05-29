// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::process::Command;
use std::sync::Arc;
use std::{path::Path, sync::Mutex};

use anyhow::Context;

use crate::{
    backend::exec::TargetChildProcess,
    vm_image::{Arch, HostExecTarget},
};

/// Build a [`Command`] that runs `program` on `exec_target`, wrapping through
/// `wsl -d <distro> --` (the target's own distro, not necessarily the default) when the
/// target is WSL2 — so binary probes run in the same distro the images are stored in.
pub fn target_command(exec_target: &HostExecTarget, program: &str) -> Command {
    match exec_target {
        HostExecTarget::WSL2(distro) => {
            let mut cmd = Command::new("wsl");
            cmd.args(["-d", distro.as_str(), "--", program]);
            cmd
        }
        _ => Command::new(program),
    }
}

/// Resolve the `qemu-system-<arch>` binary for `exec_target`, confirm it is
/// functional (by reading its version), and optionally require TPM support.
///
/// `exec_target` selects *how* the binary is invoked, not just where it lives:
/// [`HostExecTarget::WSL2`] runs everything through `wsl -d <distro> --` inside the
/// target's distro, so this works from a Windows host driving QEMU in WSL2.
///
/// # Returns
///
/// On `Ok`, the first tuple member is the binary to run (a path or bare name,
/// without any `wsl --` prefix, so re-wrap with the same target when launching),
/// and the second is the first line of its version output.
pub fn qemu_system_binary(
    arch: Arch,
    exec_target: &HostExecTarget,
    check_tpm: bool,
) -> anyhow::Result<(String, String)> {
    if check_tpm {
        assert!(!matches!(exec_target, HostExecTarget::WindowsNative));
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
/// [`HostExecTarget::WSL2`] runs everything through `wsl -d <distro> --` inside the
/// target's distro, so this works from a Windows host driving QEMU in WSL2.
///
/// # Returns
///
/// On `Ok`, the first tuple member is the binary to run (a path or bare name,
/// without any `wsl --` prefix, so re-wrap with the same target when launching),
/// and the second is the first line of its version output.
pub fn qemu_image_binary(exec_target: &HostExecTarget) -> anyhow::Result<(String, String)> {
    let binary = resolve_img_binary(exec_target);
    let version = query_version(&binary, exec_target)
        .with_context(|| format!("QEMU img binary '{binary}' is not functional"))?;

    Ok((binary, version))
}

pub fn qemu_machine(arch: Arch, exec_target: &HostExecTarget) -> &'static str {
    match arch {
        Arch::X64 => {
            // Emulate the APIC for windows hypervisor
            #[cfg(target_os = "windows")]
            if matches!(exec_target, HostExecTarget::WindowsNative) {
                return "q35,kernel-irqchip=off";
            }
            return "q35";
        }
        Arch::RISCV64 | Arch::ARM64 => "virt",
    }
}

#[allow(clippy::match_same_arms)]
pub fn qemu_cpu(arch: Arch, exec_target: &HostExecTarget) -> &'static str {
    match arch {
        Arch::X64 => {
            // WHPX is sensitive to CPUID values set during vCPU initialization.
            // -cpu host (even with stripped flags) passes through host XSAVE
            // feature bits and other CPUID leaves that WHPX cannot handle,
            // causing an immediate triple-fault before the BIOS executes a
            // single instruction. qemu64 uses a fixed minimal CPUID set with
            // no host-derived values, which WHPX initializes correctly.
            #[cfg(target_os = "windows")]
            if matches!(exec_target, HostExecTarget::WindowsNative) {
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

fn resolve_system_binary(arch: Arch, exec_target: &HostExecTarget) -> String {
    if let Ok(custom) = std::env::var("VIRTCI_QEMU_BINARY") {
        return custom;
    }

    let base = match arch {
        Arch::X64 => "qemu-system-x86_64",
        Arch::ARM64 => "qemu-system-aarch64",
        Arch::RISCV64 => "qemu-system-riscv64",
    };

    if matches!(exec_target, HostExecTarget::WindowsNative) {
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

fn resolve_img_binary(exec_target: &HostExecTarget) -> String {
    if let Ok(custom) = std::env::var("VIRTCI_QEMU_IMG_BINARY") {
        return custom;
    }

    let base = "qemu-img";

    if matches!(exec_target, HostExecTarget::WindowsNative) {
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

fn query_version(binary: &str, exec_target: &HostExecTarget) -> anyhow::Result<String> {
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

fn ensure_tpm_support(binary: &str, exec_target: &HostExecTarget) -> anyhow::Result<()> {
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

pub struct QemuBuiltCommand {
    pub program: String,
    pub arguments: Vec<String>,
}

/// Append a QEMU `-flag value` pair. MUST be two separate argv strings.
pub fn push_arg(args: &mut Vec<String>, flag: &str, value: impl Into<String>) {
    args.push(flag.to_string());
    args.push(value.into());
}

/// Build the full `qemu-system-*` invocation for `backend`, ready to spawn on its `exec_target`.
/// Requires the SSH port to be acquired (`host_port`) and cpus/memory/offline resolved into
/// `start_config`.
pub fn build_qemu_args(backend: &super::backend::QemuBackend) -> anyhow::Result<QemuBuiltCommand> {
    use super::{binaries, kvm};
    use crate::vm_image::{Arch, GuestOs};

    let qemu_config = backend
        .base_image
        .backend
        .as_qemu()
        .expect("Expected QEMU config");
    let arch = backend.base_image.arch;

    let (program, _version) =
        binaries::qemu_system_binary(arch, &backend.exec_target, backend.is_tpm())?;

    let mut args = Vec::<String>::new();

    push_arg(
        &mut args,
        "-machine",
        binaries::qemu_machine(arch, &backend.exec_target),
    );

    let cpu = match &qemu_config.cpu_model {
        Some(model) => model.clone(),
        None => binaries::qemu_cpu(arch, &backend.exec_target).to_string(),
    };
    push_arg(&mut args, "-cpu", cpu);

    push_arg(&mut args, "-name", backend.run_marker());

    let cpus = backend
        .start_config
        .cpus
        .expect("cpus resolved before launch");
    let memory_mb = backend
        .start_config
        .memory_mb
        .expect("memory resolved before launch");
    push_arg(&mut args, "-smp", cpus.to_string());
    push_arg(&mut args, "-m", format!("{memory_mb}M"));

    if let Some(uefi) = &qemu_config.uefi {
        push_arg(
            &mut args,
            "-drive",
            format!("if=pflash,format=raw,unit=0,readonly=on,file={}", uefi.code),
        );
        if let Some(vars) = &backend.uefi_vars {
            push_arg(
                &mut args,
                "-drive",
                format!(
                    "if=pflash,format=raw,unit=1,file={}",
                    vars.target().native_path()
                ),
            );
        }
    }

    // Extra drives like OpenCore. The spec already has `file=` in the exec namespace.
    for drive in &backend.additional_drives {
        push_arg(&mut args, "-drive", drive.spec.clone());
    }

    let disk = backend.disk.target().native_path();
    if qemu_config.additional_devices.is_some() {
        // Config is supplying it's own `-device` list.
        // TODO investigate correctness of this with many drives/devices
        push_arg(
            &mut args,
            "-drive",
            format!("id=SystemDisk,if=none,file={disk},format=qcow2"),
        );
    } else {
        match arch {
            Arch::ARM64 | Arch::RISCV64 => {
                push_arg(
                    &mut args,
                    "-drive",
                    format!("id=SystemDisk,if=none,file={disk},format=qcow2"),
                );
                if qemu_config.nvme {
                    push_arg(
                        &mut args,
                        "-device",
                        "nvme,drive=SystemDisk,serial=SystemDisk,bootindex=0",
                    );
                } else {
                    push_arg(
                        &mut args,
                        "-device",
                        "virtio-blk-pci,drive=SystemDisk,bootindex=0",
                    );
                }
            }
            Arch::X64 => {
                if qemu_config.nvme {
                    push_arg(
                        &mut args,
                        "-drive",
                        format!("id=SystemDisk,if=none,file={disk},format=qcow2"),
                    );
                    push_arg(
                        &mut args,
                        "-device",
                        "nvme,drive=SystemDisk,serial=SystemDisk,bootindex=0",
                    );
                } else if backend.base_image.os == GuestOs::Windows {
                    push_arg(
                        &mut args,
                        "-drive",
                        format!("file={disk},format=qcow2,if=ide"),
                    );
                } else {
                    push_arg(
                        &mut args,
                        "-drive",
                        format!("file={disk},format=qcow2,if=virtio"),
                    );
                }
            }
        }
    }

    if let Some(isos) = &qemu_config.readonly_isos {
        for iso in isos {
            push_arg(
                &mut args,
                "-drive",
                format!("file={iso},format=raw,if=virtio,readonly=on"),
            );
        }
    }

    if !backend.graphics {
        push_arg(&mut args, "-display", "none");
    }

    if let Some(serial_log) = &backend.serial_log {
        if backend.graphics {
            push_arg(
                &mut args,
                "-serial",
                format!("file:{}", serial_log.native_path()),
            );
        } else {
            push_arg(&mut args, "-serial", "stdio");
        }
    }

    push_arg(&mut args, "-rtc", "base=utc");

    match backend.exec_target {
        HostExecTarget::Linux | HostExecTarget::WSL2(_) => {
            if kvm::check_kvm_access(&backend.exec_target).is_ok() {
                push_arg(&mut args, "-accel", "kvm");
            }
        }
        HostExecTarget::MacOS => push_arg(&mut args, "-accel", "hvf"),
        HostExecTarget::WindowsNative => push_arg(&mut args, "-accel", "whpx"),
    }
    push_arg(&mut args, "-accel", "tcg");

    let host_port = backend
        .host_port
        .as_ref()
        .expect("host port acquired before build_qemu_args")
        .port;
    let inside = backend.inside_vm_port;
    let offline = backend.start_config.offline.unwrap_or(false);
    let netdev = if offline {
        format!("user,id=net0,restrict=yes,hostfwd=tcp::{host_port}-:{inside}")
    } else {
        format!("user,id=net0,hostfwd=tcp::{host_port}-:{inside}")
    };
    push_arg(&mut args, "-netdev", netdev);

    // `disable-modern=on` forces virtio legacy (INTx, not MSI-X), required by WHPX.
    if matches!(backend.exec_target, HostExecTarget::WindowsNative) {
        push_arg(
            &mut args,
            "-device",
            "virtio-net-pci,netdev=net0,disable-modern=on",
        );
    } else {
        push_arg(&mut args, "-device", "virtio-net-pci,netdev=net0");
    }

    if let Some(tpm) = &backend.tpm_info {
        push_arg(
            &mut args,
            "-chardev",
            format!("socket,id=chrtpm,path={}", tpm.socket_path.native_path()),
        );
        push_arg(&mut args, "-tpmdev", "emulator,id=tpm0,chardev=chrtpm");
        let device = match arch {
            Arch::ARM64 | Arch::RISCV64 => "tpm-tis-device,tpmdev=tpm0",
            Arch::X64 => "tpm-tis,tpmdev=tpm0",
        };
        push_arg(&mut args, "-device", device);
    }

    if let Some(devices) = &qemu_config.additional_devices {
        for device in devices {
            push_arg(&mut args, "-device", device.clone());
        }
    }

    Ok(QemuBuiltCommand {
        program,
        arguments: args,
    })
}

pub enum QemuLaunchOutcome {
    Running,
    PortTaken,
}

/// Observe the launch for about 1.5 seconds to see if the port was taken.
pub fn qemu_launch_outcome(
    qemu: &Arc<Mutex<TargetChildProcess>>,
    stderr_log: &Path,
) -> anyhow::Result<QemuLaunchOutcome> {
    const POLL: std::time::Duration = std::time::Duration::from_millis(100);
    const ATTEMPTS: u32 = 15;

    for _ in 0..ATTEMPTS {
        std::thread::sleep(POLL);
        let exited = {
            let mut guard = qemu.lock().expect("QEMU process lock poisoned how?");
            guard.try_wait()
        };
        if exited {
            let stderr = std::fs::read_to_string(stderr_log).unwrap_or_default();
            if stderr.to_lowercase().contains("host forwarding rule") {
                return Ok(QemuLaunchOutcome::PortTaken);
            }
            anyhow::bail!("QEMU exited immediately after launch:\n{}", stderr.trim());
        }
    }

    Ok(QemuLaunchOutcome::Running)
}
