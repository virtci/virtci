// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::process::Command;
use std::sync::Arc;
use std::{path::Path, sync::Mutex};

use anyhow::Context;

use crate::util::bin_version::BinVersion;
use crate::{backend::exec::TargetChildProcess, util::cpu_arch::Arch, vm_image::HostExecTarget};

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
) -> anyhow::Result<(String, BinVersion)> {
    if check_tpm {
        assert!(!matches!(exec_target, HostExecTarget::WindowsNative));
    }

    let binary = resolve_system_binary(arch, exec_target);

    // winget installs x86_64-only QEMU, which on a Windows ARM64 host installs AND
    // prints to stdout with `--version` perfectly fine under Prism emulation, but crashes in the
    // Windows unwinder silently the moment TCG executes guest code. macOS and Linux have the
    // same shape: Rosetta 2, and Linux binfmt_misc handlers (FEX/box64/qemu-user, the latter
    // often registered globally by Docker multi-arch tooling), silently run wrong-arch QEMU
    // with hardware acceleration broken and TCG doubly emulated.
    //
    // WSL2 is excluded for now: the binary lives inside the distro, so sniffing it requires
    // in-distro probing, and it must match the distro environment rather than the Windows host.
    if !matches!(exec_target, HostExecTarget::WSL2(_)) {
        ensure_built_for_native_host(&binary)?;
    }

    let version = query_version(&binary, exec_target)
        .with_context(|| format!("QEMU binary '{binary}' is not functional"))?;

    if check_tpm {
        ensure_tpm_support(&binary, exec_target)?;
    }

    let version = BinVersion::from_qemu_version_string(&version)?;

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

#[cfg_attr(not(target_os = "windows"), allow(unused_variables))]
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

/// Detect HVK (Hypervisor.framework) for a Mac host. Necessary for acceleration.
/// Possible for `kern.hv_support` to not be a registered sysctl oid, still means
/// no accel.
pub fn hvf_available() -> bool {
    if !cfg!(target_os = "macos") {
        return false;
    }
    std::process::Command::new("sysctl")
        .args(["-n", "kern.hv_support"])
        .output()
        .is_ok_and(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == "1")
}

/// QEMU older than 9.2 has an incorrect assertion in it's ARM software page-table walker
/// (`regime_is_user`, reached via `E10_*` translation regimes).
///
/// Some modern arm64 kernels can trigger this during boot, so you may see something like:
///
/// `ERROR:target/arm/internals.h:767:regime_is_user: code should not be reached`.
///
/// Only TCG code paths can encounter this. Only warn, not hard error.
pub fn warn_arm64_tcg_on_old_qemu(version: &BinVersion) {
    use colored::Colorize;

    let min_fixed_version = BinVersion {
        major: 9,
        minor: 2,
        patch: 0,
    };
    if (*version) < min_fixed_version {
        eprintln!(
            "{}",
            format!(
                "Warning: QEMU {}.{}.{} runs this ARM64 guest under TCG emulation, which \
                 before QEMU 9.2.0 can abort while booting modern arm64 kernels \
                 (\"regime_is_user: code should not be reached\"). If the VM dies during boot, \
                 upgrade QEMU to 9.2.0 or newer.",
                version.major, version.minor, version.patch
            )
            .yellow()
        );
    }
}

/// `hw_accel` is whether a same-arch hardware accelerator (KVM/HVF) is usable
/// for this launch, NOT whether one was merely requested.
#[allow(clippy::match_same_arms)]
#[allow(unused_variables)]
pub fn qemu_cpu(
    arch: Arch,
    exec_target: &HostExecTarget,
    hw_accel: bool,
    version: &BinVersion,
) -> &'static str {
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
            // `host` passes the host CPU through and only exists under KVM/HVF.
            #[cfg(target_arch = "aarch64")]
            if hw_accel {
                return "host";
            }
            let min_version_with_neoverse_n1 = BinVersion {
                major: 7,
                minor: 0,
                patch: 0,
            };
            if (*version) < min_version_with_neoverse_n1 {
                eprintln!("You are using QEMU {}.{}.{} which doesn't support `-cpu neoverse-n1`. \
                You may encounter issues using more recent arm64 UEFI firmware while using `-cpu max`. \
                If so, please update to QEMU 7.0.0 or higher.", version.major, version.minor, version.patch);
                "max"
            } else {
                "neoverse-n1"
            }
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

/// SUPER hard error if the executable at `binary` was built for a CPU architecture
/// other than the one this is ACTUALLY running on.
fn ensure_built_for_native_host(binary: &str) -> anyhow::Result<()> {
    let Some(path) = locate_on_path(binary) else {
        return Ok(());
    };
    let Some(built_for) = Arch::of_executable(&path) else {
        return Ok(());
    };
    let host = Arch::host();
    if built_for == host {
        return Ok(());
    }

    #[cfg_attr(not(target_os = "windows"), allow(unused_mut))]
    let mut message = format!(
        "QEMU binary '{}' is built for {} but this host natively runs {}.",
        path.display(),
        built_for.name(),
        host.name()
    );

    #[cfg(target_os = "windows")]
    if host == Arch::ARM64 && built_for == Arch::X64 {
        message.push_str(
            " QEMU installed from winget on Windows as of June 7th 2026 is built for \
        x86_64 hosts only. It may appear functional under Prism emulation, as --version will \
        succeed, but it will crash when the VM starts actually executing. Please install the \
        actual native Windows-on-ARM build at `https://qemu.weilnetz.de/aarch64/`, \
        or point VIRTCI_QEMU_BINARY to the right one.",
        );
    }

    #[cfg(target_os = "macos")]
    if host == Arch::ARM64 && built_for == Arch::X64 {
        message.push_str(
            " An x86_64 QEMU runs under Rosetta 2, where Hypervisor.framework acceleration \
        is unavailable and TCG is doubly emulated. This usually means QEMU came from an \
        x86_64 Homebrew prefix (/usr/local) migrated from an Intel Mac. Please reinstall \
        QEMU with native arm64 Homebrew (/opt/homebrew), or point VIRTCI_QEMU_BINARY to a \
        native build.",
        );
    }

    #[cfg(target_os = "linux")]
    message.push_str(
        " At best a binfmt_misc handler (FEX/box64/qemu-user, often registered globally by \
        Docker multi-arch tooling or Steam Frame) would silently emulate this QEMU, with KVM \
        unusable and TCG doubly emulated (or straight up fail). Please install the \
        distro's native QEMU package, or point VIRTCI_QEMU_BINARY to a native build.",
    );

    anyhow::bail!(message)
}

/// Find the file a bare program name resolves to, approximating the CreateProcess /
/// execvp PATH search. Paths that already contain a directory component are returned
/// as-is (when they exist), matching how [`resolve_system_binary`] produces them.
fn locate_on_path(binary: &str) -> Option<std::path::PathBuf> {
    let path = Path::new(binary);
    if path.components().count() > 1 {
        return path.is_file().then(|| path.to_path_buf());
    }
    let dirs = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&dirs) {
        let candidate = dir.join(path);
        if candidate.is_file() {
            return Some(candidate);
        }

        if cfg!(target_os = "windows") && path.extension().is_none() {
            let with_exe = candidate.with_extension("exe");
            if with_exe.is_file() {
                return Some(with_exe);
            }
        }
    }
    None
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

pub fn find_non_secboot_firmware(
    arch: Arch,
    exec_target: &HostExecTarget,
) -> Option<(String, String)> {
    // Secure Boot is an x86_64 Windows VM concern.
    if !matches!(arch, Arch::X64) {
        return None;
    }

    let candidates: &[(&str, &str)] = if matches!(exec_target, HostExecTarget::WindowsNative) {
        &[(
            "C:\\Program Files\\qemu\\share\\edk2-x86_64-code.fd",
            "C:\\Program Files\\qemu\\share\\edk2-i386-vars.fd",
        )]
    } else {
        &[
            (
                "/usr/share/OVMF/OVMF_CODE_4M.fd",
                "/usr/share/OVMF/OVMF_VARS_4M.fd",
            ),
            (
                "/usr/share/edk2-ovmf/x64/OVMF_CODE.4m.fd",
                "/usr/share/edk2-ovmf/x64/OVMF_VARS.4m.fd",
            ),
            (
                "/usr/share/OVMF/OVMF_CODE.fd",
                "/usr/share/OVMF/OVMF_VARS.fd",
            ),
            (
                "/usr/share/edk2/ovmf/OVMF_CODE.fd",
                "/usr/share/edk2/ovmf/OVMF_VARS.fd",
            ),
        ]
    };

    candidates
        .iter()
        .find(|(code, vars)| firmware_pair_exists(exec_target, code, vars))
        .map(|(code, vars)| ((*code).to_string(), (*vars).to_string()))
}

fn firmware_pair_exists(exec_target: &HostExecTarget, code: &str, vars: &str) -> bool {
    match exec_target {
        HostExecTarget::WSL2(_) => target_command(exec_target, "sh")
            .args(["-c", &format!("test -f '{code}' && test -f '{vars}'")])
            .status()
            .is_ok_and(|s| s.success()),
        _ => Path::new(code).exists() && Path::new(vars).exists(),
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
    use crate::vm_image::GuestOs;

    let qemu_config = backend
        .base_image
        .backend
        .as_qemu()
        .expect("Expected QEMU config");
    let arch = backend.base_image.arch;

    let (program, version) =
        binaries::qemu_system_binary(arch, &backend.exec_target, backend.is_tpm())?;

    let mut args = Vec::<String>::new();

    // KVM/HVF only accelerate same-arch guests, so a cross-arch guest is
    // always TCG even when the host hypervisor is available.
    let hw_accel = arch == Arch::host()
        && match backend.exec_target {
            HostExecTarget::Linux | HostExecTarget::WSL2(_) => {
                kvm::check_kvm_access(&backend.exec_target).is_ok()
            }
            HostExecTarget::MacOS => binaries::hvf_available(),
            // WHPX handled separately below
            HostExecTarget::WindowsNative => false,
        };

    if arch == Arch::ARM64 && !hw_accel {
        binaries::warn_arm64_tcg_on_old_qemu(&version);
    }

    push_arg(
        &mut args,
        "-machine",
        binaries::qemu_machine(arch, &backend.exec_target),
    );

    let cpu = match &qemu_config.cpu_model {
        Some(model) => model.clone(),
        None => binaries::qemu_cpu(arch, &backend.exec_target, hw_accel, &version).to_string(),
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

    if let Some(code) = &backend.uefi_code {
        push_arg(
            &mut args,
            "-drive",
            format!("if=pflash,format=raw,unit=0,readonly=on,file={code}"),
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
            if hw_accel {
                push_arg(&mut args, "-accel", "kvm");
            }
        }
        HostExecTarget::MacOS => {
            if hw_accel {
                push_arg(&mut args, "-accel", "hvf");
            }
        }
        HostExecTarget::WindowsNative => {
            // WHPX only accelerates same-architecture guests, and cannot emulate the OVMF pflash
            // MMIO that UEFI needs (QEMU GitLab #513). In either case fall through to TCG below.
            let has_uefi = backend.uefi_code.is_some() || backend.uefi_vars.is_some();
            if !has_uefi && arch == Arch::host() {
                push_arg(&mut args, "-accel", "whpx");
            }
        }
    }
    push_arg(&mut args, "-accel", "tcg");

    let host_port = backend
        .host_port
        .as_ref()
        .expect("host port acquired before build_qemu_args")
        .port;
    let inside = backend.inside_vm_port;
    let offline = backend.start_config.offline.unwrap_or(false);
    // slirp's `restrict=yes` is unusable on WSL2 from a Windows host.
    let use_restrict = offline && !matches!(backend.exec_target, HostExecTarget::WSL2(_));
    let netdev = if use_restrict {
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

pub fn format_launch_command(exec_target: &HostExecTarget, cmd: &QemuBuiltCommand) -> String {
    fn quote(s: &str) -> String {
        if s.is_empty() || s.chars().any(char::is_whitespace) {
            format!("'{}'", s.replace('\'', r"'\''"))
        } else {
            s.to_string()
        }
    }

    let mut parts: Vec<String> = Vec::new();
    if let HostExecTarget::WSL2(distro) = exec_target {
        parts.extend(["wsl".into(), "-d".into(), distro.clone(), "--".into()]);
    }
    parts.push(quote(&cmd.program));
    parts.extend(cmd.arguments.iter().map(|a| quote(a)));
    parts.join(" ")
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
