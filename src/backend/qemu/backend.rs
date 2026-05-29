// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use crate::{
    backend::{
        exec::TargetChildProcess,
        qemu::{create_backing_file, PortFlock},
        VmStartConfig,
    },
    file_lock::FileLock,
    global_paths::{TargetPath, VciGlobalPaths},
    orphan::OrphanTracker,
    run::run_id::ReservedRunId,
    vm_image::{expand_path, HostExecTarget, ImageDescription},
};

use anyhow::Context;

pub struct QemuBackend {
    pub run_id: ReservedRunId,
    /// Workflow name.
    pub name: String,
    pub base_image: ImageDescription,
    pub start_config: VmStartConfig,
    /// Basically always 22.
    pub inside_vm_port: u16,
    pub graphics: bool,
    /// If None, there is no `-serial` at all. If Some, serial is captured,
    /// and routed to stdio when `!graphics`, or to this file when `graphics`.
    pub serial_log: Option<TargetPath>,
    pub exec_target: HostExecTarget,

    /// Shared or exclusive `vci_image_<name>.lock`
    image_lock: FileLock,
    host_port: Option<PortFlock>,
    disk: BackingFile,
    uefi_vars: Option<BackingFile>,
    additional_drives: Vec<AdditionalDrive>,
    tpm_info: Option<TpmInfo>,

    orphans: OrphanTracker,
    qemu_process: Option<Arc<Mutex<TargetChildProcess>>>,
    /// Must be stored here, as it must restart when QEMU process restarts.
    tpm_process: Option<Arc<Mutex<TargetChildProcess>>>,
}

impl QemuBackend {
    /// # Arguments
    /// - `clone` Whether to create a throwaway clone of `base_image` (writes discarded), or boot
    ///   the base itself (writes persist).
    /// - `graphics` Whether to display graphics.
    /// - `serial` Whether to attach a guest serial (interactive `virtci boot`) routed to stdio
    ///   when `!graphics`, or to a log file when `graphics`. `false` for `virtci run`.
    pub fn new(
        name: String,
        base_image: ImageDescription,
        paths: &VciGlobalPaths,
        clone: bool,
        graphics: bool,
        serial: bool,
        orphans: OrphanTracker,
    ) -> anyhow::Result<Self> {
        let run_id = ReservedRunId::new(paths)?;

        let exec_target: HostExecTarget = {
            #[cfg(target_os = "windows")]
            {
                if base_image
                    .backend
                    .as_qemu()
                    .expect("Expected QEMU config")
                    .tpm
                {
                    if let Some(wsl_paths) = &paths.wsl {
                        HostExecTarget::WSL2(wsl_paths.distro.clone())
                    } else {
                        anyhow::bail!(format!("Need WSL2 paths in order to use TPM "))
                    }
                } else {
                    HostExecTarget::WindowsNative
                }
            }
            #[cfg(target_os = "macos")]
            {
                HostExecTarget::MacOS
            }
            #[cfg(target_os = "linux")]
            {
                HostExecTarget::Linux
            }
        };

        let setup = setup_run(
            &name,
            run_id.id,
            &base_image,
            paths,
            &exec_target,
            serial,
            clone,
        )?;

        Ok(QemuBackend {
            run_id,
            name,
            base_image,
            start_config: VmStartConfig::default(),
            // Guest-side SSH port. The host-side forwarded port lives in `host_port`.
            inside_vm_port: 22,
            graphics,
            serial_log: setup.serial_log,
            exec_target,
            image_lock: setup.image_lock,
            host_port: None,
            disk: setup.disk,
            uefi_vars: setup.uefi_vars,
            additional_drives: setup.additional_drives,
            tpm_info: setup.tpm_info,
            orphans,
            qemu_process: None,
            tpm_process: None,
        })
    }

    pub fn is_base_mode(&self) -> bool {
        matches!(self.disk, BackingFile::Base(_))
    }

    pub fn is_tpm(&self) -> bool {
        self.tpm_info.is_some()
    }

    /// The run marker `vci-<name>-<id:05>`: QEMU's `-name`, the substring the orphan reaper
    /// `pkill -f`s, the metadata `run_name`, and the stem of every temp artifact. Zero-padding
    /// the id keeps one run's marker from being a substring of another's. Single source of truth,
    /// so it must match the file stems built in `setup_run`.
    pub fn run_marker(&self) -> String {
        format!("vci-{}-{:05}", self.name, self.run_id.id)
    }
}

/// A file the VM boots from, resolved to the `exec_target`'s namespace fully. The variant is the
/// source of truth for whether cleanup should delete it or not.
/// - [`BackingFile::Base`] is the image's own file, used in place so writes persist and it is
///   NEVER deleted. This is `virtci boot`.
/// - [`BackingFile::Temp`] is a per-run throwaway in the temp dir (a qcow2 overlay for disks, a
///   plain copy for UEFI vars) so writes are discarded and it is deleted on cleanup.
///   Always for `virtci run`.
enum BackingFile {
    Base(TargetPath),
    Temp(TargetPath),
}

impl BackingFile {
    /// The path QEMU should use, in either mode.
    fn target(&self) -> &TargetPath {
        match self {
            BackingFile::Base(p) | BackingFile::Temp(p) => p,
        }
    }

    /// `Some` only for a throwaway file that cleanup is responsible for deleting.
    fn temp(&self) -> Option<&TargetPath> {
        match self {
            BackingFile::Temp(p) => Some(p),
            BackingFile::Base(_) => None,
        }
    }
}

/// One extra `-drive`, such as the macOS OpenCore bootloader. `spec` is the full `-drive` arg
/// with its `file=` already pointing at `file`'s in-namespace path.
struct AdditionalDrive {
    spec: String,
    file: BackingFile,
}

struct TpmInfo {
    state_dir: TargetPath,
    /// swtpm's control socket inside of `state_dir`. swtpm and QEMU share it.
    socket_path: TargetPath,
}

struct RunSetup {
    image_lock: FileLock,
    disk: BackingFile,
    uefi_vars: Option<BackingFile>,
    additional_drives: Vec<AdditionalDrive>,
    tpm_info: Option<TpmInfo>,
    serial_log: Option<TargetPath>,
}

/// Acquire a flock on the image. Shared lock if `clone`, otherwise Exclusive.
fn acquire_image_lock(
    paths: &VciGlobalPaths,
    image_name: &str,
    clone: bool,
) -> anyhow::Result<FileLock> {
    let lock_path = paths.temp.join(format!("vci_image_{image_name}.lock"));
    if clone {
        FileLock::try_new_shared(&lock_path).map_err(|e| {
            let msg = match e {
                crate::file_lock::FileLockError::OtherProcessBlock(_) => format!(
                    "Image '{image_name}' is currently being modified by `virtci boot`. \
                     Wait for it to finish before starting a new run."
                ),
                crate::file_lock::FileLockError::Other => format!(
                    "Failed to acquire shared lock for image '{image_name}'. \
                     If `virtci boot` is not running, try `virtci cleanup --force`."
                ),
            };
            anyhow::anyhow!(msg)
        })
    } else {
        FileLock::try_new(&lock_path).map_err(|e| {
            let msg = match e {
                crate::file_lock::FileLockError::OtherProcessBlock(_) => format!(
                    "Image '{image_name}' is currently in use by another virtci process — \
                     cannot boot it for modification while it is running."
                ),
                crate::file_lock::FileLockError::Other => format!(
                    "Failed to acquire exclusive lock for image '{image_name}'. \
                     Try `virtci cleanup --force` if no other run is active."
                ),
            };
            anyhow::anyhow!(msg)
        })
    }
}

/// Set up everything a run needs in `exec_target`'s temp dir, short of acquiring the SSH port
/// (that waits until launch). `clone` selects throwaway overlays/copies (`virtci run`) vs the
/// image's own files in place (`virtci boot`), decided per artifact via [`BackingFile`].
fn setup_run(
    name: &str,
    id: u16,
    base_image: &ImageDescription,
    paths: &VciGlobalPaths,
    exec_target: &HostExecTarget,
    serial: bool,
    clone: bool,
) -> anyhow::Result<RunSetup> {
    let qemu_config = base_image.backend.as_qemu().expect("Expected QEMU config");

    let image_lock = acquire_image_lock(paths, &base_image.name, clone)?;

    // May be inside WSL2.
    let temp_dir = temp_dir_target(paths, exec_target);
    std::fs::create_dir_all(&temp_dir.path).with_context(|| {
        format!(
            "Failed to create temp directory {}",
            temp_dir.path.display()
        )
    })?;

    let disk = setup_disk(name, id, qemu_config, paths, exec_target, &temp_dir, clone)?;
    let uefi_vars = setup_uefi_vars(name, id, qemu_config, paths, exec_target, &temp_dir, clone)?;
    let additional_drives =
        setup_additional_drives(name, id, qemu_config, paths, exec_target, &temp_dir, clone)?;

    // swtpm state is always a fresh per-run scratch dir, even in base mode: the `.vci` does not
    // store vTPM state yet, so persisting it across boots is a separate, future feature.
    let tpm_info = if qemu_config.tpm {
        let state_dir = temp_dir.join(&format!("vci-{name}-{id:05}-tpm"));
        std::fs::create_dir_all(&state_dir.path).with_context(|| {
            format!(
                "Failed to create TPM state dir {}",
                state_dir.path.display()
            )
        })?;
        let socket_path = state_dir.join("swtpm-sock");
        Some(TpmInfo {
            state_dir,
            socket_path,
        })
    } else {
        None
    };

    let serial_log = serial.then(|| temp_dir.join(&format!("vci-{name}-{id:05}-serial.log")));

    Ok(RunSetup {
        image_lock,
        disk,
        uefi_vars,
        additional_drives,
        tpm_info,
        serial_log,
    })
}

/// Main disk: a throwaway qcow2 overlay backed by the base (clone), or the base disk itself used
/// in place so writes persist (base).
fn setup_disk(
    name: &str,
    id: u16,
    qemu_config: &crate::vm_image::QemuConfig,
    paths: &VciGlobalPaths,
    exec_target: &HostExecTarget,
    temp_dir: &TargetPath,
    clone: bool,
) -> anyhow::Result<BackingFile> {
    if !clone {
        return Ok(BackingFile::Base(config_path_target_with_unc(
            &qemu_config.image,
            exec_target,
            paths,
        )));
    }

    // Non-UNC path, but may be a path to be done inside WSL2.
    let source_exec = expand_exec_path_no_unc(&qemu_config.image, exec_target, paths);
    let overlay = temp_dir.join(&format!("vci-{name}-{id:05}.qcow2"));
    create_backing_file(&source_exec, &overlay.native_path(), exec_target)
        .context("Failed to create the thin qcow2 overlay backing the clone")?;
    Ok(BackingFile::Temp(overlay))
}

fn setup_uefi_vars(
    name: &str,
    id: u16,
    qemu_config: &crate::vm_image::QemuConfig,
    paths: &VciGlobalPaths,
    exec_target: &HostExecTarget,
    temp_dir: &TargetPath,
    clone: bool,
) -> anyhow::Result<Option<BackingFile>> {
    let Some(uefi) = &qemu_config.uefi else {
        return Ok(None);
    };

    if !clone {
        return Ok(Some(BackingFile::Base(config_path_target_with_unc(
            &uefi.vars,
            exec_target,
            paths,
        ))));
    }

    let src = config_path_target_with_unc(&uefi.vars, exec_target, paths);
    let dest = temp_dir.join(&format!("vci-{name}-{id:05}-VARS.fd"));
    let contents = std::fs::read(&src.path)
        .with_context(|| format!("Failed to read UEFI vars {}", src.path.display()))?;
    std::fs::write(&dest.path, &contents)
        .with_context(|| format!("Failed to write UEFI vars to {}", dest.path.display()))?;
    Ok(Some(BackingFile::Temp(dest)))
}

fn setup_additional_drives(
    name: &str,
    id: u16,
    qemu_config: &crate::vm_image::QemuConfig,
    paths: &VciGlobalPaths,
    exec_target: &HostExecTarget,
    temp_dir: &TargetPath,
    clone: bool,
) -> anyhow::Result<Vec<AdditionalDrive>> {
    let Some(specs) = &qemu_config.additional_drives else {
        return Ok(Vec::new());
    };

    let mut drives = Vec::new();
    for (idx, spec) in specs.iter().enumerate() {
        let Some(file_start) = spec.find("file=") else {
            continue;
        };
        let after_file = &spec[file_start + 5..];
        let file_path = match after_file.find(',') {
            Some(comma) => &after_file[..comma],
            None => after_file,
        };

        let file = if clone {
            let source = expand_exec_path_no_unc(file_path, exec_target, paths);
            let overlay = temp_dir.join(&format!("vci-{name}-drive{idx}-{id:05}.qcow2"));
            create_backing_file(&source, &overlay.native_path(), exec_target)
                .with_context(|| format!("Failed to create overlay for additional drive {idx}"))?;
            BackingFile::Temp(overlay)
        } else {
            BackingFile::Base(config_path_target_with_unc(file_path, exec_target, paths))
        };

        let updated_spec = spec.replace(
            &format!("file={file_path}"),
            &format!("file={}", file.target().native_path()),
        );
        drives.push(AdditionalDrive {
            spec: updated_spec,
            file,
        });
    }
    Ok(drives)
}

/// Expands an image-config path string into `exec_target`'s namespace, without UNC prefixing.
/// Host-native targets call [`expand_path`], such as host `~/` become the host's user home.
/// For [`HostExecTarget::WSL2`], the path becomes the WSL distro's `$HOME`, and separators
/// stay as `/` NOT `\`.
fn expand_exec_path_no_unc(
    path: &str,
    exec_target: &HostExecTarget,
    paths: &VciGlobalPaths,
) -> String {
    #[cfg(target_os = "windows")]
    if let HostExecTarget::WSL2(_) = exec_target {
        let wsl = paths
            .wsl
            .as_ref()
            .expect("WSL2 exec target implies WSL paths");
        return match path.strip_prefix("~/") {
            Some(rest) => format!("{}/{rest}", wsl.wsl_home.trim_end_matches('/')),
            None => path.to_string(),
        };
    }

    let _ = (exec_target, paths);
    expand_path(path).to_string_lossy().into_owned()
}

/// Like [`expand_exec_path_no_unc`], but returns a full [`TargetPath`] whose `path` is reachable
/// from the Windows host, like a `\\wsl.localhost\<distro>` UNC share for WSL2, or a plain host path
/// otherwise. Use this when the host's own `std::fs` must touch the file (e.g. copying UEFI
/// vars). Use [`expand_exec_path_no_unc`] when the path is consumed by a process running inside
/// the namespace. The returned `TargetPath` still yields the in-namespace `/`-path by calling
/// `native_path()`.
fn config_path_target_with_unc(
    path: &str,
    exec_target: &HostExecTarget,
    paths: &VciGlobalPaths,
) -> TargetPath {
    let exec_str = expand_exec_path_no_unc(path, exec_target, paths);

    #[cfg(target_os = "windows")]
    {
        if let HostExecTarget::WSL2(distro) = exec_target {
            let wsl = paths
                .wsl
                .as_ref()
                .expect("WSL2 exec target implies WSL paths");
            return TargetPath {
                path: wsl.to_unc(&exec_str),
                wsl_distro: Some(distro.clone()),
            };
        }
        TargetPath {
            path: PathBuf::from(exec_str),
            wsl_distro: None,
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        TargetPath {
            path: PathBuf::from(exec_str),
        }
    }
}

fn temp_dir_target(paths: &VciGlobalPaths, exec_target: &HostExecTarget) -> TargetPath {
    #[cfg(target_os = "windows")]
    {
        if let HostExecTarget::WSL2(distro) = exec_target {
            let wsl = paths
                .wsl
                .as_ref()
                .expect("WSL2 exec target implies WSL paths");
            return TargetPath {
                path: wsl.to_unc(&wsl.temp),
                wsl_distro: Some(distro.clone()),
            };
        }
        TargetPath {
            path: paths.temp.clone(),
            wsl_distro: None,
        }
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = exec_target;
        TargetPath {
            path: paths.temp.clone(),
        }
    }
}

struct QemuBuiltCommand {
    program: String,
    arguments: Vec<String>,
}

/// Append a QEMU `-flag value` pair. MUST be two separate argv strings.
fn push_arg(args: &mut Vec<String>, flag: &str, value: impl Into<String>) {
    args.push(flag.to_string());
    args.push(value.into());
}

/// Build the full `qemu-system-*` invocation for `backend`, ready to spawn on its `exec_target`.
/// Requires the SSH port to be acquired (`host_port`) and cpus/memory/offline resolved into
/// `start_config`.
fn build_qemu_args(backend: &QemuBackend) -> anyhow::Result<QemuBuiltCommand> {
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
