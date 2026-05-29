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
    pub inside_vm_port: u16,
    pub graphics: bool,
    /// If None, there is no `-serial` at all. If Some, serial is captured,
    /// and routed to stdio when `!graphics`, or to this file when `graphics`.
    pub serial_log: Option<TargetPath>,
    pub exec_target: HostExecTarget,

    /// Shared or exclusive `vci_image_<name>.lock`
    image_lock: FileLock,
    host_port: Option<PortFlock>,
    temp_image: Option<TargetPath>,
    temp_uefi_vars: Option<TargetPath>,
    temp_additional_drives: Option<AdditionalDrives>,
    tpm_info: Option<TpmInfo>,

    orphans: OrphanTracker,
    qemu_process: Option<Arc<Mutex<TargetChildProcess>>>,
    /// Must be stored here, as it must restart when QEMU process restarts.
    tpm_process: Option<Arc<Mutex<TargetChildProcess>>>,
}

impl QemuBackend {
    /// # Arguments
    /// - `clone` Whether to create a clone of `base_image`, or boot the base itself.
    /// - `graphics` Whether to display graphics.
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

        // if clone, setup qcow2 overlay
        if clone {
            let cloned_image =
                setup_clone(&name, run_id.id, &base_image, paths, &exec_target, serial)?;
        }
    }

    pub fn is_base_mode(&self) -> bool {
        self.temp_image.is_none()
    }
}

struct AdditionalDrives {
    drives: Vec<AdditionalDrive>,
}

/// One extra `-drive`, such as the macOS OpenCore bootloader. Is a throwaway overlay plus the drive
/// spec rewritten so its `file=` points at that overlay, expressed in the exec namespace.
struct AdditionalDrive {
    updated_spec: String,
    temp_path: TargetPath,
}

struct TpmInfo {
    state_dir: TargetPath,
    /// swtpm's control socket inside of `state_dir`. swtpm and QEMU share it.
    socket_path: TargetPath,
}

struct SetupClone {
    image_lock: FileLock,
    temp_image: TargetPath,
    temp_uefi_vars: Option<TargetPath>,
    temp_additional_drives: Option<AdditionalDrives>,
    tpm_info: Option<TpmInfo>,
    serial_log: Option<TargetPath>,
}

/// Setup a qcow2 overlay on top of `base_image`, with a shared flock on the image.
/// Does UEFI vars, extra drives, TPM, living inside `exec_target`'s temp directory.
fn setup_clone(
    name: &str,
    id: u16,
    base_image: &ImageDescription,
    paths: &VciGlobalPaths,
    exec_target: &HostExecTarget,
    serial: bool,
) -> anyhow::Result<SetupClone> {
    let qemu_config = base_image.backend.as_qemu().expect("Expected QEMU config");

    let image_lock = {
        let lock_path = paths
            .temp
            .join(format!("vci_image_{}.lock", base_image.name));
        let flock = FileLock::try_new_shared(&lock_path).map_err(|e| {
            let msg = match e {
                crate::file_lock::FileLockError::OtherProcessBlock(_) => format!(
                    "Image '{}' is currently being modified by `virtci boot`. \
                        Wait for it to finish before starting a new run.",
                    base_image.name
                ),
                crate::file_lock::FileLockError::Other => format!(
                    "Failed to acquire shared lock for image '{}'. \
                        If `virtci boot` is not running, try `virtci cleanup --force`.",
                    base_image.name
                ),
            };
            anyhow::anyhow!(msg)
        })?;
        flock
    };

    // Non-UNC path, but may be a path to be done inside WSL2.
    let source_exec = expand_exec_path_no_unc(&qemu_config.image, exec_target, paths);

    // May be inside WSL2.
    let temp_dir = temp_dir_target(paths, exec_target);
    std::fs::create_dir_all(&temp_dir.path).with_context(|| {
        format!(
            "Failed to create temp directory {}",
            temp_dir.path.display()
        )
    })?;

    let temp_image = temp_dir.join(&format!("vci-{name}-{id:05}.qcow2"));
    create_backing_file(&source_exec, &temp_image.native_path(), exec_target)
        .context("Failed to create the thin qcow2 overlay backing the clone")?;

    let temp_uefi_vars = if let Some(uefi) = &qemu_config.uefi {
        let src = config_path_target_with_unc(&uefi.vars, exec_target, paths);
        let dest = temp_dir.join(&format!("vci-{name}-{id:05}-VARS.fd"));
        let contents = std::fs::read(&src.path)
            .with_context(|| format!("Failed to read UEFI vars {}", src.path.display()))?;
        std::fs::write(&dest.path, &contents)
            .with_context(|| format!("Failed to write UEFI vars to {}", dest.path.display()))?;
        Some(dest)
    } else {
        None
    };

    // Same treatment as `temp_image` earlier in this function.
    let temp_additional_drives = if let Some(specs) = &qemu_config.additional_drives {
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

            let source = expand_exec_path_no_unc(file_path, exec_target, paths);
            let temp_path = temp_dir.join(&format!("vci-{name}-drive{idx}-{id:05}.qcow2"));
            create_backing_file(&source, &temp_path.native_path(), exec_target)
                .with_context(|| format!("Failed to create overlay for additional drive {idx}"))?;

            let updated_spec = spec.replace(
                &format!("file={file_path}"),
                &format!("file={}", temp_path.native_path()),
            );
            drives.push(AdditionalDrive {
                updated_spec,
                temp_path,
            });
        }
        (!drives.is_empty()).then_some(AdditionalDrives { drives })
    } else {
        None
    };

    // On windows, 100% lives inside WSl2.
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

    Ok(SetupClone {
        image_lock,
        temp_image,
        temp_uefi_vars,
        temp_additional_drives,
        tpm_info,
        serial_log,
    })
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
