// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

use crate::{
    backend::{exec::TargetChildProcess, qemu::PortFlock, VmStartConfig},
    file_lock::FileLock,
    global_paths::{TargetPath, VciGlobalPaths},
    orphan::OrphanTracker,
    vm_image::{HostExecTarget, ImageDescription},
};

use anyhow::Context;

pub struct QemuBackend {
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
    host_port: PortFlock,
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
    pub fn new(
        name: String,
        base_image: ImageDescription,
        paths: &VciGlobalPaths,
        clone: bool,
        orphans: OrphanTracker,
    ) -> anyhow::Result<Self> {
    }

    pub fn is_base_mode(&self) -> bool {
        self.temp_image.is_none()
    }
}

struct AdditionalDrives {
    updated_spec: String,
    temp_path: TargetPath,
}

struct TpmInfo {
    state_dir: TargetPath,
    socket_path: TargetPath,
    flock: FileLock,
}
