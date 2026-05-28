// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::path::PathBuf;

use crate::vm_image::{HostExecTarget, ImageDescription};

pub struct QemuBackend {
    pub name: String,
    pub base_image: ImageDescription,
    pub cpus: u32,
    pub memory_mb: u64,
    pub offline: bool,
    pub inside_vm_port: u16,
    pub graphics: bool,
    pub serial_log: Option<PathBuf>,
    pub exec_target: HostExecTarget,
}
