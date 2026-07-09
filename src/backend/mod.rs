// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::path::{Path, PathBuf};

pub mod exec;
pub mod qemu;
pub mod tart;

use crate::{
    run::cache::metadata::Fingerprint,
    vm_image::{GuestOs, SshTarget},
};

#[derive(Debug, Clone, Default)]
pub struct VmStartConfig {
    /// `None` leaves the backend's current offline state unchanged. The first
    /// boot defaults to online (network enabled).
    pub offline: Option<bool>,
    /// `None` leaves the backend's current cpu count unchanged.
    pub cpus: Option<u32>,
    /// `None` leaves the backend's current memory unchanged.
    pub memory_mb: Option<u64>,
}

pub trait VmBackend {
    fn start_vm(&mut self, cfg: VmStartConfig) -> anyhow::Result<()>;

    fn is_offline(&self) -> bool {
        false
    }

    fn stop_vm(&mut self);

    fn ssh_target(&self) -> SshTarget;

    fn os(&self) -> GuestOs;

    /// Terrible required workaround for tart, without having to run tart as root.
    /// Tart requires root for Softnet-based isolation.
    fn offline_enforce_cmd(&self) -> Option<&'static str> {
        None
    }

    fn run_name(&self) -> String;

    /// Some(String) if the VM processes exited with stderr.
    /// Polled while waiting for SSH. None means alive or unknown.
    fn vm_exit_error(&mut self) -> Option<String> {
        None
    }

    /// With `virtci boot` the user needs to shut down the VM internally.
    fn wait_for_exit(&mut self) {}

    fn serial_log_path(&self) -> Option<&Path> {
        None
    }

    /// CPU time used by the VM process, in nanoseconds, or `None` if it cannot be queried.
    fn vm_cpu_time_ns(&self) -> Option<u64> {
        None
    }

    /// The path of the primary disk image. Used to see if there's growth, meaning something is
    /// probably happening.
    fn disk_image_path(&self) -> Option<&Path> {
        None
    }

    /// Count of IO operations (reads and writes across all drives) that the VM has done. Very
    /// useful to actually track progress.
    fn vm_disk_io_ops(&self) -> Option<u64> {
        None
    }

    /// Whether this run is running from a workflow cache.
    fn is_cached_run(&self) -> bool;

    /// Whether this run will produce a run cache if it succeeds and has a usable namespace.
    /// This also means the run will need to gracefully shutdown, rather than SIGKILLing which
    /// would normally corrupt it.
    fn produces_cache(&self) -> bool {
        false
    }

    /// Whether the VM process has already exited.
    fn vm_has_exited(&mut self) -> bool {
        self.vm_exit_error().is_some()
    }

    /// Commit this run's VM files into its cache slot so a future run can reuse them.
    /// Fingerprint is captured on the host-side notably, not inside the VM.
    /// No-op if no cache should be produced by this run.
    fn cache_run_files(
        &self,
        fingerprint: &Fingerprint,
        ttl_secs: Option<u64>,
    ) -> anyhow::Result<()>;
}

pub fn expand_path(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        // Unix: $HOME, Windows: $USERPROFILE
        if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
            return PathBuf::from(home).join(path.strip_prefix("~/").unwrap());
        }
    }
    PathBuf::from(path)
}

pub fn expand_path_in_string(s: &str) -> String {
    if let Some(idx) = s.find("~/")
        && let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE"))
    {
        let home_str = home.to_string_lossy();
        let before = &s[..idx];
        let after = &s[idx + 2..];
        return format!(
            "{}{}{}{}",
            before,
            home_str,
            std::path::MAIN_SEPARATOR,
            after
        );
    }
    s.to_string()
}
