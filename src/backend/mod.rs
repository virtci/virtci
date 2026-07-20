// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::path::{Path, PathBuf};

pub mod exec;
pub mod gpt_recovery;
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
    /// Requested disk size in whole gigabytes. `None` leaves the disk unchanged. Grow only.
    pub disk_gb: Option<u64>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DiskIoStats {
    pub rd_ops: u64,
    pub rd_time_ns: u64,
    pub wr_ops: u64,
    pub wr_time_ns: u64,
}

impl DiskIoStats {
    /// Reads and writes combined.
    pub fn total_ops(&self) -> u64 {
        self.rd_ops.saturating_add(self.wr_ops)
    }

    /// Average microseconds per operation between two samples.
    fn latency_us(ops: u64, time_ns: u64) -> Option<u64> {
        (ops > 0).then(|| time_ns / ops / 1_000)
    }

    /// Average read latency, in microseconds per op, since `prev`.
    pub fn rd_latency_us_since(&self, prev: &Self) -> Option<u64> {
        Self::latency_us(
            self.rd_ops.saturating_sub(prev.rd_ops),
            self.rd_time_ns.saturating_sub(prev.rd_time_ns),
        )
    }

    /// Average write latency, in microseconds per op, since `prev`.
    pub fn wr_latency_us_since(&self, prev: &Self) -> Option<u64> {
        Self::latency_us(
            self.wr_ops.saturating_sub(prev.wr_ops),
            self.wr_time_ns.saturating_sub(prev.wr_time_ns),
        )
    }
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

    /// Block-layer IO counters (reads and writes across all drives) that the VM has done. Very
    /// useful to actually track progress, and the latency it carries tells host IO stalls apart
    /// from the guest simply being slow.
    fn vm_disk_io_stats(&self) -> Option<DiskIoStats> {
        None
    }

    /// Give it an honest effort to get a report of disk integrity to detect boot failure.
    fn disk_integrity_report(&self) -> Option<String> {
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
