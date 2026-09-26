// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

//! What gets reported when a VM fails to boot: how fast the guest clock ran, where the vCPUs were,
//! what the serial console says went wrong, and whether the disk is intact.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::backend::{VcpuState, VmBackend};

const DOC: &str = "See CHANGELOG.md for known issues";

/// VM kernel time (printk timestamps on the serial console) against host wall time over a boot.
/// Tracked while the serial log streams in, since a timestamp read after the fact can't say when
/// it was printed.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct GuestClock {
    first: Option<ClockPoint>,
    last: Option<ClockPoint>,
}

#[derive(Debug, Clone, Copy)]
struct ClockPoint {
    guest_secs: f64,
    wall: Duration,
}

impl GuestClock {
    const MIN_WINDOW: Duration = Duration::from_secs(20);

    /// Record that the newest kernel timestamp was `guest_secs` when seen at `wall` into the boot.
    pub(super) fn observe(&mut self, guest_secs: f64, wall: Duration) {
        let point = ClockPoint { guest_secs, wall };
        self.first.get_or_insert(point);
        self.last = Some(point);
    }

    /// Guest seconds and wall time that passed between the first and latest observation, once the
    /// window is long enough to be significant.
    fn window(&self) -> Option<(f64, Duration)> {
        let (first, last) = (self.first?, self.last?);
        let wall = last.wall.checked_sub(first.wall)?;
        (wall >= Self::MIN_WINDOW).then_some((last.guest_secs - first.guest_secs, wall))
    }
}

impl fmt::Display for GuestClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const SLOW: f64 = 0.5;

        let Some(last) = self.last else {
            return write!(f, "no kernel timestamps seen on the serial console");
        };
        let Some((guest_secs, wall)) = self.window() else {
            return write!(
                f,
                "last kernel timestamp {:.1}s, seen {}s into the boot (too short a window to \
                 measure the guest clock rate)",
                last.guest_secs,
                last.wall.as_secs()
            );
        };
        let rate = guest_secs / wall.as_secs_f64();
        write!(
            f,
            "ran at {:.0}% of real time ({guest_secs:.1}s of guest kernel time over {}s of wall \
             time)",
            rate * 100.0,
            wall.as_secs()
        )?;
        if rate < SLOW {
            write!(
                f,
                ". The VM is running far slower than real time, typically slow TCG emulation, \
                 so the boot may simply need longer than the timeout allows"
            )?;
        }
        Ok(())
    }
}

/// The `[  123.456789]` printk timestamp a kernel console line starts with, in seconds.
pub(super) fn kernel_timestamp(line: &str) -> Option<f64> {
    let (stamp, _) = line.trim_start().strip_prefix('[')?.split_once(']')?;
    let stamp = stamp.trim();
    // systemd's `[  OK  ]` and spinner `[ *** ]` prefixes share the bracket shape.
    if !stamp.contains('.') {
        return None;
    }
    stamp.parse().ok()
}

/// A known failure recognized from the serial console.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SerialDiagnosis {
    KernelPanic,
    FsckFailure,
    EmergencyMode,
    RescueMode,
}

impl SerialDiagnosis {
    /// Only the end of the log is scanned, so an early, recovered-from failure doesn't match.
    const SCAN_BYTES: usize = 64 * 1024;

    fn detect(log: &[u8]) -> Option<Self> {
        let text = String::from_utf8_lossy(&log[log.len().saturating_sub(Self::SCAN_BYTES)..]);
        let any = |needles: &[&str]| needles.iter().any(|n| text.contains(n));

        if any(&["Kernel panic"]) {
            Some(Self::KernelPanic)
        } else if any(&[
            "UNEXPECTED INCONSISTENCY",
            "RUN fsck MANUALLY",
            "fsck failed",
        ]) {
            Some(Self::FsckFailure)
        } else if any(&["emergency.target", "emergency mode", "system maintenance"]) {
            Some(Self::EmergencyMode)
        } else if any(&["rescue.target", "rescue mode"]) {
            Some(Self::RescueMode)
        } else {
            None
        }
    }
}

impl fmt::Display for SerialDiagnosis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KernelPanic => write!(
                f,
                "VM KERNEL PANIC in the serial log so the kernel halted, meaning SSH will never \
                 come up. {DOC}"
            ),
            Self::FsckFailure => write!(
                f,
                "filesystem check (fsck) reported problems on boot so the VM disk may be corrupt. \
                 Check it with `qemu-img check`. {DOC}"
            ),
            Self::EmergencyMode => write!(
                f,
                "VM booted into systemd emergency mode. A boot unit failed, so sshd never starts \
                 and the boot cannot complete (the watcher correctly sees no progress). See the \
                 guest boot-failure diagnostics below (failed units + journal) for which unit \
                 tripped it. A failed/slow mount, device timeout, or a corrupt disk can all cause \
                 it. Under slow TCG emulation, systemd's 90s device timeouts can expire before \
                 udev finishes, which also could happen here. {DOC}"
            ),
            Self::RescueMode => write!(
                f,
                "VM booted into systemd rescue mode. Boot did not reach multi-user, so sshd is not \
                 running. {DOC}"
            ),
        }
    }
}

/// Everything read from the serial log, from a single read of it.
struct SerialFindings {
    diagnosis: Option<SerialDiagnosis>,
    /// Deduplicated systemd unit failure lines, newest last.
    unit_failures: Vec<String>,
    /// The VM's own `=== VIRTCI BOOT DIAGNOSTICS` dump, if it wrote one.
    guest_diagnostics: Option<String>,
    tail: String,
    total_bytes: usize,
}

impl SerialFindings {
    const TAIL_BYTES: usize = 4096;
    const MAX_UNIT_FAILURES: usize = 40;

    fn read(path: &Path) -> Option<Self> {
        let log = std::fs::read(path).ok()?;
        let text = String::from_utf8_lossy(&log);
        let tail = String::from_utf8_lossy(&log[log.len().saturating_sub(Self::TAIL_BYTES)..]);
        Some(Self {
            diagnosis: SerialDiagnosis::detect(&log),
            unit_failures: unit_failures(&text),
            guest_diagnostics: guest_diagnostics(&text),
            tail: tail.trim_end().to_string(),
            total_bytes: log.len(),
        })
    }
}

fn unit_failures(text: &str) -> Vec<String> {
    const MARKERS: &[&str] = &[
        "Dependency failed for",
        "Failed to start",
        "Failed to mount",
        "Timed out waiting for",
        "FAILED]",
        "start request repeated too quickly",
        "UNEXPECTED INCONSISTENCY",
        "Kernel panic",
    ];

    let mut lines: Vec<String> = Vec::new();
    for line in text.lines() {
        let l = line.trim();
        if !l.is_empty() && MARKERS.iter().any(|m| l.contains(m)) && !lines.iter().any(|x| x == l) {
            lines.push(l.to_string());
        }
    }
    let from = lines
        .len()
        .saturating_sub(SerialFindings::MAX_UNIT_FAILURES);
    lines.split_off(from)
}

fn guest_diagnostics(text: &str) -> Option<String> {
    const START: &str = "=== VIRTCI BOOT DIAGNOSTICS";
    const END: &str = "=== END VIRTCI BOOT DIAGNOSTICS";

    let start = text.rfind(START)?;
    let end = match text[start..].find(END) {
        Some(rel) => {
            let marker = start + rel;
            text[marker..]
                .find('\n')
                .map_or(text.len(), |nl| marker + nl)
        }
        None => text.len(),
    };
    Some(text[start..end].trim_end().to_string())
}

/// Copy the serial log next to itself as `*.failed.log`, which run cleanup does not delete, so it
/// can be collected after the run.
fn save_serial_log(path: &Path) -> Option<PathBuf> {
    let saved = path.with_extension("failed.log");
    std::fs::copy(path, &saved).ok()?;
    Some(saved)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum VmLiveness {
    Running,
    Exited,
}

enum DiskCheck {
    Report(String),
    /// Couldn't check it here, so tell the user how to.
    Suggest(PathBuf),
}

/// Everything gathered about a failed boot, rendered into the error message.
pub(super) struct BootFailureReport {
    guest_clock: GuestClock,
    vcpu_samples: Option<Vec<Vec<VcpuState>>>,
    saved_serial: Option<PathBuf>,
    serial: Option<SerialFindings>,
    disk: Option<DiskCheck>,
}

impl BootFailureReport {
    /// Gather the report. Blocks for a few seconds when vCPUs get sampled.
    pub(super) fn collect(
        backend: &dyn VmBackend,
        liveness: VmLiveness,
        guest_clock: GuestClock,
    ) -> Self {
        let serial_path = backend.serial_log_path();
        let disk = match backend.disk_integrity_report() {
            Some(report) => Some(DiskCheck::Report(report)),
            None => backend
                .disk_image_path()
                .map(|p| DiskCheck::Suggest(p.to_path_buf())),
        };
        Self {
            guest_clock,
            vcpu_samples: match liveness {
                VmLiveness::Running => backend.vcpu_samples(),
                VmLiveness::Exited => None,
            },
            saved_serial: serial_path.and_then(save_serial_log),
            serial: serial_path.and_then(SerialFindings::read),
            disk,
        }
    }
}

impl fmt::Display for BootFailureReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.serial.is_some() {
            write!(f, "\n[VirtCI] guest clock {}", self.guest_clock)?;
        }
        if let Some(samples) = &self.vcpu_samples {
            write!(
                f,
                "\n[VirtCI] vCPU samples, 1s apart (same PC every sample = stuck, varied = running):"
            )?;
            for (i, sample) in samples.iter().enumerate() {
                write!(f, "\n  sample {i}:")?;
                for vcpu in sample {
                    write!(f, " cpu{}=0x{:x}", vcpu.cpu, vcpu.pc)?;
                    if vcpu.halted == Some(true) {
                        write!(f, "(halted)")?;
                    }
                }
            }
        }
        if let Some(saved) = &self.saved_serial {
            write!(f, "\n[VirtCI] full serial log saved to {}", saved.display())?;
        }
        if let Some(serial) = &self.serial {
            if let Some(diagnosis) = serial.diagnosis {
                write!(f, "\n[VirtCI] DIAGNOSIS: {diagnosis}")?;
            }
            if !serial.unit_failures.is_empty() {
                write!(
                    f,
                    "\n[VirtCI] unit failures found in the serial log (these pull in emergency \
                     mode):\n{}",
                    serial.unit_failures.join("\n")
                )?;
            }
            if let Some(block) = &serial.guest_diagnostics {
                write!(
                    f,
                    "\n[VirtCI] guest boot-failure diagnostics (dumped to serial by the guest):\n\
                     {block}"
                )?;
            }
        }
        match &self.disk {
            Some(DiskCheck::Report(report)) => {
                write!(f, "\n[VirtCI] qemu-img check of the disk:\n{report}")?;
            }
            Some(DiskCheck::Suggest(disk)) => write!(
                f,
                "\n[VirtCI] to rule out disk corruption, run: `qemu-img check \"{}\"` if you can \
                 (you may want to use virtci shell)",
                disk.display()
            )?,
            None => {}
        }
        match &self.serial {
            Some(serial) if serial.total_bytes == 0 => write!(
                f,
                "\n\n(serial log is empty — the guest produced no console output)"
            ),
            Some(serial) => write!(
                f,
                "\n[VirtCI] last {} bytes of serial log:\n{}",
                serial.total_bytes.min(SerialFindings::TAIL_BYTES),
                serial.tail
            ),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_timestamps_skip_systemd_brackets() {
        assert_eq!(
            kernel_timestamp("[   12.442049] dracut-cmdline[132]: hi"),
            Some(12.442_049)
        );
        assert_eq!(
            kernel_timestamp("  [    0.000000] Linux version"),
            Some(0.0)
        );
        assert_eq!(
            kernel_timestamp("[  OK  ] Reached target network.target"),
            None
        );
        assert_eq!(
            kernel_timestamp("[ ***  ] Job dracut-initqueue.service/start"),
            None
        );
        assert_eq!(kernel_timestamp("no bracket"), None);
    }

    #[test]
    fn guest_clock_rate_needs_a_window() {
        let mut clock = GuestClock::default();
        assert_eq!(clock.window(), None);
        clock.observe(1.0, Duration::from_secs(2));
        clock.observe(2.0, Duration::from_secs(10));
        assert_eq!(clock.window(), None);
        clock.observe(9.0, Duration::from_secs(82));
        assert_eq!(clock.window(), Some((8.0, Duration::from_secs(80))));
        assert!(clock.to_string().contains("10% of real time"));
        assert!(clock.to_string().contains("far slower than real time"));
    }

    #[test]
    fn real_time_guest_clock_has_no_slowness_hint() {
        let mut clock = GuestClock::default();
        clock.observe(3.0, Duration::from_secs(5));
        clock.observe(103.0, Duration::from_secs(105));
        assert!(clock.to_string().contains("100% of real time"));
        assert!(!clock.to_string().contains("far slower"));
    }

    #[test]
    fn detects_the_most_severe_serial_failure() {
        let log = b"You are in emergency mode.\n[  123.4] Kernel panic - not syncing";
        assert_eq!(
            SerialDiagnosis::detect(log),
            Some(SerialDiagnosis::KernelPanic)
        );
        assert_eq!(
            SerialDiagnosis::detect(b"Press Enter for system maintenance"),
            Some(SerialDiagnosis::EmergencyMode)
        );
        assert_eq!(SerialDiagnosis::detect(b"all fine"), None);
    }

    #[test]
    fn unit_failures_are_deduplicated_in_order() {
        let text = "[FAILED] Failed to start a.service\nok\n\
                    [DEPEND] Dependency failed for b.mount\n[FAILED] Failed to start a.service\n";
        assert_eq!(
            unit_failures(text),
            vec![
                "[FAILED] Failed to start a.service".to_string(),
                "[DEPEND] Dependency failed for b.mount".to_string(),
            ]
        );
    }

    #[test]
    fn guest_diagnostics_block_is_extracted() {
        let text = "noise\n=== VIRTCI BOOT DIAGNOSTICS rescue\nunit x failed\n\
                    === END VIRTCI BOOT DIAGNOSTICS\ntrailing\n";
        assert_eq!(
            guest_diagnostics(text).as_deref(),
            Some(
                "=== VIRTCI BOOT DIAGNOSTICS rescue\nunit x failed\n=== END VIRTCI BOOT DIAGNOSTICS"
            )
        );
    }
}
