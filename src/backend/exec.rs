// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

//! A child process like QEMU or swtpm running either on the host or inside WSL2 needs reliable
//! destruction.
//!
//! WSL2 makes it kinda hard. Killing the `wsl.exe` process used to launch the internal process
//! doesn't actually kill the process inside the WSL2 distro.
//!
//! The solution is to put the WSL2 PID inside the port flock.
//! Also have orphan tracking with [`crate::orphan`].

use std::{
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
};

use anyhow::Context;

use crate::vm_image::HostExecTarget;

/// How a spawned child's standard streams are wired.
///
/// Every variant except [`ChildIo::Interactive`] detaches the child from virtci's console on
/// Windows (`CREATE_NO_WINDOW`). This matters because the child can be `wsl.exe`, which
/// reconfigures whatever console it inherits into VT/raw mode which disables automatic
/// carriage-return on newline. This can make the print outputs render like a staircase (bad).
/// A detached child gets its own hidden console instead and leaves virtci's untouched.
#[derive(Clone, Copy)]
pub enum ChildIo<'a> {
    /// Discard stdin/stdout/stderr. For background daemons like swtpm.
    Quiet,
    /// Inherit stdin/stdout (so a guest serial console reaches the terminal) and redirect stderr
    /// to `path`. For interactive `virtci boot` with `-serial stdio`, the child intentionally
    /// shares the host console.
    Interactive(&'a std::path::Path),
    /// Discard stdin/stdout and redirect stderr to `path`, detached from the console. For
    /// non-interactive `virtci run` QEMU: an early launch failure (notably the host-forwarding
    /// bind) can still be read back from the file, without the relay clobbering the console.
    StderrToFile(&'a std::path::Path),
}

/// Either is running on the host system, or inside of WSL2.
pub struct TargetChildProcess {
    process: TargetChild,
}

impl TargetChildProcess {
    /// Spawns `program args...` onto `target`. `marker` is used to identify the process
    /// if it's inside WSL2 to clean it up properly. The caller is responsible for registering it
    /// with [`crate::orphan::OrphanTracker`] so a signal handler can destroy it. `io` selects how
    /// the child's standard streams are wired (see [`ChildIo`]).
    pub fn new(
        target: &HostExecTarget,
        marker: &str,
        program: &str,
        args: &[String],
        io: ChildIo,
    ) -> anyhow::Result<Arc<Mutex<TargetChildProcess>>> {
        let process = TargetChild::spawn(target, marker, program, args, io)?;
        Ok(Arc::new(Mutex::new(TargetChildProcess { process })))
    }

    /// Forcefully stop the process (and, for WSL2, every sibling sharing its run marker).
    /// It's safe if the process already exited.
    pub fn kill(&mut self) {
        self.process.kill();
    }

    /// Block until the process exits on its own.
    pub fn wait(&mut self) {
        self.process.wait();
    }

    pub fn try_wait(&mut self) -> bool {
        self.process.try_wait()
    }

    /// Host PID for an external graceful signal. `None` for WSL2.
    pub fn host_pid(&self) -> Option<u32> {
        self.process.host_pid()
    }

    /// Total CPU time the process has consumed so far, in nanoseconds, or `None` if it can't be
    /// sampled. Works for both a host process (read directly) and a WSL2 process (read from inside
    /// the distro). Used as a boot-liveness signal; only growth between calls is meaningful.
    pub fn cpu_time_ns(&self) -> Option<u64> {
        self.process.cpu_time_ns()
    }
}

impl Drop for TargetChildProcess {
    fn drop(&mut self) {
        self.process.kill();
    }
}

/// Give a child its own hidden console instead of inheriting virtci's, so it cannot reconfigure
/// the host console (see [`ChildIo`]). No-op when `detached` is false or off Windows.
#[cfg_attr(
    not(target_os = "windows"),
    allow(unused_variables, clippy::needless_pass_by_ref_mut)
)]
fn detach_from_console(cmd: &mut Command, detached: bool) {
    #[cfg(target_os = "windows")]
    {
        if detached {
            use std::os::windows::process::CommandExt;
            // CREATE_NO_WINDOW: run the console child with a fresh, invisible console rather than
            // attaching to virtci's, so wsl.exe/QEMU can't flip our console into VT/raw mode.
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
    }
}

enum TargetChild {
    Host(Child),
    #[cfg(target_os = "windows")]
    Wsl(WslProcess),
}

impl TargetChild {
    fn spawn(
        target: &HostExecTarget,
        marker: &str,
        program: &str,
        args: &[String],
        io: ChildIo,
    ) -> anyhow::Result<Self> {
        let detached = !matches!(io, ChildIo::Interactive(_));
        let (stdin, stdout, stderr) = match io {
            ChildIo::Quiet => (Stdio::null(), Stdio::null(), Stdio::null()),
            ChildIo::Interactive(path) => {
                let file = std::fs::File::create(path)
                    .with_context(|| format!("failed to create stderr log {}", path.display()))?;
                (Stdio::inherit(), Stdio::inherit(), Stdio::from(file))
            }
            ChildIo::StderrToFile(path) => {
                let file = std::fs::File::create(path)
                    .with_context(|| format!("failed to create stderr log {}", path.display()))?;
                (Stdio::null(), Stdio::null(), Stdio::from(file))
            }
        };

        match target {
            #[cfg(target_os = "windows")]
            HostExecTarget::WSL2(distro) => {
                let mut cmd = Command::new("wsl");
                cmd.args(["-d", distro.as_str(), "--", program]);
                cmd.args(args);
                cmd.stdin(stdin).stdout(stdout).stderr(stderr);
                detach_from_console(&mut cmd, detached);
                let relay = cmd
                    .spawn()
                    .with_context(|| format!("failed to spawn `{program}` via WSL2"))?;
                Ok(Self::Wsl(WslProcess {
                    relay,
                    wsl_distro: distro.clone(),
                    marker: marker.to_string(),
                }))
            }
            _ => {
                let _ = marker;
                let mut cmd = Command::new(program);
                cmd.args(args).stdin(stdin).stdout(stdout).stderr(stderr);
                detach_from_console(&mut cmd, detached);
                let child = cmd
                    .spawn()
                    .with_context(|| format!("failed to spawn `{program}`"))?;
                Ok(Self::Host(child))
            }
        }
    }

    fn kill(&mut self) {
        match self {
            Self::Host(child) => {
                let _ = child.kill();
                let _ = child.wait();
            }
            #[cfg(target_os = "windows")]
            Self::Wsl(p) => p.kill(),
        }
    }

    fn wait(&mut self) {
        match self {
            Self::Host(child) => {
                let _ = child.wait();
            }
            #[cfg(target_os = "windows")]
            Self::Wsl(p) => {
                let _ = p.relay.wait();
            }
        }
    }

    fn try_wait(&mut self) -> bool {
        match self {
            Self::Host(child) => matches!(child.try_wait(), Ok(Some(_))),
            #[cfg(target_os = "windows")]
            Self::Wsl(p) => matches!(p.relay.try_wait(), Ok(Some(_))),
        }
    }

    #[cfg_attr(not(target_os = "windows"), allow(clippy::unnecessary_wraps))]
    fn host_pid(&self) -> Option<u32> {
        match self {
            Self::Host(child) => Some(child.id()),
            #[cfg(target_os = "windows")]
            Self::Wsl(_) => None,
        }
    }

    fn cpu_time_ns(&self) -> Option<u64> {
        match self {
            Self::Host(child) => host_process_cpu_time_ns(child.id()),
            #[cfg(target_os = "windows")]
            Self::Wsl(p) => p.cpu_time_ns(),
        }
    }
}

/// CPU time of a host (non-WSL2) process, via the per-platform native helper. See
/// `src/file_lock/process_time.c`.
fn host_process_cpu_time_ns(pid: u32) -> Option<u64> {
    let mut cpu_ns: u64 = 0;
    let ok = unsafe { get_process_cpu_time_native(pid, &raw mut cpu_ns) };
    ok.then_some(cpu_ns)
}

extern "C" {
    fn get_process_cpu_time_native(pid: u32, out_cpu_ns: *mut u64) -> bool;
}

/// Sum `(utime + stime)` across the given `/proc/<pid>/stat` line(s), returned as total CPU
/// nanoseconds. Assumes the kernel `USER_HZ` of 100, universal on Linux x86_64/aarch64. `None` if
/// no line parsed. Field 2 (`comm`) can contain spaces and parens, so each line is parsed from
/// after its last `)`: the remaining fields are `state ppid ...`, making `utime`/`stime` (overall
/// fields 14/15) the tokens at index 11/12.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn parse_proc_stat_cpu_ns(stat_lines: &str) -> Option<u64> {
    const USER_HZ: u64 = 100;
    let mut total_ticks: u64 = 0;
    let mut parsed_any = false;
    for line in stat_lines.lines() {
        let Some((_, after_comm)) = line.rsplit_once(')') else {
            continue;
        };
        let fields: Vec<&str> = after_comm.split_whitespace().collect();
        let (Some(utime), Some(stime)) = (
            fields.get(11).and_then(|s| s.parse::<u64>().ok()),
            fields.get(12).and_then(|s| s.parse::<u64>().ok()),
        ) else {
            continue;
        };
        total_ticks += utime + stime;
        parsed_any = true;
    }
    parsed_any.then(|| total_ticks * 1_000_000_000 / USER_HZ)
}

#[cfg(target_os = "windows")]
struct WslProcess {
    /// Host-side `wsl.exe` relay. Killing it alone would orphan the real process.
    relay: Child,
    wsl_distro: String,
    /// Substring of the in-distro command line identifying this run.
    marker: String,
}

#[cfg(target_os = "windows")]
impl WslProcess {
    fn kill(&mut self) {
        reap_wsl2_marker_process(&self.wsl_distro, &self.marker);
        let _ = self.relay.kill();
        let _ = self.relay.wait();
    }

    /// The real QEMU has no host PID (it lives inside the distro), so read its CPU time from the
    /// distro's `/proc`, identifying it by the same run marker used to reap it. `pgrep -f <marker>`
    /// also matches swtpm and the polling shell itself, so the lines are filtered to the
    /// `qemu-system*` process by its `comm`. Shelling out to `wsl.exe` is why the caller samples
    /// this on a slow cadence rather than every poll.
    fn cpu_time_ns(&self) -> Option<u64> {
        let script = "for p in $(pgrep -f -- \"$1\"); do \
               case \"$(cat /proc/$p/comm 2>/dev/null)\" in \
                 qemu-system*) cat /proc/$p/stat 2>/dev/null;; \
               esac; \
             done";
        let mut cmd = Command::new("wsl");
        cmd.args([
            "-d",
            self.wsl_distro.as_str(),
            "--",
            "sh",
            "-c",
            script,
            "sh",
            self.marker.as_str(),
        ]);
        detach_from_console(&mut cmd, true);
        let out = cmd.output().ok()?;
        if !out.status.success() {
            return None;
        }
        parse_proc_stat_cpu_ns(&String::from_utf8_lossy(&out.stdout))
    }
}

/// Force-kill every process inside `distro` whose command line contains `marker`
/// (the run name, such as `vci-<name>-<port>`), killing both the run's QEMU and
/// swtpm. Used by `Drop`/the signal handler (via [`WslProcess::kill`]) AND by the
/// startup `cleanup` reaper for processes orphaned by an abrupt prior death (like SIGKILL).
/// Immune to PID recycling.
#[cfg(target_os = "windows")]
pub fn reap_wsl2_marker_process(distro: &str, marker: &str) {
    let _ = Command::new("wsl")
        .args(["-d", distro, "--", "pkill", "-9", "-f", marker])
        .status();
}

#[cfg(test)]
mod tests {
    use super::*;

    // A real qemu /proc/<pid>/stat line: comm "(qemu-system-aar)" with the parens that force
    // last-')' parsing; utime=field 14 = 1234, stime=field 15 = 567.
    const QEMU_STAT: &str = "4242 (qemu-system-aar) S 1 4242 4242 0 -1 4194560 \
        9001 0 13 0 1234 567 0 0 20 0 7 0 9999999 5000000000 12345 \
        18446744073709551615 1 1 0 0 0 0 0 4096 17091";

    #[test]
    fn parses_utime_plus_stime_at_100hz() {
        // (1234 + 567) ticks / 100 Hz = 18.01 s = 18_010_000_000 ns.
        assert_eq!(parse_proc_stat_cpu_ns(QEMU_STAT), Some(18_010_000_000));
    }

    #[test]
    fn sums_multiple_processes() {
        let two = format!("{QEMU_STAT}\n{QEMU_STAT}");
        assert_eq!(parse_proc_stat_cpu_ns(&two), Some(36_020_000_000));
    }

    #[test]
    fn comm_with_spaces_and_parens_is_handled() {
        // comm itself contains a ')' and a space; parsing must key off the *last* ')'.
        let line = "10 (weird ) name) R 1 10 10 0 -1 0 0 0 0 0 100 200 \
            0 0 20 0 1 0 0 0 0";
        // (100 + 200)/100 = 3 s.
        assert_eq!(parse_proc_stat_cpu_ns(line), Some(3_000_000_000));
    }

    #[test]
    fn empty_or_garbage_is_none() {
        assert_eq!(parse_proc_stat_cpu_ns(""), None);
        assert_eq!(parse_proc_stat_cpu_ns("no parens, too few fields"), None);
    }

    #[test]
    fn host_cpu_time_reads_own_process_and_advances() {
        let pid = std::process::id();
        let before = host_process_cpu_time_ns(pid).expect("should read own CPU time");
        let mut acc = 0u64;
        for i in 0..20_000_000u64 {
            acc = acc.wrapping_add(i);
        }
        std::hint::black_box(acc);
        let after = host_process_cpu_time_ns(pid).expect("should read own CPU time");
        assert!(
            after >= before,
            "CPU time must be monotonic: {before} -> {after}"
        );
    }

    #[test]
    fn host_cpu_time_for_bogus_pid_is_none() {
        assert_eq!(host_process_cpu_time_ns(u32::MAX), None);
    }
}
