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

/// Either is running on the host system, or inside of WSL2.
pub struct TargetChildProcess {
    process: TargetChild,
}

impl TargetChildProcess {
    /// Spawns `program args...` onto `target`. `marker` is used to identify the process
    /// if it's inside WSL2 to clean it up properly. The caller is responsible for registering it
    /// with [`crate::orphan::OrphanTracker`] so a signal handler can destroy it.
    /// `quiet` routes stdout/stderr to null (swtpm), otherwise they are inherited
    /// (QEMU, so a serial console reaches the terminal).
    pub fn new(
        target: &HostExecTarget,
        marker: &str,
        program: &str,
        args: &[String],
        quiet: bool,
    ) -> anyhow::Result<Arc<Mutex<TargetChildProcess>>> {
        let process = TargetChild::spawn(target, marker, program, args, quiet)?;
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
}

impl Drop for TargetChildProcess {
    fn drop(&mut self) {
        self.process.kill();
    }
}

enum TargetChild {
    Host(Child),
    #[cfg(target_os = "windows")]
    WSL(WslProcess),
}

impl TargetChild {
    fn spawn(
        target: &HostExecTarget,
        marker: &str,
        program: &str,
        args: &[String],
        quiet: bool,
    ) -> anyhow::Result<Self> {
        let (out, err) = if quiet {
            (Stdio::null(), Stdio::null())
        } else {
            (Stdio::inherit(), Stdio::inherit())
        };

        match target {
            #[cfg(target_os = "windows")]
            HostExecTarget::WSL2(distro) => {
                let mut cmd = Command::new("wsl");
                cmd.args(["-d", distro.as_str(), "--", program]);
                cmd.args(args);
                cmd.stdout(out).stderr(err);
                let relay = cmd
                    .spawn()
                    .with_context(|| format!("failed to spawn `{program}` via WSL2"))?;
                Ok(Self::WSL(WslProcess {
                    relay,
                    wsl_distro: distro.clone(),
                    marker: marker.to_string(),
                }))
            }
            _ => {
                let _ = marker;
                let mut cmd = Command::new(program);
                cmd.args(args).stdout(out).stderr(err);
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
            Self::WSL(p) => p.kill(),
        }
    }

    fn wait(&mut self) {
        match self {
            Self::Host(child) => {
                let _ = child.wait();
            }
            #[cfg(target_os = "windows")]
            Self::WSL(p) => {
                let _ = p.relay.wait();
            }
        }
    }

    fn try_wait(&mut self) -> bool {
        match self {
            Self::Host(child) => matches!(child.try_wait(), Ok(Some(_))),
            #[cfg(target_os = "windows")]
            Self::WSL(p) => matches!(p.relay.try_wait(), Ok(Some(_))),
        }
    }

    fn host_pid(&self) -> Option<u32> {
        match self {
            Self::Host(child) => Some(child.id()),
            #[cfg(target_os = "windows")]
            Self::WSL(_) => None,
        }
    }
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
