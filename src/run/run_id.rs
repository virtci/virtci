// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use crate::{file_lock::FileLock, global_paths::VciGlobalPaths};
use std::io::Write;

/// A multi-process-wide unique run identifier, reserved by holding an exclusive flock on
/// `vci-active-{id:05}.lock` in the host's temp directory, for example, ``vci-active-00001.lock`.
///
/// Stable identity for a single VM run, or VM boot. This is decoupled from SSH forwarding
/// port entirely, because it CAN change across restarts.
///
/// The id is always done zero-padded to 5 digits so that the run marker `vci-{name}-{id:05}`
/// of one run is never a substring of another's.
pub struct ReservedRunId {
    pub id: u16,
    name: String,
    flock: Option<FileLock>,
}

impl ReservedRunId {
    pub fn new(paths: &VciGlobalPaths) -> anyhow::Result<ReservedRunId> {
        for id in 1u16..u16::MAX {
            let name = format!("vci-active-{id:05}.lock");
            let file_path = paths.temp.join(&name);
            if let Ok(flock) = FileLock::try_new(&file_path) {
                return Ok(ReservedRunId {
                    id,
                    name,
                    flock: Some(flock),
                });
            }
        }

        anyhow::bail!("Exhaused all {} VirtCI run ids", u16::MAX);
    }

    pub fn flock_mut(&mut self) -> &mut FileLock {
        self.flock.as_mut().expect("run id flock present")
    }
}

impl Drop for ReservedRunId {
    fn drop(&mut self) {
        if let Some(flock) = self.flock.take() {
            let path = flock.get_path().clone();
            drop(flock);
            let _ = std::fs::remove_file(&path);
        }
    }
}
