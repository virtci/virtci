// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

//! Registry of every [`TargetChildProcess`] spawned during a run, so they can be
//! destroyed on the way out even when `Drop` does not run.
//!
//! A normally-dropped child kills itself through its own `Drop`. But
//! `std::process::exit` — which the signal handler calls on CTRL+C / SIGTERM /
//! console-close — skips every `Drop`, which would orphan in-distro WSL2
//! processes. The signal handler instead calls [`OrphanTracker::kill_all`] to
//! destroy them explicitly first.
//!
//! This is deliberately NOT a global. Construct one [`OrphanTracker`] per run and
//! inject it where processes are spawned and into the signal handler (it is
//! cheaply `Clone`, and every clone shares the same registry). That keeps the
//! behaviour testable in isolation — a test owns its own tracker.
//!
//! In-process only: abrupt death (e.g. SIGKILL) runs no code at all and is reaped
//! on the next run by the flock-driven cleanup in [`crate::backend::qemu`].

use std::sync::{Arc, Mutex, Weak};

use crate::backend::exec::TargetChildProcess;

/// A cloneable handle to a shared set of tracked child processes.
#[derive(Clone, Default)]
pub struct OrphanTracker {
    inner: Arc<Mutex<OrphanTrackerImpl>>,
}

impl OrphanTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Track `child`. Only a [`Weak`] reference is kept, so the tracker never
    /// keeps a child alive. The owner holds the sole strong `Arc`, and dropping
    /// it still runs the child's `Drop`.
    pub fn add_child_process(&self, child: &Arc<Mutex<TargetChildProcess>>) {
        let mut lock = self.inner.lock().expect("Failed to lock OrphanTracker");
        // Drop entries whose owner has already been destroyed.
        lock.child_processes.retain(|weak| weak.strong_count() > 0);
        lock.child_processes.push(Arc::downgrade(child));
    }

    /// Kill every still-alive tracked child.
    pub fn kill_all(&self) {
        let alive: Vec<Arc<Mutex<TargetChildProcess>>> = {
            let lock = self.inner.lock().expect("Failed to lock OrphanTracker");
            lock.child_processes
                .iter()
                .filter_map(Weak::upgrade)
                .collect()
        };

        for child in alive {
            if let Ok(mut child) = child.lock() {
                child.kill();
            }
        }
    }
}

#[derive(Default)]
struct OrphanTrackerImpl {
    child_processes: Vec<Weak<Mutex<TargetChildProcess>>>,
}
