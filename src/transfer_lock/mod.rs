// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

/*
It seems that when doing very large file transfers using tar-over-ssh,
if two or more VCI processes are doing these big transfers, they'll deadlock each other.

The solution is to just use a lock file (vci-transfer.lock) with kernel file locking.
*/

use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

static LOCK_FILE_PATH: std::sync::LazyLock<PathBuf> =
    std::sync::LazyLock::new(|| std::env::temp_dir().join("vci-transfer.lock"));

extern "C" {
    fn get_process_start_time_native(pid: u32, out_start_time: *mut u64) -> bool;
    fn start_time_to_unix_secs(start_time: u64) -> u64;
    fn format_unix_time_local(unix_secs: u64, buf: *mut u8, buf_size: usize);
}

fn get_process_start_time(pid: u32) -> Option<u64> {
    let mut start_time: u64 = 0;
    let exists = unsafe { get_process_start_time_native(pid, &raw mut start_time) };
    if exists {
        Some(start_time)
    } else {
        None
    }
}

fn format_local_time(unix_secs: u64) -> String {
    let mut buf = [0u8; 32];
    unsafe { format_unix_time_local(unix_secs, buf.as_mut_ptr(), buf.len()) };
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..len]).into_owned()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockMetadata {
    pid: u32,
    process_start_time: u64,
    locked_at: u64,
}

impl LockMetadata {
    fn new() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        LockMetadata {
            pid: std::process::id(),
            process_start_time: get_process_start_time(std::process::id()).unwrap_or(0),
            locked_at: now,
        }
    }
}

impl std::fmt::Display for LockMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let locked_at_str = format_local_time(self.locked_at);
        let proc_start_unix = unsafe { start_time_to_unix_secs(self.process_start_time) };
        let proc_start_str = format_local_time(proc_start_unix);

        write!(
            f,
            "PID: {}, LockedAt: {}, ProcStart: {}",
            self.pid, locked_at_str, proc_start_str
        )
    }
}

#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;

#[cfg(unix)]
type RawHandle = std::ffi::c_int;
#[cfg(windows)]
type RawHandle = isize;

extern "C" {
    fn try_lock_file_exclusive_native(handle: RawHandle) -> bool;
    fn unlock_file_native(handle: RawHandle);
}

pub struct TransferLock {
    file: File,
}

pub enum TransferLockError {
    OtherProcessBlock(LockMetadata),
    Other,
}

impl TransferLock {
    pub fn try_new() -> Result<Self, TransferLockError> {
        let metadata = LockMetadata::new();
        let json = serde_json::to_string_pretty(&metadata).map_err(|_| TransferLockError::Other)?;

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&*LOCK_FILE_PATH)
            .map_err(|_| TransferLockError::Other)?;

        #[cfg(unix)]
        {
            if let Ok(perms) = file.metadata().map(|m| m.permissions()) {
                let mut perms = perms;
                perms.set_mode(0o600);
                let _ = std::fs::set_permissions(&*LOCK_FILE_PATH, perms);
            }
        }

        let handle = Self::get_raw_handle(&file);
        let locked = unsafe { try_lock_file_exclusive_native(handle) };

        if locked {
            file.set_len(0).map_err(|_| TransferLockError::Other)?;
            file.seek(SeekFrom::Start(0))
                .map_err(|_| TransferLockError::Other)?;
            file.write_all(json.as_bytes())
                .map_err(|_| TransferLockError::Other)?;
            file.flush().map_err(|_| TransferLockError::Other)?;

            Ok(TransferLock { file })
        } else {
            let mut contents = String::new();
            file.seek(SeekFrom::Start(0)).ok();
            if file.read_to_string(&mut contents).is_ok() {
                if let Ok(blocking_metadata) = serde_json::from_str::<LockMetadata>(&contents) {
                    return Err(TransferLockError::OtherProcessBlock(blocking_metadata));
                }
            }
            Err(TransferLockError::Other)
        }
    }

    #[cfg(unix)]
    fn get_raw_handle(file: &File) -> RawHandle {
        file.as_raw_fd()
    }

    #[cfg(windows)]
    fn get_raw_handle(file: &File) -> RawHandle {
        file.as_raw_handle() as RawHandle
    }
}

impl Drop for TransferLock {
    fn drop(&mut self) {
        let handle = Self::get_raw_handle(&self.file);
        unsafe { unlock_file_native(handle) };
    }
}
