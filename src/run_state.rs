// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use crate::file_lock::{FileLock, FileLockError, LockMetadata};
use crate::{cli, VCI_TEMP_PATH};

/// Returns metadata for all lock files currently held by a live process
/// that have run info (run_name + ssh target). Doesn't do stale ones.
pub fn list_active_runs() -> Vec<LockMetadata> {
    let temp_dir = &*VCI_TEMP_PATH;
    let mut active = Vec::new();

    let entries = match std::fs::read_dir(temp_dir) {
        Ok(e) => e,
        Err(_) => return active,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };

        if !name.starts_with("vci-") || !name.ends_with(".lock") {
            continue;
        }

        // Skip TPM lock files
        if name.contains("-tpm") {
            continue;
        }

        match FileLock::try_lock_exist(&path) {
            Ok(_lock) => {
                // Lock acquired — process is dead, not active
            }
            Err(FileLockError::OtherProcessBlock(meta)) => {
                // Lock held — process is alive
                if meta.run_name.is_some() && meta.ssh.is_some() {
                    active.push(meta);
                }
            }
            Err(FileLockError::Other) => {}
        }
    }

    active
}

pub fn find_active_run(name: &str) -> Option<LockMetadata> {
    let runs = list_active_runs();

    if let Some(run) = runs.iter().find(|r| r.run_name.as_deref() == Some(name)) {
        return Some(run.clone());
    }

    None
}

pub fn run_active() {
    use colored::Colorize;

    let runs = list_active_runs();
    if runs.is_empty() {
        println!("{}", "No active VirtCI jobs".dimmed());
        return;
    }

    println!("{:<30} {:<30}", "NAME", "SSH");
    for run in &runs {
        let ssh = run.ssh.as_ref().unwrap();
        let ssh_str = format!("{}@{}:{}", ssh.cred.user, ssh.ip, ssh.port);
        println!(
            "{:<30} {:<30}",
            run.run_name.as_deref().unwrap_or("?"),
            ssh_str,
        );
    }
}

pub fn run_shell(args: cli::ShellArgs) {
    let run = find_active_run(&args.name);
    match run {
        None => {
            eprintln!("No active job found with name '{}'", args.name);
            eprintln!("Run 'virtci active' to see all running jobs");
            std::process::exit(1);
        }
        Some(meta) => {
            let ssh = meta.ssh.as_ref().unwrap();

            let mut cmd = std::process::Command::new("ssh");
            cmd.arg("-o")
                .arg("StrictHostKeyChecking=no")
                .arg("-o")
                .arg("UserKnownHostsFile=/dev/null")
                .arg("-p")
                .arg(ssh.port.to_string());

            if let Some(ref key) = ssh.cred.key {
                cmd.arg("-i").arg(crate::backend::expand_path(key));
            }

            cmd.arg(format!("{}@{}", ssh.cred.user, ssh.ip));

            if ssh.cred.key.is_none() {
                if let Some(ref pass) = ssh.cred.pass {
                    eprintln!("Password: {pass}");
                }
            }

            let status = cmd.status();
            match status {
                Ok(s) => std::process::exit(s.code().unwrap_or(1)),
                Err(e) => {
                    eprintln!("Failed to execute ssh: {e}");
                    std::process::exit(1);
                }
            }
        }
    }
}
