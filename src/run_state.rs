use crate::file_lock::{FileLock, FileLockError, LockMetadata};
use crate::{VCI_TEMP_PATH, cli};

/// Returns metadata for all lock files currently held by a live process
/// that have SSH run info (job_name + ssh target).
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
                if meta.job_name.is_some() && meta.ssh.is_some() {
                    active.push(meta);
                }
            }
            Err(FileLockError::Other) => {}
        }
    }

    active
}

/// Find an active run by job name.
pub fn find_active_run(name: &str) -> Option<LockMetadata> {
    let runs = list_active_runs();

    // Exact match on job_name
    if let Some(run) = runs.iter().find(|r| r.job_name.as_deref() == Some(name)) {
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

    println!("{:<20} {:<30}", "NAME", "SSH");
    for run in &runs {
        let ssh = run.ssh.as_ref().unwrap();
        let ssh_str = format!("{}@{}:{}", ssh.cred.user, ssh.ip, ssh.port);
        println!(
            "{:<20} {:<30}",
            run.job_name.as_deref().unwrap_or("?"),
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
            // TODO: exec_interactive_ssh
            println!(
                "ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -p {} {}@{}",
                ssh.port, ssh.cred.user, ssh.ip
            );
            if let Some(ref pass) = ssh.cred.pass {
                println!("Password: {}", pass);
            }
        }
    }
}
