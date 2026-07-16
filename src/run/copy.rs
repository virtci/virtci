// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::{collections::HashMap, fmt::Write, time::Duration};

use russh::ChannelMsg;

use crate::{vm_image::GuestOs, vm_image::SshTarget};

enum CopyDirection {
    HostToVm,
    VmToHost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineEndingConversion {
    None,
    /// Rewrite text files in the archive so all line endings are LF.
    ToLf,
    /// Rewrite text files in the archive so all line endings are CRLF.
    ToCrlf,
}

/// `line_endings` rewrites the in-flight tar archive so text files arrive with
/// the requested line endings. Binary files are detected by a null-byte scan
/// and left alone. Files on disk (host source or VM source) are never modified.
#[allow(clippy::too_many_arguments)]
pub async fn copy_files_tar(
    ssh: &SshTarget,
    from: &str,
    to: &str,
    ignore: &[String],
    os: GuestOs,
    timeout: Option<Duration>,
    no_mkdir: bool,
    allow_empty: bool,
    line_endings: LineEndingConversion,
    ignore_plan: &crate::run::ignore_files::IgnorePlan,
) -> Result<(), String> {
    let start = std::time::Instant::now();
    let poll_interval = Duration::from_secs(5);

    let _transfer_lock = loop {
        match crate::transfer_lock::TransferLock::try_new() {
            Ok(lock) => break lock,
            Err(e) => {
                if let crate::transfer_lock::TransferLockError::OtherProcessBlock(p) = e {
                    eprintln!("Another process is copying files with tar.\n\t{p}");
                }

                if let Some(timeout) = timeout
                    && start.elapsed() >= timeout
                {
                    return Err("Timed out waiting for transfer lock".to_string());
                }

                std::thread::sleep(poll_interval);
            }
        }
    };

    let (direction, local_path, remote_path) =
        parse_copy_paths(from, to).map_err(|e| e.to_string())?;
    let remote_path = expand_remote_tilde(remote_path, &ssh.cred.user, os);

    match direction {
        CopyDirection::HostToVm => {
            if !no_mkdir {
                ensure_remote_dir(ssh, &remote_path, os).await?;
            }
            if let Some((root, pattern)) = split_glob(local_path) {
                copy_host_to_vm_glob(
                    ssh,
                    &root,
                    &pattern,
                    &remote_path,
                    ignore,
                    allow_empty,
                    line_endings,
                    ignore_plan,
                )
                .await
            } else {
                copy_host_to_vm_tar(
                    ssh,
                    local_path,
                    &remote_path,
                    ignore,
                    allow_empty,
                    line_endings,
                    ignore_plan,
                )
                .await
            }
        }
        CopyDirection::VmToHost => {
            if !no_mkdir {
                std::fs::create_dir_all(local_path)
                    .map_err(|e| format!("Failed to create local directory {local_path}: {e}"))?;
            }
            if let Some((root, pattern)) = split_glob(&remote_path) {
                copy_vm_to_host_glob(
                    ssh,
                    &root,
                    &pattern,
                    local_path,
                    ignore,
                    os,
                    allow_empty,
                    line_endings,
                )
                .await
            } else {
                copy_vm_to_host_tar(ssh, &remote_path, local_path, ignore, os, line_endings).await
            }
        }
    }
}

/// Run a [`crate::yaml::CopySpec`] against a live VM: emit the host/guest CRLF
/// advisory, resolve the in-flight line-ending conversion, run the tar transfer,
/// then apply the post-copy Windows fixup when copying into a Windows guest.
///
/// Shared by the `copy:` workflow step and the `virtci copy` command so both
/// honor every `CopySpec` field identically. `direction` is taken from which
/// side of `spec` carries the `vm:` prefix (validated upstream).
pub async fn run_copy_spec(
    ssh: &SshTarget,
    spec: &crate::yaml::CopySpec,
    guest_os: GuestOs,
    timeout: Option<Duration>,
    no_ignore: bool,
) -> Result<(), String> {
    use colored::Colorize;

    let is_host_to_vm = spec.to.starts_with("vm:");
    let host_is_windows = cfg!(target_os = "windows");
    let guest_is_windows = guest_os == GuestOs::Windows;

    if !spec.crlf {
        let warning = if is_host_to_vm {
            if host_is_windows && !guest_is_windows {
                Some(
                    "[VirtCI] Copying files from a Windows host to a non-Windows guest without CRLF conversion may result in unexpected line endings. Set 'crlf: true' if you want line-ending conversion.",
                )
            } else if !host_is_windows && guest_is_windows {
                Some(
                    "[VirtCI] Copying files from a non-Windows host to a Windows guest without CRLF conversion may result in unexpected line endings. Set 'crlf: true' if you want line-ending conversion.",
                )
            } else {
                None
            }
        } else if guest_is_windows && !host_is_windows {
            Some(
                "[VirtCI] Copying files from a Windows guest to a non-Windows host without CRLF conversion may result in unexpected line endings. Set 'crlf: true' if you want line-ending conversion.",
            )
        } else if !guest_is_windows && host_is_windows {
            Some(
                "[VirtCI] Copying files from a non-Windows guest to a Windows host without CRLF conversion may result in unexpected line endings. Set 'crlf: true' if you want line-ending conversion.",
            )
        } else {
            None
        };
        if let Some(warning) = warning {
            println!("{}", warning.yellow());
        }
    }

    // In-flight tar conversion. Host->VM CRLF is still done in-guest by
    // `convert_windows_line_endings` below, not here.
    let line_endings = if !spec.crlf {
        LineEndingConversion::None
    } else if is_host_to_vm {
        if host_is_windows && !guest_is_windows {
            LineEndingConversion::ToLf
        } else {
            LineEndingConversion::None
        }
    } else if guest_is_windows && !host_is_windows {
        LineEndingConversion::ToLf
    } else if !guest_is_windows && host_is_windows {
        LineEndingConversion::ToCrlf
    } else {
        LineEndingConversion::None
    };

    let cwd = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let ignore_plan = crate::run::ignore_files::resolve_ignore_plan(
        spec.ignore_file.as_ref(),
        no_ignore,
        is_host_to_vm,
        &cwd,
    );

    copy_files_tar(
        ssh,
        &spec.from,
        &spec.to,
        &spec.exclude,
        guest_os,
        timeout,
        spec.no_mkdir,
        spec.allow_empty,
        line_endings,
        &ignore_plan,
    )
    .await?;

    if is_host_to_vm && guest_is_windows && spec.crlf {
        convert_windows_line_endings(ssh, &spec.to).await;
    }

    Ok(())
}

const GLOB_CHARS: &[char] = &['*', '?', '['];

fn has_wildcard(s: &str) -> bool {
    s.chars().any(|c| GLOB_CHARS.contains(&c))
}

/// If `path` contains a wildcard part, split the first, returning `Some((root, pattern))`.
/// Necessary for tar.
/// `hello/world/build/**/*.exe` would have the root at `build/`, so a copy to
/// `host/folder/` would result in something like `host/folder/hi.exe` for the copy.
fn split_glob(path: &str) -> Option<(String, String)> {
    if !has_wildcard(path) {
        return None;
    }
    let segments: Vec<&str> = path.split(['/', '\\']).collect();
    let first_wild = segments.iter().position(|s| has_wildcard(s))?;
    let root = if first_wild == 0 {
        ".".to_string()
    } else {
        segments[..first_wild].join("/")
    };
    let pattern = segments[first_wild..].join("/");
    Some((root, pattern))
}

/// In the workflow copy step, if `no_mkdir` is NOT set, it will create the directories necessary
/// in the VM.
async fn ensure_remote_dir(ssh: &SshTarget, remote_path: &str, os: GuestOs) -> Result<(), String> {
    let path_clean = remote_path.trim_end_matches(['\\', '/']);
    if path_clean.is_empty() {
        return Ok(());
    }

    let mkdir_cmd = match os {
        GuestOs::Windows => {
            format!("New-Item -ItemType Directory -Force -Path \"{path_clean}\" | Out-Null")
        }
        _ => format!("mkdir -p \"{path_clean}\""),
    };

    let result =
        crate::run::command::run_command(ssh, &mkdir_cmd, None, &HashMap::new(), os).await?;

    if result.exit_code != 0 {
        return Err(format!(
            "Failed to create remote directory {path_clean} (exit {}): {}",
            result.exit_code, result.stderr
        ));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn copy_host_to_vm_tar(
    ssh: &SshTarget,
    local_path: &str,
    remote_path: &str,
    ignore: &[String],
    allow_empty: bool,
    line_endings: LineEndingConversion,
    ignore_plan: &crate::run::ignore_files::IgnorePlan,
) -> Result<(), String> {
    use std::process::{Command, Stdio};

    let local_metadata = std::fs::metadata(local_path)
        .map_err(|e| format!("Failed to read local path {local_path}: {e}"))?;

    if local_metadata.is_dir() && ignore_plan.is_enabled() {
        let rel_paths = {
            match crate::run::ignore_files::walk_filtered(
                std::path::Path::new(local_path),
                ignore_plan,
            ) {
                Ok(good) => good,
                Err(e) => return Err(e.to_string()),
            }
        };
        if rel_paths.is_empty() {
            return handle_empty_match(local_path, allow_empty);
        }
        eprintln!(
            "[VirtCI IGNORE] {} file(s) after ignore filtering",
            rel_paths.len()
        );
        let archive = build_host_tar_from_list(local_path, &rel_paths, ignore, line_endings)?;
        return send_archive_to_remote(ssh, &archive, remote_path).await;
    }

    // Uncompressed: every transfer is over loopback, so gzip only burns CPU.
    let mut tar_args = vec!["cf".to_string(), "-".to_string()];

    for pattern in ignore {
        tar_args.push("--exclude".to_string());
        tar_args.push(pattern.clone());
    }

    if local_metadata.is_dir() {
        tar_args.push("-C".to_string());
        tar_args.push(local_path.to_string());
        tar_args.push(".".to_string());
    } else {
        let path = std::path::Path::new(local_path);
        let parent = path.parent().and_then(|p| p.to_str()).unwrap_or(".");
        let filename = path
            .file_name()
            .and_then(|f| f.to_str())
            .ok_or_else(|| format!("Invalid filename in path: {local_path}"))?;

        tar_args.push("-C".to_string());
        tar_args.push(parent.to_string());
        tar_args.push(filename.to_string());
    }

    eprintln!("[TAR] Creating archive from: {local_path}");
    eprintln!("[TAR] Command: tar {}", tar_args.join(" "));

    let tar_output = Command::new("tar")
        .args(&tar_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("Failed to create tar archive: {e}"))?;

    if !tar_output.status.success() {
        let stderr = String::from_utf8_lossy(&tar_output.stderr);
        eprintln!("[TAR] Creation failed: {stderr}");
        return Err(format!("tar command failed: {stderr}"));
    }

    eprintln!("[TAR] Archive created: {} bytes", tar_output.stdout.len());

    if !tar_output.stderr.is_empty() {
        eprintln!(
            "[TAR] Warnings: {}",
            String::from_utf8_lossy(&tar_output.stderr)
        );
    }

    let archive = apply_line_ending_conversion(tar_output.stdout, line_endings)?;

    send_archive_to_remote(ssh, &archive, remote_path).await
}

fn build_host_tar_from_list(
    root: &str,
    rel_paths: &[String],
    ignore: &[String],
    line_endings: LineEndingConversion,
) -> Result<Vec<u8>, String> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    let file_list = rel_paths.join("\n");

    let mut tar_args: Vec<String> = vec![
        "cf".into(),
        "-".into(),
        "-C".into(),
        root.to_string(),
        "-T".into(),
        "-".into(),
    ];
    for p in ignore {
        tar_args.push("--exclude".into());
        tar_args.push(p.clone());
    }

    eprintln!("[TAR] Command: tar {}", tar_args.join(" "));

    let mut child = Command::new("tar")
        .args(&tar_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn tar: {e}"))?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(file_list.as_bytes())
            .map_err(|e| format!("Failed to write file list to tar stdin: {e}"))?;
    }

    let tar_output = child
        .wait_with_output()
        .map_err(|e| format!("tar wait failed: {e}"))?;

    if !tar_output.status.success() {
        return Err(format!(
            "tar command failed: {}",
            String::from_utf8_lossy(&tar_output.stderr)
        ));
    }

    eprintln!("[TAR] Archive created: {} bytes", tar_output.stdout.len());

    apply_line_ending_conversion(tar_output.stdout, line_endings)
}

#[allow(clippy::too_many_arguments)]
async fn copy_host_to_vm_glob(
    ssh: &SshTarget,
    root: &str,
    pattern: &str,
    remote_path: &str,
    ignore: &[String],
    allow_empty: bool,
    line_endings: LineEndingConversion,
    ignore_plan: &crate::run::ignore_files::IgnorePlan,
) -> Result<(), String> {
    let full_pattern = format!("{root}/{pattern}");

    eprintln!("[GLOB] Expanding host pattern '{full_pattern}'");

    let entries: Vec<std::path::PathBuf> = glob::glob(&full_pattern)
        .map_err(|e| format!("Invalid glob pattern '{full_pattern}': {e}"))?
        .filter_map(Result::ok)
        .filter(|p| p.is_file())
        .collect();

    if entries.is_empty() {
        return handle_empty_match(&full_pattern, allow_empty);
    }

    let root_path = std::path::Path::new(root);
    let mut rel_paths: Vec<String> = entries
        .iter()
        .filter_map(|p| {
            p.strip_prefix(root_path)
                .ok()
                .and_then(|r| r.to_str())
                .map(|s| s.replace('\\', "/"))
        })
        .filter(|s| !s.is_empty() && !s.contains(['\n', '\r']))
        .map(|s| format!("./{s}"))
        .collect();

    eprintln!("[VirtCI GLOB] Matched {} file(s)", rel_paths.len());

    if ignore_plan.is_enabled() {
        let allowed: std::collections::HashSet<String> = {
            match crate::run::ignore_files::walk_filtered(root_path, ignore_plan) {
                Ok(filtered) => filtered.into_iter().collect(),
                Err(e) => return Err(e.to_string()),
            }
        };
        rel_paths.retain(|p| allowed.contains(p));
        if rel_paths.is_empty() {
            return handle_empty_match(&full_pattern, allow_empty);
        }
        eprintln!(
            "[IGNORE] {} file(s) after ignore filtering",
            rel_paths.len()
        );
    }

    let archive = build_host_tar_from_list(root, &rel_paths, ignore, line_endings)?;

    send_archive_to_remote(ssh, &archive, remote_path).await
}

async fn send_archive_to_remote(
    ssh: &SshTarget,
    tar_data: &[u8],
    remote_path: &str,
) -> Result<(), String> {
    const CHUNK_SIZE: usize = 32 * 1024;

    let handle = crate::run::connect_resilient(ssh)
        .await
        .map_err(|e| format!("{e:#}"))?;

    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("Failed to open channel: {e}"))?;

    let remote_path_clean = remote_path.trim_end_matches('\\');
    let extract_cmd = format!("tar xf - -C \"{remote_path_clean}\"");
    eprintln!("[TAR] Remote extract command: {extract_cmd}");

    channel
        .exec(true, extract_cmd)
        .await
        .map_err(|e| format!("Failed to exec tar extract: {e}"))?;

    let (mut reader, writer) = channel.split();

    let drain_task = tokio::spawn(async move {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_code: u32 = 0;
        let mut got_exit_status = false;

        while let Some(msg) = reader.wait().await {
            match msg {
                ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, ext: 1 } => {
                    stderr.extend_from_slice(&data);
                }
                ChannelMsg::ExitStatus { exit_status } => {
                    exit_code = exit_status;
                    got_exit_status = true;
                }
                _ => {}
            }
        }

        (stdout, stderr, exit_code, got_exit_status)
    });

    eprintln!("[TAR] Sending {} bytes to remote...", tar_data.len());

    for chunk in tar_data.chunks(CHUNK_SIZE) {
        writer
            .data(chunk)
            .await
            .map_err(|e| format!("Failed to send tar data: {e}"))?;
    }

    writer
        .eof()
        .await
        .map_err(|e| format!("Failed to send EOF: {e}"))?;

    eprintln!("[TAR] All data sent, waiting for extraction to complete...");

    let (stdout, stderr, exit_code, got_exit_status) = drain_task
        .await
        .map_err(|e| format!("Channel message drain failed: {e}"))?;

    writer.close().await.ok();
    handle
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await
        .ok();

    tokio::task::yield_now().await;

    if !got_exit_status {
        return Err("SSH channel closed without providing an exit status".to_string());
    }

    let stdout_str = String::from_utf8_lossy(&stdout);
    let stderr_str = String::from_utf8_lossy(&stderr);

    if !stdout_str.is_empty() {
        eprintln!("[TAR] Remote stdout: {stdout_str}");
    }
    if !stderr_str.is_empty() {
        eprintln!("[TAR] Remote stderr: {stderr_str}");
    }

    if exit_code != 0 {
        eprintln!("[TAR] Extraction failed with exit code: {exit_code}");
        return Err(format!(
            "Tar extraction failed (exit code {exit_code}): {stderr_str}"
        ));
    }

    eprintln!("[TAR] Transfer completed successfully");
    Ok(())
}

async fn copy_vm_to_host_tar(
    ssh: &SshTarget,
    remote_path: &str,
    local_path: &str,
    ignore: &[String],
    os: GuestOs,
    line_endings: LineEndingConversion,
) -> Result<(), String> {
    let is_windows = os == GuestOs::Windows;

    let test_cmd = if is_windows {
        format!(
            "if (Test-Path -Path \"{remote_path}\" -PathType Container) {{ Write-Output \"DIR\" }} else {{ Write-Output \"FILE\" }}"
        )
    } else {
        format!("test -d \"{remote_path}\" && echo DIR || echo FILE")
    };
    let test_result =
        crate::run::command::run_command(ssh, &test_cmd, None, &HashMap::new(), os).await?;
    let is_dir = test_result.stdout.trim() == "DIR";

    let mut exclude_args = String::new();
    for pattern in ignore {
        let _ = write!(&mut exclude_args, " --exclude=\"{pattern}\"");
    }

    let tar_cmd = if is_dir {
        let base_cmd = format!("tar cf - -C \"{remote_path}\"{exclude_args} .");
        if is_windows {
            format!("cmd /c {base_cmd}")
        } else {
            base_cmd
        }
    } else {
        let (parent, filename) = split_parent_filename(remote_path, is_windows);
        let base_cmd = format!("tar cf - -C \"{parent}\"{exclude_args} \"{filename}\"");
        if is_windows {
            format!("cmd /c {base_cmd}")
        } else {
            base_cmd
        }
    };

    eprintln!("[TAR] Creating archive from remote: {remote_path}");
    eprintln!("[TAR] Remote command: {tar_cmd}");

    let result =
        crate::run::command::run_command_binary(ssh, &tar_cmd, None, &HashMap::new(), os).await?;

    if result.exit_code != 0 {
        return Err(format!(
            "Remote tar creation failed: {}",
            String::from_utf8_lossy(&result.stderr)
        ));
    }

    let archive = apply_line_ending_conversion(result.stdout, line_endings)?;
    extract_archive_locally(&archive, local_path)
}

#[allow(clippy::too_many_arguments)]
async fn copy_vm_to_host_glob(
    ssh: &SshTarget,
    root: &str,
    pattern: &str,
    local_path: &str,
    ignore: &[String],
    os: GuestOs,
    allow_empty: bool,
    line_endings: LineEndingConversion,
) -> Result<(), String> {
    let is_windows = os == GuestOs::Windows;

    eprintln!("[GLOB] VM-side root: {root}, pattern: {pattern}");

    let enum_cmd = if is_windows {
        format!(
            r#"$root = "{root}"; if (-not (Test-Path -Path $root -PathType Container)) {{ Write-Error "Root not found: $root"; exit 2 }}; $rootFull = (Resolve-Path -Path $root).Path; Get-ChildItem -Path $rootFull -Recurse -File | ForEach-Object {{ $rel = $_.FullName.Substring($rootFull.Length).TrimStart([char]'\','/') -replace '\\', '/'; Write-Output $rel }}"#
        )
    } else {
        format!(r#"cd "{root}" && find . -type f -print | sed 's|^\./||'"#)
    };

    let enum_result =
        crate::run::command::run_command(ssh, &enum_cmd, None, &HashMap::new(), os).await?;
    if enum_result.exit_code != 0 {
        return Err(format!(
            "Remote enumeration failed (exit {}): {}",
            enum_result.exit_code, enum_result.stderr
        ));
    }

    let all_files: Vec<String> = enum_result
        .stdout
        .lines()
        .map(|s| s.trim().trim_end_matches('\r').to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let pat = glob::Pattern::new(pattern)
        .map_err(|e| format!("Invalid glob pattern '{pattern}': {e}"))?;

    let match_opts = glob::MatchOptions {
        case_sensitive: !is_windows,
        require_literal_separator: true,
        require_literal_leading_dot: false,
    };

    let matches: Vec<String> = all_files
        .into_iter()
        .filter(|f| !f.contains(['\n', '\r']) && pat.matches_with(f, match_opts))
        .map(|f| format!("./{f}"))
        .collect();

    if matches.is_empty() {
        let full = if root == "." {
            pattern.to_string()
        } else {
            format!("{root}/{pattern}")
        };
        return handle_empty_match(&full, allow_empty);
    }

    eprintln!("[GLOB] Matched {} remote file(s)", matches.len());

    let mut exclude_args = String::new();
    for p in ignore {
        let _ = write!(&mut exclude_args, " --exclude=\"{p}\"");
    }

    let tar_cmd = if is_windows {
        format!("cmd /c tar cf - -C \"{root}\"{exclude_args} -T -")
    } else {
        format!("tar cf - -C \"{root}\"{exclude_args} -T -")
    };

    eprintln!("[TAR] Remote command: {tar_cmd}");

    let file_list = matches.join("\n");
    let archive = exec_remote_with_stdin(ssh, &tar_cmd, file_list.as_bytes()).await?;

    let archive = apply_line_ending_conversion(archive, line_endings)?;
    extract_archive_locally(&archive, local_path)
}

async fn exec_remote_with_stdin(
    ssh: &SshTarget,
    cmd: &str,
    stdin_data: &[u8],
) -> Result<Vec<u8>, String> {
    const CHUNK_SIZE: usize = 32 * 1024;

    let handle = crate::run::connect_resilient(ssh)
        .await
        .map_err(|e| format!("{e:#}"))?;
    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("Failed to open channel: {e}"))?;

    channel
        .exec(true, cmd)
        .await
        .map_err(|e| format!("Failed to exec remote command: {e}"))?;

    let (mut reader, writer) = channel.split();

    let drain_task = tokio::spawn(async move {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_code: u32 = 0;
        let mut got_exit_status = false;

        while let Some(msg) = reader.wait().await {
            match msg {
                ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, ext: 1 } => {
                    stderr.extend_from_slice(&data);
                }
                ChannelMsg::ExitStatus { exit_status } => {
                    exit_code = exit_status;
                    got_exit_status = true;
                }
                _ => {}
            }
        }

        (stdout, stderr, exit_code, got_exit_status)
    });

    for chunk in stdin_data.chunks(CHUNK_SIZE) {
        writer
            .data(chunk)
            .await
            .map_err(|e| format!("Failed to send stdin chunk: {e}"))?;
    }

    writer
        .eof()
        .await
        .map_err(|e| format!("Failed to send EOF: {e}"))?;

    let (stdout, stderr, exit_code, got_exit_status) = drain_task
        .await
        .map_err(|e| format!("Channel message drain failed: {e}"))?;

    writer.close().await.ok();
    handle
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await
        .ok();

    tokio::task::yield_now().await;

    if !got_exit_status {
        return Err("SSH channel closed without providing an exit status".to_string());
    }

    if exit_code != 0 {
        let stderr_str = String::from_utf8_lossy(&stderr);
        return Err(format!(
            "Remote command failed (exit {exit_code}): {stderr_str}"
        ));
    }

    Ok(stdout)
}

fn extract_archive_locally(archive: &[u8], dest_dir: &str) -> Result<(), String> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    // Uncompressed tar has the POSIX "ustar" magic lives at offset 257
    let looks_like_tar = archive.len() >= 262 && &archive[257..262] == b"ustar";
    let looks_empty = archive.iter().all(|&b| b == 0);
    if !looks_like_tar && !looks_empty {
        let preview: Vec<u8> = archive.iter().take(64).copied().collect();
        let preview_str = String::from_utf8_lossy(&preview);
        return Err(format!(
            "Remote tar output is not a valid tar archive. First bytes: {:02x?}, as text: '{}'",
            &archive[..std::cmp::min(16, archive.len())],
            preview_str.chars().take(64).collect::<String>()
        ));
    }

    eprintln!("[TAR] Extracting to: {dest_dir}");

    let mut tar_process = Command::new("tar")
        .args(["xf", "-", "-C", dest_dir])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn tar extract: {e}"))?;

    if let Some(mut stdin) = tar_process.stdin.take() {
        const CHUNK_SIZE: usize = 32 * 1024;
        for chunk in archive.chunks(CHUNK_SIZE) {
            stdin
                .write_all(chunk)
                .map_err(|e| format!("Failed to write to tar stdin: {e}"))?;
        }
    }

    let output = tar_process
        .wait_with_output()
        .map_err(|e| format!("Failed to wait for tar: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "Local tar extraction failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    eprintln!("[TAR] Extraction completed successfully");
    Ok(())
}

fn split_parent_filename(path: &str, is_windows: bool) -> (String, String) {
    if is_windows {
        let normalized = path.replace('/', "\\");
        match normalized.rfind('\\') {
            Some(pos) => (
                normalized[..pos].to_string(),
                normalized[pos + 1..].to_string(),
            ),
            None => (".".to_string(), normalized),
        }
    } else {
        let p = std::path::Path::new(path);
        let parent = p.parent().and_then(|p| p.to_str()).unwrap_or(".");
        let filename = p.file_name().and_then(|f| f.to_str()).unwrap_or(path);
        let parent = if parent.is_empty() { "." } else { parent };
        (parent.to_string(), filename.to_string())
    }
}

fn handle_empty_match(pattern: &str, allow_empty: bool) -> Result<(), String> {
    if allow_empty {
        eprintln!("[GLOB] No matches for '{pattern}', skipping (allow_empty: true)");
        Ok(())
    } else {
        Err(format!(
            "Glob '{pattern}' matched no files. Set `allow_empty: true` to ignore."
        ))
    }
}

fn expand_remote_tilde(path: &str, username: &str, os: GuestOs) -> String {
    let home = match os {
        GuestOs::Windows => format!("C:\\Users\\{username}"),
        GuestOs::MacOS => {
            if username == "root" {
                "/root".to_string()
            } else {
                format!("/Users/{username}")
            }
        }
        _ => {
            if username == "root" {
                "/root".to_string()
            } else {
                format!("/home/{username}")
            }
        }
    };

    if path == "~" {
        return home;
    } else if let Some(rest) = path.strip_prefix("~/") {
        let sep = if os == GuestOs::Windows { "\\" } else { "/" };
        return format!("{home}{sep}{rest}");
    }
    path.to_string()
}

fn parse_copy_paths<'a>(
    from: &'a str,
    to: &'a str,
) -> anyhow::Result<(CopyDirection, &'a str, &'a str)> {
    crate::yaml::validate_copy_direction(from, to).map_err(|e| anyhow::anyhow!("{e}"))?;

    // Exactly one side is `vm:`-prefixed (guaranteed above).
    if let Some(to_path) = to.strip_prefix("vm:") {
        Ok((CopyDirection::HostToVm, from, to_path))
    } else if let Some(from_path) = from.strip_prefix("vm:") {
        Ok((CopyDirection::VmToHost, to, from_path))
    } else {
        unreachable!("validate_copy_direction guarantees exactly one `vm:` prefix")
    }
}

fn apply_line_ending_conversion(
    tar_bytes: Vec<u8>,
    conv: LineEndingConversion,
) -> Result<Vec<u8>, String> {
    match conv {
        LineEndingConversion::None => Ok(tar_bytes),
        LineEndingConversion::ToLf => rewrite_tar(&tar_bytes, crlf_to_lf),
        LineEndingConversion::ToCrlf => rewrite_tar(&tar_bytes, lf_to_crlf),
    }
}

/// Rewrites an uncompressed tar archive in memory, running `convert` over each
/// text file payload. Binary files (detected by a null-byte scan) are passed
/// through untouched. Files on disk aren't modified either.
fn rewrite_tar(tar_bytes: &[u8], convert: fn(&[u8]) -> Vec<u8>) -> Result<Vec<u8>, String> {
    use std::io::Read as _;

    let mut archive = tar::Archive::new(tar_bytes);
    let mut out = Vec::with_capacity(tar_bytes.len());
    {
        let mut builder = tar::Builder::new(&mut out);
        let entries = archive
            .entries()
            .map_err(|e| format!("Failed to read tar entries: {e}"))?;
        for entry in entries {
            let mut entry = entry.map_err(|e| format!("Failed to read tar entry: {e}"))?;
            let mut header = entry.header().clone();
            let path = entry
                .path()
                .map_err(|e| format!("Bad path in tar entry: {e}"))?
                .into_owned();
            let entry_type = header.entry_type();

            if entry_type.is_file() {
                let mut data = Vec::new();
                entry
                    .read_to_end(&mut data)
                    .map_err(|e| format!("Failed to read tar entry data: {e}"))?;
                if is_text(&data) {
                    data = convert(&data);
                }
                header.set_size(data.len() as u64);
                builder
                    .append_data(&mut header, &path, data.as_slice())
                    .map_err(|e| format!("Failed to repack tar entry: {e}"))?;
            } else if entry_type.is_symlink() || entry_type.is_hard_link() {
                let target = entry
                    .link_name()
                    .map_err(|e| format!("Bad link name in tar entry: {e}"))?
                    .map(std::borrow::Cow::into_owned);
                match target {
                    Some(target) => builder
                        .append_link(&mut header, &path, &target)
                        .map_err(|e| format!("Failed to repack tar link: {e}"))?,
                    None => builder
                        .append_data(&mut header, &path, std::io::empty())
                        .map_err(|e| format!("Failed to repack tar link: {e}"))?,
                }
            } else {
                // Directories, fifos, etc.: no payload.
                builder
                    .append_data(&mut header, &path, std::io::empty())
                    .map_err(|e| format!("Failed to repack tar entry: {e}"))?;
            }
        }
        builder
            .finish()
            .map_err(|e| format!("Failed to finalize tar: {e}"))?;
    }
    Ok(out)
}

fn is_text(data: &[u8]) -> bool {
    !data.iter().take(8192).any(|&b| b == 0)
}

fn crlf_to_lf(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'\r' {
            out.push(b'\n');
            if i + 1 < data.len() && data[i + 1] == b'\n' {
                i += 1;
            }
        } else {
            out.push(data[i]);
        }
        i += 1;
    }
    out
}

fn lf_to_crlf(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 16);
    let mut i = 0;
    while i < data.len() {
        match data[i] {
            b'\r' => {
                out.push(b'\r');
                out.push(b'\n');
                if i + 1 < data.len() && data[i + 1] == b'\n' {
                    i += 1;
                }
            }
            b'\n' => {
                out.push(b'\r');
                out.push(b'\n');
            }
            b => out.push(b),
        }
        i += 1;
    }
    out
}

/// PowerShell script that converts text files to CRLF line endings.
/// Kinda works like git auto-crlf to filter out binary files.
/// Reads the first 8KB of each file and if any null byte is found, it's binary.
fn crlf_conversion_script() -> &'static str {
    r#"
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
$files = Get-ChildItem -Recurse -File
$converted = 0
$skipped = 0
foreach ($f in $files) {
    try {
        $stream = [IO.File]::OpenRead($f.FullName)
        $buf = New-Object byte[] 8192
        $n = $stream.Read($buf, 0, $buf.Length)
        $stream.Close()
        $isBinary = $false
        for ($i = 0; $i -lt $n; $i++) {
            if ($buf[$i] -eq 0) { $isBinary = $true; break }
        }
        if ($isBinary) { $skipped++; continue }
        $bytes = [IO.File]::ReadAllBytes($f.FullName)
        $content = [System.Text.Encoding]::UTF8.GetString($bytes)
        $content = $content -replace "`r`n","`n" -replace "`r","`n" -replace "`n","`r`n"
        [IO.File]::WriteAllText($f.FullName, $content, $utf8NoBom)
        $converted++
    } catch { }
}
Write-Host "Converted $converted files ($skipped binary skipped)"
"#
}

pub async fn convert_windows_line_endings(ssh: &SshTarget, to: &str) {
    use colored::Colorize;
    println!(
        "{}",
        "  Converting files to Windows encoding (UTF-8 without BOM + CRLF)...".dimmed()
    );

    let target_dir = if to.starts_with("vm:") {
        to.strip_prefix("vm:").unwrap()
    } else {
        to
    };

    let convert_script = crlf_conversion_script();

    let convert_result = crate::run::command::run_command(
        ssh,
        convert_script,
        Some(target_dir),
        &HashMap::new(),
        GuestOs::Windows,
    )
    .await;

    if let Ok(result) = convert_result {
        if !result.stdout.trim().is_empty() {
            println!("{}", format!("  {}", result.stdout.trim()).dimmed());
        }
    } else {
        println!("{}", "  Warning: File conversion failed".yellow());
    }
}
