// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::{collections::HashMap, fmt::Write, time::Duration};

use russh::ChannelMsg;

use crate::{vm_image::GuestOs, vm_image::SshTarget};

enum CopyDirection {
    HostToVm,
    VmToHost,
}

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

                if let Some(timeout) = timeout {
                    if start.elapsed() >= timeout {
                        return Err("Timed out waiting for transfer lock".to_string());
                    }
                }

                std::thread::sleep(poll_interval);
            }
        }
    };

    let (direction, local_path, remote_path) = parse_copy_paths(from, to);
    let remote_path = expand_remote_tilde(remote_path, &ssh.cred.user, os);

    match direction {
        CopyDirection::HostToVm => {
            if !no_mkdir {
                ensure_remote_dir(ssh, &remote_path, os).await?;
            }
            if let Some((root, pattern)) = split_glob(local_path) {
                copy_host_to_vm_glob(ssh, &root, &pattern, &remote_path, ignore, allow_empty).await
            } else {
                copy_host_to_vm_tar(ssh, local_path, &remote_path, ignore).await
            }
        }
        CopyDirection::VmToHost => {
            if !no_mkdir {
                std::fs::create_dir_all(local_path)
                    .map_err(|e| format!("Failed to create local directory {local_path}: {e}"))?;
            }
            if let Some((root, pattern)) = split_glob(&remote_path) {
                copy_vm_to_host_glob(ssh, &root, &pattern, local_path, ignore, os, allow_empty)
                    .await
            } else {
                copy_vm_to_host_tar(ssh, &remote_path, local_path, ignore, os).await
            }
        }
    }
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

async fn copy_host_to_vm_tar(
    ssh: &SshTarget,
    local_path: &str,
    remote_path: &str,
    ignore: &[String],
) -> Result<(), String> {
    use std::process::{Command, Stdio};

    let local_metadata = std::fs::metadata(local_path)
        .map_err(|e| format!("Failed to read local path {local_path}: {e}"))?;

    let mut tar_args = vec!["czf".to_string(), "-".to_string()];

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

    send_archive_to_remote(ssh, &tar_output.stdout, remote_path).await
}

async fn copy_host_to_vm_glob(
    ssh: &SshTarget,
    root: &str,
    pattern: &str,
    remote_path: &str,
    ignore: &[String],
    allow_empty: bool,
) -> Result<(), String> {
    use std::io::Write as _;
    use std::process::{Command, Stdio};

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
    let rel_paths: Vec<String> = entries
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

    eprintln!("[GLOB] Matched {} file(s)", rel_paths.len());

    let file_list = rel_paths.join("\n");

    let mut tar_args: Vec<String> = vec![
        "czf".into(),
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

    send_archive_to_remote(ssh, &tar_output.stdout, remote_path).await
}

async fn send_archive_to_remote(
    ssh: &SshTarget,
    tar_data: &[u8],
    remote_path: &str,
) -> Result<(), String> {
    const CHUNK_SIZE: usize = 32 * 1024;

    let handle = crate::run::connect(ssh).await?;

    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("Failed to open channel: {e}"))?;

    let remote_path_clean = remote_path.trim_end_matches('\\');
    let extract_cmd = format!("tar xzf - -C \"{remote_path_clean}\"");
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
) -> Result<(), String> {
    let is_windows = os == GuestOs::Windows;

    let test_cmd = if is_windows {
        format!("if (Test-Path -Path \"{remote_path}\" -PathType Container) {{ Write-Output \"DIR\" }} else {{ Write-Output \"FILE\" }}")
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
        let base_cmd = format!("tar czf - -C \"{remote_path}\"{exclude_args} .");
        if is_windows {
            format!("cmd /c {base_cmd}")
        } else {
            base_cmd
        }
    } else {
        let (parent, filename) = split_parent_filename(remote_path, is_windows);
        let base_cmd = format!("tar czf - -C \"{parent}\"{exclude_args} \"{filename}\"");
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

    extract_archive_locally(&result.stdout, local_path)
}

async fn copy_vm_to_host_glob(
    ssh: &SshTarget,
    root: &str,
    pattern: &str,
    local_path: &str,
    ignore: &[String],
    os: GuestOs,
    allow_empty: bool,
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
        format!("cmd /c tar czf - -C \"{root}\"{exclude_args} -T -")
    } else {
        format!("tar czf - -C \"{root}\"{exclude_args} -T -")
    };

    eprintln!("[TAR] Remote command: {tar_cmd}");

    let file_list = matches.join("\n");
    let archive = exec_remote_with_stdin(ssh, &tar_cmd, file_list.as_bytes()).await?;

    extract_archive_locally(&archive, local_path)
}

async fn exec_remote_with_stdin(
    ssh: &SshTarget,
    cmd: &str,
    stdin_data: &[u8],
) -> Result<Vec<u8>, String> {
    const CHUNK_SIZE: usize = 32 * 1024;

    let handle = crate::run::connect(ssh).await?;
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

    if archive.len() < 2 || archive[0] != 0x1f || archive[1] != 0x8b {
        let preview: Vec<u8> = archive.iter().take(64).copied().collect();
        let preview_str = String::from_utf8_lossy(&preview);
        return Err(format!(
            "Remote tar output is not a valid gzip archive. First bytes: {:02x?}, as text: '{}'",
            &archive[..std::cmp::min(16, archive.len())],
            preview_str.chars().take(64).collect::<String>()
        ));
    }

    eprintln!("[TAR] Extracting to: {dest_dir}");

    let mut tar_process = Command::new("tar")
        .args(["xzf", "-", "-C", dest_dir])
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

fn parse_copy_paths<'a>(from: &'a str, to: &'a str) -> (CopyDirection, &'a str, &'a str) {
    let to_starts = to.starts_with("vm:");
    let from_starts = from.starts_with("vm:");
    assert!(
        !(to_starts && from_starts),
        "Cannot use SFTP to copy files from the VM to itself!"
    );
    assert!(
        !(!to_starts && !from_starts),
        "Cannot use SFTP to copy files from the host to itself!"
    );

    if to_starts {
        (CopyDirection::HostToVm, from, &to[3..])
    } else {
        (CopyDirection::VmToHost, to, &from[3..])
    }
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
