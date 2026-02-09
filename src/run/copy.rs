use std::time::Duration;

use russh::ChannelMsg;

use crate::{backend::SshTarget, vm_image::GuestOs};

enum CopyDirection {
    HostToVm,
    VmToHost,
}

pub async fn copy_files_tar(
    ssh: &SshTarget,
    from: &str,
    to: &str,
    ignore: &[String],
    os: GuestOs,
    timeout: Option<Duration>,
) -> Result<(), String> {
    let start = std::time::Instant::now();
    let poll_interval = Duration::from_secs(5);

    let _transfer_lock = loop {
        match crate::transfer_lock::TransferLock::try_new() {
            Ok(lock) => break lock,
            Err(e) => {
                if let crate::transfer_lock::TransferLockError::OtherProcessBlock(p) = e {
                    eprintln!("Another process is copying files with tar.\n\t{}", p);
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

    let remote_path = match direction {
        CopyDirection::HostToVm => expand_remote_tilde(remote_path, &ssh.cred.user, os),
        CopyDirection::VmToHost => expand_remote_tilde(remote_path, &ssh.cred.user, os),
    };

    match direction {
        CopyDirection::HostToVm => copy_host_to_vm_tar(ssh, local_path, &remote_path, ignore).await,
        CopyDirection::VmToHost => {
            copy_vm_to_host_tar(ssh, &remote_path, local_path, ignore, os).await
        }
    }
}

async fn copy_host_to_vm_tar(
    ssh: &SshTarget,
    local_path: &str,
    remote_path: &str,
    ignore: &[String],
) -> Result<(), String> {
    use std::process::{Command, Stdio};

    let local_metadata = std::fs::metadata(local_path)
        .map_err(|e| format!("Failed to read local path {}: {}", local_path, e))?;

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
            .ok_or_else(|| format!("Invalid filename in path: {}", local_path))?;

        tar_args.push("-C".to_string());
        tar_args.push(parent.to_string());
        tar_args.push(filename.to_string());
    }

    eprintln!("[TAR] Creating archive from: {}", local_path);
    eprintln!("[TAR] Command: tar {}", tar_args.join(" "));

    let tar_output = Command::new("tar")
        .args(&tar_args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| format!("Failed to create tar archive: {}", e))?;

    if !tar_output.status.success() {
        let stderr = String::from_utf8_lossy(&tar_output.stderr);
        eprintln!("[TAR] Creation failed: {}", stderr);
        return Err(format!("tar command failed: {}", stderr));
    }

    let tar_data = tar_output.stdout;
    eprintln!("[TAR] Archive created: {} bytes", tar_data.len());

    if !tar_output.stderr.is_empty() {
        eprintln!(
            "[TAR] Warnings: {}",
            String::from_utf8_lossy(&tar_output.stderr)
        );
    }

    let handle = crate::run::connect(ssh).await?;

    let mut channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("Failed to open channel: {}", e))?;

    let extract_cmd = format!("tar xzf - -C \"{}\"", remote_path);
    eprintln!("[TAR] Remote extract command: {}", extract_cmd);

    channel
        .exec(true, extract_cmd)
        .await
        .map_err(|e| format!("Failed to exec tar extract: {}", e))?;

    eprintln!("[TAR] Sending {} bytes to remote...", tar_data.len());

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_code: u32 = 0;
    let mut got_exit_status = false;
    let mut sent_bytes = 0;
    const CHUNK_SIZE: usize = 32768; // 32KB
    let mut eof_sent = false;
    let mut done = false;

    while !done {
        if sent_bytes < tar_data.len() {
            let end = std::cmp::min(sent_bytes + CHUNK_SIZE, tar_data.len());
            channel
                .data(&tar_data[sent_bytes..end])
                .await
                .map_err(|e| format!("Failed to send data chunk: {}", e))?;
            sent_bytes = end;
        } else if !eof_sent {
            channel
                .eof()
                .await
                .map_err(|e| format!("Failed to send EOF: {}", e))?;
            eof_sent = true;
            eprintln!("[TAR] All data sent, waiting for extraction to complete...");
        }

        match tokio::time::timeout(tokio::time::Duration::from_millis(10), channel.wait()).await {
            Ok(Some(ChannelMsg::Data { data })) => stdout.extend_from_slice(&data),
            Ok(Some(ChannelMsg::ExtendedData { data, ext })) if ext == 1 => {
                stderr.extend_from_slice(&data)
            }
            Ok(Some(ChannelMsg::ExitStatus { exit_status })) => {
                exit_code = exit_status;
                got_exit_status = true;
            }
            Ok(Some(ChannelMsg::Eof)) => {}
            Ok(None) => {
                done = true;
            }
            Err(_) => {}
            _ => {}
        }
    }

    handle
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await
        .ok();

    if !got_exit_status {
        return Err("SSH channel closed without providing an exit status".to_string());
    }

    let stdout_str = String::from_utf8_lossy(&stdout);
    let stderr_str = String::from_utf8_lossy(&stderr);

    if !stdout_str.is_empty() {
        eprintln!("[TAR] Remote stdout: {}", stdout_str);
    }
    if !stderr_str.is_empty() {
        eprintln!("[TAR] Remote stderr: {}", stderr_str);
    }

    if exit_code != 0 {
        eprintln!("[TAR] Extraction failed with exit code: {}", exit_code);
        return Err(format!(
            "Tar extraction failed (exit code {}): {}",
            exit_code, stderr_str
        ));
    }

    eprintln!("[TAR] Transfer completed successfully");
    return Ok(());
}

async fn copy_vm_to_host_tar(
    ssh: &SshTarget,
    remote_path: &str,
    local_path: &str,
    ignore: &[String],
    os: GuestOs,
) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // powershell may corrupt tar binary data??
    let is_windows = os == GuestOs::Windows;

    // Check if remote_path is a file or directory
    let test_cmd = if is_windows {
        format!("if (Test-Path -Path \"{}\" -PathType Container) {{ Write-Output \"DIR\" }} else {{ Write-Output \"FILE\" }}", remote_path)
    } else {
        format!("test -d \"{}\" && echo DIR || echo FILE", remote_path)
    };
    let test_result = crate::run::command::run_command(
        ssh,
        &test_cmd,
        None,
        &std::collections::HashMap::new(),
        os,
    )
    .await?;
    let is_dir = test_result.stdout.trim() == "DIR";

    let mut exclude_args = String::new();
    for pattern in ignore {
        exclude_args.push_str(&format!(" --exclude=\"{}\"", pattern));
    }

    let tar_cmd = if is_dir {
        // For directories: tar from within the directory
        let base_cmd = format!("tar czf - -C \"{}\"{} .", remote_path, exclude_args);
        if is_windows {
            format!("cmd /c {}", base_cmd)
        } else {
            base_cmd
        }
    } else {
        // For files: tar from parent directory with specific filename
        let path = std::path::Path::new(remote_path);
        let parent = path.parent().and_then(|p| p.to_str()).unwrap_or(".");
        let filename = path
            .file_name()
            .and_then(|f| f.to_str())
            .ok_or_else(|| format!("Invalid filename in path: {}", remote_path))?;

        let base_cmd = format!(
            "tar czf - -C \"{}\"{} \"{}\"",
            parent, exclude_args, filename
        );
        if is_windows {
            format!("cmd /c {}", base_cmd)
        } else {
            base_cmd
        }
    };

    eprintln!("[TAR] Creating archive from remote: {}", remote_path);
    eprintln!("[TAR] Remote command: {}", tar_cmd);

    let result = crate::run::command::run_command_binary(
        ssh,
        &tar_cmd,
        None,
        &std::collections::HashMap::new(),
        os,
    )
    .await?;

    if result.exit_code != 0 {
        return Err(format!(
            "Remote tar creation failed: {}",
            String::from_utf8_lossy(&result.stderr)
        ));
    }

    eprintln!("[TAR] Archive size: {} bytes", result.stdout.len());

    let (extract_dir, need_rename) = if is_dir {
        (local_path.to_string(), None)
    } else {
        let local = std::path::Path::new(local_path);
        let parent = local
            .parent()
            .and_then(|p| p.to_str())
            .ok_or_else(|| format!("Invalid local path: {}", local_path))?;

        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create local directory {}: {}", parent, e))?;

        let remote_filename = std::path::Path::new(remote_path)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("file");
        let local_filename = local.file_name().and_then(|f| f.to_str()).unwrap_or("file");

        let rename = if remote_filename != local_filename {
            Some((
                format!("{}/{}", parent, remote_filename),
                local_path.to_string(),
            ))
        } else {
            None
        };

        (parent.to_string(), rename)
    };

    eprintln!("[TAR] Extracting to: {}", extract_dir);

    std::fs::create_dir_all(&extract_dir).map_err(|e| {
        format!(
            "Failed to create extraction directory {}: {}",
            extract_dir, e
        )
    })?;

    // archive should starts with gzip magic bytes
    if result.stdout.len() < 2 || result.stdout[0] != 0x1f || result.stdout[1] != 0x8b {
        let preview: Vec<u8> = result.stdout.iter().take(64).cloned().collect();
        let preview_str = String::from_utf8_lossy(&preview);
        return Err(format!(
            "Remote tar output is not a valid gzip archive. First bytes: {:02x?}, as text: '{}'",
            &result.stdout[..std::cmp::min(16, result.stdout.len())],
            preview_str.chars().take(64).collect::<String>()
        ));
    }

    let mut tar_process = Command::new("tar")
        .args(&["xzf", "-", "-C", &extract_dir])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn tar extract: {}", e))?;

    const CHUNK_SIZE: usize = 32 * 1024; // 32KB good size same as copy host to vm
    let data = &result.stdout;
    let mut bytes_written = 0usize;

    if let Some(mut stdin) = tar_process.stdin.take() {
        for chunk in data.chunks(CHUNK_SIZE) {
            match stdin.write_all(chunk) {
                Ok(()) => {
                    bytes_written += chunk.len();
                }
                Err(e) => {
                    drop(stdin);
                    let output = tar_process.wait_with_output().ok();
                    let stderr = output
                        .as_ref()
                        .map(|o| String::from_utf8_lossy(&o.stderr).to_string())
                        .unwrap_or_default();
                    return Err(format!(
                        "Failed to write to tar stdin after {} of {} bytes: {}. Tar stderr: {}",
                        bytes_written,
                        data.len(),
                        e,
                        if stderr.is_empty() {
                            "(empty)"
                        } else {
                            &stderr
                        }
                    ));
                }
            }
        }
    }

    let output = tar_process
        .wait_with_output()
        .map_err(|e| format!("Failed to wait for tar: {}", e))?;

    if !output.status.success() {
        return Err(format!(
            "Local tar extraction failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    if let Some((from, to)) = need_rename {
        eprintln!("[TAR] Renaming {} to {}", from, to);
        std::fs::rename(&from, &to)
            .map_err(|e| format!("Failed to rename {} to {}: {}", from, to, e))?;
    }

    eprintln!("[TAR] VM-to-host transfer completed successfully");
    return Ok(());
}

fn expand_remote_tilde(path: &str, username: &str, os: GuestOs) -> String {
    let home = match os {
        GuestOs::Windows => format!("C:\\Users\\{}", username),
        GuestOs::MacOS => {
            if username == "root" {
                "/root".to_string()
            } else {
                format!("/Users/{}", username)
            }
        }
        _ => {
            if username == "root" {
                "/root".to_string()
            } else {
                format!("/home/{}", username)
            }
        }
    };

    if path == "~" {
        return home;
    } else if let Some(rest) = path.strip_prefix("~/") {
        let sep = if os == GuestOs::Windows { "\\" } else { "/" };
        return format!("{}{}{}", home, sep, rest);
    }
    return path.to_string();
}

fn parse_copy_paths<'a>(from: &'a str, to: &'a str) -> (CopyDirection, &'a str, &'a str) {
    let to_starts = to.starts_with("vm:");
    let from_starts = from.starts_with("vm:");
    if to_starts && from_starts {
        panic!("Cannot use SFTP to copy files from the VM to itself!");
    }
    if !to_starts && !from_starts {
        panic!("Cannot use SFTP to copy files from the host to itself!");
    }

    if to_starts {
        return (CopyDirection::HostToVm, from, &to[3..]);
    } else {
        return (CopyDirection::VmToHost, to, &from[3..]);
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

    let target_dir = if to.starts_with("vm:") { &to[3..] } else { &to };

    let convert_script = crlf_conversion_script();

    let convert_result = crate::run::command::run_command(
        ssh,
        convert_script,
        Some(target_dir),
        &std::collections::HashMap::new(),
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
