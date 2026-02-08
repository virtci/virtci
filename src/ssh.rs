use crate::vm_image::{GuestOs, SshConfig};
use russh::keys::ssh_key;
use russh::keys::PrivateKeyWithHashAlg;
use russh::{client, ChannelMsg};
use std::collections::HashMap;
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct SshTarget {
    pub ip: String,
    pub port: u16,
    pub cred: SshConfig,
}

const PORT_RANGE_START: u16 = 50000;
const PORT_RANGE_END: u16 = 60000;

/// Windows can take long as heck to boot. Wait timeout in seconds.
pub const SSH_WAIT_TIMEOUT: u64 = 300;

/// Seconds between SSH poll attempts. 2 seems pretty reasonable.
const SSH_POLL_INTERVAL: u64 = 2;

pub fn find_available_port() -> Option<(u16, std::fs::File)> {
    for port in PORT_RANGE_START..=PORT_RANGE_END {
        let lock_path = get_port_lock_path(port);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true) // fail if file exists
            .open(&lock_path)
        {
            Ok(lock_file) => {
                return Some((port, lock_file));
            }
            Err(_) => {
                continue;
            }
        }
    }
    return None;
}

fn get_port_lock_path(port: u16) -> std::path::PathBuf {
    let temp_dir = std::env::temp_dir();
    temp_dir.join(format!("vci-port-{}.lock", port))
}

pub fn cleanup_stale_port_locks() {
    let temp_dir = std::env::temp_dir();
    let one_hour_ago = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(3600))
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH);

    if let Ok(entries) = std::fs::read_dir(&temp_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if name.starts_with("vci-port-") && name.ends_with(".lock") {
                    // Only delete if file is very old (likely from crash)
                    if let Ok(metadata) = std::fs::metadata(&path) {
                        if let Ok(modified) = metadata.modified() {
                            if modified < one_hour_ago {
                                let _ = std::fs::remove_file(&path);
                            }
                        }
                    }
                }
            }
        }
    }
}

fn is_port_available(port: u16) -> bool {
    return TcpListener::bind(("127.0.0.1", port)).is_ok();
}

pub fn wait_for_ssh(port: u16, timeout_secs: u64) -> Option<u64> {
    use std::io::{BufRead, BufReader};

    let timeout = Duration::from_secs(timeout_secs);
    let poll_interval = Duration::from_secs(SSH_POLL_INTERVAL);
    let connect_timeout = Duration::from_secs(5);
    let start = Instant::now();

    loop {
        let elapsed = start.elapsed();
        if elapsed >= timeout {
            return None;
        }

        let addr = format!("127.0.0.1:{}", port);
        match TcpStream::connect_timeout(&addr.parse().unwrap(), connect_timeout) {
            Ok(stream) => {
                // QEMU can make the SSH "available" even while the VM is still booting.
                // So must check for a "banner" thingy such as "SSH-2.0-OpenSSH_8.9"
                stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                let mut reader = BufReader::new(stream);
                let mut banner = String::new();
                match reader.read_line(&mut banner) {
                    Ok(_n) => {
                        if banner.starts_with("SSH-") {
                            return Some(elapsed.as_secs());
                        }
                    }
                    Err(_e) => {}
                }
                std::thread::sleep(poll_interval);
            }
            Err(_e) => {
                std::thread::sleep(poll_interval);
            }
        }
    }
}

// Who let Tokio be a thing? Who permitted this??

pub enum SshAuth {
    Password(String),
    Key(String), // path to private key file
}

pub struct SshCredentials {
    pub user: String,
    pub auth: SshAuth,
}

pub struct CommandResult {
    pub exit_code: u32,
    pub stdout: String,
    pub stderr: String,
}

pub struct BinaryCommandResult {
    pub exit_code: u32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

struct ClientHandler;

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    fn check_server_key(
        &mut self,
        _key: &ssh_key::PublicKey,
    ) -> impl std::future::Future<Output = Result<bool, Self::Error>> + Send {
        async { Ok(true) }
    }
}

async fn connect(
    port: u16,
    creds: &SshCredentials,
) -> Result<client::Handle<ClientHandler>, String> {
    let mut config = client::Config {
        inactivity_timeout: Some(Duration::from_secs(30)),
        ..Default::default()
    };

    // https://github.com/Eugeny/tabby/issues/10780
    config.preferred.compression = (&[russh::compression::NONE]).into();

    let config = Arc::new(config);

    let addr = format!("127.0.0.1:{}", port);
    let mut handle = client::connect(config, &addr, ClientHandler)
        .await
        .map_err(|e| format!("SSH connection failed: {}", e))?;

    let auth_result = match &creds.auth {
        SshAuth::Password(pass) => handle
            .authenticate_password(&creds.user, pass)
            .await
            .map_err(|e| format!("Password auth failed: {}", e))?,
        SshAuth::Key(key_path) => {
            let key_data = std::fs::read_to_string(key_path)
                .map_err(|e| format!("Failed to read key file: {}", e))?;
            let key_pair = russh::keys::decode_secret_key(&key_data, None)
                .map_err(|e| format!("Failed to decode key: {}", e))?;
            let key = PrivateKeyWithHashAlg::new(Arc::new(key_pair), None);
            handle
                .authenticate_publickey(&creds.user, key)
                .await
                .map_err(|e| format!("Key auth failed: {}", e))?
        }
    };

    if !matches!(auth_result, russh::client::AuthResult::Success) {
        return Err("Authentication rejected".to_string());
    }

    Ok(handle)
}

pub async fn detect_guest_os(port: u16, creds: &SshCredentials) -> GuestOs {
    for attempt in 1..=3 {
        if attempt > 1 {
            eprintln!("[OS Detection] Retry attempt {}/3", attempt);
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        }

        match run_command(port, creds, "$env:OS", None, &HashMap::new()).await {
            Ok(result) => {
                if result.stdout.trim().contains("Windows_NT") {
                    eprintln!("[OS Detection] Detected: Windows (attempt {})", attempt);
                    return GuestOs::Windows;
                }
                break;
            }
            Err(e) => {
                eprintln!(
                    "[OS Detection] Windows check failed (attempt {}): {}",
                    attempt, e
                );
                if attempt == 3 {
                    break;
                }
            }
        }
    }

    if let Ok(result) = run_command(port, creds, "uname", None, &HashMap::new()).await {
        let output = result.stdout.trim();
        if output.contains("Linux") {
            eprintln!("[OS Detection] Detected: Linux");
            return GuestOs::Linux;
        } else if output.contains("Darwin") {
            eprintln!("[OS Detection] Detected: macOS");
            return GuestOs::MacOS;
        }
    }

    eprintln!("[OS Detection] Could not detect OS, assuming Unknown");
    GuestOs::Other
}

pub async fn run_command(
    port: u16,
    creds: &SshCredentials,
    command: &str,
    workdir: Option<&str>,
    env: &HashMap<String, String>,
) -> Result<CommandResult, String> {
    run_command_with_os(port, creds, command, workdir, env, None).await
}

pub async fn run_command_with_os(
    port: u16,
    creds: &SshCredentials,
    command: &str,
    workdir: Option<&str>,
    env: &HashMap<String, String>,
    guest_os: Option<GuestOs>,
) -> Result<CommandResult, String> {
    let handle = connect(port, creds).await?;

    let mut channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("Failed to open channel: {}", e))?;

    let full_command = build_command(command, workdir, env, guest_os);

    channel
        .exec(true, full_command)
        .await
        .map_err(|e| format!("Failed to exec: {}", e))?;

    let mut stdout_str = String::new();
    let mut stderr_str = String::new();
    let mut exit_code: u32 = 0;
    let mut got_exit_status = false;

    loop {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) => {
                let s = String::from_utf8_lossy(&data);
                print!("{}", s);
                std::io::Write::flush(&mut std::io::stdout()).ok();
                stdout_str.push_str(&s);
            }
            Some(ChannelMsg::ExtendedData { data, ext }) if ext == 1 => {
                let s = String::from_utf8_lossy(&data);
                eprint!("{}", s);
                std::io::Write::flush(&mut std::io::stderr()).ok();
                stderr_str.push_str(&s);
            }
            Some(ChannelMsg::ExitStatus { exit_status }) => {
                exit_code = exit_status;
                got_exit_status = true;
            }
            Some(ChannelMsg::Eof) => {}
            None => {
                if got_exit_status {
                    break;
                }
            }
            _ => {}
        }
    }

    channel.close().await.ok();
    handle
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await
        .ok();

    Ok(CommandResult {
        exit_code,
        stdout: stdout_str,
        stderr: stderr_str,
    })
}

pub async fn run_command_binary(
    port: u16,
    creds: &SshCredentials,
    command: &str,
    workdir: Option<&str>,
    env: &HashMap<String, String>,
    guest_os: Option<GuestOs>,
) -> Result<BinaryCommandResult, String> {
    let handle = connect(port, creds).await?;

    let mut channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("Failed to open channel: {}", e))?;

    let full_command = build_command(command, workdir, env, guest_os);

    channel
        .exec(true, full_command)
        .await
        .map_err(|e| format!("Failed to exec: {}", e))?;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_code: u32 = 0;
    let mut got_exit_status = false;

    loop {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) => stdout.extend_from_slice(&data),
            Some(ChannelMsg::ExtendedData { data, ext }) if ext == 1 => {
                stderr.extend_from_slice(&data)
            }
            Some(ChannelMsg::ExitStatus { exit_status }) => {
                exit_code = exit_status;
                got_exit_status = true;
            }
            Some(ChannelMsg::Eof) => {}
            None => {
                if got_exit_status {
                    break;
                }
            }
            _ => {}
        }
    }

    channel.close().await.ok();
    handle
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await
        .ok();

    Ok(BinaryCommandResult {
        exit_code,
        stdout,
        stderr,
    })
}

fn build_command(
    command: &str,
    workdir: Option<&str>,
    env: &HashMap<String, String>,
    guest_os: Option<GuestOs>,
) -> String {
    let mut parts = Vec::new();

    let is_windows = matches!(guest_os, Some(GuestOs::Windows));
    let separator = if is_windows { "; " } else { " && " };

    for (key, value) in env {
        if !is_valid_env_key(key) {
            continue;
        }

        if is_windows {
            let escaped = value.replace("'", "''");
            parts.push(format!("$env:{}='{}'", key, escaped));
        } else {
            let escaped = value.replace("'", "'\\''");
            parts.push(format!("export {}='{}'", key, escaped));
        }
    }

    // do in the VM workdir
    if let Some(dir) = workdir {
        if dir.starts_with("~/") {
            let path_after_tilde = &dir[2..];
            let escaped = path_after_tilde
                .replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("$", "\\$");
            parts.push(format!("cd \"$HOME/{}\"", escaped));
        } else if dir == "~" {
            parts.push("cd \"$HOME\"".to_string());
        } else {
            parts.push(format!("cd '{}'", dir.replace("'", "'\\''")));
        }
    }

    parts.push(command.to_string());
    parts.join(separator)
}

fn is_valid_env_key(key: &str) -> bool {
    if key.is_empty() {
        return false;
    }

    let mut chars = key.chars();
    let first = chars.next().unwrap();
    if !first.is_ascii_alphabetic() && first != '_' {
        return false;
    }

    for c in chars {
        if !c.is_ascii_alphanumeric() && c != '_' {
            return false;
        }
    }

    true
}

pub enum CopyDirection {
    HostToVm,
    VmToHost,
}

/// "vm:" prefix means its a directory in the VM
pub fn parse_copy_paths<'a>(from: &'a str, to: &'a str) -> (CopyDirection, &'a str, &'a str) {
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

fn expand_remote_tilde(path: &str, username: &str, guest_os: Option<GuestOs>) -> String {
    if path == "~" {
        if username == "root" {
            return "/root".to_string();
        } else {
            let home_base = if matches!(guest_os, Some(GuestOs::MacOS)) {
                "/Users"
            } else {
                "/home"
            };
            return format!("{}/{}", home_base, username);
        }
    } else if let Some(rest) = path.strip_prefix("~/") {
        if username == "root" {
            return format!("/root/{}", rest);
        } else {
            let home_base = if matches!(guest_os, Some(GuestOs::MacOS)) {
                "/Users"
            } else {
                "/home"
            };
            return format!("{}/{}/{}", home_base, username, rest);
        }
    }
    return path.to_string();
}

pub async fn copy_files_tar(
    port: u16,
    creds: &SshCredentials,
    from: &str,
    to: &str,
    ignore: &[String],
    guest_os: Option<GuestOs>,
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
        CopyDirection::HostToVm => expand_remote_tilde(remote_path, &creds.user, guest_os),
        CopyDirection::VmToHost => expand_remote_tilde(remote_path, &creds.user, guest_os),
    };

    match direction {
        CopyDirection::HostToVm => {
            copy_host_to_vm_tar(port, creds, local_path, &remote_path, ignore).await
        }
        CopyDirection::VmToHost => {
            copy_vm_to_host_tar(port, creds, &remote_path, local_path, ignore, guest_os).await
        }
    }
}

/// Tar is on windows now by default
async fn copy_host_to_vm_tar(
    port: u16,
    creds: &SshCredentials,
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

    let handle = connect(port, creds).await?;

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
    let mut sent_bytes = 0;
    let chunk_size = 32768; // 32KB
    let mut eof_sent = false;
    let mut done = false;

    while !done {
        if sent_bytes < tar_data.len() {
            let end = std::cmp::min(sent_bytes + chunk_size, tar_data.len());
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
            Ok(Some(ChannelMsg::ExitStatus { exit_status })) => exit_code = exit_status,
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
    port: u16,
    creds: &SshCredentials,
    remote_path: &str,
    local_path: &str,
    ignore: &[String],
    guest_os: Option<GuestOs>,
) -> Result<(), String> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    // Check if remote_path is a file or directory
    // Use PowerShell syntax for Windows, bash for Unix
    let test_cmd = if matches!(guest_os, Some(GuestOs::Windows)) {
        format!("if (Test-Path -Path \"{}\" -PathType Container) {{ Write-Output \"DIR\" }} else {{ Write-Output \"FILE\" }}", remote_path)
    } else {
        format!("test -d \"{}\" && echo DIR || echo FILE", remote_path)
    };
    let test_result = run_command(
        port,
        creds,
        &test_cmd,
        None,
        &std::collections::HashMap::new(),
    )
    .await?;
    let is_dir = test_result.stdout.trim() == "DIR";

    // powershell may corrupt tar binary data??
    let is_windows = matches!(guest_os, Some(GuestOs::Windows));

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

    let result = run_command_binary(
        port,
        creds,
        &tar_cmd,
        None,
        &std::collections::HashMap::new(),
        guest_os,
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

    const CHUNK_SIZE: usize = 64 * 1024; // 64KB good size
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_available_port() {
        let result = find_available_port();
        assert!(result.is_some());
        let (port, _listener) = result.unwrap();
        assert!(port >= PORT_RANGE_START && port <= PORT_RANGE_END);
    }

    #[test]
    fn test_port_is_available() {
        let (port, _listener) = find_available_port().unwrap();
        assert!(!is_port_available(port));
        drop(_listener);
        assert!(is_port_available(port));
    }
}
