use russh::keys::ssh_key;
use russh::keys::PrivateKeyWithHashAlg;
use russh::{client, ChannelMsg};
use russh_sftp::client::SftpSession;
use russh_sftp::protocol::OpenFlags;
use std::collections::HashMap;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestOs {
    Windows,
    Linux,
    MacOS,
    Unknown,
}

const PORT_RANGE_START: u16 = 50000;
const PORT_RANGE_END: u16 = 60000;

/// Windows can take long as heck to boot. Wait timeout in seconds.
pub const SSH_WAIT_TIMEOUT: u64 = 300;

/// Seconds between SSH poll attempts. 2 seems pretty reasonable.
const SSH_POLL_INTERVAL: u64 = 2;

/// Retains connection
pub fn find_available_port() -> Option<(u16, TcpListener)> {
    for port in PORT_RANGE_START..=PORT_RANGE_END {
        if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)) {
            return Some((port, listener));
        }
    }
    return None;
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
    // Powershell usage is assumed nowadays, so try this
    if let Ok(result) = run_command(port, creds, "$env:OS", None, &HashMap::new()).await {
        if result.stdout.trim().contains("Windows_NT") {
            eprintln!("[OS Detection] Detected: Windows");
            return GuestOs::Windows;
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
    GuestOs::Unknown
}

pub async fn run_command(
    port: u16,
    creds: &SshCredentials,
    command: &str,
    workdir: Option<&str>,
    env: &HashMap<String, String>,
) -> Result<CommandResult, String> {
    let handle = connect(port, creds).await?;

    let mut channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("Failed to open channel: {}", e))?;

    let full_command = build_command(command, workdir, env);

    channel
        .exec(true, full_command)
        .await
        .map_err(|e| format!("Failed to exec: {}", e))?;

    let mut stdout_str = String::new();
    let mut stderr_str = String::new();
    let mut exit_code: u32 = 0;
    let mut got_exit_status = false;
    let mut got_eof = false;

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
            Some(ChannelMsg::Eof) => {
                got_eof = true;
            }
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
) -> Result<BinaryCommandResult, String> {
    let handle = connect(port, creds).await?;

    let mut channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("Failed to open channel: {}", e))?;

    let full_command = build_command(command, workdir, env);

    channel
        .exec(true, full_command)
        .await
        .map_err(|e| format!("Failed to exec: {}", e))?;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_code: u32 = 0;
    let mut got_exit_status = false;
    let mut got_eof = false;

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
            Some(ChannelMsg::Eof) => {
                got_eof = true;
            }
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

fn build_command(command: &str, workdir: Option<&str>, env: &HashMap<String, String>) -> String {
    let mut parts = Vec::new();

    for (key, value) in env {
        if !is_valid_env_key(key) {
            continue;
        }
        let escaped = value.replace("'", "'\\''");
        parts.push(format!("export {}='{}'", key, escaped));
    }

    // do in the VM workdir
    if let Some(dir) = workdir {
        parts.push(format!("cd '{}'", dir.replace("'", "'\\''")));
    }

    parts.push(command.to_string());
    parts.join(" && ")
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

fn expand_remote_tilde(path: &str, username: &str) -> String {
    if path == "~" {
        if username == "root" {
            return "/root".to_string();
        } else {
            return format!("/home/{}", username);
        }
    } else if let Some(rest) = path.strip_prefix("~/") {
        if username == "root" {
            return format!("/root/{}", rest);
        } else {
            return format!("/home/{}/{}", username, rest);
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
) -> Result<(), String> {
    let (direction, local_path, remote_path) = parse_copy_paths(from, to);

    let remote_path = match direction {
        CopyDirection::HostToVm => expand_remote_tilde(remote_path, &creds.user),
        CopyDirection::VmToHost => expand_remote_tilde(remote_path, &creds.user),
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
    use tokio::io::AsyncWriteExt;

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

    // Build tar command with exclusions on remote
    let mut exclude_args = String::new();
    for pattern in ignore {
        exclude_args.push_str(&format!(" --exclude=\"{}\"", pattern));
    }

    let tar_cmd = if is_dir {
        // For directories: tar from within the directory
        format!("tar czf - -C \"{}\"{} .", remote_path, exclude_args)
    } else {
        // For files: tar from parent directory with specific filename
        let path = std::path::Path::new(remote_path);
        let parent = path.parent().and_then(|p| p.to_str()).unwrap_or(".");
        let filename = path
            .file_name()
            .and_then(|f| f.to_str())
            .ok_or_else(|| format!("Invalid filename in path: {}", remote_path))?;

        format!(
            "tar czf - -C \"{}\"{} \"{}\"",
            parent, exclude_args, filename
        )
    };

    eprintln!("[TAR] Creating archive from remote: {}", remote_path);
    eprintln!("[TAR] Remote command: {}", tar_cmd);

    let result = run_command_binary(
        port,
        creds,
        &tar_cmd,
        None,
        &std::collections::HashMap::new(),
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

    let mut tar_process = Command::new("tar")
        .args(&["xzf", "-", "-C", &extract_dir])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to spawn tar extract: {}", e))?;

    if let Some(mut stdin) = tar_process.stdin.take() {
        stdin
            .write_all(&result.stdout)
            .map_err(|e| format!("Failed to write to tar stdin: {}", e))?;
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

/// SFTP file / dir copy
pub async fn copy_files(
    port: u16,
    creds: &SshCredentials,
    from: &str,
    to: &str,
    ignore: &[String],
) -> Result<(), String> {
    let (direction, local_path, remote_path) = parse_copy_paths(from, to);

    let remote_path = match direction {
        CopyDirection::HostToVm => expand_remote_tilde(remote_path, &creds.user),
        CopyDirection::VmToHost => expand_remote_tilde(remote_path, &creds.user),
    };

    let remote_path = normalize_sftp_path(&remote_path);

    let handle = connect(port, creds).await?;

    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("Failed to open SFTP channel: {}", e))?;

    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| format!("Failed to request SFTP subsystem: {}", e))?;

    let sftp = SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| format!("Failed to create SFTP session: {}", e))?;

    match direction {
        CopyDirection::HostToVm => {
            copy_host_to_vm(&sftp, local_path, &remote_path, ignore).await?;
        }
        CopyDirection::VmToHost => {
            copy_vm_to_host(&sftp, &remote_path, local_path, ignore).await?;
        }
    }

    sftp.close()
        .await
        .map_err(|e| format!("Failed to close SFTP: {}", e))?;
    handle
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await
        .ok();

    Ok(())
}

async fn copy_host_to_vm(
    sftp: &SftpSession,
    local_path: &str,
    remote_path: &str,
    ignore: &[String],
) -> Result<(), String> {
    let local = Path::new(local_path);

    if !local.exists() {
        return Err(format!("Local path does not exist: {}", local_path));
    }

    if local.is_file() {
        // if remote is a directory, sending a file should go into the remote directory
        let final_remote = if sftp.try_exists(remote_path).await.unwrap_or(false) {
            if let Ok(meta) = sftp.metadata(remote_path).await {
                if meta.is_dir() {
                    let file_name = local
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| "file".to_string());
                    format!("{}/{}", remote_path.trim_end_matches('/'), file_name)
                } else {
                    remote_path.to_string()
                }
            } else {
                remote_path.to_string()
            }
        } else {
            remote_path.to_string()
        };
        upload_file(sftp, local, &final_remote).await
    } else if local.is_dir() {
        upload_dir_recursive(sftp, local, remote_path, ignore).await
    } else {
        Err(format!("Unsupported file type: {}", local_path))
    }
}

async fn upload_file(sftp: &SftpSession, local: &Path, remote_path: &str) -> Result<(), String> {
    use tokio::io::AsyncWriteExt;

    let contents = std::fs::read(local)
        .map_err(|e| format!("Failed to read local file {:?}: {}", local, e))?;

    // https://github.com/Eugeny/russh/blob/main/russh/examples/sftp_client.rs
    let mut file = sftp
        .open_with_flags(
            remote_path,
            OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE | OpenFlags::READ,
        )
        .await
        .map_err(|e| format!("Failed to open remote file {}: {:?}", remote_path, e))?;

    file.write_all(&contents)
        .await
        .map_err(|e| format!("Failed to write_all remote file {}: {:?}", remote_path, e))?;

    file.flush()
        .await
        .map_err(|e| format!("Failed to flush remote file {}: {:?}", remote_path, e))?;

    file.shutdown()
        .await
        .map_err(|e| format!("Failed to shutdown remote file {}: {:?}", remote_path, e))?;

    return Ok(());
}

fn normalize_sftp_path(path: &str) -> String {
    // apparently SFTP always uses forward slashes, even on Windows?
    path.replace('\\', "/")
}

async fn upload_dir_recursive(
    sftp: &SftpSession,
    local_dir: &Path,
    remote_dir: &str,
    ignore: &[String],
) -> Result<(), String> {
    let remote_dir = normalize_sftp_path(remote_dir);

    if !sftp.try_exists(&remote_dir).await.unwrap_or(false) {
        sftp.create_dir(&remote_dir)
            .await
            .map_err(|e| format!("Failed to create remote dir {}: {}", remote_dir, e))?;
    }

    let entries = std::fs::read_dir(local_dir)
        .map_err(|e| format!("Failed to read local dir {:?}: {}", local_dir, e))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("Failed to read dir entry: {}", e))?;
        let local_path = entry.path();
        let file_name = entry.file_name();
        let file_name_str = file_name.to_string_lossy();

        if should_ignore(&file_name_str, ignore) {
            continue;
        }

        let remote_path = format!("{}/{}", remote_dir.trim_end_matches('/'), file_name_str);

        if local_path.is_file() {
            upload_file(sftp, &local_path, &remote_path).await?;
        } else if local_path.is_dir() {
            Box::pin(upload_dir_recursive(
                sftp,
                &local_path,
                &remote_path,
                ignore,
            ))
            .await?;
        }
    }

    return Ok(());
}

async fn copy_vm_to_host(
    sftp: &SftpSession,
    remote_path: &str,
    local_path: &str,
    ignore: &[String],
) -> Result<(), String> {
    let metadata = sftp
        .metadata(remote_path)
        .await
        .map_err(|e| format!("Failed to get remote metadata for {}: {}", remote_path, e))?;

    if metadata.is_dir() {
        download_dir_recursive(sftp, remote_path, local_path, ignore).await
    } else {
        // if the remote is a file, it should be able to go into a host directory
        let local = Path::new(local_path);
        let final_local = if local.is_dir() {
            let file_name = Path::new(remote_path)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "file".to_string());
            format!("{}/{}", local_path.trim_end_matches('/'), file_name)
        } else {
            local_path.to_string()
        };
        download_file(sftp, remote_path, &final_local).await
    }
}

async fn download_file(
    sftp: &SftpSession,
    remote_path: &str,
    local_path: &str,
) -> Result<(), String> {
    let contents = sftp
        .read(remote_path)
        .await
        .map_err(|e| format!("Failed to read remote file {}: {}", remote_path, e))?;

    if let Some(parent) = Path::new(local_path).parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create local dir {:?}: {}", parent, e))?;
    }

    std::fs::write(local_path, contents)
        .map_err(|e| format!("Failed to write local file {}: {}", local_path, e))?;

    return Ok(());
}

async fn download_dir_recursive(
    sftp: &SftpSession,
    remote_dir: &str,
    local_dir: &str,
    ignore: &[String],
) -> Result<(), String> {
    let remote_dir = normalize_sftp_path(remote_dir);

    std::fs::create_dir_all(local_dir)
        .map_err(|e| format!("Failed to create local dir {}: {}", local_dir, e))?;

    let entries = sftp
        .read_dir(&remote_dir)
        .await
        .map_err(|e| format!("Failed to read remote dir {}: {}", remote_dir, e))?;

    for entry in entries {
        let file_name = entry.file_name();

        // TODO should skip . and ..?
        if file_name == "." || file_name == ".." {
            continue;
        }

        if should_ignore(&file_name, ignore) {
            continue;
        }

        let remote_path = format!("{}/{}", remote_dir.trim_end_matches('/'), file_name);
        let local_path = format!("{}/{}", local_dir.trim_end_matches('/'), file_name);

        let metadata = sftp
            .metadata(&remote_path)
            .await
            .map_err(|e| format!("Failed to get metadata for {}: {}", remote_path, e))?;

        if metadata.is_dir() {
            Box::pin(download_dir_recursive(
                sftp,
                &remote_path,
                &local_path,
                ignore,
            ))
            .await?;
        } else {
            download_file(sftp, &remote_path, &local_path).await?;
        }
    }

    Ok(())
}

fn should_ignore(filename: &str, patterns: &[String]) -> bool {
    for pattern in patterns {
        if pattern_matches(filename, pattern) {
            return true;
        }
    }
    false
}

fn pattern_matches(filename: &str, pattern: &str) -> bool {
    if pattern == filename {
        return true;
    }

    // *.ext pattern
    if pattern.starts_with('*') {
        let suffix = &pattern[1..];
        if filename.ends_with(suffix) {
            return true;
        }
    }

    // prefix* pattern
    if pattern.ends_with('*') {
        let prefix = &pattern[..pattern.len() - 1];
        if filename.starts_with(prefix) {
            return true;
        }
    }

    false
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
