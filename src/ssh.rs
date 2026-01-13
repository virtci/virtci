use russh::keys::PrivateKeyWithHashAlg;
use russh::keys::ssh_key;
use russh::{ChannelMsg, client};
use russh_sftp::client::SftpSession;
use std::collections::HashMap;
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

const PORT_RANGE_START: u16 = 50000;
const PORT_RANGE_END: u16 = 60000;

/// Windows can take long as heck to boot. Wait timeout in seconds.
pub const SSH_WAIT_TIMEOUT: u64 = 150;

/// Seconds between SSH poll attempts. 2 seems pretty reasonable.
const SSH_POLL_INTERVAL: u64 = 2;

/// find available TCP port for SSH
pub fn find_available_port() -> Option<u16> {
    for port in PORT_RANGE_START..=PORT_RANGE_END {
        if is_port_available(port) {
            return Some(port);
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
                    Err(_e) => {
                    }
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
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(30)),
        ..Default::default()
    });

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

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_code: u32 = 0;

    loop {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) => stdout.extend_from_slice(&data),
            Some(ChannelMsg::ExtendedData { data, ext }) if ext == 1 => {
                stderr.extend_from_slice(&data)
            }
            Some(ChannelMsg::ExitStatus { exit_status }) => exit_code = exit_status,
            Some(ChannelMsg::Eof) | None => break,
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
        stdout: String::from_utf8_lossy(&stdout).to_string(),
        stderr: String::from_utf8_lossy(&stderr).to_string(),
    })
}

fn build_command(command: &str, workdir: Option<&str>, env: &HashMap<String, String>) -> String {
    let mut parts = Vec::new();

    for (key, value) in env {
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
        return (CopyDirection::VmToHost, &from[3..], to);
    }
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
            copy_host_to_vm(&sftp, local_path, remote_path, ignore).await?;
        }
        CopyDirection::VmToHost => {
            copy_vm_to_host(&sftp, remote_path, local_path, ignore).await?;
        }
    }

    sftp.close().await.map_err(|e| format!("Failed to close SFTP: {}", e))?;
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
                    let file_name = local.file_name()
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

    let mut file = sftp.create(remote_path)
        .await
        .map_err(|e| format!("Failed to create remote file {}: {}", remote_path, e))?;

    file.write_all(&contents)
        .await
        .map_err(|e| format!("Failed to write remote file {}: {}", remote_path, e))?;

    return Ok(());
}

async fn upload_dir_recursive(
    sftp: &SftpSession,
    local_dir: &Path,
    remote_dir: &str,
    ignore: &[String],
) -> Result<(), String> {
    if !sftp.try_exists(remote_dir).await.unwrap_or(false) {
        sftp.create_dir(remote_dir)
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
            Box::pin(upload_dir_recursive(sftp, &local_path, &remote_path, ignore)).await?;
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

async fn download_file(sftp: &SftpSession, remote_path: &str, local_path: &str) -> Result<(), String> {
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
    std::fs::create_dir_all(local_dir)
        .map_err(|e| format!("Failed to create local dir {}: {}", local_dir, e))?;

    let entries = sftp
        .read_dir(remote_dir)
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
            Box::pin(download_dir_recursive(sftp, &remote_path, &local_path, ignore)).await?;
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
        let port = find_available_port();
        assert!(port.is_some());
        let port = port.unwrap();
        assert!(port >= PORT_RANGE_START && port <= PORT_RANGE_END);
    }

    #[test]
    fn test_port_is_available() {
        let port = find_available_port().unwrap();
        let _listener = TcpListener::bind(("127.0.0.1", port)).unwrap();
        assert!(!is_port_available(port));
    }
}
