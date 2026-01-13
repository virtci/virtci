use russh::keys::PrivateKeyWithHashAlg;
use russh::keys::ssh_key;
use russh::{ChannelMsg, client};
use std::collections::HashMap;
use std::net::{TcpListener, TcpStream};
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
