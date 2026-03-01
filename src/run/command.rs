// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::collections::HashMap;

use russh::ChannelMsg;

use crate::{run::connect, vm_image::GuestOs, vm_image::SshTarget};

pub struct CommandResult {
    pub exit_code: u32,
    pub stdout: String,
    #[allow(dead_code)]
    pub stderr: String,
}

pub struct BinaryCommandResult {
    pub exit_code: u32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub async fn run_command(
    ssh: &SshTarget,
    command: &str,
    workdir: Option<&str>,
    env: &HashMap<String, String>,
    os: GuestOs,
) -> Result<CommandResult, String> {
    let handle = connect(ssh).await?;

    let mut channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("Failed to open channel: {e}"))?;

    let full_command = build_command(command, workdir, env, os);

    channel
        .exec(true, full_command)
        .await
        .map_err(|e| format!("Failed to exec: {e}"))?;

    let mut stdout_str = String::new();
    let mut stderr_str = String::new();
    let mut exit_code: u32 = 0;
    let mut got_exit_status = false;

    loop {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) => {
                let s = String::from_utf8_lossy(&data);
                print!("{s}");
                std::io::Write::flush(&mut std::io::stdout()).ok();
                stdout_str.push_str(&s);
            }
            Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                let s = String::from_utf8_lossy(&data);
                eprint!("{s}");
                std::io::Write::flush(&mut std::io::stderr()).ok();
                stderr_str.push_str(&s);
            }
            Some(ChannelMsg::ExitStatus { exit_status }) => {
                exit_code = exit_status;
                got_exit_status = true;
            }
            None => {
                break;
            }
            _ => {}
        }
    }

    channel.close().await.ok();
    handle
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await
        .ok();

    if !got_exit_status {
        return Err("SSH channel closed without providing an exit status".to_string());
    }

    Ok(CommandResult {
        exit_code,
        stdout: stdout_str,
        stderr: stderr_str,
    })
}

fn build_command(
    command: &str,
    workdir: Option<&str>,
    env: &HashMap<String, String>,
    guest_os: GuestOs,
) -> String {
    let mut parts = Vec::new();

    let is_windows = guest_os == GuestOs::Windows;
    let separator = if is_windows { "; " } else { " && " };

    for (key, value) in env {
        if !is_valid_env_key(key) {
            continue;
        }

        if is_windows {
            let escaped = value.replace('\'', "''");
            parts.push(format!("$env:{key}='{escaped}'"));
        } else {
            let escaped = value.replace('\'', "'\\''");
            parts.push(format!("export {key}='{escaped}'"));
        }
    }

    // do in the VM workdir
    if let Some(dir) = workdir {
        if let Some(path_after_tilde) = dir.strip_prefix("~/") {
            let escaped = path_after_tilde
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('$', "\\$");
            parts.push(format!("cd \"$HOME/{escaped}\""));
        } else if dir == "~" {
            parts.push("cd \"$HOME\"".to_string());
        } else {
            parts.push(format!("cd '{}'", dir.replace('\'', "'\\''")));
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

pub async fn run_command_binary(
    ssh: &SshTarget,
    command: &str,
    workdir: Option<&str>,
    env: &HashMap<String, String>,
    os: GuestOs,
) -> Result<BinaryCommandResult, String> {
    let handle = connect(ssh).await?;

    let mut channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("Failed to open channel: {e}"))?;

    let full_command = build_command(command, workdir, env, os);

    channel
        .exec(true, full_command)
        .await
        .map_err(|e| format!("Failed to exec: {e}"))?;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_code: u32 = 0;
    let mut got_exit_status = false;

    loop {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) => stdout.extend_from_slice(&data),
            Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                stderr.extend_from_slice(&data);
            }
            Some(ChannelMsg::ExitStatus { exit_status }) => {
                exit_code = exit_status;
                got_exit_status = true;
            }
            None => {
                break;
            }
            _ => {}
        }
    }

    channel.close().await.ok();
    handle
        .disconnect(russh::Disconnect::ByApplication, "", "en")
        .await
        .ok();

    if !got_exit_status {
        return Err("SSH channel closed without providing an exit status".to_string());
    }

    Ok(BinaryCommandResult {
        exit_code,
        stdout,
        stderr,
    })
}
