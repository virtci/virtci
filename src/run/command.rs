// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::collections::HashMap;
use std::time::{Duration, Instant};

use russh::ChannelMsg;
use russh::client;

use crate::{
    run::{ClientHandler, connect_resilient},
    vm_image::GuestOs,
    vm_image::SshTarget,
};

/// Exit code of GNU timeout.
pub const TIMEOUT_EXIT_CODE: u32 = 124;

/// How to enforce a timeout inside the VM itself, rather than orphaning. Also works with host-side
/// tokio timeout. Use [`probe_timeout_mechanism`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeoutMechanism {
    ///  `timeout(1)` GNU coreutils, busybox, bsd.
    Timeout,
    /// macOS basically. `set -m`.
    BashJobControl,
    /// `taskkill /T`.
    WindowsTaskkill,
    /// No in-VM timeout mechanism
    Unwrapped,
}

pub async fn probe_timeout_mechanism(ssh: &SshTarget, os: GuestOs) -> TimeoutMechanism {
    if os == GuestOs::Windows {
        return TimeoutMechanism::WindowsTaskkill;
    }
    // Prints "t" if `timeout` exists and/or "b" if `bash` exists.
    let probe = "command -v timeout >/dev/null 2>&1 && printf t; \
                 command -v bash >/dev/null 2>&1 && printf b";
    match run_command(ssh, probe, None, &HashMap::new(), os).await {
        Ok(res) if res.stdout.contains('t') => TimeoutMechanism::Timeout,
        Ok(res) if res.stdout.contains('b') => TimeoutMechanism::BashJobControl,
        _ => TimeoutMechanism::Unwrapped,
    }
}

fn posix_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Wrap a command so it can be forcekilled after `secs` seconds. Returns the command
/// unchanged for [`TimeoutMechanism::Unwrapped`] or a non-positive timeout. On expiry the wrapper
/// exits [`TIMEOUT_EXIT_CODE`].
pub fn wrap_with_timeout(user_cmd: &str, secs: u64, mech: TimeoutMechanism) -> String {
    if secs == 0 || mech == TimeoutMechanism::Unwrapped {
        return user_cmd.to_string();
    }
    match mech {
        TimeoutMechanism::Timeout => {
            format!(
                "timeout -k 5 {secs} /bin/sh -c {}",
                posix_single_quote(user_cmd)
            )
        }
        TimeoutMechanism::BashJobControl => {
            let watchdog = format!(
                "set -m; f=$(mktemp); ( exec /bin/sh -c \"$1\" ) & c=$!; \
                 ( sleep {secs}; : > \"$f\"; kill -TERM -\"$c\" 2>/dev/null; sleep 5; \
                 kill -KILL -\"$c\" 2>/dev/null ) & w=$!; wait \"$c\"; s=$?; \
                 kill \"$w\" 2>/dev/null; kill -- -\"$w\" 2>/dev/null; \
                 if [ -s \"$f\" ]; then rm -f \"$f\"; exit {TIMEOUT_EXIT_CODE}; fi; rm -f \"$f\"; exit \"$s\""
            );
            format!("bash -c '{watchdog}' _ {}", posix_single_quote(user_cmd))
        }
        TimeoutMechanism::WindowsTaskkill => windows_timeout_wrapper(user_cmd, secs),
        TimeoutMechanism::Unwrapped => user_cmd.to_string(),
    }
}

fn windows_timeout_wrapper(user_cmd: &str, secs: u64) -> String {
    format!(
        "$__vciTo = {secs}; $__vciSelf = $PID; \
         $__vciFlag = Join-Path $env:TEMP ('vci_to_' + [guid]::NewGuid().ToString('N')); \
         $__vciWd = Start-Job -ScriptBlock {{ \
         Start-Sleep -Seconds $using:__vciTo; \
         New-Item -ItemType File -Force -Path $using:__vciFlag | Out-Null; \
         Get-CimInstance Win32_Process -Filter ('ParentProcessId=' + $using:__vciSelf) | \
         Where-Object {{ $_.ProcessId -ne $PID }} | \
         ForEach-Object {{ & taskkill /T /F /PID $_.ProcessId 2>$null | Out-Null }} }}; \
         try {{ {user_cmd}; $__vciCode = $LASTEXITCODE; if ($null -eq $__vciCode) {{ $__vciCode = 0 }} }} \
         finally {{ Stop-Job $__vciWd -ErrorAction SilentlyContinue; \
         Remove-Job $__vciWd -Force -ErrorAction SilentlyContinue }}; \
         if (Test-Path $__vciFlag) {{ Remove-Item $__vciFlag -Force -ErrorAction SilentlyContinue; \
         exit {TIMEOUT_EXIT_CODE} }}; exit $__vciCode"
    )
}

#[derive(Default)]
struct ChannelOutcome {
    saw_eof: bool,
    saw_close: bool,
    exit_signal: Option<String>,
    bytes: usize,
}

async fn diagnose_missing_exit_status(
    handle: &client::Handle<ClientHandler>,
    outcome: &ChannelOutcome,
    elapsed: Duration,
) -> String {
    let transport = match tokio::time::timeout(
        Duration::from_secs(10),
        handle.channel_open_session(),
    )
    .await
    {
        Ok(Ok(_)) => {
            "transport still alive (a fresh session opened) and only this channel was closed \
                      by the server, no exit-status was sent"
                .to_string()
        }
        Ok(Err(e)) => format!(
            "transport is dead (opening a fresh session failed: {e}) and the SSH connection itself \
             dropped, not just the channel"
        ),
        Err(_) => "transport is dead (opening a fresh session hung >10s) since the SSH connection \
                   itself is wedged"
            .to_string(),
    };

    let mut seen = Vec::new();
    if outcome.saw_eof {
        seen.push("EOF".to_string());
    }
    if outcome.saw_close {
        seen.push("Close".to_string());
    }
    if let Some(sig) = &outcome.exit_signal {
        seen.push(format!("ExitSignal({sig})"));
    }
    let seen = if seen.is_empty() {
        "none (channel went straight to closed)".to_string()
    } else {
        seen.join(", ")
    };

    format!(
        "SSH channel closed without providing an exit status \
         [{transport}; channel messages seen before close: {seen}; \
         {} bytes received over {:.1}s]",
        outcome.bytes,
        elapsed.as_secs_f64(),
    )
}

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
    let handle = connect_resilient(ssh).await.map_err(|e| format!("{e:#}"))?;

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
    let mut outcome = ChannelOutcome::default();
    let exec_at = Instant::now();

    loop {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) => {
                outcome.bytes += data.len();
                let s = String::from_utf8_lossy(&data);
                print!("{s}");
                std::io::Write::flush(&mut std::io::stdout()).ok();
                stdout_str.push_str(&s);
            }
            Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                outcome.bytes += data.len();
                let s = String::from_utf8_lossy(&data);
                eprint!("{s}");
                std::io::Write::flush(&mut std::io::stderr()).ok();
                stderr_str.push_str(&s);
            }
            Some(ChannelMsg::ExitStatus { exit_status }) => {
                exit_code = exit_status;
                got_exit_status = true;
            }
            Some(ChannelMsg::Eof) => outcome.saw_eof = true,
            Some(ChannelMsg::Close) => outcome.saw_close = true,
            Some(ChannelMsg::ExitSignal {
                signal_name,
                error_message,
                ..
            }) => {
                outcome.exit_signal = Some(format!("{signal_name:?}: {error_message}"));
            }
            None => {
                break;
            }
            _ => {}
        }
    }

    if !got_exit_status {
        let diag = diagnose_missing_exit_status(&handle, &outcome, exec_at.elapsed()).await;
        handle
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await
            .ok();
        return Err(diag);
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
    let handle = connect_resilient(ssh).await.map_err(|e| format!("{e:#}"))?;

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
    let mut outcome = ChannelOutcome::default();
    let exec_at = Instant::now();

    loop {
        match channel.wait().await {
            Some(ChannelMsg::Data { data }) => {
                outcome.bytes += data.len();
                stdout.extend_from_slice(&data);
            }
            Some(ChannelMsg::ExtendedData { data, ext: 1 }) => {
                outcome.bytes += data.len();
                stderr.extend_from_slice(&data);
            }
            Some(ChannelMsg::ExitStatus { exit_status }) => {
                exit_code = exit_status;
                got_exit_status = true;
            }
            Some(ChannelMsg::Eof) => outcome.saw_eof = true,
            Some(ChannelMsg::Close) => outcome.saw_close = true,
            Some(ChannelMsg::ExitSignal {
                signal_name,
                error_message,
                ..
            }) => {
                outcome.exit_signal = Some(format!("{signal_name:?}: {error_message}"));
            }
            None => {
                break;
            }
            _ => {}
        }
    }

    if !got_exit_status {
        let diag = diagnose_missing_exit_status(&handle, &outcome, exec_at.elapsed()).await;
        handle
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await
            .ok();
        return Err(diag);
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

#[cfg(test)]
mod timeout_wrap_tests {
    use super::{TIMEOUT_EXIT_CODE, TimeoutMechanism, wrap_with_timeout};

    #[test]
    fn unwrapped_or_zero_timeout_passes_through_verbatim() {
        let cmd = "cargo test --locked";
        assert_eq!(
            wrap_with_timeout(cmd, 30, TimeoutMechanism::Unwrapped),
            cmd,
            "Unwrapped must not alter the command"
        );
        assert_eq!(
            wrap_with_timeout(cmd, 0, TimeoutMechanism::Timeout),
            cmd,
            "a zero timeout means no deadline, so no wrapping"
        );
    }

    #[test]
    fn timeout_mechanism_wraps_and_single_quote_escapes() {
        let wrapped = wrap_with_timeout("echo it's fine", 5, TimeoutMechanism::Timeout);
        assert_eq!(wrapped, "timeout -k 5 5 /bin/sh -c 'echo it'\\''s fine'");
    }

    #[test]
    fn bash_mechanism_is_self_contained_and_reports_124() {
        let wrapped = wrap_with_timeout("make", 12, TimeoutMechanism::BashJobControl);
        assert!(
            wrapped.starts_with("bash -c '"),
            "runs under bash: {wrapped}"
        );
        assert!(
            wrapped.contains("set -m"),
            "needs job control for the pgroup"
        );
        assert!(
            wrapped.contains("sleep 12"),
            "the deadline is baked in: {wrapped}"
        );
        assert!(
            wrapped.contains("kill -TERM -\"$c\""),
            "must group-kill the whole tree (negative PID targets the process group)"
        );
        assert!(wrapped.contains(&format!("exit {TIMEOUT_EXIT_CODE}")));
        assert!(
            wrapped.ends_with("_ 'make'"),
            "user command passed as the $1 positional: {wrapped}"
        );
    }

    #[test]
    fn windows_mechanism_uses_a_real_scriptblock_not_a_nested_command_string() {
        let wrapped = wrap_with_timeout("cargo build", 20, TimeoutMechanism::WindowsTaskkill);

        assert!(wrapped.contains("Start-Job -ScriptBlock"));
        assert!(
            !wrapped.contains("-Command"),
            "no fragile nested command string"
        );
        assert!(wrapped.contains("$using:__vciSelf"));
        assert!(wrapped.contains("taskkill /T /F"));
        assert!(
            wrapped.contains("$_.ProcessId -ne $PID"),
            "must not kill itself"
        );
        assert!(wrapped.contains("cargo build"), "user command runs inline");
        assert!(wrapped.contains(&format!("exit {TIMEOUT_EXIT_CODE}")));
    }
}
