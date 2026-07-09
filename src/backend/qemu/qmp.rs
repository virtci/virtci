// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// QMP should never take this long.
const QMP_IO_TIMEOUT: Duration = Duration::from_secs(2);

/// Connects to QMP TCP endpoint and returns how many block-layer IO operations that have been
/// performed in total, or None if it wasn't able to.
pub fn query_disk_io_ops(addr: SocketAddr) -> Option<u64> {
    let stream = TcpStream::connect_timeout(&addr, QMP_IO_TIMEOUT).ok()?;
    stream.set_read_timeout(Some(QMP_IO_TIMEOUT)).ok()?;
    stream.set_write_timeout(Some(QMP_IO_TIMEOUT)).ok()?;

    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut writer = stream;

    read_json_line(&mut reader)?;

    send(&mut writer, r#"{"execute":"qmp_capabilities"}"#)?;
    read_return(&mut reader)?;

    send(&mut writer, r#"{"execute":"query-blockstats"}"#)?;
    let resp = read_return(&mut reader)?;
    Some(sum_block_io_ops(&resp))
}

fn send(writer: &mut TcpStream, line: &str) -> Option<()> {
    writer.write_all(line.as_bytes()).ok()?;
    writer.write_all(b"\r\n").ok()?;
    writer.flush().ok()
}

/// Read one line and parse it as JSON, skipping blank lines.
fn read_json_line(reader: &mut impl BufRead) -> Option<serde_json::Value> {
    loop {
        let mut line = String::new();
        let n = reader.read_line(&mut line).ok()?;
        if n == 0 {
            return None;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        return serde_json::from_str(trimmed).ok();
    }
}

/// Read lines until a command reply arrives, skipping any asynchronous `event` messages QEMU
/// interleaves. Returns `Some(return_value)` on success, `None` on an `error` reply or read
/// failure.
fn read_return(reader: &mut impl BufRead) -> Option<serde_json::Value> {
    for _ in 0..64 {
        let msg = read_json_line(reader)?;
        if let Some(ret) = msg.get("return") {
            return Some(ret.clone());
        }
        if msg.get("error").is_some() {
            return None;
        }
    }
    None
}

fn sum_block_io_ops(blockstats: &serde_json::Value) -> u64 {
    let Some(devices) = blockstats.as_array() else {
        return 0;
    };
    devices
        .iter()
        .filter_map(|dev| dev.get("stats"))
        .map(|stats| {
            let rd = stats
                .get("rd_operations")
                .and_then(serde_json::Value::as_u64);
            let wr = stats
                .get("wr_operations")
                .and_then(serde_json::Value::as_u64);
            rd.unwrap_or(0).saturating_add(wr.unwrap_or(0))
        })
        .sum()
}

#[cfg(test)]
mod tests {
    #[test]
    fn sums_rd_and_wr_across_devices() {
        let stats = serde_json::json!([
            {"device": "SystemDisk", "stats": {"rd_operations": 100, "wr_operations": 50}},
            {"device": "seed",       "stats": {"rd_operations": 7,   "wr_operations": 0}},
        ]);
        assert_eq!(super::sum_block_io_ops(&stats), 157);
    }

    #[test]
    fn missing_or_partial_stats_are_zero() {
        let stats = serde_json::json!([
            {"device": "cd", "stats": {}},
            {"device": "no-stats-key"},
            {"device": "x", "stats": {"wr_operations": 3}},
        ]);
        assert_eq!(super::sum_block_io_ops(&stats), 3);
    }

    #[test]
    fn non_array_is_zero() {
        assert_eq!(super::sum_block_io_ops(&serde_json::json!({})), 0);
    }

    #[test]
    fn read_return_skips_events() {
        let mut input =
            std::io::Cursor::new("{\"event\":\"RESUME\"}\n{\"return\":{\"ok\":1}}\n".to_string());
        let ret = super::read_return(&mut input).expect("should find return past the event");
        assert_eq!(ret, serde_json::json!({"ok": 1}));
    }

    #[test]
    fn read_return_none_on_error_reply() {
        let mut input =
            std::io::Cursor::new("{\"error\":{\"class\":\"GenericError\"}}\n".to_string());
        assert!(super::read_return(&mut input).is_none());
    }
}
