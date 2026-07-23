// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::backend::DiskIoStats;

/// QMP should never take this long.
const QMP_IO_TIMEOUT: Duration = Duration::from_secs(2);

/// Connects to QMP TCP endpoint and returns the cumulative block-layer IO counters across every
/// drive, or None if it wasn't able to.
pub fn query_disk_io_stats(addr: SocketAddr) -> Option<DiskIoStats> {
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
    Some(sum_block_stats(&resp))
}

pub fn system_powerdown(addr: SocketAddr) -> bool {
    fn inner(addr: SocketAddr) -> Option<()> {
        let stream = TcpStream::connect_timeout(&addr, QMP_IO_TIMEOUT).ok()?;
        stream.set_read_timeout(Some(QMP_IO_TIMEOUT)).ok()?;
        stream.set_write_timeout(Some(QMP_IO_TIMEOUT)).ok()?;

        let mut reader = BufReader::new(stream.try_clone().ok()?);
        let mut writer = stream;

        read_json_line(&mut reader)?;

        send(&mut writer, r#"{"execute":"qmp_capabilities"}"#)?;
        read_return(&mut reader)?;

        send(&mut writer, r#"{"execute":"system_powerdown"}"#)?;
        read_return(&mut reader)?;
        Some(())
    }
    inner(addr).is_some()
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

fn sum_block_stats(blockstats: &serde_json::Value) -> DiskIoStats {
    let Some(devices) = blockstats.as_array() else {
        return DiskIoStats::default();
    };
    let field = |stats: &serde_json::Value, key: &str| {
        stats
            .get(key)
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0)
    };
    devices.iter().filter_map(|dev| dev.get("stats")).fold(
        DiskIoStats::default(),
        |mut acc, stats| {
            acc.rd_ops = acc.rd_ops.saturating_add(field(stats, "rd_operations"));
            acc.rd_time_ns = acc
                .rd_time_ns
                .saturating_add(field(stats, "rd_total_time_ns"));
            acc.wr_ops = acc.wr_ops.saturating_add(field(stats, "wr_operations"));
            acc.wr_time_ns = acc
                .wr_time_ns
                .saturating_add(field(stats, "wr_total_time_ns"));
            acc
        },
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn sums_rd_and_wr_across_devices() {
        let stats = serde_json::json!([
            {"device": "SystemDisk", "stats": {
                "rd_operations": 100, "rd_total_time_ns": 1_000_000_000,
                "wr_operations": 50,  "wr_total_time_ns": 500_000_000}},
            {"device": "seed", "stats": {
                "rd_operations": 7,   "rd_total_time_ns": 7_000_000,
                "wr_operations": 0,   "wr_total_time_ns": 0}},
        ]);
        let summed = super::sum_block_stats(&stats);
        assert_eq!(summed.rd_ops, 107);
        assert_eq!(summed.rd_time_ns, 1_007_000_000);
        assert_eq!(summed.wr_ops, 50);
        assert_eq!(summed.wr_time_ns, 500_000_000);
        assert_eq!(summed.total_ops(), 157);
    }

    #[test]
    fn missing_or_partial_stats_are_zero() {
        let stats = serde_json::json!([
            {"device": "cd", "stats": {}},
            {"device": "no-stats-key"},
            {"device": "x", "stats": {"wr_operations": 3}},
        ]);
        let summed = super::sum_block_stats(&stats);
        assert_eq!(summed.total_ops(), 3);
        assert_eq!(summed.wr_time_ns, 0);
    }

    #[test]
    fn non_array_is_zero() {
        assert_eq!(
            super::sum_block_stats(&serde_json::json!({})),
            crate::backend::DiskIoStats::default()
        );
    }

    #[test]
    fn latency_is_measured_over_the_interval() {
        let prev = crate::backend::DiskIoStats {
            rd_ops: 100,
            rd_time_ns: 100_000_000,
            wr_ops: 10,
            wr_time_ns: 10_000_000,
        };

        let now = crate::backend::DiskIoStats {
            rd_ops: 200,
            rd_time_ns: 150_000_000,
            wr_ops: 10,
            wr_time_ns: 10_000_000,
        };
        assert_eq!(now.rd_latency_us_since(&prev), Some(500));
        assert_eq!(now.wr_latency_us_since(&prev), None);
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
