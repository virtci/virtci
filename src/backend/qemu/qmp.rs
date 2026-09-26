// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::backend::{DiskIoStats, VcpuState};

/// QMP should never take this long.
const QMP_IO_TIMEOUT: Duration = Duration::from_secs(2);

/// A negotiated QMP connection, ready for commands.
struct QmpSession {
    reader: BufReader<TcpStream>,
    writer: TcpStream,
}

impl QmpSession {
    /// Connect, read the greeting, and leave capabilities negotiation mode.
    fn connect(addr: SocketAddr) -> Option<Self> {
        let stream = TcpStream::connect_timeout(&addr, QMP_IO_TIMEOUT).ok()?;
        stream.set_read_timeout(Some(QMP_IO_TIMEOUT)).ok()?;
        stream.set_write_timeout(Some(QMP_IO_TIMEOUT)).ok()?;

        let mut session = Self {
            reader: BufReader::new(stream.try_clone().ok()?),
            writer: stream,
        };
        read_json_line(&mut session.reader)?;
        session.execute(&serde_json::json!({ "execute": "qmp_capabilities" }))?;
        Some(session)
    }

    /// Send one command and return its `return` value, `None` on an error reply or IO failure.
    fn execute(&mut self, command: &serde_json::Value) -> Option<serde_json::Value> {
        self.writer.write_all(command.to_string().as_bytes()).ok()?;
        self.writer.write_all(b"\r\n").ok()?;
        self.writer.flush().ok()?;
        read_return(&mut self.reader)
    }

    /// Run an HMP command (such as `info registers -a`) and return its text output.
    fn human_monitor_command(&mut self, command_line: &str) -> Option<String> {
        let ret = self.execute(&serde_json::json!({
            "execute": "human-monitor-command",
            "arguments": { "command-line": command_line },
        }))?;
        ret.as_str().map(str::to_string)
    }
}

/// Connects to QMP TCP endpoint and returns the cumulative block-layer IO counters across every
/// drive, or None if it wasn't able to.
pub fn query_disk_io_stats(addr: SocketAddr) -> Option<DiskIoStats> {
    let resp = QmpSession::connect(addr)?
        .execute(&serde_json::json!({ "execute": "query-blockstats" }))?;
    Some(sum_block_stats(&resp))
}

/// Whether QEMU is actually running on KVM. `-accel kvm -accel tcg` can silently fall back to TCG
/// when KVM can't initialize.
pub fn kvm_enabled(addr: SocketAddr) -> Option<bool> {
    let resp =
        QmpSession::connect(addr)?.execute(&serde_json::json!({ "execute": "query-kvm" }))?;
    resp.get("enabled").and_then(serde_json::Value::as_bool)
}

/// Every vCPU's program counter right now, from `info registers -a`.
pub fn vcpu_states(addr: SocketAddr) -> Option<Vec<VcpuState>> {
    let dump = QmpSession::connect(addr)?.human_monitor_command("info registers -a")?;
    Some(parse_vcpu_states(&dump))
}

pub fn system_powerdown(addr: SocketAddr) -> bool {
    QmpSession::connect(addr)
        .and_then(|mut qmp| qmp.execute(&serde_json::json!({ "execute": "system_powerdown" })))
        .is_some()
}

/// Pull each vCPU's program counter out of an `info registers -a` dump. `CPU#n` headers separate
/// the vCPUs; the PC line differs per arch: aarch64 `PC=`, x86 `RIP=`/`EIP=` (with `HLT=`), riscv
/// ` pc       <hex>`.
fn parse_vcpu_states(dump: &str) -> Vec<VcpuState> {
    let hex = |s: &str| u64::from_str_radix(s.split_whitespace().next()?, 16).ok();

    let mut states = Vec::new();
    let mut cpu = 0;
    for line in dump.lines() {
        let line = line.trim();
        if let Some(n) = line.strip_prefix("CPU#") {
            cpu = n.trim().parse().unwrap_or(cpu);
            continue;
        }
        let (pc, halted) = if let Some(rest) = line.strip_prefix("PC=") {
            (hex(rest), None)
        } else if let Some(rest) = line
            .strip_prefix("RIP=")
            .or_else(|| line.strip_prefix("EIP="))
        {
            let halted = line
                .split_whitespace()
                .find_map(|field| field.strip_prefix("HLT="))
                .map(|v| v == "1");
            (hex(rest), halted)
        } else if let Some(rest) = line.strip_prefix("pc ") {
            (hex(rest), None)
        } else {
            continue;
        };
        if let Some(pc) = pc {
            states.push(VcpuState { cpu, pc, halted });
        }
    }
    states
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

    #[test]
    fn parses_aarch64_vcpus() {
        let dump = "CPU#0\n\
                    PC=ffff800081b1b9a0 X00=0000000000000000 X01=0000000000000001\n\
                    PSTATE=00000000804000c5 N--- EL1h     FPCR=00000000 FPSR=00000000\n\
                    CPU#1\n\
                    PC=ffff800080023294 X00=ffff800085633988 X01=ffff800085633a66\n";
        let states = super::parse_vcpu_states(dump);
        assert_eq!(
            states,
            vec![
                crate::backend::VcpuState {
                    cpu: 0,
                    pc: 0xffff_8000_81b1_b9a0,
                    halted: None
                },
                crate::backend::VcpuState {
                    cpu: 1,
                    pc: 0xffff_8000_8002_3294,
                    halted: None
                },
            ]
        );
    }

    #[test]
    fn parses_x86_vcpus_with_halt_state() {
        let dump = "CPU#0\r\n\
                    RAX=0000000000000000 RBX=0000000000000000\r\n\
                    RIP=00007a8f6e0dd458 RFL=00000202 [-------] CPL=3 II=0 A20=1 SMM=0 HLT=0\r\n\
                    CPU#1\r\n\
                    EIP=000052fa EFL=00000246 [---Z-P-] CPL=0 II=0 A20=1 SMM=0 HLT=1\r\n";
        let states = super::parse_vcpu_states(dump);
        assert_eq!(states.len(), 2);
        assert_eq!(states[0].pc, 0x7a8f_6e0d_d458);
        assert_eq!(states[0].halted, Some(false));
        assert_eq!(states[1].cpu, 1);
        assert_eq!(states[1].pc, 0x52fa);
        assert_eq!(states[1].halted, Some(true));
    }

    #[test]
    fn parses_riscv_vcpus() {
        let dump = "CPU#0\n V      =   0\n pc       ffffffff80001234\n mhartid  0000000000000000\n";
        let states = super::parse_vcpu_states(dump);
        assert_eq!(states.len(), 1);
        assert_eq!(states[0].pc, 0xffff_ffff_8000_1234);
    }
}
