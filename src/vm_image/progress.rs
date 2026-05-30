// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::io::{Read, Write};

/// Wraps a reader and prints carriage returns `\r` plus a label and stuff as bytes are consumed.
/// `total` is the expected byte count (0 means unknown).
pub struct ProgressReader<R> {
    inner: R,
    total: u64,
    read_so_far: u64,
    last_percent: f32,
    label: String,
}

impl<R: Read> ProgressReader<R> {
    pub fn new(inner: R, total: u64, label: String) -> Self {
        Self {
            inner,
            total,
            read_so_far: 0,
            last_percent: 0.0,
            label,
        }
    }
}

#[allow(clippy::cast_precision_loss, clippy::float_cmp)]
impl<R: Read> Read for ProgressReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.read_so_far += n as u64;

        let percent: f32 = if self.total > 0 {
            (self.read_so_far as f32 / self.total as f32) * 100.0
        } else {
            100.0
        };

        if percent != self.last_percent {
            self.last_percent = percent;
            print!(
                "\r  {} ... {:.1}% ({}/{})\x1b[K",
                self.label,
                percent,
                format_size(self.read_so_far),
                format_size(self.total),
            );
            std::io::stdout().flush().ok();

            if self.read_so_far >= self.total {
                println!();
            }
        }

        Ok(n)
    }
}

#[allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
pub fn format_size(bytes: u64) -> String {
    const MB: f64 = 1024.0 * 1024.0;
    const GB: f64 = MB * 1024.0;

    if bytes >= GB as u64 {
        format!("{:.1} GB", bytes as f64 / GB)
    } else {
        format!("{:.1} MB", bytes as f64 / MB)
    }
}
