// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use anyhow::Context;

#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BinVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl BinVersion {
    pub fn from_qemu_version_string(version_str: &str) -> anyhow::Result<Self> {
        let token = version_str
            .split_whitespace()
            .find(|t| t.chars().next().is_some_and(|c| c.is_ascii_digit()))
            .context("malformed QEMU version string")?;
        let mut parts = token.split('.');
        let major = parts
            .next()
            .context("no major")?
            .parse()
            .ok()
            .context("failed to parse major")?;
        let minor = parts
            .next()
            .context("no minor")?
            .parse()
            .ok()
            .context("failed to parse minor")?;
        let patch = parts
            .next()
            .context("no patch")?
            .parse()
            .ok()
            .context("failed to parse patch")?;
        Ok(BinVersion {
            major,
            minor,
            patch,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::BinVersion;

    #[test]
    fn parse_qemu_version_upstream() {
        assert_eq!(
            BinVersion::from_qemu_version_string("QEMU emulator version 10.2.0").expect("what"),
            BinVersion {
                major: 10,
                minor: 2,
                patch: 0
            }
        );
    }

    #[test]
    fn parse_qemu_version_distro_suffix() {
        assert_eq!(
            BinVersion::from_qemu_version_string(
                "QEMU emulator version 8.2.2 (Debian 1:8.2.2+ds-0ubuntu1.7)"
            )
            .expect("what"),
            BinVersion {
                major: 8,
                minor: 2,
                patch: 2
            }
        );
    }

    #[test]
    fn parse_qemu_version_no_version() {
        assert!(matches!(
            BinVersion::from_qemu_version_string("not a version line"),
            anyhow::Result::Err(_)
        ));
        assert!(matches!(
            BinVersion::from_qemu_version_string(""),
            anyhow::Result::Err(_)
        ));
    }
}
