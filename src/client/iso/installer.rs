// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use serde_with::TimestampNanoSecondsWithFrac;

use crate::{util::bin_version::BinVersion, vm_image::GuestOs};

pub struct DetectedInstallOs {
    pub os: GuestOs,
    pub installer: Option<UnattendedInstaller>,
    pub ssh_setup: SshSetup,
}

pub enum UnattendedInstaller {
    Subiquity,
    DebianInstaller,
    Anaconda,
    Calamares,
    WindowsSetup,
}

/// Detected from the ISO as how to setup the SSH server, cause VirtCI is useless without it.
pub struct SshSetup {
    package: SshPackage,
    service: SshService,
    enable: SshEnableStyle,
    privilege: SshPrivilege,
    selinux_restorecon: bool,
}

pub enum SshPackage {
    OpenSshServer,
    OpenSsh,
}

impl SshPackage {
    pub fn as_str(&self) -> &'static str {
        match self {
            SshPackage::OpenSshServer => "openssh-server",
            SshPackage::OpenSsh => "openssh",
        }
    }
}

pub enum SshService {
    Ssh,
    Sshd,
}

impl SshService {
    pub fn as_str(&self) -> &'static str {
        match self {
            SshService::Ssh => "ssh",
            SshService::Sshd => "sshd",
        }
    }
}

pub enum SshEnableStyle {
    /// Always on.
    SystemdService,
    /// Launches on incoming connection. Modern linux distros are seemingly favouring this.
    SystemdSocket,
    /// Alpine linux
    OpenRc,
    WindowsScm,
}

pub enum SshPrivilege {
    Sudoer,
    /// Alpine linux.
    Doas,
    WindowsAdmin,
}

pub enum Distro {
    Windows,
    // TODO MacOS
    Ubuntu,
    Debian,
    Fedora,
    Rhel,
}

pub struct OsVersion {
    /// "26.04.1", "25H2", etc.
    pub raw: String,
    pub major: Option<u32>,
    pub minor: Option<u32>,
    pub patch: Option<u32>,
    /// Windows build. Win32 uses DWORD for the version number, so this is definitely fine.
    pub build: Option<u32>,
}

pub enum LinuxVersion {
    /// Includes derivatives, excluding Ubuntu.
    /// Debian netinst can do either desktop or server, no need to split.
    Debian(OsVersion),
    Ubuntu(UbuntuVersion),
    Fedora,
    RHEL,
    /// Includes derivatives.
    Arch,
}

pub enum UbuntuVersion {
    Desktop(OsVersion),
    Server(OsVersion),
    // ubuntu touch?
}

pub struct WindowsBuildNumber(Option<u32>);

impl WindowsBuildNumber {
    /// Returns `Some(true)` if at least windows 11. Returns `Some(false)` if Windows 10 or earlier.
    /// Returns `None` is `self.0.is_none()`. This is only relevant cause TPM for Windows 11.
    pub fn is_at_least_windows_11(&self) -> Option<bool> {
        match self.0 {
            // https://en.wikipedia.org/wiki/Windows_11_version_history
            Some(num) => return Some(num >= 22000),
            None => None,
        }
    }
}

pub enum WindowsVersion {
    Desktop(WindowsBuildNumber),
    Server(WindowsBuildNumber),
    // idk there's IoT, xbox, hololens, and mobile too.
}
