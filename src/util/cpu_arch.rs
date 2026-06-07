// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::path::Path;

use serde::{Deserialize, Serialize};

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
// All `unsafe` usage is just FFI in `src/util/exec_built_cpu_arch.c`, and is fully
// validated, so it's fine.
#[allow(clippy::unsafe_derive_deserialize)]
pub enum Arch {
    X64 = 0,
    ARM64 = 1,
    RISCV64 = 2,
}

extern "C" {
    /// `src/util/exec_built_cpu_arch.c`. If returned `-1`, some kind of error happened.
    fn virtci_get_arch_of_executable_native(executable_path: *const u8, path_len: usize) -> i32;
    /// `src/util/exec_built_cpu_arch.c`. If returned `-1`, some kind of error happened.
    fn virtci_get_host_cpu_arch_native() -> i32;
}

impl Arch {
    /// The architecture the host OS actually runs natively, even when this process is
    /// emulated, like an x86_64 virtci under Prism on a Windows ARM64 host, where
    /// [`std::env::consts::ARCH`] reports `"x86_64"`. Sees through Prism on Windows
    /// (IsWow64Process2), Rosetta 2 on macOS (sysctl.proc_translated), and FEX/box64/
    /// qemu-user on Linux 6.1+ (/proc/sys/kernel/arch, a procfs read that emulators do
    /// not intercept the way they fake the `uname` syscall). Falls back to
    /// [`std::env::consts::ARCH`] when it cannot be determined, such as Linux pre-6.1.
    #[must_use]
    pub fn host() -> Arch {
        if let Some(arch) = Arch::from_native(unsafe { virtci_get_host_cpu_arch_native() }) {
            arch
        } else {
            match std::env::consts::ARCH {
                "x86_64" => Arch::X64,
                "aarch64" => Arch::ARM64,
                "riscv64" => Arch::RISCV64,
                other => panic!("Unsupported host CPU architecture: {other}"),
            }
        }
    }

    /// The architecture the executable at `path` was built for, read from the
    /// executable's file header, NOT whether the host can launch it, since emulation
    /// (Prism/Rosetta 2/binfmt_misc handlers like FEX or qemu-user) lets wrong-arch binaries
    /// run. QEMU built for x86_64 hosts can fail under Prism emulation on Windows arm64.
    ///
    /// Parses PE on Windows, ELF on Linux, and Mach-O (thin and universal) on macOS. For a
    /// universal binary this reports the slice the kernel would pick: the native one when
    /// present, otherwise the first recognizable foreign slice.
    /// `None` when the file cannot be read or parsed, or on other platforms.
    #[must_use]
    pub fn of_executable(path: &Path) -> Option<Arch> {
        let utf8 = path.to_str()?;
        Arch::from_native(unsafe {
            virtci_get_arch_of_executable_native(utf8.as_ptr(), utf8.len())
        })
    }

    /// Human readable name, for error messages.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Arch::X64 => "x86_64",
            Arch::ARM64 => "arm64",
            Arch::RISCV64 => "riscv64",
        }
    }

    /// `CpuArch` (C) to [`Arch`]. The C enum is never transmuted directly because
    /// `CPU_ARCH_UNKNOWN` (-1) is not a valid [`Arch`] discriminant.
    fn from_native(raw: i32) -> Option<Arch> {
        match raw {
            0 => Some(Arch::X64),
            1 => Some(Arch::ARM64),
            2 => Some(Arch::RISCV64),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Arch;

    #[test]
    fn arch_of_non_executable() {
        assert_eq!(
            Arch::of_executable(std::path::Path::new("Cargo.toml")),
            None
        );
    }

    #[test]
    fn arch_of_missing_file() {
        assert_eq!(
            Arch::of_executable(std::path::Path::new("does/not/exist.exe")),
            None
        );
    }

    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    #[test]
    fn arch_of_current_exe() {
        let exe = std::env::current_exe().expect("current exe");
        // The test binary's header is by definition the compile-time architecture, which
        // matches `Arch::host()` whenever tests run natively (which CI does).
        assert_eq!(Arch::of_executable(&exe), Some(Arch::host()));
    }
}
