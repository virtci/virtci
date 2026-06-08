// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

#include <assert.h>
#include <stddef.h>
#include <stdint.h>

/// Matches with `virtci::util::cpu_arch::Arch` enum
typedef enum CpuArch {
    CPU_ARCH_X64 = 0,
    CPU_ARCH_ARM64 = 1,
    CPU_ARCH_RISCV64 = 2,

    CPU_ARCH_UNKNOWN = -1,

    // Force i32
    _CPU_ARCH_UNUSED = 0x7FFFFFFF
} CpuArch;

/// CPU architecture that the executable at `executable_path` was built for, read
/// from the executable's file header. `executable_path` is UTF-8 and NOT null
/// terminated; it is `path_len` bytes long.
/// CPU architecture that the executable at `executable_path` was actually built for.
/// @param executable_path utf8, maybe non-null terminated path
/// @param path_len length, in bytes, of `executable_path`.
/// @return For Windows, only ever returns `CPU_ARCH_X64` or `CPU_ARCH_ARM64`.
CpuArch virtci_get_arch_of_executable_native(const char *executable_path, size_t path_len);

/// CPU architecture the host OS itself runs on, even when this process is running
/// under emulation, such as prism or rosetta 2.
/// @return For Windows, only ever returns `CPU_ARCH_X64` or `CPU_ARCH_ARM64`.
CpuArch virtci_get_host_cpu_arch_native(void);

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

// Older MinGW headers may lack these.
#ifndef PROCESSOR_ARCHITECTURE_ARM64
#define PROCESSOR_ARCHITECTURE_ARM64 12
#endif

// https://learn.microsoft.com/en-us/windows/win32/sysinfo/image-file-machine-constants
#ifndef IMAGE_FILE_MACHINE_AMD64
#define IMAGE_FILE_MACHINE_AMD64 0x8664
#endif
#ifndef IMAGE_FILE_MACHINE_ARM64
#define IMAGE_FILE_MACHINE_ARM64 0xAA64
#endif

static CpuArch pe_machine_to_arch(uint16_t machine) {
    switch (machine) {
    case IMAGE_FILE_MACHINE_AMD64:
        return CPU_ARCH_X64;
    case IMAGE_FILE_MACHINE_ARM64:
        return CPU_ARCH_ARM64;
    default:
        return CPU_ARCH_UNKNOWN;
    }
}

// Reads the COFF machine field of a PE image: the DOS header stores `e_lfanew`
// (file offset of the "PE\0\0" signature) at 0x3C, and the u16 machine field
// immediately follows the 4-byte signature.
// https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
//
// NOTE: ARM64X binaries report IMAGE_FILE_MACHINE_AMD64 while containing native
// ARM64EC code, so this would misclassify them as x86_64. QEMU does not ship
// ARM64X builds though so being strict is safe here.
CpuArch virtci_get_arch_of_executable_native(const char *executable_path, size_t path_len) {
    if (executable_path == NULL || path_len == 0 || path_len > (size_t)INT_MAX) {
        return CPU_ARCH_UNKNOWN;
    }

    // Rust paths are UTF-8, but CreateFileW needs UTF-16.
    const int wide_len = MultiByteToWideChar(CP_UTF8, 0, executable_path, (int)path_len, NULL, 0);
    if (wide_len <= 0) {
        return CPU_ARCH_UNKNOWN;
    }
    wchar_t *wide_path = malloc(((size_t)wide_len + 1) * sizeof(wchar_t));
    if (wide_path == NULL) {
        return CPU_ARCH_UNKNOWN;
    }
    MultiByteToWideChar(CP_UTF8, 0, executable_path, (int)path_len, wide_path, wide_len);
    wide_path[wide_len] = L'\0';

    HANDLE file =
        CreateFileW(wide_path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    free(wide_path);
    if (file == INVALID_HANDLE_VALUE) {
        return CPU_ARCH_UNKNOWN;
    }

    CpuArch arch = CPU_ARCH_UNKNOWN;
    uint8_t dos_header[64];
    DWORD bytes_read = 0;
    if (ReadFile(file, dos_header, sizeof(dos_header), &bytes_read, NULL) &&
        bytes_read == sizeof(dos_header) && dos_header[0] == 'M' && dos_header[1] == 'Z') {
        uint32_t e_lfanew = 0;
        memcpy(&e_lfanew, dos_header + 0x3C, sizeof(e_lfanew));

        LARGE_INTEGER seek_to;
        seek_to.QuadPart = e_lfanew;
        uint8_t pe_header[6]; // "PE\0\0" signature, then the u16 little endian machine field
        if (SetFilePointerEx(file, seek_to, NULL, FILE_BEGIN) &&
            ReadFile(file, pe_header, sizeof(pe_header), &bytes_read, NULL) &&
            bytes_read == sizeof(pe_header) && pe_header[0] == 'P' && pe_header[1] == 'E' &&
            pe_header[2] == 0 && pe_header[3] == 0) {
            const uint16_t machine =
                (uint16_t)((uint16_t)pe_header[4] | ((uint16_t)pe_header[5] << 8));
            arch = pe_machine_to_arch(machine);
        }
    }
    CloseHandle(file);

    return arch;
}

/// IsWow64Process2's native machine out-param reports the true host architecture even
/// when this process itself runs emulated (such as an x86_64 virtci under Prism on a
/// Windows ARM64 host).
/// https://learn.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process2
CpuArch virtci_get_host_cpu_arch_native(void) {
    typedef BOOL(WINAPI * IsWow64Process2Fn)(HANDLE, USHORT *, USHORT *);
    const HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    if (kernel32 != NULL) {
        const IsWow64Process2Fn is_wow64_process2 =
            (IsWow64Process2Fn)GetProcAddress(kernel32, "IsWow64Process2");
        if (is_wow64_process2 != NULL) {
            USHORT process_machine = 0;
            USHORT native_machine = 0;
            if (is_wow64_process2(GetCurrentProcess(), &process_machine, &native_machine)) {
                // Conveniently also an IMAGE_FILE_MACHINE_* value, same as PE headers.
                return pe_machine_to_arch(native_machine);
            }
        }
    }

    // Fallback. Reports the emulated architecture if this process is itself
    // emulated, but that host probably predate Windows-on-ARM x64 emulation regardless.
    SYSTEM_INFO info;
    GetNativeSystemInfo(&info);
    switch (info.wProcessorArchitecture) {
    case PROCESSOR_ARCHITECTURE_AMD64:
        return CPU_ARCH_X64;
    case PROCESSOR_ARCHITECTURE_ARM64:
        return CPU_ARCH_ARM64;
    default:
        assert(0 && "Failed to get host CPU architecture on Windows");
    }

    return CPU_ARCH_UNKNOWN;
}

#elif defined(__APPLE__) || defined(__linux__)

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/// `open(2)` the executable for header sniffing. Rust paths arrive without a null
/// terminator. Returns -1 on any failure.
static int open_executable(const char *executable_path, size_t path_len) {
    if (executable_path == NULL || path_len == 0) {
        return -1;
    }
    char *path = malloc(path_len + 1);
    if (path == NULL) {
        return -1;
    }
    memcpy(path, executable_path, path_len);
    path[path_len] = '\0';
    const int fd = open(path, O_RDONLY | O_CLOEXEC);
    free(path);
    return fd;
}

#if defined(__APPLE__)

#include <sys/sysctl.h>

#define VCI_MH_MAGIC_64 0xFEEDFACFu  // thin 64-bit Mach-O, stored in target byte order
#define VCI_FAT_MAGIC 0xCAFEBABEu    // universal binary, header stored big-endian
#define VCI_FAT_MAGIC_64 0xCAFEBABFu // universal binary with 64-bit slice offsets
#define VCI_CPU_TYPE_X86_64 0x01000007u
#define VCI_CPU_TYPE_ARM64 0x0100000Cu

static uint32_t read_le32(const uint8_t *bytes) {
    return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) | ((uint32_t)bytes[2] << 16) |
           ((uint32_t)bytes[3] << 24);
}

static uint32_t read_be32(const uint8_t *bytes) {
    return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) | ((uint32_t)bytes[2] << 8) |
           (uint32_t)bytes[3];
}

static CpuArch macho_cputype_to_arch(uint32_t cputype) {
    switch (cputype) {
    case VCI_CPU_TYPE_X86_64:
        return CPU_ARCH_X64;
    case VCI_CPU_TYPE_ARM64:
        return CPU_ARCH_ARM64;
    default:
        return CPU_ARCH_UNKNOWN;
    }
}

/// Reads the Mach-O `cputype`, the 32-bit field straight after the 32-bit magic.
/// Thin binaries (Homebrew bottles) store the header in the target's byte order,
/// which is little-endian for both supported macOS architectures. Universal/fat
/// binaries (Apple system binaries) store the fat header big-endian, followed by
/// `nfat_arch` slice descriptors whose first field is that slice's cputype.
CpuArch virtci_get_arch_of_executable_native(const char *executable_path, size_t path_len) {
    const int fd = open_executable(executable_path, path_len);
    if (fd < 0) {
        return CPU_ARCH_UNKNOWN;
    }

    uint8_t header[8]; // magic, then cputype (thin) or nfat_arch (fat)
    if (read(fd, header, sizeof(header)) != (ssize_t)sizeof(header)) {
        close(fd);
        return CPU_ARCH_UNKNOWN;
    }

    if (read_le32(header) == VCI_MH_MAGIC_64) {
        close(fd);
        return macho_cputype_to_arch(read_le32(header + 4));
    }

    const uint32_t fat_magic = read_be32(header);
    if (fat_magic == VCI_FAT_MAGIC || fat_magic == VCI_FAT_MAGIC_64) {
        // `fat_arch` slice descriptors are 20 bytes, `fat_arch_64` are 32; only the
        // leading cputype is needed. The kernel prefers the slice matching the
        // native architecture, so report that one when present. A wrong-arch-only
        // fat binary reports its first recognizable slice instead.
        const size_t entry_size = (fat_magic == VCI_FAT_MAGIC) ? 20 : 32;
        uint32_t nfat_arch = read_be32(header + 4);
        if (nfat_arch > 16) {
            nfat_arch = 16; // a real universal binary has 2-3 slices
        }
        const CpuArch host = virtci_get_host_cpu_arch_native();
        CpuArch first_known = CPU_ARCH_UNKNOWN;
        for (uint32_t i = 0; i < nfat_arch; i++) {
            uint8_t cputype_bytes[4];
            const off_t entry_offset = (off_t)(sizeof(header) + (size_t)i * entry_size);
            if (pread(fd, cputype_bytes, sizeof(cputype_bytes), entry_offset) !=
                (ssize_t)sizeof(cputype_bytes)) {
                break;
            }
            const CpuArch slice = macho_cputype_to_arch(read_be32(cputype_bytes));
            if (slice == host && slice != CPU_ARCH_UNKNOWN) {
                close(fd);
                return slice;
            }
            if (first_known == CPU_ARCH_UNKNOWN) {
                first_known = slice;
            }
        }
        close(fd);
        return first_known;
    }

    close(fd);
    return CPU_ARCH_UNKNOWN;
}

// `sysctl.proc_translated` is 1 when this process runs under Rosetta 2, and Rosetta
// only ever translates x86_64 processes on arm64 silicon, so translated means the
// real host is arm64. 0, or ENOENT on Intel Macs that predate the sysctl, means
// native, where it's just the compile-time arch.
// https://developer.apple.com/documentation/apple-silicon/about-the-rosetta-translation-environment
CpuArch virtci_get_host_cpu_arch_native(void) {
    int translated = 0;
    size_t size = sizeof(translated);
    if (sysctlbyname("sysctl.proc_translated", &translated, &size, NULL, 0) == 0 &&
        translated == 1) {
        return CPU_ARCH_ARM64;
    }
#if defined(__aarch64__) || defined(__arm64__)
    return CPU_ARCH_ARM64;
#elif defined(__x86_64__)
    return CPU_ARCH_X64;
#else
    return CPU_ARCH_UNKNOWN;
#endif
}

#else // __linux__

// ELF e_machine values, from <elf.h>.
#define VCI_EM_X86_64 62
#define VCI_EM_AARCH64 183
#define VCI_EM_RISCV 243

/// Reads the ELF `e_machine` field: a u16 at offset 0x12, stored in the file's own
/// byte order (EI_DATA at offset 0x5). All supported architectures are 64-bit
/// little-endian, so anything else is unrecognized rather than guessed at.
CpuArch virtci_get_arch_of_executable_native(const char *executable_path, size_t path_len) {
    const int fd = open_executable(executable_path, path_len);
    if (fd < 0) {
        return CPU_ARCH_UNKNOWN;
    }

    uint8_t header[20]; // e_ident, e_type, then e_machine at 0x12
    const ssize_t bytes_read = read(fd, header, sizeof(header));
    close(fd);
    if (bytes_read != (ssize_t)sizeof(header) || header[0] != 0x7F || header[1] != 'E' ||
        header[2] != 'L' || header[3] != 'F') {
        return CPU_ARCH_UNKNOWN;
    }
    // EI_CLASS must be ELFCLASS64 (2) and EI_DATA must be ELFDATA2LSB (1). This also
    // keeps EM_RISCV below unambiguous, since it covers rv32 ELFs too.
    if (header[4] != 2 || header[5] != 1) {
        return CPU_ARCH_UNKNOWN;
    }

    const uint16_t machine = (uint16_t)((uint16_t)header[0x12] | ((uint16_t)header[0x13] << 8));
    switch (machine) {
    case VCI_EM_X86_64:
        return CPU_ARCH_X64;
    case VCI_EM_AARCH64:
        return CPU_ARCH_ARM64;
    case VCI_EM_RISCV:
        return CPU_ARCH_RISCV64;
    default:
        return CPU_ARCH_UNKNOWN;
    }
}

/// `/proc/sys/kernel/arch` is in Linux 6.1+.
/// User-mode emulators intercept the uname(2) SYSCALL to fake the machine name, but none of them
/// intercept this file read.
CpuArch virtci_get_host_cpu_arch_native(void) {
    const int fd = open("/proc/sys/kernel/arch", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return CPU_ARCH_UNKNOWN;
    }
    char machine[16] = {0}; // longest expected is "aarch64\n"
    const ssize_t bytes_read = read(fd, machine, sizeof(machine) - 1);
    close(fd);
    if (bytes_read <= 0) {
        return CPU_ARCH_UNKNOWN;
    }
    if (machine[bytes_read - 1] == '\n') {
        machine[bytes_read - 1] = '\0';
    }

    if (strcmp(machine, "x86_64") == 0) {
        return CPU_ARCH_X64;
    }
    if (strcmp(machine, "aarch64") == 0) {
        return CPU_ARCH_ARM64;
    }
    if (strcmp(machine, "riscv64") == 0) {
        return CPU_ARCH_RISCV64;
    }
    return CPU_ARCH_UNKNOWN;
}

#endif

#else

/// Unsupported platform: no header sniffing. The Rust side treats UNKNOWN as
/// "cannot determine" and skips the architecture check.
CpuArch virtci_get_arch_of_executable_native(const char *executable_path, size_t path_len) {
    (void)executable_path;
    (void)path_len;
    return CPU_ARCH_UNKNOWN;
}

CpuArch virtci_get_host_cpu_arch_native(void) { return CPU_ARCH_UNKNOWN; }

#endif
