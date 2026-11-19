use std::io::{Read, Seek};

use crate::{
    client::iso::filesystem::{IsoError, entry::EntryKind, image::IsoImage},
    util::cpu_arch::Arch,
};

/// How many bytes of a PE file to read when looking for its header. The PE header offset is
/// almost always a lot under this.
const PE_HEADER_READ_LIMIT: usize = 4096;
/// Offset of `e_lfanew` in the DOS header. It's a u32 holding the offset of the PE signature.
const DOS_E_LFANEW_OFFSET: usize = 0x3c;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeHeaderError {
    /// Doesn't start with the `MZ` DOS header signature.
    MissingMzSignature,
    /// Too short to contain the `e_lfanew` field.
    TruncatedDosHeader,
    /// `e_lfanew` points past the bytes that were read.
    PeHeaderOutOfBounds { pe_offset: u32, available: usize },
    /// No `PE\0\0` signature at `e_lfanew`.
    MissingPeSignature,
}

impl std::fmt::Display for PeHeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingMzSignature => f.write_str("Missing MZ signature in DOS header"),
            Self::TruncatedDosHeader => f.write_str("DOS header too short to contain e_lfanew"),
            Self::PeHeaderOutOfBounds {
                pe_offset,
                available,
            } => write!(
                f,
                "PE header at offset {pe_offset:#x} is past the {available} bytes read"
            ),
            Self::MissingPeSignature => f.write_str("Expected PE\\0\\0 signature at e_lfanew"),
        }
    }
}

impl std::error::Error for PeHeaderError {}

/// Reads the COFF `Machine` field from the start of a PE file (such as `BOOTX64.EFI`).
/// `bytes` may be just the beginning of the file, as long as it reaches past the PE signature.
pub fn pe_machine_field(bytes: &[u8]) -> Result<u16, PeHeaderError> {
    if !bytes.starts_with(b"MZ") {
        return Err(PeHeaderError::MissingMzSignature);
    }
    let e_lfanew: [u8; 4] = bytes
        .get(DOS_E_LFANEW_OFFSET..DOS_E_LFANEW_OFFSET + 4)
        .and_then(|s| s.try_into().ok())
        .ok_or(PeHeaderError::TruncatedDosHeader)?;
    let pe_offset = u32::from_le_bytes(e_lfanew);

    // "PE\0\0" followed by the 2 byte machine field.
    let out_of_bounds = PeHeaderError::PeHeaderOutOfBounds {
        pe_offset,
        available: bytes.len(),
    };
    let start = usize::try_from(pe_offset).map_err(|_| out_of_bounds)?;
    let header = start
        .checked_add(6)
        .and_then(|end| bytes.get(start..end))
        .ok_or(out_of_bounds)?;

    let (signature, machine) = header.split_at(4);
    if signature != b"PE\0\0" {
        return Err(PeHeaderError::MissingPeSignature);
    }
    Ok(u16::from_le_bytes([machine[0], machine[1]]))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FoundCpuArch {
    Arch(Arch),
    /// Several different architectures, deduplicated, in the order they were found.
    Many(Vec<Arch>),
    /// `EFI/BOOT` exists, but no `BOOT*.EFI` in it has a supported machine type.
    None,
    NoEfiBoot,
}

#[derive(Debug)]
pub enum EfiBootArchError {
    Iso(IsoError),
    /// A `BOOT*.EFI` file in `EFI/BOOT` is not a valid PE image.
    InvalidPe {
        file: String,
        error: PeHeaderError,
    },
}

impl From<IsoError> for EfiBootArchError {
    fn from(e: IsoError) -> Self {
        Self::Iso(e)
    }
}

impl From<std::io::Error> for EfiBootArchError {
    fn from(e: std::io::Error) -> Self {
        Self::Iso(IsoError::Io(e))
    }
}

impl std::fmt::Display for EfiBootArchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Iso(e) => e.fmt(f),
            Self::InvalidPe { file, error } => write!(f, "EFI/BOOT/{file}: {error}"),
        }
    }
}

impl std::error::Error for EfiBootArchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Iso(e) => Some(e),
            Self::InvalidPe { error, .. } => Some(error),
        }
    }
}

/// If `name` starts with `BOOT` and ends with `.EFI`, such as `BOOTX64.EFI`.
fn is_efi_boot_loader_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    bytes.len() >= 8
        && bytes[..4].eq_ignore_ascii_case(b"BOOT")
        && bytes[bytes.len() - 4..].eq_ignore_ascii_case(b".EFI")
}

fn summarize_architectures(found: Vec<Arch>) -> FoundCpuArch {
    let mut unique = Vec::new();
    for arch in found {
        if !unique.contains(&arch) {
            unique.push(arch);
        }
    }
    match unique.as_slice() {
        [] => FoundCpuArch::None,
        [single] => FoundCpuArch::Arch(*single),
        _ => FoundCpuArch::Many(unique),
    }
}

/// Detects the CPU architecture from the PE machine field of each `EFI/BOOT/BOOT*.EFI` file.
pub fn efi_boot_arch<R: Read + Seek>(
    iso: &mut IsoImage<R>,
) -> Result<FoundCpuArch, EfiBootArchError> {
    let root = iso.root();
    let Some(efi_boot) = iso.find_entry(&root, "efi/boot")? else {
        return Ok(FoundCpuArch::NoEfiBoot);
    };
    if efi_boot.kind != EntryKind::Directory {
        return Ok(FoundCpuArch::NoEfiBoot);
    }

    let mut found = Vec::new();
    for entry in iso.read_dir(&efi_boot)? {
        if entry.kind != EntryKind::File || !is_efi_boot_loader_name(&entry.name) {
            continue;
        }
        let mut header = Vec::with_capacity(PE_HEADER_READ_LIMIT);
        iso.open_file(&entry)?
            .take(PE_HEADER_READ_LIMIT as u64)
            .read_to_end(&mut header)?;
        let machine = pe_machine_field(&header).map_err(|error| EfiBootArchError::InvalidPe {
            file: entry.name.clone(),
            error,
        })?;
        if let Some(arch) = Arch::from_pe32_machine_field(machine) {
            found.push(arch);
        }
    }
    Ok(summarize_architectures(found))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe_bytes(pe_offset: u32, machine: u16) -> Vec<u8> {
        let start = pe_offset as usize;
        let mut bytes = vec![0u8; start + 6];
        bytes[0..2].copy_from_slice(b"MZ");
        bytes[DOS_E_LFANEW_OFFSET..DOS_E_LFANEW_OFFSET + 4]
            .copy_from_slice(&pe_offset.to_le_bytes());
        bytes[start..start + 4].copy_from_slice(b"PE\0\0");
        bytes[start + 4..start + 6].copy_from_slice(&machine.to_le_bytes());
        bytes
    }

    #[test]
    fn efi_boot_loader_names() {
        assert!(is_efi_boot_loader_name("BOOTX64.EFI"));
        assert!(is_efi_boot_loader_name("bootaa64.efi"));
        assert!(is_efi_boot_loader_name("BOOTRISCV64.EFI"));
        assert!(!is_efi_boot_loader_name("grubx64.efi"));
        assert!(!is_efi_boot_loader_name("mmx64.efi"));
        assert!(!is_efi_boot_loader_name("BOOTX64.EFI.bak"));
        assert!(!is_efi_boot_loader_name("BOOTEFI"));
        assert!(!is_efi_boot_loader_name(""));
    }

    #[test]
    fn summarize_architectures_cases() {
        assert_eq!(summarize_architectures(vec![]), FoundCpuArch::None);
        assert_eq!(
            summarize_architectures(vec![Arch::X64, Arch::X64]),
            FoundCpuArch::Arch(Arch::X64)
        );
        assert_eq!(
            summarize_architectures(vec![Arch::ARM64, Arch::X64, Arch::ARM64]),
            FoundCpuArch::Many(vec![Arch::ARM64, Arch::X64])
        );
    }

    #[test]
    fn reads_machine_field() {
        assert_eq!(pe_machine_field(&pe_bytes(0x80, 0x8664)), Ok(0x8664));
        assert_eq!(pe_machine_field(&pe_bytes(0x40, 0xAA64)), Ok(0xAA64));
    }

    #[test]
    fn rejects_missing_mz() {
        let mut bytes = pe_bytes(0x80, 0x8664);
        bytes[0] = b'X';
        assert_eq!(
            pe_machine_field(&bytes),
            Err(PeHeaderError::MissingMzSignature)
        );
        assert_eq!(
            pe_machine_field(&[]),
            Err(PeHeaderError::MissingMzSignature)
        );
    }

    #[test]
    fn rejects_truncated_dos_header() {
        let bytes = pe_bytes(0x80, 0x8664);
        assert_eq!(
            pe_machine_field(&bytes[..DOS_E_LFANEW_OFFSET + 3]),
            Err(PeHeaderError::TruncatedDosHeader)
        );
    }

    #[test]
    fn rejects_pe_offset_past_buffer() {
        let bytes = pe_bytes(0x80, 0x8664);
        assert_eq!(
            pe_machine_field(&bytes[..bytes.len() - 1]),
            Err(PeHeaderError::PeHeaderOutOfBounds {
                pe_offset: 0x80,
                available: bytes.len() - 1
            })
        );
    }

    #[test]
    fn rejects_huge_pe_offset_without_overflow() {
        let mut bytes = pe_bytes(0x80, 0x8664);
        bytes[DOS_E_LFANEW_OFFSET..DOS_E_LFANEW_OFFSET + 4]
            .copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            pe_machine_field(&bytes),
            Err(PeHeaderError::PeHeaderOutOfBounds {
                pe_offset: u32::MAX,
                ..
            })
        ));
    }

    #[test]
    fn rejects_missing_pe_signature() {
        let mut bytes = pe_bytes(0x80, 0x8664);
        bytes[0x80] = b'X';
        assert_eq!(
            pe_machine_field(&bytes),
            Err(PeHeaderError::MissingPeSignature)
        );
    }
}
