use std::{
    collections::HashSet,
    io::{Read, Seek},
};

use crate::{client::iso::filesystem::FileSystemRecord, util::cpu_arch::Arch};

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

#[derive(Debug, Clone)]
pub enum FoundCpuArch {
    Arch(Arch),
    Many(Vec<Arch>),
    None,
    NoEfiBoot,
}

impl FoundCpuArch {
    /// Returns a result. If `Ok`, it was able to read through the records successfully, and stored the
    /// found value in the inner Option. If that inner Option contains `Some`, a singular architecture
    /// was successfully parsed. If it contains `None`, however, it was unable to find the architecture.
    /// This could be because there were a few conflicting ones found.
    pub fn get_cpu_arch_from_efi_boot<T: Seek + Read>(
        root_record: &FileSystemRecord,
        stream: &mut T,
    ) -> anyhow::Result<Self> {
        let efi_boot_record = {
            let r = root_record.record_for("efi/boot", stream)?;
            if r.is_none() {
                return Ok(Self::NoEfiBoot);
            }
            r.expect("has some here")
        };

        let efi_boot_entries = efi_boot_record.directory_records(stream)?;

        let mut found_architectures = Vec::<Arch>::default();

        // Should be PE32 or PE32+
        for entry in efi_boot_entries {
            match entry.file_identifier.clone() {
                super::filesystem::FileSystemRecordIdentifier::FileOrDir(items) => {
                    let name = std::str::from_utf8(items.as_slice())?.trim_end_matches(";1");
                    println!(
                        "Entry Name as UTF8 (with ';1' trimmed if present): {name}, is file? {}, is directory? {}",
                        entry.is_file(),
                        entry.is_directory()
                    );
                    if !name.starts_with("BOOT") || !name.ends_with(".EFI") {
                        continue;
                    }

                    let file_bytes = entry.read_file_bytes(stream, Some(PE_HEADER_READ_LIMIT))?;
                    let machine_arch_value = pe_machine_field(&file_bytes)?;

                    if let Some(arch) = Arch::from_pe32_machine_field(machine_arch_value) {
                        found_architectures.push(arch);
                    }
                }
                _ => (),
            }
        }

        let Some(first) = found_architectures.first() else {
            return Ok(Self::None);
        };

        if found_architectures.iter().all(|x| *x == *first) {
            return Ok(Self::Arch(found_architectures[0]));
        } else {
            let mut unique = HashSet::new();

            // TODO obviously don't print out here but get something useful?
            println!(
                "[VirtCI] Found mismatching architectures in EFI/BOOT/: {:?}",
                found_architectures
            );

            found_architectures.retain(|x| unique.insert(*x));
            return Ok(Self::Many(found_architectures));
        }
    }
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
