use std::{
    collections::HashSet,
    io::{Read, Seek},
};

use crate::{client::iso::filesystem::FileSystemRecord, util::cpu_arch::Arch};

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

                    // TODO could be out of bounds reads. Fix
                    let file_bytes = entry.read_file_bytes(stream, Some(4096));
                    let pe_offset = u32::from_le_bytes(
                        file_bytes[0x3c as usize..0x3c as usize + 4].try_into()?,
                    );

                    if file_bytes[pe_offset as usize + 0] != 'P' as u8
                        || file_bytes[pe_offset as usize + 1] != 'E' as u8
                        || file_bytes[pe_offset as usize + 2] != 0
                        || file_bytes[pe_offset as usize + 3] != 0
                    {
                        anyhow::bail!("Expected PE\\0\\0 in header");
                    }

                    let machine_arch_value = u16::from_le_bytes([
                        file_bytes[pe_offset as usize + 4],
                        file_bytes[pe_offset as usize + 5],
                    ]);

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
