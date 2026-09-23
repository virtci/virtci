// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::{path::Path, str::FromStr};

use crate::{client::iso::extract::get_cpu_arch_from_efi_boot, util::cpu_arch::Arch};

pub mod extract;
pub mod filesystem;
pub mod installer;

// Relevant reading.
// https://en.wikipedia.org/wiki/ISO_9660
// https://wiki.osdev.org/ISO_9660
// https://en.wikipedia.org/wiki/Universal_Disk_Format

pub struct IsoMetadata {
    arch: Arch,
    // boot_support: IsoBootSupport,
}

pub struct IsoBootSupport {
    bios: bool,
    uefi: bool,
    // track the entries here too?
}

pub struct Iso9660Sector {
    /// Volume descriptor is 2048 bytes.
    /// Offset 0, Size 1, Field "Type"
    /// - `0` Boot record volume descriptor.
    /// - `1` Primary volume descriptor.
    /// - `2` Supplementary volume descriptor, or enhanced volume descriptor.
    /// - `3` Volume partition descriptor.
    /// - `255` Volume descriptor set terminator.
    ///
    /// Offset 1, Size 5, Field "Standard Identifier"
    /// - `'CD001'` ISO 9660 / ECMA-119. Should Walk the descriptor set normally.
    /// - `'BEA01'` Beginning Extended Area. This is only present for Universal Disk Format (UDF).
    /// - `'NSR02'` ECMA-167 Revision 2. UDF stuff.
    /// - `'NSR03'` ECMA-167 Revision 3. UDF stuff.
    /// - `'TEA01'` Terminating Extended Area. Complementary with `'BEA01'` to mark its end.
    /// - `'CDW02'` ECMA-168 (CD-RW). Seemingly nothing uses this.
    ///
    /// Offset 6, Size 1, Field "Version" (should always be 0x01)
    ///
    /// Offset 7, Size 2041, Field "Data" payload depending on "Type".
    bytes: [u8; 2048],
}

impl Iso9660Sector {
    /// Returns either the right sector type, or the byte value which is an unknown sector type.
    pub fn sector_type(&self) -> Result<IsoSectorType, u8> {
        return IsoSectorType::try_from(self.bytes[0]);
    }

    pub fn standard_identifier(
        &self,
    ) -> Result<IsoStandardIdentifier, IsoStandardIdentifierParseErr> {
        let part = &self.bytes[1..6];
        let s = match str::from_utf8(part) {
            Ok(string) => string,
            // if not valid utf8, definitely not valid ascii
            Err(_) => return Err(IsoStandardIdentifierParseErr::InvalidAscii),
        };
        return IsoStandardIdentifier::from_str(s);
    }
}

impl Default for Iso9660Sector {
    fn default() -> Self {
        Self { bytes: [0u8; 2048] }
    }
}

#[derive(Debug, Clone, Copy)]
#[repr(u8)]
pub enum IsoSectorType {
    BootRecord = 0,
    PrimaryVolumeDescriptor = 1,
    SupplementaryVolumeDescriptor = 2,
    VolumePartitionDescriptor = 3,
    VolumeDescriptorSetTerminator = 255,
}

impl TryFrom<u8> for IsoSectorType {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(IsoSectorType::BootRecord),
            1 => Ok(IsoSectorType::PrimaryVolumeDescriptor),
            2 => Ok(IsoSectorType::SupplementaryVolumeDescriptor),
            3 => Ok(IsoSectorType::VolumePartitionDescriptor),
            255 => Ok(IsoSectorType::VolumeDescriptorSetTerminator),
            _ => Err(value),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum IsoStandardIdentifier {
    CD001,
    BEA01,
    NSR02,
    NSR03,
    TEA01,
}

#[derive(Debug)]
pub enum IsoStandardIdentifierParseErr {
    /// Why was this found.
    CDW02,
    InvalidAscii,
    Unknown,
}

impl FromStr for IsoStandardIdentifier {
    type Err = IsoStandardIdentifierParseErr;

    /// `s`: Must always be 5 ASCII characters.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        debug_assert_eq!(s.len(), 5);

        match s {
            "CD001" => Ok(IsoStandardIdentifier::CD001),
            "BEA01" => Ok(IsoStandardIdentifier::BEA01),
            "NSR02" => Ok(IsoStandardIdentifier::NSR02),
            "NSR03" => Ok(IsoStandardIdentifier::NSR03),
            "TEA01" => Ok(IsoStandardIdentifier::TEA01),
            "CDW02" => Err(IsoStandardIdentifierParseErr::CDW02),
            _ => Err(IsoStandardIdentifierParseErr::Unknown),
        }
    }
}

pub fn inspect_iso(file: &Path) {
    let mut opened_file = std::fs::File::open(file).unwrap();

    use std::io::{Read, Seek, SeekFrom};

    // ignore the first 16 sectors, so the first 32768 bytes.
    let _ = opened_file.seek(SeekFrom::Start(16 * 2048));

    let mut sector = Iso9660Sector::default();

    let _ = opened_file.read_exact(&mut sector.bytes);

    println!(
        "Type: {:?}, Standard Identifier: {:?}",
        sector.sector_type().unwrap(),
        sector.standard_identifier().unwrap()
    );

    println!("System Identifier {}", unsafe {
        str::from_utf8_unchecked(&sector.bytes[8..40])
    });

    println!("Volume Identifier {}", unsafe {
        str::from_utf8_unchecked(&sector.bytes[40..72])
    });

    let root_record = unsafe {
        filesystem::FileSystemRecord::parse_from_directory_entry_start(
            sector.bytes.as_ptr().byte_add(156),
        )
        .expect("huh")
    };
    println!("");
    println!("Root Directory Entry {root_record:?}");
    println!("");

    let entries = root_record
        .directory_records(&mut opened_file.try_clone().expect("hmm"))
        .expect("yeah");

    for entry in entries {
        println!("New FS Entry {entry:?}");
        match entry.file_identifier.clone() {
            filesystem::FileSystemRecordIdentifier::FileOrDir(items) => {
                println!(
                    "Entry Name as UTF8: {}, is file? {}, is directory? {}",
                    std::str::from_utf8(items.as_slice()).expect("holy"),
                    entry.is_file(),
                    entry.is_directory()
                )
            }
            _ => (),
        }
    }

    println!(
        "Read CPU arch: {:?}",
        get_cpu_arch_from_efi_boot(&root_record, &mut opened_file.try_clone().expect("hmm"))
    );

    // let efi_boot_record = root_record
    //     .record_for("efi/boot", &mut opened_file.try_clone().expect("hmm"))
    //     .unwrap()
    //     .unwrap();

    // let efi_boot_entries = efi_boot_record
    //     .directory_records(&mut opened_file.try_clone().expect("hmm"))
    //     .expect("yeah");

    // for entry in efi_boot_entries {
    //     println!("");
    //     println!("EFI/BOOT FS Entry {entry:?}");
    //     match entry.file_identifier.clone() {
    //         filesystem::FileSystemRecordIdentifier::FileOrDir(items) => {
    //             let name = std::str::from_utf8(items.as_slice())
    //                 .expect("holy")
    //                 .trim_end_matches(";1");
    //             println!(
    //                 "Entry Name as UTF8 (with ';1' trimmed if present): {name}, is file? {}, is directory? {}",
    //                 entry.is_file(),
    //                 entry.is_directory()
    //             );
    //             if !name.starts_with("BOOT") || !name.ends_with(".EFI") {
    //                 continue;
    //             }

    //             let _ = opened_file.seek(SeekFrom::Start(entry.location_of_extent as u64 * 2048));
    //             let bytes_to_read = usize::min(entry.data_length as usize, 4096);
    //             let mut maybe_elf_bytes = Vec::<u8>::with_capacity(bytes_to_read);
    //             maybe_elf_bytes.resize(bytes_to_read, 0);

    //             let _ = opened_file.read_exact(&mut maybe_elf_bytes);

    //             let arch_from_elf = Arch::from_elf_header(&maybe_elf_bytes);
    //             println!("Parsed ELF Arch: {arch_from_elf:?}");
    //             let pe_offset = u32::from_le_bytes(
    //                 maybe_elf_bytes[0x3c as usize..0x3c as usize + 4]
    //                     .try_into()
    //                     .expect("slice length mismatch"),
    //             );

    //             println!(
    //                 "At pe_offset: {:x?}",
    //                 &maybe_elf_bytes[pe_offset as usize..pe_offset as usize + 8]
    //             );

    //             // println!("Actual bytes trying to parse ELF arch: {maybe_elf_bytes:?}");
    //             println!(
    //                 "At 0x12: {:?}",
    //                 &maybe_elf_bytes[0x12 as usize..0x12 as usize + 12]
    //             );
    //         }
    //         _ => (),
    //     }
    // }
}
