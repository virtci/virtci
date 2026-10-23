// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::{path::Path, str::FromStr};

use crate::{
    client::iso::{
        extract::FoundCpuArch,
        filesystem::{VolumeDescriptorSet, udf::UdfSectorType},
    },
    util::cpu_arch::Arch,
};

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

pub const BYTES_PER_SECTOR: usize = 2048;

pub struct IsoSector {
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
    /// - Zeroes is unallocated space descriptor
    ///
    /// Offset 6, Size 1, Field "Version" (should always be 0x01)
    ///
    /// Offset 7, Size 2041, Field "Data" payload depending on "Type".
    bytes: [u8; BYTES_PER_SECTOR],
}

impl IsoSector {
    /// Returns either the right sector type, or the byte value which is an unknown sector type.
    pub fn iso_9660_sector_type(&self) -> Result<Iso9660SectorType, u8> {
        return Iso9660SectorType::try_from(self.bytes[0]);
    }

    pub fn udf_sector_type(&self) -> Result<UdfSectorType, u16> {
        return UdfSectorType::try_from(u16::from_le_bytes([self.bytes[0], self.bytes[1]]));
    }

    pub fn standard_identifier(
        &self,
    ) -> Result<Option<IsoStandardIdentifier>, IsoStandardIdentifierParseErr> {
        let part = &self.bytes[1..6];
        if part.iter().all(|&x| x == 0) {
            return Ok(None);
        }
        let s = match str::from_utf8(part) {
            Ok(string) => string,
            // if not valid utf8, definitely not valid ascii
            Err(_) => return Err(IsoStandardIdentifierParseErr::InvalidAscii),
        };
        match IsoStandardIdentifier::from_str(s) {
            Ok(id) => Ok(Some(id)),
            Err(e) => Err(e),
        }
    }
}

impl Default for IsoSector {
    fn default() -> Self {
        Self { bytes: [0u8; 2048] }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Iso9660SectorType {
    BootRecord = 0,
    PrimaryVolumeDescriptor = 1,
    SupplementaryVolumeDescriptor = 2,
    VolumePartitionDescriptor = 3,
    VolumeDescriptorSetTerminator = 255,
}

impl TryFrom<u8> for Iso9660SectorType {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Iso9660SectorType::BootRecord),
            1 => Ok(Iso9660SectorType::PrimaryVolumeDescriptor),
            2 => Ok(Iso9660SectorType::SupplementaryVolumeDescriptor),
            3 => Ok(Iso9660SectorType::VolumePartitionDescriptor),
            255 => Ok(Iso9660SectorType::VolumeDescriptorSetTerminator),
            _ => Err(value),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IsoStandardIdentifier {
    CD001,
    /// Beginning Extended Area. This is only present for Universal Disk Format (UDF).
    BEA01,
    /// ECMA-167 Revision 2. UDF 1.x
    NSR02,
    /// ECMA-167 Revision 3. UDF 2.0+
    NSR03,
    /// Terminating Extended Area. Complementary with `'BEA01'` to mark its end.
    TEA01,
    BOOT2,
    CDW02,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IsoStandardIdentifierParseErr {
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
            "BOOT2" => Ok(IsoStandardIdentifier::BOOT2),
            "CDW02" => Ok(IsoStandardIdentifier::CDW02),
            _ => Err(IsoStandardIdentifierParseErr::Unknown),
        }
    }
}

pub fn inspect_iso(file: &Path) {
    let mut opened_file = std::fs::File::open(file).unwrap();

    use std::io::{Read, Seek, SeekFrom};

    println!(
        "ISO Type: {:?}",
        VolumeDescriptorSet::from_stream(&mut opened_file)
    );

    // ignore the first 16 sectors, so the first 32768 bytes.
    let _ = opened_file.seek(SeekFrom::Start(16 * 2048));

    let mut sector = IsoSector::default();

    let _ = opened_file.read_exact(&mut sector.bytes);

    let _ = opened_file.seek(SeekFrom::Start(17 * 2048));
    let mut sector17 = IsoSector::default();
    let _ = opened_file.read_exact(&mut sector17.bytes);

    let _ = opened_file.seek(SeekFrom::Start(18 * 2048));
    let mut sector18 = IsoSector::default();
    let _ = opened_file.read_exact(&mut sector18.bytes);

    let _ = opened_file.seek(SeekFrom::Start(19 * 2048));
    let mut sector19 = IsoSector::default();
    let _ = opened_file.read_exact(&mut sector19.bytes);

    let _ = opened_file.seek(SeekFrom::Start(20 * 2048));
    let mut sector20 = IsoSector::default();
    let _ = opened_file.read_exact(&mut sector20.bytes);

    println!(
        "Sector 16... Type: {:?}, Standard Identifier: {:?}",
        sector.iso_9660_sector_type().unwrap(),
        sector.standard_identifier()
    );
    println!(
        "Sector 17... Type: {:?}, Standard Identifier: {:?}",
        sector17.iso_9660_sector_type().unwrap(),
        sector17.standard_identifier()
    );
    println!(
        "Sector 18... Type: {:?}, Standard Identifier: {:?}",
        sector18.iso_9660_sector_type().unwrap(),
        sector18.standard_identifier()
    );
    println!(
        "Sector 19... Type: {:?}, Standard Identifier: {:?}",
        sector19.iso_9660_sector_type().unwrap(),
        sector19.standard_identifier()
    );
    println!(
        "Sector 20... Type: {:?}, Standard Identifier: {:?}",
        sector20.iso_9660_sector_type().unwrap(),
        sector20.standard_identifier()
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
        FoundCpuArch::get_cpu_arch_from_efi_boot(
            &root_record,
            &mut opened_file.try_clone().expect("hmm")
        )
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
