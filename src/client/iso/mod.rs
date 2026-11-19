// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::{path::Path, str::FromStr};

use anyhow::Context;

use crate::{
    client::iso::{
        extract::efi_boot_arch,
        filesystem::{image::IsoImage, udf::UdfSectorType},
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

pub fn inspect_iso(file: &Path) -> anyhow::Result<()> {
    let opened_file =
        std::fs::File::open(file).with_context(|| format!("Failed to open {}", file.display()))?;
    let mut iso = IsoImage::new(opened_file)?;

    println!("Descriptors: {:?}", iso.descriptors());
    println!("Volume ID: {}", iso.volume().volume_id);
    println!("Name encoding: {:?}", iso.encoding());

    let root = iso.root();
    println!("Root directory:");
    for entry in iso.read_dir(&root)? {
        let size: u64 = entry.extents.iter().map(|e| u64::from(e.len)).sum();
        println!("  {:?} {} ({size} bytes)", entry.kind, entry.name);
    }

    println!("EFI boot arch: {:?}", efi_boot_arch(&mut iso)?);
    Ok(())
}
