// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::io::{Read, Seek, SeekFrom};

use anyhow::Context;

use crate::client::iso::BYTES_PER_SECTOR;

/// https://wiki.osdev.org/UDF

/// This is the first sector where the AVDP should exist.
/// If it's not there, check the final sector (N). If it's not there too,
/// check the last 256th sector (N - 256).
const FIRST_ANCHOR_VOLUME_DESCRIPTOR_POINTER_SECTOR: u64 = 256;

#[cfg(target_endian = "big")]
compile_error!("UDF parser assumes little endian host");

#[repr(C)] // the reserved bytes must be right after the extents for the CRC-16-CCITT check
pub struct AnchorVolumeDescriptorPointer {
    pub descriptor_tag: DescriptorTag,
    pub main_volume_descriptor_sequence: Extent,
    pub reserve_volume_descriptor_sequence: Extent,
    pub reserved: [u8; 480],
}

impl AnchorVolumeDescriptorPointer {
    pub fn from_full_stream<T: Seek + Read>(
        stream: &mut T,
        expected_descriptor_version: u16,
    ) -> anyhow::Result<Self> {
        let old_seek = stream.stream_position().expect("Why fail");
        let result = Self::from_full_stream_helper(stream, expected_descriptor_version);
        stream
            .seek(SeekFrom::Start(old_seek))
            .expect("Why did restoring old seek fail?"); // restore since it's shared
        result
    }

    fn validate(
        self: &Self,
        expected_tag_identifier: UdfSectorType,
        expected_descriptor_version: u16,
        expected_location: u32,
    ) -> anyhow::Result<()> {
        debug_assert!(expected_descriptor_version == 2 || expected_descriptor_version == 3);

        const CRC_BUFFER_SIZE: usize = std::mem::size_of::<AnchorVolumeDescriptorPointer>()
            - std::mem::size_of::<DescriptorTag>();

        if self.descriptor_tag.tag_location != expected_location {
            anyhow::bail!(
                "tag location {} != sector read {expected_location}",
                self.descriptor_tag.tag_location
            );
        }

        if self.descriptor_tag.tag_identifier != expected_tag_identifier as u16 {
            anyhow::bail!(
                "Expected tag identifier of anchor volume descriptor pointer to be {expected_tag_identifier:?}"
            );
        }

        // NSR02 / NSR03
        debug_assert!(expected_descriptor_version == 2 || expected_descriptor_version == 3);
        if self.descriptor_tag.descriptor_version != expected_descriptor_version {
            anyhow::bail!(
                "Expected descriptor version of anchor volume descriptor pointer to be {expected_descriptor_version}"
            );
        }

        unsafe {
            let descriptor_tag_as_bytes = &self.descriptor_tag as *const DescriptorTag as *const u8;
            if DescriptorTag::tag_checksum_in_bytes(&std::slice::from_raw_parts(
                descriptor_tag_as_bytes,
                std::mem::size_of::<DescriptorTag>(),
            )) != self.descriptor_tag.tag_checksum
            {
                anyhow::bail!(
                    "Failed descriptor tag checksum for anchor volume descriptor pointer"
                );
            }
        }

        if (self.descriptor_tag.descriptor_crc_len as usize) + 16 > 512 {
            anyhow::bail!(
                "Cyclic redundancy check length too big for anchor volume descriptor pointer"
            );
        }

        // Each descriptor sequence apparently needs to cover 16 sectors
        if self.main_volume_descriptor_sequence.len < (16 * BYTES_PER_SECTOR as u32) {
            anyhow::bail!(
                "Main volume descriptor sequence must be at least 16 sectors for anchor volume descriptor pointer"
            );
        }
        if self.reserve_volume_descriptor_sequence.len < (16 * BYTES_PER_SECTOR as u32) {
            anyhow::bail!(
                "Reserve volume descriptor sequence must be at least 16 sectors for anchor volume descriptor pointer"
            );
        }

        let mut crc_bytes: [u8; CRC_BUFFER_SIZE] = [0u8; CRC_BUFFER_SIZE];
        unsafe {
            let src = &self.main_volume_descriptor_sequence as *const Extent as *const u8;
            let dst = crc_bytes.as_mut_ptr();
            std::ptr::copy_nonoverlapping(src, dst, CRC_BUFFER_SIZE);
        }
        if crc16ccitt(&crc_bytes) != self.descriptor_tag.descriptor_crc {
            anyhow::bail!("Failed cyclic redundancy check for anchor volume descriptor pointer");
        }

        Ok(())
    }

    fn from_full_stream_helper<T: Seek + Read>(
        stream: &mut T,
        expected_descriptor_version: u16,
    ) -> anyhow::Result<Self> {
        // only need 512 bytes
        let end_sector = stream.seek(SeekFrom::End(0))? / 2048 - 1;
        if end_sector <= FIRST_ANCHOR_VOLUME_DESCRIPTOR_POINTER_SECTOR {
            anyhow::bail!("Not enough sectors for UDF");
        }

        let mut failures: Vec<(u64, anyhow::Error)> = Vec::new();

        for sector in [256, end_sector, end_sector - 256] {
            let attempt = (|| -> anyhow::Result<Self> {
                stream.seek(SeekFrom::Start(sector * BYTES_PER_SECTOR as u64))?;
                let mut buffer = [0u8; 512];
                stream.read_exact(&mut buffer)?;
                let avdp = Self::from_bytes_unvalidated(buffer);
                avdp.validate(
                    UdfSectorType::AnchorVolumeDescriptorPointer,
                    expected_descriptor_version,
                    sector as u32,
                )?;
                Ok(avdp)
            })();

            match attempt {
                Ok(avdp) => return Ok(avdp),
                Err(e) => failures.push((sector, e)),
            }
        }

        let details: String = failures
            .iter()
            .map(|(sector, e)| format!("\n  sector {sector}: {e:#}"))
            .collect();
        anyhow::bail!("No valid UDF anchor volume descriptor pointer found:{details}");
    }

    fn from_bytes_unvalidated(bytes: [u8; 512]) -> Self {
        let mut reserved: [u8; 480] = [0; 480];
        reserved[..480].copy_from_slice(
            &bytes[std::mem::size_of::<DescriptorTag>()
                + std::mem::size_of::<Extent>()
                + std::mem::size_of::<Extent>()..],
        );

        Self {
            descriptor_tag: DescriptorTag {
                tag_identifier: u16::from_le_bytes(
                    bytes[0..2].try_into().expect("UDF AVDP DT tag identifier"),
                ),
                descriptor_version: u16::from_le_bytes(
                    bytes[2..4]
                        .try_into()
                        .expect("UDF AVDP DT descriptor version"),
                ),
                tag_checksum: u8::from_le_bytes(
                    bytes[4..5].try_into().expect("UDF AVDP DT tag checksum"),
                ),
                reserved: u8::from_le_bytes(
                    bytes[5..6].try_into().expect("UDF AVDP DT tag reserved"),
                ),
                tag_serial_number: u16::from_le_bytes(
                    bytes[6..8]
                        .try_into()
                        .expect("UDF AVDP DT tag serial number"),
                ),
                descriptor_crc: u16::from_le_bytes(
                    bytes[8..10].try_into().expect("UDF AVDP DT descriptor crc"),
                ),
                descriptor_crc_len: u16::from_le_bytes(
                    bytes[10..12]
                        .try_into()
                        .expect("UDF AVDP DT descriptor crc length"),
                ),
                tag_location: u32::from_le_bytes(
                    bytes[12..16].try_into().expect("UDF AVDP DT tag location"),
                ),
            },
            main_volume_descriptor_sequence: Extent {
                len: u32::from_le_bytes(bytes[16..20].try_into().expect("UDF AVDP MVDS len")),
                location_sector: u32::from_le_bytes(
                    bytes[20..24]
                        .try_into()
                        .expect("UDF AVDP MVDS location sector"),
                ),
            },
            reserve_volume_descriptor_sequence: Extent {
                len: u32::from_le_bytes(bytes[24..28].try_into().expect("UDF AVDP RVDS len")),
                location_sector: u32::from_le_bytes(
                    bytes[28..32]
                        .try_into()
                        .expect("UDF AVDP RVDS location sector"),
                ),
            },
            reserved,
        }
    }
}

#[repr(C)]
pub struct DescriptorTag {
    pub tag_identifier: u16,
    pub descriptor_version: u16,
    pub tag_checksum: u8,
    pub reserved: u8, // needed for checksum
    pub tag_serial_number: u16,
    pub descriptor_crc: u16,
    pub descriptor_crc_len: u16,
    pub tag_location: u32,
}

impl DescriptorTag {
    fn tag_checksum_in_bytes(raw: &[u8]) -> u8 {
        raw[..16]
            .iter()
            .enumerate()
            .filter(|&(i, _)| i != 4) // ignore the actual `tag_checksum`
            .fold(0u8, |acc, (_, &b)| acc.wrapping_add(b))
    }
}

#[repr(C)]
pub struct Extent {
    /// How many bytes is the data.
    pub len: u32,
    /// The sector index of the data relative to the beginning of the volume.
    pub location_sector: u32,
}

fn crc16ccitt(data: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                (crc << 1) ^ 0x1021
            } else {
                crc << 1
            };
        }
    }
    crc
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum UdfSectorType {
    PrimaryVolumeDescriptor = 0x0001,
    AnchorVolumeDescriptorPointer = 0x0002,
    VolumeDescriptorPointer = 0x0003,
    ImplementationUseVolumeDescriptor = 0x0004,
    PartitionDescriptor = 0x0005,
    LogicalVolumeDescriptor = 0x0006,
    UnallocatedSpaceDescriptor = 0x0007,
    TerminatingDescriptor = 0x0008,
    LogicalVolumeIntegrityDescriptor = 0x0009,
    FileSetDescriptor = 0x0100,
    FileIdentifierDescriptor = 0x0101,
    AllocationExtentDescriptor = 0x0102,
    IndirectEntry = 0x0103,
    TerminalEntry = 0x0104,
    FileEntry = 0x0105,
    ExtendedAttributeHeaderDescriptor = 0x0106,
    UnallocatedSpaceEntry = 0x0107,
    SpaceBitmapDescriptor = 0x0108,
    PartitionIntegrityEntry = 0x0109,
    ExtendedFileEntry = 0x010a,
}

impl TryFrom<u16> for UdfSectorType {
    type Error = u16;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0001 => Ok(UdfSectorType::PrimaryVolumeDescriptor),
            0x0002 => Ok(UdfSectorType::AnchorVolumeDescriptorPointer),
            0x0003 => Ok(UdfSectorType::VolumeDescriptorPointer),
            0x0004 => Ok(UdfSectorType::ImplementationUseVolumeDescriptor),
            0x0005 => Ok(UdfSectorType::PartitionDescriptor),
            0x0006 => Ok(UdfSectorType::LogicalVolumeDescriptor),
            0x0007 => Ok(UdfSectorType::UnallocatedSpaceDescriptor),
            0x0008 => Ok(UdfSectorType::TerminatingDescriptor),
            0x0009 => Ok(UdfSectorType::LogicalVolumeIntegrityDescriptor),
            0x0100 => Ok(UdfSectorType::FileSetDescriptor),
            0x0101 => Ok(UdfSectorType::FileIdentifierDescriptor),
            0x0102 => Ok(UdfSectorType::AllocationExtentDescriptor),
            0x0103 => Ok(UdfSectorType::IndirectEntry),
            0x0104 => Ok(UdfSectorType::TerminalEntry),
            0x0105 => Ok(UdfSectorType::FileEntry),
            0x0106 => Ok(UdfSectorType::ExtendedAttributeHeaderDescriptor),
            0x0107 => Ok(UdfSectorType::UnallocatedSpaceEntry),
            0x0108 => Ok(UdfSectorType::SpaceBitmapDescriptor),
            0x0109 => Ok(UdfSectorType::PartitionIntegrityEntry),
            0x010a => Ok(UdfSectorType::ExtendedFileEntry),
            _ => Err(value),
        }
    }
}
