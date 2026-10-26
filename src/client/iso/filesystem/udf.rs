// Copyright (C) 2026 gabkhanfig
// SPDX-License-Identifier: GPL-2.0-only

use std::io::{Read, Seek, SeekFrom};

use anyhow::Context;

use crate::client::iso::{BYTES_PER_SECTOR, filesystem::AbsoluteSector};

/// https://wiki.osdev.org/UDF

/// This is the first sector where the AVDP should exist.
/// If it's not there, check the final sector (N). If it's not there too,
/// check the last 256th sector (N - 256).
const FIRST_ANCHOR_VOLUME_DESCRIPTOR_POINTER_SECTOR: AbsoluteSector = AbsoluteSector(256);

#[cfg(target_endian = "big")]
compile_error!("UDF parser assumes little endian host");

#[repr(C)]
pub struct AnchorVolumeDescriptorPointer {
    pub descriptor_tag: DescriptorTag,
    /// A bunch
    pub main_volume_descriptor_sequence: Extent,
    pub reserve_volume_descriptor_sequence: Extent,
    pub reserved: [u8; 480],
}

impl AnchorVolumeDescriptorPointer {
    pub fn from_full_stream<T: Seek + Read>(stream: &mut T) -> anyhow::Result<Self> {
        let old_seek = stream.stream_position().expect("Why fail");
        let result = Self::from_full_stream_helper(stream);
        stream
            .seek(SeekFrom::Start(old_seek))
            .expect("Why did restoring old seek fail?"); // restore since it's shared
        result
    }

    /// Only the AVDP specific checks. The descriptor tag itself (checksum, identifier, version,
    /// location, CRC) is checked by [`DescriptorTag::validate_sector`] on the raw bytes.
    fn validate(self: &Self) -> anyhow::Result<()> {
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

        Ok(())
    }

    fn from_full_stream_helper<T: Seek + Read>(stream: &mut T) -> anyhow::Result<Self> {
        // only need 512 bytes
        let total_sectors = stream.seek(SeekFrom::End(0))? / BYTES_PER_SECTOR as u64;
        if total_sectors <= FIRST_ANCHOR_VOLUME_DESCRIPTOR_POINTER_SECTOR.0 as u64 + 1 {
            anyhow::bail!("Not enough sectors for UDF");
        }
        let end_sector = AbsoluteSector(
            u32::try_from(total_sectors - 1)
                .context("Image too large for UDF sector addressing")?,
        );

        let mut failures: Vec<(AbsoluteSector, anyhow::Error)> = Vec::new();

        for sector in [
            FIRST_ANCHOR_VOLUME_DESCRIPTOR_POINTER_SECTOR,
            end_sector,
            AbsoluteSector(end_sector.0 - 256),
        ] {
            let attempt = (|| -> anyhow::Result<Self> {
                stream.seek(SeekFrom::Start(sector.byte_offset()))?;
                let mut buffer = [0u8; 512];
                stream.read_exact(&mut buffer)?;
                DescriptorTag::validate_sector(
                    &buffer,
                    UdfSectorType::AnchorVolumeDescriptorPointer,
                    sector.0,
                )?;
                let avdp = Self::from_bytes_unvalidated(buffer);
                avdp.validate()?;
                Ok(avdp)
            })();

            match attempt {
                Ok(avdp) => return Ok(avdp),
                Err(e) => failures.push((sector, e)),
            }
        }

        let details: String = failures
            .iter()
            .map(|(sector, e)| format!("\n  sector {}: {e:#}", sector.0))
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
            descriptor_tag: DescriptorTag::from_bytes(&bytes[0..16]),
            main_volume_descriptor_sequence: Extent {
                len: u32::from_le_bytes(bytes[16..20].try_into().expect("UDF AVDP MVDS len")),
                location_sector: AbsoluteSector(u32::from_le_bytes(
                    bytes[20..24]
                        .try_into()
                        .expect("UDF AVDP MVDS location sector"),
                )),
            },
            reserve_volume_descriptor_sequence: Extent {
                len: u32::from_le_bytes(bytes[24..28].try_into().expect("UDF AVDP RVDS len")),
                location_sector: AbsoluteSector(u32::from_le_bytes(
                    bytes[28..32]
                        .try_into()
                        .expect("UDF AVDP RVDS location sector"),
                )),
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

    /// # Arguments
    ///
    /// - `bytes` Reads the first 16 bytes as the `DescriptorTag`.
    fn from_bytes(bytes: &[u8]) -> Self {
        debug_assert!(bytes.len() >= 16);

        Self {
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
            reserved: u8::from_le_bytes(bytes[5..6].try_into().expect("UDF AVDP DT tag reserved")),
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
        }
    }

    /// Validates the descriptor tag at the start of `sector_bytes`, and the CRC of the descriptor
    /// body that follows it.
    ///
    /// # Arguments
    ///
    /// - `sector_bytes` The raw descriptor bytes, starting with the tag. Must contain at least
    /// `16 + descriptor_crc_len` bytes, so normally the whole sector.
    /// - `expected_tag_identifier` What kind of descriptor this should be.
    /// - `expected_location` The sector this was read from. Every tag records its own location
    /// (relative to the partition for descriptors inside one).
    fn validate_sector(
        sector_bytes: &[u8],
        expected_tag_identifier: UdfSectorType,
        expected_location: u32,
    ) -> anyhow::Result<()> {
        const TAG_SIZE: usize = std::mem::size_of::<DescriptorTag>();

        if sector_bytes.len() < TAG_SIZE {
            anyhow::bail!(
                "{expected_tag_identifier:?}: only {} bytes, need at least {TAG_SIZE} for the descriptor tag",
                sector_bytes.len()
            );
        }

        let sector_descriptor_tag = DescriptorTag::from_bytes(sector_bytes);

        let checksum = DescriptorTag::tag_checksum_in_bytes(sector_bytes);
        if checksum != sector_descriptor_tag.tag_checksum {
            anyhow::bail!(
                "{expected_tag_identifier:?}: tag checksum {} != calculated {checksum}",
                sector_descriptor_tag.tag_checksum
            );
        }

        if sector_descriptor_tag.tag_identifier != expected_tag_identifier as u16 {
            anyhow::bail!(
                "{expected_tag_identifier:?}: tag identifier is {}, expected {}",
                sector_descriptor_tag.tag_identifier,
                expected_tag_identifier as u16
            );
        }

        // NSR02 / NSR03. Discs mix these, so don't require it to match the NSR descriptor.
        if sector_descriptor_tag.descriptor_version != 2
            && sector_descriptor_tag.descriptor_version != 3
        {
            anyhow::bail!(
                "{expected_tag_identifier:?}: descriptor version {} is not 2 (NSR02) or 3 (NSR03)",
                sector_descriptor_tag.descriptor_version
            );
        }

        if sector_descriptor_tag.tag_location != expected_location {
            anyhow::bail!(
                "{expected_tag_identifier:?}: tag location {} != sector read {expected_location}",
                sector_descriptor_tag.tag_location
            );
        }

        // ECMA-167 3/7.2.6: the CRC covers exactly `descriptor_crc_len` bytes after the tag, not
        // the rest of the sector.
        let crc_end = TAG_SIZE + sector_descriptor_tag.descriptor_crc_len as usize;
        if crc_end > sector_bytes.len() {
            anyhow::bail!(
                "{expected_tag_identifier:?}: CRC length {} runs past the {} bytes read",
                sector_descriptor_tag.descriptor_crc_len,
                sector_bytes.len()
            );
        }

        let crc = crc16ccitt(&sector_bytes[TAG_SIZE..crc_end]);
        if crc != sector_descriptor_tag.descriptor_crc {
            anyhow::bail!(
                "{expected_tag_identifier:?}: descriptor CRC {} != calculated {crc}",
                sector_descriptor_tag.descriptor_crc
            );
        }

        Ok(())
    }
}

/// ECMA-167 3/7.1 `extent_ad`. Only used in the volume layer (AVDP, volume descriptors), where
/// locations are absolute. File data uses `short_ad` / `long_ad`, which are partition relative.
#[repr(C)]
pub struct Extent {
    /// How many bytes is the data.
    pub len: u32,
    /// The sector index of the data relative to the beginning of the volume.
    pub location_sector: AbsoluteSector,
}

/// Block index relative to the start of a UDF partition.
/// ECMA-167 calls this a "logical block number". It is NOT an ISO9660 LBA, see [`AbsoluteSector`].
/// Only meaningful together with a [`PartitionRef`], via an [`LbAddr`].
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartitionRelativeBlock(pub u32);

/// Index into the Logical Volume Descriptor's partition map table.
/// The map entry translates this into a [`PartitionNumber`].
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartitionRef(pub u16);

/// The partition's own number, as written in its Partition Descriptor.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PartitionNumber(pub u16);

/// ECMA-167 4/7.1 `lb_addr`. A block inside a partition. 6 bytes on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LbAddr {
    pub block: PartitionRelativeBlock,
    pub partition_ref: PartitionRef,
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a valid AVDP sector at `location`, with a CRC covering `crc_len` bytes.
    fn build_avdp(location: u32, crc_len: u16) -> [u8; 512] {
        let mut bytes = [0u8; 512];
        bytes[0..2]
            .copy_from_slice(&(UdfSectorType::AnchorVolumeDescriptorPointer as u16).to_le_bytes());
        bytes[2..4].copy_from_slice(&2u16.to_le_bytes());
        bytes[12..16].copy_from_slice(&location.to_le_bytes());
        // MVDS / RVDS extents, 16 sectors each
        bytes[16..20].copy_from_slice(&(16 * BYTES_PER_SECTOR as u32).to_le_bytes());
        bytes[20..24].copy_from_slice(&32u32.to_le_bytes());
        bytes[24..28].copy_from_slice(&(16 * BYTES_PER_SECTOR as u32).to_le_bytes());
        bytes[28..32].copy_from_slice(&48u32.to_le_bytes());

        let crc = crc16ccitt(&bytes[16..16 + crc_len as usize]);
        bytes[8..10].copy_from_slice(&crc.to_le_bytes());
        bytes[10..12].copy_from_slice(&crc_len.to_le_bytes());
        bytes[4] = DescriptorTag::tag_checksum_in_bytes(&bytes);
        bytes
    }

    #[test]
    fn crc16ccitt_known_vector() {
        assert_eq!(crc16ccitt(b"123456789"), 0x31C3);
        assert_eq!(crc16ccitt(&[]), 0);
    }

    #[test]
    fn validate_sector_accepts_valid_avdp() {
        let bytes = build_avdp(256, 496);
        DescriptorTag::validate_sector(&bytes, UdfSectorType::AnchorVolumeDescriptorPointer, 256)
            .unwrap();
        AnchorVolumeDescriptorPointer::from_bytes_unvalidated(bytes)
            .validate()
            .unwrap();
    }

    #[test]
    fn validate_sector_uses_crc_len_not_full_sector() {
        // Garbage past the CRC length must not affect the CRC.
        let mut bytes = build_avdp(256, 16);
        bytes[100] = 0xAB;
        DescriptorTag::validate_sector(&bytes, UdfSectorType::AnchorVolumeDescriptorPointer, 256)
            .unwrap();
    }

    #[test]
    fn validate_sector_rejects_bad_fields() {
        let ok = build_avdp(256, 496);
        let id = UdfSectorType::AnchorVolumeDescriptorPointer;

        assert!(DescriptorTag::validate_sector(&ok, id, 257).is_err());
        assert!(DescriptorTag::validate_sector(&ok, UdfSectorType::FileEntry, 256).is_err());
        assert!(DescriptorTag::validate_sector(&ok[..10], id, 256).is_err());

        let mut bad_checksum = ok;
        bad_checksum[4] ^= 1;
        assert!(DescriptorTag::validate_sector(&bad_checksum, id, 256).is_err());

        let mut bad_crc = ok;
        bad_crc[40] ^= 1;
        assert!(DescriptorTag::validate_sector(&bad_crc, id, 256).is_err());

        // crc length past the buffer
        let long_crc = build_avdp(256, 496);
        assert!(DescriptorTag::validate_sector(&long_crc[..256], id, 256).is_err());
    }

    #[test]
    fn validate_sector_accepts_both_descriptor_versions() {
        let id = UdfSectorType::AnchorVolumeDescriptorPointer;
        for version in [2u16, 3] {
            let mut bytes = build_avdp(256, 496);
            bytes[2..4].copy_from_slice(&version.to_le_bytes());
            bytes[4] = DescriptorTag::tag_checksum_in_bytes(&bytes);
            DescriptorTag::validate_sector(&bytes, id, 256).unwrap();
        }

        let mut bytes = build_avdp(256, 496);
        bytes[2..4].copy_from_slice(&1u16.to_le_bytes());
        bytes[4] = DescriptorTag::tag_checksum_in_bytes(&bytes);
        assert!(DescriptorTag::validate_sector(&bytes, id, 256).is_err());
    }
}
