use std::io::{Read, Seek, SeekFrom};

use crate::client::iso::{BYTES_PER_SECTOR, Iso9660SectorType, IsoSector, IsoStandardIdentifier};

pub mod entry;
pub mod image;
pub mod udf;

pub const PRIMARY_VOLUME_DESCRIPTOR_START_LOOKING_SECTOR_OFFSET: AbsoluteSector =
    AbsoluteSector(16);

pub const PRIMARY_VOLUME_DESCRIPTOR_ROOT_RECORD_OFFSET: usize = 156;

/// Absolute 2048-byte sector index from the start of the image.
/// ISO9660 calls this a logical block address (LBA).
/// Not to be confused with UDF's [`udf::PartitionRelativeBlock`].
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AbsoluteSector(pub u32);

impl AbsoluteSector {
    /// Byte offset from the start of the image, for seeking.
    pub fn byte_offset(self) -> u64 {
        self.0 as u64 * BYTES_PER_SECTOR as u64
    }
}

/// ECMA-167 3/7.1 `extent_ad`. Only used in the volume layer (AVDP, volume descriptors), where
/// locations are absolute. File data uses `short_ad` / `long_ad`, which are partition relative.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct Extent {
    /// How many bytes is the data.
    pub len: u32,
    /// The sector index of the data relative to the beginning of the volume.
    pub location_sector: AbsoluteSector,
}

#[derive(Debug)]
pub enum IsoError {
    Io(std::io::Error),
    NotAnIso,
    /// - `sector` The malformed sector.
    /// - `what` What was malformed as a user facing string message.
    Malformed {
        sector: AbsoluteSector,
        what: &'static str,
    },
    /// e.g. multi-extent (>4 GiB) files
    Unsupported(&'static str),
    NotAFile,
    NotADirectory,
}

impl From<std::io::Error> for IsoError {
    fn from(e: std::io::Error) -> Self {
        IsoError::Io(e)
    }
}

impl std::fmt::Display for IsoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IsoError::Io(e) => write!(f, "I/O error reading ISO: {e}"),
            IsoError::NotAnIso => f.write_str("Not an ISO 9660 / UDF image"),
            IsoError::Malformed { sector, what } => {
                write!(f, "Malformed ISO at sector {}: {what}", sector.0)
            }
            IsoError::Unsupported(what) => write!(f, "Unsupported ISO feature: {what}"),
            IsoError::NotAFile => f.write_str("Expected a file, found a directory"),
            IsoError::NotADirectory => f.write_str("Expected a directory, found a file"),
        }
    }
}

impl std::error::Error for IsoError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IsoError::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// Seeks to `lba` and reads the whole sector.
pub fn read_sector<T: Seek + Read>(
    stream: &mut T,
    lba: AbsoluteSector,
) -> Result<[u8; BYTES_PER_SECTOR], IsoError> {
    let mut buffer: [u8; BYTES_PER_SECTOR] = [0u8; BYTES_PER_SECTOR];
    stream.seek(SeekFrom::Start(lba.byte_offset()))?;
    stream.read_exact(&mut buffer)?;
    Ok(buffer)
}

#[derive(Debug, Clone)]
pub struct VolumeDescriptorSet {
    /// The first sector containing the primary volume descriptor. Nearly always 16.
    /// Technically UDF doesn't require containing iso 9660 data at all.
    /// TODO what happens when multiple copies of the same descriptor?
    pub primary_sector: Option<AbsoluteSector>,
    /// The first sector containing the el torito boot record sector. Nearly always 17.
    pub el_torito_boot_record_sector: Option<AbsoluteSector>,
    /// The first sector containing the joliet sector as a supplementary volume descriptor.
    pub joliet_sector: Option<AbsoluteSector>,
    pub udf: Option<NsrRevision>,
}

impl VolumeDescriptorSet {
    /// # Errors
    ///
    /// - [`IsoError::NotAnIso`] if the stream is too short to contain a volume descriptor, or the
    ///   first one has no recognized standard identifier.
    /// - [`IsoError::Malformed`] if a descriptor appears more than once where it must be unique.
    /// - [`IsoError::Io`] on any other read failure.
    pub fn from_stream<T: Seek + Read>(stream: &mut T) -> Result<Self, IsoError> {
        let mut found_identifiers: Vec<(AbsoluteSector, IsoStandardIdentifier)> = Vec::new();

        let mut primary_sector = None;
        let mut el_torito_boot_record_sector = None;
        let mut joliet_sector = None;

        for lba in (PRIMARY_VOLUME_DESCRIPTOR_START_LOOKING_SECTOR_OFFSET.0..).map(AbsoluteSector) {
            // TODO upper bounds on this loop, or continue on errors after a certain point?
            let mut sector = IsoSector::default();
            stream.seek(SeekFrom::Start(lba.byte_offset()))?;
            if let Err(e) = stream.read_exact(&mut sector.bytes) {
                // Too short to even hold the first descriptor, so this definitely isn't an ISO.
                if found_identifiers.is_empty() && e.kind() == std::io::ErrorKind::UnexpectedEof {
                    return Err(IsoError::NotAnIso);
                }
                return Err(e.into());
            }
            match sector.standard_identifier() {
                Ok(Some(id)) => {
                    match sector.iso_9660_sector_type() {
                        Ok(t) => {
                            if t == Iso9660SectorType::PrimaryVolumeDescriptor
                                && id == IsoStandardIdentifier::CD001
                            {
                                if primary_sector.is_some() {
                                    return Err(IsoError::Malformed {
                                        sector: lba,
                                        what: "Found two primary volume descriptors",
                                    });
                                }
                                primary_sector = Some(lba);
                            }
                            if t == Iso9660SectorType::BootRecord
                                && id == IsoStandardIdentifier::CD001
                            {
                                if sector.bytes[7..30] == *b"EL TORITO SPECIFICATION" {
                                    if el_torito_boot_record_sector.is_some() {
                                        return Err(IsoError::Malformed {
                                            sector: lba,
                                            what: "Found two el torito boot record sectors",
                                        });
                                    }
                                    el_torito_boot_record_sector = Some(lba);
                                }
                            }
                            if t == Iso9660SectorType::SupplementaryVolumeDescriptor
                                && id == IsoStandardIdentifier::CD001
                                && is_joliet_escape(&sector.bytes[88..91])
                            {
                                if joliet_sector.is_some() {
                                    return Err(IsoError::Malformed {
                                        sector: lba,
                                        what: "Found two joliet supplementary volume descriptors",
                                    });
                                }
                                joliet_sector = Some(lba);
                            }
                        }
                        _ => (),
                    };
                    found_identifiers.push((lba, id));
                }
                _ => break,
            }
        }

        if found_identifiers.is_empty() {
            return Err(IsoError::NotAnIso);
        }

        let mut inside_extended_area = false;
        let mut found_nsr_revision = None;

        for (lba, id) in found_identifiers {
            if id == IsoStandardIdentifier::BEA01 {
                if inside_extended_area {
                    return Err(IsoError::Malformed {
                        sector: lba,
                        what: "Found BEA01 while already inside the UDF extended area",
                    });
                }

                inside_extended_area = true;
                continue;
            }

            if inside_extended_area {
                if id == IsoStandardIdentifier::NSR02 || id == IsoStandardIdentifier::NSR03 {
                    if found_nsr_revision.is_some() {
                        return Err(IsoError::Malformed {
                            sector: lba,
                            what: "Found two NSR revisions in the UDF extended area",
                        });
                    }
                    found_nsr_revision = Some(match id {
                        IsoStandardIdentifier::NSR02 => NsrRevision::NSR02,
                        IsoStandardIdentifier::NSR03 => NsrRevision::NSR03,
                        _ => unreachable!(),
                    });
                }
            }

            if id == IsoStandardIdentifier::TEA01 {
                break;
            }
        }

        Ok(Self {
            primary_sector,
            el_torito_boot_record_sector,
            joliet_sector,
            udf: found_nsr_revision,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NsrRevision {
    NSR02,
    NSR03,
}

fn is_joliet_escape(bytes: &[u8]) -> bool {
    if bytes == *b"%/@" || bytes == *b"%/C" || bytes == *b"%/E" {
        true
    } else {
        false
    }
}

/// A record for something on the filesystem.
/// For directories, when you go to the extent where it lives, its just a bunch more contiguous
/// instances of `FileSystemRecord` (at least the raw data that gets parsed into multiple
/// `FileSystemRecord`). This would have no headers to parse out, its just the entries contiguously.
/// For files, this is actually the raw file binary data.
#[derive(Clone, Debug)]
pub struct FileSystemRecord {
    /// Byte offset 0.
    pub len: u8,
    /// Byte offset 1.
    pub extended_attr_record_len: u8,
    /// Byte offset 2
    pub location_of_extent: AbsoluteSector,
    /// Byte offset 10
    pub data_length: u32,
    /// Byte offset 18
    pub recording_date_time: FileSystemDateTime,
    /// Byte offset 25. Bitflags of [`FileBitFlags`].
    pub file_flags: u8,
    /// Byte offset 26.
    pub file_unit_size_interleaved_mode: u8,
    /// Byte offset 27.
    pub interleave_gap_size: u8,
    /// Byte offset 28.
    pub volume_sequence_number: u16,
    /// Byte offset 32. May contains the trailing `";1"`.
    pub file_name_length: u8,
    /// Byte offset 32. May contains the trailing `";1"`.
    pub file_identifier: FileSystemRecordIdentifier,
    pub system_use: Vec<u8>,
}

/// Byte offset of the file identifier within a directory record. Everything before it is fixed size.
const DIRECTORY_RECORD_FIXED_LEN: usize = 33;
/// The smallest a directory record can be: the fixed part plus a 1 byte file identifier.
pub const DIRECTORY_RECORD_MIN_LEN: usize = DIRECTORY_RECORD_FIXED_LEN + 1;

/// Copies `N` bytes starting at `at`. This doesn't do bounds check so only call this after bounds
/// have been checked.
fn array_at<const N: usize>(bytes: &[u8], at: usize) -> [u8; N] {
    bytes[at..at + N]
        .try_into()
        .expect("slice of length N always converts to [u8; N]")
}

impl FileSystemRecord {
    /// Parses a single directory record from the start of `bytes`. `bytes` may be longer than the
    /// record, such as a whole directory extent sliced from the record's start. Only the first
    /// [`FileSystemRecord::len`] bytes are read.
    ///
    /// For the root directory record in the Primary Volume Descriptor, pass the sector bytes from
    /// offset [`PRIMARY_VOLUME_DESCRIPTOR_ROOT_RECORD_OFFSET`] onwards.
    pub fn parse(bytes: &[u8]) -> Result<Self, FileSystemRecordParseError> {
        let Some(&len) = bytes.first() else {
            return Err(FileSystemRecordParseError::BufferTooShort);
        };
        if (len as usize) < DIRECTORY_RECORD_MIN_LEN {
            return Err(FileSystemRecordParseError::LengthTooSmall);
        }
        let Some(record) = bytes.get(..len as usize) else {
            return Err(FileSystemRecordParseError::LengthExceedsBuffer);
        };

        let file_name_length = record[32];
        if file_name_length == 0 {
            return Err(FileSystemRecordParseError::EmptyFileIdentifier);
        }
        let file_identifier_end = DIRECTORY_RECORD_FIXED_LEN + file_name_length as usize;
        let Some(file_identifier_slice) =
            record.get(DIRECTORY_RECORD_FIXED_LEN..file_identifier_end)
        else {
            return Err(FileSystemRecordParseError::FileIdentifierExceedsRecord);
        };

        let file_identifier = match file_identifier_slice {
            [0] => FileSystemRecordIdentifier::SelfDir,
            [1] => FileSystemRecordIdentifier::ParentDir,
            name => FileSystemRecordIdentifier::FileOrDir(name.to_vec()),
        };

        // A padding byte is after the identifier when its length is even, so that the system
        // use area starts on an even offset.
        let system_use_start =
            (file_identifier_end + usize::from(file_name_length % 2 == 0)).min(record.len());

        Ok(FileSystemRecord {
            len,
            extended_attr_record_len: record[1],
            location_of_extent: AbsoluteSector(u32::from_le_bytes(array_at(record, 2))),
            data_length: u32::from_le_bytes(array_at(record, 10)),
            recording_date_time: FileSystemDateTime::from_bytes(array_at(record, 18)),
            file_flags: record[25],
            file_unit_size_interleaved_mode: record[26],
            interleave_gap_size: record[27],
            volume_sequence_number: u16::from_le_bytes(array_at(record, 28)),
            file_name_length,
            file_identifier,
            system_use: record[system_use_start..].to_vec(),
        })
    }

    pub fn is_directory(&self) -> bool {
        return self.file_flags & (FileBitFlags::IsDirectory as u8) != 0;
    }

    pub fn is_file(&self) -> bool {
        return self.file_flags & (FileBitFlags::IsDirectory as u8) == 0;
    }

    pub fn is_final_record(&self) -> bool {
        return self.file_flags & (FileBitFlags::NotFinalDirectoryRecord as u8) == 0;
    }

    pub fn is_associated_file(&self) -> bool {
        return self.file_flags & (FileBitFlags::IsAssociatedFile as u8) != 0;
    }
}

#[derive(Clone, Debug)]
pub enum FileSystemRecordIdentifier {
    /// `.` entry, which would file `file_identifier == [0]`.
    SelfDir,
    /// `..` entry, which would file `file_identifier == [1]`.
    ParentDir,
    /// For normal ISO 9660, this is a subset of ASCII. For Joliet / Rock Ridge, this can be
    /// UCS-2 / UTF-16.
    FileOrDir(Vec<u8>),
}

/// Can be converted into an [`IsoError::Malformed`] with [`FileSystemRecordParseError::at_sector`]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileSystemRecordParseError {
    /// The buffer was empty, so there isn't even a length byte.
    BufferTooShort,
    /// The record's length byte is below [`DIRECTORY_RECORD_MIN_LEN`].
    LengthTooSmall,
    /// The record's length byte is claiming more bytes than were available.
    LengthExceedsBuffer,
    /// The file identifier length is 0, not allowed.
    EmptyFileIdentifier,
    /// The file identifier length goes past the end of the record.
    FileIdentifierExceedsRecord,
}

impl FileSystemRecordParseError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BufferTooShort => "Directory record buffer is empty",
            Self::LengthTooSmall => "Directory record shorter than the 34 byte minimum",
            Self::LengthExceedsBuffer => {
                "Directory record extends past its sector or the directory extent"
            }
            Self::EmptyFileIdentifier => "Directory record has an empty file identifier",
            Self::FileIdentifierExceedsRecord => {
                "Directory record file identifier extends past the end of the record"
            }
        }
    }

    pub fn at_sector(self, sector: AbsoluteSector) -> IsoError {
        IsoError::Malformed {
            sector,
            what: self.as_str(),
        }
    }
}

impl std::fmt::Display for FileSystemRecordParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for FileSystemRecordParseError {}

/// Bitflags for file / directory information for a filesystem entry.
/// The comments on the members are taken straight from https://wiki.osdev.org/ISO_9660
#[repr(u8)]
#[derive(Copy, Clone)]
pub enum FileBitFlags {
    /// If set, the existence of this file need not be made known to the user (basically a 'hidden' flag).
    Hidden = 1 << 0,
    /// If set, this record describes a directory (in other words, it is a subdirectory extent).
    IsDirectory = 1 << 1,
    /// If set, this file is an "Associated File".
    IsAssociatedFile = 1 << 2,
    /// If set, the extended attribute record contains information about the format of this file.
    ExtendedArrtRecordContains = 1 << 3,
    /// If set, owner and group permissions are set in the extended attribute record.
    PermissionInExtendedArrtRecord = 1 << 4,
    // Bits 5 and 6 are reserved
    /// If set, this is not the final directory record for this file (for files spanning several extents, for example files over 4GiB long).
    NotFinalDirectoryRecord = 1 << 7,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FileSystemDateTime {
    /// Byte offset 0.
    pub years_since_1900: u8,
    /// Byte offset 1. Range 1 to 12.
    pub month_of_year: u8,
    /// Byte offset 2. Range 1 to 31.
    pub day_of_month: u8,
    /// Byte offset 3. Range 0 to 23.
    pub hour: u8,
    /// Byte offset 4. Range 0 to 59.
    pub minute: u8,
    /// Byte offset 5. Range 0 to 59.
    pub second: u8,
    /// Byte offset 6. 15 minute intervals from -48 (west) to +52 (east).
    pub gmt_offset: i8,
}

impl FileSystemDateTime {
    pub fn from_bytes(bytes: [u8; 7]) -> Self {
        let [
            years_since_1900,
            month_of_year,
            day_of_month,
            hour,
            minute,
            second,
            gmt_offset,
        ] = bytes;
        Self {
            years_since_1900,
            month_of_year,
            day_of_month,
            hour,
            minute,
            second,
            gmt_offset: i8::from_ne_bytes([gmt_offset]),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn record_bytes(
        name: &[u8],
        flags: u8,
        extent: u32,
        data_len: u32,
        system_use: &[u8],
    ) -> Vec<u8> {
        let padding = usize::from(name.len() % 2 == 0);
        let len = DIRECTORY_RECORD_FIXED_LEN + name.len() + padding + system_use.len();
        let mut bytes = vec![0u8; len];
        bytes[0] = u8::try_from(len).unwrap();
        bytes[2..6].copy_from_slice(&extent.to_le_bytes());
        bytes[6..10].copy_from_slice(&extent.to_be_bytes());
        bytes[10..14].copy_from_slice(&data_len.to_le_bytes());
        bytes[14..18].copy_from_slice(&data_len.to_be_bytes());
        bytes[18..25].copy_from_slice(&[126, 8, 26, 12, 30, 45, 0xF8]); // 2026-08-26 12:30:45, GMT-2
        bytes[25] = flags;
        bytes[28..30].copy_from_slice(&1u16.to_le_bytes());
        bytes[30..32].copy_from_slice(&1u16.to_be_bytes());
        bytes[32] = u8::try_from(name.len()).unwrap();
        bytes[33..33 + name.len()].copy_from_slice(name);
        bytes[33 + name.len() + padding..].copy_from_slice(system_use);
        bytes
    }

    #[test]
    fn parse_file_record_odd_name() {
        let bytes = record_bytes(b"BOOTX64.EFI;1", 0, 1234, 5678, b"RR");
        let record = FileSystemRecord::parse(&bytes).unwrap();
        assert_eq!(record.len as usize, bytes.len());
        assert_eq!(record.location_of_extent, AbsoluteSector(1234));
        assert_eq!(record.data_length, 5678);
        assert!(record.is_file());
        assert_eq!(record.volume_sequence_number, 1);
        assert_eq!(record.recording_date_time.years_since_1900, 126);
        assert_eq!(record.recording_date_time.gmt_offset, -8);
        assert!(matches!(
            record.file_identifier,
            FileSystemRecordIdentifier::FileOrDir(ref n) if n == b"BOOTX64.EFI;1"
        ));
        assert_eq!(record.system_use, b"RR");
    }

    #[test]
    fn parse_directory_record_even_name_skips_padding() {
        let bytes = record_bytes(b"EFI_", FileBitFlags::IsDirectory as u8, 20, 2048, b"SU");
        let record = FileSystemRecord::parse(&bytes).unwrap();
        assert!(record.is_directory());
        assert_eq!(record.system_use, b"SU");
    }

    #[test]
    fn parse_ignores_bytes_after_record() {
        let mut bytes = record_bytes(b"A", 0, 1, 1, &[]);
        let len = bytes.len();
        bytes.extend_from_slice(&[0xFF; 64]);
        let record = FileSystemRecord::parse(&bytes).unwrap();
        assert_eq!(record.len as usize, len);
        assert!(record.system_use.is_empty());
    }

    #[test]
    fn parse_self_and_parent_dir() {
        let flags = FileBitFlags::IsDirectory as u8;
        let self_dir = FileSystemRecord::parse(&record_bytes(&[0], flags, 1, 1, &[])).unwrap();
        let parent = FileSystemRecord::parse(&record_bytes(&[1], flags, 1, 1, &[])).unwrap();
        assert!(matches!(
            self_dir.file_identifier,
            FileSystemRecordIdentifier::SelfDir
        ));
        assert!(matches!(
            parent.file_identifier,
            FileSystemRecordIdentifier::ParentDir
        ));
    }

    #[test]
    fn parse_rejects_empty_buffer() {
        assert_eq!(
            FileSystemRecord::parse(&[]).unwrap_err(),
            FileSystemRecordParseError::BufferTooShort
        );
    }

    #[test]
    fn parse_rejects_length_below_minimum() {
        let mut bytes = record_bytes(b"A", 0, 1, 1, &[]);
        bytes[0] = 33;
        assert_eq!(
            FileSystemRecord::parse(&bytes).unwrap_err(),
            FileSystemRecordParseError::LengthTooSmall
        );
    }

    #[test]
    fn parse_rejects_length_past_buffer() {
        let bytes = record_bytes(b"ABC", 0, 1, 1, &[]);
        assert_eq!(
            FileSystemRecord::parse(&bytes[..bytes.len() - 1]).unwrap_err(),
            FileSystemRecordParseError::LengthExceedsBuffer
        );
    }

    #[test]
    fn parse_rejects_empty_identifier() {
        let mut bytes = record_bytes(b"A", 0, 1, 1, &[]);
        bytes[32] = 0;
        assert_eq!(
            FileSystemRecord::parse(&bytes).unwrap_err(),
            FileSystemRecordParseError::EmptyFileIdentifier
        );
    }

    #[test]
    fn parse_rejects_identifier_past_record() {
        let mut bytes = record_bytes(b"A", 0, 1, 1, &[]);
        bytes[32] = 200;
        assert_eq!(
            FileSystemRecord::parse(&bytes).unwrap_err(),
            FileSystemRecordParseError::FileIdentifierExceedsRecord
        );
    }

    #[test]
    fn parse_error_maps_to_malformed_at_sector() {
        let err = FileSystemRecordParseError::LengthTooSmall.at_sector(AbsoluteSector(42));
        assert!(matches!(
            err,
            IsoError::Malformed {
                sector: AbsoluteSector(42),
                ..
            }
        ));
    }
}
