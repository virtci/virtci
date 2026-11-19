use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;

use crate::client::iso::BYTES_PER_SECTOR;
use crate::client::iso::IsoSector;
use crate::client::iso::filesystem::AbsoluteSector;
use crate::client::iso::filesystem::DIRECTORY_RECORD_MIN_LEN;
use crate::client::iso::filesystem::Extent;
use crate::client::iso::filesystem::FileBitFlags;
use crate::client::iso::filesystem::FileSystemRecord;
use crate::client::iso::filesystem::FileSystemRecordIdentifier;
use crate::client::iso::filesystem::IsoError;
use crate::client::iso::filesystem::PRIMARY_VOLUME_DESCRIPTOR_ROOT_RECORD_OFFSET;
use crate::client::iso::filesystem::VolumeDescriptorSet;
use crate::client::iso::filesystem::entry::Entry;
use crate::client::iso::filesystem::entry::EntryKind;
use crate::client::iso::filesystem::entry::group_into_entries;
use crate::client::iso::filesystem::entry::read_directory_records;
use crate::client::iso::filesystem::read_sector;

pub struct IsoImage<R: Read + Seek> {
    stream: R,
    descriptors: VolumeDescriptorSet,
    tree: DirectoryTree,
    total_image_sectors: u32,
}

impl<R: Read + Seek> IsoImage<R> {
    pub fn new(stream: R) -> Result<Self, IsoError> {
        iso_image_from_stream(stream)
    }

    pub fn descriptors(&self) -> &VolumeDescriptorSet {
        &self.descriptors
    }

    /// The entry for the root record.
    pub fn root(&self) -> Entry {
        match &self.tree {
            DirectoryTree::Iso9660Family { root, .. } => root.clone(),
        }
    }

    /// Get all entries in `dir`.
    pub fn read_dir(&mut self, dir: &Entry) -> Result<Vec<Entry>, IsoError> {
        if dir.kind != EntryKind::Directory {
            return Err(IsoError::NotADirectory);
        }
        let descriptor = match dir.kind {
            EntryKind::Directory => {
                debug_assert_eq!(dir.extents.len(), 1);
                dir.extents[0]
            }
            _ => return Err(IsoError::NotADirectory),
        };
        let records = read_directory_records(&mut self.stream, descriptor)?;
        match &self.tree {
            DirectoryTree::Iso9660Family { encoding, .. } => {
                group_into_entries(records, *encoding, self.total_image_sectors)
            }
        }
    }

    /// # Arguments
    ///
    /// - `dir` The directory to search in. This can be `IsoImage::root()`.
    /// - `path_case_insensitive` A path separated by `/` only. Do not use `..`.
    pub fn find_entry(
        &mut self,
        dir: &Entry,
        path_case_insensitive: &str,
    ) -> Result<Option<Entry>, IsoError> {
        let mut current = dir.clone();
        for component in path_case_insensitive
            .split('/')
            .filter(|c| !c.is_empty() && *c != ".")
        {
            if component == ".." {
                return Err(IsoError::Unsupported(
                    "Cannot use '..' to navigate Iso9660 trees",
                ));
            }
            if current.kind != EntryKind::Directory {
                return Ok(None);
            }
            match Entry::find_by_name(self.read_dir(&current)?, component) {
                Some(next) => current = next,
                None => return Ok(None),
            }
        }
        Ok(Some(current))
    }

    pub fn open_file<'a>(&'a mut self, file: &'a Entry) -> Result<IsoFileReader<'a, R>, IsoError> {
        if file.kind != EntryKind::File {
            return Err(IsoError::NotAFile);
        }
        Ok(IsoFileReader::<'a> {
            stream: &mut self.stream,
            extents: file.extents.iter(),
            remaining_in_extent: 0,
        })
    }

    pub fn read_file_bytes(&mut self, file: &Entry) -> Result<Vec<u8>, IsoError> {
        let mut out = Vec::new();
        self.open_file(file)?.read_to_end(&mut out)?;
        Ok(out)
    }

    pub fn copy_file_to(&mut self, file: &Entry, out: &mut impl Write) -> Result<u64, IsoError> {
        Ok(std::io::copy(&mut self.open_file(file)?, out)?)
    }
}

#[derive(Debug)]
enum DirectoryTree {
    Iso9660Family {
        root: Entry,
        encoding: Iso9660NameEncoding,
        volume_info: VolumeInfo,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Iso9660NameEncoding {
    Iso9660,
    Joliet,
    // RockRidge,
}

impl Iso9660NameEncoding {
    pub fn decode(self, identifier: &[u8]) -> Result<String, NameDecodeError> {
        let raw = match self {
            Self::Iso9660 => {
                if !identifier.is_ascii() {
                    return Err(NameDecodeError::NotAscii);
                }
                String::from_utf8(identifier.to_vec()).expect("ASCII is valid UTF-8")
            }
            Self::Joliet => {
                if identifier.len() % 2 != 0 {
                    return Err(NameDecodeError::OddJolietLength);
                }
                let units = identifier
                    .chunks_exact(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]));
                char::decode_utf16(units)
                    .collect::<Result<String, _>>()
                    .map_err(|_| NameDecodeError::InvalidUtf16)?
            }
        };
        let name = strip_version(&raw);
        if name.is_empty() {
            return Err(NameDecodeError::Empty);
        }
        if name.contains(['/', '\0']) {
            return Err(NameDecodeError::ForbiddenCharacter);
        }
        Ok(name.to_owned())
    }
}

/// - "GRUB.CFG;1" -> "GRUB.CFG"
/// - "README.;1" -> "README"
/// - "grub.cfg" -> "grub.cfg"
/// - "a.;x" -> "a.;x"
fn strip_version(name: &str) -> &str {
    match name.rsplit_once(';') {
        Some((base, version))
            if !version.is_empty() && version.bytes().all(|b| b.is_ascii_digit()) =>
        {
            base.strip_suffix('.').unwrap_or(base)
        }
        _ => name,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameDecodeError {
    NotAscii,
    // UCS-2 is 2 bytes per unit
    OddJolietLength,
    // unpaired surrogate
    InvalidUtf16,
    // example: ".;1"
    Empty,
    // '/' or NUL. Would break path lookup
    ForbiddenCharacter,
}

impl NameDecodeError {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotAscii => "Not valid ASCII name",
            Self::OddJolietLength => "Joliet name length must be even, since its 2 bytes per unit",
            Self::InvalidUtf16 => "Invalid UTF16 name",
            Self::Empty => "Empty name",
            Self::ForbiddenCharacter => "Forbidden character in name",
        }
    }

    pub fn at_sector(self, sector: AbsoluteSector) -> IsoError {
        IsoError::Malformed {
            sector,
            what: self.as_str(),
        }
    }
}

impl std::fmt::Display for NameDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::error::Error for NameDecodeError {}

#[derive(Clone, Debug)]
pub struct VolumeInfo {
    pub volume_id: String,
}

impl VolumeInfo {
    pub fn from_pvd(
        pvd_sector: &[u8],
        pvd: AbsoluteSector,
        total_image_sectors: u32,
    ) -> Result<Self, IsoError> {
        check_logical_block_size(pvd_sector)?;

        let volume_id_bytes = &pvd_sector[40..72];
        if !volume_id_bytes.is_ascii() {
            return Err(IsoError::Malformed {
                sector: pvd,
                what: "Volume ID must be ASCII",
            });
        }

        Ok(VolumeInfo {
            volume_id: str::from_utf8(volume_id_bytes)
                .expect("Just checked this")
                .trim_end_matches(' ')
                .to_string(),
        })
    }
}

/// Already adjusted for extended attribute record.
#[derive(Clone, Copy, Debug)]
pub struct DataExtent {
    /// Where the data actually starts, past any extended attribute records.
    pub start: AbsoluteSector,
    /// How long the data is in bytes.
    pub len: u32,
}

impl DataExtent {
    pub fn from_record(r: &FileSystemRecord, total_image_sectors: u32) -> Result<Self, IsoError> {
        let start = u64::from(r.location_of_extent.0) + u64::from(r.extended_attr_record_len);
        let end = start + u64::from(r.data_length).div_ceil(BYTES_PER_SECTOR as u64);

        if end > u64::from(total_image_sectors) {
            return Err(IsoError::Malformed {
                sector: r.location_of_extent,
                what: "Data extent out of bounds",
            });
        }

        let extent = DataExtent {
            start: AbsoluteSector(
                start
                    .try_into()
                    .expect("end > total_image_sectors ensures this is valid"),
            ),
            len: r.data_length,
        };

        Ok(extent)
    }
}

pub struct IsoFileReader<'a, R> {
    stream: &'a mut R,
    extents: std::slice::Iter<'a, DataExtent>,
    remaining_in_extent: u64,
}

impl<R: Read + Seek> Read for IsoFileReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // Skip to next extent
        while self.remaining_in_extent == 0 {
            let Some(extent) = self.extents.next() else {
                return Ok(0); // EOF
            };
            self.stream
                .seek(SeekFrom::Start(extent.start.byte_offset()))?;
            self.remaining_in_extent = u64::from(extent.len);
        }
        let max = buf
            .len()
            .min(usize::try_from(self.remaining_in_extent).unwrap_or(usize::MAX));
        let n = self.stream.read(&mut buf[..max])?;
        if n == 0 && max > 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        self.remaining_in_extent -= n as u64;
        Ok(n)
    }
}

fn iso_image_from_stream<R: Read + Seek>(mut stream: R) -> Result<IsoImage<R>, IsoError> {
    let total_image_sectors = {
        let len_bytes = stream.seek(SeekFrom::End(0))?;
        u32::try_from(len_bytes / BYTES_PER_SECTOR as u64)
            .map_err(|_| IsoError::Unsupported("Image larger than 2^32 sectors (8 TiB)"))
    }?;

    // Always start from the beginning :)
    stream.seek(SeekFrom::Start(0))?;

    let descriptors = VolumeDescriptorSet::from_stream(&mut stream)?;

    let pvd = match &descriptors.primary_sector {
        None => {
            if descriptors.udf.is_some() {
                return Err(IsoError::Unsupported("UDF only image"));
            }
            return Err(IsoError::NotAnIso);
        }
        Some(p) => *p,
    };

    let pvd_sector = read_sector(&mut stream, pvd)?;

    let (root_descriptor, encoding) = match &descriptors.joliet_sector {
        Some(svd) => (*svd, Iso9660NameEncoding::Joliet),
        None => (pvd, Iso9660NameEncoding::Iso9660),
    };

    let volume_info = VolumeInfo::from_pvd(&pvd_sector, pvd, total_image_sectors)?;

    let root_sector = if root_descriptor == pvd {
        pvd_sector
    } else {
        let s = read_sector(&mut stream, root_descriptor)?;
        check_logical_block_size(&s)?;
        s
    };

    let root_record =
        match FileSystemRecord::parse(&root_sector[PRIMARY_VOLUME_DESCRIPTOR_ROOT_RECORD_OFFSET..])
        {
            Ok(r) => r,
            Err(e) => return Err(e.at_sector(root_descriptor)),
        };

    Ok(IsoImage::<R> {
        stream,
        descriptors,
        tree: DirectoryTree::Iso9660Family {
            root: Entry::root(&root_record, root_descriptor, total_image_sectors)?,
            encoding,
            volume_info,
        },
        total_image_sectors,
    })
}

fn check_logical_block_size(sector: &[u8]) -> Result<(), IsoError> {
    let logical_block_size =
        u16::from_le_bytes(sector[128..130].try_into().expect("How did this fail"));
    if logical_block_size as usize != BYTES_PER_SECTOR {
        return Err(IsoError::Unsupported(
            "Only support logical block size of 2048 bytes",
        ));
    }
    Ok(())
}
