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

    pub fn volume(&self) -> &VolumeInfo {
        match &self.tree {
            DirectoryTree::Iso9660Family { volume_info, .. } => volume_info,
        }
    }

    /// Which name encoding the chosen directory tree uses.
    pub fn encoding(&self) -> Iso9660NameEncoding {
        match &self.tree {
            DirectoryTree::Iso9660Family { encoding, .. } => *encoding,
        }
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

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::client::iso::filesystem::{FileBitFlags, tests::record_bytes};

    const DIR: u8 = FileBitFlags::IsDirectory as u8;

    fn joliet(name: &str) -> Vec<u8> {
        name.encode_utf16().flat_map(u16::to_be_bytes).collect()
    }

    #[test]
    fn strip_version_examples() {
        assert_eq!(strip_version("GRUB.CFG;1"), "GRUB.CFG");
        assert_eq!(strip_version("README.;1"), "README");
        assert_eq!(strip_version("grub.cfg"), "grub.cfg");
        assert_eq!(strip_version("a.;x"), "a.;x");
    }

    #[test]
    fn strip_version_keeps_trailing_dot_without_version() {
        assert_eq!(strip_version("a."), "a.");
        assert_eq!(strip_version("a;"), "a;");
        assert_eq!(strip_version("A;32767"), "A");
    }

    #[test]
    fn decode_iso9660_strips_version() {
        let enc = Iso9660NameEncoding::Iso9660;
        assert_eq!(enc.decode(b"GRUB.CFG;1").unwrap(), "GRUB.CFG");
        assert_eq!(enc.decode(b"README.;1").unwrap(), "README");
        assert_eq!(enc.decode(b"BOOT").unwrap(), "BOOT");
    }

    #[test]
    fn decode_iso9660_rejects_non_ascii() {
        assert_eq!(
            Iso9660NameEncoding::Iso9660.decode(&[0xC3, 0xA9]),
            Err(NameDecodeError::NotAscii)
        );
    }

    #[test]
    fn decode_joliet_ucs2_be() {
        let enc = Iso9660NameEncoding::Joliet;
        assert_eq!(enc.decode(&joliet("grub.cfg;1")).unwrap(), "grub.cfg");
        assert_eq!(enc.decode(&joliet("user-data")).unwrap(), "user-data");
        assert_eq!(enc.decode(&joliet("café_日本")).unwrap(), "café_日本");
    }

    #[test]
    fn decode_joliet_rejects_odd_length() {
        assert_eq!(
            Iso9660NameEncoding::Joliet.decode(&[0, b'a', 0]),
            Err(NameDecodeError::OddJolietLength)
        );
    }

    #[test]
    fn decode_joliet_rejects_unpaired_surrogate() {
        assert_eq!(
            Iso9660NameEncoding::Joliet.decode(&[0xD8, 0x00, 0, b'a']),
            Err(NameDecodeError::InvalidUtf16)
        );
    }

    #[test]
    fn decode_rejects_empty_name_after_stripping() {
        assert_eq!(
            Iso9660NameEncoding::Iso9660.decode(b".;1"),
            Err(NameDecodeError::Empty)
        );
        assert_eq!(
            Iso9660NameEncoding::Joliet.decode(&joliet(";1")),
            Err(NameDecodeError::Empty)
        );
    }

    #[test]
    fn decode_rejects_slash_and_nul() {
        assert_eq!(
            Iso9660NameEncoding::Joliet.decode(&joliet("a/b")),
            Err(NameDecodeError::ForbiddenCharacter)
        );
        assert_eq!(
            Iso9660NameEncoding::Iso9660.decode(b"A\0B"),
            Err(NameDecodeError::ForbiddenCharacter)
        );
    }

    fn file_record(extent: u32, data_len: u32, ear_len: u8) -> FileSystemRecord {
        let mut bytes = record_bytes(b"A;1", 0, extent, data_len, &[]);
        bytes[1] = ear_len;
        FileSystemRecord::parse(&bytes).unwrap()
    }

    #[test]
    fn data_extent_in_bounds() {
        let extent = DataExtent::from_record(&file_record(10, 4096, 0), 100).unwrap();
        assert_eq!(extent.start, AbsoluteSector(10));
        assert_eq!(extent.len, 4096);
    }

    #[test]
    fn data_extent_skips_extended_attribute_record() {
        let extent = DataExtent::from_record(&file_record(10, 1, 2), 100).unwrap();
        assert_eq!(extent.start, AbsoluteSector(12));
    }

    #[test]
    fn data_extent_may_end_exactly_at_image_end() {
        // 2 sectors starting at 98 end at 100.
        assert!(DataExtent::from_record(&file_record(98, 4096, 0), 100).is_ok());
        // A partial last sector still occupies the whole sector.
        assert!(DataExtent::from_record(&file_record(99, 1, 0), 100).is_ok());
        // Empty file at the very end.
        assert!(DataExtent::from_record(&file_record(100, 0, 0), 100).is_ok());
    }

    #[test]
    fn data_extent_rejects_past_image_end() {
        for record in [
            file_record(98, 4097, 0),
            file_record(100, 1, 0),
            file_record(99, 1, 1),
        ] {
            match DataExtent::from_record(&record, 100) {
                Err(IsoError::Malformed { sector, .. }) => {
                    assert_eq!(sector, record.location_of_extent);
                }
                other => panic!("expected Malformed, got {other:?}"),
            }
        }
    }

    #[test]
    fn data_extent_huge_values_do_not_overflow() {
        let record = file_record(u32::MAX, u32::MAX, u8::MAX);
        assert!(matches!(
            DataExtent::from_record(&record, u32::MAX),
            Err(IsoError::Malformed { .. })
        ));
    }

    fn numbered_sectors(sectors: u8) -> Cursor<Vec<u8>> {
        Cursor::new(
            (0..sectors)
                .flat_map(|n| std::iter::repeat_n(n, BYTES_PER_SECTOR))
                .collect(),
        )
    }

    fn extent(start: u32, len: u32) -> DataExtent {
        DataExtent {
            start: AbsoluteSector(start),
            len,
        }
    }

    fn read_extents(
        stream: &mut Cursor<Vec<u8>>,
        extents: &[DataExtent],
    ) -> std::io::Result<Vec<u8>> {
        let mut reader = IsoFileReader {
            stream,
            extents: extents.iter(),
            remaining_in_extent: 0,
        };
        let mut out = Vec::new();
        reader.read_to_end(&mut out)?;
        Ok(out)
    }

    #[test]
    fn file_reader_single_extent_stops_at_len() {
        let mut image = numbered_sectors(4);
        let bytes = read_extents(&mut image, &[extent(2, 10)]).unwrap();
        assert_eq!(bytes, vec![2; 10]);
    }

    #[test]
    fn file_reader_reads_non_adjacent_extents_in_order() {
        let mut image = numbered_sectors(5);
        let bytes = read_extents(
            &mut image,
            &[extent(3, BYTES_PER_SECTOR as u32), extent(1, 5)],
        )
        .unwrap();
        let mut expected = vec![3; BYTES_PER_SECTOR];
        expected.extend_from_slice(&[1; 5]);
        assert_eq!(bytes, expected);
    }

    #[test]
    fn file_reader_empty_file() {
        let mut image = numbered_sectors(1);
        assert!(
            read_extents(&mut image, &[extent(0, 0)])
                .unwrap()
                .is_empty()
        );
        assert!(read_extents(&mut image, &[]).unwrap().is_empty());
    }

    #[test]
    fn file_reader_skips_zero_length_extent_in_middle() {
        let mut image = numbered_sectors(3);
        let bytes = read_extents(&mut image, &[extent(1, 2), extent(0, 0), extent(2, 3)]).unwrap();
        assert_eq!(bytes, vec![1, 1, 2, 2, 2]);
    }

    #[test]
    fn file_reader_take_stops_mid_extent() {
        let mut image = numbered_sectors(3);
        let extents = [extent(1, BYTES_PER_SECTOR as u32), extent(2, 100)];
        let mut reader = IsoFileReader {
            stream: &mut image,
            extents: extents.iter(),
            remaining_in_extent: 0,
        };
        let mut out = Vec::new();
        (&mut reader).take(7).read_to_end(&mut out).unwrap();
        assert_eq!(out, vec![1; 7]);
        out.clear();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out.len(), BYTES_PER_SECTOR - 7 + 100);
    }

    #[test]
    fn file_reader_truncated_stream_is_unexpected_eof() {
        let mut image = numbered_sectors(2);
        image.get_mut().truncate(BYTES_PER_SECTOR + 3);
        let err = read_extents(&mut image, &[extent(1, 10)]).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    // Custom Iso9660 (no Joliet).
    // 16 PVD, 17 terminator, 18 root dir, 19 BOOT dir, 20 BOOT/GRUB dir,
    // 21 README.TXT data, 22 BOOT/GRUB/GRUB.CFG data.

    const README: &[u8] = b"hello";
    const GRUB_CFG: &[u8] = b"menuentry x";

    fn put_sector(image: &mut [u8], sector: usize, records: &[Vec<u8>]) {
        let mut at = sector * BYTES_PER_SECTOR;
        for record in records {
            image[at..at + record.len()].copy_from_slice(record);
            at += record.len();
        }
    }

    fn directory(own: u32, parent: u32, children: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let mut records = vec![
            record_bytes(&[0], DIR, own, 2048, &[]),
            record_bytes(&[1], DIR, parent, 2048, &[]),
        ];
        records.extend_from_slice(children);
        records
    }

    fn test_image() -> Cursor<Vec<u8>> {
        const TOTAL: usize = 23;
        let mut image = vec![0u8; TOTAL * BYTES_PER_SECTOR];

        let pvd = &mut image[16 * BYTES_PER_SECTOR..17 * BYTES_PER_SECTOR];
        pvd[0] = 1;
        pvd[1..6].copy_from_slice(b"CD001");
        pvd[6] = 1;
        pvd[40..72].fill(b' ');
        pvd[40..47].copy_from_slice(b"TESTVOL");
        pvd[80..84].copy_from_slice(&(TOTAL as u32).to_le_bytes());
        pvd[84..88].copy_from_slice(&(TOTAL as u32).to_be_bytes());
        pvd[128..130].copy_from_slice(&2048u16.to_le_bytes());
        pvd[130..132].copy_from_slice(&2048u16.to_be_bytes());
        let root = record_bytes(&[0], DIR, 18, 2048, &[]);
        pvd[156..156 + root.len()].copy_from_slice(&root);

        let terminator = &mut image[17 * BYTES_PER_SECTOR..18 * BYTES_PER_SECTOR];
        terminator[0] = 255;
        terminator[1..6].copy_from_slice(b"CD001");
        terminator[6] = 1;

        let records = directory(
            18,
            18,
            &[
                record_bytes(b"BOOT", DIR, 19, 2048, &[]),
                record_bytes(b"README.TXT;1", 0, 21, README.len() as u32, &[]),
            ],
        );
        put_sector(&mut image, 18, &records);
        let records = directory(19, 18, &[record_bytes(b"GRUB", DIR, 20, 2048, &[])]);
        put_sector(&mut image, 19, &records);
        let records = directory(
            20,
            19,
            &[record_bytes(
                b"GRUB.CFG;1",
                0,
                22,
                GRUB_CFG.len() as u32,
                &[],
            )],
        );
        put_sector(&mut image, 20, &records);

        image[21 * BYTES_PER_SECTOR..][..README.len()].copy_from_slice(README);
        image[22 * BYTES_PER_SECTOR..][..GRUB_CFG.len()].copy_from_slice(GRUB_CFG);
        Cursor::new(image)
    }

    fn find(iso: &mut IsoImage<Cursor<Vec<u8>>>, path: &str) -> Option<Entry> {
        let root = iso.root();
        iso.find_entry(&root, path).unwrap()
    }

    #[test]
    fn iso_image_opens_iso9660_only_image() {
        let iso = IsoImage::new(test_image()).unwrap();
        assert_eq!(iso.volume().volume_id, "TESTVOL");
        assert_eq!(iso.encoding(), Iso9660NameEncoding::Iso9660);
        let root = iso.root();
        assert_eq!(root.name, "");
        assert_eq!(root.kind, EntryKind::Directory);
    }

    #[test]
    fn iso_image_rejects_non_iso() {
        let zeros = Cursor::new(vec![0u8; 20 * BYTES_PER_SECTOR]);
        assert!(matches!(IsoImage::new(zeros), Err(IsoError::NotAnIso)));
        let tiny = Cursor::new(vec![0u8; 100]);
        assert!(matches!(IsoImage::new(tiny), Err(IsoError::NotAnIso)));
    }

    #[test]
    fn iso_image_read_dir_root() {
        let mut iso = IsoImage::new(test_image()).unwrap();
        let root = iso.root();
        let entries = iso.read_dir(&root).unwrap();
        let listing: Vec<_> = entries.iter().map(|e| (e.name.as_str(), e.kind)).collect();
        assert_eq!(
            listing,
            vec![
                ("BOOT", EntryKind::Directory),
                ("README.TXT", EntryKind::File),
            ]
        );
    }

    #[test]
    fn iso_image_find_entry_case_insensitive_nested() {
        let mut iso = IsoImage::new(test_image()).unwrap();
        let cfg = find(&mut iso, "boot/grub/grub.cfg").unwrap();
        assert_eq!(cfg.name, "GRUB.CFG");
        assert_eq!(cfg.kind, EntryKind::File);
        assert_eq!(iso.read_file_bytes(&cfg).unwrap(), GRUB_CFG);
    }

    #[test]
    fn iso_image_find_entry_ignores_empty_and_dot_components() {
        let mut iso = IsoImage::new(test_image()).unwrap();
        let cfg = find(&mut iso, "/BOOT//./grub/GRUB.CFG/").unwrap();
        assert_eq!(cfg.name, "GRUB.CFG");
    }

    #[test]
    fn iso_image_find_entry_empty_path_is_dir_itself() {
        let mut iso = IsoImage::new(test_image()).unwrap();
        assert_eq!(find(&mut iso, "").unwrap().name, "");
        assert_eq!(find(&mut iso, "/").unwrap().name, "");
        let boot = find(&mut iso, "boot").unwrap();
        let grub = iso.find_entry(&boot, "grub").unwrap().unwrap();
        assert_eq!(grub.name, "GRUB");
        assert_eq!(iso.find_entry(&grub, ".").unwrap().unwrap().name, "GRUB");
    }

    #[test]
    fn iso_image_find_entry_missing_is_none() {
        let mut iso = IsoImage::new(test_image()).unwrap();
        assert!(find(&mut iso, "missing").is_none());
        assert!(find(&mut iso, "boot/missing/grub.cfg").is_none());
    }

    #[test]
    fn iso_image_find_entry_through_file_is_none() {
        let mut iso = IsoImage::new(test_image()).unwrap();
        assert!(find(&mut iso, "readme.txt/anything").is_none());
    }

    #[test]
    fn iso_image_find_entry_rejects_parent_dir() {
        let mut iso = IsoImage::new(test_image()).unwrap();
        let root = iso.root();
        assert!(matches!(
            iso.find_entry(&root, "boot/../readme.txt"),
            Err(IsoError::Unsupported(_))
        ));
    }

    #[test]
    fn iso_image_file_and_directory_kind_errors() {
        let mut iso = IsoImage::new(test_image()).unwrap();
        let readme = find(&mut iso, "readme.txt").unwrap();
        let boot = find(&mut iso, "boot").unwrap();
        assert!(matches!(
            iso.read_dir(&readme),
            Err(IsoError::NotADirectory)
        ));
        assert!(matches!(iso.open_file(&boot), Err(IsoError::NotAFile)));
    }

    #[test]
    fn iso_image_copy_file_to() {
        let mut iso = IsoImage::new(test_image()).unwrap();
        let readme = find(&mut iso, "readme.txt").unwrap();
        let mut out = Vec::new();
        assert_eq!(
            iso.copy_file_to(&readme, &mut out).unwrap(),
            README.len() as u64
        );
        assert_eq!(out, README);
    }

    #[test]
    fn iso_image_rejects_truncated_image() {
        let mut image = test_image();
        image.get_mut().truncate(19 * BYTES_PER_SECTOR);
        let mut iso = IsoImage::new(image).unwrap();
        let root = iso.root();
        assert!(matches!(
            iso.read_dir(&root),
            Err(IsoError::Malformed { .. })
        ));
    }
}
