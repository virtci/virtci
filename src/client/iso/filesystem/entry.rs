use std::io::{Read, Seek};

use crate::client::iso::{
    BYTES_PER_SECTOR,
    filesystem::{
        AbsoluteSector, DIRECTORY_RECORD_MIN_LEN, FileSystemRecord, FileSystemRecordIdentifier,
        IsoError,
        image::{DataExtent, Iso9660NameEncoding},
        read_sector,
    },
};

#[derive(Clone, Debug)]
pub struct Entry {
    /// This is decoded per [`Iso9660NameEncoding`]. For instance, ";1" and trailing "." would be
    /// stripped. For the root record, this is `""`. When doing lookup, `"/"` will also work as the
    /// root.
    pub name: String,
    pub kind: EntryKind,
    /// Almost always contains 1. Would be >1 for multi-extent files, which generally are just
    /// larger than u32 in size (more than 4GB).
    pub extents: Vec<DataExtent>,
}

impl Entry {
    pub fn root(
        root_record: &FileSystemRecord,
        descriptor: AbsoluteSector,
        total_image_sectors: u32,
    ) -> Result<Self, IsoError> {
        if !matches!(
            root_record.file_identifier,
            FileSystemRecordIdentifier::SelfDir
        ) {
            return Err(IsoError::Malformed {
                sector: descriptor,
                what: "For the root record, the identifier must be the self dir",
            });
        }

        if !root_record.is_directory() {
            return Err(IsoError::Malformed {
                sector: descriptor,
                what: "Root record must be a directory",
            });
        }

        if !root_record.is_final_record() {
            return Err(IsoError::Malformed {
                sector: descriptor,
                what: "Directories must not be multi-extent",
            });
        }

        if (root_record.data_length as usize) < 2 * DIRECTORY_RECORD_MIN_LEN {
            return Err(IsoError::Malformed {
                sector: descriptor,
                what: "Root directory too small to hold . and ..",
            });
        }

        Ok(Entry {
            name: "".to_string(),
            kind: EntryKind::Directory,
            extents: vec![DataExtent::from_record(&root_record, total_image_sectors)?],
        })
    }

    pub fn find_by_name(entries: Vec<Entry>, wanted: &str) -> Option<Entry> {
        let mut fallback = None; // just in case doesn't find case exact
        for entry in entries {
            if entry.name == wanted {
                return Some(entry);
            }
            if fallback.is_none() && entry.name.eq_ignore_ascii_case(wanted) {
                fallback = Some(entry);
            }
        }
        fallback
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EntryKind {
    File,
    Directory,
}

pub struct LocatedRecord {
    sector: AbsoluteSector,
    record: FileSystemRecord,
}

pub fn read_directory_records<R: Read + Seek>(
    stream: &mut R,
    dir: DataExtent,
) -> Result<Vec<LocatedRecord>, IsoError> {
    let mut records = Vec::new();
    let mut remaining = dir.len as usize;
    let mut sector = dir.start;

    while remaining > 0 {
        let bytes = read_sector(stream, sector)?;
        let valid = &bytes[..remaining.min(BYTES_PER_SECTOR)];

        // start from byte offset 0, start of FileSystemRecord
        let mut offset = 0;
        while offset < valid.len() {
            // if len is ever zero, the rest of this sector is padding
            if valid[offset] == 0 {
                break;
            }
            let record =
                FileSystemRecord::parse(&valid[offset..]).map_err(|e| e.at_sector(sector))?;
            // parse guarantees len >= 34, so will always advance correctly
            offset += record.len as usize;
            records.push(LocatedRecord { sector, record });
        }

        remaining -= valid.len();
        sector = AbsoluteSector(sector.0 + 1);
    }

    Ok(records)
}

#[derive(Clone)]
struct Run {
    first_sector: AbsoluteSector,
    // raw bytes.
    identifier: Vec<u8>,
    kind: EntryKind,
    extents: Vec<DataExtent>,
}

impl Run {
    fn start(
        record: &FileSystemRecord,
        identifier: &[u8],
        sector: AbsoluteSector,
        total_image_sectors: u32,
    ) -> Result<Self, IsoError> {
        if record.is_directory() && !record.is_final_record() {
            return Err(IsoError::Malformed {
                sector,
                what: "Directories cannot be multi-extent",
            });
        }

        Ok(Self {
            first_sector: sector,
            identifier: Vec::from(identifier),
            kind: if record.is_directory() {
                EntryKind::Directory
            } else {
                EntryKind::File
            },
            extents: vec![DataExtent::from_record(record, total_image_sectors)?],
        })
    }

    fn continue_with(
        &self,
        record: &FileSystemRecord,
        identifier: &[u8],
        sector: AbsoluteSector,
        total_image_sectors: u32,
    ) -> Result<Self, IsoError> {
        if self.identifier != identifier {
            return Err(IsoError::Malformed {
                sector,
                what: "Multi-extent file interrupted by a different record",
            });
        }

        if !matches!(self.kind, EntryKind::File) {
            return Err(IsoError::Malformed {
                sector,
                what: "The current multi-extent record is not a file and thus cannot be multi-extent",
            });
        }

        if !record.is_file() {
            return Err(IsoError::Malformed {
                sector,
                what: "Expected a multi-extent file",
            });
        }

        let previous_extent = self.extents.last().expect("Should have a previous extent");
        if (previous_extent.len as usize) < BYTES_PER_SECTOR {
            return Err(IsoError::Malformed {
                sector,
                what: "Previous extent too small",
            });
        }
        if previous_extent.len as usize % BYTES_PER_SECTOR != 0 {
            return Err(IsoError::Malformed {
                sector,
                what: "Previous extent must be a multiple of BYTES_PER_SECTOR",
            });
        }

        let mut cloned = self.clone();
        cloned
            .extents
            .push(DataExtent::from_record(record, total_image_sectors)?);
        Ok(cloned)
    }

    fn finish(self, encoding: Iso9660NameEncoding) -> Result<Entry, IsoError> {
        let name = encoding
            .decode(&self.identifier)
            .map_err(|e| e.at_sector(self.first_sector))?;
        Ok(Entry {
            name,
            kind: self.kind,
            extents: self.extents,
        })
    }
}

pub fn group_into_entries(
    records: Vec<LocatedRecord>,
    encoding: Iso9660NameEncoding,
    total_image_sectors: u32,
) -> Result<Vec<Entry>, IsoError> {
    let mut entries = Vec::new();
    let mut pending: Option<Run> = None;

    for LocatedRecord { sector, record } in records {
        let FileSystemRecordIdentifier::FileOrDir(identifier) = &record.file_identifier else {
            if pending.is_some() {
                return Err(IsoError::Malformed {
                    sector,
                    what: "Multi-extent file interrupted by . or .. entries",
                });
            }
            continue; // skip `.` or `..`
        };

        if record.is_associated_file() {
            continue;
        }

        let run = match pending.take() {
            Some(run) => run.continue_with(&record, identifier, sector, total_image_sectors)?,
            None => Run::start(&record, &identifier, sector, total_image_sectors)?,
        };

        if record.is_final_record() {
            entries.push(run.finish(encoding)?)
        } else {
            pending = Some(run)
        }
    }

    if let Some(run) = pending {
        return Err(IsoError::Malformed {
            sector: run.first_sector,
            what: "Directory ended in the middle of a multi-extent file",
        });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::client::iso::filesystem::{FileBitFlags, tests::record_bytes};

    const DIR: u8 = FileBitFlags::IsDirectory as u8;
    const NOT_FINAL: u8 = FileBitFlags::NotFinalDirectoryRecord as u8;
    const ASSOCIATED: u8 = FileBitFlags::IsAssociatedFile as u8;
    const TOTAL_SECTORS: u32 = 1000;

    fn entry(name: &str) -> Entry {
        Entry {
            name: name.to_string(),
            kind: EntryKind::File,
            extents: Vec::new(),
        }
    }

    fn located(sector: u32, bytes: &[u8]) -> LocatedRecord {
        LocatedRecord {
            sector: AbsoluteSector(sector),
            record: FileSystemRecord::parse(bytes).unwrap(),
        }
    }

    fn dot_records() -> Vec<LocatedRecord> {
        vec![
            located(10, &record_bytes(&[0], DIR, 10, 2048, &[])),
            located(10, &record_bytes(&[1], DIR, 9, 2048, &[])),
        ]
    }

    fn malformed_sector(result: Result<Vec<Entry>, IsoError>) -> AbsoluteSector {
        match result {
            Err(IsoError::Malformed { sector, .. }) => sector,
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    fn directory_image(sectors: &[Vec<Vec<u8>>]) -> Cursor<Vec<u8>> {
        let mut image = Vec::new();
        for sector in sectors {
            let start = image.len();
            for record in sector {
                image.extend_from_slice(record);
            }
            assert!(image.len() - start <= BYTES_PER_SECTOR);
            image.resize(start + BYTES_PER_SECTOR, 0);
        }
        Cursor::new(image)
    }

    fn names(records: &[LocatedRecord]) -> Vec<(u32, Vec<u8>)> {
        records
            .iter()
            .map(|r| {
                let name = match &r.record.file_identifier {
                    FileSystemRecordIdentifier::SelfDir => vec![0],
                    FileSystemRecordIdentifier::ParentDir => vec![1],
                    FileSystemRecordIdentifier::FileOrDir(n) => n.clone(),
                };
                (r.sector.0, name)
            })
            .collect()
    }

    #[test]
    fn find_by_name_prefers_exact_over_earlier_case_insensitive() {
        let found = Entry::find_by_name(vec![entry("README"), entry("readme")], "readme");
        assert_eq!(found.unwrap().name, "readme");
    }

    #[test]
    fn find_by_name_falls_back_to_ascii_case_insensitive() {
        let found = Entry::find_by_name(vec![entry("OTHER"), entry("GRUB.CFG")], "grub.cfg");
        assert_eq!(found.unwrap().name, "GRUB.CFG");
    }

    #[test]
    fn find_by_name_non_ascii_must_match_exactly() {
        assert!(Entry::find_by_name(vec![entry("É")], "é").is_none());
        assert_eq!(
            Entry::find_by_name(vec![entry("É")], "É").unwrap().name,
            "É"
        );
    }

    #[test]
    fn find_by_name_no_match() {
        assert!(Entry::find_by_name(vec![entry("a"), entry("b")], "c").is_none());
        assert!(Entry::find_by_name(Vec::new(), "c").is_none());
    }

    #[test]
    fn read_directory_records_skips_zero_padding_across_sectors() {
        let mut image = directory_image(&[
            vec![
                record_bytes(&[0], DIR, 0, 4096, &[]),
                record_bytes(&[1], DIR, 0, 4096, &[]),
                record_bytes(b"A;1", 0, 5, 1, &[]),
            ],
            vec![record_bytes(b"B;1", 0, 6, 1, &[])],
        ]);
        let extent = DataExtent {
            start: AbsoluteSector(0),
            len: 4096,
        };
        let records = read_directory_records(&mut image, extent).unwrap();
        assert_eq!(
            names(&records),
            vec![
                (0, vec![0]),
                (0, vec![1]),
                (0, b"A;1".to_vec()),
                (1, b"B;1".to_vec()),
            ]
        );
    }

    #[test]
    fn read_directory_records_reports_sector_relative_to_extent_start() {
        let mut image =
            directory_image(&[vec![], vec![], vec![record_bytes(b"A;1", 0, 5, 1, &[])]]);
        let extent = DataExtent {
            start: AbsoluteSector(2),
            len: 2048,
        };
        let records = read_directory_records(&mut image, extent).unwrap();
        assert_eq!(names(&records), vec![(2, b"A;1".to_vec())]);
    }

    #[test]
    fn read_directory_records_ignores_bytes_past_len() {
        let first = record_bytes(b"A;1", 0, 5, 1, &[]);
        let len = u32::try_from(first.len()).unwrap();
        let mut image = directory_image(&[vec![first, record_bytes(b"B;1", 0, 6, 1, &[])]]);
        let extent = DataExtent {
            start: AbsoluteSector(0),
            len,
        };
        let records = read_directory_records(&mut image, extent).unwrap();
        assert_eq!(names(&records), vec![(0, b"A;1".to_vec())]);
    }

    #[test]
    fn read_directory_records_rejects_record_crossing_sector_end() {
        let record = record_bytes(b"A;1", 0, 5, 1, &[]);
        let mut bytes = Vec::new();
        while bytes.len() + record.len() <= BYTES_PER_SECTOR {
            bytes.extend_from_slice(&record);
        }
        bytes.extend_from_slice(&record);
        bytes.resize(2 * BYTES_PER_SECTOR, 0);
        let mut image = Cursor::new(bytes);
        let extent = DataExtent {
            start: AbsoluteSector(0),
            len: 4096,
        };
        match read_directory_records(&mut image, extent) {
            Err(IsoError::Malformed { sector, .. }) => assert_eq!(sector, AbsoluteSector(0)),
            other => panic!("expected Malformed, got {:?}", other.map(|r| names(&r))),
        }
    }

    #[test]
    fn read_directory_records_empty_extent() {
        let mut image = directory_image(&[]);
        let extent = DataExtent {
            start: AbsoluteSector(0),
            len: 0,
        };
        assert!(
            read_directory_records(&mut image, extent)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn group_skips_dot_dotdot_and_associated_files() {
        let mut records = dot_records();
        records.push(located(
            10,
            &record_bytes(b"HIDDEN;1", ASSOCIATED, 20, 1, &[]),
        ));
        records.push(located(10, &record_bytes(b"BOOT", DIR, 21, 2048, &[])));
        records.push(located(10, &record_bytes(b"GRUB.CFG;1", 0, 22, 100, &[])));

        let entries =
            group_into_entries(records, Iso9660NameEncoding::Iso9660, TOTAL_SECTORS).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "BOOT");
        assert_eq!(entries[0].kind, EntryKind::Directory);
        assert_eq!(entries[1].name, "GRUB.CFG");
        assert_eq!(entries[1].kind, EntryKind::File);
        assert_eq!(entries[1].extents.len(), 1);
        assert_eq!(entries[1].extents[0].start, AbsoluteSector(22));
        assert_eq!(entries[1].extents[0].len, 100);
    }

    #[test]
    fn group_merges_multi_extent_file() {
        let mut records = dot_records();
        records.push(located(
            10,
            &record_bytes(b"BIG;1", NOT_FINAL, 20, 4096, &[]),
        ));
        records.push(located(10, &record_bytes(b"BIG;1", 0, 30, 10, &[])));
        records.push(located(10, &record_bytes(b"NEXT;1", 0, 40, 1, &[])));

        let entries =
            group_into_entries(records, Iso9660NameEncoding::Iso9660, TOTAL_SECTORS).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "BIG");
        let extents: Vec<_> = entries[0]
            .extents
            .iter()
            .map(|e| (e.start.0, e.len))
            .collect();
        assert_eq!(extents, vec![(20, 4096), (30, 10)]);
        assert_eq!(entries[1].name, "NEXT");
    }

    #[test]
    fn group_rejects_run_interrupted_by_different_name() {
        let mut records = dot_records();
        records.push(located(
            10,
            &record_bytes(b"BIG;1", NOT_FINAL, 20, 2048, &[]),
        ));
        records.push(located(11, &record_bytes(b"OTHER;1", 0, 30, 10, &[])));
        let result = group_into_entries(records, Iso9660NameEncoding::Iso9660, TOTAL_SECTORS);
        assert_eq!(malformed_sector(result), AbsoluteSector(11));
    }

    #[test]
    fn group_rejects_run_interrupted_by_dot_entry() {
        let mut records = vec![located(
            10,
            &record_bytes(b"BIG;1", NOT_FINAL, 20, 2048, &[]),
        )];
        records.push(located(11, &record_bytes(&[1], DIR, 9, 2048, &[])));
        let result = group_into_entries(records, Iso9660NameEncoding::Iso9660, TOTAL_SECTORS);
        assert_eq!(malformed_sector(result), AbsoluteSector(11));
    }

    #[test]
    fn group_rejects_run_left_open_at_end_of_directory() {
        let mut records = dot_records();
        records.push(located(
            12,
            &record_bytes(b"BIG;1", NOT_FINAL, 20, 2048, &[]),
        ));
        let result = group_into_entries(records, Iso9660NameEncoding::Iso9660, TOTAL_SECTORS);
        assert_eq!(malformed_sector(result), AbsoluteSector(12));
    }

    #[test]
    fn group_rejects_non_sector_aligned_non_final_extent() {
        let mut records = dot_records();
        records.push(located(
            10,
            &record_bytes(b"BIG;1", NOT_FINAL, 20, 3000, &[]),
        ));
        records.push(located(11, &record_bytes(b"BIG;1", 0, 30, 10, &[])));
        let result = group_into_entries(records, Iso9660NameEncoding::Iso9660, TOTAL_SECTORS);
        assert_eq!(malformed_sector(result), AbsoluteSector(11));
    }

    #[test]
    fn group_rejects_multi_extent_directory() {
        let mut records = dot_records();
        records.push(located(
            13,
            &record_bytes(b"DIR", DIR | NOT_FINAL, 20, 2048, &[]),
        ));
        let result = group_into_entries(records, Iso9660NameEncoding::Iso9660, TOTAL_SECTORS);
        assert_eq!(malformed_sector(result), AbsoluteSector(13));
    }

    #[test]
    fn group_rejects_extent_out_of_bounds() {
        let mut records = dot_records();
        records.push(located(10, &record_bytes(b"A;1", 0, TOTAL_SECTORS, 1, &[])));
        let result = group_into_entries(records, Iso9660NameEncoding::Iso9660, TOTAL_SECTORS);
        assert_eq!(malformed_sector(result), AbsoluteSector(TOTAL_SECTORS));
    }

    #[test]
    fn group_reports_name_decode_failure_at_record_sector() {
        let mut records = dot_records();
        records.push(located(14, &record_bytes(&[0xC3, 0xA9], 0, 20, 1, &[])));
        let result = group_into_entries(records, Iso9660NameEncoding::Iso9660, TOTAL_SECTORS);
        assert_eq!(malformed_sector(result), AbsoluteSector(14));
    }

    #[test]
    fn group_decodes_joliet_names() {
        let name: Vec<u8> = "grub.cfg;1"
            .encode_utf16()
            .flat_map(u16::to_be_bytes)
            .collect();
        let mut records = dot_records();
        records.push(located(10, &record_bytes(&name, 0, 20, 1, &[])));
        let entries =
            group_into_entries(records, Iso9660NameEncoding::Joliet, TOTAL_SECTORS).unwrap();
        assert_eq!(entries[0].name, "grub.cfg");
    }
}
