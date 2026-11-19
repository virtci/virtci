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
        if !matches!(&self.identifier, identifier) {
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
        if previous_extent.len as usize <= BYTES_PER_SECTOR {
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
