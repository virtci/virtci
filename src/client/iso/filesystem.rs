use std::io::{Read, Seek, SeekFrom};

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
    pub location_of_extent: u32,
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

impl FileSystemRecord {
    /// For the Primary Volume Descriptor, `start` would start at byte offset `156` for example.
    pub unsafe fn parse_from_directory_entry_start(
        start: *const u8,
    ) -> Result<Self, FileSystemRecordParseError> {
        unsafe {
            // Aligning some memory accesses.
            let location_of_extent = u32::from_le_bytes(
                std::slice::from_raw_parts(start.byte_add(2), 4)
                    .try_into()
                    .expect("how??"),
            );
            let data_length = u32::from_le_bytes(
                std::slice::from_raw_parts(start.byte_add(10), 4)
                    .try_into()
                    .expect("how??"),
            );
            let volume_sequence_number = u16::from_le_bytes(
                std::slice::from_raw_parts(start.byte_add(28), 2)
                    .try_into()
                    .expect("how??"),
            );
            let file_name_length = *start.byte_add(32);

            let file_identifier = {
                let file_identifier_slice =
                    std::slice::from_raw_parts(start.byte_add(33), file_name_length as usize);
                if file_name_length == 1 {
                    match file_identifier_slice[0] {
                        0 => FileSystemRecordIdentifier::SelfDir,
                        1 => FileSystemRecordIdentifier::ParentDir,
                        _ => FileSystemRecordIdentifier::FileOrDir(Vec::<u8>::from(
                            file_identifier_slice,
                        )),
                    }
                } else {
                    FileSystemRecordIdentifier::FileOrDir(Vec::<u8>::from(file_identifier_slice))
                }
            };

            let mut record = FileSystemRecord {
                len: *start,
                extended_attr_record_len: *start.byte_add(1),
                location_of_extent,
                data_length,
                recording_date_time: *(start.byte_add(18) as *const FileSystemDateTime),
                file_flags: *start.byte_add(25),
                file_unit_size_interleaved_mode: *start.byte_add(26),
                interleave_gap_size: *start.byte_add(27),
                volume_sequence_number,
                file_name_length,
                file_identifier,
                system_use: Vec::<u8>::default(),
            };

            let system_use_start = 33
                + record.file_name_length as usize
                + usize::from(record.file_name_length % 2 == 0);
            let system_use = std::slice::from_raw_parts(
                start.byte_add(system_use_start),
                record.len as usize - system_use_start,
            );
            record.system_use = Vec::<u8>::from(system_use);

            Ok(record)
        }
    }

    pub fn is_directory(&self) -> bool {
        return self.file_flags & (FileBitFlags::IsDirectory as u8) != 0;
    }

    pub fn is_file(&self) -> bool {
        return self.file_flags & (FileBitFlags::IsDirectory as u8) == 0;
    }

    /// Get all of the records for a directory. Will contain files, other directories, etc.
    /// It's technically more optimal to just read on demand rather than reading all entries and
    /// filtering from there, but this works fine for now. Will revisit if performance is a concern.
    ///
    /// # Arguments
    ///
    /// - `stream` any stream that can be seeked. This can be [`std::fs::File`], so you could do
    /// [`std::fs::File::try_clone()`]. Since the stream cursor is shared, it will store the one
    /// when this function is invoked, and then restore it before returning.
    ///
    /// # Debug Asserts
    ///
    /// `self.is_directory()`
    pub fn directory_records<T: Seek + Read>(
        &self,
        stream: &mut T,
    ) -> Result<Vec<FileSystemRecord>, FileSystemRecordParseError> {
        debug_assert!(self.is_directory());

        // The list of records in a directory are contigous over one or more blocks.
        let mut entries_bytes = Vec::<u8>::with_capacity(self.data_length as usize);
        entries_bytes.resize(self.data_length as usize, 0);

        let old_seek = stream.stream_position().expect("Why fail");

        stream
            .seek(SeekFrom::Start(self.location_of_extent as u64 * 2048))
            .expect("Why did seek fail?");
        stream
            .read_exact(&mut entries_bytes)
            .expect("Why did reading fail");

        stream
            .seek(SeekFrom::Start(old_seek))
            .expect("Why did restoring old seek fail?"); // restore since it's shared

        let mut entries = Vec::<FileSystemRecord>::default();

        let start = entries_bytes.as_slice().as_ptr();
        let mut offset = 0 as usize;
        while offset < self.data_length as usize
            && unsafe { *start.byte_add(offset) > 0 } // the first byte is always the `len` field.
            && (offset + unsafe { *start.byte_add(offset) as usize }) <= self.data_length as usize
        {
            let len = unsafe { *start.byte_add(offset) };
            if len < 34 {
                return Err(FileSystemRecordParseError::TooSmall);
            }
            // TODO what if len says one thing but name len says another?

            let entry = unsafe {
                FileSystemRecord::parse_from_directory_entry_start(start.byte_add(offset))?
            };

            offset += entry.len as usize;
            entries.push(entry);
        }

        Ok(entries)
    }

    /// Ignores trailing ";1" from the file / directory names that are actually found.
    pub fn record_for<T: Seek + Read>(
        &self,
        path_case_insensitive: &str,
        stream: &mut T,
    ) -> Result<Option<Self>, FileSystemRecordParseError> {
        debug_assert!(self.is_directory());

        let mut current_record = self.clone();

        for path_entry in path_case_insensitive.split('/') {
            if path_entry == "." {
                // just this directory
                continue;
            }

            let records_in_this_dir = current_record.directory_records(stream)?;

            let mut found = false;
            for record in records_in_this_dir.clone() {
                match record.file_identifier {
                    FileSystemRecordIdentifier::SelfDir => continue,
                    FileSystemRecordIdentifier::ParentDir => {
                        if path_entry == ".." {
                            current_record = record.clone();
                            found = true;
                        } else {
                            continue;
                        }
                    }
                    FileSystemRecordIdentifier::FileOrDir(ref identifier_name_bytes) => {
                        // TODO utf16? maybe not relevant here, as here may just be ASCII.
                        let identifier_name = std::str::from_utf8(identifier_name_bytes.as_slice())
                            .expect("how fail utf8 conversion");
                        if path_entry.eq_ignore_ascii_case(identifier_name.trim_end_matches(";1")) {
                            current_record = record.clone();
                            found = true;
                        } else {
                            continue;
                        }
                    }
                }
            }

            if !found {
                return Ok(None);
            }
        }

        Ok(Some(current_record))
    }

    pub fn read_file_bytes<T: Seek + Read>(
        &self,
        stream: &mut T,
        max_bytes: Option<usize>,
    ) -> Vec<u8> {
        debug_assert!(self.is_file());

        let old_seek = stream.stream_position().expect("Why fail");

        let bytes_to_read = {
            match max_bytes {
                Some(amount) => usize::min(amount, self.data_length as usize),
                None => self.data_length as usize,
            }
        };

        let mut bytes_out = Vec::<u8>::with_capacity(bytes_to_read);
        bytes_out.resize(bytes_to_read, 0);

        stream
            .seek(SeekFrom::Start(self.location_of_extent as u64 * 2048))
            .expect("Why did seek fail?");
        stream
            .read_exact(&mut bytes_out)
            .expect("Why did reading fail");

        stream
            .seek(SeekFrom::Start(old_seek))
            .expect("Why did restoring old seek fail?"); // restore since it's shared

        bytes_out
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

#[derive(Clone, Debug)]
pub enum FileSystemRecordParseError {
    InvalidFileIdentifier,
    /// Records must be at least 34 bytes in length.
    TooSmall,
}

impl std::fmt::Display for FileSystemRecordParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FileSystemRecordParseError::InvalidFileIdentifier => {
                f.write_str("Invalid File Identifier")
            }
            FileSystemRecordParseError::TooSmall => f.write_str("Too Small"),
        }
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
