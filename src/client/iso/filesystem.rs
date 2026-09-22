/// A record for something on the filesystem.
/// For directories, when you go to the extent where it lives, its just a bunch more contiguous
/// instances of `FileSystemRecord` (at least the raw data that gets parsed into multiple
/// `FileSystemRecord`). This would have no headers to parse out, its just the entries contiguously.
/// For files, this is actually the raw file binary data.
#[derive(Clone, Debug)]
pub struct FileSystemRecord {
    /// Byte offset 0.
    len: u8,
    /// Byte offset 1.
    extended_attr_record_len: u8,
    /// Byte offset 2
    location_of_extent: u32,
    /// Byte offset 10
    data_length: u32,
    /// Byte offset 18
    recording_date_time: FileSystemDateTime,
    /// Byte offset 25. Bitflags of [`FileBitFlags`].
    file_flags: u8,
    /// Byte offset 26.
    file_unit_size_interleaved_mode: u8,
    /// Byte offset 27.
    interleave_gap_size: u8,
    /// Byte offset 28.
    volume_sequence_number: u16,
    /// Byte offset 32. May contains the trailing `";1"`.
    file_name_length: u8,
    /// Byte offset 32. May contains the trailing `";1"`.
    file_identifier: Vec<u8>,
    system_use: Vec<u8>,
}

impl FileSystemRecord {
    /// For the Primary Volume Descriptor, `start` would start at byte offset `156` for example.
    pub unsafe fn parse_from_directory_entry_start(start: *const u8) -> Self {
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
                file_name_length: *start.byte_add(32),
                file_identifier: Vec::<u8>::default(),
                system_use: Vec::<u8>::default(),
            };

            let file_identifier =
                std::slice::from_raw_parts(start.byte_add(33), record.file_name_length as usize);
            record.file_identifier = Vec::<u8>::from(file_identifier);

            let system_use_start = 33
                + record.file_name_length as usize
                + usize::from(record.file_name_length % 2 == 0);
            let system_use = std::slice::from_raw_parts(
                start.byte_add(system_use_start),
                record.len as usize - system_use_start,
            );
            record.system_use = Vec::<u8>::from(system_use);

            record
        }
    }
}

/// Bitflags for file / directory information for a filesystem entry.
/// The comments on the members are taken straight from https://wiki.osdev.org/ISO_9660
#[repr(u8)]
#[derive(Copy, Clone)]
pub enum FileBitFlags {
    /// If set, the existence of this file need not be made known to the user (basically a 'hidden' flag.
    Hidden = 0,
    /// If set, this record describes a directory (in other words, it is a subdirectory extent).
    IsDirectory = 1,
    /// If set, this file is an "Associated File".
    IsAssociatedFile = 2,
    /// If set, the extended attribute record contains information about the format of this file.
    ExtendedArrtRecordContains = 3,
    /// If set, owner and group permissions are set in the extended attribute record.
    PermissionInExtendedArrtRecord = 4,
    // Bits 5 and 6 are reserved
    /// If set, this is not the final directory record for this file (for files spanning several extents, for example files over 4GiB long.
    NotFinalDirectoryRecord = 7,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FileSystemDateTime {
    /// Byte offset 0.
    years_since_1900: u8,
    /// Byte offset 1. Range 1 to 12.
    month_of_year: u8,
    /// Byte offset 2. Range 1 to 31.
    day_of_month: u8,
    /// Byte offset 3. Range 0 to 23.
    hour: u8,
    /// Byte offset 4. Range 0 to 59.
    minute: u8,
    /// Byte offset 5. Range 0 to 59.
    second: u8,
    /// Byte offset 6. 15 minute intervals from -48 (west) to +52 (east).
    gmt_offset: i8,
}
