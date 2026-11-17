use std::io::Read;
use std::io::Seek;

use crate::client::iso::filesystem::FileSystemRecord;
use crate::client::iso::filesystem::IsoError;
use crate::client::iso::filesystem::VolumeDescriptorSet;

pub struct IsoImage<R: Read + Seek> {
    stream: R,
    descriptors: VolumeDescriptorSet,
    tree: DirectoryTree,
}

impl<R: Read + Seek> IsoImage<R> {
    pub fn new(mut stream: R) -> Result<Self, IsoError> {
        let descriptors = VolumeDescriptorSet::from_stream(&mut stream)?;
        todo!();
    }
}

enum DirectoryTree {
    Iso9660 { root: FileSystemRecord },
    Joliet { root: FileSystemRecord },
    // TODO UDF for Windows
}
