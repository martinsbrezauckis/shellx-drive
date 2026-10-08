//! Owner-private staging validation for macOS and Linux.

use std::{fs, path::Path};

use crate::{DesktopError, Result};

pub(super) fn create_private_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    fs::DirBuilder::new().mode(0o700).create(path)?;
    validate_private_directory(path)
}

pub(super) fn validate_private_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    validate_owner_private(&metadata, path, true)
}

pub(super) fn validate_private_file(file: &fs::File) -> Result<()> {
    let metadata = file.metadata()?;
    validate_owner_private(&metadata, Path::new("private staging file"), false)
}

fn validate_owner_private(metadata: &fs::Metadata, path: &Path, directory: bool) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let valid_kind = if directory {
        metadata.is_dir()
    } else {
        metadata.is_file()
    };
    if !valid_kind || metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
        return Err(DesktopError::UnsafePath(format!(
            "private staging {} is not owner-private: {}",
            if directory { "directory" } else { "file" },
            path.display()
        )));
    }
    Ok(())
}
