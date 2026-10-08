//! Unix cache-object admission on already-open descriptors.

use std::{fs, io, os::unix::fs::MetadataExt as _};

const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
const REJECTED_DIRECTORY_SPECIAL_BITS: u32 = 0o5000;
const PEER_WRITE_BITS: u32 = 0o022;

pub(super) fn verify_directory(file: &fs::File) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sync cache object must be a directory",
        ));
    }
    verify_owner(&metadata, "sync cache directory")?;
    if metadata.mode() & 0o777 != PRIVATE_DIRECTORY_MODE
        || metadata.mode() & REJECTED_DIRECTORY_SPECIAL_BITS != 0
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "sync cache directory must have owner-only 0700 access bits",
        ));
    }
    Ok(())
}

pub(super) fn verify_input_file(file: &fs::File) -> io::Result<fs::Metadata> {
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "sync input leaf must be a regular file",
        ));
    }
    verify_owner(&metadata, "sync input leaf")?;
    if metadata.mode() & PEER_WRITE_BITS != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "sync input leaf must not be writable by group or other users",
        ));
    }
    if metadata.nlink() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "sync input leaf must have exactly one hard link",
        ));
    }
    Ok(metadata)
}

fn verify_owner(metadata: &fs::Metadata, label: &str) -> io::Result<()> {
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{label} must be owned by the current user"),
        ));
    }
    Ok(())
}
