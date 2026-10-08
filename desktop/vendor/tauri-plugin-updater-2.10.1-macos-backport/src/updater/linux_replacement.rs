// SPDX-License-Identifier: Apache-2.0
// SPDX-License-Identifier: MIT

//! Prepare the entire AppImage before atomically replacing the installed file.

use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::Path,
};

use crate::error::{Error, Result};

pub(super) fn install_appimage(destination: &Path, bytes: &[u8]) -> Result<()> {
    let original = fs::symlink_metadata(destination)?;
    if !original.file_type().is_file() {
        return Err(Error::InvalidUpdaterFormat);
    }
    let parent = destination
        .parent()
        .ok_or(Error::FailedToDetermineExtractPath)?;
    // The destination directory is necessarily on the destination filesystem.
    // Failure here leaves the installed file untouched, without moving it into
    // a temporary directory whose destructor could remove the only copy.
    let mut staged = tempfile::Builder::new()
        .prefix(".tauri-appimage-update-")
        .tempfile_in(parent)?;
    write_payload(staged.as_file_mut(), bytes)?;
    validate_appimage(staged.as_file_mut())?;
    staged.as_file().set_permissions(original.permissions())?;
    staged.as_file().sync_all()?;
    // POSIX rename replaces the old regular file atomically. Preparation,
    // extraction and permission errors occur before this sole commit point.
    staged.persist(destination).map_err(|error| error.error)?;
    Ok(())
}

fn write_payload(output: &mut fs::File, bytes: &[u8]) -> Result<()> {
    #[cfg(feature = "zip")]
    if infer::archive::is_gz(bytes) {
        return write_archive_payload(output, bytes);
    }
    output.write_all(bytes)?;
    Ok(())
}

#[cfg(feature = "zip")]
fn write_archive_payload(output: &mut fs::File, bytes: &[u8]) -> Result<()> {
    let decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(bytes));
    let mut archive = tar::Archive::new(decoder);
    let mut found = false;
    for entry in archive.entries()? {
        let mut entry = entry?;
        if entry.path()?.extension() != Some(std::ffi::OsStr::new("AppImage")) {
            continue;
        }
        if found || !entry.header().entry_type().is_file() {
            return Err(Error::InvalidUpdaterFormat);
        }
        std::io::copy(&mut entry, output)?;
        found = true;
    }
    // Reading through the gzip trailer detects truncation/CRC failure before
    // publication, even when tar has already reached its end marker.
    std::io::copy(&mut archive.into_inner(), &mut std::io::sink())?;
    if !found {
        return Err(Error::BinaryNotFoundInArchive);
    }
    Ok(())
}

fn validate_appimage(file: &mut fs::File) -> Result<()> {
    let mut header = [0u8; 11];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut header)
        .map_err(|_| Error::InvalidUpdaterFormat)?;
    if &header[..4] != b"\x7fELF" || &header[8..10] != b"AI" || !matches!(header[10], 1 | 2) {
        return Err(Error::InvalidUpdaterFormat);
    }
    Ok(())
}

#[cfg(test)]
#[path = "linux_replacement_tests.rs"]
mod tests;
