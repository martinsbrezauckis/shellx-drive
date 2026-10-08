//! Handle-bound publication of a verified single-file staging payload.

use std::{
    ffi::c_void,
    fs,
    mem::size_of,
    os::windows::{ffi::OsStrExt, io::AsRawHandle},
    path::Path,
};

use shellx_drive_desktop_core::{DesktopError, Result as CoreResult};
use windows_sys::{
    Wdk::Storage::FileSystem::{FileRenameInformation, NtSetInformationFile},
    Win32::{
        Foundation::RtlNtStatusToDosError, Storage::FileSystem::FILE_RENAME_INFO,
        System::IO::IO_STATUS_BLOCK,
    },
};

use super::transfer_execution::{
    open_checked_rename_target_directory, pin_checked_rename_directory_chain,
};

/// The live no-write-share handle proves the renamed file is the exact body
/// that completed the hash check.
pub(super) struct VerifiedStagedFile(pub(super) fs::File);

pub(super) fn rename_open_file_at(
    file: &fs::File,
    parent: &fs::File,
    leaf: &std::ffi::OsStr,
    replace_if_exists: bool,
) -> CoreResult<()> {
    let leaf_wide = leaf.encode_wide().collect::<Vec<_>>();
    if leaf_wide.is_empty() || leaf_wide.contains(&0) {
        return Err(DesktopError::UnsafePath(
            "verified rename destination leaf is empty or contains a NUL".to_string(),
        ));
    }
    let header_size = std::mem::offset_of!(FILE_RENAME_INFO, FileName);
    let name_size = leaf_wide
        .len()
        .checked_mul(size_of::<u16>())
        .ok_or_else(|| DesktopError::InvalidState("rename name is too large".to_string()))?;
    // FILE_RENAME_INFO has a one-WCHAR flexible tail plus x64 tail padding.
    // Pass the conventional complete ABI size; `FileNameLength` still omits
    // the zero terminator supplied by the zero-initialized trailing storage.
    let buffer_size = size_of::<FILE_RENAME_INFO>()
        .checked_add(name_size)
        .ok_or_else(|| DesktopError::InvalidState("rename buffer is too large".to_string()))?;
    let words = buffer_size.div_ceil(size_of::<usize>());
    let mut storage = vec![0_usize; words];
    let buffer = unsafe {
        std::slice::from_raw_parts_mut(
            storage.as_mut_ptr().cast::<u8>(),
            words * size_of::<usize>(),
        )
    };
    let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();
    unsafe {
        (*info).Anonymous.ReplaceIfExists = replace_if_exists;
        // Bind relative resolution to the exact validated parent object so an
        // in-place pathname/reparse change cannot redirect publication.
        (*info).RootDirectory = parent.as_raw_handle();
        (*info).FileNameLength = u32::try_from(name_size)
            .map_err(|_| DesktopError::InvalidState("rename name is too large".to_string()))?;
        std::ptr::copy_nonoverlapping(
            leaf_wide.as_ptr().cast::<u8>(),
            buffer.as_mut_ptr().add(header_size),
            name_size,
        );
        let mut io_status = IO_STATUS_BLOCK::default();
        let status = NtSetInformationFile(
            file.as_raw_handle(),
            &mut io_status,
            buffer.as_ptr().cast::<c_void>(),
            u32::try_from(buffer_size).map_err(|_| {
                DesktopError::InvalidState("rename buffer is too large".to_string())
            })?,
            FileRenameInformation,
        );
        if status < 0 {
            return Err(DesktopError::Io(std::io::Error::from_raw_os_error(
                RtlNtStatusToDosError(status) as i32,
            )));
        }
    }
    Ok(())
}

pub(super) fn move_verified_staged_file<F>(
    source_root: &Path,
    source: &Path,
    verified: &VerifiedStagedFile,
    destination: &Path,
    destination_pin_root: &Path,
    replace_if_exists: bool,
    before_native: F,
) -> CoreResult<()>
where
    F: FnOnce() -> CoreResult<()>,
{
    let source_parent = source.parent().ok_or_else(|| {
        DesktopError::UnsafePath("verified staged source has no parent".to_string())
    })?;
    let destination_parent = destination.parent().ok_or_else(|| {
        DesktopError::UnsafePath("verified staged destination has no parent".to_string())
    })?;
    let leaf = destination.file_name().ok_or_else(|| {
        DesktopError::UnsafePath("verified staged destination has no leaf".to_string())
    })?;
    let _source_pins = pin_checked_rename_directory_chain(source_root, source_parent)?;
    let destination_pins =
        pin_checked_rename_directory_chain(destination_pin_root, destination_parent)?;
    destination_pins.last().ok_or_else(|| {
        DesktopError::UnsafePath("verified staged destination has no pinned parent".to_string())
    })?;
    let parent = open_checked_rename_target_directory(destination_parent, false)?;
    before_native()?;
    rename_open_file_at(&verified.0, &parent, leaf, replace_if_exists)
}
