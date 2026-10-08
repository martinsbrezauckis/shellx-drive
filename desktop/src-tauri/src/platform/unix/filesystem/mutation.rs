//! Descriptor-bound retained replacement and rename primitives.
//!
//! Platform-specific replacement bodies stay isolated because Linux can retain
//! an inode through `renameat2`, while macOS must stage an independent recovery
//! copy before its `renameatx_np` exchange. Shared no-replace moves remain in
//! the sibling module so their descriptor-bound contract is identical on both.

use std::{
    fs,
    io::{Seek, SeekFrom},
};

use shellx_drive_desktop_core::{LocalEntry, LocalScanLimits, Result as CoreResult};

use super::descriptor::file_identity;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
mod renames;

#[cfg(target_os = "linux")]
pub(super) use linux::prepare_staged_file_replacement;
#[cfg(target_os = "linux")]
pub(crate) use linux::LinuxPreparedReplacement;
#[cfg(target_os = "macos")]
pub(super) use macos::prepare_staged_file_replacement;
#[cfg(target_os = "macos")]
pub(crate) use macos::MacOsPreparedReplacement;
pub(super) use renames::{
    move_complete_root_to_recovery, move_entry_noreplace, move_entry_to_recovery,
    publish_staged_entry_noreplace,
};

fn file_matches_local_entry(file: &fs::File, expected: &LocalEntry) -> CoreResult<bool> {
    if expected.is_directory {
        return Ok(false);
    }
    let before = file_identity(file)?;
    if before.size != expected.size_bytes || before.size > LocalScanLimits::default().max_file_bytes
    {
        return Ok(false);
    }
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let (hash, bytes) = shellx_drive_desktop_core::hash_reader_bounded(
        &mut reader,
        LocalScanLimits::default().max_file_bytes,
    )?;
    Ok(bytes == expected.size_bytes
        && expected.content_hash.as_deref() == Some(hash.as_str())
        && file_identity(file)? == before)
}
