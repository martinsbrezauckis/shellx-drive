//! Free-space admission for private Unix downloads and recovery copies.

#[cfg(target_os = "linux")]
use std::{fs, os::unix::fs::OpenOptionsExt};
use std::{fs::File, os::fd::AsRawFd, path::Path};

#[cfg(target_os = "linux")]
use shellx_drive_desktop_core::validate_private_staging_file;
use shellx_drive_desktop_core::{
    DesktopError, DownloadPrecondition, OwnedStagingRoot, Result as CoreResult,
};

const FREE_SPACE_RESERVE_BYTES: u64 = 512 * 1024 * 1024;

pub(crate) fn replacement_recovery_bytes(precondition: &DownloadPrecondition) -> u64 {
    match precondition {
        DownloadPrecondition::Absent => 0,
        DownloadPrecondition::ExactLocal { size_bytes, .. } => *size_bytes,
    }
}

/// Retain the checked local recovery body only after replacement publication
/// exchanged the destination. Other remote payloads are reproducible.
pub(crate) fn finish_failed_download(
    owned: &OwnedStagingRoot,
    batch: &Path,
    exchange_completed: bool,
) -> CoreResult<()> {
    if exchange_completed {
        owned.retain_batch(batch)
    } else {
        owned.remove_batch(batch)
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn create_private_staged_file(path: &Path) -> CoreResult<File> {
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    validate_private_staging_file(&file)?;
    Ok(file)
}

pub(crate) struct DownloadSpaceBudget {
    expected_bytes: u64,
    recovery_bytes: u64,
    written_bytes: u64,
}

impl DownloadSpaceBudget {
    pub(crate) fn new(expected_bytes: u64, recovery_bytes: u64) -> Self {
        Self {
            expected_bytes,
            recovery_bytes,
            written_bytes: 0,
        }
    }

    /// Check the target filesystem before creating a new staged body.
    pub(crate) fn check_path(&self, path: &Path) -> CoreResult<()> {
        self.check_file(&File::open(path)?)
    }

    /// Recheck the same filesystem as the open payload before each write.
    pub(crate) fn check_file(&self, file: &File) -> CoreResult<()> {
        let required = self.required_bytes()?;
        let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        if unsafe { libc::fstatvfs(file.as_raw_fd(), stats.as_mut_ptr()) } != 0 {
            return Err(DesktopError::Io(std::io::Error::last_os_error()));
        }
        let stats = unsafe { stats.assume_init() };
        let available = u128::from(stats.f_bavail)
            .saturating_mul(u128::from(stats.f_frsize))
            .min(u128::from(u64::MAX)) as u64;
        ensure_available(available, required)
    }

    fn required_bytes(&self) -> CoreResult<u64> {
        self.expected_bytes
            .saturating_sub(self.written_bytes)
            .checked_add(self.recovery_bytes)
            .and_then(|bytes| bytes.checked_add(FREE_SPACE_RESERVE_BYTES))
            .ok_or_else(|| {
                DesktopError::InvalidState("download space requirement overflowed".into())
            })
    }

    pub(crate) fn write_chunk(&mut self, file: &mut File, chunk: &[u8]) -> std::io::Result<()> {
        use std::io::Write;

        self.check_file(file).map_err(std::io::Error::other)?;
        file.write_all(chunk)?;
        self.written_bytes = self
            .written_bytes
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| std::io::Error::other("download byte count overflowed"))?;
        Ok(())
    }
}

fn ensure_available(available: u64, required: u64) -> CoreResult<()> {
    if available < required {
        return Err(DesktopError::InvalidState(format!(
            "download requires {required} free bytes including recovery and reserve; only {available} are available"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
