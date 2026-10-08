//! Persistent, bounded upload lock inodes shared by all processes.
//!
//! Never unlink these files or change the v1 mapping while users can hold a
//! lock. A stripe collision is a retryable conflict, not a second lock owner.

use std::{
    fs::File,
    path::{Path, PathBuf},
};

use sha2::{Digest, Sha256};

use crate::error::{ApiError, ApiResult};

pub(crate) const STRIPE_COUNT: usize = 1024;

struct LockedFile(File);

impl Drop for LockedFile {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd as _;
            // Explicit unlock also releases ownership if a concurrently
            // spawned child inherited the descriptor before exec.
            let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

pub(crate) struct UploadSessionLock {
    _legacy_file: Option<LockedFile>,
    _stripe_file: LockedFile,
}

impl UploadSessionLock {
    pub(crate) fn acquire(directory: &Path, session_id: &str) -> ApiResult<Self> {
        // Both upload families use canonical path components. Reject unsafe
        // input before even creating a bounded stripe.
        if crate::upload_ids::require_canonical(session_id).is_err()
            && !(session_id.len() == 64
                && session_id
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')))
        {
            return Err(ApiError::Validation(
                "invalid upload lock identifier".to_string(),
            ));
        }
        let file = open_lock(&stripe_path(directory, session_id), true).map_err(lock_error)?;
        // Existing legacy inodes remain part of the exclusion protocol. Do not
        // create new legacy files or delete old ones while another process may
        // have opened them. Dropping `file` on failure releases the stripe.
        let legacy_file = match open_lock(&directory.join(format!("{session_id}.lock")), false) {
            Ok(file) => Some(file),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(lock_error(error)),
        };
        Ok(Self {
            _stripe_file: file,
            _legacy_file: legacy_file,
        })
    }

    #[cfg(all(test, windows))]
    pub(crate) fn verify_private_handles(&self) -> std::io::Result<()> {
        crate::fs_private::verify_private_file_handle(&self._stripe_file.0)?;
        if let Some(file) = &self._legacy_file {
            crate::fs_private::verify_private_file_handle(&file.0)?;
        }
        Ok(())
    }
}

fn stripe_path(directory: &Path, session_id: &str) -> PathBuf {
    let digest = Sha256::digest(session_id.as_bytes());
    let stripe = usize::from(u16::from_be_bytes([digest[0], digest[1]])) % STRIPE_COUNT;
    directory.join(format!("lock-v1-{stripe:03x}.lock"))
}

fn open_lock(path: &Path, create: bool) -> std::io::Result<LockedFile> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true).create(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    #[cfg(windows)]
    crate::fs_private::configure_private_lock_options(&mut options, 0);
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd as _;
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    let file = LockedFile(file);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.0
            .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(windows)]
    crate::fs_private::apply_private_file_handle(&file.0)?;
    Ok(file)
}

fn lock_error(error: std::io::Error) -> ApiError {
    let busy = error.kind() == std::io::ErrorKind::WouldBlock;
    #[cfg(windows)]
    let busy = busy || matches!(error.raw_os_error(), Some(32) | Some(33));
    if busy {
        ApiError::Conflict
    } else {
        error.into()
    }
}

#[cfg(test)]
mod tests;
