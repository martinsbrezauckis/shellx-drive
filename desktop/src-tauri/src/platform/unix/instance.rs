//! Per-user Unix desktop process lease.
//!
//! `flock` is attached to the open descriptor and released by the kernel when
//! the process exits. The lock lives in the same owner-private state boundary
//! as credential cleanup metadata, so another user cannot pre-create it.

use std::{
    fs,
    path::{Path, PathBuf},
};

use shellx_drive_desktop_core::{
    private_state_directory, validate_private_staging_file, DesktopError, Result as CoreResult,
};

const INSTANCE_LEASE_FILE: &str = "desktop-instance-v1.lock";

pub(crate) struct UnixDesktopInstanceLease {
    _file: fs::File,
}

impl UnixDesktopInstanceLease {
    /// `Ok(None)` means another process owns the current user's lease.
    pub(crate) fn acquire() -> CoreResult<Option<Self>> {
        Self::acquire_at(&lease_file_path(&private_state_directory()?))
    }

    fn acquire_at(path: &Path) -> CoreResult<Option<Self>> {
        use std::os::unix::{fs::OpenOptionsExt, io::AsRawFd};

        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)?;
        validate_private_staging_file(&file)?;
        let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            Ok(Some(Self { _file: file }))
        } else {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                Ok(None)
            } else {
                Err(DesktopError::Io(error))
            }
        }
    }
}

fn lease_file_path(private_state_directory: &Path) -> PathBuf {
    private_state_directory.join(INSTANCE_LEASE_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn lease_is_namespaced_under_the_private_state_directory() {
        assert_eq!(
            lease_file_path(Path::new("/private/state")),
            Path::new("/private/state").join(INSTANCE_LEASE_FILE)
        );
    }

    #[test]
    fn second_same_user_lease_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let private = directory.path().join("private");
        shellx_drive_desktop_core::ensure_private_staging_directory(&private).unwrap();
        let path = lease_file_path(&private);
        let _first = UnixDesktopInstanceLease::acquire_at(&path)
            .unwrap()
            .unwrap();
        assert!(UnixDesktopInstanceLease::acquire_at(&path)
            .unwrap()
            .is_none());
    }

    #[test]
    fn shared_lease_file_is_rejected_before_locking() {
        let directory = tempfile::tempdir().unwrap();
        let private = directory.path().join("private");
        shellx_drive_desktop_core::ensure_private_staging_directory(&private).unwrap();
        let path = lease_file_path(&private);
        fs::write(&path, b"").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(UnixDesktopInstanceLease::acquire_at(&path).is_err());
    }
}
