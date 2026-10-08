use std::path::{Path, PathBuf};

use crate::{error::ApiResult, storage::Storage, upload_locks::UploadSessionLock};

use super::{remove_part_file_best_effort, require_canonical_session_id};

pub(in crate::routes::drop_uploads) struct SessionFileLock {
    _lock: UploadSessionLock,
    inactive_part_cleanup: Option<InactivePartCleanup>,
}

struct InactivePartCleanup {
    storage: Storage,
    session_id: String,
    part_path: PathBuf,
}

impl SessionFileLock {
    pub(in crate::routes::drop_uploads) fn acquire(
        directory: &Path,
        session_id: &str,
    ) -> ApiResult<Self> {
        require_canonical_session_id(session_id)?;
        let lock = UploadSessionLock::acquire(directory, session_id)?;
        Ok(Self {
            _lock: lock,
            inactive_part_cleanup: None,
        })
    }

    pub(in crate::routes::drop_uploads) fn remove_part_if_session_inactive_on_drop(
        &mut self,
        storage: Storage,
        session_id: String,
        part_path: PathBuf,
    ) {
        self.inactive_part_cleanup = Some(InactivePartCleanup {
            storage,
            session_id,
            part_path,
        });
    }
}

impl Drop for SessionFileLock {
    fn drop(&mut self) {
        if let Some(cleanup) = &self.inactive_part_cleanup {
            let inactive = cleanup
                .storage
                .get_drop_upload_session(&cleanup.session_id)
                .ok()
                .flatten()
                .is_some_and(|session| session.status != "active");
            if inactive {
                remove_part_file_best_effort(&cleanup.part_path, &cleanup.session_id);
            }
        }
        // The stripe and any legacy handle remain held through part cleanup.
    }
}

#[cfg(all(test, windows))]
#[path = "session_lock/windows_tests.rs"]
mod windows_tests;
