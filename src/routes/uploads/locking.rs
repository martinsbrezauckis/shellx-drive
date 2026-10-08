use std::path::{Path, PathBuf};

use crate::{error::ApiError, server::AppState, upload_locks::UploadSessionLock};

pub(super) struct UploadFileLock {
    _lock: UploadSessionLock,
}

pub(super) fn acquire_upload_lock(
    state: &AppState,
    upload_id: &str,
) -> Result<UploadFileLock, ApiError> {
    let upload_id = crate::upload_ids::normalize(upload_id)?;
    let lock = UploadSessionLock::acquire(&upload_dir(state), &upload_id)?;
    Ok(UploadFileLock { _lock: lock })
}

pub(super) fn upload_dir(state: &AppState) -> PathBuf {
    state.data_dir().join("uploads")
}

pub(super) fn upload_part_path(state: &AppState, upload_id: &str) -> Result<PathBuf, ApiError> {
    Ok(upload_dir(state).join(format!("{}.part", crate::upload_ids::normalize(upload_id)?)))
}

pub(super) fn rollback_unacknowledged_chunk(part_path: &Path, offset: i64) {
    if let Ok(file) = std::fs::OpenOptions::new().write(true).open(part_path) {
        let _ = file.set_len(offset.max(0) as u64);
        let _ = file.sync_all();
    }
}

#[cfg(all(test, windows))]
#[path = "locking/windows_tests.rs"]
mod windows_tests;
