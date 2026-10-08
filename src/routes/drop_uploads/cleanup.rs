use crate::{
    error::{ApiError, ApiResult},
    server::AppState,
};

use super::file_io::{drop_upload_dir, require_canonical_session_id, SessionFileLock};

const MAX_RECONCILE_ENTRIES_PER_BATCH: usize = 256;

#[derive(Debug, Clone, Copy)]
pub(crate) struct DropPartReconcileBatch {
    pub(crate) inspected: usize,
    pub(crate) cleaned: usize,
    pub(crate) complete: bool,
}

/// Reconcile terminal or abandoned Drop-upload parts without touching a live
/// resumable upload. Every decision holds the bounded stripe and any legacy
/// per-session lock; their inodes persist for cross-process exclusion.
pub(crate) fn reconcile_terminal_drop_upload_parts_lock_safe(
    state: &AppState,
    orphan_grace_seconds: i64,
) -> ApiResult<DropPartReconcileBatch> {
    let directory = drop_upload_dir(state);
    crate::fs_private::create_dir_all_private(&directory)?;
    let orphan_grace = std::time::Duration::from_secs(orphan_grace_seconds.max(0) as u64);
    let mut cleaned = 0usize;
    let mut inspected = 0usize;
    let mut complete = false;
    let mut cursor = state.drop_upload_part_reconcile_cursor.lock().unwrap();
    if cursor.is_none() {
        *cursor = Some(std::fs::read_dir(&directory)?);
    }
    while inspected < MAX_RECONCILE_ENTRIES_PER_BATCH {
        let Some(next) = cursor.as_mut().and_then(Iterator::next) else {
            *cursor = None;
            complete = true;
            break;
        };
        inspected += 1;
        let entry = next?;
        let file_type = entry.file_type()?;
        if !file_type.is_file() || file_type.is_symlink() {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let Some(session_id) = name.strip_suffix(".part") else {
            continue;
        };
        if require_canonical_session_id(session_id).is_err() {
            continue;
        }
        let old_enough_if_orphaned = entry
            .metadata()?
            .modified()
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age >= orphan_grace);
        let _lock = match SessionFileLock::acquire(&directory, session_id) {
            Ok(lock) => lock,
            Err(ApiError::Conflict) => continue,
            Err(error) => return Err(error),
        };
        let should_remove = match state.storage.get_drop_upload_session(session_id)? {
            Some(session) => session.status != "active",
            None => old_enough_if_orphaned,
        };
        if !should_remove {
            continue;
        }
        let part_path = directory.join(format!("{session_id}.part"));
        let metadata = match std::fs::symlink_metadata(&part_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            continue;
        }
        match std::fs::remove_file(&part_path) {
            Ok(()) => cleaned += 1,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(session_id, %error, "terminal Drop upload part cleanup failed");
            }
        }
    }
    Ok(DropPartReconcileBatch {
        inspected,
        cleaned,
        complete,
    })
}
