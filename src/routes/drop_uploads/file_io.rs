use std::{
    fs::OpenOptions,
    io::{Seek as _, SeekFrom, Write as _},
    path::{Path, PathBuf},
};

use crate::{
    error::{ApiError, ApiResult},
    model::DriveFile,
    server::AppState,
    storage::DropUploadRecord,
};

mod session_lock;
pub(super) use session_lock::SessionFileLock;

pub(super) fn drop_upload_dir(state: &AppState) -> PathBuf {
    state.data_dir().join("drop-uploads")
}

pub(super) fn require_canonical_session_id(session_id: &str) -> ApiResult<()> {
    if session_id.len() == 64
        && session_id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Ok(());
    }
    Err(ApiError::Validation(
        "drop upload session id must be a canonical lowercase hex token".to_string(),
    ))
}

pub(super) fn append_chunk(
    state: &AppState,
    session: &DropUploadRecord,
    part_path: &Path,
    offset: i64,
    body: &[u8],
) -> ApiResult<()> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt as _;
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(part_path)?;
    let actual_size = i64::try_from(file.metadata()?.len()).map_err(|_| ApiError::Conflict)?;
    if actual_size > offset {
        file.set_len(u64::try_from(offset).map_err(|_| ApiError::Conflict)?)?;
    } else if actual_size < offset {
        let _ = state
            .storage
            .fail_drop_upload_session(&session.id, "part_size_mismatch");
        return Err(ApiError::Conflict);
    }
    file.seek(SeekFrom::Start(
        u64::try_from(offset).map_err(|_| ApiError::Conflict)?,
    ))?;
    file.write_all(body)?;
    file.sync_data()?;
    crate::fs_private::set_file_private(part_path)?;
    Ok(())
}

pub(super) fn rollback_unacknowledged_chunk(part_path: &Path, offset: i64) {
    if let Ok(file) = OpenOptions::new().write(true).open(part_path) {
        if let Ok(offset) = u64::try_from(offset) {
            let _ = file.set_len(offset);
            let _ = file.sync_data();
        }
    }
}

pub(super) fn index_declared_text_if_bounded(
    state: &AppState,
    session: &DropUploadRecord,
    file: &DriveFile,
    part_path: &Path,
) -> ApiResult<()> {
    const MAX_IMMEDIATE_TEXT_BYTES: i64 = 2 * 1024 * 1024;
    let is_text = session.content_type.as_deref().is_some_and(|content_type| {
        content_type.starts_with("text/")
            || matches!(
                content_type,
                "application/json" | "application/xml" | "application/javascript"
            )
    });
    if !is_text || session.total_size > MAX_IMMEDIATE_TEXT_BYTES {
        return Ok(());
    }
    let bytes = std::fs::read(part_path)?;
    if let Ok(content) = std::str::from_utf8(&bytes) {
        if file.workspace_id != session.workspace_id {
            return Err(ApiError::NotFound);
        }
        state.storage.index_file_text(file, content)?;
    }
    Ok(())
}

pub(super) fn remove_part_file_best_effort(part_path: &Path, session_id: &str) {
    match std::fs::remove_file(part_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => tracing::warn!(%session_id, %error, "drop upload part cleanup failed"),
    }
}

pub(super) fn cleanup_canceled_parts(state: &AppState, session_ids: &[String]) {
    if session_ids.is_empty() {
        return;
    }
    let directory = drop_upload_dir(state);
    if let Err(error) = crate::fs_private::create_dir_all_private(&directory) {
        tracing::warn!(%error, "revoked drop upload directory cleanup failed");
        return;
    }
    for session_id in session_ids {
        match SessionFileLock::acquire(&directory, session_id) {
            Ok(_lock) => remove_part_file_best_effort(
                &directory.join(format!("{session_id}.part")),
                session_id,
            ),
            Err(ApiError::Conflict) => {}
            Err(error) => {
                tracing::warn!(%session_id, %error, "revoked drop upload part lock failed")
            }
        }
    }
}

/// Reap only candidates whose per-session lock can be acquired. The callback
/// re-checks staleness while the same stable lock inode is held, so a live
/// chunk or cancellation cannot be raced by a cleaner.
pub(super) fn reap_stale_candidates_lock_safe_with(
    state: &AppState,
    session_ids: Vec<String>,
    mut reap: impl FnMut(&str) -> ApiResult<Option<DropUploadRecord>>,
) -> ApiResult<Vec<DropUploadRecord>> {
    if session_ids.is_empty() {
        return Ok(Vec::new());
    }
    let directory = drop_upload_dir(state);
    crate::fs_private::create_dir_all_private(&directory)?;
    let mut reaped = Vec::new();
    for session_id in session_ids {
        let _lock = match SessionFileLock::acquire(&directory, &session_id) {
            Ok(lock) => lock,
            Err(ApiError::Conflict) => continue,
            Err(error) => return Err(error),
        };
        let Some(session) = reap(&session_id)? else {
            continue;
        };
        remove_part_file_best_effort(&directory.join(format!("{session_id}.part")), &session_id);
        reaped.push(session);
    }
    Ok(reaped)
}
