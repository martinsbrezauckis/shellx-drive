use axum::{extract::State, http::HeaderMap, Json};

use crate::{
    auth::require_admin_with_credential,
    error::{ApiError, ApiResult},
    model::{UploadCleanupRequest, UploadCleanupResponse},
    server::AppState,
};

const MAX_RECONCILE_ENTRIES_PER_BATCH: usize = 256;

#[derive(Debug, Clone, Copy)]
pub(crate) struct UploadPartReconcileBatch {
    pub(crate) inspected: usize,
    pub(crate) cleaned: usize,
    pub(crate) complete: bool,
}

/// Reap only the supplied candidates. Each cancellation happens while the
/// ordinary upload's stable staging lock is held, then removes only its part
/// file. Bounded stripe locks and pre-existing legacy lock paths persist so
/// cross-process users always contend on the same inodes.
pub(crate) fn reap_upload_candidates_lock_safe(
    state: &AppState,
    upload_ids: Vec<String>,
    older_than_seconds: i64,
) -> ApiResult<Vec<crate::model::UploadSession>> {
    reap_upload_candidates_lock_safe_with(state, upload_ids, |upload_id| {
        state
            .storage
            .reap_stale_upload_session(upload_id, older_than_seconds)
    })
}

/// Reconcile terminal or abandoned ordinary-upload parts without touching an
/// active resumable upload. Every decision is made while the canonical upload
/// stripe and any legacy lock are held; their inodes remain in place for
/// cross-process exclusion.
pub(crate) fn reconcile_terminal_upload_parts_lock_safe(
    state: &AppState,
    orphan_grace_seconds: i64,
) -> ApiResult<UploadPartReconcileBatch> {
    let upload_dir = super::locking::upload_dir(state);
    crate::fs_private::create_dir_all_private(&upload_dir)?;
    let orphan_grace = std::time::Duration::from_secs(orphan_grace_seconds.max(0) as u64);
    let mut cleaned = 0usize;
    let mut inspected = 0usize;
    let mut complete = false;
    let mut cursor = state.upload_part_reconcile_cursor.lock().unwrap();
    if cursor.is_none() {
        *cursor = Some(std::fs::read_dir(&upload_dir)?);
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
        let Some(upload_id) = name.strip_suffix(".part") else {
            continue;
        };
        if crate::upload_ids::require_canonical(upload_id).is_err() {
            continue;
        }
        let old_enough_if_orphaned = entry
            .metadata()?
            .modified()
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age >= orphan_grace);
        let _lock = match super::locking::acquire_upload_lock(state, upload_id) {
            Ok(lock) => lock,
            Err(ApiError::Conflict) => continue,
            Err(error) => return Err(error),
        };
        let should_remove = match state.storage.get_upload_session(upload_id)? {
            Some(session) => session.completed || session.canceled,
            None => old_enough_if_orphaned,
        };
        if !should_remove {
            continue;
        }
        let part_path = super::locking::upload_part_path(state, upload_id)?;
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
                tracing::warn!(upload_id = %upload_id, %error, "terminal upload part cleanup failed");
            }
        }
    }
    Ok(UploadPartReconcileBatch {
        inspected,
        cleaned,
        complete,
    })
}

fn reap_upload_candidates_lock_safe_with(
    state: &AppState,
    upload_ids: Vec<String>,
    mut reap: impl FnMut(&str) -> ApiResult<Option<crate::model::UploadSession>>,
) -> ApiResult<Vec<crate::model::UploadSession>> {
    if upload_ids.is_empty() {
        return Ok(Vec::new());
    }
    crate::fs_private::create_dir_all_private(&super::locking::upload_dir(state))?;
    let mut reaped = Vec::new();
    for upload_id in upload_ids {
        let _lock = match super::locking::acquire_upload_lock(state, &upload_id) {
            Ok(lock) => lock,
            Err(ApiError::Conflict) => continue,
            Err(error) => return Err(error),
        };
        let Some(session) = reap(&upload_id)? else {
            continue;
        };
        let part_path = super::locking::upload_part_path(state, &upload_id)?;
        if let Err(error) = std::fs::remove_file(part_path) {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(upload_id = %upload_id, %error, "stale upload part cleanup failed");
            }
        }
        reaped.push(session);
    }
    Ok(reaped)
}

pub(super) async fn cleanup_uploads(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<UploadCleanupRequest>,
) -> ApiResult<Json<UploadCleanupResponse>> {
    let (actor, source_credential) = require_admin_with_credential(&state, &headers)?;
    let older_than_seconds = request.older_than_seconds.unwrap_or(86_400);
    let (upload_ids, receipt) = state.storage.stale_upload_cleanup_candidates_authorized(
        older_than_seconds,
        &actor,
        &source_credential,
    )?;
    let sessions = reap_upload_candidates_lock_safe_with(&state, upload_ids, |upload_id| {
        state.storage.reap_stale_upload_session_authorized(
            upload_id,
            older_than_seconds,
            &actor,
            &source_credential,
        )
    })?;
    let (drop_session_ids, _) = state
        .storage
        .stale_drop_upload_cleanup_candidates_authorized(
            older_than_seconds,
            &actor,
            &source_credential,
        )?;
    let drop_sessions =
        crate::routes::drop_uploads::reap_stale_drop_upload_candidates_lock_safe_authorized(
            &state,
            drop_session_ids,
            older_than_seconds,
            &actor,
            &source_credential,
        )?;
    crate::routes::drop_uploads::cleanup::reconcile_terminal_drop_upload_parts_lock_safe(
        &state,
        older_than_seconds,
    )?;
    Ok(Json(UploadCleanupResponse {
        cleaned_sessions: (sessions.len() + drop_sessions.len()) as i64,
        receipt,
    }))
}
