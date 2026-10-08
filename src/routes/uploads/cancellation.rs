use axum::{http::HeaderMap, Json};

use super::{locking, validation::ensure_upload_session_actor};
use crate::{
    auth::require_drive_actor_with_credential,
    error::{ApiError, ApiResult},
    model::UploadSessionMutationResponse,
    server::AppState,
};

pub(super) async fn cancel_upload(
    state: AppState,
    headers: HeaderMap,
    upload_id: String,
) -> ApiResult<Json<UploadSessionMutationResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    crate::upload_ids::require_canonical(&upload_id)?;
    let canonical_upload_id = upload_id;
    let worker_state = state.clone();
    state
        .run_detached_mutation(async move {
            tokio::task::spawn_blocking(move || {
                // Unknown or foreign identifiers must not create directories or lock
                // files. Re-fetch after locking below to preserve current-state checks.
                let session = worker_state
                    .storage
                    .get_upload_session(&canonical_upload_id)?
                    .ok_or(ApiError::NotFound)?;
                ensure_upload_session_actor(&session, &actor)?;
                crate::fs_private::create_dir_all_private(&locking::upload_dir(&worker_state))?;
                let _lock = locking::acquire_upload_lock(&worker_state, &canonical_upload_id)?;
                let session = worker_state
                    .storage
                    .get_upload_session(&canonical_upload_id)?
                    .ok_or(ApiError::NotFound)?;
                ensure_upload_session_actor(&session, &actor)?;
                let (session, receipt) = worker_state.storage.cancel_upload_session_authorized(
                    &canonical_upload_id,
                    &actor,
                    &source_credential,
                )?;
                let part_path = locking::upload_part_path(&worker_state, &canonical_upload_id)?;
                if let Err(error) = std::fs::remove_file(part_path) {
                    if error.kind() != std::io::ErrorKind::NotFound {
                        tracing::warn!(upload_id = %canonical_upload_id, %error, "canceled upload part cleanup failed");
                    }
                }
                Ok(Json(UploadSessionMutationResponse { session, receipt }))
            })
            .await
            .map_err(|_| ApiError::Maintenance("upload cancellation worker failed".to_string()))?
        })
        .await
}
