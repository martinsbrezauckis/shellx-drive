use axum::http::HeaderMap;

use crate::{
    auth::require_drive_actor_with_credential,
    error::{ApiError, ApiResult},
    model::UploadChunkResponse,
    server::AppState,
};

use super::{ensure_upload_session_permission, validation::ensure_upload_session_actor};

pub(super) enum UploadChunkAuthorization {
    Active(crate::auth::Actor),
    Completed(Box<UploadChunkResponse>),
}

pub(super) fn authorize_upload_chunk(
    state: &AppState,
    headers: &HeaderMap,
    upload_id: &str,
    finish: bool,
) -> ApiResult<UploadChunkAuthorization> {
    let (actor, source_credential) = require_drive_actor_with_credential(state, headers)?;
    let session = state
        .storage
        .get_upload_session(upload_id)?
        .ok_or(ApiError::NotFound)?;
    ensure_upload_session_actor(&session, &actor)?;
    ensure_upload_session_permission(state, &session, &actor)?;
    if session.canceled {
        return Err(ApiError::Conflict);
    }
    state
        .storage
        .ensure_workspace_server_content_allowed(&session.workspace_id)?;
    if session.completed {
        if !finish {
            return Err(ApiError::Conflict);
        }
        let completed = state.storage.completed_upload_outcome_authorized(
            upload_id,
            &actor,
            &source_credential,
        )?;
        return Ok(UploadChunkAuthorization::Completed(Box::new(
            UploadChunkResponse {
                session: completed.session,
                file: Some(completed.file),
                receipt: Some(completed.receipt),
                conflict: completed.conflict,
            },
        )));
    }
    Ok(UploadChunkAuthorization::Active(actor))
}
