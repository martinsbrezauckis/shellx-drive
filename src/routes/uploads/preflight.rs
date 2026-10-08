use axum::{extract::State, http::HeaderMap, routing::post, Json, Router};

use crate::{
    auth::{require_drive_actor_with_credential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{UploadPreflightRequest, UploadPreflightResponse},
    server::AppState,
};

use super::{ensure_upload_destination_permission, validate_declared_upload_size};

const MAX_PREFLIGHT_FILES: usize = 512;

pub(super) fn router() -> Router<AppState> {
    Router::new().route("/uploads/preflight", post(upload_preflight))
}

async fn upload_preflight(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<UploadPreflightRequest>,
) -> ApiResult<Json<UploadPreflightResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    ensure_upload_destination_permission(
        &state,
        &request.workspace_id,
        request.parent_id.as_deref(),
        &actor,
    )?;
    state
        .storage
        .ensure_workspace_server_content_allowed(&request.workspace_id)?;
    if request.files.len() > MAX_PREFLIGHT_FILES {
        return Err(ApiError::Validation(format!(
            "upload preflight accepts at most {MAX_PREFLIGHT_FILES} files"
        )));
    }
    let requested_bytes = request.files.iter().try_fold(0_i64, |total, file| {
        validate_declared_upload_size(file.size)?;
        total.checked_add(file.size).ok_or_else(|| {
            ApiError::Validation("upload preflight byte total overflowed".to_string())
        })
    })?;
    let mut response = state
        .run_upload_preflight(
            request.workspace_id.clone(),
            request.parent_id.clone(),
            request.files,
            requested_bytes,
            &actor.email,
        )
        .await?;
    if let Some(parent_id) = request.parent_id.as_deref() {
        let access = state.storage.ensure_item_response_publication_authorized(
            parent_id,
            &actor,
            &source_credential,
            WorkspacePermission::Write,
        )?;
        if access.workspace_id != request.workspace_id {
            return Err(ApiError::NotFound);
        }
        match state.storage.ensure_workspace_permission(
            &request.workspace_id,
            &actor,
            WorkspacePermission::Read,
        ) {
            Ok(()) => state.storage.ensure_workspace_publication_authorized(
                &request.workspace_id,
                &actor,
                &source_credential,
                WorkspacePermission::Read,
            )?,
            Err(ApiError::Forbidden | ApiError::NotFound) => {
                response.current_file_bytes = None;
                response.quota_bytes = None;
                response.remaining_bytes = None;
            }
            Err(error) => return Err(error),
        }
    } else {
        state.storage.ensure_workspace_publication_authorized(
            &request.workspace_id,
            &actor,
            &source_credential,
            WorkspacePermission::Write,
        )?;
    }
    Ok(Json(response))
}
