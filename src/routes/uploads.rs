use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};

use crate::{
    auth::{require_drive_actor_with_credential, DriveCredential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{
        CreateUploadSessionRequest, UploadChunkRequest, UploadChunkResponse,
        UploadSessionListResponse, UploadSessionMutationResponse, UploadSessionResponse,
    },
    server::AppState,
    storage::{UploadAdmissionPolicy, UploadSessionCreate},
};

mod admission;
mod binary;
mod cancellation;
pub(crate) mod cleanup;
mod execution;
#[cfg(test)]
mod ingress_tests;
mod locking;
mod preflight;
mod validation;

use admission::{authorize_upload_chunk, UploadChunkAuthorization};
pub(super) use execution::put_upload_bytes;
use locking::upload_dir;
use validation::{ensure_upload_session_actor, upload_chunk_bytes, validate_declared_upload_size};

pub(super) const MAX_RESUMABLE_UPLOAD_BYTES: i64 = 2 * 1024 * 1024 * 1024;
pub(super) const MAX_RESUMABLE_CHUNK_BYTES: usize = 8 * 1024 * 1024;

pub(super) fn ensure_upload_destination_permission(
    state: &AppState,
    workspace_id: &str,
    parent_id: Option<&str>,
    actor: &crate::auth::Actor,
) -> ApiResult<()> {
    match parent_id {
        Some(parent_id) => state
            .storage
            .ensure_item_response_permission(parent_id, actor, WorkspacePermission::Write)
            .map(|_| ()),
        None => state.storage.ensure_workspace_permission(
            workspace_id,
            actor,
            WorkspacePermission::Write,
        ),
    }
}

pub(super) fn ensure_upload_session_permission(
    state: &AppState,
    session: &crate::model::UploadSession,
    actor: &crate::auth::Actor,
) -> ApiResult<()> {
    if let Some(target_file_id) = session.target_file_id.as_deref() {
        return state
            .storage
            .ensure_item_response_permission(target_file_id, actor, WorkspacePermission::Write)
            .map(|_| ());
    }
    ensure_upload_destination_permission(
        state,
        &session.workspace_id,
        session.parent_id.as_deref(),
        actor,
    )
}

fn ensure_upload_session_publication_permission(
    state: &AppState,
    session: &crate::model::UploadSession,
    actor: &crate::auth::Actor,
    source_credential: &DriveCredential,
) -> ApiResult<()> {
    if let Some(target_file_id) = session.target_file_id.as_deref() {
        state.storage.ensure_item_response_publication_authorized(
            target_file_id,
            actor,
            source_credential,
            WorkspacePermission::Write,
        )?;
    } else if let Some(parent_id) = session.parent_id.as_deref() {
        state.storage.ensure_item_response_publication_authorized(
            parent_id,
            actor,
            source_credential,
            WorkspacePermission::Write,
        )?;
    } else {
        state.storage.ensure_workspace_publication_authorized(
            &session.workspace_id,
            actor,
            source_credential,
            WorkspacePermission::Write,
        )?;
    }
    Ok(())
}

pub(in crate::routes) fn validated_upload_part_path(
    state: &AppState,
    upload_id: &str,
) -> ApiResult<std::path::PathBuf> {
    locking::upload_part_path(state, upload_id)
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/uploads/resumable", post(create_session))
        .route(
            "/workspaces/{workspace_id}/uploads",
            get(list_workspace_uploads),
        )
        .route(
            "/uploads/resumable/{upload_id}",
            get(get_session).put(put_chunk),
        )
        .route(
            "/uploads/resumable/{upload_id}/cancel",
            post(cancel_session),
        )
        .route("/admin/uploads/cleanup", post(cleanup::cleanup_uploads))
        .merge(binary::router())
        .merge(preflight::router())
}

async fn create_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateUploadSessionRequest>,
) -> ApiResult<(StatusCode, Json<UploadSessionResponse>)> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let total_size = request.total_size.ok_or_else(|| {
        ApiError::Validation("total_size is required for resumable uploads".to_string())
    })?;
    validate_declared_upload_size(total_size)?;
    let duplicate_policy = match request.duplicate_policy.as_deref().unwrap_or("keep_both") {
        "keep_both" => "keep_both",
        // Preserve clients that used the previous spelling while retaining the
        // decision through finalization, where a race can still occur.
        "cancel" | "skip" => "cancel",
        "replace" => "replace",
        _ => {
            return Err(ApiError::Validation(
                "duplicate_policy must be keep_both, replace, or cancel".to_string(),
            ));
        }
    };
    let session = match (&request.target_file_id, request.base_revision) {
        (Some(target_file_id), Some(base_revision)) => {
            if !matches!(request.duplicate_policy.as_deref(), None | Some("replace")) {
                return Err(ApiError::Validation(
                    "target_file_id updates require duplicate_policy replace".to_string(),
                ));
            }
            let target = state
                .storage
                .get_file(target_file_id)?
                .ok_or(ApiError::NotFound)?;
            state.storage.ensure_item_response_permission(
                &target.id,
                &actor,
                WorkspacePermission::Write,
            )?;
            if !matches!(target.kind, crate::model::FileKind::File) || target.trashed {
                return Err(ApiError::Validation(
                    "resumable replacements require one live regular file".to_string(),
                ));
            }
            state
                .storage
                .ensure_workspace_server_content_allowed(&target.workspace_id)?;
            state.storage.create_replacement_upload_session_authorized(
                target_file_id,
                base_revision,
                &actor,
                &source_credential,
                total_size,
                UploadAdmissionPolicy::default(),
            )?
        }
        (None, None) => {
            if duplicate_policy == "replace" {
                return Err(ApiError::Validation(
                    "duplicate_policy replace requires target_file_id and base_revision"
                        .to_string(),
                ));
            }
            let workspace_id = request.workspace_id.as_deref().ok_or_else(|| {
                ApiError::Validation(
                    "workspace_id is required for new resumable uploads".to_string(),
                )
            })?;
            let name = request.name.as_deref().ok_or_else(|| {
                ApiError::Validation("name is required for new resumable uploads".to_string())
            })?;
            ensure_upload_destination_permission(
                &state,
                workspace_id,
                request.parent_id.as_deref(),
                &actor,
            )?;
            state
                .storage
                .ensure_workspace_server_content_allowed(workspace_id)?;
            state
                .storage
                .ensure_workspace_quota(workspace_id, None, total_size)?;
            if duplicate_policy == "cancel" {
                let candidate = crate::model::UploadPreflightFile {
                    name: name.to_string(),
                    size: total_size,
                    path: request.path.clone(),
                };
                let preflight = state
                    .run_upload_preflight(
                        workspace_id.to_string(),
                        request.parent_id.clone(),
                        vec![candidate],
                        total_size,
                        &actor.email,
                    )
                    .await?;
                if !preflight.conflicts.is_empty() {
                    return Err(ApiError::Conflict);
                }
            }
            state.storage.create_upload_session_authorized(
                UploadSessionCreate {
                    workspace_id,
                    actor_email: &actor.email,
                    parent_id: request.parent_id,
                    name,
                    total_size: Some(total_size),
                    path: request.path,
                    duplicate_policy,
                },
                UploadAdmissionPolicy::default(),
                &actor,
                &source_credential,
            )?
        }
        _ => {
            return Err(ApiError::Validation(
                "target_file_id and base_revision must be supplied together".to_string(),
            ));
        }
    };
    crate::fs_private::create_dir_all_private(&upload_dir(&state))?;
    Ok((StatusCode::CREATED, Json(UploadSessionResponse { session })))
}

async fn get_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(upload_id): Path<String>,
) -> ApiResult<Json<UploadSessionResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let session = state
        .storage
        .get_upload_session(&upload_id)?
        .ok_or(ApiError::NotFound)?;
    ensure_upload_session_actor(&session, &actor)?;
    ensure_upload_session_publication_permission(&state, &session, &actor, &source_credential)?;
    Ok(Json(UploadSessionResponse { session }))
}

async fn list_workspace_uploads(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> ApiResult<Json<UploadSessionListResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    state
        .storage
        .ensure_workspace_permission(&workspace_id, &actor, WorkspacePermission::Read)?;
    let sessions = state
        .storage
        .list_upload_sessions_for_workspace(&workspace_id, &actor)?;
    state.storage.ensure_workspace_publication_authorized(
        &workspace_id,
        &actor,
        &source_credential,
        WorkspacePermission::Read,
    )?;
    Ok(Json(UploadSessionListResponse { sessions }))
}

async fn cancel_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(upload_id): Path<String>,
) -> ApiResult<Json<UploadSessionMutationResponse>> {
    cancellation::cancel_upload(state, headers, upload_id).await
}

async fn put_chunk(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(upload_id): Path<String>,
    Json(request): Json<UploadChunkRequest>,
) -> ApiResult<Json<UploadChunkResponse>> {
    let (actor, _) = require_drive_actor_with_credential(&state, &headers)?;
    let ingress_permit = state.try_authenticated_upload_ingress(&actor.email)?;
    let chunk = upload_chunk_bytes(&request)?;
    if chunk.len() > MAX_RESUMABLE_CHUNK_BYTES {
        return Err(ApiError::PayloadTooLarge(format!(
            "upload chunks must not exceed {MAX_RESUMABLE_CHUNK_BYTES} bytes"
        )));
    }
    put_upload_bytes(
        state,
        headers,
        upload_id,
        request.offset,
        request.finish.unwrap_or(false),
        chunk,
        ingress_permit,
    )
    .await
}
