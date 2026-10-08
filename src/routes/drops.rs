use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, patch, post},
    Json, Router,
};

use crate::{
    auth::{require_user_actor_with_credential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{CreateDropRequest, CreateDropResponse, DropListResponse, UpdateDropRequest},
    server::AppState,
    storage::{DropCreateFields, DropUpdateFields},
    workspace_policy::{
        validate_drop_policy, validate_drop_update_policy, validate_new_public_capability_password,
    },
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/drops", post(create_drop))
        .route(
            "/workspaces/{workspace_id}/drops",
            get(list_workspace_drops),
        )
        .route("/drops/{drop_id}", patch(update_drop))
        .route("/drops/{drop_id}/revoke", post(revoke_drop))
}

async fn create_drop(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateDropRequest>,
) -> ApiResult<(StatusCode, Json<CreateDropResponse>)> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    state.storage.ensure_workspace_permission(
        &request.workspace_id,
        &actor,
        WorkspacePermission::Write,
    )?;
    let policy = state.storage.get_workspace_policy(&request.workspace_id)?;
    let password_required = validate_new_public_capability_password(&request.password)?;
    validate_drop_policy(&policy, password_required, request.expires_in_seconds)?;
    let password_hash = state.hash_public_password(&request.password).await?;
    let (drop, receipt) = state.storage.create_pending_drop_publication(
        DropCreateFields {
            workspace_id: &request.workspace_id,
            name: &request.name,
            password_hash: &password_hash,
            password_required,
            expires_in_seconds: request.expires_in_seconds,
        },
        &actor,
        &source_credential,
    )?;
    state.storage.publish_pending_drop(
        &drop.id,
        &receipt,
        password_required,
        request.expires_in_seconds,
        &actor,
        &source_credential,
    )?;
    Ok((
        StatusCode::CREATED,
        Json(CreateDropResponse { drop, receipt }),
    ))
}

async fn list_workspace_drops(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> ApiResult<Json<DropListResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    state
        .storage
        .ensure_workspace_permission(&workspace_id, &actor, WorkspacePermission::Write)?;
    let drops = state.storage.list_workspace_drops(&workspace_id)?;
    state.storage.ensure_workspace_publication_authorized(
        &workspace_id,
        &actor,
        &source_credential,
        WorkspacePermission::Write,
    )?;
    Ok(Json(DropListResponse { drops }))
}

async fn update_drop(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(drop_id): Path<String>,
    Json(request): Json<UpdateDropRequest>,
) -> ApiResult<Json<CreateDropResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    let record = state
        .storage
        .get_drop(&drop_id)?
        .ok_or(ApiError::NotFound)?;
    state.storage.ensure_workspace_permission(
        &record.drop.workspace_id,
        &actor,
        WorkspacePermission::Write,
    )?;
    let policy = state
        .storage
        .get_workspace_policy(&record.drop.workspace_id)?;
    let password_required = request
        .password
        .as_deref()
        .map(validate_new_public_capability_password)
        .transpose()?;
    validate_drop_update_policy(&policy, password_required, request.expires_in_seconds)?;
    let password_hash = match request.password.as_deref() {
        Some(password) => Some(state.hash_public_password(password).await?),
        None => None,
    };
    let (drop, receipt, canceled_session_ids) = state.storage.update_drop(
        &drop_id,
        DropUpdateFields {
            name: request.name.as_deref(),
            password_hash: password_hash.as_deref(),
            password_required,
            expires_in_seconds: request.expires_in_seconds,
        },
        &actor,
        &source_credential,
    )?;
    super::drop_uploads::cleanup_canceled_drop_upload_parts(&state, &canceled_session_ids);
    Ok(Json(CreateDropResponse { drop, receipt }))
}

async fn revoke_drop(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(drop_id): Path<String>,
) -> ApiResult<Json<CreateDropResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    let record = state
        .storage
        .get_drop(&drop_id)?
        .ok_or(ApiError::NotFound)?;
    state.storage.ensure_workspace_permission(
        &record.drop.workspace_id,
        &actor,
        WorkspacePermission::Write,
    )?;
    let (drop, receipt, canceled_session_ids) =
        state
            .storage
            .revoke_drop(&drop_id, &actor, &source_credential)?;
    super::drop_uploads::cleanup_canceled_drop_upload_parts(&state, &canceled_session_ids);
    Ok(Json(CreateDropResponse { drop, receipt }))
}
