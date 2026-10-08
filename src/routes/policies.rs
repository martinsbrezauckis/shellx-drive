use axum::{
    extract::{Path, State},
    http::HeaderMap,
    routing::get,
    Json, Router,
};

use crate::{
    auth::{
        require_drive_actor_with_credential, require_user_actor_with_credential,
        WorkspacePermission,
    },
    error::{ApiError, ApiResult},
    model::{
        UpdateWorkspacePolicyRequest, WorkspacePolicyMutationResponse, WorkspacePolicyReadResponse,
        WorkspaceUsage,
    },
    server::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/workspaces/{workspace_id}/usage", get(workspace_usage))
        .route(
            "/workspaces/{workspace_id}/policy",
            get(get_workspace_policy).patch(update_workspace_policy),
        )
}

async fn workspace_usage(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> ApiResult<Json<WorkspaceUsage>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    state
        .storage
        .ensure_workspace_permission(&workspace_id, &actor, WorkspacePermission::Read)?;
    let usage = state
        .run_workspace_usage(workspace_id.clone(), &actor.email)
        .await?;
    state.storage.ensure_workspace_publication_authorized(
        &workspace_id,
        &actor,
        &source_credential,
        WorkspacePermission::Read,
    )?;
    Ok(Json(usage))
}

async fn get_workspace_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> ApiResult<Json<WorkspacePolicyReadResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    state
        .storage
        .ensure_workspace_permission(&workspace_id, &actor, WorkspacePermission::Read)?;
    let policy = state.storage.get_workspace_policy(&workspace_id)?;
    state.storage.ensure_workspace_publication_authorized(
        &workspace_id,
        &actor,
        &source_credential,
        WorkspacePermission::Read,
    )?;
    Ok(Json(WorkspacePolicyReadResponse { policy }))
}

async fn update_workspace_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(request): Json<UpdateWorkspacePolicyRequest>,
) -> ApiResult<Json<WorkspacePolicyMutationResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    if request.quota_bytes.is_present() && !actor.is_admin {
        return Err(ApiError::Forbidden);
    }
    state.storage.ensure_workspace_permission(
        &workspace_id,
        &actor,
        WorkspacePermission::Manage,
    )?;
    let (policy, receipt) = state.storage.update_workspace_policy(
        &workspace_id,
        request,
        &actor,
        &source_credential,
    )?;
    Ok(Json(WorkspacePolicyMutationResponse { policy, receipt }))
}
