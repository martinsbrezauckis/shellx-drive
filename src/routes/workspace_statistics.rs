use axum::{
    extract::{Path, State},
    http::HeaderMap,
    routing::get,
    Json, Router,
};

use crate::{
    auth::{require_drive_actor_with_credential, WorkspacePermission},
    error::ApiResult,
    model::WorkspaceFileStatisticsResponse,
    server::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new().route(
        "/workspaces/{workspace_id}/file-statistics",
        get(workspace_file_statistics),
    )
}

async fn workspace_file_statistics(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> ApiResult<Json<WorkspaceFileStatisticsResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    state.storage.ensure_workspace_permission(
        &workspace_id,
        &actor,
        WorkspacePermission::Manage,
    )?;
    let statistics = state.storage.workspace_file_statistics(&workspace_id)?;
    state.storage.ensure_workspace_publication_authorized(
        &workspace_id,
        &actor,
        &source_credential,
        WorkspacePermission::Manage,
    )?;
    Ok(Json(statistics))
}
