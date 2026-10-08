use std::collections::HashSet;

use axum::{extract::State, http::HeaderMap, routing::post, Json, Router};

use crate::{
    auth::{
        require_admin_with_credential, require_user_actor_with_credential, DriveCredential,
        WorkspacePermission,
    },
    blob,
    error::ApiResult,
    model::{RetentionPreviewResponse, RetentionRequest},
    server::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/retention/preview", post(admin_retention_preview))
        .route("/admin/retention/apply", post(admin_retention_apply))
        .route("/debug/retention/preview", post(debug_retention_preview))
}

async fn admin_retention_preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RetentionRequest>,
) -> ApiResult<Json<RetentionPreviewResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    ensure_retention_scope(&state, request.workspace_id.as_deref(), &actor)?;
    Ok(Json(retention_response(
        &state,
        request.workspace_id,
        true,
        None,
        &actor,
        &source_credential,
    )?))
}

async fn admin_retention_apply(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RetentionRequest>,
) -> ApiResult<Json<RetentionPreviewResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    ensure_retention_scope(&state, request.workspace_id.as_deref(), &actor)?;
    let _blob_lifecycle_lock = blob::acquire_exclusive_lifecycle_lock(state.data_dir()).await?;
    let (trash, revisions, _totals, more_available) = state
        .storage
        .preview_retention(request.workspace_id.as_deref())?;
    let (receipt, candidate_hashes, trash, revisions) = state.storage.apply_retention_authorized(
        &trash,
        &revisions,
        &actor,
        &source_credential,
        request.workspace_id.as_deref(),
    )?;
    prune_unreferenced_candidate_blobs(&state, candidate_hashes)?;
    let totals = crate::model::RetentionTotals {
        trashed_files: trash.len(),
        revisions: revisions.len(),
        content_bytes: trash
            .iter()
            .map(|candidate| candidate.content_bytes)
            .chain(revisions.iter().map(|candidate| candidate.content_bytes))
            .sum(),
    };
    Ok(Json(RetentionPreviewResponse {
        service: "shellx-drive".to_string(),
        dry_run: false,
        workspace_id: request.workspace_id,
        trash,
        revisions,
        totals,
        more_available,
        receipt: Some(receipt),
    }))
}

async fn debug_retention_preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RetentionRequest>,
) -> ApiResult<Json<RetentionPreviewResponse>> {
    let (actor, source_credential) = require_admin_with_credential(&state, &headers)?;
    Ok(Json(retention_response(
        &state,
        request.workspace_id,
        true,
        None,
        &actor,
        &source_credential,
    )?))
}

fn prune_unreferenced_candidate_blobs(state: &AppState, hashes: Vec<String>) -> ApiResult<()> {
    for hash in hashes.into_iter().collect::<HashSet<_>>() {
        if !state.storage.content_hash_is_referenced(&hash)? {
            blob::remove_blob(&state.data_dir(), &hash)?;
        }
    }
    Ok(())
}

fn retention_response(
    state: &AppState,
    workspace_id: Option<String>,
    dry_run: bool,
    receipt: Option<crate::model::Receipt>,
    actor: &crate::auth::Actor,
    source_credential: &DriveCredential,
) -> ApiResult<RetentionPreviewResponse> {
    let (trash, revisions, totals, more_available) = state.storage.preview_retention_authorized(
        workspace_id.as_deref(),
        actor,
        source_credential,
    )?;
    Ok(RetentionPreviewResponse {
        service: "shellx-drive".to_string(),
        dry_run,
        workspace_id,
        trash,
        revisions,
        totals,
        more_available,
        receipt,
    })
}

fn ensure_retention_scope(
    state: &AppState,
    workspace_id: Option<&str>,
    actor: &crate::auth::Actor,
) -> ApiResult<()> {
    if actor.is_admin {
        return Ok(());
    }
    let Some(workspace_id) = workspace_id else {
        return Err(crate::error::ApiError::Forbidden);
    };
    state
        .storage
        .ensure_workspace_permission(workspace_id, actor, WorkspacePermission::Manage)
}
