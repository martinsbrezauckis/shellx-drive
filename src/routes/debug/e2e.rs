use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    auth::{require_admin_with_credential, token_hash, Actor, DriveCredential},
    blob,
    error::{ApiError, ApiResult},
    model::{CreateFileRequest, FileKind},
    server::AppState,
    storage::E2eHumanSharingCleanupProbe,
};

#[derive(Debug, Deserialize)]
struct ExpireCapabilityRequest {
    invitation_id: Option<String>,
    password_reset_token: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CleanupQuery {
    run_id: String,
    actor_ids: Option<String>,
    actor_emails: Option<String>,
    root_file_id: Option<String>,
    group_id: Option<String>,
    #[serde(default)]
    actor_cleanup: bool,
}

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/debug/e2e/seed", post(seed))
        .route("/debug/e2e/reset", post(reset))
        .route("/debug/e2e/expire-capability", post(expire_capability))
        .route(
            "/debug/e2e/human-sharing/groups/{group_id}",
            delete(delete_human_sharing_group),
        )
        .route(
            "/debug/e2e/human-sharing/actors/{actor_id}",
            delete(delete_human_sharing_actor),
        )
        .route(
            "/debug/e2e/human-sharing/cleanup",
            get(human_sharing_cleanup_probe),
        )
}

fn require_e2e(state: &AppState, headers: &HeaderMap) -> ApiResult<(Actor, DriveCredential)> {
    let actor = require_admin_with_credential(state, headers)?;
    if !state.config.e2e_enabled {
        return Err(ApiError::Forbidden);
    }
    Ok(actor)
}

fn require_e2e_operator(
    state: &AppState,
    headers: &HeaderMap,
) -> ApiResult<(Actor, DriveCredential)> {
    let (actor, credential) = require_e2e(state, headers)?;
    if !matches!(credential, DriveCredential::Operator) {
        return Err(ApiError::Forbidden);
    }
    Ok((actor, credential))
}

async fn seed(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let (actor, source_credential) = require_e2e(&state, &headers)?;
    let (workspace, owner, workspace_receipt) = state.storage.create_workspace_authorized(
        "E2E Workspace",
        "e2e@example.test",
        None,
        &actor,
        &source_credential,
    )?;
    let _blob_lifecycle_lock = blob::acquire_shared_lifecycle_lock(state.data_dir()).await?;
    let content_hash = blob::put_blob(&state.data_dir(), b"seed file")?;
    let (file, file_receipt) = state.storage.create_file_with_content_bytes_authorized(
        CreateFileRequest {
            workspace_id: workspace.id.clone(),
            parent_id: None,
            name: "seed.txt".to_string(),
            kind: FileKind::File,
            content: None,
            path: None,
        },
        Some(content_hash),
        "seed file".len() as i64,
        &actor,
        &source_credential,
    )?;
    Ok(Json(json!({
        "workspace": workspace,
        "owner": owner,
        "file": file,
        "receipts": [workspace_receipt, file_receipt],
    })))
}

async fn reset(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<(StatusCode, Json<serde_json::Value>)> {
    let (actor, source_credential) = require_e2e_operator(&state, &headers)?;
    let _blob_lifecycle_lock = blob::acquire_exclusive_lifecycle_lock(state.data_dir()).await?;
    state
        .storage
        .reset_all_authorized(&actor, &source_credential)?;
    let blobs = state.data_dir().join("blobs");
    if blobs.exists() {
        std::fs::remove_dir_all(blobs)?;
    }
    Ok((StatusCode::OK, Json(json!({ "ok": true }))))
}

async fn expire_capability(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ExpireCapabilityRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let (actor, source_credential) = require_e2e(&state, &headers)?;
    let changed = match (
        request.invitation_id.as_deref(),
        request.password_reset_token.as_deref(),
    ) {
        (Some(invitation_id), None) => state.storage.e2e_expire_workspace_invitation_authorized(
            invitation_id,
            &actor,
            &source_credential,
        )?,
        (None, Some(token)) => state.storage.e2e_expire_password_reset_authorized(
            &token_hash(token),
            &actor,
            &source_credential,
        )?,
        _ => {
            return Err(ApiError::Validation(
                "supply exactly one disposable capability".to_string(),
            ))
        }
    };
    if !changed {
        return Err(ApiError::NotFound);
    }
    Ok(Json(json!({ "expired": true })))
}

async fn delete_human_sharing_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(group_id): Path<String>,
    Query(query): Query<CleanupQuery>,
) -> ApiResult<StatusCode> {
    let (actor, source_credential) = require_e2e_operator(&state, &headers)?;
    state.storage.delete_e2e_human_sharing_group(
        &group_id,
        &query.run_id,
        &actor,
        &source_credential,
    )?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_human_sharing_actor(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(actor_id): Path<String>,
    Query(query): Query<CleanupQuery>,
) -> ApiResult<StatusCode> {
    let (actor, source_credential) = require_e2e_operator(&state, &headers)?;
    state.storage.delete_e2e_human_sharing_actor(
        &actor_id,
        &query.run_id,
        &actor,
        &source_credential,
    )?;
    Ok(StatusCode::NO_CONTENT)
}

async fn human_sharing_cleanup_probe(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<CleanupQuery>,
) -> ApiResult<Json<serde_json::Value>> {
    let (actor, source_credential) = require_e2e_operator(&state, &headers)?;
    let actor_ids = query
        .actor_ids
        .as_deref()
        .ok_or_else(|| ApiError::Validation("cleanup probe requires actor_ids".to_string()))?
        .split(',')
        .map(str::trim)
        .map(str::to_string)
        .collect::<Vec<_>>();
    let actor_emails = query
        .actor_emails
        .as_deref()
        .ok_or_else(|| ApiError::Validation("cleanup probe requires actor_emails".to_string()))?
        .split(',')
        .map(str::trim)
        .map(str::to_string)
        .collect::<Vec<_>>();
    let probe = state.storage.e2e_human_sharing_cleanup_probe(
        E2eHumanSharingCleanupProbe {
            run_id: &query.run_id,
            actor_ids: &actor_ids,
            actor_emails: &actor_emails,
            root_file_id: query.root_file_id.as_deref(),
            group_id: query.group_id.as_deref(),
            actor_cleanup: query.actor_cleanup,
        },
        &actor,
        &source_credential,
    )?;
    Ok(Json(json!({ "clean": probe.clean })))
}
