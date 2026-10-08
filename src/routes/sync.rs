use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap},
    response::{IntoResponse, Response},
    routing::{get, put},
    Json, Router,
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    auth::{require_drive_actor_with_credential, Actor, DriveCredential, WorkspacePermission},
    blob,
    error::{ApiError, ApiResult},
    model::{
        FileChunkManifestResponse, MobileManifestResponse, MobileOfflineListResponse,
        MobileOfflineMutationResponse, MobileOfflineRequest, MobileWorkspace,
        MobileWorkspacesResponse, SyncChangesResponse, SyncConflictsResponse, SyncHealthResponse,
    },
    routes::{
        blob_response::{serve_blob_file_with_guard_after_open, Disposition},
        content_revalidation::{AuthenticatedFilePublication, AuthenticatedWorkspacePublication},
        metadata_publication::revalidate_file_id_metadata_publication,
        metadata_response::guarded_metadata_json_with_permit,
    },
    server::AppState,
    storage::FileAccessKind,
};

mod chunks;
mod delta;
mod mobile_metadata;

use mobile_metadata::{ensure_mobile_downloadable, mobile_file_metadata};

use chunks::{
    chunk_descriptors, ensure_chunk_manifest_descriptor_limit, ensure_delta_file_allowed,
    file_bytes, sha256_hex, validate_chunk_size, DEFAULT_DELTA_CHUNK_SIZE,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/sync/workspaces", get(list_workspaces))
        .route("/sync/health", get(sync_health))
        .route("/sync/changes", get(sync_changes))
        .route("/sync/conflicts", get(sync_conflicts))
        .route("/sync/mobile/workspaces", get(mobile_workspaces))
        .route(
            "/sync/mobile/workspaces/{workspace_id}/manifest",
            get(mobile_manifest),
        )
        .route(
            "/sync/mobile/offline",
            get(mobile_offline).post(set_mobile_offline),
        )
        .route(
            "/sync/mobile/files/{file_id}/content",
            get(mobile_file_content),
        )
        .route("/sync/files/{file_id}/chunks", get(file_chunk_manifest))
        .route("/sync/files/{file_id}/delta", put(delta::put))
        .route(
            "/sync/workspaces/{workspace_id}/manifest",
            get(sync_manifest),
        )
        .route(
            "/sync/workspaces/{workspace_id}/changes",
            get(workspace_sync_changes),
        )
}

#[derive(Deserialize)]
struct ChangesQuery {
    cursor: Option<i64>,
}

#[derive(Deserialize)]
struct ChunkManifestQuery {
    chunk_size: Option<usize>,
}

const MAX_SYNC_MANIFEST_FILES: usize = 10_000;
/// Account-wide metadata routes must reject before constructing a response or
/// fanning out into per-workspace queries.  This matches the terminal
/// publication subject ceiling in storage authorization.
const MAX_SYNC_METADATA_WORKSPACES: usize = 1_000;

async fn list_workspaces(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let workspaces = state
        .storage
        .list_workspaces_for_actor_bounded(&actor, MAX_SYNC_METADATA_WORKSPACES)?;
    let workspace_ids = workspace_ids_from_workspaces(&workspaces);
    let response = json!({
        "mode": "multi_workspace",
        "workspaces": workspaces,
    });
    revalidate_sync_metadata_publication(&state, &workspace_ids, &actor, &source_credential)?;
    Ok(Json(response))
}

async fn sync_health(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<SyncHealthResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let workspaces = state
        .storage
        .list_workspaces_for_actor_bounded(&actor, MAX_SYNC_METADATA_WORKSPACES)?;
    let workspace_ids = workspace_ids_from_workspaces(&workspaces);
    let response = state
        .storage
        .sync_health_for_workspaces(workspaces, Some(actor.email.clone()))?;
    revalidate_sync_metadata_publication(&state, &workspace_ids, &actor, &source_credential)?;
    Ok(Json(response))
}

async fn sync_manifest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> ApiResult<Response> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    state
        .storage
        .ensure_workspace_permission(&workspace_id, &actor, WorkspacePermission::Read)?;
    // The manifest query materializes the complete active workspace tree and
    // derives folder totals while holding SQLite's sole connection mutex.
    // Admit it through the fail-fast planning lane before that work starts;
    // this covers the blocking read itself, not merely later JSON encoding.
    let planning_workspace_id = workspace_id.clone();
    let planning_storage = state.storage.clone();
    let ((files, next_cursor), planning_permit) = state
        .run_metadata_planning_retained(&actor.email, move || {
            planning_storage.list_sync_manifest_files_with_cursor(
                &planning_workspace_id,
                MAX_SYNC_MANIFEST_FILES,
            )
        })
        .await?;
    let publication = AuthenticatedWorkspacePublication::new(
        &state.storage,
        &workspace_id,
        &files,
        &actor,
        &source_credential,
    )?;
    guarded_metadata_json_with_permit(
        &state,
        &actor.email,
        planning_permit,
        || {
            json!({
                "workspace_id": workspace_id,
                "mode": "full_desktop_sync",
                "next_cursor": next_cursor,
                "files": files,
            })
        },
        || publication.revalidate(),
    )
}

async fn sync_changes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ChangesQuery>,
) -> ApiResult<Json<SyncChangesResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let cursor = query.cursor.unwrap_or(0).max(0);
    let changes = state.storage.list_sync_changes_for_actor(&actor, cursor)?;
    let next_cursor = changes
        .iter()
        .map(|change| change.id)
        .max()
        .unwrap_or(cursor);
    let workspace_ids = changes
        .iter()
        .map(|change| change.workspace_id.clone())
        .collect::<Vec<_>>();
    let response = SyncChangesResponse {
        cursor,
        next_cursor,
        changes,
    };
    revalidate_sync_metadata_publication(&state, &workspace_ids, &actor, &source_credential)?;
    Ok(Json(response))
}

async fn workspace_sync_changes(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Query(query): Query<ChangesQuery>,
) -> ApiResult<Json<SyncChangesResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    state
        .storage
        .ensure_workspace_permission(&workspace_id, &actor, WorkspacePermission::Read)?;
    let cursor = query.cursor.unwrap_or(0).max(0);
    let changes = state
        .storage
        .list_sync_changes(cursor, Some(&workspace_id))?;
    let next_cursor = changes
        .iter()
        .map(|change| change.id)
        .max()
        .unwrap_or(cursor);
    let response = SyncChangesResponse {
        cursor,
        next_cursor,
        changes,
    };
    revalidate_sync_metadata_publication(
        &state,
        std::slice::from_ref(&workspace_id),
        &actor,
        &source_credential,
    )?;
    Ok(Json(response))
}

async fn sync_conflicts(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<SyncConflictsResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let conflicts = state.storage.list_sync_conflicts_for_actor(&actor)?;
    let workspace_ids = conflicts
        .iter()
        .map(|conflict| conflict.workspace_id.clone())
        .collect::<Vec<_>>();
    let response = SyncConflictsResponse { conflicts };
    revalidate_sync_metadata_publication(&state, &workspace_ids, &actor, &source_credential)?;
    Ok(Json(response))
}

async fn file_chunk_manifest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
    Query(query): Query<ChunkManifestQuery>,
) -> ApiResult<Response> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let file = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    state
        .storage
        .ensure_item_response_permission(&file.id, &actor, WorkspacePermission::Read)?;
    ensure_delta_file_allowed(&state, &file)?;
    let publication =
        AuthenticatedFilePublication::new(&state.storage, &file, &actor, &source_credential)?;
    let chunk_size = validate_chunk_size(query.chunk_size.unwrap_or(DEFAULT_DELTA_CHUNK_SIZE))?;
    ensure_chunk_manifest_descriptor_limit(&file, chunk_size)?;
    let worker_state = state.clone();
    state
        .run_sync_compute(&actor.email, move || {
            let bytes = file_bytes(&worker_state, &file)?;
            let response = Json(FileChunkManifestResponse {
                file_id: file.id,
                workspace_id: file.workspace_id,
                revision: file.revision,
                content_bytes: bytes.len() as i64,
                chunk_size,
                content_sha256: sha256_hex(&bytes),
                chunks: chunk_descriptors(&bytes, chunk_size),
            });
            publication.revalidate()?;
            Ok(response.into_response())
        })
        .await?
}

async fn mobile_workspaces(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let planning_actor = actor.clone();
    let planning_storage = state.storage.clone();
    let ((workspaces, offline_counts), planning_permit) = state
        .run_metadata_planning_retained(&actor.email, move || {
            Ok((
                planning_storage.list_workspaces_for_actor_bounded(
                    &planning_actor,
                    MAX_SYNC_METADATA_WORKSPACES,
                )?,
                planning_storage.mobile_offline_counts_for_actor(&planning_actor.email)?,
            ))
        })
        .await?;
    let workspace_ids = workspace_ids_from_workspaces(&workspaces);
    let mut mobile_workspaces = Vec::with_capacity(workspaces.len());
    for workspace in workspaces {
        let offline_files = offline_counts.get(&workspace.id).copied().unwrap_or(0);
        mobile_workspaces.push(MobileWorkspace {
            id: workspace.id,
            name: workspace.name,
            storage_mode: workspace.storage_mode,
            created_at: workspace.created_at,
            sync_mode: "metadata_selective_offline".to_string(),
            offline_files,
        });
    }
    let response = MobileWorkspacesResponse {
        mode: "mobile_metadata".to_string(),
        workspaces: mobile_workspaces,
    };
    guarded_metadata_json_with_permit(
        &state,
        &actor.email,
        planning_permit,
        || response,
        || revalidate_sync_metadata_publication(&state, &workspace_ids, &actor, &source_credential),
    )
}

async fn mobile_manifest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> ApiResult<Response> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    state
        .storage
        .ensure_workspace_permission(&workspace_id, &actor, WorkspacePermission::Read)?;
    // Keep all blocking metadata materialization behind the same fail-fast
    // admission used by desktop manifests.  In particular the planning permit
    // remains owned while SQLite builds the bounded tree and its aggregates.
    let planning_workspace_id = workspace_id.clone();
    let planning_actor = actor.email.clone();
    let planning_storage = state.storage.clone();
    let ((storage_mode, offline_ids, manifest_files), planning_permit) = state
        .run_metadata_planning_retained(&actor.email, move || {
            let manifest_files = planning_storage
                .list_sync_manifest_files(&planning_workspace_id, MAX_SYNC_MANIFEST_FILES)?;
            Ok((
                planning_storage.workspace_storage_mode(&planning_workspace_id)?,
                planning_storage.mobile_offline_file_ids_for_manifest(
                    &planning_actor,
                    &planning_workspace_id,
                    &manifest_files,
                )?,
                manifest_files,
            ))
        })
        .await?;
    let publication = AuthenticatedWorkspacePublication::new(
        &state.storage,
        &workspace_id,
        &manifest_files,
        &actor,
        &source_credential,
    )?;
    guarded_metadata_json_with_permit(
        &state,
        &actor.email,
        planning_permit,
        || MobileManifestResponse {
            workspace_id,
            mode: "mobile_metadata".to_string(),
            files: manifest_files
                .into_iter()
                .map(|file| mobile_file_metadata(file, &storage_mode, &offline_ids))
                .collect(),
        },
        || publication.revalidate(),
    )
}

async fn mobile_offline(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<MobileOfflineListResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let files = state.storage.list_mobile_offline_files_for_actor(&actor)?;
    let file_ids = files
        .iter()
        .map(|file| file.file_id.clone())
        .collect::<Vec<_>>();
    let response = MobileOfflineListResponse { files };
    revalidate_file_id_metadata_publication(&state.storage, &file_ids, &actor, &source_credential)?;
    Ok(Json(response))
}

async fn set_mobile_offline(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<MobileOfflineRequest>,
) -> ApiResult<Json<MobileOfflineMutationResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let file = state
        .storage
        .get_file(&request.file_id)?
        .ok_or(ApiError::NotFound)?;
    state
        .storage
        .ensure_item_response_permission(&file.id, &actor, WorkspacePermission::Read)?;
    let storage_mode = state.storage.workspace_storage_mode(&file.workspace_id)?;
    if request.offline {
        ensure_mobile_downloadable(&file, &storage_mode)?;
        state.storage.ensure_file_effectively_live(&file.id)?;
    }
    let receipt = state.storage.set_mobile_offline_file(
        &actor,
        &source_credential,
        &file.workspace_id,
        &file.id,
        request.offline,
    )?;
    Ok(Json(MobileOfflineMutationResponse {
        file_id: file.id,
        offline: request.offline,
        receipt,
    }))
}

async fn mobile_file_content(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> ApiResult<Response> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let file = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    state
        .storage
        .ensure_item_response_permission(&file.id, &actor, WorkspacePermission::Read)?;
    state.storage.ensure_file_effectively_live(&file.id)?;
    if !state
        .storage
        .is_mobile_offline_file(&actor.email, &file_id)?
    {
        return Err(ApiError::Forbidden);
    }
    let storage_mode = state.storage.workspace_storage_mode(&file.workspace_id)?;
    ensure_mobile_downloadable(&file, &storage_mode)?;
    let publication =
        AuthenticatedFilePublication::new(&state.storage, &file, &actor, &source_credential)?;
    let path = blob::blob_file_path(&state.data_dir(), publication.content_hash())?;
    let range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok());
    state.storage.record_file_access_best_effort(
        &file.id,
        &file.workspace_id,
        FileAccessKind::Download,
    );
    let stream_permit = state.try_authenticated_body_stream(&actor.email)?;
    let terminal_storage = state.storage.clone();
    let terminal_actor = publication.actor_email().to_string();
    let terminal_file_id = publication.file_id().to_string();
    let terminal_workspace_id = publication.workspace_id().to_string();
    let terminal_file = file.clone();
    serve_blob_file_with_guard_after_open(
        &file.name,
        &path,
        range,
        Disposition::Attachment,
        stream_permit,
        move || {
            publication.revalidate()?;
            if !terminal_storage.is_mobile_offline_file(&terminal_actor, &terminal_file_id)? {
                return Err(ApiError::Forbidden);
            }
            let storage_mode = terminal_storage.workspace_storage_mode(&terminal_workspace_id)?;
            ensure_mobile_downloadable(&terminal_file, &storage_mode)
        },
    )
    .await
}

/// Account-wide sync endpoints select metadata from more than one workspace.
/// Preserve exactly those response subjects and prove the originating
/// credential, current role, and app-token scope immediately before Axum can
/// publish the buffered JSON.
fn revalidate_sync_metadata_publication(
    state: &AppState,
    workspace_ids: &[String],
    actor: &Actor,
    source_credential: &DriveCredential,
) -> ApiResult<()> {
    state
        .storage
        .ensure_workspace_metadata_publication_authorized(workspace_ids, actor, source_credential)
}

fn workspace_ids_from_workspaces(workspaces: &[crate::model::Workspace]) -> Vec<String> {
    workspaces
        .iter()
        .map(|workspace| workspace.id.clone())
        .collect()
}
