use axum::{
    extract::{Path, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;

use crate::{
    auth::{require_drive_actor_with_credential, WorkspacePermission},
    blob,
    download_subjects::{FileContentSubject, RevisionSubject},
    error::{ApiError, ApiResult},
    model::{
        FileMutationResponse, FileRevision, FileRevisionMutationResponse,
        FileRevisionPruneResponse, FileRevisionsResponse, RevisionStorageSummary,
    },
    server::AppState,
};

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/files/{file_id}/revisions", get(list_revisions))
        .route("/files/{file_id}/revisions/prune", post(prune_revisions))
        .route(
            "/files/{file_id}/revisions/{revision}",
            axum::routing::delete(delete_revision),
        )
        .route(
            "/files/{file_id}/revisions/{revision}/download",
            post(prepare_revision_download),
        )
        .route(
            "/files/{file_id}/revisions/{revision}/restore",
            post(restore_revision),
        )
        .route(
            "/files/{file_id}/revisions/{revision}/pin",
            post(pin_revision),
        )
        .route(
            "/files/{file_id}/revisions/{revision}/unpin",
            post(unpin_revision),
        )
}

#[derive(Serialize)]
struct PreparedDownload {
    download_url: String,
    expires_in_seconds: u64,
}

async fn list_revisions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> ApiResult<Json<FileRevisionsResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let file = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    state
        .storage
        .ensure_item_response_permission(&file.id, &actor, WorkspacePermission::Read)?;
    if state.storage.file_is_effectively_trashed(&file.id)? {
        return Err(ApiError::NotFound);
    }
    let revisions = state.storage.list_file_revisions(&file_id)?;
    state.storage.ensure_item_response_publication_authorized(
        &file.id,
        &actor,
        &source_credential,
        WorkspacePermission::Read,
    )?;
    Ok(Json(FileRevisionsResponse {
        storage: revision_storage_summary(&revisions),
        revisions,
    }))
}

async fn restore_revision(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((file_id, revision)): Path<(String, i64)>,
) -> ApiResult<Json<FileMutationResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let file = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    state
        .storage
        .ensure_item_response_permission(&file.id, &actor, WorkspacePermission::Write)?;
    let _blob_lifecycle_lock = blob::acquire_shared_lifecycle_lock(state.data_dir()).await?;
    let (file, receipt) = state.storage.restore_file_revision_authorized(
        &file_id,
        revision,
        &actor,
        &source_credential,
    )?;
    Ok(Json(FileMutationResponse { file, receipt }))
}

async fn pin_revision(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((file_id, revision)): Path<(String, i64)>,
) -> ApiResult<Json<FileRevisionMutationResponse>> {
    mutate_revision_pin(state, headers, file_id, revision, true).await
}

async fn unpin_revision(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((file_id, revision)): Path<(String, i64)>,
) -> ApiResult<Json<FileRevisionMutationResponse>> {
    mutate_revision_pin(state, headers, file_id, revision, false).await
}

async fn mutate_revision_pin(
    state: AppState,
    headers: HeaderMap,
    file_id: String,
    revision: i64,
    pinned: bool,
) -> ApiResult<Json<FileRevisionMutationResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let file = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    state
        .storage
        .ensure_item_response_permission(&file.id, &actor, WorkspacePermission::Manage)?;
    let (revisions, receipt) = state.storage.set_revision_pinned_authorized(
        &file_id,
        revision,
        pinned,
        &actor,
        &source_credential,
    )?;
    Ok(Json(FileRevisionMutationResponse {
        storage: revision_storage_summary(&revisions),
        revisions,
        receipt,
    }))
}

async fn prepare_revision_download(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((file_id, revision)): Path<(String, i64)>,
) -> ApiResult<Json<PreparedDownload>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let file = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    state
        .storage
        .ensure_item_response_permission(&file.id, &actor, WorkspacePermission::Read)?;
    if state.storage.file_is_effectively_trashed(&file.id)? {
        return Err(ApiError::NotFound);
    }
    state
        .storage
        .ensure_workspace_server_content_allowed(&file.workspace_id)?;
    let stored = state
        .storage
        .list_file_revisions(&file_id)?
        .into_iter()
        .find(|candidate| candidate.revision == revision)
        .ok_or(ApiError::NotFound)?;
    let hash = state
        .storage
        .file_revision_content_hash(&file_id, revision)?
        .ok_or_else(|| ApiError::Validation("revision has no downloadable content".to_string()))?;
    let expected_size = u64::try_from(stored.content_bytes)
        .map_err(|_| ApiError::Validation("revision has an invalid stored size".to_string()))?;
    let path = blob::blob_file_path(&state.data_dir(), &hash)?;
    if tokio::fs::metadata(&path).await?.len() != expected_size {
        return Err(ApiError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "stored revision blob size does not match metadata",
        )));
    }
    let ticket = state.file_download_tickets.issue_for_file(
        file.name,
        path,
        FileContentSubject::Revision(RevisionSubject {
            file_id: file.id.clone(),
            revision,
            content_hash: hash,
            expected_size,
        }),
        file.workspace_id.clone(),
        &actor.email,
        actor.clone(),
        source_credential,
    )?;
    state.storage.insert_receipt(
        "file.revision.download.prepare",
        &actor.email,
        Some(&file_id),
    )?;
    Ok(Json(PreparedDownload {
        download_url: format!("/downloads/files/{ticket}"),
        expires_in_seconds: crate::download_tickets::FILE_DOWNLOAD_TICKET_TTL_SECONDS,
    }))
}

async fn delete_revision(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((file_id, revision)): Path<(String, i64)>,
) -> ApiResult<Json<FileRevisionMutationResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let file = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    state
        .storage
        .ensure_item_response_permission(&file.id, &actor, WorkspacePermission::Write)?;
    let _blob_lifecycle_lock = blob::acquire_exclusive_lifecycle_lock(state.data_dir()).await?;
    let (revisions, candidate_hashes, receipt) = state.storage.delete_file_revision_authorized(
        &file_id,
        revision,
        &actor,
        &source_credential,
    )?;
    super::prune_unreferenced_blobs_locked(&state, candidate_hashes)?;
    Ok(Json(FileRevisionMutationResponse {
        storage: revision_storage_summary(&revisions),
        revisions,
        receipt,
    }))
}

async fn prune_revisions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> ApiResult<Json<FileRevisionPruneResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let file = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    state
        .storage
        .ensure_item_response_permission(&file.id, &actor, WorkspacePermission::Manage)?;
    let _blob_lifecycle_lock = blob::acquire_exclusive_lifecycle_lock(state.data_dir()).await?;
    let result =
        state
            .storage
            .prune_file_revisions_authorized(&file_id, &actor, &source_credential)?;
    super::prune_unreferenced_blobs_locked(&state, result.candidate_hashes)?;
    Ok(Json(FileRevisionPruneResponse {
        deleted_revisions: result.deleted_revisions,
        deleted_content_bytes: result.deleted_content_bytes,
        storage: revision_storage_summary(&result.revisions),
        revisions: result.revisions,
        receipt: result.receipt,
    }))
}

fn revision_storage_summary(revisions: &[FileRevision]) -> RevisionStorageSummary {
    RevisionStorageSummary {
        revision_count: revisions.len(),
        content_bytes: revisions.iter().fold(0_i64, |total, revision| {
            total.saturating_add(revision.content_bytes)
        }),
        reclaimable_content_bytes: revisions
            .iter()
            .filter(|revision| !revision.current && !revision.pinned)
            .fold(0_i64, |total, revision| {
                total.saturating_add(revision.content_bytes)
            }),
    }
}
