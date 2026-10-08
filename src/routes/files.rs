use std::collections::HashSet;

use axum::{
    body::to_bytes,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, patch, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::DateTime;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    auth::{require_drive_actor_with_credential, Actor, DriveCredential, WorkspacePermission},
    blob,
    download_subjects::{CurrentFileSubject, FileContentSubject},
    error::{ApiError, ApiResult},
    model::{
        BrowseFile, BulkFileActionRequest, BulkFileActionResponse, ContentWrite, CopyFileRequest,
        CreateFileRequest, FileKind, FileMetadata, FileMutationResponse, FileOperationResponse,
        FilePreviewResponse, FileTreeResponse, PutContentRequest, SearchResponse,
        UpdateFileRequest, MAX_BULK_FILE_ACTIONS,
    },
    routes::{
        blob_publication,
        blob_response::{
            is_initial_content_request, serve_blob_file_with_guard_after_open,
            serve_blob_file_with_overrides_and_guard_after_open, BlobResponseOverrides,
            Disposition,
        },
        content_revalidation::AuthenticatedFilePublication,
        metadata_publication::{
            revalidate_browse_metadata_publication, revalidate_file_id_metadata_publication,
            revalidate_file_metadata_publication, revalidate_search_metadata_publication,
            revalidate_workspace_metadata_publication,
        },
        metadata_response::{guarded_metadata_json, guarded_metadata_json_with_permit},
    },
    server::{request_client_fingerprint, AppState},
    storage::{FileAccessKind, FileBrowseCursor, FileBrowseScope, MAX_WORKSPACE_NAME_BYTES},
    streaming_zip::{self, MAX_ARCHIVE_SELECTIONS},
};

mod browse_filters;
mod revisions;
mod state_authorization;

use browse_filters::{validate_browse_filters, BrowseQuery};
use state_authorization::ensure_file_state_route_write;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/files", post(create_file).get(list_files))
        .route("/files/bulk", post(bulk_file_action))
        .route("/files/download-zip", post(download_bulk_zip))
        .route("/workspaces/{workspace_id}/tree", get(workspace_tree))
        .route("/files/{file_id}", patch(update_file).delete(delete_file))
        .route(
            "/workspaces/{workspace_id}/trash/empty",
            post(empty_workspace_trash),
        )
        .route(
            "/files/{file_id}/preview",
            get(get_preview).post(prepare_file_preview),
        )
        .route("/files/{file_id}/thumbnail", get(get_thumbnail))
        // Custom folder cover image (Google-Drive style). PUT accepts raw image
        // bytes; the per-route body limit raises the default so a reasonable
        // cover photo is accepted while still capping abuse.
        .route(
            "/files/{file_id}/cover",
            get(get_cover)
                .put(set_cover)
                .delete(clear_cover)
                .layer(DefaultBodyLimit::max(MAX_COVER_BYTES)),
        )
        .route(
            "/files/{file_id}/content",
            get(get_content).put(put_content),
        )
        .route(
            "/files/{file_id}/download",
            get(download_content).post(prepare_file_download),
        )
        .route("/files/{file_id}/metadata", get(get_metadata))
        .route("/files/{file_id}/copy", post(copy_file))
        .route("/files/{file_id}/download-zip", post(prepare_folder_zip))
        .route("/files/{file_id}/trash", post(trash_file))
        .route("/files/{file_id}/restore", post(restore_file))
        .route("/files/{file_id}/star", post(star_file))
        .route("/files/{file_id}/unstar", post(unstar_file))
        .route("/search", get(search_files))
        .route("/browse/files", get(browse_files))
        .route("/recent", get(recent_files))
        .route("/shared", get(shared_files))
        .route("/starred", get(starred_files))
        .route("/activity", get(activity))
        .merge(revisions::router())
}

#[derive(Deserialize)]
struct SearchQuery {
    q: Option<String>,
}

const DEFAULT_BROWSE_PAGE_LIMIT: usize = 100;
const MAX_BROWSE_PAGE_LIMIT: usize = 100;

#[derive(Serialize, Deserialize)]
struct BrowseCursorPayload {
    scope: String,
    order: String,
    id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind_rank: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    workspace_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    updated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    filters: Option<String>,
}

#[derive(Deserialize)]
struct BulkDownloadRequest {
    file_ids: Vec<String>,
}

#[derive(Serialize)]
struct PreparedDownload {
    download_url: String,
    expires_in_seconds: u64,
}

#[derive(Serialize)]
struct PreparedPreview {
    content_url: String,
    expires_in_seconds: u64,
}

async fn get_metadata(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> ApiResult<Json<FileMetadata>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let file = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    state
        .storage
        .ensure_item_response_permission(&file.id, &actor, WorkspacePermission::Read)?;
    state.storage.ensure_file_effectively_live(&file.id)?;
    let metadata = state.storage.get_file_metadata(&file_id)?;
    state.storage.ensure_item_response_publication_authorized(
        &file.id,
        &actor,
        &source_credential,
        WorkspacePermission::Read,
    )?;
    Ok(Json(metadata))
}

async fn update_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
    Json(request): Json<UpdateFileRequest>,
) -> ApiResult<Json<FileOperationResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let current = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    state.storage.ensure_item_response_permission(
        &current.id,
        &actor,
        WorkspacePermission::Write,
    )?;
    let (file, metadata, receipt) =
        state
            .storage
            .update_file_authorized(&file_id, request, &actor, &source_credential)?;
    Ok(Json(FileOperationResponse {
        file,
        metadata,
        receipt,
    }))
}

async fn create_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut request): Json<CreateFileRequest>,
) -> ApiResult<(StatusCode, Json<FileMutationResponse>)> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    // Folder upload: when a relative `path` is supplied (e.g. a browser
    // `webkitRelativePath`), materialise the intermediate folders under the
    // target parent and retarget this create at the leaf. Segment validation
    // (traversal defence) lives in `resolve_relative_upload_path`. The storage
    // transaction rechecks the resolved parent (or whole workspace for a root
    // create), so every generated folder and the final file are authorized.
    if let Some(path) = request.path.clone() {
        let path = path.trim();
        if !path.is_empty() {
            let (parent_id, leaf) = state.storage.resolve_relative_upload_path_authorized(
                &request.workspace_id,
                request.parent_id.as_deref(),
                path,
                &actor,
                &source_credential,
            )?;
            request.parent_id = parent_id;
            request.name = leaf;
        }
    }
    let index_text = if matches!(request.kind, FileKind::File) {
        request.content.clone()
    } else {
        None
    };
    let content_bytes = match (&request.kind, request.content.as_ref()) {
        (FileKind::File, Some(content)) => content.len() as i64,
        _ => 0,
    };
    if content_bytes > 0 {
        state
            .storage
            .ensure_workspace_server_content_allowed(&request.workspace_id)?;
    }
    state
        .storage
        .ensure_workspace_quota(&request.workspace_id, None, content_bytes)?;
    let (file, receipt) = blob_publication::run(&state, |publications| {
        let content_hash = match (&request.kind, &request.content) {
            (FileKind::File, Some(content)) => {
                Some(publications.put_bytes(content.as_bytes())?.hash)
            }
            _ => None,
        };
        let (file, receipt) = state.storage.create_file_with_content_bytes_authorized(
            request,
            content_hash,
            content_bytes,
            &actor,
            &source_credential,
        )?;
        if let Some(content) = index_text {
            state.storage.index_file_text(&file, &content)?;
        }
        Ok((file, receipt))
    })
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(FileMutationResponse { file, receipt }),
    ))
}

async fn copy_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
    Json(request): Json<CopyFileRequest>,
) -> ApiResult<(StatusCode, Json<FileOperationResponse>)> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let source = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    state.storage.ensure_item_response_permission(
        &source.id,
        &actor,
        WorkspacePermission::Write,
    )?;
    let _blob_lifecycle_lock = blob::acquire_shared_lifecycle_lock(state.data_dir()).await?;
    let (file, metadata, receipt) = state.storage.copy_file_authorized(
        &file_id,
        request.name,
        request.parent_id,
        &actor,
        &source_credential,
    )?;
    Ok((
        StatusCode::CREATED,
        Json(FileOperationResponse {
            file,
            metadata,
            receipt,
        }),
    ))
}

async fn put_content(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
    Json(request): Json<PutContentRequest>,
) -> ApiResult<Response> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let file = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    state
        .storage
        .ensure_item_response_permission(&file.id, &actor, WorkspacePermission::Write)?;
    if !matches!(file.kind, FileKind::File) {
        return Err(ApiError::Validation(
            "folders cannot contain file content".to_string(),
        ));
    }
    let content_bytes = request.content.len() as i64;
    state
        .storage
        .ensure_workspace_server_content_allowed(&file.workspace_id)?;
    let quota_target = if request.base_revision == file.revision {
        Some(file_id.as_str())
    } else {
        None
    };
    state
        .storage
        .ensure_workspace_quota(&file.workspace_id, quota_target, content_bytes)?;
    blob_publication::run(&state, |publications| {
        let hash = publications.put_bytes(request.content.as_bytes())?.hash;
        let write = state.storage.put_content_authorized(
            &file_id,
            request.base_revision,
            &hash,
            content_bytes,
            &actor,
            &source_credential,
        )?;
        match write {
            ContentWrite::Updated { file, receipt } => {
                state.storage.index_file_text(&file, &request.content)?;
                Ok(Json(FileMutationResponse { file, receipt }).into_response())
            }
            ContentWrite::Conflict(conflict) => {
                let conflict_file = state
                    .storage
                    .get_file(&conflict.conflict_file_id)?
                    .ok_or(ApiError::NotFound)?;
                state
                    .storage
                    .index_file_text(&conflict_file, &request.content)?;
                if let Err(error) = state.storage.notify_workspace_members(
                    &conflict_file.workspace_id,
                    &actor.email,
                    "sync_conflict",
                    "Sync conflict created",
                    &format!("A stale save created {}", conflict_file.name),
                    Some(&conflict_file.id),
                    Some("file"),
                    Some(&conflict_file.id),
                ) {
                    tracing::warn!(
                        file_id = %conflict_file.id,
                        %error,
                        "conflict notification fanout failed after durable conflict creation"
                    );
                }
                Ok((StatusCode::CONFLICT, Json(conflict)).into_response())
            }
        }
    })
    .await
}

/// `GET /files/{id}/content` — serve raw file bytes for inline rendering.
///
/// Best-effort `Content-Type` from the file extension, `Content-Disposition:
/// inline`, `Accept-Ranges: bytes`, and full `Range`/`206 Partial Content`
/// support (needed for `<video>`/`<audio>` seeking and pdf.js range fetches).
/// The existing text-editor read path still works because it reads the body.
async fn get_content(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> ApiResult<Response> {
    serve_file_content(state, headers, file_id, Disposition::Inline).await
}

/// `GET /files/{id}/download` — same bytes as `/content` but forces a browser
/// save via `Content-Disposition: attachment`.
async fn download_content(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> ApiResult<Response> {
    serve_file_content(state, headers, file_id, Disposition::Attachment).await
}

/// Authorize one native browser download without putting the file body in the
/// JavaScript heap. The returned capability is short-lived, one-use, and stores
/// only a blob path plus bounded metadata in memory.
async fn prepare_file_download(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> ApiResult<Json<PreparedDownload>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let file = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    state
        .storage
        .ensure_item_response_permission(&file.id, &actor, WorkspacePermission::Read)?;
    state.storage.ensure_file_effectively_live(&file.id)?;
    if !matches!(file.kind, FileKind::File) {
        return Err(ApiError::Validation(
            "single-file downloads require a file".to_string(),
        ));
    }
    let subject = CurrentFileSubject::from_file(&file)?;
    let path = blob::blob_file_path(&state.data_dir(), &subject.content_hash)?;
    let actual_size = tokio::fs::metadata(&path).await?.len();
    if actual_size != subject.expected_size {
        return Err(ApiError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "stored blob size does not match file metadata",
        )));
    }
    let ticket = state.file_download_tickets.issue_for_file(
        file.name,
        path,
        FileContentSubject::Current(subject),
        file.workspace_id.clone(),
        &actor.email,
        actor.clone(),
        source_credential,
    )?;
    state
        .storage
        .insert_receipt("file.download.prepare", &actor.email, Some(&file_id))?;
    Ok(Json(PreparedDownload {
        download_url: format!("/downloads/files/{ticket}"),
        expires_in_seconds: crate::download_tickets::FILE_DOWNLOAD_TICKET_TTL_SECONDS,
    }))
}

/// Shared content/download implementation. Auth: workspace `Read` on the file.
async fn serve_file_content(
    state: AppState,
    headers: HeaderMap,
    file_id: String,
    disposition: Disposition,
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
    let publication =
        AuthenticatedFilePublication::new(&state.storage, &file, &actor, &source_credential)?;
    let path = blob::blob_file_path(&state.data_dir(), publication.content_hash())?;
    let range_header = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok());
    let stream_permit = state.try_authenticated_body_stream(&actor.email)?;
    let response = serve_blob_file_with_guard_after_open(
        &file.name,
        &path,
        range_header,
        disposition,
        stream_permit,
        move || publication.revalidate(),
    )
    .await?;
    if is_initial_content_request(range_header) {
        let kind = if disposition == Disposition::Attachment {
            FileAccessKind::Download
        } else {
            FileAccessKind::Access
        };
        state
            .storage
            .record_file_access_best_effort(&file.id, &file.workspace_id, kind);
    }
    Ok(response)
}

async fn get_preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> ApiResult<Json<FilePreviewResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let file = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    state
        .storage
        .ensure_item_response_permission(&file.id, &actor, WorkspacePermission::Read)?;
    state.storage.ensure_file_effectively_live(&file.id)?;
    let preview = state
        .storage
        .get_file_preview(&file_id)?
        .ok_or(ApiError::NotFound)?;
    state.storage.ensure_item_response_publication_authorized(
        &file.id,
        &actor,
        &source_credential,
        WorkspacePermission::Read,
    )?;
    Ok(Json(FilePreviewResponse { preview }))
}

/// Issue a range-capable inline media capability for browsers authenticated by
/// a bearer header rather than a cookie. The capability is reusable only for a
/// bounded number of media range requests and expires after two minutes.
async fn prepare_file_preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> ApiResult<Json<PreparedPreview>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let file = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    state
        .storage
        .ensure_item_response_permission(&file.id, &actor, WorkspacePermission::Read)?;
    state.storage.ensure_file_effectively_live(&file.id)?;
    if !matches!(file.kind, FileKind::File) {
        return Err(ApiError::NotFound);
    }
    let subject = CurrentFileSubject::from_file(&file)?;
    let path = blob::blob_file_path(&state.data_dir(), &subject.content_hash)?;
    let actual_size = tokio::fs::metadata(&path).await?.len();
    if actual_size != subject.expected_size {
        return Err(ApiError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "stored blob size does not match file metadata",
        )));
    }
    let ticket = state.file_download_tickets.issue_preview_for_file(
        file.name,
        path,
        FileContentSubject::Current(subject),
        file.workspace_id.clone(),
        &actor.email,
        actor.clone(),
        source_credential,
    )?;
    Ok(Json(PreparedPreview {
        content_url: format!("/downloads/files/{ticket}"),
        expires_in_seconds: crate::download_tickets::FILE_DOWNLOAD_TICKET_TTL_SECONDS,
    }))
}

/// `GET /files/{id}/thumbnail` — serve the generated preview thumbnail PNG.
///
/// Auth: workspace `Read`. Returns `404` when no thumbnail has been generated.
/// Thumbnails are always PNG (see
/// `storage::generate_image_preview`), so the content type is fixed.
async fn get_thumbnail(
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
    let preview = state
        .storage
        .get_file_preview(&file_id)?
        .ok_or(ApiError::NotFound)?;
    let preview_revision = preview.revision;
    let hash = preview.thumbnail_hash.ok_or(ApiError::NotFound)?;
    let path = blob::blob_file_path(&state.data_dir(), &hash)?;
    let range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok());
    let stream_permit = state.try_authenticated_body_stream(&actor.email)?;
    let terminal_storage = state.storage.clone();
    let terminal_workspace_id = file.workspace_id.clone();
    let terminal_file_id = file.id.clone();
    let terminal_hash = hash.clone();
    serve_blob_file_with_overrides_and_guard_after_open(
        "thumbnail.png",
        &path,
        range,
        Disposition::Inline,
        Some(BlobResponseOverrides::IMAGE_CACHE),
        stream_permit,
        move || {
            terminal_storage.ensure_thumbnail_publication_authorized(
                &terminal_workspace_id,
                &terminal_file_id,
                preview_revision,
                &terminal_hash,
                &actor,
                &source_credential,
            )
        },
    )
    .await
}

/// Max accepted folder-cover image size (8 MiB). Enforced by the per-route body
/// limit on the cover route; covers are small decorative thumbnails, so this
/// only caps abuse.
const MAX_COVER_BYTES: usize = 8 * 1024 * 1024;
/// Only the signature is required to select a safe image response type. Never
/// read the stored cover's full body merely to rediscover its format.
const COVER_TYPE_PROBE_BYTES: u64 = 64;

/// Validate that `bytes` are a supported cover image and return the matching
/// content type. Uses a signature check (`image::guess_format`) that inspects
/// only the magic bytes — it never decodes the image, so it cannot be turned
/// into a decompression-bomb CPU sink. Non-images and unsupported formats map
/// to a `400`. The allowlist is intentionally narrow (PNG/JPEG/GIF/WebP)
/// because the bytes are served straight into an `<img>`.
fn cover_content_type(bytes: &[u8]) -> ApiResult<&'static str> {
    match image::guess_format(bytes) {
        Ok(image::ImageFormat::Png) => Ok("image/png"),
        Ok(image::ImageFormat::Jpeg) => Ok("image/jpeg"),
        Ok(image::ImageFormat::Gif) => Ok("image/gif"),
        Ok(image::ImageFormat::WebP) => Ok("image/webp"),
        _ => Err(ApiError::Validation(
            "cover image must be a PNG, JPEG, GIF, or WebP image".to_string(),
        )),
    }
}

/// `PUT /files/{id}/cover` — set a folder's custom cover image.
///
/// Body: raw image bytes (PNG/JPEG/GIF/WebP; validated by signature, not
/// decoded). Auth: workspace `Write`. The target must be a folder. The image
/// is stored in the content-addressed blob store; a replaced cover's blob is
/// reference-counted and reclaimed if nothing else points at it.
async fn set_cover(
    State(state): State<AppState>,
    Path(file_id): Path<String>,
    request: Request,
) -> ApiResult<Json<FileMutationResponse>> {
    let headers = request.headers().clone();
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let file = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    ensure_file_state_route_write(&state, &file, &actor)?;
    if !matches!(file.kind, FileKind::Folder) {
        return Err(ApiError::Validation(
            "cover images can only be set on folders".to_string(),
        ));
    }
    let _ingress = state.try_authenticated_upload_ingress(&actor.email)?;
    let body = to_bytes(request.into_body(), MAX_COVER_BYTES)
        .await
        .map_err(|_| {
            ApiError::PayloadTooLarge(format!(
                "folder covers must not exceed {MAX_COVER_BYTES} bytes"
            ))
        })?;
    if body.is_empty() {
        return Err(ApiError::Validation(
            "cover image body is empty".to_string(),
        ));
    }
    // Validates the bytes ARE a supported image (signature only). Rejected → 400.
    let _ = cover_content_type(&body)?;
    let (file, previous, receipt, hash) = blob_publication::run(&state, |publications| {
        let hash = publications.put_bytes(&body)?.hash;
        let (file, previous, receipt) = state.storage.set_folder_cover_authorized(
            &file_id,
            &hash,
            body.len() as i64,
            &actor,
            &source_credential,
        )?;
        Ok((file, previous, receipt, hash))
    })
    .await?;
    // Reclaim the replaced cover's blob if nothing else references it.
    if let Some(previous) = previous {
        if previous != hash {
            prune_unreferenced_blobs(&state, vec![previous]).await?;
        }
    }
    Ok(Json(FileMutationResponse { file, receipt }))
}

/// `GET /files/{id}/cover` — serve a folder's custom cover image.
///
/// Auth: workspace `Read`. Returns the stored image bytes with their detected
/// content type (`image/png|jpeg|gif|webp`), a private `Cache-Control`, and
/// `nosniff`. Returns `404` when the folder has no cover.
async fn get_cover(
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
    let hash = state
        .storage
        .folder_cover_hash(&file_id)?
        .ok_or(ApiError::NotFound)?;
    let prefix = blob::get_blob_prefix(&state.data_dir(), &hash, COVER_TYPE_PROBE_BYTES)?;
    // Re-derive the type from the stored bytes so the served type always
    // matches the actual content (single source of truth).
    let content_type = cover_content_type(&prefix)?;
    let path = blob::blob_file_path(&state.data_dir(), &hash)?;
    let range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok());
    let stream_permit = state.try_authenticated_body_stream(&actor.email)?;
    let terminal_storage = state.storage.clone();
    let terminal_workspace_id = file.workspace_id.clone();
    let terminal_file_id = file.id.clone();
    let terminal_hash = hash.clone();
    serve_blob_file_with_overrides_and_guard_after_open(
        "cover",
        &path,
        range,
        Disposition::Inline,
        Some(BlobResponseOverrides {
            content_type,
            cache_control: "private, no-store",
        }),
        stream_permit,
        move || {
            terminal_storage.ensure_cover_publication_authorized(
                &terminal_workspace_id,
                &terminal_file_id,
                &terminal_hash,
                &actor,
                &source_credential,
            )
        },
    )
    .await
}

/// `DELETE /files/{id}/cover` — remove a folder's cover image.
///
/// Auth: workspace `Write`. Unsets `cover_hash` and reference-counts the blob,
/// reclaiming it if now unreferenced. Idempotent — clearing an already-coverless
/// folder is a no-op success.
async fn clear_cover(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> ApiResult<Json<FileMutationResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let file = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    ensure_file_state_route_write(&state, &file, &actor)?;
    if !matches!(file.kind, FileKind::Folder) {
        return Err(ApiError::Validation(
            "cover images can only be set on folders".to_string(),
        ));
    }
    let _blob_lifecycle_lock = blob::acquire_exclusive_lifecycle_lock(state.data_dir()).await?;
    let (file, previous, receipt) =
        state
            .storage
            .clear_folder_cover_authorized(&file_id, &actor, &source_credential)?;
    if let Some(previous) = previous {
        prune_unreferenced_blobs_locked(&state, vec![previous])?;
    }
    Ok(Json(FileMutationResponse { file, receipt }))
}

async fn trash_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> ApiResult<Json<FileMutationResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let current = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    ensure_file_state_route_write(&state, &current, &actor)?;
    let (file, receipt) =
        state
            .storage
            .set_trashed_authorized(&file_id, true, &actor, &source_credential)?;
    Ok(Json(FileMutationResponse { file, receipt }))
}

async fn restore_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> ApiResult<Json<FileMutationResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let current = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    ensure_file_state_route_write(&state, &current, &actor)?;
    let (file, receipt) =
        state
            .storage
            .set_trashed_authorized(&file_id, false, &actor, &source_credential)?;
    Ok(Json(FileMutationResponse { file, receipt }))
}

/// `DELETE /files/{id}` — permanently delete a file (or folder, recursively).
///
/// Auth: workspace `Write` (Editor/Owner). Removes the file rows and every
/// revision, then reclaims each backing blob with reference-counted cleanup so
/// a hash still referenced by another file/revision/thumbnail is preserved.
/// Returns `204 No Content`.
async fn delete_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> ApiResult<Response> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let current = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    ensure_file_state_route_write(&state, &current, &actor)?;
    let _blob_lifecycle_lock = blob::acquire_exclusive_lifecycle_lock(state.data_dir()).await?;
    let (candidate_hashes, _) =
        state
            .storage
            .permanently_delete_file_authorized(&file_id, &actor, &source_credential)?;
    prune_unreferenced_blobs_locked(&state, candidate_hashes)?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// `POST /workspaces/{id}/trash/empty` — permanently delete only trashed
/// subtrees past the workspace retention cutoff (Editor/Owner), with the same
/// reference-counted blob cleanup. The response names retained root items.
async fn empty_workspace_trash(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    state
        .storage
        .ensure_workspace_permission(&workspace_id, &actor, WorkspacePermission::Write)?;
    let _blob_lifecycle_lock = blob::acquire_exclusive_lifecycle_lock(state.data_dir()).await?;
    let (result, _) =
        state
            .storage
            .empty_workspace_trash(&workspace_id, &actor, &source_credential)?;
    let deleted = result.deleted;
    let retained_count = result.retained.len();
    let retained_items = result.retained;
    prune_unreferenced_blobs_locked(&state, result.candidate_hashes)?;
    Ok(Json(serde_json::json!({
        "deleted": deleted,
        "retained": retained_count,
        "retained_items": retained_items,
    })))
}

/// Remove any of `hashes` whose bytes are no longer referenced by a file,
/// revision, or thumbnail row, acquiring exclusive lifecycle ownership for
/// callers that have already completed their database mutation.
async fn prune_unreferenced_blobs(state: &AppState, hashes: Vec<String>) -> ApiResult<()> {
    let _blob_lifecycle_lock = blob::acquire_exclusive_lifecycle_lock(state.data_dir()).await?;
    prune_unreferenced_blobs_locked(state, hashes)
}

/// Remove any of `hashes` whose bytes are no longer referenced by a file,
/// revision, or thumbnail row. The caller must retain the exclusive lifecycle
/// lock from the database deletion through this check-and-unlink sequence.
fn prune_unreferenced_blobs_locked(state: &AppState, hashes: Vec<String>) -> ApiResult<()> {
    let unique: HashSet<String> = hashes.into_iter().collect();
    for hash in unique {
        if !state.storage.content_hash_is_referenced(&hash)? {
            blob::remove_blob(&state.data_dir(), &hash)?;
        }
    }
    Ok(())
}

async fn list_files(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let planning_actor = actor.clone();
    let storage = state.storage.clone();
    let mut files = state
        .run_metadata_planning(&actor.email, move || {
            storage.list_files_for_actor_bounded(
                &planning_actor,
                crate::storage::MAX_COMPATIBILITY_FILE_LIST,
                true,
            )
        })
        .await?;
    append_shared_item_roots(
        &state,
        &actor,
        &mut files,
        crate::storage::MAX_COMPATIBILITY_FILE_LIST,
    )?;
    revalidate_file_metadata_publication(&state.storage, &files, &actor, &source_credential)?;
    guarded_metadata_json(
        &state,
        &actor.email,
        &actor.email,
        || serde_json::json!({ "files": files }),
    )
}

async fn star_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> ApiResult<Json<FileMutationResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let current = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    ensure_file_state_route_write(&state, &current, &actor)?;
    let (file, receipt) =
        state
            .storage
            .set_starred_authorized(&file_id, true, &actor, &source_credential)?;
    Ok(Json(FileMutationResponse { file, receipt }))
}

async fn unstar_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> ApiResult<Json<FileMutationResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let current = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    ensure_file_state_route_write(&state, &current, &actor)?;
    let (file, receipt) =
        state
            .storage
            .set_starred_authorized(&file_id, false, &actor, &source_credential)?;
    Ok(Json(FileMutationResponse { file, receipt }))
}

async fn search_files(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SearchQuery>,
) -> ApiResult<Json<SearchResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let term = query.q.unwrap_or_default();
    let _planning = state.try_metadata_planning(&format!("search:{}", actor.email))?;
    let (results, has_more) = state
        .storage
        .search_file_results_for_actor_page(&actor, &term)?;
    let files = results
        .iter()
        .map(|result| result.file.clone())
        .collect::<Vec<_>>();
    revalidate_search_metadata_publication(&state.storage, &results, &actor, &source_credential)?;
    Ok(Json(SearchResponse {
        query: term,
        files,
        results,
        has_more,
    }))
}

/// Account-wide browser data. Location-oriented scopes return workspace-root
/// items so folders remain folders instead of duplicating every descendant in
/// one flat page. Recent remains an intentional cross-folder activity list.
/// This sits beside, rather than changes, `/sync/workspaces/{id}/manifest`:
/// sync stays one bounded local workspace contract while the browser can page
/// across every workspace the actor is already authorized to read.
async fn browse_files(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<BrowseQuery>,
) -> ApiResult<Response> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let scope = match query.scope.as_deref().unwrap_or("files") {
        "files" => FileBrowseScope::Files,
        "mine" => FileBrowseScope::Mine,
        "shared" => FileBrowseScope::SharedWithMe,
        "recent" => FileBrowseScope::Recent,
        _ => {
            return Err(ApiError::Validation(
                "browse scope must be files, mine, shared, or recent".to_string(),
            ))
        }
    };
    let limit = match query.limit {
        None => DEFAULT_BROWSE_PAGE_LIMIT,
        Some(limit) if (1..=MAX_BROWSE_PAGE_LIMIT).contains(&limit) => limit,
        Some(_) => {
            return Err(ApiError::Validation(format!(
                "browse limit must be a whole number from 1 to {MAX_BROWSE_PAGE_LIMIT}"
            )))
        }
    };
    let filters = validate_browse_filters(&query)?;
    let filter_key = serde_json::json!([
        filters.type_filter,
        filters.owner_scope,
        filters.modified_since,
        filters.workspace_id,
        filters.folder_id,
        filters.state_filter
    ])
    .to_string();
    let cursor = parse_browse_cursor(query.cursor.as_deref(), scope, &filter_key)?;
    let append_roots = cursor.is_none() && filter_key == "[null,null,null,null,null,null]";
    let planning_storage = state.storage.clone();
    let planning_actor = actor.clone();
    let ((files, next_cursor), planning_permit) = state
        .run_metadata_planning_retained(&actor.email, move || {
            let (mut files, next_cursor) = planning_storage.browse_files_for_actor(
                &planning_actor,
                scope,
                cursor.as_ref(),
                limit,
                &filters,
            )?;
            if append_roots && files.len() < limit {
                let roots = planning_storage
                    .list_shared_item_roots_for_actor(&planning_actor, limit - files.len())?;
                for root in roots {
                    if !matches!(scope, FileBrowseScope::Mine)
                        && !files.iter().any(|file| file.file.id == root.file.id)
                    {
                        files.push(BrowseFile {
                            file: root.file,
                            workspace_name: root.owner_label,
                            access_role: root.role,
                            owned_by_actor: false,
                        });
                    }
                }
            }
            Ok((files, next_cursor))
        })
        .await?;
    guarded_metadata_json_with_permit(
        &state,
        &actor.email,
        planning_permit,
        || {
            serde_json::json!({
                "scope": scope.as_str(),
                "files": files,
                "next_cursor": next_cursor.map(|cursor| encode_browse_cursor(scope, cursor, &filter_key)),
            })
        },
        || {
            revalidate_browse_metadata_publication(
                &state.storage,
                &files,
                &actor,
                &source_credential,
            )
        },
    )
}

fn parse_browse_cursor(
    raw_cursor: Option<&str>,
    scope: FileBrowseScope,
    filter_key: &str,
) -> ApiResult<Option<FileBrowseCursor>> {
    let Some(raw_cursor) = raw_cursor else {
        return Ok(None);
    };
    // A 255-byte workspace label can expand sixfold through JSON escaping;
    // leave bounded room for the file name and the selected filter identity.
    if raw_cursor.is_empty() || raw_cursor.len() > 4096 {
        return Err(ApiError::Validation("browse cursor is invalid".to_string()));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(raw_cursor)
        .map_err(|_| ApiError::Validation("browse cursor is invalid".to_string()))?;
    let payload: BrowseCursorPayload = serde_json::from_slice(&bytes)
        .map_err(|_| ApiError::Validation("browse cursor is invalid".to_string()))?;
    if payload.scope != scope.as_str()
        || payload.order != scope.cursor_order()
        || payload
            .filters
            .as_deref()
            .unwrap_or("[null,null,null,null,null,null]")
            != filter_key
    {
        return Err(ApiError::Validation(
            "browse cursor does not match the selected scope".to_string(),
        ));
    }
    let id = Uuid::parse_str(&payload.id)
        .map_err(|_| ApiError::Validation("browse cursor is invalid".to_string()))?;
    if id.hyphenated().to_string() != payload.id {
        return Err(ApiError::Validation("browse cursor is invalid".to_string()));
    }
    let cursor = if scope.uses_recent_order() {
        let updated_at = payload
            .updated_at
            .filter(|value| DateTime::parse_from_rfc3339(value).is_ok())
            .ok_or_else(|| ApiError::Validation("browse cursor is invalid".to_string()))?;
        if payload.kind_rank.is_some() || payload.name.is_some() || payload.workspace_name.is_some()
        {
            return Err(ApiError::Validation("browse cursor is invalid".to_string()));
        }
        FileBrowseCursor::Recent {
            updated_at,
            id: payload.id,
        }
    } else {
        let kind_rank = payload
            .kind_rank
            .filter(|value| matches!(*value, 0 | 1))
            .ok_or_else(|| ApiError::Validation("browse cursor is invalid".to_string()))?;
        let name = bounded_cursor_text(payload.name)?;
        let workspace_name = bounded_cursor_text(payload.workspace_name)?;
        if workspace_name.len() > MAX_WORKSPACE_NAME_BYTES {
            return Err(ApiError::Validation("browse cursor is invalid".to_string()));
        }
        if payload.updated_at.is_some() {
            return Err(ApiError::Validation("browse cursor is invalid".to_string()));
        }
        FileBrowseCursor::Name {
            kind_rank,
            name,
            workspace_name,
            id: payload.id,
        }
    };
    Ok(Some(cursor))
}

fn bounded_cursor_text(value: Option<String>) -> ApiResult<String> {
    let value =
        value.ok_or_else(|| ApiError::Validation("browse cursor is invalid".to_string()))?;
    if value.is_empty() || value.len() > 512 {
        return Err(ApiError::Validation("browse cursor is invalid".to_string()));
    }
    Ok(value)
}

fn encode_browse_cursor(
    scope: FileBrowseScope,
    cursor: FileBrowseCursor,
    filter_key: &str,
) -> String {
    let payload = match cursor {
        FileBrowseCursor::Name {
            kind_rank,
            name,
            workspace_name,
            id,
        } if !scope.uses_recent_order() => BrowseCursorPayload {
            scope: scope.as_str().to_string(),
            order: scope.cursor_order().to_string(),
            id,
            kind_rank: Some(kind_rank),
            name: Some(name),
            workspace_name: Some(workspace_name),
            updated_at: None,
            filters: Some(filter_key.to_string()),
        },
        FileBrowseCursor::Recent { updated_at, id } if scope.uses_recent_order() => {
            BrowseCursorPayload {
                scope: scope.as_str().to_string(),
                order: scope.cursor_order().to_string(),
                id,
                kind_rank: None,
                name: None,
                workspace_name: None,
                updated_at: Some(updated_at),
                filters: Some(filter_key.to_string()),
            }
        }
        _ => unreachable!("storage returns a cursor compatible with its browse scope"),
    };
    // Serializing this small in-memory payload is infallible for the concrete
    // fields above; keeping the invariant explicit avoids emitting a malformed
    // cursor that could make a later page appear empty.
    let bytes = serde_json::to_vec(&payload).expect("browse cursor payload serializes");
    URL_SAFE_NO_PAD.encode(bytes)
}

async fn recent_files(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let mut files = state.storage.recent_files_for_actor(&actor)?;
    append_shared_item_roots(
        &state,
        &actor,
        &mut files,
        crate::storage::MAX_COMPATIBILITY_FILE_LIST,
    )?;
    revalidate_file_metadata_publication(&state.storage, &files, &actor, &source_credential)?;
    Ok(Json(serde_json::json!({
        "files": files
    })))
}

async fn starred_files(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let mut files = state.storage.starred_files_for_actor(&actor)?;
    append_shared_item_roots(
        &state,
        &actor,
        &mut files,
        crate::storage::MAX_COMPATIBILITY_FILE_LIST,
    )?;
    files.retain(|file| file.starred);
    revalidate_file_metadata_publication(&state.storage, &files, &actor, &source_credential)?;
    Ok(Json(serde_json::json!({
        "files": files
    })))
}

async fn shared_files(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let mut files = state.storage.shared_files_for_actor(&actor)?;
    append_shared_item_roots(
        &state,
        &actor,
        &mut files,
        crate::storage::MAX_COMPATIBILITY_FILE_LIST,
    )?;
    revalidate_file_metadata_publication(&state.storage, &files, &actor, &source_credential)?;
    Ok(Json(serde_json::json!({
        "files": files
    })))
}

pub(super) fn append_shared_item_roots(
    state: &AppState,
    actor: &Actor,
    files: &mut Vec<crate::model::DriveFile>,
    max_rows: usize,
) -> ApiResult<()> {
    // Check shared roots even when workspace rows exactly fill the response.
    // Otherwise an item-only share disappears without an overflow error.
    let roots = state
        .storage
        .list_shared_item_roots_for_actor(actor, max_rows)?;
    for root in roots {
        if !files.iter().any(|file| file.id == root.file.id) {
            if files.len() >= max_rows {
                return Err(ApiError::PayloadTooLarge(format!(
                    "file listing exceeds the {max_rows}-item compatibility limit; use the paginated browser API"
                )));
            }
            files.push(root.file);
        }
    }
    Ok(())
}

/// `GET /activity` — recent activity feed scoped to the caller's visible
/// workspaces. A non-admin only sees events whose target resolves to a file in
/// (or the id of) a workspace they belong to; admins see the system-wide feed.
async fn activity(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let (activity, subjects) = state
        .storage
        .list_activity_for_actor_with_workspace_subjects(&actor)?;
    revalidate_workspace_metadata_publication(
        &state.storage,
        &subjects.workspace_ids,
        &actor,
        &source_credential,
    )?;
    revalidate_file_id_metadata_publication(
        &state.storage,
        &subjects.file_ids,
        &actor,
        &source_credential,
    )?;
    Ok(Json(serde_json::json!({
        "activity": activity
    })))
}

async fn workspace_tree(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> ApiResult<Json<FileTreeResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    state
        .storage
        .ensure_workspace_permission(&workspace_id, &actor, WorkspacePermission::Read)?;
    let planning_workspace_id = workspace_id.clone();
    let storage = state.storage.clone();
    let tree = state
        .run_metadata_planning(&actor.email, move || {
            storage.file_tree(&planning_workspace_id)
        })
        .await?;
    revalidate_workspace_metadata_publication(
        &state.storage,
        &[workspace_id],
        &actor,
        &source_credential,
    )?;
    Ok(Json(tree))
}

async fn bulk_file_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<BulkFileActionRequest>,
) -> ApiResult<Json<BulkFileActionResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    match request.action.as_str() {
        "trash" | "restore" | "star" | "unstar" => {}
        _ => {
            return Err(ApiError::Validation(
                "action must be trash, restore, star, or unstar".to_string(),
            ))
        }
    };
    if request.file_ids.is_empty() {
        return Err(ApiError::Validation("file_ids cannot be empty".to_string()));
    }
    if request.file_ids.len() > MAX_BULK_FILE_ACTIONS {
        return Err(ApiError::PayloadTooLarge(format!(
            "select no more than {MAX_BULK_FILE_ACTIONS} items at once"
        )));
    }
    if request.file_ids.iter().collect::<HashSet<_>>().len() != request.file_ids.len() {
        return Err(ApiError::Validation(
            "file_ids must not contain duplicates".to_string(),
        ));
    }
    for file_id in &request.file_ids {
        let file = state.storage.get_file(file_id)?.ok_or(ApiError::NotFound)?;
        ensure_file_state_route_write(&state, &file, &actor)?;
    }
    Ok(Json(state.storage.bulk_file_action_authorized(
        request,
        &actor,
        &source_credential,
    )?))
}

/// Create one bounded, ZIP64-capable archive from the current folder's
/// selected rows. Selected folders expand recursively and the response streams
/// immutable blobs without buffering the archive in process memory.
async fn download_bulk_zip(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<BulkDownloadRequest>,
) -> ApiResult<Json<PreparedDownload>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    Ok(Json(
        issue_archive_download(
            &state,
            &actor,
            &source_credential,
            &request.file_ids,
            "file.bulk.zip",
            request_client_fingerprint(&headers),
        )
        .await?,
    ))
}

async fn issue_archive_download(
    state: &AppState,
    actor: &Actor,
    source_credential: &DriveCredential,
    file_ids: &[String],
    receipt_kind: &str,
    client_fingerprint: &str,
) -> ApiResult<PreparedDownload> {
    if file_ids.is_empty() {
        return Err(ApiError::Validation(
            "select at least one item to download".to_string(),
        ));
    }
    if file_ids.len() > MAX_ARCHIVE_SELECTIONS {
        return Err(ApiError::PayloadTooLarge(format!(
            "select no more than {MAX_ARCHIVE_SELECTIONS} items at once"
        )));
    }
    let mut single_name = None;
    let mut selection_workspace = None;
    for file_id in file_ids {
        let file = state.storage.get_file(file_id)?.ok_or(ApiError::NotFound)?;
        state.storage.ensure_item_response_permission(
            &file.id,
            actor,
            WorkspacePermission::Read,
        )?;
        if state.storage.file_is_effectively_trashed(&file.id)? {
            return Err(ApiError::NotFound);
        }
        if selection_workspace
            .as_ref()
            .is_some_and(|current| current != &file.workspace_id)
        {
            return Err(ApiError::Validation(
                "download selections must come from one workspace".to_string(),
            ));
        }
        selection_workspace = Some(file.workspace_id.clone());
        if file_ids.len() == 1 {
            single_name = Some(file.name.clone());
        }
    }
    let workspace_id = selection_workspace.ok_or(ApiError::NotFound)?;
    let _planning_permit = state
        .archive_tickets
        .try_acquire_planner_for_actor(&actor.email, &workspace_id)?;

    let nodes = state.storage.bulk_archive_nodes(file_ids)?;
    let source_file_ids = nodes.iter().map(|(_, file)| file.id.clone()).collect();
    let mut entries = streaming_zip::entries_from_nodes(&state.data_dir(), nodes)?;
    streaming_zip::validate_entries(&mut entries).await?;
    let download_name = single_name
        .map(|name| format!("{name}-selection"))
        .unwrap_or_else(|| "shellx-drive-selection".to_string());
    let ticket = state.archive_tickets.issue_for_actor(
        entries,
        download_name,
        streaming_zip::AuthenticatedArchiveSource {
            actor: actor.clone(),
            source_credential: source_credential.clone(),
            workspace_id,
            source_file_ids,
        },
        client_fingerprint.to_string(),
    )?;
    state.storage.insert_receipt(
        receipt_kind,
        &actor.email,
        file_ids.first().map(String::as_str),
    )?;
    Ok(PreparedDownload {
        download_url: format!("/downloads/{ticket}"),
        expires_in_seconds: streaming_zip::DOWNLOAD_TICKET_TTL_SECONDS,
    })
}

async fn prepare_folder_zip(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> ApiResult<Json<PreparedDownload>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let folder = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    state
        .storage
        .ensure_item_response_permission(&folder.id, &actor, WorkspacePermission::Read)?;
    if state.storage.file_is_effectively_trashed(&folder.id)? {
        return Err(ApiError::NotFound);
    }
    if !matches!(folder.kind, FileKind::Folder) {
        return Err(ApiError::Validation(
            "folder ZIP downloads require a folder".to_string(),
        ));
    }
    Ok(Json(
        issue_archive_download(
            &state,
            &actor,
            &source_credential,
            &[file_id],
            "file.folder.zip",
            request_client_fingerprint(&headers),
        )
        .await?,
    ))
}
