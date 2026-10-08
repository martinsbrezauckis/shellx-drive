use axum::{
    extract::{Path, Query, RawQuery, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::{
    auth::{require_drive_actor_with_credential, WorkspacePermission},
    blob,
    error::{ApiError, ApiResult},
    model::{CreateFileRequest, DriveFile, FileKind},
    routes::{
        blob_publication,
        blob_response::{serve_blob_file_with_guard_after_open, Disposition},
        content_revalidation::AuthenticatedFilePublication,
        files::append_shared_item_roots,
        metadata_publication::revalidate_file_metadata_publication,
        metadata_response::guarded_metadata_json,
    },
    server::AppState,
    storage::FileAccessKind,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/drive/v3/files", get(list_files).post(create_file))
        .route("/drive/v3/files/{file_id}", get(get_file))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DriveGetQuery {
    alt: Option<String>,
}

#[derive(Deserialize)]
struct DriveCreateRequest {
    workspace_id: String,
    name: String,
    #[serde(default)]
    mime_type: Option<String>,
    #[serde(default, rename = "mimeType")]
    mime_type_camel: Option<String>,
    #[serde(default)]
    content: Option<String>,
}

#[derive(Serialize)]
struct DriveFilesResponse {
    files: Vec<DriveFileMetadata>,
}

#[derive(Serialize)]
struct DriveFileMetadata {
    id: String,
    name: String,
    #[serde(rename = "mimeType")]
    mime_type: String,
    trashed: bool,
    starred: bool,
    #[serde(rename = "modifiedTime")]
    modified_time: String,
    #[serde(rename = "createdTime")]
    created_time: String,
    parents: Vec<String>,
}

async fn list_files(
    State(state): State<AppState>,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> ApiResult<Response> {
    if query.as_deref().is_some_and(|query| !query.is_empty()) {
        return Err(ApiError::Validation(
            "Google-compatible file listing does not support query parameters".to_string(),
        ));
    }
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let planning_actor = actor.clone();
    let storage = state.storage.clone();
    let mut files = state
        .run_metadata_planning(&actor.email, move || {
            storage.list_files_for_actor_bounded(
                &planning_actor,
                crate::storage::MAX_COMPATIBILITY_FILE_LIST,
                false,
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
    guarded_metadata_json(&state, &actor.email, &actor.email, || DriveFilesResponse {
        files: files.into_iter().map(|file| metadata(&file)).collect(),
    })
}

async fn create_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<DriveCreateRequest>,
) -> ApiResult<(StatusCode, Json<DriveFileMetadata>)> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    state.storage.ensure_workspace_permission(
        &request.workspace_id,
        &actor,
        WorkspacePermission::Write,
    )?;

    let content_bytes = request
        .content
        .as_ref()
        .map(|content| content.len() as i64)
        .unwrap_or(0);
    if content_bytes > 0 {
        state
            .storage
            .ensure_workspace_server_content_allowed(&request.workspace_id)?;
    }
    state
        .storage
        .ensure_workspace_quota(&request.workspace_id, None, content_bytes)?;
    // Accept the Google-shaped request fields, but do not imply they are
    // stored: this adapter reports the stable name-derived MIME on every
    // response instead.
    let _requested_mime_type = request
        .mime_type_camel
        .as_deref()
        .or(request.mime_type.as_deref());
    let index_text = request.content.clone();
    let file = blob_publication::run(&state, |publications| {
        let content_hash = match request.content.as_ref() {
            Some(content) => Some(publications.put_bytes(content.as_bytes())?.hash),
            None => None,
        };
        let (file, _) = state.storage.create_file_with_content_bytes_authorized(
            CreateFileRequest {
                workspace_id: request.workspace_id,
                parent_id: None,
                name: request.name,
                kind: FileKind::File,
                content: None,
                path: None,
            },
            content_hash,
            content_bytes,
            &actor,
            &source_credential,
        )?;
        if let Some(content) = index_text {
            state.storage.index_file_text(&file, &content)?;
        }
        Ok(file)
    })
    .await?;

    Ok((
        StatusCode::CREATED,
        // The compatibility adapter does not persist caller-supplied MIME
        // metadata, so returning it here would claim a round-trip guarantee
        // the subsequent list/get routes cannot provide.
        Json(metadata(&file)),
    ))
}

async fn get_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
    Query(query): Query<DriveGetQuery>,
) -> ApiResult<Response> {
    if query.alt.as_deref().is_some_and(|alt| alt != "media") {
        return Err(ApiError::Validation(
            "Google-compatible file metadata supports only alt=media".to_string(),
        ));
    }
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let file = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    state
        .storage
        .ensure_item_response_permission(&file.id, &actor, WorkspacePermission::Read)?;
    state.storage.ensure_file_effectively_live(&file.id)?;

    if query.alt.as_deref() == Some("media") {
        if !matches!(file.kind, FileKind::File) {
            return Err(ApiError::NotFound);
        }
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
        return serve_blob_file_with_guard_after_open(
            &file.name,
            &path,
            range,
            Disposition::Attachment,
            stream_permit,
            move || publication.revalidate(),
        )
        .await;
    }

    revalidate_file_metadata_publication(
        &state.storage,
        std::slice::from_ref(&file),
        &actor,
        &source_credential,
    )?;
    Ok((StatusCode::OK, Json(metadata(&file))).into_response())
}

fn metadata(file: &DriveFile) -> DriveFileMetadata {
    metadata_with_mime(file, mime_type_for(file).to_string())
}

fn metadata_with_mime(file: &DriveFile, mime_type: String) -> DriveFileMetadata {
    DriveFileMetadata {
        id: file.id.clone(),
        name: file.name.clone(),
        mime_type,
        trashed: file.trashed,
        starred: file.starred,
        modified_time: file.updated_at.clone(),
        created_time: file.created_at.clone(),
        parents: file.parent_id.clone().into_iter().collect(),
    }
}

fn mime_type_for(file: &DriveFile) -> &'static str {
    match file.kind {
        FileKind::Folder => "application/vnd.google-apps.folder",
        FileKind::File => file
            .name
            .rsplit_once('.')
            .map(|(_, extension)| extension.to_ascii_lowercase())
            .as_deref()
            .map(|extension| match extension {
                "txt" | "md" | "log" | "csv" => "text/plain",
                "json" => "application/json",
                "html" | "htm" => "text/html",
                "png" => "image/png",
                "jpg" | "jpeg" => "image/jpeg",
                "gif" => "image/gif",
                "webp" => "image/webp",
                "pdf" => "application/pdf",
                _ => "application/octet-stream",
            })
            .unwrap_or("application/octet-stream"),
    }
}
