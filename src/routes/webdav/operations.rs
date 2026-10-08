//! WebDAV file reads and write-side mutations.

use axum::{
    body::Body,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};

use crate::{
    auth::{require_drive_actor_with_credential, WorkspacePermission},
    blob,
    error::{ApiError, ApiResult},
    model::{CopyParentId, CreateFileRequest, FileKind, UpdateFileRequest},
    routes::{
        blob_response::{serve_blob_file_with_guard_after_open, Disposition},
        content_revalidation::AuthenticatedFilePublication,
    },
    server::AppState,
    storage::FileAccessKind,
};

use super::{
    locks,
    paths::{
        active_child_by_name, destination_header_path, ensure_destination_available,
        resolve_destination_path, resolve_path,
    },
    put,
};

pub(super) async fn get_file(
    state: AppState,
    headers: HeaderMap,
    workspace_id: String,
    path: String,
) -> ApiResult<Response> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    state.storage.ensure_whole_workspace_permission(
        &workspace_id,
        &actor,
        WorkspacePermission::Read,
    )?;
    let file = resolve_path(&state, &workspace_id, &path)?;
    if !matches!(file.kind, FileKind::File) {
        return Err(ApiError::NotFound);
    }
    let publication =
        AuthenticatedFilePublication::new(&state.storage, &file, &actor, &source_credential)?;
    let blob_path = blob::blob_file_path(&state.data_dir(), publication.content_hash())?;
    let range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok());
    state.storage.record_file_access_best_effort(
        &file.id,
        &file.workspace_id,
        FileAccessKind::Download,
    );
    let stream_permit = state.try_authenticated_body_stream(&actor.email)?;
    serve_blob_file_with_guard_after_open(
        &file.name,
        &blob_path,
        range,
        Disposition::Attachment,
        stream_permit,
        move || publication.revalidate(),
    )
    .await
}

pub(super) async fn put_file(
    state: AppState,
    headers: HeaderMap,
    workspace_id: String,
    path: String,
    body: Body,
    ingress: crate::server::PartitionedPermit,
) -> ApiResult<Response> {
    put::put_file(state, headers, workspace_id, path, body, ingress).await
}

pub(super) async fn mkcol(
    state: AppState,
    headers: HeaderMap,
    workspace_id: String,
    path: String,
) -> ApiResult<Response> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    state.storage.ensure_whole_workspace_permission(
        &workspace_id,
        &actor,
        WorkspacePermission::Write,
    )?;
    let _webdav_operation = state.lock_webdav_operation().await;
    let destination = resolve_destination_path(&state, &workspace_id, &path)?;
    if active_child_by_name(
        &state,
        &workspace_id,
        destination.parent_id.as_deref(),
        &destination.name,
    )?
    .is_some()
    {
        return Ok(StatusCode::METHOD_NOT_ALLOWED.into_response());
    }
    locks::ensure_mutation_allowed(
        &state,
        &headers,
        &workspace_id,
        &[crate::storage::WebDavMutationTarget::Membership(
            destination.parent_id.clone(),
        )],
        &actor.email,
        actor.is_admin,
    )?;
    state.storage.create_file_with_content_bytes_authorized(
        CreateFileRequest {
            workspace_id,
            parent_id: destination.parent_id,
            name: destination.name,
            kind: FileKind::Folder,
            content: None,
            path: None,
        },
        None,
        0,
        &actor,
        &source_credential,
    )?;
    Ok(StatusCode::CREATED.into_response())
}

pub(super) async fn delete_path(
    state: AppState,
    headers: HeaderMap,
    workspace_id: String,
    path: String,
) -> ApiResult<Response> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    state.storage.ensure_whole_workspace_permission(
        &workspace_id,
        &actor,
        WorkspacePermission::Write,
    )?;
    let _webdav_operation = state.lock_webdav_operation().await;
    let file = resolve_path(&state, &workspace_id, &path)?;
    locks::ensure_mutation_allowed(
        &state,
        &headers,
        &workspace_id,
        &[
            crate::storage::WebDavMutationTarget::Resource(Some(file.id.clone())),
            crate::storage::WebDavMutationTarget::Membership(file.parent_id.clone()),
            crate::storage::WebDavMutationTarget::Subtree(Some(file.id.clone())),
        ],
        &actor.email,
        actor.is_admin,
    )?;
    state
        .storage
        .set_trashed_authorized(&file.id, true, &actor, &source_credential)?;
    state
        .storage
        .delete_webdav_locks_in_subtree(&workspace_id, Some(&file.id))?;
    Ok(StatusCode::NO_CONTENT.into_response())
}

pub(super) async fn move_path(
    state: AppState,
    headers: HeaderMap,
    workspace_id: String,
    path: String,
) -> ApiResult<Response> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    state.storage.ensure_whole_workspace_permission(
        &workspace_id,
        &actor,
        WorkspacePermission::Write,
    )?;
    let _webdav_operation = state.lock_webdav_operation().await;
    let source = resolve_path(&state, &workspace_id, &path)?;
    let destination_path = destination_header_path(&headers, &workspace_id)?;
    let destination = resolve_destination_path(&state, &workspace_id, &destination_path)?;
    ensure_destination_available(&state, &workspace_id, &destination)?;
    locks::ensure_mutation_allowed(
        &state,
        &headers,
        &workspace_id,
        &[
            crate::storage::WebDavMutationTarget::Resource(Some(source.id.clone())),
            crate::storage::WebDavMutationTarget::Membership(source.parent_id.clone()),
            crate::storage::WebDavMutationTarget::Subtree(Some(source.id.clone())),
            crate::storage::WebDavMutationTarget::Membership(destination.parent_id.clone()),
        ],
        &actor.email,
        actor.is_admin,
    )?;
    state.storage.update_file_authorized(
        &source.id,
        UpdateFileRequest {
            base_revision: None,
            name: Some(destination.name),
            move_to_root: destination.parent_id.is_none().then_some(true),
            parent_id: destination.parent_id,
            collision_policy: Some("cancel".to_string()),
            replace_target_id: None,
            replace_target_revision: None,
            labels: None,
            custom_metadata: None,
        },
        &actor,
        &source_credential,
    )?;
    Ok(StatusCode::CREATED.into_response())
}

pub(super) async fn copy_path(
    state: AppState,
    headers: HeaderMap,
    workspace_id: String,
    path: String,
) -> ApiResult<Response> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    state.storage.ensure_whole_workspace_permission(
        &workspace_id,
        &actor,
        WorkspacePermission::Write,
    )?;
    let _webdav_operation = state.lock_webdav_operation().await;
    let source = resolve_path(&state, &workspace_id, &path)?;
    let destination_path = destination_header_path(&headers, &workspace_id)?;
    let destination = resolve_destination_path(&state, &workspace_id, &destination_path)?;
    ensure_destination_available(&state, &workspace_id, &destination)?;
    locks::ensure_mutation_allowed(
        &state,
        &headers,
        &workspace_id,
        &[crate::storage::WebDavMutationTarget::Membership(
            destination.parent_id.clone(),
        )],
        &actor.email,
        actor.is_admin,
    )?;
    let _blob_lifecycle_lock = blob::acquire_shared_lifecycle_lock(state.data_dir()).await?;
    let copy_parent_id = match destination.parent_id {
        Some(parent_id) => CopyParentId::Parent(parent_id),
        None => CopyParentId::Root,
    };
    state.storage.copy_file_authorized_exact_destination(
        &source.id,
        destination.name,
        copy_parent_id,
        &actor,
        &source_credential,
    )?;
    Ok(StatusCode::CREATED.into_response())
}
