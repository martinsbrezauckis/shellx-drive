//! Bounded, byte-preserving WebDAV PUT staging and publication.

use std::path::Path;

use axum::{
    body::Body,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use http_body_util::BodyExt as _;
use sha2::{Digest as _, Sha256};
use tokio::io::AsyncWriteExt as _;

use crate::{
    auth::{require_drive_actor_with_credential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{ContentWrite, CreateFileRequest, DriveFile, FileKind},
    routes::blob_publication::PendingBlobPublications,
    server::{AppState, PartitionedPermit},
};

use super::{
    locks,
    paths::{active_child_by_name, resolve_destination_path, DavDestination},
};

mod staging;

use staging::{content_length, DavStagingFile, StagedDavBody, StreamLimits};

/// This is an on-disk streaming route, not an in-memory body limit. It remains
/// aligned with the documented v0.1 server file ceiling while quota policies
/// can impose much smaller workspace-specific bounds.
const MAX_WEBDAV_PUT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const STREAM_WRITE_BYTES: usize = 64 * 1024;
const MAX_TEXT_INDEX_BYTES: u64 = 256 * 1024;

pub(super) async fn put_file(
    state: AppState,
    headers: HeaderMap,
    workspace_id: String,
    path: String,
    body: Body,
    ingress: PartitionedPermit,
) -> ApiResult<Response> {
    let (actor, _) = require_drive_actor_with_credential(&state, &headers)?;
    state.storage.ensure_whole_workspace_permission(
        &workspace_id,
        &actor,
        WorkspacePermission::Write,
    )?;
    let expected_length = content_length(&headers)?;
    let limits = admit_put(
        &state,
        &headers,
        &workspace_id,
        &path,
        &actor,
        expected_length,
    )
    .await?;
    let staging = DavStagingFile::create(&state).await?;
    let staged = stage_body(body, staging, limits, expected_length).await?;

    let actor_email = actor.email;
    let worker_state = state.clone();
    state
        .run_detached_mutation(async move {
            let _ingress = ingress;
            let _webdav_operation = worker_state.lock_webdav_operation().await;
            let finalization_state = worker_state.clone();
            let work = worker_state
                .run_authenticated_upload_finalization(&actor_email, move || {
                    publish_staged_put(&finalization_state, headers, workspace_id, path, staged)
                })
                .await?;
            work.finish().await
        })
        .await
}

async fn admit_put(
    state: &AppState,
    headers: &HeaderMap,
    workspace_id: &str,
    path: &str,
    actor: &crate::auth::Actor,
    expected_length: Option<u64>,
) -> ApiResult<StreamLimits> {
    state
        .storage
        .ensure_workspace_server_content_allowed(workspace_id)?;
    let _webdav_operation = state.lock_webdav_operation().await;
    let destination = resolve_destination_path(state, workspace_id, path)?;
    let existing = target_for_destination(state, workspace_id, &destination)?;
    ensure_locks(
        state,
        headers,
        workspace_id,
        &destination,
        existing.as_ref(),
        actor,
    )?;
    let limits = StreamLimits::for_workspace(state, workspace_id)?;
    if let Some(length) = expected_length {
        let length = limits.check(length)?;
        state.storage.ensure_workspace_quota(
            workspace_id,
            existing.as_ref().map(|file| file.id.as_str()),
            length,
        )?;
    }
    Ok(limits)
}

fn target_for_destination(
    state: &AppState,
    workspace_id: &str,
    destination: &DavDestination,
) -> ApiResult<Option<DriveFile>> {
    let existing = active_child_by_name(
        state,
        workspace_id,
        destination.parent_id.as_deref(),
        &destination.name,
    )?;
    if existing
        .as_ref()
        .is_some_and(|file| !matches!(file.kind, FileKind::File))
    {
        return Err(ApiError::Validation(
            "webdav PUT target must be a file".to_string(),
        ));
    }
    Ok(existing)
}

fn ensure_locks(
    state: &AppState,
    headers: &HeaderMap,
    workspace_id: &str,
    destination: &DavDestination,
    existing: Option<&DriveFile>,
    actor: &crate::auth::Actor,
) -> ApiResult<()> {
    let targets = match existing {
        Some(file) => vec![crate::storage::WebDavMutationTarget::Resource(Some(
            file.id.clone(),
        ))],
        None => vec![crate::storage::WebDavMutationTarget::Membership(
            destination.parent_id.clone(),
        )],
    };
    locks::ensure_mutation_allowed(
        state,
        headers,
        workspace_id,
        &targets,
        &actor.email,
        actor.is_admin,
    )
}

async fn stage_body(
    mut body: Body,
    mut staging: DavStagingFile,
    limits: StreamLimits,
    expected_length: Option<u64>,
) -> ApiResult<StagedDavBody> {
    let mut file = tokio::fs::File::from_std(staging.take_open_file());
    let mut hasher = Sha256::new();
    let mut received = 0u64;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| {
            ApiError::Validation("WebDAV PUT body ended before publication".to_string())
        })?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        for chunk in data.chunks(STREAM_WRITE_BYTES) {
            received = received
                .checked_add(chunk.len() as u64)
                .ok_or_else(|| ApiError::PayloadTooLarge("WebDAV PUT size overflow".to_string()))?;
            limits.check(received)?;
            hasher.update(chunk);
            file.write_all(chunk).await?;
        }
    }
    if expected_length.is_some_and(|expected| expected != received) {
        return Err(ApiError::Validation(
            "WebDAV Content-Length did not match the received body".to_string(),
        ));
    }
    // Empty files still consume the same one-byte minimum quota charge used by
    // storage, and are checked before the private staging file is finalized.
    limits.check(received)?;
    file.sync_data().await?;
    drop(file);
    Ok(StagedDavBody {
        staging,
        size: received,
        hash: hex::encode(hasher.finalize()),
    })
}

fn publish_staged_put(
    state: &AppState,
    headers: HeaderMap,
    workspace_id: String,
    path: String,
    staged: StagedDavBody,
) -> DavPutWork {
    let mut publications = match PendingBlobPublications::acquire_blocking(state) {
        Ok(publications) => publications,
        Err(error) => return DavPutWork::without_publication(staged, error),
    };
    let result = (|| {
        // The source credential, whole-workspace relationship, storage mode,
        // destination, locks, and quota are all mutable. Re-read each under
        // the DAV mutation serialization boundary immediately before the DB
        // commit, after the client body has been staged.
        let (actor, source_credential) = require_drive_actor_with_credential(state, &headers)?;
        state.storage.ensure_whole_workspace_permission(
            &workspace_id,
            &actor,
            WorkspacePermission::Write,
        )?;
        state
            .storage
            .ensure_workspace_server_content_allowed(&workspace_id)?;
        let destination = resolve_destination_path(state, &workspace_id, &path)?;
        let existing = target_for_destination(state, &workspace_id, &destination)?;
        ensure_locks(
            state,
            &headers,
            &workspace_id,
            &destination,
            existing.as_ref(),
            &actor,
        )?;
        let bytes = i64::try_from(staged.size).map_err(|_| {
            ApiError::PayloadTooLarge("WebDAV PUT exceeds supported range".to_string())
        })?;
        state.storage.ensure_workspace_quota(
            &workspace_id,
            existing.as_ref().map(|file| file.id.as_str()),
            bytes,
        )?;
        let publication = publications.put_file_with_expected_digest(
            staged.staging.path(),
            &staged.hash,
            staged.size,
        )?;
        let (status, file) = match existing {
            Some(existing) => {
                let write = state.storage.put_content_authorized(
                    &existing.id,
                    existing.revision,
                    &publication.hash,
                    bytes,
                    &actor,
                    &source_credential,
                )?;
                let file = match write {
                    ContentWrite::Updated { file, .. } => file,
                    ContentWrite::Conflict(conflict) => state
                        .storage
                        .get_file(&conflict.conflict_file_id)?
                        .ok_or(ApiError::NotFound)?,
                };
                (StatusCode::OK, file)
            }
            None => {
                let (file, _) = state.storage.create_file_with_content_bytes_authorized(
                    CreateFileRequest {
                        workspace_id: workspace_id.clone(),
                        parent_id: destination.parent_id,
                        name: destination.name,
                        kind: FileKind::File,
                        content: None,
                        path: None,
                    },
                    Some(publication.hash),
                    bytes,
                    &actor,
                    &source_credential,
                )?;
                (StatusCode::CREATED, file)
            }
        };
        Ok((status, file))
    })();
    DavPutWork {
        staged,
        storage: Some(state.storage.clone()),
        publications: Some(publications),
        result,
    }
}

struct DavPutWork {
    staged: StagedDavBody,
    storage: Option<crate::storage::Storage>,
    publications: Option<PendingBlobPublications>,
    result: ApiResult<(StatusCode, DriveFile)>,
}

impl DavPutWork {
    fn without_publication(staged: StagedDavBody, error: ApiError) -> Self {
        Self {
            staged,
            storage: None,
            publications: None,
            result: Err(error),
        }
    }

    async fn finish(mut self) -> ApiResult<Response> {
        let result = match self.result {
            Ok((status, file)) => {
                if let Some(storage) = self.storage.as_ref() {
                    index_text_if_allowed(
                        storage,
                        &file,
                        self.staged.staging.path(),
                        self.staged.size,
                    );
                }
                Ok(status.into_response())
            }
            Err(error) => Err(error),
        };
        match self.publications.take() {
            Some(publications) => publications.finish(result).await,
            None => result,
        }
    }
}

fn index_text_if_allowed(
    storage: &crate::storage::Storage,
    file: &DriveFile,
    path: &Path,
    size: u64,
) {
    if size > MAX_TEXT_INDEX_BYTES {
        return;
    }
    let Ok(bytes) = std::fs::read(path) else {
        tracing::warn!(file_id = %file.id, "could not read staged WebDAV text for indexing");
        return;
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return;
    };
    // Search indexing is intentionally non-critical: durable binary and
    // metadata publication has already completed, and text extraction cannot
    // turn a successful PUT into a failed one.
    if let Err(error) = storage.index_file_text(file, text) {
        tracing::warn!(file_id = %file.id, %error, "WebDAV text index update failed after publication");
    }
}
