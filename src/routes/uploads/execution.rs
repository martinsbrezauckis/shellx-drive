use axum::{http::HeaderMap, Json};

use crate::{
    auth::{require_drive_actor_with_credential, Actor, DriveCredential},
    error::{ApiError, ApiResult},
    model::UploadChunkResponse,
    routes::blob_publication::PendingBlobPublications,
    server::{AppState, PartitionedPermit},
};

use super::{
    ensure_upload_session_permission,
    locking::{acquire_upload_lock, rollback_unacknowledged_chunk, upload_dir, upload_part_path},
    validation::{ensure_upload_session_actor, validate_declared_upload_size},
};

mod outcome;

use outcome::UploadChunkWork;

pub(crate) async fn put_upload_bytes(
    state: AppState,
    headers: HeaderMap,
    upload_id: String,
    offset: i64,
    finish: bool,
    chunk: Vec<u8>,
    ingress_permit: PartitionedPermit,
) -> ApiResult<Json<UploadChunkResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let upload_id = crate::upload_ids::normalize(&upload_id)?;
    let initial = state
        .storage
        .get_upload_session(&upload_id)?
        .ok_or(ApiError::NotFound)?;
    ensure_upload_session_actor(&initial, &actor)?;
    ensure_upload_session_permission(&state, &initial, &actor)?;
    state
        .storage
        .ensure_workspace_server_content_allowed(&initial.workspace_id)?;

    let worker_state = state.clone();
    state
        .run_detached_mutation(async move {
            // The request waiter may disappear while its mutation continues.
            // Keep admission with the retained bytes through real completion.
            let _ingress_permit = ingress_permit;
            run_upload_chunk_work(
                worker_state,
                upload_id,
                offset,
                finish,
                chunk,
                actor,
                source_credential,
            )
            .await
        })
        .await
}

#[allow(clippy::too_many_arguments)]
async fn run_upload_chunk_work(
    state: AppState,
    upload_id: String,
    offset: i64,
    finish: bool,
    chunk: Vec<u8>,
    actor: Actor,
    source_credential: DriveCredential,
) -> ApiResult<Json<UploadChunkResponse>> {
    let actor_email = actor.email.clone();
    let outcome = if finish {
        let worker_state = state.clone();
        state
            .run_authenticated_upload_finalization(&actor_email, move || {
                write_upload_chunk(
                    &worker_state,
                    upload_id,
                    offset,
                    finish,
                    chunk,
                    actor,
                    source_credential,
                )
            })
            .await?
    } else {
        // Keep routine writes off async workers without serializing contenders
        // before the per-session lock: same-offset races must still resolve as
        // one acknowledged write and one Conflict, not admission rejection.
        let worker_state = state.clone();
        tokio::task::spawn_blocking(move || {
            write_upload_chunk(
                &worker_state,
                upload_id,
                offset,
                finish,
                chunk,
                actor,
                source_credential,
            )
        })
        .await
        .map_err(|_| ApiError::Maintenance("upload chunk worker failed".to_string()))?
    };
    outcome.finish().await
}

fn write_upload_chunk(
    state: &AppState,
    upload_id: String,
    offset: i64,
    finish: bool,
    chunk: Vec<u8>,
    actor: Actor,
    source_credential: DriveCredential,
) -> UploadChunkWork {
    let mut publications = None;
    let result = (|| {
        let directory = upload_dir(state);
        crate::fs_private::create_dir_all_private(&directory)?;
        let _lock = acquire_upload_lock(state, &upload_id)?;
        let session = state
            .storage
            .get_upload_session(&upload_id)?
            .ok_or(ApiError::NotFound)?;
        ensure_upload_session_actor(&session, &actor)?;
        ensure_upload_session_permission(state, &session, &actor)?;
        state
            .storage
            .ensure_workspace_server_content_allowed(&session.workspace_id)?;
        if session.completed {
            if !finish {
                return Err(ApiError::Conflict);
            }
            let completed = state.storage.completed_upload_outcome_authorized(
                &upload_id,
                &actor,
                &source_credential,
            )?;
            return Ok(Json(UploadChunkResponse {
                session: completed.session,
                file: Some(completed.file),
                receipt: Some(completed.receipt),
                conflict: completed.conflict,
            }));
        }
        if session.canceled || offset != session.received_bytes {
            return Err(ApiError::Conflict);
        }

        let received_bytes = session
            .received_bytes
            .checked_add(i64::try_from(chunk.len()).map_err(|_| {
                ApiError::PayloadTooLarge("upload chunk exceeds supported range".to_string())
            })?)
            .ok_or_else(|| ApiError::Validation("upload offset overflowed".to_string()))?;
        let total_size = session.total_size.ok_or_else(|| {
            ApiError::Validation("upload session is missing total_size".to_string())
        })?;
        validate_declared_upload_size(total_size)?;
        if received_bytes > total_size {
            return Err(ApiError::Validation(
                "chunk exceeds declared total_size".to_string(),
            ));
        }
        if session.target_file_id.is_none() {
            state
                .storage
                .ensure_workspace_quota(&session.workspace_id, None, received_bytes)?;
        }
        if finish && received_bytes != total_size {
            return Err(ApiError::Validation(
                "finished upload size does not match total_size".to_string(),
            ));
        }

        let part_path = upload_part_path(state, &upload_id)?;
        let part_size = match std::fs::metadata(&part_path) {
            Ok(metadata) => i64::try_from(metadata.len()).map_err(|_| {
                ApiError::Validation("upload part size exceeds supported range".to_string())
            })?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
            Err(error) => return Err(error.into()),
        };
        if part_size != session.received_bytes {
            return Err(ApiError::Conflict);
        }
        if finish {
            publications = Some(PendingBlobPublications::acquire_blocking(state)?);
        }
        if let Err(error) = append_chunk(&part_path, &chunk, finish) {
            rollback_unacknowledged_chunk(&part_path, session.received_bytes);
            return Err(error);
        }

        let result = if finish {
            complete_upload_chunk(
                state,
                &upload_id,
                &part_path,
                &session,
                &actor,
                &source_credential,
                received_bytes,
                total_size,
                publications
                    .as_mut()
                    .expect("terminal upload publication guard exists"),
            )
        } else {
            let session = state.storage.update_upload_session_received_authorized(
                &upload_id,
                session.received_bytes,
                received_bytes,
                &actor,
                &source_credential,
            )?;
            Ok(Json(UploadChunkResponse {
                session,
                file: None,
                receipt: None,
                conflict: None,
            }))
        };
        if result.is_err() {
            rollback_unacknowledged_chunk(&part_path, session.received_bytes);
        }
        result
    })();
    UploadChunkWork {
        publications,
        result,
    }
}

fn append_chunk(part_path: &std::path::Path, chunk: &[u8], finish: bool) -> ApiResult<()> {
    use std::io::Write as _;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(part_path)?;
    file.write_all(chunk)?;
    if finish {
        file.sync_all()?;
    }
    crate::fs_private::set_file_private(part_path)?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn complete_upload_chunk(
    state: &AppState,
    upload_id: &str,
    part_path: &std::path::Path,
    session: &crate::model::UploadSession,
    actor: &Actor,
    source_credential: &DriveCredential,
    received_bytes: i64,
    total_size: i64,
    publications: &mut PendingBlobPublications,
) -> ApiResult<Json<UploadChunkResponse>> {
    // Re-check mutable authority and target state at the terminal boundary.
    // Storage repeats this in its completion transaction, closing concurrent
    // finalizer and revoked-credential races.
    if session.target_file_id.is_some() {
        ensure_upload_session_actor(session, actor)?;
        ensure_upload_session_permission(state, session, actor)?;
        state
            .storage
            .ensure_workspace_server_content_allowed(&session.workspace_id)?;
        let publication = publications.put_file(part_path)?;
        if publication.size != total_size as u64 {
            return Err(ApiError::Conflict);
        }
        let completed = state.storage.complete_replacement_upload_session(
            upload_id,
            actor,
            source_credential,
            received_bytes,
            &publication.hash,
        )?;
        let _ = std::fs::remove_file(part_path);
        return Ok(Json(UploadChunkResponse {
            session: completed.session,
            file: Some(completed.file),
            receipt: Some(completed.receipt),
            conflict: completed.conflict,
        }));
    }

    let (target_parent, target_name) = match session
        .path
        .as_deref()
        .map(str::trim)
        .filter(|path| !path.is_empty())
    {
        Some(path) => state.storage.resolve_relative_upload_path_authorized(
            &session.workspace_id,
            session.parent_id.as_deref(),
            path,
            actor,
            source_credential,
        )?,
        None => (session.parent_id.clone(), session.name.clone()),
    };
    let publication = publications.put_file(part_path)?;
    if publication.size != total_size as u64 {
        return Err(ApiError::Conflict);
    }
    let completed =
        state
            .storage
            .complete_new_upload_session(crate::storage::NewUploadCompletion {
                upload_id,
                actor,
                source_credential,
                received_bytes,
                parent_id: target_parent,
                name: target_name,
                content_hash: &publication.hash,
            })?;
    let _ = std::fs::remove_file(part_path);
    Ok(Json(UploadChunkResponse {
        session: completed.session,
        file: Some(completed.file),
        receipt: Some(completed.receipt),
        conflict: None,
    }))
}
