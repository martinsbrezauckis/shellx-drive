use axum::{body::Bytes, Json};

use crate::{
    auth::constant_time_str_eq,
    error::{ApiError, ApiResult},
    model::PublicDropUploadResponse,
    routes::blob_publication::PendingBlobPublications,
    server::{AppState, PublicDropChunkIngressPermit},
    storage::DropRecord,
};

use super::{auth::ensure_drop_active, bound_active_session, file_io, public_session};

struct DropChunkWork {
    publications: Option<PendingBlobPublications>,
    chunk_ingress_permit: PublicDropChunkIngressPermit,
    finalization_permit: Option<tokio::sync::OwnedSemaphorePermit>,
    result: ApiResult<Json<PublicDropUploadResponse>>,
}

impl DropChunkWork {
    async fn finish(self) -> ApiResult<Json<PublicDropUploadResponse>> {
        let _chunk_ingress_permit = self.chunk_ingress_permit;
        let _finalization_permit = self.finalization_permit;
        match self.publications {
            Some(publications) => publications.finish(self.result).await,
            None => self.result,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn put_drop_chunk(
    state: AppState,
    drop_record: DropRecord,
    drop_id: String,
    session_id: String,
    proof_fingerprint: String,
    offset: i64,
    received_bytes: i64,
    finish: bool,
    body: Bytes,
    chunk_ingress_permit: PublicDropChunkIngressPermit,
) -> ApiResult<Json<PublicDropUploadResponse>> {
    let finalization_permit = finish
        .then(|| state.try_public_drop_finalization())
        .transpose()?;
    let worker_state = state.clone();
    state
        .run_detached_mutation(async move {
            let outcome = tokio::task::spawn_blocking(move || {
                write_drop_chunk(
                    &worker_state,
                    &drop_record,
                    &drop_id,
                    &session_id,
                    &proof_fingerprint,
                    offset,
                    received_bytes,
                    finish,
                    &body,
                    chunk_ingress_permit,
                    finalization_permit,
                )
            })
            .await
            .map_err(|_| ApiError::Maintenance("public drop chunk worker failed".to_string()))?;
            outcome.finish().await
        })
        .await
}

#[allow(clippy::too_many_arguments)]
fn write_drop_chunk(
    state: &AppState,
    drop_record: &DropRecord,
    drop_id: &str,
    session_id: &str,
    proof_fingerprint: &str,
    offset: i64,
    received_bytes: i64,
    finish: bool,
    body: &[u8],
    chunk_ingress_permit: PublicDropChunkIngressPermit,
    finalization_permit: Option<tokio::sync::OwnedSemaphorePermit>,
) -> DropChunkWork {
    let mut publications = None;
    let result = (|| {
        let directory = file_io::drop_upload_dir(state);
        crate::fs_private::create_dir_all_private(&directory)?;
        let mut session_lock = file_io::SessionFileLock::acquire(&directory, session_id)?;
        let session = bound_active_session(state, drop_id, session_id, proof_fingerprint)?;
        if session.received_bytes != offset {
            return Err(ApiError::Conflict);
        }
        state
            .storage
            .ensure_workspace_quota(&session.workspace_id, None, session.total_size)?;
        let current_drop = state.storage.get_drop(drop_id)?.ok_or(ApiError::NotFound)?;
        ensure_drop_active(&current_drop)?;
        if !constant_time_str_eq(
            &current_drop.authorization_fingerprint(),
            &drop_record.authorization_fingerprint(),
        ) {
            return Err(ApiError::Unauthenticated);
        }
        let part_path = directory.join(format!("{session_id}.part"));
        session_lock.remove_part_if_session_inactive_on_drop(
            state.storage.clone(),
            session_id.to_string(),
            part_path.clone(),
        );
        if finish {
            publications = Some(PendingBlobPublications::acquire_blocking(state)?);
        }
        file_io::append_chunk(state, &session, &part_path, offset, body)?;
        let session =
            match state
                .storage
                .update_drop_upload_received(session_id, offset, received_bytes)
            {
                Ok(session) => session,
                Err(error) => {
                    let inactive = state
                        .storage
                        .get_drop_upload_session(session_id)
                        .ok()
                        .flatten()
                        .is_some_and(|session| session.status != "active")
                        || state
                            .storage
                            .get_drop(drop_id)
                            .ok()
                            .flatten()
                            .is_none_or(|record| ensure_drop_active(&record).is_err());
                    if inactive {
                        file_io::remove_part_file_best_effort(&part_path, session_id);
                    } else {
                        file_io::rollback_unacknowledged_chunk(&part_path, offset);
                    }
                    return Err(error);
                }
            };
        if !finish {
            return Ok(Json(PublicDropUploadResponse {
                session: public_session(&session),
                receipt: None,
            }));
        }

        let publication = publications
            .as_mut()
            .expect("terminal drop publication guard exists")
            .put_file(&part_path)?;
        if i64::try_from(publication.size).ok() != Some(session.total_size) {
            let _ = state
                .storage
                .fail_drop_upload_session(session_id, "part_size_mismatch");
            file_io::remove_part_file_best_effort(&part_path, session_id);
            return Err(ApiError::Conflict);
        }
        let (session, file, receipt) = match state
            .storage
            .finalize_drop_upload_file(session_id, &publication.hash)
        {
            Ok(result) => result,
            Err(error) => {
                let _ = state
                    .storage
                    .fail_drop_upload_session(session_id, "storage_error");
                file_io::remove_part_file_best_effort(&part_path, session_id);
                return Err(error);
            }
        };
        if let Err(error) =
            file_io::index_declared_text_if_bounded(state, &session, &file, &part_path)
        {
            tracing::warn!(session_id = %session.id, %error, "drop upload immediate text index failed");
        }
        file_io::remove_part_file_best_effort(&part_path, &session.id);
        if let Err(error) = state.storage.notify_workspace_members(
            &file.workspace_id,
            "public",
            "drop_upload",
            "New drop upload",
            &format!(
                "{} was uploaded through {}",
                file.name, drop_record.drop.name
            ),
            Some(&file.id),
            Some("drop"),
            Some(drop_id),
        ) {
            tracing::warn!(session_id = %session.id, %error, "drop upload notification failed");
        }
        let mut receipt = receipt;
        receipt.target_id = None;
        Ok(Json(PublicDropUploadResponse {
            session: public_session(&session),
            receipt: Some(receipt),
        }))
    })();
    DropChunkWork {
        publications,
        chunk_ingress_permit,
        finalization_permit,
        result,
    }
}

pub(super) async fn cancel_drop_upload(
    state: AppState,
    drop_id: String,
    session_id: String,
    proof_fingerprint: String,
) -> ApiResult<Json<PublicDropUploadResponse>> {
    let worker_state = state.clone();
    state
        .run_detached_mutation(async move {
            tokio::task::spawn_blocking(move || {
                let directory = file_io::drop_upload_dir(&worker_state);
                crate::fs_private::create_dir_all_private(&directory)?;
                let _lock = file_io::SessionFileLock::acquire(&directory, &session_id)?;
                let session =
                    bound_active_session(&worker_state, &drop_id, &session_id, &proof_fingerprint)?;
                let (session, receipt) = worker_state
                    .storage
                    .cancel_drop_upload_session(&session.id)?;
                file_io::remove_part_file_best_effort(
                    &directory.join(format!("{session_id}.part")),
                    &session_id,
                );
                let mut receipt = receipt;
                receipt.target_id = None;
                Ok(Json(PublicDropUploadResponse {
                    session: public_session(&session),
                    receipt: Some(receipt),
                }))
            })
            .await
            .map_err(|_| {
                ApiError::Maintenance("public drop cancellation worker failed".to_string())
            })?
        })
        .await
}
