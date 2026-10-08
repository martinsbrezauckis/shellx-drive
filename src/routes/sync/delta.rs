use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};

use crate::{
    auth::{require_drive_actor_with_credential, Actor, DriveCredential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{
        ContentWrite, DeltaChunkOperation, DeltaContentRequest, DeltaContentResponse, DriveFile,
    },
    routes::blob_publication::PendingBlobPublications,
    server::AppState,
};

use super::chunks::{
    delta_blob_bytes, ensure_chunk_descriptor_limit, ensure_delta_file_allowed, sha256_hex,
    validate_chunk_size, MAX_DELTA_IN_MEMORY_BYTES,
};

const MAX_DELTA_OPERATIONS: usize = 2048;

struct DeltaWork {
    file_id: String,
    file: DriveFile,
    actor: Actor,
    source_credential: DriveCredential,
    request: DeltaContentRequest,
    base_hash: String,
    base_content_bytes: usize,
    chunk_size: usize,
}

pub(super) async fn put(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
    Json(request): Json<DeltaContentRequest>,
) -> ApiResult<Response> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let file = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    state
        .storage
        .ensure_item_response_permission(&file.id, &actor, WorkspacePermission::Write)?;
    ensure_delta_file_allowed(&state, &file)?;
    let chunk_size = validate_chunk_size(request.chunk_size)?;
    if request.operations.len() > MAX_DELTA_OPERATIONS {
        return Err(ApiError::Validation(format!(
            "delta operations must be {MAX_DELTA_OPERATIONS} or fewer"
        )));
    }
    let (base_hash, base_content_bytes) = state
        .storage
        .file_revision_content_descriptor(&file_id, request.base_revision)?
        .ok_or(ApiError::NotFound)?;
    let base_content_bytes = validate_base_size(base_content_bytes)?;
    ensure_chunk_descriptor_limit(base_content_bytes, chunk_size, "delta base")?;

    let actor_partition = actor.email.clone();
    let detached_state = state.clone();
    state
        .run_detached_mutation(async move {
            let worker_state = detached_state.clone();
            let (pending, result) = detached_state
                .run_sync_compute(&actor_partition, move || {
                    let mut pending = PendingBlobPublications::acquire_blocking(&worker_state)?;
                    let result = apply(
                        &worker_state,
                        &mut pending,
                        DeltaWork {
                            file_id,
                            file,
                            actor,
                            source_credential,
                            request,
                            base_hash,
                            base_content_bytes,
                            chunk_size,
                        },
                    );
                    Ok::<_, ApiError>((pending, result))
                })
                .await??;
            pending.finish(result).await
        })
        .await
}

fn apply(
    state: &AppState,
    publications: &mut PendingBlobPublications,
    work: DeltaWork,
) -> ApiResult<Response> {
    let DeltaWork {
        file_id,
        file,
        actor,
        source_credential,
        request,
        base_hash,
        base_content_bytes,
        chunk_size,
    } = work;
    let base_bytes = delta_blob_bytes(state, &base_hash, "delta base")?;
    if base_bytes.len() != base_content_bytes {
        return Err(ApiError::Validation(
            "delta base size does not match revision metadata".to_string(),
        ));
    }
    let mut reconstructed = Vec::new();
    let mut chunks_reused = 0usize;
    let mut uploaded_bytes = 0i64;

    for operation in &request.operations {
        match operation {
            DeltaChunkOperation::Copy { source_index } => {
                let chunk = base_chunk(&base_bytes, chunk_size, *source_index)?;
                ensure_in_memory_limit(reconstructed.len(), chunk.len())?;
                reconstructed.extend_from_slice(chunk);
                chunks_reused += 1;
            }
            DeltaChunkOperation::Data {
                content,
                content_base64,
            } => {
                let bytes = decode_data(content.as_deref(), content_base64.as_deref())?;
                uploaded_bytes = uploaded_bytes
                    .checked_add(i64::try_from(bytes.len()).unwrap_or(i64::MAX))
                    .ok_or_else(|| {
                        ApiError::Validation("delta uploaded byte count is too large".to_string())
                    })?;
                ensure_in_memory_limit(reconstructed.len(), bytes.len())?;
                reconstructed.extend_from_slice(&bytes);
            }
        }
    }
    drop(base_bytes);

    let content_sha256 = sha256_hex(&reconstructed);
    if request
        .expected_content_sha256
        .as_deref()
        .is_some_and(|expected| expected != content_sha256)
    {
        return Err(ApiError::Validation(
            "expected_content_sha256 does not match reconstructed content".to_string(),
        ));
    }
    let content_bytes = i64::try_from(reconstructed.len())
        .map_err(|_| ApiError::Validation("delta content is too large".to_string()))?;
    let quota_target = (request.base_revision == file.revision).then_some(file_id.as_str());
    state
        .storage
        .ensure_workspace_quota(&file.workspace_id, quota_target, content_bytes)?;
    let hash = publications.put_bytes(&reconstructed)?.hash;
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
            index_reconstructed_content(state, &file, &reconstructed)?;
            let delta = state.storage.record_delta_sync_write(
                &file_id,
                &file.workspace_id,
                &actor.email,
                request.base_revision,
                file.revision,
                chunk_size,
                request.operations.len(),
                chunks_reused,
                uploaded_bytes,
                content_bytes,
                &content_sha256,
            )?;
            Ok(Json(DeltaContentResponse {
                file,
                receipt,
                delta,
            })
            .into_response())
        }
        ContentWrite::Conflict(conflict) => {
            let conflict_file = state
                .storage
                .get_file(&conflict.conflict_file_id)?
                .ok_or(ApiError::NotFound)?;
            index_reconstructed_content(state, &conflict_file, &reconstructed)?;
            if let Err(error) = state.storage.notify_workspace_members(
                &conflict_file.workspace_id,
                &actor.email,
                "sync_conflict",
                "Sync conflict created",
                &format!("A stale delta sync created {}", conflict_file.name),
                Some(&conflict_file.id),
                Some("file"),
                Some(&conflict_file.id),
            ) {
                tracing::warn!(
                    file_id = %conflict_file.id,
                    %error,
                    "delta conflict notification fanout failed after durable conflict creation"
                );
            }
            state.storage.record_delta_sync_write(
                &file_id,
                &conflict_file.workspace_id,
                &actor.email,
                request.base_revision,
                conflict_file.revision,
                chunk_size,
                request.operations.len(),
                chunks_reused,
                uploaded_bytes,
                content_bytes,
                &content_sha256,
            )?;
            Ok((StatusCode::CONFLICT, Json(conflict)).into_response())
        }
    }
}

fn validate_base_size(content_bytes: i64) -> ApiResult<usize> {
    let content_bytes = usize::try_from(content_bytes)
        .map_err(|_| ApiError::Validation("delta base has an invalid stored size".to_string()))?;
    if content_bytes > MAX_DELTA_IN_MEMORY_BYTES {
        return Err(ApiError::Validation(format!(
            "delta base exceeds the {MAX_DELTA_IN_MEMORY_BYTES}-byte in-memory delta limit; use resumable full-content upload"
        )));
    }
    Ok(content_bytes)
}

fn base_chunk(bytes: &[u8], chunk_size: usize, source_index: usize) -> ApiResult<&[u8]> {
    let start = source_index.checked_mul(chunk_size).ok_or_else(|| {
        ApiError::Validation("delta copy source_index is outside the base manifest".to_string())
    })?;
    if start >= bytes.len() {
        return Err(ApiError::Validation(
            "delta copy source_index is outside the base manifest".to_string(),
        ));
    }
    let end = start.saturating_add(chunk_size).min(bytes.len());
    Ok(&bytes[start..end])
}

fn ensure_in_memory_limit(current: usize, additional: usize) -> ApiResult<()> {
    let next = current.checked_add(additional).ok_or_else(|| {
        ApiError::Validation("delta reconstructed content is too large".to_string())
    })?;
    if next > MAX_DELTA_IN_MEMORY_BYTES {
        return Err(ApiError::Validation(format!(
            "delta reconstructed content must be {MAX_DELTA_IN_MEMORY_BYTES} bytes or smaller; use resumable full-content upload for larger files"
        )));
    }
    Ok(())
}

fn decode_data(content: Option<&str>, content_base64: Option<&str>) -> ApiResult<Vec<u8>> {
    match (content, content_base64) {
        (Some(_), Some(_)) => Err(ApiError::Validation(
            "delta data operation must contain content or content_base64, not both".to_string(),
        )),
        (Some(content), None) => Ok(content.as_bytes().to_vec()),
        (None, Some(content_base64)) => STANDARD.decode(content_base64).map_err(|error| {
            ApiError::Validation(format!("invalid delta content_base64: {error}"))
        }),
        (None, None) => Err(ApiError::Validation(
            "delta data operation must contain content or content_base64".to_string(),
        )),
    }
}

fn index_reconstructed_content(state: &AppState, file: &DriveFile, bytes: &[u8]) -> ApiResult<()> {
    let content_text = String::from_utf8_lossy(bytes);
    state.storage.index_file_text(file, content_text.as_ref())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_32_mib_one_byte_geometry_without_allocating_descriptors() {
        let error =
            ensure_chunk_descriptor_limit(MAX_DELTA_IN_MEMORY_BYTES, 1, "delta base").unwrap_err();
        assert!(matches!(error, ApiError::Validation(_)));
        assert!(error
            .to_string()
            .contains("33554432 delta base descriptors"));
    }

    #[test]
    fn checked_chunk_lookup_handles_partial_and_invalid_indices() {
        let bytes = b"abcdefghij";
        assert_eq!(base_chunk(bytes, 4, 0).unwrap(), b"abcd");
        assert_eq!(base_chunk(bytes, 4, 2).unwrap(), b"ij");
        assert!(base_chunk(bytes, 4, 3).is_err());
        assert!(base_chunk(bytes, 2, usize::MAX).is_err());
    }
}
