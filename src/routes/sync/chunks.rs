use sha2::{Digest, Sha256};

use crate::{
    blob,
    error::{ApiError, ApiResult},
    model::{DriveFile, FileChunkDescriptor, FileKind},
    server::AppState,
};

pub(super) const DEFAULT_DELTA_CHUNK_SIZE: usize = 1024 * 1024;
const MAX_DELTA_CHUNK_SIZE: usize = 16 * 1024 * 1024;
const MAX_CHUNK_MANIFEST_DESCRIPTORS: usize = 16 * 1024;
/// The JSON delta protocol still reconstructs its base and result in memory.
pub(super) const MAX_DELTA_IN_MEMORY_BYTES: usize = 32 * 1024 * 1024;

pub(super) fn ensure_delta_file_allowed(state: &AppState, file: &DriveFile) -> ApiResult<()> {
    state.storage.ensure_file_effectively_live(&file.id)?;
    if !matches!(file.kind, FileKind::File) {
        return Err(ApiError::NotFound);
    }
    state
        .storage
        .ensure_workspace_server_content_allowed(&file.workspace_id)
}

pub(super) fn validate_chunk_size(chunk_size: usize) -> ApiResult<usize> {
    if chunk_size == 0 || chunk_size > MAX_DELTA_CHUNK_SIZE {
        return Err(ApiError::Validation(format!(
            "chunk_size must be between 1 and {MAX_DELTA_CHUNK_SIZE}"
        )));
    }
    Ok(chunk_size)
}

pub(super) fn ensure_chunk_manifest_descriptor_limit(
    file: &DriveFile,
    chunk_size: usize,
) -> ApiResult<()> {
    let content_bytes = file
        .size_bytes
        .ok_or_else(|| ApiError::Validation("file has no stored content size".to_string()))?;
    let content_bytes = usize::try_from(content_bytes)
        .map_err(|_| ApiError::Validation("file has an invalid stored content size".to_string()))?;
    ensure_chunk_descriptor_limit(content_bytes, chunk_size, "manifest")
}

pub(super) fn ensure_chunk_descriptor_limit(
    content_bytes: usize,
    chunk_size: usize,
    description: &str,
) -> ApiResult<()> {
    let descriptor_count =
        content_bytes / chunk_size + usize::from(!content_bytes.is_multiple_of(chunk_size));
    if descriptor_count > MAX_CHUNK_MANIFEST_DESCRIPTORS {
        let minimum_chunk_size = content_bytes / MAX_CHUNK_MANIFEST_DESCRIPTORS
            + usize::from(!content_bytes.is_multiple_of(MAX_CHUNK_MANIFEST_DESCRIPTORS));
        return Err(ApiError::Validation(format!(
            "chunk_size {chunk_size} would produce {descriptor_count} {description} descriptors; maximum is {MAX_CHUNK_MANIFEST_DESCRIPTORS}. Use at least {minimum_chunk_size} bytes for this {content_bytes}-byte file"
        )));
    }
    Ok(())
}

pub(super) fn file_bytes(state: &AppState, file: &DriveFile) -> ApiResult<Vec<u8>> {
    let Some(hash) = file.content_hash.as_deref() else {
        return Ok(Vec::new());
    };
    delta_blob_bytes(state, hash, "chunk manifest")
}

pub(super) fn delta_blob_bytes(state: &AppState, hash: &str, purpose: &str) -> ApiResult<Vec<u8>> {
    blob::get_blob_limited(&state.data_dir(), hash, MAX_DELTA_IN_MEMORY_BYTES as u64)?
        .ok_or_else(|| {
            ApiError::Validation(format!(
                "{purpose} exceeds the {MAX_DELTA_IN_MEMORY_BYTES}-byte in-memory delta limit; use resumable full-content upload"
            ))
        })
}

pub(super) fn chunk_descriptors(bytes: &[u8], chunk_size: usize) -> Vec<FileChunkDescriptor> {
    bytes
        .chunks(chunk_size)
        .enumerate()
        .map(|(index, chunk)| FileChunkDescriptor {
            index,
            offset: (index * chunk_size) as i64,
            length: chunk.len(),
            sha256: sha256_hex(chunk),
        })
        .collect()
}

pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
