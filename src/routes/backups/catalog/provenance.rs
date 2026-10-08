use std::path::Path;

use crate::{
    error::{ApiError, ApiResult},
    model::BackupMetadata,
    server::AppState,
};

use super::{
    ensure_v2_generation_complete, read_portable_metadata, read_v2_sidecar, v2_backup_path,
    v2_sidecar_path,
};

pub(super) fn read_v2_backup_metadata(
    data_dir: &Path,
    backup_id: &str,
    managed_archive_sha256: Option<&str>,
) -> ApiResult<BackupMetadata> {
    ensure_v2_generation_complete(data_dir, backup_id)?;
    let sidecar_path = v2_sidecar_path(data_dir, backup_id)?;
    if let Some(expected_archive_sha256) = managed_archive_sha256 {
        if !sidecar_path.exists() {
            return Err(ApiError::Validation(
                "managed backup v2 authenticated sidecar is missing".to_string(),
            ));
        }
        let sidecar = read_v2_sidecar(data_dir, backup_id)?;
        if sidecar.archive_sha256 != expected_archive_sha256 {
            return Err(ApiError::Validation(
                "managed backup v2 sidecar conflicts with durable provenance".to_string(),
            ));
        }
        return Ok(sidecar.metadata);
    }
    if sidecar_path.exists() {
        return Ok(read_v2_sidecar(data_dir, backup_id)?.metadata);
    }
    let metadata = read_portable_metadata(&v2_backup_path(data_dir, backup_id)?)?.ok_or_else(|| {
        ApiError::Validation(
            "backup v2 archive lacks portable verification metadata and has no local authenticated sidecar"
                .to_string(),
        )
    })?;
    if metadata.backup_id != backup_id {
        return Err(ApiError::Validation(
            "backup v2 archive identity does not match its filename".to_string(),
        ));
    }
    Ok(metadata)
}

pub(crate) fn read_v2_backup_metadata_for_state(
    state: &AppState,
    backup_id: &str,
) -> ApiResult<BackupMetadata> {
    let digest = state.storage.managed_backup_archive_sha256(backup_id)?;
    read_v2_backup_metadata(&state.data_dir(), backup_id, digest.as_deref())
}
