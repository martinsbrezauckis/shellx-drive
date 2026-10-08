use crate::{
    error::{ApiError, ApiResult},
    server::AppState,
};

use super::super::catalog::{read_v2_sidecar, v2_sidecar_path, V2SidecarPayload};

pub(super) fn verify_v2_archive(
    state: &AppState,
    backup_id: &str,
    archive_sha256: &str,
    has_portable_metadata: bool,
) -> ApiResult<Option<V2SidecarPayload>> {
    let data_dir = state.data_dir();
    let sidecar_path = v2_sidecar_path(&data_dir, backup_id)?;
    if let Some(expected_archive_sha256) = state.storage.managed_backup_archive_sha256(backup_id)? {
        if !sidecar_path.exists() {
            return Err(ApiError::Validation(
                "managed backup v2 authenticated sidecar is missing".to_string(),
            ));
        }
        let sidecar = read_v2_sidecar(&data_dir, backup_id)?;
        if sidecar.archive_sha256 != expected_archive_sha256
            || archive_sha256 != expected_archive_sha256
        {
            return Err(ApiError::Validation(
                "managed backup v2 archive provenance does not match durable publication"
                    .to_string(),
            ));
        }
        return Ok(Some(sidecar));
    }
    if sidecar_path.exists() {
        let sidecar = read_v2_sidecar(&data_dir, backup_id)?;
        if archive_sha256 != sidecar.archive_sha256 {
            return Err(ApiError::Validation(
                "backup v2 archive hash does not match authenticated sidecar".to_string(),
            ));
        }
        return Ok(Some(sidecar));
    }
    if !has_portable_metadata {
        return Err(ApiError::Validation(
            "backup v2 archive lacks portable integrity metadata and has no local authenticated sidecar"
                .to_string(),
        ));
    }
    Ok(None)
}
