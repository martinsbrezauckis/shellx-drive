use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use std::path::Path as FsPath;
use tokio_util::io::ReaderStream;

use crate::{
    auth::require_admin_with_credential,
    backup_v2,
    error::{ApiError, ApiResult},
    routes::blob_response::guard_response_body,
    server::AppState,
};

mod legacy;
mod snapshot;
#[cfg(test)]
mod tests;

use super::catalog::{read_v2_backup_metadata_for_state, read_v2_sidecar, v2_backup_path};
use snapshot::snapshot_v2_archive;

pub(super) fn cleanup_download_snapshots(data_dir: &FsPath) -> ApiResult<()> {
    snapshot::cleanup_download_snapshots(data_dir)
}

pub(super) async fn download_backup(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(backup_id): Path<String>,
) -> ApiResult<Response> {
    let (actor, source_credential) = require_admin_with_credential(&state, &headers)?;
    if super::select_backup_v2_lane(&state, &backup_id)? {
        // Admit both the eventual response body and the expensive snapshot
        // preparation before reading or copying backup media. The backup-work
        // permit moves into the blocking closure below, so request cancellation
        // cannot admit a second full archive copy while the first is running.
        let stream_permit = state.try_authenticated_body_stream(&actor.email)?;
        let backup_work = state.try_backup_work()?;
        let managed_archive_sha256 = state.storage.managed_backup_archive_sha256(&backup_id)?;
        let v2_path = v2_backup_path(&state.data_dir(), &backup_id)?;
        let metadata = read_v2_backup_metadata_for_state(&state, &backup_id)?;
        let sidecar = match managed_archive_sha256.as_deref() {
            Some(expected_archive_sha256) => {
                // Do not trust worker-only provenance or prior metadata reads:
                // this response independently verifies both durable sources.
                let sidecar = read_v2_sidecar(&state.data_dir(), &backup_id)?;
                if sidecar.archive_sha256 != expected_archive_sha256 {
                    return Err(ApiError::Validation(
                        "managed backup v2 sidecar conflicts with durable provenance".to_string(),
                    ));
                }
                Some(sidecar)
            }
            None => None,
        };
        let max_archive_bytes = state.config.backup_max_archive_bytes;
        let archive_path = v2_path.clone();
        let data_dir = state.data_dir();
        let (snapshot, archive_bytes, archive_sha256) = tokio::task::spawn_blocking(move || {
            let result = snapshot_v2_archive(&data_dir, &archive_path, max_archive_bytes);
            drop(backup_work);
            result
        })
        .await
        .map_err(|_| {
            ApiError::Maintenance("backup v2 download preparation worker failed".to_string())
        })??;
        if metadata.archive_bytes != Some(archive_bytes) {
            return Err(ApiError::Validation(
                "backup v2 archive length does not match its reported metadata".to_string(),
            ));
        }
        if let (Some(expected_archive_sha256), Some(sidecar)) =
            (managed_archive_sha256.as_deref(), sidecar.as_ref())
        {
            if archive_sha256 != expected_archive_sha256 || archive_sha256 != sidecar.archive_sha256
            {
                return Err(ApiError::Validation(
                    "managed backup v2 archive digest does not match durable provenance"
                        .to_string(),
                ));
            }
        }
        let file = snapshot.into_stream();
        let _receipt = state.storage.create_backup_download_publication_intent(
            &backup_id,
            &actor,
            &source_credential,
        )?;
        // Stream only the private snapshot whose bytes were hashed above.
        // Neither a pathname replacement nor an in-place mutation of the
        // source archive can change the published body after this point.
        let mut response = Body::from_stream(ReaderStream::new(file)).into_response();
        *response.status_mut() = StatusCode::OK;
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/x-shellx-drive-backup"),
        );
        response.headers_mut().insert(
            header::CONTENT_LENGTH,
            HeaderValue::from_str(&archive_bytes.to_string())
                .map_err(|_| ApiError::Validation("invalid backup archive length".to_string()))?,
        );
        response.headers_mut().insert(
            header::CONTENT_DISPOSITION,
            HeaderValue::from_str(&format!(
                "attachment; filename=\"{backup_id}.{}\"",
                backup_v2::ARCHIVE_EXTENSION
            ))
            .map_err(|_| ApiError::Validation("invalid backup filename".to_string()))?,
        );
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        return Ok(guard_response_body(response, stream_permit));
    }
    legacy::download(state, actor, source_credential, backup_id).await
}
