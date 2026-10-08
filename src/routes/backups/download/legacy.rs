use axum::{
    body::Body,
    http::{header, HeaderValue},
    response::{IntoResponse, Response},
};

use crate::{
    auth::{Actor, DriveCredential},
    error::{ApiError, ApiResult},
    model::BackupDownloadResponse,
    routes::blob_response::guard_bounded_bytes_response_with_total_deadline,
    server::AppState,
};

use super::super::legacy::read_backup_bundle;

const MAX_LEGACY_DOWNLOAD_RESPONSE_BYTES: usize = 130 * 1024 * 1024;

pub(super) async fn download(
    state: AppState,
    actor: Actor,
    source_credential: DriveCredential,
    backup_id: String,
) -> ApiResult<Response> {
    let stream_permit = state.try_authenticated_body_stream(&actor.email)?;
    let backup_work = state.try_backup_work()?;
    let data_dir = state.data_dir();
    let download_storage = state.storage.clone();
    let (encoded, backup_work) = tokio::task::spawn_blocking(move || {
        let bundle = read_backup_bundle(&data_dir, &backup_id)?;
        let receipt = download_storage.create_backup_download_publication_intent(
            &backup_id,
            &actor,
            &source_credential,
        )?;
        let encoded =
            serde_json::to_vec(&BackupDownloadResponse { bundle, receipt }).map_err(|error| {
                ApiError::Validation(format!("could not encode legacy backup download: {error}"))
            })?;
        if encoded.len() > MAX_LEGACY_DOWNLOAD_RESPONSE_BYTES {
            return Err(ApiError::PayloadTooLarge(format!(
                "legacy backup download response exceeds {MAX_LEGACY_DOWNLOAD_RESPONSE_BYTES} bytes"
            )));
        }
        Ok::<_, ApiError>((encoded, backup_work))
    })
    .await
    .map_err(|_| ApiError::Maintenance("legacy backup download worker failed".to_string()))??;
    let content_length = encoded.len();
    let mut response = Body::empty().into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response.headers_mut().insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&content_length.to_string()).map_err(|_| {
            ApiError::Validation("invalid legacy backup response length".to_string())
        })?,
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(guard_bounded_bytes_response_with_total_deadline(
        response,
        encoded,
        (stream_permit, backup_work),
        Duration::from_secs(30 * 60),
    ))
}
use std::time::Duration;
