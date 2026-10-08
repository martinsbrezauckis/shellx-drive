//! Bounded archive issuance for public folder shares.

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};
use serde::{Deserialize, Serialize};

use crate::{
    error::{ApiError, ApiResult},
    model::FileKind,
    public_client_binding::{self, PublicClientBinding},
    server::{request_client_fingerprint, AppState},
    streaming_zip::{self, MAX_ARCHIVE_SELECTIONS},
};

use super::{
    access::{authorize_share_read, load_public_share_for_claimed_access},
    request_helpers::share_access_token_from_request,
};

const SHARE_ARCHIVES_PER_MINUTE: i64 = 12;

#[derive(Debug, Deserialize)]
pub(super) struct PublicBulkDownloadRequest {
    #[serde(default)]
    base_path: String,
    paths: Vec<String>,
}

#[derive(Serialize)]
pub(super) struct PreparedDownload {
    download_url: String,
    expires_in_seconds: u64,
}

pub(super) async fn public_share_bulk_download(
    State(state): State<AppState>,
    Path(share_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<PublicBulkDownloadRequest>,
) -> ApiResult<Response> {
    if request.paths.is_empty() {
        return Err(ApiError::Validation(
            "select at least one item to download".to_string(),
        ));
    }
    if request.paths.len() > MAX_ARCHIVE_SELECTIONS {
        return Err(ApiError::PayloadTooLarge(format!(
            "select no more than {MAX_ARCHIVE_SELECTIONS} items at once"
        )));
    }
    let (record, target) = load_public_share_for_claimed_access(&state, &share_id, &headers)?;
    authorize_share_read(&state, &share_id, &record, &headers).await?;
    if !record.share.allow_download {
        return Err(ApiError::Forbidden);
    }
    if !matches!(target.kind, FileKind::Folder) {
        return Err(ApiError::Validation(
            "bulk download requires a shared folder".to_string(),
        ));
    }

    state.storage.consume_partitioned_public_rate_limit(
        &target.workspace_id,
        "share_archive",
        request_client_fingerprint(&headers),
        SHARE_ARCHIVES_PER_MINUTE,
        60,
    )?;
    let planning_permit = state
        .archive_tickets
        .try_acquire_planner_for_share(&share_id, &target.workspace_id)?;
    let storage = state.storage.clone();
    let target_id = target.id.clone();
    let base_path = request.base_path.trim().to_string();
    let selected_paths = request.paths;
    let (nodes, _planning_permit) = state
        .run_metadata_planning(&format!("share:{share_id}"), move || {
            let nodes = storage.share_archive_nodes(&target_id, &base_path, &selected_paths)?;
            Ok((nodes, planning_permit))
        })
        .await?;
    let source_file_ids = nodes.iter().map(|(_, file)| file.id.clone()).collect();
    let mut entries = streaming_zip::entries_from_nodes(&state.data_dir(), nodes)?;
    streaming_zip::validate_entries(&mut entries).await?;
    let folder_name = request
        .base_path
        .trim()
        .rsplit_once('/')
        .map(|(_, name)| name)
        .filter(|name| !name.is_empty())
        .or_else(|| (!request.base_path.trim().is_empty()).then_some(request.base_path.trim()))
        .unwrap_or(&target.name);
    let client_binding = response_client_binding(&state, &headers)?;
    let ticket = state.archive_tickets.issue_for_share(
        entries,
        format!("{folder_name}-selection"),
        streaming_zip::PublicShareArchiveSource {
            share_id: share_id.clone(),
            share_root_id: target.id.clone(),
            workspace_id: target.workspace_id.clone(),
            authorization_fingerprint: record.authorization_fingerprint(),
            source_file_ids,
        },
        client_binding.fingerprint().to_string(),
    )?;
    state.storage.record_unlimited_share_access(&share_id)?;
    state
        .storage
        .insert_receipt("share.bulk_download", "public", Some(&share_id))?;
    let mut response = Json(PreparedDownload {
        download_url: format!("/downloads/{ticket}"),
        expires_in_seconds: streaming_zip::DOWNLOAD_TICKET_TTL_SECONDS,
    })
    .into_response();
    client_binding.apply_cookie(response.headers_mut());
    Ok(response)
}

fn response_client_binding(
    state: &AppState,
    headers: &HeaderMap,
) -> ApiResult<PublicClientBinding> {
    if share_access_token_from_request(headers).is_some() {
        public_client_binding::require_binding(state, headers)
    } else {
        public_client_binding::provision(state, headers)
    }
}
