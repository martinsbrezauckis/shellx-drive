//! Bounded machine-readable metadata for public shares.

use crate::{
    error::{ApiError, ApiResult},
    model::{DriveFile, FileKind},
    public_client_binding,
    server::{request_client_fingerprint, AppState},
    storage::ShareRecord,
};
use axum::{
    body::Body,
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};

use super::{
    access::verify_share_password,
    request_helpers::{share_password_from_request, share_password_supplied},
};

const SHARE_METADATA_REQUESTS_PER_MINUTE: i64 = 60;
const MAX_PUBLIC_SHARE_METADATA_BYTES: usize = 8 * 1024 * 1024;

mod publication;
mod response;
#[cfg(test)]
mod tests;

use publication::MetadataPublication;
use response::bounded_metadata_response;

pub(super) async fn public_share_metadata(
    state: &AppState,
    share_id: &str,
    record: &ShareRecord,
    target: &DriveFile,
    headers: &HeaderMap,
) -> ApiResult<Response> {
    let requires_password = record.password_required;
    let supplied_password = share_password_supplied(headers);
    if requires_password && supplied_password {
        let supplied = share_password_from_request(headers);
        verify_share_password(
            state,
            share_id,
            record,
            supplied,
            ApiError::Unauthenticated,
            request_client_fingerprint(headers),
        )
        .await?;
    }
    if requires_password && !supplied_password {
        return Ok(Json(serde_json::json!({ "requires_password": true })).into_response());
    }
    state.storage.consume_partitioned_public_rate_limit(
        share_id,
        "share_metadata",
        request_client_fingerprint(headers),
        SHARE_METADATA_REQUESTS_PER_MINUTE,
        60,
    )?;
    let stream_permit =
        state.try_public_body_stream(share_id, request_client_fingerprint(headers))?;
    let (entries, metadata_subjects) = if matches!(target.kind, FileKind::Folder) {
        let storage = state.storage.clone();
        let target_id = target.id.clone();
        let (entries, subjects) = state
            .run_metadata_planning(&format!("share:{share_id}"), move || {
                storage.share_folder_entries_with_subjects(&target_id)
            })
            .await?;
        (Some(entries), subjects)
    } else {
        (None, Vec::new())
    };
    let folder_size_bytes = if let Some(entries) = entries.as_ref() {
        Some(entries.iter().try_fold(0_i64, |total, entry| {
            total
                .checked_add(entry.size_bytes.unwrap_or(0))
                .ok_or_else(|| ApiError::Validation("shared folder size overflow".to_string()))
        })?)
    } else {
        target.folder_size_bytes
    };
    let client_binding = public_client_binding::provision(state, headers)?;
    // Re-check the exact planned root/subtree and claim a visit together in
    // one immediate transaction.  This is a second fail-fast planning lane:
    // the terminal bounded tree walk runs off Tokio and cannot monopolize the
    // SQLite connection outside metadata admission.
    let terminal_storage = state.storage.clone();
    let terminal_share_id = share_id.to_string();
    let terminal_fingerprint = record.authorization_fingerprint();
    let terminal_client_fingerprint = client_binding.fingerprint().to_string();
    let terminal_target = target.clone();
    let publication = MetadataPublication {
        target: target.clone(),
        entries,
        folder_size_bytes,
        requires_password,
        share_id: share_id.to_string(),
        authorization_fingerprint: terminal_fingerprint.clone(),
        client_fingerprint: terminal_client_fingerprint.clone(),
        signing_secret: state.config.token.clone(),
    };
    let (_, metadata_bytes) = state
        .run_metadata_planning(&format!("share:{share_id}"), move || {
            terminal_storage.claim_share_metadata_access_with(
                &terminal_share_id,
                &terminal_fingerprint,
                &terminal_client_fingerprint,
                &terminal_target,
                &metadata_subjects,
                |claimed| publication.encode(claimed),
            )
        })
        .await?;
    let mut response = Body::empty().into_response();
    client_binding.apply_cookie(response.headers_mut());
    bounded_metadata_response(response, metadata_bytes, stream_permit)
}
