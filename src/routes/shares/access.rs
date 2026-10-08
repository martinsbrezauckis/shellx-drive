//! Capability resolution and authorization for public-share reads.

use crate::{
    auth::constant_time_str_eq,
    download_subjects::CurrentFileSubject,
    error::{ApiError, ApiResult},
    model::{DriveFile, FileKind},
    server::{request_client_fingerprint, AppState},
    storage::ShareRecord,
};
use axum::http::HeaderMap;

use super::request_helpers::{is_expired, share_access_token_from_request};

mod authorization;

pub(super) use authorization::{authorize_share_read, verify_share_password};

const SHARE_FOLDER_RESOLUTIONS_PER_WORKSPACE_CLIENT_PER_MINUTE: i64 = 32;

pub(in crate::routes) fn load_public_share(
    state: &AppState,
    share_id: &str,
) -> ApiResult<(ShareRecord, DriveFile)> {
    load_public_share_inner(state, share_id, false)
}

/// Load a public Share for a follow-up request that presents a durable access
/// grant. The grant is validated immediately by `authorize_share_read`; only
/// that already-claimed final use may proceed after the public link itself is
/// exhausted.
pub(in crate::routes) fn load_public_share_for_claimed_access(
    state: &AppState,
    share_id: &str,
    headers: &HeaderMap,
) -> ApiResult<(ShareRecord, DriveFile)> {
    load_public_share_inner(
        state,
        share_id,
        share_access_token_from_request(headers).is_some(),
    )
}

fn load_public_share_inner(
    state: &AppState,
    share_id: &str,
    allow_claimed_final_use: bool,
) -> ApiResult<(ShareRecord, DriveFile)> {
    let record = state
        .storage
        .get_share(share_id)?
        .ok_or(ApiError::NotFound)?;
    if record.share.revoked
        || is_expired(record.share.expires_at.as_deref())
        || (record.share.uses_remaining == Some(0) && !allow_claimed_final_use)
    {
        return Err(ApiError::NotFound);
    }
    let target = state
        .storage
        .get_file_unaggregated(&record.share.file_id)?
        .ok_or(ApiError::NotFound)?;
    if state.storage.file_is_effectively_trashed(&target.id)? {
        return Err(ApiError::NotFound);
    }
    Ok((record, target))
}

/// Recheck the live Share and immutable selected body immediately before a
/// direct response is opened. This deliberately does not claim access again:
/// a finite visit may already have consumed its final allowed use.
pub(super) fn revalidate_share_file_publication(
    state: &AppState,
    share_id: &str,
    expected_root_id: &str,
    expected_authorization_fingerprint: &str,
    subject: &CurrentFileSubject,
) -> ApiResult<(ShareRecord, DriveFile)> {
    let record = state
        .storage
        .get_share(share_id)?
        .ok_or(ApiError::NotFound)?;
    if record.share.revoked
        || is_expired(record.share.expires_at.as_deref())
        || record.share.file_id != expected_root_id
        || !constant_time_str_eq(
            expected_authorization_fingerprint,
            &record.authorization_fingerprint(),
        )
        || state
            .storage
            .file_is_effectively_trashed(expected_root_id)?
    {
        return Err(ApiError::NotFound);
    }
    state.storage.ensure_share_file_ticket_authorized(
        expected_root_id,
        &subject.file_id,
        subject,
    )?;
    let file = state
        .storage
        .get_file_unaggregated(&subject.file_id)?
        .ok_or(ApiError::NotFound)?;
    Ok((record, file))
}

/// Resolve a capability to one concrete file without reading its body. Content
/// and thumbnail requests share this lookup so their folder-subtree boundary is
/// structurally identical.
pub(super) async fn resolve_share_file(
    state: &AppState,
    share_id: &str,
    headers: &HeaderMap,
    target: &DriveFile,
    path: Option<&str>,
) -> ApiResult<DriveFile> {
    if matches!(target.kind, FileKind::File) {
        return Ok(target.clone());
    }
    let rel = path
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ApiError::Validation(
                "folder share requires a file path (?path=) inside the shared folder".to_string(),
            )
        })?
        .to_string();
    state.storage.consume_partitioned_public_rate_limit(
        &target.workspace_id,
        "share_folder_resolution",
        request_client_fingerprint(headers),
        SHARE_FOLDER_RESOLUTIONS_PER_WORKSPACE_CLIENT_PER_MINUTE,
        60,
    )?;
    let storage = state.storage.clone();
    let target_id = target.id.clone();
    state
        .run_metadata_planning(&format!("share:{share_id}"), move || {
            storage.share_folder_content(&target_id, &rel)
        })
        .await
}
