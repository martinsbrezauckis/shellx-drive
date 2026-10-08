use axum::http::HeaderMap;
use chrono::Utc;

use crate::{
    error::{ApiError, ApiResult},
    public_client_binding,
    server::{request_client_fingerprint, AppState},
    share_access_tokens,
    storage::{PublicCapabilityKind, ShareRecord},
};

use super::super::request_helpers::{share_access_token_from_request, share_password_from_request};

/// Verify a share's link password against the shared per-share throttle and
/// lockout. Success deliberately leaves the pre-Argon work allowance intact.
pub(in crate::routes::shares) async fn verify_share_password(
    state: &AppState,
    share_id: &str,
    record: &ShareRecord,
    supplied: Option<&str>,
    fail_status: ApiError,
    client_fingerprint: &str,
) -> ApiResult<()> {
    if !record.password_required {
        return Ok(());
    }
    let (verified, attempt) = state
        .verify_public_capability_password(
            PublicCapabilityKind::Share,
            share_id,
            &record.password_hash,
            supplied,
            client_fingerprint,
        )
        .await?;
    if !verified {
        record_public_failure(
            state,
            share_id,
            "share.access_denied",
            "share.access_lockout",
            attempt.locked_out,
        )?;
        return Err(fail_status);
    }
    Ok(())
}

/// Prefer a short-lived metadata proof so one guest page can load many assets
/// without repeating Argon2 work. Finite links retain their durable grant.
pub(in crate::routes::shares) async fn authorize_share_read(
    state: &AppState,
    share_id: &str,
    record: &ShareRecord,
    headers: &HeaderMap,
) -> ApiResult<()> {
    if let Some(access_token) = share_access_token_from_request(headers) {
        let client_binding = public_client_binding::require(state, headers)?;
        if record.share.max_uses.is_none() {
            share_access_tokens::verify(
                access_token,
                share_id,
                &record.authorization_fingerprint(),
                &client_binding,
                &state.config.token,
                Utc::now().timestamp(),
            )?;
            return state.storage.validate_unlimited_share_authorization(
                share_id,
                &record.authorization_fingerprint(),
            );
        }
        return state.storage.validate_share_access_grant(
            share_id,
            Some(access_token),
            &client_binding,
        );
    }
    verify_share_password(
        state,
        share_id,
        record,
        share_password_from_request(headers),
        ApiError::Unauthenticated,
        request_client_fingerprint(headers),
    )
    .await?;
    state
        .storage
        .validate_unlimited_share_authorization(share_id, &record.authorization_fingerprint())
}

fn record_public_failure(
    state: &AppState,
    resource_id: &str,
    denied_receipt: &str,
    lockout_receipt: &str,
    locked_out: bool,
) -> ApiResult<()> {
    state
        .storage
        .insert_receipt(denied_receipt, "public", Some(resource_id))?;
    if locked_out {
        state
            .storage
            .insert_receipt(lockout_receipt, "public", Some(resource_id))?;
    }
    Ok(())
}
