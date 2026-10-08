//! Password and signed-grant authorization for public Drop workflows.

use axum::http::HeaderMap;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{DateTime, Utc};

use crate::{
    drop_access_tokens,
    error::{ApiError, ApiResult},
    public_client_binding::{self, PublicClientBinding},
    server::{request_client_fingerprint, AppState},
    storage::{DropRecord, PublicCapabilityKind},
};

const DROP_REQUESTS_PER_MINUTE: i64 = 600;
const DROP_PASSWORD_HEADER: &str = "x-shellx-drop-password-b64";
const DROP_ACCESS_TOKEN_HEADER: &str = "x-shellx-drop-access-token";

pub(super) async fn authenticate_drop(
    state: &AppState,
    drop_id: &str,
    headers: &HeaderMap,
) -> ApiResult<(DropRecord, PublicClientBinding)> {
    let (record, client_fingerprint) = load_drop_request(state, drop_id, headers)?;
    if let Some(access_token) = read_drop_access_token(headers) {
        let client_binding = public_client_binding::require_binding(state, headers)?;
        drop_access_tokens::verify(
            access_token,
            drop_id,
            &record.authorization_fingerprint(),
            client_binding.fingerprint(),
            &state.config.token,
            Utc::now().timestamp(),
        )?;
        Ok((record, client_binding))
    } else {
        verify_drop_password(state, drop_id, &record, headers, client_fingerprint).await?;
        Ok((record, public_client_binding::provision(state, headers)?))
    }
}

pub(super) fn load_drop_request<'a>(
    state: &AppState,
    drop_id: &str,
    headers: &'a HeaderMap,
) -> ApiResult<(DropRecord, &'a str)> {
    let client_fingerprint = request_client_fingerprint(headers);
    let record = state.storage.get_drop(drop_id)?.ok_or(ApiError::NotFound)?;
    ensure_drop_active(&record)?;
    state.storage.consume_partitioned_public_rate_limit(
        drop_id,
        "drop_upload_request",
        client_fingerprint,
        DROP_REQUESTS_PER_MINUTE,
        60,
    )?;
    Ok((record, client_fingerprint))
}

pub(super) async fn verify_drop_password(
    state: &AppState,
    drop_id: &str,
    record: &DropRecord,
    headers: &HeaderMap,
    client_fingerprint: &str,
) -> ApiResult<()> {
    let password = read_drop_password(headers).ok();
    let (password_valid, attempt) = state
        .verify_public_capability_password(
            PublicCapabilityKind::Drop,
            drop_id,
            &record.password_hash,
            password.as_deref(),
            client_fingerprint,
        )
        .await?;
    if !password_valid {
        record_public_failure(state, drop_id, attempt.locked_out)?;
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

pub(super) fn ensure_drop_active(record: &DropRecord) -> ApiResult<()> {
    if record.drop.revoked || is_expired(&record.drop.expires_at) {
        Err(ApiError::NotFound)
    } else {
        Ok(())
    }
}

fn read_drop_password(headers: &HeaderMap) -> ApiResult<String> {
    let encoded = headers
        .get(DROP_PASSWORD_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or(ApiError::Forbidden)?;
    let bytes = STANDARD.decode(encoded).map_err(|_| ApiError::Forbidden)?;
    if bytes.len() > 1024 {
        return Err(ApiError::Forbidden);
    }
    String::from_utf8(bytes).map_err(|_| ApiError::Forbidden)
}

fn read_drop_access_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(DROP_ACCESS_TOKEN_HEADER)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn record_public_failure(state: &AppState, drop_id: &str, locked_out: bool) -> ApiResult<()> {
    state
        .storage
        .insert_receipt("drop.upload_denied", "public", Some(drop_id))?;
    if locked_out {
        state
            .storage
            .insert_receipt("drop.upload_lockout", "public", Some(drop_id))?;
    }
    Ok(())
}

fn is_expired(expires_at: &str) -> bool {
    DateTime::parse_from_rfc3339(expires_at)
        .map(|dt| dt.with_timezone(&Utc) < Utc::now())
        .unwrap_or(true)
}
