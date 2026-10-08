//! Exchange a valid Drop password for a short-lived client-bound grant.

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;

use crate::{
    auth::constant_time_str_eq,
    drop_access_tokens,
    error::{ApiError, ApiResult},
    model::PublicDropAccessGrant,
    public_client_binding,
    server::AppState,
    storage::DropRecord,
};

use super::auth::{ensure_drop_active, load_drop_request, verify_drop_password};

/// Later writes reload the Drop and bind this grant to live authorization.
pub(super) async fn preflight(
    State(state): State<AppState>,
    Path(drop_id): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let (record, client_fingerprint) = load_drop_request(&state, &drop_id, &headers)?;
    verify_drop_password(&state, &drop_id, &record, &headers, client_fingerprint).await?;
    // Argon2 yields: a rotation or revocation may commit during verification.
    let client_binding = public_client_binding::provision(&state, &headers)?;
    let expires_at = Utc::now()
        .timestamp()
        .saturating_add(drop_access_tokens::TTL_SECONDS);
    let (access_token, name) = state
        .storage
        .with_current_drop_record(&drop_id, |current| {
            let current = current_drop_after_password(&record, || Ok(current))?;
            let access_token = drop_access_tokens::mint(
                &drop_id,
                &current.authorization_fingerprint(),
                client_binding.fingerprint(),
                expires_at,
                &state.config.token,
            )?;
            Ok((access_token, current.drop.name))
        })?;
    let mut response = Json(PublicDropAccessGrant {
        access_token,
        expires_at,
        name,
    })
    .into_response();
    client_binding.apply_cookie(response.headers_mut());
    Ok(response)
}

fn current_drop_after_password(
    verified: &DropRecord,
    reload: impl FnOnce() -> ApiResult<Option<DropRecord>>,
) -> ApiResult<DropRecord> {
    let current = reload()?.ok_or(ApiError::NotFound)?;
    ensure_drop_active(&current)?;
    if !constant_time_str_eq(
        &verified.authorization_fingerprint(),
        &current.authorization_fingerprint(),
    ) {
        return Err(ApiError::Forbidden);
    }
    Ok(current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::DropLink;

    fn record(hash: &str) -> DropRecord {
        DropRecord {
            drop: DropLink {
                id: "drop-race".into(),
                workspace_id: "workspace".into(),
                name: "Inbox".into(),
                inbox_file_id: None,
                expires_at: (Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
                revoked: false,
                created_at: Utc::now().to_rfc3339(),
                upload_count: 0,
                last_uploaded_at: None,
            },
            password_hash: hash.into(),
            password_required: true,
        }
    }

    #[test]
    fn preflight_reloads_after_password_check_and_rejects_rotation_or_revocation() {
        let verified = record("old-argon2-hash");
        let rotated = record("new-argon2-hash");
        assert!(matches!(
            current_drop_after_password(&verified, || Ok(Some(rotated))),
            Err(ApiError::Forbidden)
        ));
        let mut revoked = record("old-argon2-hash");
        revoked.drop.revoked = true;
        assert!(matches!(
            current_drop_after_password(&verified, || Ok(Some(revoked))),
            Err(ApiError::NotFound)
        ));
        assert!(matches!(
            current_drop_after_password(&verified, || Ok(None)),
            Err(ApiError::NotFound)
        ));
        let mut expired = record("old-argon2-hash");
        expired.drop.expires_at = (Utc::now() - chrono::Duration::seconds(1)).to_rfc3339();
        assert!(matches!(
            current_drop_after_password(&verified, || Ok(Some(expired))),
            Err(ApiError::NotFound)
        ));
    }
}
