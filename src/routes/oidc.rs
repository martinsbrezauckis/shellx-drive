use axum::{
    extract::State,
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use chrono::{Duration, Utc};
use uuid::Uuid;

use crate::{
    auth::{mint_sso_token, normalize_user_email, require_admin_with_credential, token_hash},
    error::{ApiError, ApiResult},
    model::{OidcConfigResponse, OidcExchangeRequest, OidcExchangeResponse},
    server::AppState,
};

const MAX_EXPIRES_IN_SECONDS: i64 = 28_800;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/oidc/config", get(oidc_config))
        .route("/auth/oidc/exchange", post(oidc_exchange))
}

async fn oidc_config() -> Json<OidcConfigResponse> {
    Json(OidcConfigResponse {
        enabled: true,
        flow: "verified_claim_exchange".to_string(),
        token_type: "sso.v1".to_string(),
        max_expires_in_seconds: MAX_EXPIRES_IN_SECONDS,
    })
}

async fn oidc_exchange(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<OidcExchangeRequest>,
) -> ApiResult<Json<OidcExchangeResponse>> {
    let (admin_actor, source_credential) = require_admin_with_credential(&state, &headers)?;

    let email = normalize_user_email(&request.email)?;
    let issuer = request.issuer.trim();
    let subject = request.subject.trim();
    if issuer.is_empty() || subject.is_empty() {
        return Err(ApiError::Validation(
            "email, issuer, and subject must not be empty".to_string(),
        ));
    }

    let expires_in = request
        .expires_in_seconds
        .unwrap_or(3600)
        .clamp(60, MAX_EXPIRES_IN_SECONDS);
    let expires_at = Utc::now() + Duration::seconds(expires_in);
    let session_id = Uuid::now_v7().to_string();
    let sso_token = mint_sso_token(
        &session_id,
        &email,
        issuer,
        subject,
        expires_at.timestamp(),
        &state.config.token,
    )?;
    let session = state.storage.record_pending_auth_session_publication(
        &session_id,
        &email,
        issuer,
        subject,
        &token_hash(&sso_token),
        &expires_at.to_rfc3339(),
        &admin_actor,
        &source_credential,
    )?;
    state
        .storage
        .publish_pending_auth_session(&session.id, &admin_actor, &source_credential)?;

    Ok(Json(OidcExchangeResponse {
        token_type: "Bearer".to_string(),
        sso_token,
        session_id,
        actor: email,
        issuer: issuer.to_string(),
        subject: subject.to_string(),
        expires_at: expires_at.to_rfc3339(),
    }))
}
