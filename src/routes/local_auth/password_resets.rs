use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::post,
    Json, Router,
};
use chrono::{Duration, Utc};

use crate::{
    auth::{normalize_email, random_secret_token, require_admin_with_credential, token_hash},
    error::{ApiError, ApiResult},
    model::{
        AdminPasswordResetLinkRequest, AdminPasswordResetLinkResponse,
        AdminPasswordResetLinkRevocationResponse, PasswordResetConsumeRequest,
        PasswordResetRequest, PasswordResetResponse,
    },
    server::{request_client_fingerprint, AppState},
};

const PASSWORD_RESET_REQUESTS_PER_15_MINUTES: i64 = 5;
const PASSWORD_RESET_CONSUMES_PER_15_MINUTES: i64 = 10;
const ADMIN_RESET_LINK_DEFAULT_SECONDS: i64 = 60 * 60;
const ADMIN_RESET_LINK_MIN_SECONDS: i64 = 5 * 60;
const ADMIN_RESET_LINK_MAX_SECONDS: i64 = 24 * 60 * 60;

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/password/reset/request", post(request_password_reset))
        .route("/auth/password/reset/consume", post(consume_password_reset))
        .route(
            "/admin/auth/users/{email}/password-reset-link",
            post(create_admin_password_reset_link).delete(revoke_admin_password_reset_link),
        )
}

/// Requesting a reset remains non-enumerating and never sends a plaintext
/// capability to an unauthenticated caller. Capture transport is a queue, not
/// delivery; a server administrator can instead create a short-lived manual
/// link through the authenticated route below.
async fn request_password_reset(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PasswordResetRequest>,
) -> ApiResult<(StatusCode, Json<PasswordResetResponse>)> {
    let email = normalize_email(&request.email)?;
    let client_fingerprint = request_client_fingerprint(&headers);
    state.storage.consume_partitioned_public_rate_limit(
        "password-reset",
        "password_reset_client",
        client_fingerprint,
        PASSWORD_RESET_REQUESTS_PER_15_MINUTES,
        900,
    )?;
    state.storage.consume_partitioned_fixed_window_rate_limit(
        &email,
        "password_reset_email",
        "all-clients",
        PASSWORD_RESET_REQUESTS_PER_15_MINUTES,
        900,
    )?;
    let mut debug_token = None;
    if let Some(account) = state.storage.get_auth_account(&email)? {
        if !account.disabled {
            let token = random_secret_token();
            let expires_at = (Utc::now() + Duration::hours(1)).to_rfc3339();
            let reset_url = format!(
                "{}#token={token}",
                state
                    .config
                    .public_origin
                    .application_route("/reset-password")
            );
            let email_body =
                format!("Use this ShellX Drive password reset link before it expires: {reset_url}");
            let created = match state
                .storage
                .create_password_reset_token_and_email_if_none_active(
                    &email,
                    &token_hash(&token),
                    &expires_at,
                    "Reset your ShellX Drive password",
                    &email_body,
                ) {
                Ok(created) => created,
                // Preserve generic public behavior when the protected mail
                // reserve is full. The storage transaction rolls back the
                // reset token along with its rejected outbox insert.
                Err(ApiError::TooManyRequests) => false,
                Err(error) => return Err(error),
            };
            if !created {
                return Ok((
                    StatusCode::ACCEPTED,
                    Json(PasswordResetResponse {
                        queued: true,
                        debug_token: None,
                        account: None,
                        receipt: None,
                    }),
                ));
            }
            // E2E-only compatibility: retained for existing isolated test
            // harnesses, and still requires a current administrator
            // credential. Production never exposes this token from the
            // requester route.
            if state.config.e2e_enabled {
                if let Ok((actor, source_credential)) =
                    require_admin_with_credential(&state, &headers)
                {
                    let reset_token_hash = token_hash(&token);
                    if state
                        .storage
                        .create_password_reset_debug_publication_intent(
                            &email,
                            &reset_token_hash,
                            &actor,
                            &source_credential,
                        )
                        .is_ok()
                    {
                        debug_token = Some(token);
                    }
                }
            }
        }
    }
    Ok((
        StatusCode::ACCEPTED,
        Json(PasswordResetResponse {
            queued: true,
            debug_token,
            account: None,
            receipt: None,
        }),
    ))
}

async fn consume_password_reset(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PasswordResetConsumeRequest>,
) -> ApiResult<Json<PasswordResetResponse>> {
    let client_fingerprint = request_client_fingerprint(&headers);
    state.storage.consume_partitioned_public_rate_limit(
        "password-reset-consume",
        "password_reset_consume_client",
        client_fingerprint,
        PASSWORD_RESET_CONSUMES_PER_15_MINUTES,
        900,
    )?;
    if request.token.len() != 64 || !request.token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ApiError::Validation(
            "password reset token is invalid or expired".to_string(),
        ));
    }
    let reset_token_hash = token_hash(&request.token);
    if !state
        .storage
        .password_reset_token_is_active(&reset_token_hash)?
    {
        return Err(ApiError::Validation(
            "password reset token is invalid or expired".to_string(),
        ));
    }
    let password_hash = state
        .hash_untrusted_account_password(&request.new_password)
        .await?;
    let (account, receipt) = state
        .storage
        .consume_password_reset_token(&reset_token_hash, &password_hash)?;
    Ok(Json(PasswordResetResponse {
        queued: false,
        debug_token: None,
        account: Some(account),
        receipt: Some(receipt),
    }))
}

async fn create_admin_password_reset_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(email): Path<String>,
    Json(request): Json<AdminPasswordResetLinkRequest>,
) -> ApiResult<(StatusCode, Json<AdminPasswordResetLinkResponse>)> {
    let (admin, source_credential) = require_admin_with_credential(&state, &headers)?;
    let email = normalize_email(&email)?;
    let expires_in_seconds = request
        .expires_in_seconds
        .unwrap_or(ADMIN_RESET_LINK_DEFAULT_SECONDS);
    if !(ADMIN_RESET_LINK_MIN_SECONDS..=ADMIN_RESET_LINK_MAX_SECONDS).contains(&expires_in_seconds)
    {
        return Err(ApiError::Validation(format!(
            "expires_in_seconds must be between {ADMIN_RESET_LINK_MIN_SECONDS} and {ADMIN_RESET_LINK_MAX_SECONDS}"
        )));
    }
    let token = random_secret_token();
    let expires_at = (Utc::now() + Duration::seconds(expires_in_seconds)).to_rfc3339();
    let receipt = state.storage.create_admin_password_reset_link(
        &email,
        &token_hash(&token),
        &expires_at,
        &admin,
        &source_credential,
    )?;
    let reset_link = format!(
        "{}#token={token}",
        state
            .config
            .public_origin
            .application_route("/reset-password")
    );
    Ok((
        StatusCode::CREATED,
        Json(AdminPasswordResetLinkResponse {
            reset_link,
            expires_at,
            receipt,
        }),
    ))
}

async fn revoke_admin_password_reset_link(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(email): Path<String>,
) -> ApiResult<Json<AdminPasswordResetLinkRevocationResponse>> {
    let (admin, source_credential) = require_admin_with_credential(&state, &headers)?;
    let email = normalize_email(&email)?;
    let receipt =
        state
            .storage
            .revoke_admin_password_reset_link(&email, &admin, &source_credential)?;
    Ok(Json(AdminPasswordResetLinkRevocationResponse {
        revoked: true,
        receipt,
    }))
}
