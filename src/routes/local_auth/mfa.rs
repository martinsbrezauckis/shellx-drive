use axum::{
    extract::{Extension, State},
    http::{header, HeaderMap},
    response::{IntoResponse, Response},
    Json,
};
use chrono::Utc;
use serde::Serialize;

use super::{
    record_auth_failure, require_account_actor,
    second_factor::{validate_second_factor_evidence, validate_second_factor_throttled},
    session_rotation::PreparedLocalSessionRotation,
};
use crate::{
    auth::{
        explicit_bearer_token, generate_recovery_codes, generate_totp_secret, recovery_code_hash,
    },
    error::{ApiError, ApiResult},
    model::{
        RecoveryCodesResponse, TotpCodeRequest, TotpDisableResponse, TotpSetupRequest,
        TotpSetupResponse,
    },
    server::{request_client_fingerprint, AppState, ClientRequestMetadata},
    storage::VerifiedLocalSecondFactor,
    totp_qr,
};

const TOTP_SETUP_ATTEMPTS_PER_15_MINUTES: i64 = 10;
const TOTP_SECURITY_MUTATIONS_PER_15_MINUTES: i64 = 10;

pub(super) async fn setup_totp(
    State(state): State<AppState>,
    Extension(client): Extension<ClientRequestMetadata>,
    headers: HeaderMap,
    Json(request): Json<TotpSetupRequest>,
) -> ApiResult<Response> {
    let (actor, source_credential) = require_account_actor(&state, &headers)?;
    let client_fingerprint = request_client_fingerprint(&headers);
    state.storage.consume_partitioned_public_rate_limit(
        &actor.email,
        "totp_setup",
        "account",
        TOTP_SETUP_ATTEMPTS_PER_15_MINUTES,
        900,
    )?;
    state.storage.ensure_auth_attempt_not_locked(
        Some(&actor.email),
        "totp_setup_password",
        client_fingerprint,
        Utc::now().timestamp(),
    )?;
    let mut account = state
        .storage
        .get_auth_account_secret(&actor.email)?
        .ok_or(ApiError::Unauthenticated)?;
    let mut second_factor = VerifiedLocalSecondFactor::NotRequired;
    if !state
        .verify_account_password(&account.password_hash, &request.password)
        .await?
    {
        record_auth_failure(
            &state,
            &actor.email,
            "totp_setup_password",
            client_fingerprint,
        )?;
        return Err(ApiError::Unauthenticated);
    }
    state.storage.clear_auth_attempt(
        Some(&actor.email),
        "totp_setup_password",
        client_fingerprint,
    )?;
    if account.totp_enabled {
        let validated = validate_second_factor_evidence(
            &state,
            &actor.email,
            request.code.as_deref(),
            request.recovery_code.as_deref(),
            true,
        )?;
        second_factor = validated.credential;
        account = validated.account;
    }
    let secret = generate_totp_secret();
    // Encode and validate the disclosure before rotating security state. An
    // encoder failure must leave the current factor/session untouched.
    let (otpauth_uri, qr) = totp_qr::preflight(&secret, &actor.email)?;
    let replacement = PreparedLocalSessionRotation::for_source_credential(
        &state,
        &account,
        &client,
        &source_credential,
    )?;
    let rotation = replacement.rotation(&actor, &source_credential);
    state.storage.update_totp_secret(
        &actor.email,
        &secret,
        account.security_version,
        second_factor,
        &rotation,
    )?;
    state
        .storage
        .insert_receipt("auth.2fa.setup", &actor.email, Some(&actor.email))?;
    let explicit_bearer = explicit_bearer_token(&headers).is_some();
    let body = TotpSetupResponse {
        otpauth_uri,
        secret,
        qr_size: qr.size,
        qr_modules: qr.modules,
        replacement: replacement.response(explicit_bearer),
    };
    Ok(rotated_json(&state, &replacement, body, explicit_bearer))
}

pub(super) async fn enable_totp(
    State(state): State<AppState>,
    Extension(client): Extension<ClientRequestMetadata>,
    headers: HeaderMap,
    Json(request): Json<TotpCodeRequest>,
) -> ApiResult<Response> {
    let (actor, source_credential) = require_account_actor(&state, &headers)?;
    consume_mutation_budget(&state, &actor.email)?;
    let current = state
        .storage
        .get_auth_account_secret(&actor.email)?
        .ok_or(ApiError::Unauthenticated)?;
    if current.totp_enabled {
        return Err(ApiError::Conflict);
    }
    let validated = validate_second_factor_throttled(
        &state,
        &actor.email,
        request.code.as_deref(),
        None,
        false,
        request_client_fingerprint(&headers),
    )?;
    let recovery_codes = generate_recovery_codes();
    let hashes = recovery_codes
        .iter()
        .map(|code| recovery_code_hash(code))
        .collect::<Vec<_>>();
    let replacement = PreparedLocalSessionRotation::for_source_credential(
        &state,
        &validated.account,
        &client,
        &source_credential,
    )?;
    let rotation = replacement.rotation(&actor, &source_credential);
    state.storage.enable_totp(
        &actor.email,
        &hashes,
        validated.account.security_version,
        validated.credential,
        &rotation,
    )?;
    state
        .storage
        .insert_receipt("auth.2fa.enable", &actor.email, Some(&actor.email))?;
    let explicit_bearer = explicit_bearer_token(&headers).is_some();
    let body = RecoveryCodesResponse {
        recovery_codes,
        replacement: replacement.response(explicit_bearer),
    };
    Ok(rotated_json(&state, &replacement, body, explicit_bearer))
}

pub(super) async fn disable_totp(
    State(state): State<AppState>,
    Extension(client): Extension<ClientRequestMetadata>,
    headers: HeaderMap,
    Json(request): Json<TotpCodeRequest>,
) -> ApiResult<Response> {
    let (actor, source_credential) = require_account_actor(&state, &headers)?;
    consume_mutation_budget(&state, &actor.email)?;
    let mut account = state
        .storage
        .get_auth_account_secret(&actor.email)?
        .ok_or(ApiError::Unauthenticated)?;
    if let Some(password) = request.password.as_deref() {
        if !state
            .verify_account_password(&account.password_hash, password)
            .await?
        {
            return Err(ApiError::Unauthenticated);
        }
    }
    let mut second_factor = VerifiedLocalSecondFactor::NotRequired;
    if account.totp_enabled {
        let validated = validate_second_factor_throttled(
            &state,
            &actor.email,
            request.code.as_deref(),
            request.recovery_code.as_deref(),
            true,
            request_client_fingerprint(&headers),
        )?;
        second_factor = validated.credential;
        account = validated.account;
    }
    let replacement = PreparedLocalSessionRotation::for_source_credential(
        &state,
        &account,
        &client,
        &source_credential,
    )?;
    let rotation = replacement.rotation(&actor, &source_credential);
    let account = state.storage.disable_totp(
        &actor.email,
        account.security_version,
        second_factor,
        &rotation,
    )?;
    state
        .storage
        .insert_receipt("auth.2fa.disable", &actor.email, Some(&actor.email))?;
    let explicit_bearer = explicit_bearer_token(&headers).is_some();
    let body = TotpDisableResponse {
        account,
        replacement: replacement.response(explicit_bearer),
    };
    Ok(rotated_json(&state, &replacement, body, explicit_bearer))
}

pub(super) async fn rotate_recovery_codes(
    State(state): State<AppState>,
    Extension(client): Extension<ClientRequestMetadata>,
    headers: HeaderMap,
    Json(request): Json<TotpCodeRequest>,
) -> ApiResult<Response> {
    let (actor, source_credential) = require_account_actor(&state, &headers)?;
    consume_mutation_budget(&state, &actor.email)?;
    let validated = validate_second_factor_throttled(
        &state,
        &actor.email,
        request.code.as_deref(),
        request.recovery_code.as_deref(),
        true,
        request_client_fingerprint(&headers),
    )?;
    let recovery_codes = generate_recovery_codes();
    let hashes = recovery_codes
        .iter()
        .map(|code| recovery_code_hash(code))
        .collect::<Vec<_>>();
    let replacement = PreparedLocalSessionRotation::for_source_credential(
        &state,
        &validated.account,
        &client,
        &source_credential,
    )?;
    let rotation = replacement.rotation(&actor, &source_credential);
    state.storage.rotate_recovery_code_hashes(
        &actor.email,
        &hashes,
        validated.account.security_version,
        validated.credential,
        &rotation,
    )?;
    state.storage.insert_receipt(
        "auth.recovery_codes.rotate",
        &actor.email,
        Some(&actor.email),
    )?;
    let explicit_bearer = explicit_bearer_token(&headers).is_some();
    let body = RecoveryCodesResponse {
        recovery_codes,
        replacement: replacement.response(explicit_bearer),
    };
    Ok(rotated_json(&state, &replacement, body, explicit_bearer))
}

fn consume_mutation_budget(state: &AppState, email: &str) -> ApiResult<()> {
    state.storage.consume_partitioned_public_rate_limit(
        email,
        "totp_security_mutation",
        "account",
        TOTP_SECURITY_MUTATIONS_PER_15_MINUTES,
        900,
    )
}

fn rotated_json<T: Serialize>(
    state: &AppState,
    replacement: &PreparedLocalSessionRotation,
    body: T,
    explicit_bearer: bool,
) -> Response {
    if explicit_bearer {
        Json(body).into_response()
    } else if let Some(cookie) = replacement.cookie(state.config.secure_cookies) {
        ([(header::SET_COOKIE, cookie)], Json(body)).into_response()
    } else {
        Json(body).into_response()
    }
}
