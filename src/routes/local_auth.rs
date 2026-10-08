use std::sync::OnceLock;

use axum::{
    extract::{Extension, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, patch, post},
    Json, Router,
};
use chrono::{Duration, Utc};
use uuid::Uuid;

mod mfa;
mod password_budget;
mod password_resets;
mod second_factor;
mod session_rotation;
mod sessions;

#[cfg(test)]
mod tests;

use password_budget::{
    clear_password_change_failures, clear_password_login_failures,
    ensure_password_change_not_locked, ensure_password_login_not_locked,
    record_password_change_failure, record_password_login_failure,
};
use second_factor::{
    clear_password_change_totp_failures, clear_totp_login_failures,
    ensure_password_change_totp_not_locked, ensure_totp_login_not_locked,
    record_password_change_totp_failure, record_totp_login_failure,
    validate_second_factor_evidence,
};

use crate::{
    auth::{
        constant_time_str_eq, explicit_bearer_token, hash_account_password,
        mint_sso_token_with_admin, normalize_email, normalize_user_email, require_admin,
        require_admin_with_credential, require_drive_actor, require_drive_actor_with_credential,
        require_user_actor_with_credential, session_cookie_name, token_hash, Actor,
        DriveCredential,
    },
    error::{ApiError, ApiResult},
    model::{
        AuthAccountListResponse, AuthAccountMutationResponse, AuthAccountSecret,
        AuthAttemptUnlockRequest, AuthAttemptUnlockResponse, AuthLogoutResponse, BootstrapRequest,
        BootstrapStatusResponse, BootstrapWizardRequest, BootstrapWizardResponse,
        ChangePasswordRequest, ChangePasswordResponse, CreateAuthAccountRequest,
        DebugAuthAttemptsResponse, DebugAuthResponse, LoginRequest, LoginResponse, MeResponse,
        RegisterRequest, RegistrationStatusResponse, SecurityEventListResponse,
        UpdateAuthAccountRequest,
    },
    server::{request_client_fingerprint, AppState, ClientRequestMetadata},
    storage::{
        AuthThrottlePolicy, NewSecurityEvent, VerifiedLocalSecondFactor, MAX_SECURITY_EVENTS,
        SECURITY_EVENT_RETENTION_DAYS,
    },
};

const AUTH_LOGIN_REQUESTS_PER_MINUTE: i64 = 30;
const LOCAL_ISSUER: &str = "local-password";
const AUTH_THROTTLE_POLICY: AuthThrottlePolicy = AuthThrottlePolicy {
    threshold: 5,
    base_lockout_seconds: 30,
    max_lockout_seconds: 300,
    decay_seconds: 900,
};
static DUMMY_ACCOUNT_PASSWORD_HASH: OnceLock<String> = OnceLock::new();

pub fn router() -> Router<AppState> {
    // Initialize the enumeration-resistant dummy hash while constructing the
    // router, never on the first unauthenticated async login request.
    let _ = dummy_account_password_hash();
    Router::new()
        .merge(sessions::router())
        .route("/auth/bootstrap/status", get(bootstrap_status))
        .route("/auth/bootstrap", post(bootstrap))
        .route("/auth/bootstrap/wizard", post(bootstrap_wizard))
        .route("/auth/registration/status", get(registration_status))
        .route("/auth/register", post(register_account))
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(me))
        .route("/auth/security-events", get(self_security_events))
        .route("/auth/password/change", post(change_password))
        .merge(password_resets::router())
        .route("/auth/2fa/setup", post(mfa::setup_totp))
        .route("/auth/2fa/enable", post(mfa::enable_totp))
        .route("/auth/2fa/disable", post(mfa::disable_totp))
        .route(
            "/auth/recovery-codes/rotate",
            post(mfa::rotate_recovery_codes),
        )
        .route(
            "/admin/auth/users",
            get(list_auth_users).post(create_auth_user),
        )
        .route("/admin/auth/users/{email}", patch(update_auth_user))
        .route("/admin/auth/attempts", get(admin_auth_attempts))
        .route("/admin/auth/attempts/unlock", post(unlock_auth_attempt))
        .route("/debug/auth", get(debug_auth))
        .route("/debug/auth-attempts", get(debug_auth_attempts))
}

async fn bootstrap_status(
    State(state): State<AppState>,
) -> ApiResult<Json<BootstrapStatusResponse>> {
    let required = state.storage.auth_account_count()? == 0;
    Ok(Json(BootstrapStatusResponse { required }))
}

async fn bootstrap(
    State(state): State<AppState>,
    Extension(client): Extension<ClientRequestMetadata>,
    headers: HeaderMap,
    Json(request): Json<BootstrapRequest>,
) -> ApiResult<Response> {
    require_bootstrap_authority(&state, &headers)?;
    let email = normalize_user_email(&request.email)?;
    let password_hash = state.hash_account_password(&request.password).await?;
    let (account, _) = state
        .storage
        .bootstrap_auth_account(&email, &password_hash)?;
    let response = issue_local_session(
        &state,
        &account.email,
        &account.user_id,
        account.is_admin,
        None,
        VerifiedLocalSecondFactor::NotRequired,
        &client,
    )?;
    Ok(login_response(
        StatusCode::CREATED,
        response,
        state.config.secure_cookies,
        request.cookie_only.unwrap_or(false),
    ))
}

async fn bootstrap_wizard(
    State(state): State<AppState>,
    Extension(client): Extension<ClientRequestMetadata>,
    headers: HeaderMap,
    Json(request): Json<BootstrapWizardRequest>,
) -> ApiResult<Response> {
    require_bootstrap_authority(&state, &headers)?;
    let email = normalize_user_email(&request.email)?;
    let storage_mode = request.storage_mode.as_deref().unwrap_or("open");
    if storage_mode != "open" {
        return Err(ApiError::Validation(
            "storage_mode must be open".to_string(),
        ));
    }
    let workspace_name = request.workspace_name.trim();
    if workspace_name.is_empty() {
        return Err(ApiError::Validation(
            "workspace_name must not be empty".to_string(),
        ));
    }
    let password_hash = state.hash_account_password(&request.password).await?;
    let (account, workspace, owner, receipt) =
        state.storage.bootstrap_auth_account_with_workspace(
            &email,
            &password_hash,
            workspace_name,
            storage_mode,
        )?;
    let mut login = issue_local_session(
        &state,
        &account.email,
        &account.user_id,
        account.is_admin,
        None,
        VerifiedLocalSecondFactor::NotRequired,
        &client,
    )?;
    let cookie = session_cookie(&login, state.config.secure_cookies);
    if request.cookie_only.unwrap_or(false) {
        login.token = None;
    }
    Ok((
        StatusCode::CREATED,
        [(header::SET_COOKIE, cookie)],
        Json(BootstrapWizardResponse {
            login,
            account,
            workspace,
            owner,
            receipt,
        }),
    )
        .into_response())
}

fn require_bootstrap_authority(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    // A separate setup credential cannot authorize any normal admin route. It
    // is accepted explicitly here and never from a browser session cookie.
    if let Some(expected) = state.config.bootstrap_token.as_deref() {
        let supplied = explicit_bearer_token(headers).ok_or(ApiError::Unauthenticated)?;
        if !constant_time_str_eq(supplied, expected) {
            return Err(ApiError::Unauthenticated);
        }
        return Ok(());
    }

    // Compatibility path for existing installations without a separate setup
    // credential. Loopback itself is never treated as an authentication boundary.
    require_admin(state, headers)?;
    Ok(())
}

async fn registration_status(
    State(state): State<AppState>,
) -> ApiResult<Json<RegistrationStatusResponse>> {
    Ok(Json(RegistrationStatusResponse {
        enabled: state.storage.registration_enabled()?,
    }))
}

async fn register_account(
    State(_state): State<AppState>,
    _headers: HeaderMap,
    Json(_request): Json<RegisterRequest>,
) -> ApiResult<Response> {
    Err(ApiError::Forbidden)
}

async fn create_auth_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateAuthAccountRequest>,
) -> ApiResult<(StatusCode, Json<AuthAccountMutationResponse>)> {
    let (actor, source_credential) = require_admin_with_credential(&state, &headers)?;
    let email = normalize_user_email(&request.email)?;
    let password_hash = state.hash_account_password(&request.password).await?;
    let (account, receipt) = state.storage.create_auth_account(
        &email,
        &password_hash,
        request.is_admin.unwrap_or(false),
        &actor,
        &source_credential,
    )?;
    Ok((
        StatusCode::CREATED,
        Json(AuthAccountMutationResponse { account, receipt }),
    ))
}

async fn list_auth_users(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<AuthAccountListResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(AuthAccountListResponse {
        accounts: state.storage.list_auth_accounts()?,
    }))
}

async fn update_auth_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(email): Path<String>,
    Json(request): Json<UpdateAuthAccountRequest>,
) -> ApiResult<Response> {
    let (actor, source_credential) = require_admin_with_credential(&state, &headers)?;
    let email = normalize_email(&email)?;
    let self_removal =
        actor.email == email && (request.disabled == Some(true) || request.is_admin == Some(false));
    let expected_self_removal_security_version = if self_removal {
        let confirmed_email = normalize_email(
            request
                .confirm_email
                .as_deref()
                .ok_or(ApiError::Forbidden)?,
        )?;
        if confirmed_email != email {
            return Err(ApiError::Forbidden);
        }
        let account = state
            .storage
            .get_auth_account_secret(&email)?
            .ok_or(ApiError::Unauthenticated)?;
        let current_password = request
            .current_password
            .as_deref()
            .ok_or(ApiError::Forbidden)?;
        if !state
            .verify_account_password(&account.password_hash, current_password)
            .await?
        {
            return Err(ApiError::Unauthenticated);
        }
        Some(account.security_version)
    } else {
        None
    };
    let password_hash = if let Some(password) = request.reset_password.as_deref() {
        Some(state.hash_account_password(password).await?)
    } else {
        None
    };
    let (account, receipt) = state.storage.update_auth_account(
        &email,
        request.disabled,
        request.is_admin,
        password_hash.as_deref(),
        request.reset_2fa.unwrap_or(false),
        expected_self_removal_security_version,
        &actor,
        &source_credential,
    )?;
    let mut response = if self_removal {
        Json(serde_json::json!({"self_removal_completed": true})).into_response()
    } else {
        Json(AuthAccountMutationResponse { account, receipt }).into_response()
    };
    if self_removal {
        crate::server::admin_response_guard::mark_admin_self_removal_completion(
            &mut response,
            &actor,
            &email,
            &source_credential,
            expected_self_removal_security_version
                .and_then(|version| version.checked_add(1))
                .ok_or(ApiError::Conflict)?,
            request.disabled == Some(true),
        );
    }
    Ok(response)
}

async fn login(
    State(state): State<AppState>,
    Extension(client): Extension<ClientRequestMetadata>,
    headers: HeaderMap,
    Json(request): Json<LoginRequest>,
) -> ApiResult<Response> {
    // Preserve useful actor context for known accounts without turning the
    // security ledger into a durable list of arbitrary identifiers probed by
    // unauthenticated callers.
    let audit_email = normalize_email(&request.email).ok().and_then(|email| {
        state
            .storage
            .get_auth_account(&email)
            .ok()
            .flatten()
            .map(|_| email)
    });
    let result = login_inner(&state, &client, &headers, request).await;
    let (outcome, status, session_id) = match &result {
        Ok(outcome) => (
            outcome.outcome,
            outcome.response.status().as_u16(),
            outcome.session_id.as_deref(),
        ),
        Err(error) => (
            login_error_outcome(error),
            error.status_code().as_u16(),
            None,
        ),
    };
    let record_event = status < 400
        || state.admit_low_authority_security_event(&format!(
            "login\0{}\0{status}",
            audit_email.as_deref().unwrap_or("unknown")
        ));
    if record_event {
        if let Err(error) = state.storage.record_security_event(NewSecurityEvent {
            category: "login",
            action: "POST",
            route: "/auth/login",
            outcome,
            status_code: status,
            actor_email: audit_email.as_deref(),
            credential_kind: "local_password",
            credential_ref: None,
            session_id,
            client_ip: Some(&client.client_ip),
            user_agent: client.user_agent.as_deref(),
            target_ref: None,
            low_authority: status >= 400,
        }) {
            tracing::warn!(%error, "could not record sign-in security event");
        }
    }
    result.map(|outcome| outcome.response)
}

struct LoginOutcome {
    response: Response,
    outcome: &'static str,
    session_id: Option<String>,
}

async fn login_inner(
    state: &AppState,
    client: &ClientRequestMetadata,
    headers: &HeaderMap,
    request: LoginRequest,
) -> ApiResult<LoginOutcome> {
    let email = normalize_email(&request.email)?;
    let client_fingerprint = request_client_fingerprint(headers);
    state.storage.consume_partitioned_public_rate_limit(
        "auth-login",
        "auth_login_client",
        client_fingerprint,
        AUTH_LOGIN_REQUESTS_PER_MINUTE,
        60,
    )?;
    let account = state.storage.get_auth_account_secret(&email)?;
    let throttle_actor = login_throttle_actor(state, &email, account.is_some());
    let password_admission =
        ensure_password_login_not_locked(state, &throttle_actor, client_fingerprint)?;
    let password_ok = match account.as_ref() {
        Some(account) => {
            state
                .verify_untrusted_account_password(&account.password_hash, &request.password)
                .await?
        }
        None => {
            state
                .verify_untrusted_account_password(dummy_account_password_hash(), &request.password)
                .await?
        }
    };
    let Some(account) = account else {
        record_password_login_failure(
            state,
            &throttle_actor,
            client_fingerprint,
            password_admission,
        )?;
        return Err(ApiError::Unauthenticated);
    };
    if account.disabled_at.is_some() || !password_ok {
        record_password_login_failure(state, &email, client_fingerprint, password_admission)?;
        return Err(ApiError::Unauthenticated);
    }
    clear_password_login_failures(state, &email, client_fingerprint)?;
    finish_password_login(state, client, account, request, client_fingerprint)
}

fn finish_password_login(
    state: &AppState,
    client: &ClientRequestMetadata,
    account: AuthAccountSecret,
    request: LoginRequest,
    client_fingerprint: &str,
) -> ApiResult<LoginOutcome> {
    let email = account.email.clone();
    let mut login_second_factor = VerifiedLocalSecondFactor::NotRequired;
    if account.totp_enabled {
        if request.totp_code.is_none() && request.recovery_code.is_none() {
            return Ok(LoginOutcome {
                response: (
                    StatusCode::ACCEPTED,
                    Json(LoginResponse {
                        token_type: "Bearer".to_string(),
                        token: None,
                        session_id: None,
                        actor: account.email,
                        is_admin: account.is_admin,
                        requires_2fa: true,
                        expires_at: None,
                    }),
                )
                    .into_response(),
                outcome: "challenge",
                session_id: None,
            });
        }
        let totp_admission = ensure_totp_login_not_locked(state, &email, client_fingerprint)?;
        match validate_second_factor_evidence(
            state,
            &account.email,
            request.totp_code.as_deref(),
            request.recovery_code.as_deref(),
            true,
        ) {
            Ok(validated) => {
                // Keep the password-verified snapshot for the final transaction.
                // The factor reread must not replace proof of the password hash.
                login_second_factor = validated.credential;
            }
            Err(error) => {
                record_totp_login_failure(state, &email, client_fingerprint, totp_admission)?;
                return Err(error);
            }
        }
    }
    let response = issue_local_session(
        state,
        &account.email,
        &account.user_id,
        account.is_admin,
        Some(&account),
        login_second_factor,
        client,
    )?;
    if account.totp_enabled {
        clear_totp_login_failures(state, &email, client_fingerprint)?;
    }
    let session_id = response.session_id.clone();
    Ok(LoginOutcome {
        response: login_response(
            StatusCode::OK,
            response,
            state.config.secure_cookies,
            request.cookie_only.unwrap_or(false),
        ),
        outcome: "success",
        session_id,
    })
}

fn login_error_outcome(error: &ApiError) -> &'static str {
    match error.status_code() {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => "denied",
        StatusCode::LOCKED | StatusCode::TOO_MANY_REQUESTS => "blocked",
        status if status.is_client_error() => "rejected",
        _ => "failed",
    }
}

fn dummy_account_password_hash() -> &'static str {
    DUMMY_ACCOUNT_PASSWORD_HASH
        .get_or_init(|| {
            hash_account_password("dummy timing password")
                .expect("dummy password hash should be valid")
        })
        .as_str()
}

fn login_throttle_actor(state: &AppState, email: &str, account_exists: bool) -> String {
    if account_exists {
        return email.to_string();
    }
    // Unknown identifiers receive the same per-candidate lockout sequence as
    // real accounts without persisting the probed email in debug/audit rows.
    let keyed = token_hash(&format!("unknown-login\0{}\0{email}", state.config.token));
    format!("unknown:{keyed}")
}

fn login_response(
    status: StatusCode,
    mut response: LoginResponse,
    secure: bool,
    cookie_only: bool,
) -> Response {
    let cookie = session_cookie(&response, secure);
    if cookie_only {
        response.token = None;
    }
    (status, [(header::SET_COOKIE, cookie)], Json(response)).into_response()
}

/// Build the `Set-Cookie` value for the session cookie. Secure mode always
/// emits the browser-enforced `__Host-` cookie with `Secure; Path=/` and no
/// `Domain` attribute. Intentionally insecure loopback/e2e mode uses a
/// distinct development-only name. `Secure` is gated on config rather than
/// the request scheme because Drive typically terminates TLS at a reverse
/// proxy, so the app sees plain `http` even when the browser leg is HTTPS.
fn session_cookie(response: &LoginResponse, secure: bool) -> String {
    let token = response.token.as_deref().unwrap_or_default();
    let max_age = response
        .expires_at
        .as_deref()
        .and_then(|expires_at| chrono::DateTime::parse_from_rfc3339(expires_at).ok())
        .map(|expires_at| {
            (expires_at.timestamp() - Utc::now().timestamp())
                .max(0)
                .to_string()
        })
        .unwrap_or_else(|| "0".to_string());
    format!(
        "{}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{}",
        session_cookie_name(secure),
        secure_attr(secure)
    )
}

fn clear_session_cookie(secure: bool) -> String {
    format!(
        "{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{}",
        session_cookie_name(secure),
        secure_attr(secure)
    )
}

/// `"; Secure"` when secure cookies are enabled, else the empty string. The
/// clear-cookie must carry the same attribute so browsers overwrite the
/// original (attributes are part of the cookie's identity for replacement).
fn secure_attr(secure: bool) -> &'static str {
    if secure {
        "; Secure"
    } else {
        ""
    }
}

async fn logout(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    match source_credential {
        DriveCredential::UserSession(session_id) => {
            let source_credential = DriveCredential::UserSession(session_id.clone());
            let (session, receipt) = state.storage.revoke_auth_session_for_actor_authorized(
                &session_id,
                &actor,
                &source_credential,
                "auth.logout",
            )?;
            Ok((
                [(
                    header::SET_COOKIE,
                    clear_session_cookie(state.config.secure_cookies),
                )],
                Json(AuthLogoutResponse {
                    session: Some(session),
                    delegated_agent: None,
                    receipt,
                }),
            )
                .into_response())
        }
        DriveCredential::DelegatedAgentToken(token_id) => {
            let (delegated_agent, receipt) = state
                .storage
                .revoke_delegated_agent_token_for_actor(&token_id, &actor)?;
            Ok(Json(AuthLogoutResponse {
                session: None,
                delegated_agent: Some(delegated_agent),
                receipt,
            })
            .into_response())
        }
        DriveCredential::Operator | DriveCredential::AppToken(_) => Err(ApiError::Forbidden),
    }
}

async fn self_security_events(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<SecurityEventListResponse>> {
    let (actor, source_credential) = require_account_self_service_actor(&state, &headers)?;
    let events = state
        .storage
        .list_login_security_events_for_actor(&actor.email, 100)?;
    state
        .storage
        .ensure_source_credential_publication_authorized(&actor, &source_credential)?;
    Ok(Json(SecurityEventListResponse {
        events,
        retention_days: SECURITY_EVENT_RETENTION_DAYS,
        maximum_events: MAX_SECURITY_EVENTS,
    }))
}

async fn change_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ChangePasswordRequest>,
) -> ApiResult<Response> {
    let (actor, source_credential) = require_account_self_service_actor(&state, &headers)?;
    let client_fingerprint = request_client_fingerprint(&headers);
    let password_admission =
        ensure_password_change_not_locked(&state, &actor.email, client_fingerprint)?;
    let mut account = state
        .storage
        .get_auth_account_secret(&actor.email)?
        .ok_or(ApiError::Unauthenticated)?;
    let mut password_second_factor = VerifiedLocalSecondFactor::NotRequired;
    if !state
        .verify_account_password(&account.password_hash, &request.current_password)
        .await?
    {
        record_password_change_failure(
            &state,
            &actor.email,
            client_fingerprint,
            password_admission,
        )?;
        return Err(ApiError::Unauthenticated);
    }
    clear_password_change_failures(&state, &actor.email, client_fingerprint)?;
    if account.totp_enabled {
        if request.totp_code.is_none() && request.recovery_code.is_none() {
            return Ok((
                StatusCode::ACCEPTED,
                Json(ChangePasswordResponse {
                    requires_2fa: true,
                    account: None,
                    receipt: None,
                }),
            )
                .into_response());
        }
        let totp_admission =
            ensure_password_change_totp_not_locked(&state, &actor.email, client_fingerprint)?;
        match validate_second_factor_evidence(
            &state,
            &actor.email,
            request.totp_code.as_deref(),
            request.recovery_code.as_deref(),
            true,
        ) {
            Ok(validated) => {
                password_second_factor = validated.credential;
                account = validated.account;
            }
            Err(error) => {
                record_password_change_totp_failure(
                    &state,
                    &actor.email,
                    client_fingerprint,
                    totp_admission,
                )?;
                return Err(error);
            }
        }
        clear_password_change_totp_failures(&state, &actor.email, client_fingerprint)?;
    }
    let password_hash = state.hash_account_password(&request.new_password).await?;
    let (account, receipt) = state.storage.change_auth_account_password(
        &actor.email,
        &password_hash,
        account.security_version,
        password_second_factor,
        &actor,
        &source_credential,
    )?;
    Ok(Json(ChangePasswordResponse {
        requires_2fa: false,
        account: Some(account),
        receipt: Some(receipt),
    })
    .into_response())
}

async fn me(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<MeResponse>> {
    let actor = require_drive_actor(&state, &headers)?;
    let totp_enabled = if actor.auth_mode.account_security_available() {
        state
            .storage
            .get_auth_account(&actor.email)?
            .map(|account| account.totp_enabled)
    } else {
        None
    };
    Ok(Json(MeResponse {
        actor: actor.email,
        is_admin: actor.is_admin,
        auth_mode: actor.auth_mode.as_str().to_string(),
        totp_enabled,
        account_security_available: actor.auth_mode.account_security_available(),
        session_management_available: actor.auth_mode.session_management_available(),
        notifications_available: actor.auth_mode.notifications_available(),
        admin_tools_available: actor.is_admin
            || matches!(actor.auth_mode, crate::auth::AuthMode::Operator),
    }))
}

async fn debug_auth(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<DebugAuthResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(DebugAuthResponse {
        service: "shellx-drive".to_string(),
        accounts: state.storage.list_auth_accounts()?,
        sessions: state.storage.list_auth_sessions_bounded(500)?,
    }))
}

async fn debug_auth_attempts(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<DebugAuthAttemptsResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(DebugAuthAttemptsResponse {
        service: "shellx-drive".to_string(),
        attempts: super::debug::redaction::auth_attempts(
            state.storage.list_auth_attempts_bounded(1_000)?,
            &state.config.token,
        ),
    }))
}

async fn admin_auth_attempts(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<DebugAuthAttemptsResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(DebugAuthAttemptsResponse {
        service: "shellx-drive".to_string(),
        attempts: super::debug::redaction::auth_attempts(
            state.storage.list_auth_attempts_bounded(1_000)?,
            &state.config.token,
        ),
    }))
}

async fn unlock_auth_attempt(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AuthAttemptUnlockRequest>,
) -> ApiResult<Json<AuthAttemptUnlockResponse>> {
    let (actor, source_credential) = require_admin_with_credential(&state, &headers)?;
    let requested_key = request.key.trim();
    let stored_key = state
        .storage
        .list_auth_attempts_bounded(1_000)?
        .into_iter()
        .find(|attempt| {
            attempt.key == requested_key
                || (super::debug::redaction::is_capability_attempt_scope(&attempt.scope)
                    && super::debug::redaction::attempt_key_ref(&attempt.key, &state.config.token)
                        == requested_key)
        })
        .map(|attempt| attempt.key)
        .ok_or(ApiError::NotFound)?;
    let receipt = state
        .storage
        .unlock_auth_attempt(&stored_key, &actor, &source_credential)?;
    Ok(Json(AuthAttemptUnlockResponse {
        removed: true,
        receipt,
    }))
}

fn require_account_actor(
    state: &AppState,
    headers: &HeaderMap,
) -> ApiResult<(Actor, DriveCredential)> {
    let (actor, credential) = require_drive_actor_with_credential(state, headers)?;
    if !matches!(
        actor.auth_mode,
        crate::auth::AuthMode::LocalAccount | crate::auth::AuthMode::DelegatedAgent
    ) || !matches!(
        credential,
        DriveCredential::UserSession(_) | DriveCredential::DelegatedAgentToken(_)
    ) {
        return Err(ApiError::Forbidden);
    }
    Ok((actor, credential))
}

fn require_account_self_service_actor(
    state: &AppState,
    headers: &HeaderMap,
) -> ApiResult<(Actor, DriveCredential)> {
    let (actor, credential) = require_user_actor_with_credential(state, headers)?;
    if matches!(
        credential,
        DriveCredential::UserSession(_) | DriveCredential::DelegatedAgentToken(_)
    ) {
        Ok((actor, credential))
    } else {
        Err(ApiError::Forbidden)
    }
}

fn issue_local_session(
    state: &AppState,
    email: &str,
    subject: &str,
    is_admin: bool,
    verified_account: Option<&AuthAccountSecret>,
    second_factor: VerifiedLocalSecondFactor,
    client: &ClientRequestMetadata,
) -> ApiResult<LoginResponse> {
    let session_id = Uuid::now_v7().to_string();
    let expires_at = Utc::now() + Duration::seconds(state.config.local_session_ttl_seconds);
    let token = mint_sso_token_with_admin(
        &session_id,
        email,
        LOCAL_ISSUER,
        subject,
        expires_at.timestamp(),
        is_admin,
        &state.config.token,
    )?;
    let digest = token_hash(&token);
    let expiry = expires_at.to_rfc3339();
    if let Some(account) = verified_account {
        state.storage.record_verified_local_auth_session(
            &session_id,
            account,
            second_factor,
            LOCAL_ISSUER,
            &digest,
            &expiry,
            Some(&client.client_ip),
            client.user_agent.as_deref(),
        )?;
    } else {
        state.storage.record_auth_session_with_client(
            &session_id,
            email,
            LOCAL_ISSUER,
            subject,
            &digest,
            &expiry,
            Some(&client.client_ip),
            client.user_agent.as_deref(),
        )?;
    }
    Ok(LoginResponse {
        token_type: "Bearer".to_string(),
        token: Some(token),
        session_id: Some(session_id),
        actor: email.to_string(),
        is_admin,
        requires_2fa: false,
        expires_at: Some(expires_at.to_rfc3339()),
    })
}

fn record_auth_failure(
    state: &AppState,
    email: &str,
    scope: &str,
    client_fingerprint: &str,
) -> ApiResult<()> {
    state.storage.record_auth_attempt_failure(
        Some(email),
        scope,
        client_fingerprint,
        AUTH_THROTTLE_POLICY,
    )?;
    Ok(())
}
