use axum::{
    extract::State,
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};

use crate::{
    auth::{require_user_actor_with_credential, DriveCredential},
    error::ApiResult,
    model::{
        AuthSessionBulkMutationResponse, AuthSessionListResponse, AuthSessionMutationResponse,
    },
    server::AppState,
};

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/auth/sessions", get(list_self_sessions))
        .route(
            "/auth/sessions/revoke-others",
            post(revoke_other_self_sessions),
        )
        .route(
            "/auth/sessions/{session_id}/revoke",
            post(revoke_self_session),
        )
}

async fn list_self_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<AuthSessionListResponse>> {
    let (actor, source_credential) = require_account_session_actor(&state, &headers)?;
    let current_session_id = match &source_credential {
        DriveCredential::UserSession(session_id) => Some(session_id.clone()),
        DriveCredential::DelegatedAgentToken(_) => None,
        DriveCredential::Operator | DriveCredential::AppToken(_) => unreachable!(),
    };
    let sessions = state
        .storage
        .list_active_auth_sessions_for_actor(&actor.email)?;
    state
        .storage
        .ensure_source_credential_publication_authorized(&actor, &source_credential)?;
    Ok(Json(AuthSessionListResponse {
        total: sessions.len(),
        sessions,
        current_session_id,
        next_cursor: None,
    }))
}

async fn revoke_self_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(session_id): axum::extract::Path<String>,
) -> ApiResult<Json<AuthSessionMutationResponse>> {
    let (actor, source_credential) = require_account_session_actor(&state, &headers)?;
    let (session, receipt) = state.storage.revoke_auth_session_for_actor_authorized(
        &session_id,
        &actor,
        &source_credential,
        "auth.session.revoke",
    )?;
    Ok(Json(AuthSessionMutationResponse { session, receipt }))
}

async fn revoke_other_self_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<AuthSessionBulkMutationResponse>> {
    let (actor, source_credential) = require_account_session_actor(&state, &headers)?;
    let current_session_id = match &source_credential {
        DriveCredential::UserSession(session_id) => Some(session_id.as_str()),
        DriveCredential::DelegatedAgentToken(_) => None,
        DriveCredential::Operator | DriveCredential::AppToken(_) => unreachable!(),
    };
    let (revoked_sessions, receipt) = state
        .storage
        .revoke_other_auth_sessions_for_actor_authorized(
            current_session_id,
            &actor,
            &source_credential,
        )?;
    Ok(Json(AuthSessionBulkMutationResponse {
        revoked_sessions,
        receipt,
    }))
}

fn require_account_session_actor(
    state: &AppState,
    headers: &HeaderMap,
) -> ApiResult<(crate::auth::Actor, DriveCredential)> {
    let (actor, credential) = require_user_actor_with_credential(state, headers)?;
    if matches!(
        credential,
        DriveCredential::UserSession(_) | DriveCredential::DelegatedAgentToken(_)
    ) {
        Ok((actor, credential))
    } else {
        Err(crate::error::ApiError::Forbidden)
    }
}
