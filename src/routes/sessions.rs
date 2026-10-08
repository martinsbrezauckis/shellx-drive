use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};

use crate::{
    auth::{require_admin, require_admin_with_credential, DriveCredential},
    error::ApiResult,
    model::{AuthSessionListResponse, AuthSessionMutationResponse, DebugSessionsResponse},
    server::AppState,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::DateTime;
use serde::{Deserialize, Serialize};

const DEFAULT_SESSION_PAGE_LIMIT: usize = 100;
const MAX_SESSION_PAGE_LIMIT: usize = 100;

#[derive(Deserialize)]
struct SessionListQuery {
    cursor: Option<String>,
    limit: Option<usize>,
}

#[derive(Serialize, Deserialize)]
struct SessionCursorPayload {
    created_at: String,
    id: String,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/sessions", get(list_sessions))
        .route("/admin/sessions/{session_id}/revoke", post(revoke_session))
        .route("/debug/sessions", get(debug_sessions))
}

async fn list_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SessionListQuery>,
) -> ApiResult<Json<AuthSessionListResponse>> {
    let (_, credential) = require_admin_with_credential(&state, &headers)?;
    let current_session_id = match credential {
        DriveCredential::UserSession(session_id) => Some(session_id),
        DriveCredential::Operator
        | DriveCredential::AppToken(_)
        | DriveCredential::DelegatedAgentToken(_) => None,
    };
    let limit = match query.limit {
        None => DEFAULT_SESSION_PAGE_LIMIT,
        Some(limit) if (1..=MAX_SESSION_PAGE_LIMIT).contains(&limit) => limit,
        Some(_) => {
            return Err(crate::error::ApiError::Validation(format!(
                "session limit must be a whole number from 1 to {MAX_SESSION_PAGE_LIMIT}"
            )))
        }
    };
    let cursor = parse_session_cursor(query.cursor.as_deref())?;
    let page = state.storage.list_active_auth_sessions_page(
        cursor
            .as_ref()
            .map(|cursor| (cursor.created_at.as_str(), cursor.id.as_str())),
        limit,
    )?;
    Ok(Json(AuthSessionListResponse {
        sessions: page.sessions,
        current_session_id,
        total: page.total,
        next_cursor: page
            .next_cursor
            .map(|(created_at, id)| encode_session_cursor(&created_at, &id)),
    }))
}

fn parse_session_cursor(raw_cursor: Option<&str>) -> ApiResult<Option<SessionCursorPayload>> {
    let Some(raw_cursor) = raw_cursor else {
        return Ok(None);
    };
    if raw_cursor.is_empty() || raw_cursor.len() > 512 {
        return Err(crate::error::ApiError::Validation(
            "session cursor is invalid".to_string(),
        ));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(raw_cursor)
        .map_err(|_| crate::error::ApiError::Validation("session cursor is invalid".to_string()))?;
    let payload: SessionCursorPayload = serde_json::from_slice(&bytes)
        .map_err(|_| crate::error::ApiError::Validation("session cursor is invalid".to_string()))?;
    if payload.created_at.len() > 64
        || payload.id.is_empty()
        || payload.id.len() > 256
        || DateTime::parse_from_rfc3339(&payload.created_at).is_err()
    {
        return Err(crate::error::ApiError::Validation(
            "session cursor is invalid".to_string(),
        ));
    }
    Ok(Some(payload))
}

fn encode_session_cursor(created_at: &str, id: &str) -> String {
    URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&SessionCursorPayload {
            created_at: created_at.to_string(),
            id: id.to_string(),
        })
        .expect("session cursor payload serializes"),
    )
}

async fn revoke_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
) -> ApiResult<Json<AuthSessionMutationResponse>> {
    let (actor, source_credential) = require_admin_with_credential(&state, &headers)?;
    let (session, receipt) =
        state
            .storage
            .revoke_auth_session_authorized(&session_id, &actor, &source_credential)?;
    Ok(Json(AuthSessionMutationResponse { session, receipt }))
}

async fn debug_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<DebugSessionsResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(DebugSessionsResponse {
        service: "shellx-drive".to_string(),
        sessions: state.storage.list_auth_sessions_bounded(1_000)?,
    }))
}
