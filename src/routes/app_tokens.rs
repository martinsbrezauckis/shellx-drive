use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use chrono::{Duration, Utc};

use crate::{
    auth::{
        normalize_email, random_secret_token, require_admin, require_admin_with_credential,
        token_hash, Actor, WorkspacePermission, APP_TOKEN_PREFIX,
    },
    error::{ApiError, ApiResult},
    model::{
        AppTokenListResponse, AppTokenMutationResponse, CreateAppTokenRequest,
        CreateAppTokenResponse,
    },
    server::AppState,
};

const DEFAULT_EXPIRY_SECONDS: i64 = 90 * 24 * 60 * 60;
const MIN_EXPIRY_SECONDS: i64 = 60 * 60;
const MAX_EXPIRY_SECONDS: i64 = 365 * 24 * 60 * 60;
const MAX_WORKSPACES_PER_TOKEN: usize = 128;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/admin/app-tokens",
            get(list_app_tokens).post(create_app_token),
        )
        .route(
            "/admin/app-tokens/{token_id}/revoke",
            post(revoke_app_token),
        )
}

async fn list_app_tokens(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<AppTokenListResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(AppTokenListResponse {
        app_tokens: state.storage.list_app_tokens()?,
    }))
}

async fn create_app_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateAppTokenRequest>,
) -> ApiResult<(StatusCode, Json<CreateAppTokenResponse>)> {
    let (admin, source_credential) = require_admin_with_credential(&state, &headers)?;
    let label = request.label.trim();
    if label.is_empty() || label.len() > 120 {
        return Err(ApiError::Validation(
            "label must contain 1 to 120 bytes".to_string(),
        ));
    }
    let actor_email = normalize_email(&request.actor_email)?;
    if state
        .storage
        .get_auth_account(&actor_email)?
        .is_some_and(|account| account.disabled)
    {
        return Err(ApiError::Validation(
            "actor account is disabled".to_string(),
        ));
    }

    let mut workspace_ids = request
        .workspace_ids
        .into_iter()
        .map(|workspace_id| workspace_id.trim().to_string())
        .collect::<Vec<_>>();
    workspace_ids.sort();
    workspace_ids.dedup();
    if workspace_ids.is_empty() || workspace_ids.len() > MAX_WORKSPACES_PER_TOKEN {
        return Err(ApiError::Validation(format!(
            "workspace_ids must contain 1 to {MAX_WORKSPACES_PER_TOKEN} unique entries"
        )));
    }
    if workspace_ids
        .iter()
        .any(|workspace_id| workspace_id.is_empty() || workspace_id.len() > 128)
    {
        return Err(ApiError::Validation(
            "workspace_ids entries must contain 1 to 128 bytes".to_string(),
        ));
    }

    let scoped_actor = Actor {
        email: actor_email.clone(),
        is_admin: false,
        auth_mode: admin.auth_mode,
        allowed_workspace_ids: None,
    };
    for workspace_id in &workspace_ids {
        state.storage.ensure_workspace_permission(
            workspace_id,
            &scoped_actor,
            WorkspacePermission::Read,
        )?;
    }

    let expiry_seconds = request.expires_in_seconds.unwrap_or(DEFAULT_EXPIRY_SECONDS);
    if !(MIN_EXPIRY_SECONDS..=MAX_EXPIRY_SECONDS).contains(&expiry_seconds) {
        return Err(ApiError::Validation(format!(
            "expires_in_seconds must be between {MIN_EXPIRY_SECONDS} and {MAX_EXPIRY_SECONDS}"
        )));
    }
    let expires_at = (Utc::now() + Duration::seconds(expiry_seconds)).to_rfc3339();
    let token = format!("{APP_TOKEN_PREFIX}{}", random_secret_token());
    let (app_token, receipt) = state.storage.create_pending_app_token_publication(
        label,
        &actor_email,
        &token_hash(&token),
        &workspace_ids,
        &expires_at,
        &admin,
        &source_credential,
    )?;
    state
        .storage
        .publish_pending_app_token(&app_token.id, &receipt, &admin, &source_credential)?;
    Ok((
        StatusCode::CREATED,
        Json(CreateAppTokenResponse {
            app_token,
            token,
            receipt,
        }),
    ))
}

async fn revoke_app_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(token_id): Path<String>,
) -> ApiResult<Json<AppTokenMutationResponse>> {
    let (admin, source_credential) = require_admin_with_credential(&state, &headers)?;
    let (app_token, receipt) =
        state
            .storage
            .revoke_app_token(&token_id, &admin, &source_credential)?;
    Ok(Json(AppTokenMutationResponse { app_token, receipt }))
}
