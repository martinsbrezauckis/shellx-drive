//! Server broker endpoints for a desktop that pulls typed control work. This
//! route family never accepts a desktop listener address, path, shell command,
//! Tauri invoke name, or arbitrary action payload.

use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;

use crate::{
    auth::{
        explicit_bearer_token, require_drive_actor_with_credential, require_local_session_actor,
        Actor, DriveCredential,
    },
    desktop_agent::{
        parse_submit_request, DesktopAgentAcknowledgeRequest, DesktopAgentClaimRequest,
        DesktopAgentDeviceAssertion, DesktopAgentDeviceRegistration, DesktopAgentProgressRequest,
        DesktopAgentSubmitWireRequest, DesktopAgentTerminalRequest,
    },
    error::{ApiError, ApiResult},
    server::AppState,
};

mod disconnect;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/desktop-agent/devices", get(list_devices))
        .route("/desktop-agent/devices/register", post(register_device))
        .route(
            "/desktop-agent/commands",
            get(list_commands).post(submit_command),
        )
        .route("/desktop-agent/commands/{command_id}", get(get_command))
        .route(
            "/desktop-agent/commands/{command_id}/cancel",
            post(cancel_command),
        )
        .route(
            "/desktop-agent/devices/{device_id}/claim",
            post(claim_command),
        )
        .route(
            "/desktop-agent/devices/{device_id}/heartbeat",
            post(heartbeat_device),
        )
        .route(
            "/desktop-agent/devices/{device_id}/retire",
            post(retire_device),
        )
        .route(
            "/desktop-agent/devices/{device_id}/revoke",
            post(revoke_device),
        )
        .route(
            "/desktop-agent/commands/{command_id}/acknowledge",
            post(acknowledge_command),
        )
        .route(
            "/desktop-agent/commands/{command_id}/progress",
            post(progress_command),
        )
        .route(
            "/desktop-agent/commands/{command_id}/terminal",
            post(terminal_command),
        )
        .route(
            "/desktop-agent/commands/{command_id}/disconnect-retire",
            post(disconnect::retire),
        )
        .route(
            "/desktop-agent/commands/{command_id}/disconnect-complete",
            post(disconnect::complete),
        )
}

async fn register_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(registration): Json<DesktopAgentDeviceRegistration>,
) -> ApiResult<(
    StatusCode,
    Json<crate::desktop_agent::DesktopAgentEnrollment>,
)> {
    let (owner, session_id) = require_local_session_actor(&state, &headers)?;
    let enrollment =
        state
            .storage
            .register_desktop_agent_device(&owner, &session_id, &registration)?;
    Ok((StatusCode::CREATED, Json(enrollment)))
}

async fn list_devices(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<crate::desktop_agent::DesktopAgentDeviceListResponse>> {
    let (owner, source_credential) = desktop_owner_source(&state, &headers)?;
    let devices = state
        .storage
        .list_desktop_agent_devices(&owner, &source_credential)?;
    Ok(Json(crate::desktop_agent::DesktopAgentDeviceListResponse {
        devices,
    }))
}

async fn submit_command(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<DesktopAgentSubmitWireRequest>,
) -> ApiResult<(StatusCode, Json<crate::desktop_agent::DesktopAgentCommand>)> {
    let (owner, source_credential) = desktop_owner_source(&state, &headers)?;
    let command = state.storage.submit_desktop_agent_command(
        &owner,
        &source_credential,
        parse_submit_request(request)?,
    )?;
    Ok((StatusCode::ACCEPTED, Json(command)))
}

async fn list_commands(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<DesktopAgentCommandPageQuery>,
) -> ApiResult<Json<crate::desktop_agent::DesktopAgentCommandPage>> {
    let (owner, source_credential) = desktop_owner_source(&state, &headers)?;
    let page = state.storage.list_desktop_agent_commands(
        &owner,
        &source_credential,
        query.limit,
        query.before.as_deref(),
    )?;
    Ok(Json(page))
}

async fn get_command(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(command_id): Path<String>,
) -> ApiResult<Json<crate::desktop_agent::DesktopAgentCommand>> {
    let (owner, source_credential) = desktop_owner_source(&state, &headers)?;
    Ok(Json(state.storage.get_desktop_agent_command(
        &command_id,
        &owner,
        &source_credential,
    )?))
}

async fn cancel_command(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(command_id): Path<String>,
) -> ApiResult<Json<crate::desktop_agent::DesktopAgentCommand>> {
    let (owner, source_credential) = desktop_owner_source(&state, &headers)?;
    Ok(Json(state.storage.cancel_desktop_agent_command(
        &command_id,
        &owner,
        &source_credential,
    )?))
}

async fn claim_command(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
    Json(request): Json<DesktopAgentClaimRequest>,
) -> ApiResult<Json<crate::desktop_agent::DesktopAgentClaimResponse>> {
    if !request.valid_wait_seconds() {
        return Err(ApiError::Validation(
            "invalid_desktop_agent_request".to_string(),
        ));
    }
    let assertion = request.assertion();
    let claim = state.storage.claim_desktop_agent_command(
        &device_id,
        device_bearer(&headers)?,
        &assertion,
    )?;
    Ok(Json(claim))
}

async fn heartbeat_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
    Json(assertion): Json<DesktopAgentDeviceAssertion>,
) -> ApiResult<StatusCode> {
    state.storage.heartbeat_desktop_agent_device(
        &device_id,
        device_bearer(&headers)?,
        &assertion,
    )?;
    Ok(StatusCode::NO_CONTENT)
}

async fn retire_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
    Json(assertion): Json<DesktopAgentDeviceAssertion>,
) -> ApiResult<StatusCode> {
    state
        .storage
        .retire_desktop_agent_device(&device_id, device_bearer(&headers)?, &assertion)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn revoke_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(device_id): Path<String>,
) -> ApiResult<StatusCode> {
    let (owner, source_credential) = desktop_owner_source(&state, &headers)?;
    state
        .storage
        .revoke_desktop_agent_device(&device_id, &owner, &source_credential)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn acknowledge_command(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(command_id): Path<String>,
    Json(request): Json<DesktopAgentAcknowledgeRequest>,
) -> ApiResult<StatusCode> {
    state.storage.acknowledge_desktop_agent_command(
        &command_id,
        device_bearer(&headers)?,
        &request,
    )?;
    Ok(StatusCode::NO_CONTENT)
}

async fn progress_command(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(command_id): Path<String>,
    Json(request): Json<DesktopAgentProgressRequest>,
) -> ApiResult<StatusCode> {
    state.storage.progress_desktop_agent_command(
        &command_id,
        device_bearer(&headers)?,
        &request,
    )?;
    Ok(StatusCode::NO_CONTENT)
}

async fn terminal_command(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(command_id): Path<String>,
    Json(request): Json<DesktopAgentTerminalRequest>,
) -> ApiResult<StatusCode> {
    state.storage.terminal_desktop_agent_command(
        &command_id,
        device_bearer(&headers)?,
        &request,
    )?;
    Ok(StatusCode::NO_CONTENT)
}

fn desktop_owner_source(
    state: &AppState,
    headers: &HeaderMap,
) -> ApiResult<(Actor, DriveCredential)> {
    let (actor, credential) = require_drive_actor_with_credential(state, headers)?;
    if actor.allowed_workspace_ids.is_some()
        || !matches!(
            credential,
            DriveCredential::UserSession(_) | DriveCredential::DelegatedAgentToken(_)
        )
    {
        return Err(ApiError::Forbidden);
    }
    Ok((actor, credential))
}

fn device_bearer(headers: &HeaderMap) -> ApiResult<&str> {
    explicit_bearer_token(headers)
        .filter(|token| token.starts_with("sxd_device_"))
        .ok_or(ApiError::Unauthenticated)
}

fn disconnect_completion_bearer(headers: &HeaderMap) -> ApiResult<&str> {
    explicit_bearer_token(headers)
        .filter(|token| token.starts_with("sxd_disconnect_"))
        .ok_or(ApiError::Unauthenticated)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DesktopAgentCommandPageQuery {
    limit: Option<i64>,
    before: Option<String>,
}
