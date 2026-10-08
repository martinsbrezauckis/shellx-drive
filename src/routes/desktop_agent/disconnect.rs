use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    Json,
};

use crate::{
    desktop_agent::{
        DesktopAgentDisconnectCompletionRequest, DesktopAgentDisconnectRetirementRequest,
    },
    error::ApiResult,
    server::AppState,
};

pub(super) async fn retire(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(command_id): Path<String>,
    Json(request): Json<DesktopAgentDisconnectRetirementRequest>,
) -> ApiResult<StatusCode> {
    state.storage.begin_desktop_agent_disconnect_retirement(
        &command_id,
        super::disconnect_completion_bearer(&headers)?,
        &request,
    )?;
    Ok(StatusCode::NO_CONTENT)
}

pub(super) async fn complete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(command_id): Path<String>,
    Json(request): Json<DesktopAgentDisconnectCompletionRequest>,
) -> ApiResult<StatusCode> {
    state.storage.complete_desktop_agent_disconnect(
        &command_id,
        super::disconnect_completion_bearer(&headers)?,
        &request,
    )?;
    Ok(StatusCode::NO_CONTENT)
}
