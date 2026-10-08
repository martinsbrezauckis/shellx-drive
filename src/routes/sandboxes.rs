use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};

mod render;

use crate::{
    auth::{require_admin, require_admin_with_credential},
    error::ApiResult,
    model::{
        SandboxApplyIntentResponse, SandboxPreviewResponse, SandboxProfileMutationResponse,
        SandboxProfileResponse, UpdateSandboxProfileRequest,
    },
    server::AppState,
};

pub use render::preview_for_profile;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/sandbox", get(get_sandbox).patch(update_sandbox))
        .route("/admin/sandbox/preview", post(preview_sandbox))
        .route("/admin/sandbox/apply-intent", post(apply_sandbox_intent))
}

async fn get_sandbox(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<SandboxProfileResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(SandboxProfileResponse {
        profile: state.storage.get_sandbox_profile()?,
    }))
}

async fn update_sandbox(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<UpdateSandboxProfileRequest>,
) -> ApiResult<Json<SandboxProfileMutationResponse>> {
    let (actor, source_credential) = require_admin_with_credential(&state, &headers)?;
    let (profile, receipt) =
        state
            .storage
            .update_sandbox_profile_authorized(request, &actor, &source_credential)?;
    Ok(Json(SandboxProfileMutationResponse { profile, receipt }))
}

async fn preview_sandbox(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<SandboxPreviewResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(preview_for_profile(
        state.storage.get_sandbox_profile()?,
        state.config.public_origin.as_str(),
    )?))
}

async fn apply_sandbox_intent(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<(StatusCode, Json<SandboxApplyIntentResponse>)> {
    let (actor, source_credential) = require_admin_with_credential(&state, &headers)?;
    let (profile, receipt) = state
        .storage
        .record_sandbox_apply_intent_authorized(&actor, &source_credential)?;
    let preview = preview_for_profile(profile, state.config.public_origin.as_str())?;
    Ok((
        StatusCode::ACCEPTED,
        Json(SandboxApplyIntentResponse {
            profile: preview.profile,
            commands: preview.commands,
            unit_preview: preview.unit_preview,
            receipt,
        }),
    ))
}
