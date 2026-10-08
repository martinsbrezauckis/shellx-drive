use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};

use crate::{
    auth::{require_admin, require_admin_with_credential},
    error::{ApiError, ApiResult},
    model::{
        CreateHostedTenantRequest, DebugHostedResponse, HostedSignupRequest, HostedSignupResponse,
        HostedStatusResponse, HostedTenantListResponse, HostedTenantResponse,
    },
    server::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/hosted/status", get(hosted_status))
        .route("/hosted/signup", post(hosted_signup))
        .route(
            "/admin/hosted/tenants",
            get(admin_list_tenants).post(admin_create_tenant),
        )
}

pub(crate) fn hosted_status_for_state(state: &AppState) -> ApiResult<HostedStatusResponse> {
    Ok(HostedStatusResponse {
        hosted_mode: state.config.hosted_mode,
        public_base_url: state.config.public_origin.as_str().to_string(),
        billing_provider: state.config.hosted_billing_provider.clone(),
        public_rate_limit_per_minute: state.config.hosted_public_rate_limit_per_minute,
        public_signup_enabled: state.storage.registration_enabled()?,
        backup_scheduler: "admin_policy".to_string(),
        drop_malware_scanning: "not_configured".to_string(),
    })
}

pub(crate) fn debug_hosted_response(state: &AppState) -> ApiResult<DebugHostedResponse> {
    Ok(DebugHostedResponse {
        service: "shellx-drive".to_string(),
        status: hosted_status_for_state(state)?,
        tenants: state.storage.list_hosted_tenants()?,
    })
}

async fn hosted_status(State(state): State<AppState>) -> ApiResult<Json<HostedStatusResponse>> {
    Ok(Json(hosted_status_for_state(&state)?))
}

async fn admin_list_tenants(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<HostedTenantListResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(HostedTenantListResponse {
        tenants: state.storage.list_hosted_tenants()?,
    }))
}

async fn admin_create_tenant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateHostedTenantRequest>,
) -> ApiResult<(StatusCode, Json<HostedTenantResponse>)> {
    let (actor, source_credential) = require_admin_with_credential(&state, &headers)?;
    let (tenant, receipt) = state.storage.create_hosted_tenant_authorized(
        &request.name,
        &request.owner_email,
        request.plan.as_deref().unwrap_or("manual"),
        request.billing_status.as_deref().unwrap_or("manual"),
        &actor,
        &source_credential,
    )?;
    Ok((
        StatusCode::CREATED,
        Json(HostedTenantResponse { tenant, receipt }),
    ))
}

async fn hosted_signup(
    State(_state): State<AppState>,
    _headers: HeaderMap,
    Json(_request): Json<HostedSignupRequest>,
) -> ApiResult<(StatusCode, Json<HostedSignupResponse>)> {
    Err(ApiError::Forbidden)
}
