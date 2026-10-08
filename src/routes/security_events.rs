use axum::{
    extract::{Query, State},
    http::HeaderMap,
    routing::get,
    Json, Router,
};
use serde::Deserialize;

use crate::{
    auth::require_admin,
    error::ApiResult,
    model::SecurityEventListResponse,
    server::AppState,
    storage::{MAX_SECURITY_EVENTS, SECURITY_EVENT_RETENTION_DAYS},
};

#[derive(Debug, Deserialize)]
struct SecurityEventQuery {
    category: Option<String>,
    outcome: Option<String>,
    query: Option<String>,
    before: Option<String>,
    before_id: Option<String>,
    limit: Option<usize>,
}

pub fn router() -> Router<AppState> {
    Router::new().route("/admin/security-events", get(list_security_events))
}

async fn list_security_events(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SecurityEventQuery>,
) -> ApiResult<Json<SecurityEventListResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(SecurityEventListResponse {
        events: state.storage.list_security_events(
            query.category.as_deref(),
            query.outcome.as_deref(),
            query.query.as_deref(),
            query.before.as_deref(),
            query.before_id.as_deref(),
            query.limit.unwrap_or(200),
        )?,
        retention_days: SECURITY_EVENT_RETENTION_DAYS,
        maximum_events: MAX_SECURITY_EVENTS,
    }))
}
