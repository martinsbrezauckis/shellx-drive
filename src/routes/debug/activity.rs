use axum::{
    extract::{Query, State},
    http::HeaderMap,
    routing::get,
    Json, Router,
};
use serde::Serialize;

use super::query::{BoundedListQuery, PageMeta};
use crate::{
    auth::require_admin, error::ApiResult, server::AppState, storage::DebugActivitySummary,
};

#[derive(Serialize)]
struct DebugActivityResponse {
    service: &'static str,
    page: PageMeta,
    activity: Vec<DebugActivitySummary>,
}

pub(super) fn router() -> Router<AppState> {
    Router::new().route("/debug/activity", get(debug_activity))
}

async fn debug_activity(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<BoundedListQuery>,
) -> ApiResult<Json<DebugActivityResponse>> {
    require_admin(&state, &headers)?;
    let limit = query.checked_limit()?;
    let (total, activity) = state.storage.debug_activity_summaries(
        limit as i64,
        query.normalized_before(),
        query.normalized_kind(),
    )?;
    let next_before = (total > activity.len() as i64)
        .then(|| activity.last().map(|row| row.created_at.clone()))
        .flatten();
    Ok(Json(DebugActivityResponse {
        service: "shellx-drive",
        page: PageMeta::new(total, activity.len(), limit, next_before),
        activity,
    }))
}
