use axum::{
    extract::{Query, State},
    http::HeaderMap,
    routing::get,
    Json, Router,
};
use serde::Serialize;

use super::query::{BoundedListQuery, PageMeta};
use crate::{
    auth::require_admin, error::ApiResult, server::AppState, storage::DebugSyncConflictSummary,
};

#[derive(Serialize)]
struct DebugSyncConflictsResponse {
    service: &'static str,
    resolution_tracking: &'static str,
    page: PageMeta,
    conflicts: Vec<DebugSyncConflictSummary>,
}

pub(super) fn router() -> Router<AppState> {
    Router::new().route("/debug/sync/conflicts", get(debug_sync_conflicts))
}

async fn debug_sync_conflicts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<BoundedListQuery>,
) -> ApiResult<Json<DebugSyncConflictsResponse>> {
    require_admin(&state, &headers)?;
    let limit = query.checked_limit()?;
    let (total, conflicts) = state.storage.debug_sync_conflict_summaries(limit as i64)?;
    Ok(Json(DebugSyncConflictsResponse {
        service: "shellx-drive",
        resolution_tracking: "conflict revisions remain discoverable while their file is live",
        page: PageMeta::new(total, conflicts.len(), limit, None),
        conflicts,
    }))
}
