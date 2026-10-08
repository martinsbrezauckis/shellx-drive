use axum::{
    extract::{Query, State},
    http::HeaderMap,
    routing::get,
    Json, Router,
};
use serde::Serialize;

use super::query::{BoundedListQuery, PageMeta};
use crate::{
    auth::require_admin, error::ApiResult, server::AppState, storage::DebugWorkspaceSummary,
};

#[derive(Serialize)]
struct DebugWorkspacesResponse {
    service: &'static str,
    page: PageMeta,
    workspaces: Vec<DebugWorkspaceSummary>,
}

pub(super) fn router() -> Router<AppState> {
    Router::new().route("/debug/workspaces", get(debug_workspaces))
}

async fn debug_workspaces(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<BoundedListQuery>,
) -> ApiResult<Json<DebugWorkspacesResponse>> {
    require_admin(&state, &headers)?;
    let limit = query.checked_limit()?;
    let (total, workspaces) = state.storage.debug_workspace_summaries(limit as i64)?;
    Ok(Json(DebugWorkspacesResponse {
        service: "shellx-drive",
        page: PageMeta::new(total, workspaces.len(), limit, None),
        workspaces,
    }))
}
