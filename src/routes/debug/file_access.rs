use axum::{
    extract::{Query, State},
    http::HeaderMap,
    routing::get,
    Json, Router,
};
use serde::Serialize;

use super::query::{BoundedSnapshotQuery, PageMeta};
use crate::{
    auth::require_admin, error::ApiResult, server::AppState, storage::DebugFileAccessSummary,
};

#[derive(Serialize)]
struct DebugFileAccessResponse {
    service: &'static str,
    identifiers_redacted: bool,
    names_and_paths_redacted: bool,
    page: PageMeta,
    workspaces: Vec<DebugFileAccessSummary>,
}

pub(super) fn router() -> Router<AppState> {
    Router::new().route("/debug/file-access", get(debug_file_access))
}

async fn debug_file_access(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<BoundedSnapshotQuery>,
) -> ApiResult<Json<DebugFileAccessResponse>> {
    require_admin(&state, &headers)?;
    let limit = query.checked_limit()?;
    let (total, workspaces) = state.storage.debug_file_access_summaries(limit as i64)?;
    Ok(Json(DebugFileAccessResponse {
        service: "shellx-drive",
        identifiers_redacted: true,
        names_and_paths_redacted: true,
        page: PageMeta::new(total, workspaces.len(), limit, None),
        workspaces,
    }))
}
