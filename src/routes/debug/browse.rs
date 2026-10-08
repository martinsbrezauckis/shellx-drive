use axum::{extract::State, http::HeaderMap, routing::get, Json, Router};
use serde_json::json;

use crate::{
    auth::require_admin,
    error::ApiResult,
    model::{DebugBrowseResponse, DebugBrowseTotals},
    server::AppState,
};

pub(super) fn router() -> Router<AppState> {
    Router::new().route("/debug/browse", get(debug_browse))
}

async fn debug_browse(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<DebugBrowseResponse>> {
    require_admin(&state, &headers)?;
    let (workspaces, large_folders) = state.storage.debug_browse_aggregates()?;
    let totals = DebugBrowseTotals {
        workspaces: workspaces.len() as i64,
        live_files: workspaces.iter().map(|row| row.live_files).sum(),
        live_folders: workspaces.iter().map(|row| row.live_folders).sum(),
        trashed_items: workspaces.iter().map(|row| row.trashed_items).sum(),
        current_file_bytes: workspaces.iter().map(|row| row.current_file_bytes).sum(),
        max_direct_children: workspaces
            .iter()
            .map(|row| row.max_direct_children)
            .max()
            .unwrap_or(0),
    };
    Ok(Json(DebugBrowseResponse {
        service: "shellx-drive".to_string(),
        page_size: 100,
        large_folders_limit: 50,
        folder_size_semantics:
            "recursive current non-trashed descendant file body bytes; excludes revisions, backups, previews, and storage overhead"
                .to_string(),
        supported_sort_keys: ["name", "modified", "size", "type"]
            .into_iter()
            .map(str::to_string)
            .collect(),
        supported_filter_keys: [
            "type",
            "owner_relationship",
            "modified_range",
            "location",
            "guest_link",
            "starred",
            "offline",
        ]
        .into_iter()
        .map(str::to_string)
        .collect(),
        totals,
        workspaces,
        large_folders,
    }))
}

pub(super) fn debug_browse_value(state: &AppState) -> ApiResult<serde_json::Value> {
    let (workspaces, large_folders) = state.storage.debug_browse_aggregates()?;
    Ok(json!({
        "page_size": 100,
        "large_folders_limit": 50,
        "workspaces": workspaces,
        "large_folders": large_folders,
    }))
}
