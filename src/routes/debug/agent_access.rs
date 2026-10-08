use axum::{
    extract::{Query, State},
    http::HeaderMap,
    routing::get,
    Json, Router,
};
use serde::Serialize;

use super::query::{BoundedSnapshotQuery, PageMeta};
use crate::{
    auth::require_admin, error::ApiResult, server::AppState, storage::DebugAgentHealthSummary,
};

#[derive(Serialize)]
struct DebugAgentAccessResponse {
    service: &'static str,
    identifiers_redacted: bool,
    token_values_redacted: bool,
    token_hashes_redacted: bool,
    names_and_paths_redacted: bool,
    page: PageMeta,
    principals: Vec<DebugAgentHealthSummary>,
}

pub(super) fn router() -> Router<AppState> {
    Router::new().route("/debug/agent-access", get(debug_agent_access))
}

async fn debug_agent_access(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<BoundedSnapshotQuery>,
) -> ApiResult<Json<DebugAgentAccessResponse>> {
    require_admin(&state, &headers)?;
    let limit = query.checked_limit()?;
    let (total, principals) = state.storage.debug_agent_health_summaries(limit as i64)?;
    Ok(Json(DebugAgentAccessResponse {
        service: "shellx-drive",
        identifiers_redacted: true,
        token_values_redacted: true,
        token_hashes_redacted: true,
        names_and_paths_redacted: true,
        page: PageMeta::new(total, principals.len(), limit, None),
        principals,
    }))
}
