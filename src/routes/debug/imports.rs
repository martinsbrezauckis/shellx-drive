use axum::{
    extract::{Query, State},
    http::HeaderMap,
    routing::get,
    Json, Router,
};
use serde::Serialize;

use super::query::{BoundedListQuery, PageMeta};
use crate::{auth::require_admin, error::ApiResult, server::AppState, storage::DebugImportSummary};

#[derive(Serialize)]
struct DebugImportsResponse {
    service: &'static str,
    active_operations: i64,
    failure_history_persisted: bool,
    page: PageMeta,
    operations: Vec<DebugImportSummary>,
}

pub(super) fn router() -> Router<AppState> {
    Router::new().route("/debug/imports", get(debug_imports))
}

async fn debug_imports(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<BoundedListQuery>,
) -> ApiResult<Json<DebugImportsResponse>> {
    require_admin(&state, &headers)?;
    let limit = query.checked_limit()?;
    let (total, operations) = state.storage.debug_import_summaries(limit as i64)?;
    Ok(Json(DebugImportsResponse {
        service: "shellx-drive",
        active_operations: state.storage.debug_active_import_run_count()?,
        failure_history_persisted: true,
        page: PageMeta::new(total, operations.len(), limit, None),
        operations,
    }))
}
