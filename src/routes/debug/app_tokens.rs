use axum::{
    extract::{Query, State},
    http::HeaderMap,
    routing::get,
    Json, Router,
};
use serde::Serialize;

use super::query::{BoundedListQuery, PageMeta};
use crate::{
    auth::require_admin, error::ApiResult, server::AppState, storage::DebugAppTokenSummary,
};

#[derive(Serialize)]
struct DebugAppTokensResponse {
    service: &'static str,
    token_values_redacted: bool,
    page: PageMeta,
    app_tokens: Vec<DebugAppTokenSummary>,
}

pub(super) fn router() -> Router<AppState> {
    Router::new().route("/debug/app-tokens", get(debug_app_tokens))
}

async fn debug_app_tokens(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<BoundedListQuery>,
) -> ApiResult<Json<DebugAppTokensResponse>> {
    require_admin(&state, &headers)?;
    let limit = query.checked_limit()?;
    let (total, app_tokens) = state.storage.debug_app_token_summaries(limit as i64)?;
    Ok(Json(DebugAppTokensResponse {
        service: "shellx-drive",
        token_values_redacted: true,
        page: PageMeta::new(total, app_tokens.len(), limit, None),
        app_tokens,
    }))
}
