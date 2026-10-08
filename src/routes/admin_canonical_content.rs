//! Bounded administrator inventory for canonical Drive content.  This is kept
//! separate from general admin settings so ownership-tree reads remain small
//! and independently reviewable.

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::get,
    Json, Router,
};
use serde::Deserialize;

use crate::{
    auth::require_admin_with_credential,
    error::ApiResult,
    model::{CanonicalContentResponse, CanonicalShareDetailsResponse},
    server::AppState,
};

const DEFAULT_CONTENT_PAGE_LIMIT: usize = 50;
const DEFAULT_SHARE_DETAIL_PAGE_LIMIT: usize = 25;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/canonical-content", get(list_canonical_content))
        .route(
            "/admin/canonical-content/{file_id}/share-details",
            get(canonical_share_details),
        )
}

#[derive(Debug, Deserialize)]
struct CanonicalContentQuery {
    limit: Option<usize>,
    cursor: Option<String>,
    query: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CanonicalShareDetailsQuery {
    kind: String,
    limit: Option<usize>,
    cursor: Option<String>,
}

async fn list_canonical_content(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<CanonicalContentQuery>,
) -> ApiResult<Json<CanonicalContentResponse>> {
    let (actor, credential) = require_admin_with_credential(&state, &headers)?;
    let response = state.storage.list_canonical_content(
        query.limit.unwrap_or(DEFAULT_CONTENT_PAGE_LIMIT),
        query.cursor.as_deref(),
        query.query.as_deref(),
    )?;
    state
        .storage
        .ensure_admin_publication_authorized(&actor, &credential)?;
    Ok(Json(response))
}

async fn canonical_share_details(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
    Query(query): Query<CanonicalShareDetailsQuery>,
) -> ApiResult<Json<CanonicalShareDetailsResponse>> {
    let (actor, credential) = require_admin_with_credential(&state, &headers)?;
    let response = state.storage.canonical_share_details(
        &file_id,
        &query.kind,
        query.limit.unwrap_or(DEFAULT_SHARE_DETAIL_PAGE_LIMIT),
        query.cursor.as_deref(),
    )?;
    state
        .storage
        .ensure_admin_publication_authorized(&actor, &credential)?;
    Ok(Json(response))
}
