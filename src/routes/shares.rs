use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::Response,
    routing::{get, post},
    Router,
};
use serde::Deserialize;

use crate::{
    error::{ApiError, ApiResult},
    server::AppState,
};

mod access;
mod archive;
mod file_tickets;
mod guest_page;
mod management;
mod metadata;
mod public_content;
mod request_helpers;

pub(super) use access::load_public_share;
use guest_page::{render_link_unavailable_page, render_share_page};
use request_helpers::wants_json;

/// Query parameters accepted on the public read paths. All optional:
/// - `format=json` forces the machine-readable JSON metadata response.
/// - `path=<relpath>` selects a file inside a folder share's subtree.
#[derive(Debug, Default, Deserialize)]
pub(super) struct ShareAccessQuery {
    format: Option<String>,
    pub(super) path: Option<String>,
    #[serde(default)]
    pub(super) download: bool,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/pub/shares/{share_id}", get(public_share_view))
        .route(
            "/pub/shares/{share_id}/content",
            get(public_content::public_share_content_get)
                .post(public_content::public_share_content),
        )
        .route(
            "/pub/shares/{share_id}/thumbnail",
            get(public_content::public_share_thumbnail),
        )
        .route(
            "/pub/shares/{share_id}/download-zip",
            post(archive::public_share_bulk_download),
        )
        .merge(file_tickets::router())
        .merge(management::router())
}

/// `GET /pub/shares/{id}` — dual-use share view off a single capability id.
///
/// Content-negotiated: a browser (`Accept: text/html`) gets the HTML guest page;
/// an agent (`Accept: application/json` or `?format=json`) gets machine-readable
/// metadata. Read-only for both. Revoked or expired shares are `404` with no
/// metadata leak.
async fn public_share_view(
    State(state): State<AppState>,
    Path(share_id): Path<String>,
    Query(query): Query<ShareAccessQuery>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    if wants_json(&headers, &query) {
        let (record, target) = load_public_share(&state, &share_id)?;
        return metadata::public_share_metadata(&state, &share_id, &record, &target, &headers)
            .await;
    }
    match load_public_share(&state, &share_id) {
        Ok((record, target)) => Ok(render_share_page(
            &share_id,
            &target,
            record.password_required,
        )),
        // A browser capability URL must not reveal whether the identifier was
        // unknown, revoked, expired, or has exhausted its visit budget. API
        // callers take the JSON branch above and retain the generic 404.
        Err(ApiError::NotFound) => Ok(render_link_unavailable_page()),
        Err(error) => Err(error),
    }
}
