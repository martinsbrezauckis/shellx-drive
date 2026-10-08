use axum::{
    body::to_bytes,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::header,
    routing::put,
    Json, Router,
};
use serde::Deserialize;

use crate::{
    error::{ApiError, ApiResult},
    model::UploadChunkResponse,
    server::AppState,
};

use super::{
    authorize_upload_chunk, put_upload_bytes, UploadChunkAuthorization, MAX_RESUMABLE_CHUNK_BYTES,
};

#[derive(Debug, Deserialize)]
struct BinaryChunkQuery {
    offset: i64,
    #[serde(default)]
    finish: bool,
}

pub(super) fn router() -> Router<AppState> {
    Router::new().route(
        "/uploads/resumable/{upload_id}/content",
        put(put_binary_chunk).layer(DefaultBodyLimit::max(MAX_RESUMABLE_CHUNK_BYTES)),
    )
}

async fn put_binary_chunk(
    State(state): State<AppState>,
    Path(upload_id): Path<String>,
    Query(query): Query<BinaryChunkQuery>,
    request: Request,
) -> ApiResult<Json<UploadChunkResponse>> {
    let headers = request.headers().clone();
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    if !content_type.split(';').next().is_some_and(|value| {
        value
            .trim()
            .eq_ignore_ascii_case("application/octet-stream")
    }) {
        return Err(ApiError::Validation(
            "binary upload chunks require application/octet-stream".to_string(),
        ));
    }
    let actor = match authorize_upload_chunk(&state, &headers, &upload_id, query.finish)? {
        UploadChunkAuthorization::Active(actor) => actor,
        UploadChunkAuthorization::Completed(response) => return Ok(Json(*response)),
    };
    let ingress_permit = state.try_authenticated_upload_ingress(&actor.email)?;
    let body = to_bytes(request.into_body(), MAX_RESUMABLE_CHUNK_BYTES)
        .await
        .map_err(|_| {
            ApiError::PayloadTooLarge(format!(
                "upload chunks must not exceed {MAX_RESUMABLE_CHUNK_BYTES} bytes"
            ))
        })?;
    put_upload_bytes(
        state,
        headers,
        upload_id,
        query.offset,
        query.finish,
        body.to_vec(),
        ingress_permit,
    )
    .await
}
