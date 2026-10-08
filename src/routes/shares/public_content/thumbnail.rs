use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap},
    response::Response,
};

use crate::{
    blob,
    download_subjects::CurrentFileSubject,
    error::{ApiError, ApiResult},
    routes::blob_response::{
        serve_blob_file_with_overrides_and_guard_after_open, BlobResponseOverrides, Disposition,
    },
    server::{request_client_fingerprint, AppState},
};

use super::super::{
    access::{
        authorize_share_read, load_public_share_for_claimed_access, resolve_share_file,
        revalidate_share_file_publication,
    },
    ShareAccessQuery,
};

/// Capability-scoped PNG thumbnail for a shared image. Folder shares select a
/// descendant with `?path=` and retain the same live-subject authorization.
pub(in crate::routes::shares) async fn public_share_thumbnail(
    State(state): State<AppState>,
    Path(share_id): Path<String>,
    Query(query): Query<ShareAccessQuery>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let (record, target) = load_public_share_for_claimed_access(&state, &share_id, &headers)?;
    authorize_share_read(&state, &share_id, &record, &headers).await?;
    let file =
        resolve_share_file(&state, &share_id, &headers, &target, query.path.as_deref()).await?;
    let preview = state
        .storage
        .get_file_preview(&file.id)?
        .ok_or(ApiError::NotFound)?;
    let subject = CurrentFileSubject::from_file(&file)?;
    let thumbnail_hash = preview.thumbnail_hash.ok_or(ApiError::NotFound)?;
    let path = blob::blob_file_path(&state.data_dir(), &thumbnail_hash)?;
    let range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok());
    let stream_permit =
        state.try_public_body_stream(&share_id, request_client_fingerprint(&headers))?;
    serve_blob_file_with_overrides_and_guard_after_open(
        "thumbnail.png",
        &path,
        range,
        Disposition::Inline,
        Some(BlobResponseOverrides::IMAGE_CACHE),
        stream_permit,
        || {
            revalidate_share_file_publication(
                &state,
                &share_id,
                &target.id,
                &record.authorization_fingerprint(),
                &subject,
            )?;
            let live_preview = state
                .storage
                .get_file_preview(&subject.file_id)?
                .ok_or(ApiError::NotFound)?;
            if live_preview.revision != subject.revision
                || live_preview.thumbnail_hash.as_deref() != Some(thumbnail_hash.as_str())
            {
                return Err(ApiError::NotFound);
            }
            Ok(())
        },
    )
    .await
}
