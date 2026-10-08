//! Public-share content and thumbnail response paths.

use axum::{
    extract::{Path, Query, State},
    http::{header, HeaderMap},
    response::Response,
    Json,
};

use crate::{
    blob,
    download_subjects::CurrentFileSubject,
    error::{ApiError, ApiResult},
    model::SharePasswordRequest,
    public_client_binding,
    routes::blob_response::{
        is_initial_content_request, is_safe_inline_file_name,
        serve_blob_file_with_guard_after_open, Disposition,
    },
    server::{request_client_fingerprint, AppState},
    storage::FileAccessKind,
};

use super::{
    access::{
        authorize_share_read, load_public_share, load_public_share_for_claimed_access,
        resolve_share_file, revalidate_share_file_publication, verify_share_password,
    },
    request_helpers::share_access_token_from_request,
    ShareAccessQuery,
};

mod thumbnail;

pub(super) use thumbnail::public_share_thumbnail;

const PUBLIC_SHARE_CONTENT_REQUESTS_PER_MINUTE: i64 = 240;

/// Serve raw public-share bytes after capability and subtree authorization.
pub(super) async fn public_share_content_get(
    State(state): State<AppState>,
    Path(share_id): Path<String>,
    Query(query): Query<ShareAccessQuery>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let (record, target) = load_public_share_for_claimed_access(&state, &share_id, &headers)?;
    authorize_share_read(&state, &share_id, &record, &headers).await?;
    if query.download && !record.share.allow_download {
        return Err(ApiError::Forbidden);
    }
    let client_fingerprint = request_client_fingerprint(&headers);
    state.storage.consume_partitioned_fixed_window_rate_limit(
        &share_id,
        "share_content",
        client_fingerprint,
        PUBLIC_SHARE_CONTENT_REQUESTS_PER_MINUTE,
        60,
    )?;
    let range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok());
    let file =
        resolve_share_file(&state, &share_id, &headers, &target, query.path.as_deref()).await?;
    let subject = CurrentFileSubject::from_file(&file)?;
    let path = blob::blob_file_path(&state.data_dir(), &subject.content_hash)?;
    let disposition = if query.download {
        Disposition::Attachment
    } else {
        Disposition::Inline
    };
    let stream_permit = state.try_public_body_stream(&share_id, client_fingerprint)?;
    let response = serve_blob_file_with_guard_after_open(
        &file.name,
        &path,
        range,
        disposition,
        stream_permit,
        || {
            let (live_record, live_file) = revalidate_share_file_publication(
                &state,
                &share_id,
                &target.id,
                &record.authorization_fingerprint(),
                &subject,
            )?;
            if query.download && !live_record.share.allow_download {
                return Err(ApiError::Forbidden);
            }
            if !live_record.share.allow_download && !is_safe_inline_file_name(&live_file.name) {
                return Err(ApiError::Forbidden);
            }
            Ok(())
        },
    )
    .await?;
    if is_initial_content_request(range) {
        state.storage.record_public_share_file_access_once(
            &share_id,
            &file.id,
            &file.workspace_id,
            client_fingerprint,
            if query.download {
                FileAccessKind::Download
            } else {
                FileAccessKind::Access
            },
        )?;
    }
    Ok(response)
}

/// Build one recursive archive from selected rows in a public folder share.
/// Authentication and capability scoping are identical to metadata/content
/// reads; the archive engine adds independent entry and byte bounds.
/// Preserve the original password-body content contract for legacy clients.
pub(super) async fn public_share_content(
    State(state): State<AppState>,
    Path(share_id): Path<String>,
    Query(query): Query<ShareAccessQuery>,
    headers: HeaderMap,
    Json(request): Json<SharePasswordRequest>,
) -> ApiResult<Response> {
    let (record, target) = load_public_share(&state, &share_id)?;
    verify_share_password(
        &state,
        &share_id,
        &record,
        Some(&request.password),
        ApiError::Forbidden,
        request_client_fingerprint(&headers),
    )
    .await?;
    if record.share.max_uses.is_some() {
        if let Some(token) = share_access_token_from_request(&headers) {
            let client_binding = public_client_binding::require(&state, &headers)?;
            state
                .storage
                .validate_share_access_grant(&share_id, Some(token), &client_binding)?;
        } else {
            // Preserve the legacy password-only POST contract without letting
            // it bypass a finite share's atomic use budget. Modern clients
            // claim through metadata and present the returned grant; a legacy
            // request consumes exactly one use before any body is published.
            state.storage.claim_share_access(
                &share_id,
                &record.authorization_fingerprint(),
                request_client_fingerprint(&headers),
            )?;
        }
    } else {
        state.storage.validate_unlimited_share_authorization(
            &share_id,
            &record.authorization_fingerprint(),
        )?;
    }
    if !record.share.allow_download {
        return Err(ApiError::Forbidden);
    }
    let client_fingerprint = request_client_fingerprint(&headers);
    state.storage.consume_partitioned_fixed_window_rate_limit(
        &share_id,
        "share_content",
        client_fingerprint,
        PUBLIC_SHARE_CONTENT_REQUESTS_PER_MINUTE,
        60,
    )?;
    let path = request.path.as_deref().or(query.path.as_deref());
    let file = resolve_share_file(&state, &share_id, &headers, &target, path).await?;
    let subject = CurrentFileSubject::from_file(&file)?;
    let blob_path = blob::blob_file_path(&state.data_dir(), &subject.content_hash)?;
    let range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok());
    if is_initial_content_request(range) {
        state.storage.record_public_share_file_access_once(
            &share_id,
            &file.id,
            &file.workspace_id,
            client_fingerprint,
            FileAccessKind::Download,
        )?;
    }
    let stream_permit = state.try_public_body_stream(&share_id, client_fingerprint)?;
    serve_blob_file_with_guard_after_open(
        &file.name,
        &blob_path,
        range,
        Disposition::Attachment,
        stream_permit,
        || {
            let (live_record, _) = revalidate_share_file_publication(
                &state,
                &share_id,
                &target.id,
                &record.authorization_fingerprint(),
                &subject,
            )?;
            if !live_record.share.allow_download {
                return Err(ApiError::Forbidden);
            }
            Ok(())
        },
    )
    .await
}
