//! Short-lived native file tickets for public shares.
//!
//! Browser pages authenticate this preparation request with their share
//! password/grant. The follow-up navigation carries only a short-lived ticket,
//! so a large response body never has to pass through JavaScript as a `Blob`.

use axum::{
    extract::{Path, State},
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};

use crate::{
    blob,
    download_subjects::CurrentFileSubject,
    download_tickets::{FileTicketDisposition, FILE_DOWNLOAD_TICKET_TTL_SECONDS},
    error::{ApiError, ApiResult},
    model::FileKind,
    public_client_binding::{self, PublicClientBinding},
    routes::blob_response::is_safe_inline_file_name,
    server::{request_client_fingerprint, AppState},
};

use super::{
    access::{authorize_share_read, load_public_share_for_claimed_access, resolve_share_file},
    request_helpers::share_access_token_from_request,
};

const PUBLIC_FILE_TICKETS_PER_WORKSPACE_CLIENT_PER_MINUTE: i64 = 32;

#[derive(Debug, Default, Deserialize)]
struct PublicShareFileTicketRequest {
    path: Option<String>,
}

#[derive(Serialize)]
struct PreparedPublicShareDownload {
    download_url: String,
    expires_in_seconds: u64,
}

#[derive(Serialize)]
struct PreparedPublicSharePreview {
    content_url: String,
    expires_in_seconds: u64,
}

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/pub/shares/{share_id}/download",
            post(prepare_public_share_download),
        )
        .route(
            "/pub/shares/{share_id}/preview",
            post(prepare_public_share_preview),
        )
}

/// Prepare an attachment ticket after the ordinary public-share authorization
/// boundary. Redeeming it later revalidates the share and its selected file.
async fn prepare_public_share_download(
    State(state): State<AppState>,
    Path(share_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<PublicShareFileTicketRequest>,
) -> ApiResult<Response> {
    let client_binding = response_client_binding(&state, &headers)?;
    let ticket = issue_public_share_file_ticket(
        &state,
        &share_id,
        &headers,
        request.path.as_deref(),
        FileTicketDisposition::Attachment,
        client_binding.fingerprint(),
    )
    .await?;
    let mut response = Json(PreparedPublicShareDownload {
        download_url: format!("/downloads/files/{ticket}"),
        expires_in_seconds: FILE_DOWNLOAD_TICKET_TTL_SECONDS,
    })
    .into_response();
    client_binding.apply_cookie(response.headers_mut());
    Ok(response)
}

/// Prepare a bounded-reuse inline ticket for a protected image or video. This
/// lets the browser use its normal media pipeline, including byte ranges,
/// without exposing the share password in a media URL.
async fn prepare_public_share_preview(
    State(state): State<AppState>,
    Path(share_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<PublicShareFileTicketRequest>,
) -> ApiResult<Response> {
    let client_binding = response_client_binding(&state, &headers)?;
    let ticket = issue_public_share_file_ticket(
        &state,
        &share_id,
        &headers,
        request.path.as_deref(),
        FileTicketDisposition::Inline,
        client_binding.fingerprint(),
    )
    .await?;
    let mut response = Json(PreparedPublicSharePreview {
        content_url: format!("/downloads/files/{ticket}"),
        expires_in_seconds: FILE_DOWNLOAD_TICKET_TTL_SECONDS,
    })
    .into_response();
    client_binding.apply_cookie(response.headers_mut());
    Ok(response)
}

async fn issue_public_share_file_ticket(
    state: &AppState,
    share_id: &str,
    headers: &HeaderMap,
    path: Option<&str>,
    disposition: FileTicketDisposition,
    client_binding: &str,
) -> ApiResult<String> {
    let (record, target) = load_public_share_for_claimed_access(state, share_id, headers)?;
    authorize_share_read(state, share_id, &record, headers).await?;
    let client_fingerprint = request_client_fingerprint(headers);
    state.storage.consume_partitioned_public_rate_limit(
        &target.workspace_id,
        "share_file_ticket",
        client_fingerprint,
        PUBLIC_FILE_TICKETS_PER_WORKSPACE_CLIENT_PER_MINUTE,
        60,
    )?;
    let file = resolve_share_file(state, share_id, headers, &target, path).await?;
    if !matches!(file.kind, FileKind::File) {
        return Err(ApiError::NotFound);
    }

    match disposition {
        FileTicketDisposition::Attachment if !record.share.allow_download => {
            return Err(ApiError::Forbidden);
        }
        FileTicketDisposition::Inline
            if !record.share.allow_download && !is_safe_inline_file_name(&file.name) =>
        {
            return Err(ApiError::Forbidden);
        }
        _ => {}
    }

    let subject = CurrentFileSubject::from_file(&file)?;
    let blob_path = blob::blob_file_path(&state.data_dir(), &subject.content_hash)?;
    let actual_size = tokio::fs::metadata(&blob_path).await?.len();
    if actual_size != subject.expected_size {
        return Err(ApiError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "stored blob size does not match share metadata",
        )));
    }

    state.file_download_tickets.issue_for_share(
        file.name,
        blob_path,
        disposition,
        share_id.to_string(),
        target.id,
        subject,
        file.workspace_id,
        record.authorization_fingerprint(),
        client_binding.to_string(),
    )
}

fn response_client_binding(
    state: &AppState,
    headers: &HeaderMap,
) -> ApiResult<PublicClientBinding> {
    if share_access_token_from_request(headers).is_some() {
        public_client_binding::require_binding(state, headers)
    } else {
        public_client_binding::provision(state, headers)
    }
}
