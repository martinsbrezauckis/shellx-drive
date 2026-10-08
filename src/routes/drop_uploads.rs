use axum::{
    body::to_bytes,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use serde::Deserialize;
use std::time::Duration;

use crate::{
    auth::constant_time_str_eq,
    error::{ApiError, ApiResult},
    model::{CreatePublicDropUploadRequest, PublicDropUploadResponse, PublicDropUploadSession},
    routes::ui,
    server::{request_client_fingerprint, AppState},
    storage::{DropUploadAdmissionPolicy, DropUploadRecord, DropUploadSessionCreate},
};

mod auth;
pub(crate) mod cleanup;
mod execution;
mod file_io;
mod preflight;

use auth::{authenticate_drop, ensure_drop_active};

const MAX_DROP_UPLOAD_BYTES: i64 = 2 * 1024 * 1024 * 1024;
const MAX_DROP_CHUNK_BYTES: usize = 8 * 1024 * 1024;
const DROP_CHUNK_BODY_TIMEOUT_SECONDS: u64 = 60;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/pub/drops/{drop_id}", get(public_drop_page))
        .route("/pub/drops/{drop_id}/preflight", post(preflight::preflight))
        .route(
            "/pub/drops/{drop_id}/uploads",
            post(create_session).layer(DefaultBodyLimit::max(16 * 1024)),
        )
        .route(
            "/pub/drops/{drop_id}/uploads/{session_id}",
            put(put_chunk).layer(DefaultBodyLimit::max(MAX_DROP_CHUNK_BYTES)),
        )
        .route(
            "/pub/drops/{drop_id}/uploads/{session_id}/cancel",
            post(cancel_session),
        )
}

#[derive(Debug, Deserialize)]
struct ChunkQuery {
    offset: i64,
    #[serde(default)]
    finish: bool,
}

async fn create_session(
    State(state): State<AppState>,
    Path(drop_id): Path<String>,
    request: Request,
) -> ApiResult<Response> {
    let headers = request.headers().clone();
    let transport_fingerprint = request_client_fingerprint(&headers);
    let (record, client_binding) = authenticate_drop(&state, &drop_id, &headers).await?;
    require_json_content_type(&headers)?;
    let body = to_bytes(request.into_body(), 16 * 1024)
        .await
        .map_err(|_| {
            ApiError::PayloadTooLarge(
                "drop upload metadata must not exceed 16384 bytes".to_string(),
            )
        })?;
    let request: CreatePublicDropUploadRequest = serde_json::from_slice(&body)
        .map_err(|error| ApiError::Validation(format!("invalid drop upload metadata: {error}")))?;
    validate_total_size(request.total_size)?;
    state
        .storage
        .ensure_workspace_server_content_allowed(&record.drop.workspace_id)?;
    state
        .storage
        .ensure_workspace_quota(&record.drop.workspace_id, None, request.total_size)?;
    let (session, receipt) = state
        .storage
        .create_drop_upload_session(DropUploadSessionCreate {
            drop_id: &drop_id,
            workspace_id: &record.drop.workspace_id,
            client_fingerprint: client_binding.fingerprint(),
            transport_fingerprint,
            expected_authorization_fingerprint: &record.authorization_fingerprint(),
            name: &request.name,
            path: request.path.as_deref(),
            content_type: request.content_type.as_deref(),
            total_size: request.total_size,
            policy: DropUploadAdmissionPolicy::default(),
        })?;
    crate::fs_private::create_dir_all_private(&file_io::drop_upload_dir(&state))?;
    let mut receipt = receipt;
    receipt.target_id = None;
    let mut response = (
        StatusCode::CREATED,
        Json(PublicDropUploadResponse {
            session: public_session(&session),
            receipt: Some(receipt),
        }),
    )
        .into_response();
    client_binding.apply_cookie(response.headers_mut());
    Ok(response)
}

async fn put_chunk(
    State(state): State<AppState>,
    Path((drop_id, session_id)): Path<(String, String)>,
    Query(query): Query<ChunkQuery>,
    request: Request,
) -> ApiResult<Json<PublicDropUploadResponse>> {
    let headers = request.headers().clone();
    let (drop_record, client_binding) = authenticate_drop(&state, &drop_id, &headers).await?;
    let proof_fingerprint = client_binding.fingerprint().to_string();
    let transport_fingerprint = request_client_fingerprint(&headers).to_string();
    require_binary_content_type(&headers)?;
    state
        .storage
        .ensure_workspace_server_content_allowed(&drop_record.drop.workspace_id)?;
    let session = bound_active_session(&state, &drop_id, &session_id, &proof_fingerprint)?;
    if query.offset != session.received_bytes {
        return Err(ApiError::Conflict);
    }
    state
        .storage
        .ensure_workspace_quota(&session.workspace_id, None, session.total_size)?;
    let chunk_ingress_permit =
        state.try_public_drop_chunk_ingress(&drop_id, &transport_fingerprint)?;
    let body = tokio::time::timeout(
        Duration::from_secs(DROP_CHUNK_BODY_TIMEOUT_SECONDS),
        to_bytes(request.into_body(), MAX_DROP_CHUNK_BYTES),
    )
    .await
    .map_err(|_| ApiError::RequestTimeout)?
    .map_err(|_| {
        ApiError::PayloadTooLarge(format!(
            "drop upload chunks must not exceed {MAX_DROP_CHUNK_BYTES} bytes"
        ))
    })?;
    if body.len() > MAX_DROP_CHUNK_BYTES {
        return Err(ApiError::PayloadTooLarge(format!(
            "drop upload chunks must not exceed {MAX_DROP_CHUNK_BYTES} bytes"
        )));
    }
    if body.is_empty() && !(query.finish && query.offset == session.total_size) {
        return Err(ApiError::Validation(
            "an empty chunk may only finish a fully received upload".to_string(),
        ));
    }
    let received_bytes = query
        .offset
        .checked_add(i64::try_from(body.len()).map_err(|_| {
            ApiError::PayloadTooLarge("drop upload chunk exceeds supported range".to_string())
        })?)
        .ok_or_else(|| ApiError::Validation("drop upload offset overflow".to_string()))?;
    if received_bytes > session.total_size {
        return Err(ApiError::Validation(
            "chunk exceeds declared total_size".to_string(),
        ));
    }
    if query.finish && received_bytes != session.total_size {
        return Err(ApiError::Validation(
            "finished upload size does not match total_size".to_string(),
        ));
    }
    execution::put_drop_chunk(
        state,
        drop_record,
        drop_id,
        session_id,
        proof_fingerprint,
        query.offset,
        received_bytes,
        query.finish,
        body,
        chunk_ingress_permit,
    )
    .await
}

async fn cancel_session(
    State(state): State<AppState>,
    Path((drop_id, session_id)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<Json<PublicDropUploadResponse>> {
    let (_, client_binding) = authenticate_drop(&state, &drop_id, &headers).await?;
    let proof_fingerprint = client_binding.fingerprint().to_string();
    bound_active_session(&state, &drop_id, &session_id, &proof_fingerprint)?;
    execution::cancel_drop_upload(state, drop_id, session_id, proof_fingerprint).await
}

async fn public_drop_page(
    State(state): State<AppState>,
    Path(drop_id): Path<String>,
) -> ApiResult<Response> {
    let record = state
        .storage
        .get_drop(&drop_id)?
        .ok_or(ApiError::NotFound)?;
    ensure_drop_active(&record)?;
    let name = escape_html(if record.password_required {
        "Protected Drop"
    } else {
        &record.drop.name
    });
    let password_required = record.password_required;
    let drop_id = escape_html(&drop_id);
    Ok(ui::public_html(format!(
        r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>ShellX Drive Drop · {name}</title>
    <link rel="stylesheet" href="/assets/public-drop.css?v=2026-09-24-passwordless-drop1" />
    <script src="/assets/upload-progress.js?v=2026-07-17-uploadprogress1" defer></script>
    <script src="/assets/public-drop-access.js?v=2026-08-30-drop-password-memory1" defer></script>
    <script src="/assets/public-drop.js?v=2026-09-24-passwordless-drop1" defer></script>
  </head>
  <body>
    <main id="public-drop-app" data-drop-id="{drop_id}" data-password-required="{password_required}">
      <header>
        <span class="eyebrow">ShellX Drive upload drop</span>
        <h1 id="drop-title">{name}</h1>
        <p>Files go directly into this private upload inbox. Visitors cannot browse or read anything already there.</p>
      </header>
      <form id="drop-upload-form" class="drop-form">
        <input type="text" name="username" autocomplete="username" value="ShellX Drive Drop" hidden aria-hidden="true" tabindex="-1" />
        <section class="drop-auth" aria-labelledby="drop-password-label">
          <label id="drop-password-label" for="drop-password">Drop password</label>
          <input id="drop-password" type="password" autocomplete="current-password" />
          <button id="drop-password-check-button" type="submit">Check password</button>
          <p id="drop-password-guidance" class="drop-password-guidance">Check the password before choosing files.</p>
        </section>
        <section id="drop-zone" class="drop-zone" tabindex="-1" aria-describedby="drop-help drop-password-guidance" aria-disabled="true">
          <strong>Drop files or folders here</strong>
          <span id="drop-help">or choose them from this device</span>
          <div class="picker-actions">
            <button id="choose-files" type="button">Choose files</button>
            <button id="choose-folder" class="secondary" type="button">Choose folder</button>
          </div>
          <input id="file-picker" type="file" multiple hidden />
          <input id="folder-picker" type="file" multiple webkitdirectory directory hidden />
        </section>
      </form>
      <p class="policy-note">Duplicate names are kept as separate files. Nothing is silently replaced.</p>
      <section id="drop-progress" class="drop-progress" hidden aria-live="polite">
        <div class="progress-heading">
          <strong>Upload progress</strong>
          <output id="drop-status" role="status">Ready</output>
        </div>
        <div data-upload-aggregate hidden>
          <span data-upload-aggregate-value></span>
          <span class="upload-progress-track" data-upload-aggregate-track role="progressbar" aria-label="Overall upload progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="0" aria-valuetext="0 B of 0 B, 0%">
            <span class="upload-progress-bar" data-upload-aggregate-bar></span>
          </span>
        </div>
        <div id="drop-upload-queue" class="upload-queue"></div>
      </section>
    </main>
  </body>
</html>"#
    )))
}

pub(super) fn bound_active_session(
    state: &AppState,
    drop_id: &str,
    session_id: &str,
    proof_fingerprint: &str,
) -> ApiResult<DropUploadRecord> {
    let session = state
        .storage
        .get_drop_upload_session(session_id)?
        .ok_or(ApiError::NotFound)?;
    if session.drop_id != drop_id {
        return Err(ApiError::NotFound);
    }
    if !constant_time_str_eq(&session.client_fingerprint, proof_fingerprint) {
        return Err(ApiError::NotFound);
    }
    if session.status != "active" {
        return Err(ApiError::Conflict);
    }
    Ok(session)
}

fn require_binary_content_type(headers: &HeaderMap) -> ApiResult<()> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim();
    if content_type.eq_ignore_ascii_case("application/octet-stream") {
        Ok(())
    } else {
        Err(ApiError::Validation(
            "drop upload chunks require application/octet-stream".to_string(),
        ))
    }
}

fn require_json_content_type(headers: &HeaderMap) -> ApiResult<()> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim();
    if content_type.eq_ignore_ascii_case("application/json") {
        Ok(())
    } else {
        Err(ApiError::Validation(
            "drop upload metadata requires application/json".to_string(),
        ))
    }
}

fn validate_total_size(total_size: i64) -> ApiResult<()> {
    if !(1..=MAX_DROP_UPLOAD_BYTES).contains(&total_size) {
        return Err(ApiError::Validation(format!(
            "public Drop files must contain at least 1 byte and no more than {MAX_DROP_UPLOAD_BYTES} bytes"
        )));
    }
    Ok(())
}

pub(crate) fn cleanup_canceled_drop_upload_parts(state: &AppState, session_ids: &[String]) {
    file_io::cleanup_canceled_parts(state, session_ids);
}

/// Reap stale Drop sessions only after acquiring the exact same stable lock
/// inode used by chunk writes and cancellation.
pub(crate) fn reap_stale_drop_upload_candidates_lock_safe(
    state: &AppState,
    session_ids: Vec<String>,
    older_than_seconds: i64,
) -> ApiResult<Vec<DropUploadRecord>> {
    file_io::reap_stale_candidates_lock_safe_with(state, session_ids, |session_id| {
        state
            .storage
            .reap_stale_drop_upload_session(session_id, older_than_seconds)
    })
}

/// Administrative cleanup revalidates its authorization inside the conditional
/// state transition while the Drop session's stable lock remains held.
pub(crate) fn reap_stale_drop_upload_candidates_lock_safe_authorized(
    state: &AppState,
    session_ids: Vec<String>,
    older_than_seconds: i64,
    actor: &crate::auth::Actor,
    source_credential: &crate::auth::DriveCredential,
) -> ApiResult<Vec<DropUploadRecord>> {
    file_io::reap_stale_candidates_lock_safe_with(state, session_ids, |session_id| {
        state.storage.reap_stale_drop_upload_session_authorized(
            session_id,
            older_than_seconds,
            actor,
            source_credential,
        )
    })
}

pub(super) fn public_session(session: &DropUploadRecord) -> PublicDropUploadSession {
    PublicDropUploadSession {
        id: session.id.clone(),
        upload_url: format!("/pub/drops/{}/uploads/{}", session.drop_id, session.id),
        total_size: session.total_size,
        received_bytes: session.received_bytes,
        status: session.status.clone(),
        duplicate_policy: "keep_both".to_string(),
        created_at: session.created_at.clone(),
        updated_at: session.updated_at.clone(),
    }
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
