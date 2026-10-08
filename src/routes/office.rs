use axum::{
    body::to_bytes,
    extract::{Path, Query, Request, State},
    http::{header, HeaderMap, HeaderName, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};

use crate::{
    auth::{
        require_drive_actor, require_drive_actor_with_credential, Actor, DriveCredential,
        WorkspacePermission,
    },
    blob,
    download_subjects::CurrentFileSubject,
    error::{ApiError, ApiResult},
    model::{
        ContentWrite, DebugOfficeSession, DriveFile, FileMutationResponse, OfficeEditSession,
        OfficeOpenResponse, OfficePackageCommitQuery, OfficeProviderStatus, OfficeSessionManifest,
        PutContentRequest,
    },
    office_handoffs::NewOfficeHandoff,
    routes::{
        blob_publication,
        blob_response::{serve_blob_file_with_guard_after_open, Disposition},
    },
    server::AppState,
    storage::FileAccessKind,
};

const MAX_OFFICE_JSON_BYTES: usize = 2 * 1024 * 1024;
const MAX_OFFICE_PACKAGE_BYTES: usize = 2 * 1024 * 1024;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/office/status", get(office_status))
        .route("/office/files/{file_id}/open", post(open_file))
        .route("/office/launch/{handoff}", get(launch_office_provider))
        .route("/office/files/{file_id}/save", post(save_file))
        .route("/office/sessions/{token}", get(session_manifest))
        .route(
            "/office/sessions/{token}/package",
            get(get_session_package).put(put_session_package),
        )
        .route("/office/sessions/{token}/save", post(save_session_file))
}

/// `GET /office/status` — lightweight, file-independent probe of whether an
/// online-editing provider is configured (`SHELLX_DRIVE_OFFICE_PROVIDER_URL`).
/// The web UI calls this once after sign-in so it can HIDE the "Edit online"
/// affordance and office-handoff hint entirely on the common self-host case
/// where no provider exists — instead of surfacing a techy "not checked" status.
async fn office_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<OfficeProviderStatus>> {
    // Authenticated (any drive actor) — availability is not a secret, but the
    // whole API surface requires a session, so keep it consistent.
    require_drive_actor(&state, &headers)?;
    Ok(Json(OfficeProviderStatus {
        configured: state.config.office_provider_url.is_some(),
        name: state.config.office_provider_name.clone(),
        launch_url: None,
    }))
}

async fn open_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> ApiResult<Json<OfficeOpenResponse>> {
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let file = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    if state.storage.file_is_effectively_trashed(&file.id)? {
        return Err(ApiError::NotFound);
    }
    state
        .storage
        .ensure_item_response_permission(&file.id, &actor, WorkspacePermission::Read)?;
    state
        .storage
        .ensure_workspace_server_content_allowed(&file.workspace_id)?;
    let base_revision = file.revision;
    let save_url = format!("/office/files/{file_id}/save");
    let provider = OfficeProviderStatus {
        configured: state.config.office_provider_url.is_some(),
        name: state.config.office_provider_name.clone(),
        launch_url: None,
    };
    let edit_session = if let Some(provider_url) = state.config.office_provider_url.as_deref() {
        state.storage.ensure_item_response_permission(
            &file.id,
            &actor,
            WorkspacePermission::Write,
        )?;
        let (session, token) = state.storage.create_office_edit_session(
            &file.id,
            &actor.email,
            &source_credential,
            base_revision,
            &state.config.office_provider_name,
            state.config.office_session_ttl_seconds,
        )?;
        let session_url = office_session_url(&token);
        let package_url = office_session_package_url(&token);
        let commit_url = package_url.clone();
        let session_save_url = format!("/office/sessions/{token}/save");
        let handoff = match state.office_handoffs.issue(NewOfficeHandoff {
            provider_url: provider_url.to_string(),
            session_token: token,
            file_id: file.id.clone(),
            save_url: session_save_url,
            session_url,
            package_url,
            commit_url,
            actor_email: actor.email.clone(),
        }) {
            Ok(handoff) => handoff,
            Err(error) => {
                state
                    .storage
                    .discard_unclaimed_office_edit_session(&session.id)?;
                return Err(error);
            }
        };
        let launch_url = format!("/office/launch/{handoff}");
        Some(OfficeEditSession {
            file_id: session.file_id,
            actor_email: session.actor_email,
            base_revision: session.base_revision,
            expires_at: session.expires_at,
            launch_url,
        })
    } else {
        None
    };
    Ok(Json(OfficeOpenResponse {
        file,
        base_revision,
        save_url,
        locking: "optimistic_revision".to_string(),
        provider,
        edit_session,
    }))
}

/// Redeem a one-time browser handoff into a POST body for the configured
/// provider. The durable Office bearer is never placed in a URL, browser
/// history, Drive's application DOM, referrer, or provider access-log query.
async fn launch_office_provider(
    State(state): State<AppState>,
    Path(handoff_token): Path<String>,
) -> ApiResult<Response> {
    let handoff = state.office_handoffs.redeem(&handoff_token)?;
    let provider = reqwest::Url::parse(&handoff.provider_url).map_err(|_| {
        ApiError::Validation("configured Office provider URL is invalid".to_string())
    })?;
    let provider_origin = provider.origin().ascii_serialization();
    if provider_origin == "null" {
        return Err(ApiError::Validation(
            "configured Office provider URL has no secure origin".to_string(),
        ));
    }
    let fields = [
        ("session", handoff.session_token.as_str()),
        ("file_id", handoff.file_id.as_str()),
        ("save_url", handoff.save_url.as_str()),
        ("session_url", handoff.session_url.as_str()),
        ("package_url", handoff.package_url.as_str()),
        ("commit_url", handoff.commit_url.as_str()),
    ];
    let hidden_fields = fields
        .into_iter()
        .map(|(name, value)| {
            format!(
                "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
                html_attribute(name),
                html_attribute(value)
            )
        })
        .collect::<String>();
    let nonce = handoff_token;
    let body = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"referrer\" content=\"no-referrer\"><title>Opening editor</title></head><body><form id=\"office-handoff\" method=\"post\" action=\"{}\">{}<noscript><button type=\"submit\">Open editor</button></noscript></form><script nonce=\"{}\">document.getElementById('office-handoff').submit();</script></body></html>",
        html_attribute(provider.as_str()),
        hidden_fields,
        html_attribute(&nonce),
    );
    let mut response = Response::new(axum::body::Body::from(body));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, max-age=0"),
    );
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    let content_security_policy = format!(
        "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action {provider_origin}; script-src 'nonce-{nonce}'"
    );
    response.headers_mut().insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_str(&content_security_policy).map_err(|_| {
            ApiError::Validation("configured Office provider origin is invalid".to_string())
        })?,
    );
    Ok(response)
}

fn html_attribute(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '&' => "&amp;".to_string(),
            '<' => "&lt;".to_string(),
            '>' => "&gt;".to_string(),
            '"' => "&quot;".to_string(),
            '\'' => "&#39;".to_string(),
            _ => character.to_string(),
        })
        .collect()
}

async fn save_file(
    State(state): State<AppState>,
    Path(file_id): Path<String>,
    request: Request,
) -> ApiResult<Response> {
    let headers = request.headers().clone();
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    let file = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    state
        .storage
        .ensure_item_response_permission(&file.id, &actor, WorkspacePermission::Write)?;
    let _ingress = state.try_authenticated_upload_ingress(&actor.email)?;
    let body = to_bytes(request.into_body(), MAX_OFFICE_JSON_BYTES)
        .await
        .map_err(|_| {
            ApiError::PayloadTooLarge(format!(
                "Office JSON body exceeds {MAX_OFFICE_JSON_BYTES} bytes"
            ))
        })?;
    let request = serde_json::from_slice::<PutContentRequest>(&body)
        .map_err(|error| ApiError::Validation(format!("invalid Office save body: {error}")))?;
    write_office_content(&state, &file_id, request, &actor, &source_credential).await
}

async fn save_session_file(
    State(state): State<AppState>,
    Path(token): Path<String>,
    request: Request,
) -> ApiResult<Response> {
    let (session, _) = load_active_office_session(&state, &token)?;
    let _ingress = state.try_authenticated_upload_ingress(&session.actor_email)?;
    let body = to_bytes(request.into_body(), MAX_OFFICE_JSON_BYTES)
        .await
        .map_err(|_| {
            ApiError::PayloadTooLarge(format!(
                "Office JSON body exceeds {MAX_OFFICE_JSON_BYTES} bytes"
            ))
        })?;
    let mut request = serde_json::from_slice::<PutContentRequest>(&body)
        .map_err(|error| ApiError::Validation(format!("invalid Office save body: {error}")))?;
    let (session, actor, source_credential) =
        state.storage.claim_office_edit_session_authorized(&token)?;
    request.base_revision = session.base_revision;
    write_office_content(
        &state,
        &session.file_id,
        request,
        &actor,
        &source_credential,
    )
    .await
}

async fn session_manifest(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> ApiResult<Json<OfficeSessionManifest>> {
    let (session, file) = load_active_office_session(&state, &token)?;
    Ok(Json(OfficeSessionManifest {
        workspace_storage_mode: state.storage.workspace_storage_mode(&file.workspace_id)?,
        package_url: office_session_package_url(&token),
        commit_url: office_session_package_url(&token),
        locking: "optimistic_revision".to_string(),
        file,
        actor_email: session.actor_email,
        provider_name: session.provider_name,
        base_revision: session.base_revision,
        expires_at: session.expires_at,
    }))
}

async fn get_session_package(
    State(state): State<AppState>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let (session, file) = load_active_office_session(&state, &token)?;
    let subject = CurrentFileSubject::from_file(&file)?;
    let path = blob::blob_file_path(&state.data_dir(), &subject.content_hash)?;
    let range = headers
        .get(axum::http::header::RANGE)
        .and_then(|value| value.to_str().ok());
    state.storage.record_file_access_best_effort(
        &file.id,
        &file.workspace_id,
        FileAccessKind::Download,
    );
    let stream_permit = state.try_authenticated_body_stream(&session.actor_email)?;
    let terminal_state = state.clone();
    let terminal_token = token.clone();
    serve_blob_file_with_guard_after_open(
        &file.name,
        &path,
        range,
        Disposition::Attachment,
        stream_permit,
        move || {
            let (_, current_file) = load_active_office_session(&terminal_state, &terminal_token)?;
            if CurrentFileSubject::from_file(&current_file)? != subject {
                return Err(ApiError::NotFound);
            }
            Ok(())
        },
    )
    .await
}

async fn put_session_package(
    State(state): State<AppState>,
    Path(token): Path<String>,
    Query(_query): Query<OfficePackageCommitQuery>,
    request: Request,
) -> ApiResult<Response> {
    let (session, _) = load_active_office_session(&state, &token)?;
    let _ingress = state.try_authenticated_upload_ingress(&session.actor_email)?;
    let body = to_bytes(request.into_body(), MAX_OFFICE_PACKAGE_BYTES)
        .await
        .map_err(|_| {
            ApiError::PayloadTooLarge(format!(
                "Office package exceeds {MAX_OFFICE_PACKAGE_BYTES} bytes"
            ))
        })?;
    let (session, actor, source_credential) =
        state.storage.claim_office_edit_session_authorized(&token)?;
    write_office_package(
        &state,
        &session.file_id,
        session.base_revision,
        body.as_ref(),
        &actor,
        &source_credential,
    )
    .await
}

async fn write_office_content(
    state: &AppState,
    file_id: &str,
    request: PutContentRequest,
    actor: &Actor,
    source_credential: &DriveCredential,
) -> ApiResult<Response> {
    let file = state.storage.get_file(file_id)?.ok_or(ApiError::NotFound)?;
    let content_bytes = request.content.len() as i64;
    state
        .storage
        .ensure_workspace_server_content_allowed(&file.workspace_id)?;
    let quota_target = if request.base_revision == file.revision {
        Some(file_id)
    } else {
        None
    };
    state
        .storage
        .ensure_workspace_quota(&file.workspace_id, quota_target, content_bytes)?;
    blob_publication::run(state, |publications| {
        let hash = publications.put_bytes(request.content.as_bytes())?.hash;
        let write = state.storage.put_content_authorized(
            file_id,
            request.base_revision,
            &hash,
            content_bytes,
            actor,
            source_credential,
        )?;
        match write {
            ContentWrite::Updated { file, receipt } => {
                state.storage.index_file_text(&file, &request.content)?;
                Ok(Json(FileMutationResponse { file, receipt }).into_response())
            }
            ContentWrite::Conflict(conflict) => {
                let conflict_file = state
                    .storage
                    .get_file(&conflict.conflict_file_id)?
                    .ok_or(ApiError::NotFound)?;
                state
                    .storage
                    .index_file_text(&conflict_file, &request.content)?;
                Ok((StatusCode::CONFLICT, Json(conflict)).into_response())
            }
        }
    })
    .await
}

async fn write_office_package(
    state: &AppState,
    file_id: &str,
    base_revision: i64,
    package: &[u8],
    actor: &Actor,
    source_credential: &DriveCredential,
) -> ApiResult<Response> {
    let file = state.storage.get_file(file_id)?.ok_or(ApiError::NotFound)?;
    let content_bytes = package.len() as i64;
    state
        .storage
        .ensure_workspace_server_content_allowed(&file.workspace_id)?;
    let quota_target = if base_revision == file.revision {
        Some(file_id)
    } else {
        None
    };
    state
        .storage
        .ensure_workspace_quota(&file.workspace_id, quota_target, content_bytes)?;
    blob_publication::run(state, |publications| {
        let hash = publications.put_bytes(package)?.hash;
        let write = state.storage.put_content_authorized(
            file_id,
            base_revision,
            &hash,
            content_bytes,
            actor,
            source_credential,
        )?;
        match write {
            ContentWrite::Updated { file, receipt } => {
                state.storage.index_file_bytes(&file, package)?;
                Ok(Json(FileMutationResponse { file, receipt }).into_response())
            }
            ContentWrite::Conflict(conflict) => {
                let conflict_file = state
                    .storage
                    .get_file(&conflict.conflict_file_id)?
                    .ok_or(ApiError::NotFound)?;
                state.storage.index_file_bytes(&conflict_file, package)?;
                Ok((StatusCode::CONFLICT, Json(conflict)).into_response())
            }
        }
    })
    .await
}

fn load_active_office_session(
    state: &AppState,
    token: &str,
) -> ApiResult<(DebugOfficeSession, DriveFile)> {
    let session = state
        .storage
        .get_office_edit_session_by_token(token)?
        .ok_or(ApiError::NotFound)?;
    if session.used_at.is_some() {
        return Err(ApiError::Forbidden);
    }
    let expires_at = DateTime::parse_from_rfc3339(&session.expires_at)
        .map_err(|_| ApiError::Forbidden)?
        .with_timezone(&Utc);
    if expires_at <= Utc::now() {
        return Err(ApiError::Forbidden);
    }
    let file = state
        .storage
        .get_file(&session.file_id)?
        .ok_or(ApiError::NotFound)?;
    if state.storage.file_is_effectively_trashed(&file.id)? {
        return Err(ApiError::NotFound);
    }
    let actor = crate::auth::Actor {
        email: session.actor_email.clone(),
        is_admin: false,
        auth_mode: crate::auth::AuthMode::OfficeSession,
        allowed_workspace_ids: None,
    };
    state
        .storage
        .ensure_item_response_permission(&file.id, &actor, WorkspacePermission::Write)?;
    state
        .storage
        .ensure_workspace_server_content_allowed(&file.workspace_id)?;
    Ok((session, file))
}

fn office_session_url(token: &str) -> String {
    format!("/office/sessions/{token}")
}

fn office_session_package_url(token: &str) -> String {
    format!("/office/sessions/{token}/package")
}
