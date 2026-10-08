use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, patch, post},
    Json, Router,
};

use crate::{
    auth::{normalize_email, require_user_actor_with_credential, WorkspacePermission},
    error::{ApiError, ApiResult},
    model::{CreateShareRequest, CreateShareResponse, ShareListResponse, UpdateShareRequest},
    server::AppState,
    storage::{ShareCreateFields, ShareUpdateFields},
    workspace_policy::{
        validate_new_public_capability_password, validate_share_policy,
        validate_share_update_policy,
    },
};

pub(super) fn router() -> Router<AppState> {
    Router::new()
        .route("/shares", post(create_share))
        .route("/files/{file_id}/shares", get(list_file_shares))
        .route(
            "/workspaces/{workspace_id}/shares",
            get(list_workspace_shares),
        )
        .route("/shares/{share_id}", patch(update_share))
        .route("/shares/{share_id}/revoke", post(revoke_share))
}

async fn create_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateShareRequest>,
) -> ApiResult<(StatusCode, Json<CreateShareResponse>)> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    let file = state
        .storage
        .get_file(&request.file_id)?
        .ok_or(ApiError::NotFound)?;
    state
        .storage
        .ensure_item_response_permission(&file.id, &actor, WorkspacePermission::Read)?;
    state.storage.ensure_workspace_permission(
        &file.workspace_id,
        &actor,
        WorkspacePermission::Write,
    )?;
    let policy = state.storage.get_workspace_policy(&file.workspace_id)?;
    let password_required = validate_new_public_capability_password(&request.password)?;
    validate_share_policy(&policy, password_required, request.expires_in_seconds)?;
    let notify_email = request
        .notify_email
        .as_deref()
        .map(normalize_email)
        .transpose()?;
    let password_hash = state.hash_public_password(&request.password).await?;
    let (share, receipt) = state.storage.create_pending_share_publication(
        ShareCreateFields {
            file_id: &request.file_id,
            password_hash: &password_hash,
            password_required,
            expires_in_seconds: request.expires_in_seconds,
            target_kind: file.kind.as_db_str(),
            allow_download: request.allow_download,
            recipient_note: request.recipient_note.as_deref(),
            max_uses: request.max_uses,
        },
        &actor,
        &source_credential,
    )?;
    state
        .storage
        .publish_pending_share(&share.id, &receipt, &actor, &source_credential)?;
    if let Some(recipient) = notify_email {
        let share_url = format!(
            "{}/pub/shares/{}",
            state.config.public_origin.as_str(),
            share.id
        );
        let note = share
            .recipient_note
            .as_deref()
            .map(|value| format!("\n\nNote: {value}"))
            .unwrap_or_default();
        if let Err(error) = state.storage.queue_workspace_email(
            &file.workspace_id,
            "share_created",
            &recipient,
            "ShellX Drive shared file",
            &format!(
                "{} shared {} with you in ShellX Drive: {}{}",
                actor.email, file.name, share_url, note
            ),
            Some("share"),
            Some(&share.id),
        ) {
            tracing::warn!(
                workspace_id = %file.workspace_id,
                %error,
                "share email failed after durable share creation"
            );
        }
        if let Err(error) = state.storage.create_notification(
            &recipient,
            "share_created",
            "File shared with you",
            &format!(
                "{} shared {} with you: {}",
                actor.email, file.name, share_url
            ),
            Some(&file.workspace_id),
            Some(&file.id),
            Some("share"),
            Some(&share.id),
        ) {
            tracing::warn!(
                workspace_id = %file.workspace_id,
                %error,
                "share notification failed after durable share creation"
            );
        }
    }
    Ok((
        StatusCode::CREATED,
        Json(CreateShareResponse { share, receipt }),
    ))
}

async fn list_file_shares(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> ApiResult<Json<ShareListResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    let file = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    state
        .storage
        .ensure_item_response_permission(&file.id, &actor, WorkspacePermission::Read)?;
    state.storage.ensure_workspace_permission(
        &file.workspace_id,
        &actor,
        WorkspacePermission::Write,
    )?;
    let shares = state.storage.list_file_shares(&file_id)?;
    state.storage.ensure_workspace_publication_authorized(
        &file.workspace_id,
        &actor,
        &source_credential,
        WorkspacePermission::Write,
    )?;
    Ok(Json(ShareListResponse { shares }))
}

async fn list_workspace_shares(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> ApiResult<Json<ShareListResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    state
        .storage
        .ensure_workspace_permission(&workspace_id, &actor, WorkspacePermission::Write)?;
    let shares = state.storage.list_workspace_shares(&workspace_id)?;
    state.storage.ensure_workspace_publication_authorized(
        &workspace_id,
        &actor,
        &source_credential,
        WorkspacePermission::Write,
    )?;
    Ok(Json(ShareListResponse { shares }))
}

async fn update_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(share_id): Path<String>,
    Json(request): Json<UpdateShareRequest>,
) -> ApiResult<Json<CreateShareResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    let record = state
        .storage
        .get_share(&share_id)?
        .ok_or(ApiError::NotFound)?;
    let file = state
        .storage
        .get_file(&record.share.file_id)?
        .ok_or(ApiError::NotFound)?;
    state.storage.ensure_workspace_permission(
        &file.workspace_id,
        &actor,
        WorkspacePermission::Write,
    )?;
    let policy = state.storage.get_workspace_policy(&file.workspace_id)?;
    let password_required = request
        .password
        .as_deref()
        .map(validate_new_public_capability_password)
        .transpose()?;
    validate_share_update_policy(&policy, password_required, request.expires_in_seconds)?;
    let password_hash = match request.password.as_deref() {
        Some(password) => Some(state.hash_public_password(password).await?),
        None => None,
    };
    let recipient_note = if request.clear_recipient_note.unwrap_or(false) {
        Some(None)
    } else {
        request.recipient_note.as_deref().map(Some)
    };
    let max_uses = if request.clear_max_uses.unwrap_or(false) {
        Some(None)
    } else {
        request.max_uses.map(Some)
    };
    let (share, receipt) = state.storage.update_share(
        &share_id,
        ShareUpdateFields {
            password_hash: password_hash.as_deref(),
            password_required,
            expires_in_seconds: request.expires_in_seconds,
            allow_download: request.allow_download,
            recipient_note,
            max_uses,
        },
        &actor,
        &source_credential,
    )?;
    Ok(Json(CreateShareResponse { share, receipt }))
}

async fn revoke_share(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(share_id): Path<String>,
) -> ApiResult<Json<CreateShareResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    let record = state
        .storage
        .get_share(&share_id)?
        .ok_or(ApiError::NotFound)?;
    let file = state
        .storage
        .get_file(&record.share.file_id)?
        .ok_or(ApiError::NotFound)?;
    state.storage.ensure_workspace_permission(
        &file.workspace_id,
        &actor,
        WorkspacePermission::Write,
    )?;
    let (share, receipt) = state
        .storage
        .revoke_share(&share_id, &actor, &source_credential)?;
    Ok(Json(CreateShareResponse { share, receipt }))
}
