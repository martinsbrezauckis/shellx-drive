use crate::{
    auth::{
        random_secret_token, require_admin_with_credential, require_drive_actor_with_credential,
        require_user_actor_with_credential, token_hash, DriveCredential, WorkspacePermission,
        WorkspaceRole,
    },
    error::{ApiError, ApiResult},
    model::{
        CreateWorkspaceInvitationRequest, CreateWorkspaceRequest, CreateWorkspaceResponse,
        RemoveWorkspaceMemberRequest, TransferWorkspaceOwnerRequest,
        TransferWorkspaceOwnerResponse, UpdateWorkspaceRequest, UpsertWorkspaceMemberRequest,
        WorkspaceInvitationAcceptResponse, WorkspaceInvitationListResponse,
        WorkspaceInvitationMutationResponse, WorkspaceLeaveResponse, WorkspaceMemberResponse,
        WorkspaceMutationResponse,
    },
    server::AppState,
};
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, StatusCode},
    response::Response,
    routing::{get, patch, post},
    Json, Router,
};
use serde::Deserialize;

use super::ui;

#[derive(Debug, Deserialize)]
struct PublicInvitationAcceptRequest {
    token: String,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/workspaces", post(create_workspace))
        .route("/workspaces/{workspace_id}", patch(update_workspace))
        .route(
            "/workspaces/{workspace_id}/members",
            get(list_members).post(upsert_member).delete(remove_member),
        )
        .route(
            "/workspaces/{workspace_id}/invitations",
            get(list_invitations).post(create_invitation),
        )
        .route(
            "/workspaces/{workspace_id}/invitations/{invitation_id}/resend",
            post(resend_invitation),
        )
        .route(
            "/workspaces/{workspace_id}/invitations/{invitation_id}/cancel",
            post(cancel_invitation),
        )
        .route(
            "/pub/invitations/accept",
            get(public_invitation_page).post(accept_public_invitation),
        )
        .route("/workspaces/{workspace_id}/leave", post(leave_workspace))
        .route(
            "/workspaces/{workspace_id}/transfer-owner",
            post(transfer_owner),
        )
        .route(
            "/workspaces/{workspace_id}/archive",
            post(archive_workspace),
        )
        .route(
            "/workspaces/{workspace_id}/unarchive",
            post(unarchive_workspace),
        )
}

async fn create_workspace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateWorkspaceRequest>,
) -> ApiResult<(StatusCode, Json<CreateWorkspaceResponse>)> {
    let (actor, source_credential) = require_admin_with_credential(&state, &headers)?;
    let storage_mode = request.storage_mode.as_deref().unwrap_or("open");
    if storage_mode != "open" {
        return Err(crate::error::ApiError::Validation(
            "storage_mode must be open".to_string(),
        ));
    }
    if state.config.hosted_mode && request.tenant_id.is_none() {
        return Err(ApiError::Validation(
            "tenant_id is required when hosted mode is enabled".to_string(),
        ));
    }
    let (workspace, owner, receipt) = state.storage.create_workspace_authorized(
        &request.name,
        &request.owner_email,
        request.tenant_id.as_deref(),
        &actor,
        &source_credential,
    )?;
    Ok((
        StatusCode::CREATED,
        Json(CreateWorkspaceResponse {
            workspace,
            owner,
            receipt,
        }),
    ))
}

async fn update_workspace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(request): Json<UpdateWorkspaceRequest>,
) -> ApiResult<Json<WorkspaceMutationResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    state.storage.ensure_workspace_permission(
        &workspace_id,
        &actor,
        WorkspacePermission::Manage,
    )?;
    let Some(name) = request.name.as_deref() else {
        return Err(ApiError::Validation("name is required".to_string()));
    };
    let (workspace, receipt) =
        state
            .storage
            .update_workspace_name(&workspace_id, name, &actor, &source_credential)?;
    Ok(Json(WorkspaceMutationResponse { workspace, receipt }))
}

async fn list_members(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    state.storage.ensure_workspace_permission(
        &workspace_id,
        &actor,
        WorkspacePermission::Manage,
    )?;
    let members = state.storage.list_workspace_members(&workspace_id)?;
    state.storage.ensure_workspace_publication_authorized(
        &workspace_id,
        &actor,
        &source_credential,
        WorkspacePermission::Manage,
    )?;
    Ok(Json(serde_json::json!({
        "members": members,
    })))
}

async fn upsert_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(request): Json<UpsertWorkspaceMemberRequest>,
) -> ApiResult<(StatusCode, Json<WorkspaceMemberResponse>)> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    state.storage.ensure_workspace_permission(
        &workspace_id,
        &actor,
        WorkspacePermission::Manage,
    )?;
    let role = WorkspaceRole::parse(&request.role)
        .ok_or_else(|| ApiError::Validation("role must be owner, editor, or viewer".to_string()))?;
    let (member, receipt) = state.storage.upsert_workspace_member(
        &workspace_id,
        &request.email,
        role,
        &actor,
        &source_credential,
    )?;
    Ok((
        StatusCode::CREATED,
        Json(WorkspaceMemberResponse { member, receipt }),
    ))
}

async fn remove_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(request): Json<RemoveWorkspaceMemberRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    state.storage.ensure_workspace_permission(
        &workspace_id,
        &actor,
        WorkspacePermission::Manage,
    )?;
    let receipt = state.storage.remove_workspace_member(
        &workspace_id,
        &request.email,
        &actor,
        &source_credential,
    )?;
    Ok(Json(serde_json::json!({ "receipt": receipt })))
}

async fn create_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(request): Json<CreateWorkspaceInvitationRequest>,
) -> ApiResult<(StatusCode, Json<WorkspaceInvitationMutationResponse>)> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    state.storage.ensure_workspace_permission(
        &workspace_id,
        &actor,
        WorkspacePermission::Manage,
    )?;
    let role = WorkspaceRole::parse(&request.role)
        .ok_or_else(|| ApiError::Validation("role must be owner, editor, or viewer".to_string()))?;
    let token = new_invitation_token();
    let email_body = invitation_email_body(
        &state,
        &token,
        &format!("{} invited you as {}", actor.email, role.as_db_str()),
    );
    let token_hash = token_hash(&token);
    let (invitation, receipt) = state.storage.create_workspace_invitation(
        &workspace_id,
        &request.email,
        role,
        request.member_expires_in_seconds,
        &token_hash,
        &email_body,
        &actor,
        &source_credential,
    )?;
    if let Err(error) = state
        .storage
        .create_workspace_invitation_notification_if_current(
            &invitation,
            &token_hash,
            "Workspace invitation",
            &format!(
                "{} invited you as {} to a ShellX Drive workspace.",
                invitation.invited_by, invitation.role
            ),
        )
    {
        tracing::warn!(
            workspace_id = %workspace_id,
            %error,
            "invitation notification failed after durable invitation creation"
        );
    }
    Ok((
        StatusCode::CREATED,
        Json(WorkspaceInvitationMutationResponse {
            invitation,
            token: Some(token),
            receipt,
        }),
    ))
}

async fn list_invitations(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> ApiResult<Json<WorkspaceInvitationListResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    state.storage.ensure_workspace_permission(
        &workspace_id,
        &actor,
        WorkspacePermission::Manage,
    )?;
    let invitations = state.storage.list_workspace_invitations(&workspace_id)?;
    state.storage.ensure_workspace_publication_authorized(
        &workspace_id,
        &actor,
        &source_credential,
        WorkspacePermission::Manage,
    )?;
    Ok(Json(WorkspaceInvitationListResponse { invitations }))
}

async fn resend_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((workspace_id, invitation_id)): Path<(String, String)>,
) -> ApiResult<Json<WorkspaceInvitationMutationResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    state.storage.ensure_workspace_permission(
        &workspace_id,
        &actor,
        WorkspacePermission::Manage,
    )?;
    let token = new_invitation_token();
    let email_body = invitation_email_body(&state, &token, "Your invitation was resent");
    let token_hash = token_hash(&token);
    let (invitation, receipt) = state.storage.resend_workspace_invitation(
        &workspace_id,
        &invitation_id,
        &token_hash,
        &email_body,
        &actor,
        &source_credential,
    )?;
    if let Err(error) = state
        .storage
        .create_workspace_invitation_notification_if_current(
            &invitation,
            &token_hash,
            "Workspace invitation resent",
            &format!(
                "{} resent your {} invitation to a ShellX Drive workspace.",
                actor.email, invitation.role
            ),
        )
    {
        tracing::warn!(
            workspace_id = %workspace_id,
            %error,
            "invitation notification failed after durable invitation resend"
        );
    }
    Ok(Json(WorkspaceInvitationMutationResponse {
        invitation,
        token: Some(token),
        receipt,
    }))
}

async fn cancel_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((workspace_id, invitation_id)): Path<(String, String)>,
) -> ApiResult<Json<WorkspaceInvitationMutationResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    state.storage.ensure_workspace_permission(
        &workspace_id,
        &actor,
        WorkspacePermission::Manage,
    )?;
    let (invitation, receipt) = state.storage.cancel_workspace_invitation(
        &workspace_id,
        &invitation_id,
        &actor,
        &source_credential,
    )?;
    Ok(Json(WorkspaceInvitationMutationResponse {
        invitation,
        token: None,
        receipt,
    }))
}

/// Serve a token-free invitation page. The invitation token belongs in the URL
/// fragment (`#token=...`), which browsers never send to Drive, proxies, or
/// same-origin assets. The page removes it from browser history before making a
/// same-origin POST.
async fn public_invitation_page() -> Response {
    ui::public_html(
        r#"<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Workspace invitation · ShellX Drive</title>
    <link rel="stylesheet" href="/assets/public-invitation.css" />
  </head>
  <body>
    <main class="invitation-shell">
      <section class="invitation-card" aria-labelledby="invitation-title">
        <p class="invitation-eyebrow">ShellX Drive</p>
        <h1 id="invitation-title">Workspace invitation</h1>
        <p id="invitation-status" role="status" aria-live="polite">Checking your sign-in…</p>
        <p id="invitation-guidance">Sign in to your existing Drive account in another tab, then return here to accept.</p>
        <div class="invitation-actions">
          <a id="invitation-sign-in" href="/" target="_blank" rel="noopener">Open Drive sign-in</a>
          <button id="invitation-refresh" type="button">Check sign-in</button>
          <button id="invitation-accept" type="button" disabled>Accept invitation</button>
        </div>
      </section>
    </main>
    <script src="/assets/public-invitation.js" defer></script>
  </body>
</html>"#
            .to_string(),
    )
}

async fn accept_public_invitation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<PublicInvitationAcceptRequest>,
) -> ApiResult<Json<WorkspaceInvitationAcceptResponse>> {
    require_invitation_accept_origin(&state, &headers)?;
    let (actor, source_credential) = require_drive_actor_with_credential(&state, &headers)?;
    if !matches!(
        &source_credential,
        DriveCredential::UserSession(_) | DriveCredential::DelegatedAgentToken(_)
    ) {
        return Err(ApiError::Forbidden);
    }
    let (invitation, member, receipt) = state.storage.accept_workspace_invitation_for_account(
        &token_hash(request.token.trim()),
        &actor.email,
        &actor,
        &source_credential,
    )?;
    Ok(Json(WorkspaceInvitationAcceptResponse {
        invitation,
        member,
        receipt,
    }))
}

/// Cookie-authenticated browser requests are accepted only from the configured
/// Drive origin. A caller with an explicit session bearer token is a manual API
/// client rather than a CSRF-capable ambient-cookie request, so it remains
/// supported without an `Origin` header.
fn require_invitation_accept_origin(state: &AppState, headers: &HeaderMap) -> ApiResult<()> {
    if headers.contains_key(header::AUTHORIZATION) {
        return Ok(());
    }
    let origin = headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or(ApiError::Forbidden)?;
    let expected = state.config.public_origin.as_str();
    if origin != expected {
        return Err(ApiError::Forbidden);
    }
    Ok(())
}

async fn transfer_owner(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(request): Json<TransferWorkspaceOwnerRequest>,
) -> ApiResult<Json<TransferWorkspaceOwnerResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    state.storage.ensure_workspace_permission(
        &workspace_id,
        &actor,
        WorkspacePermission::Manage,
    )?;
    let (old_owner, new_owner, receipt) = state.storage.transfer_workspace_owner(
        &workspace_id,
        &actor,
        &source_credential,
        &request.email,
    )?;
    Ok(Json(TransferWorkspaceOwnerResponse {
        old_owner,
        new_owner,
        receipt,
    }))
}

async fn leave_workspace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> ApiResult<Json<WorkspaceLeaveResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    let receipt = state
        .storage
        .leave_workspace(&workspace_id, &actor, &source_credential)?;
    Ok(Json(WorkspaceLeaveResponse { receipt }))
}

async fn archive_workspace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> ApiResult<Json<WorkspaceMutationResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    state.storage.ensure_workspace_permission(
        &workspace_id,
        &actor,
        WorkspacePermission::Manage,
    )?;
    let (workspace, receipt) =
        state
            .storage
            .set_workspace_archived(&workspace_id, true, &actor, &source_credential)?;
    Ok(Json(WorkspaceMutationResponse { workspace, receipt }))
}

async fn unarchive_workspace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> ApiResult<Json<WorkspaceMutationResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    state.storage.ensure_workspace_permission(
        &workspace_id,
        &actor,
        WorkspacePermission::Manage,
    )?;
    let (workspace, receipt) =
        state
            .storage
            .set_workspace_archived(&workspace_id, false, &actor, &source_credential)?;
    Ok(Json(WorkspaceMutationResponse { workspace, receipt }))
}

fn new_invitation_token() -> String {
    random_secret_token()
}

fn invitation_email_body(state: &AppState, token: &str, introduction: &str) -> String {
    let accept_url = format!(
        "{}/pub/invitations/accept#token={}",
        state.config.public_origin.as_str(),
        token
    );
    format!("{introduction} to a ShellX Drive workspace: {accept_url}")
}
