use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, get, post},
    Json, Router,
};
use serde_json::json;

use crate::{
    auth::{
        require_admin_with_credential, require_user_actor_with_credential, WorkspacePermission,
        WorkspaceRole,
    },
    error::{ApiError, ApiResult},
    model::{
        CreateGroupRequest, GroupMemberResponse, GroupResponse, UpsertGroupMemberRequest,
        UpsertWorkspaceGroupGrantRequest, WorkspaceGroupGrantResponse,
    },
    server::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/groups", get(list_groups).post(create_group))
        .route(
            "/groups/{group_id}/members",
            post(upsert_group_member).delete(remove_group_member),
        )
        .route(
            "/workspaces/{workspace_id}/group-grants",
            post(upsert_workspace_group_grant),
        )
        .route(
            "/workspaces/{workspace_id}/group-grants/{group_id}",
            delete(remove_workspace_group_grant),
        )
}

async fn list_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<serde_json::Value>> {
    let (actor, source_credential) = require_admin_with_credential(&state, &headers)?;
    let groups = state.storage.list_groups()?;
    let members = state.storage.list_all_group_members()?;
    let workspace_grants = state.storage.list_all_workspace_group_grants()?;
    state
        .storage
        .ensure_admin_publication_authorized(&actor, &source_credential)?;
    Ok(Json(json!({
        "groups": groups,
        "members": members,
        "workspace_grants": workspace_grants,
    })))
}

async fn create_group(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateGroupRequest>,
) -> ApiResult<(StatusCode, Json<GroupResponse>)> {
    let (actor, source_credential) = require_admin_with_credential(&state, &headers)?;
    let (group, receipt) =
        state
            .storage
            .create_group_authorized(&request.name, &actor, &source_credential)?;
    Ok((StatusCode::CREATED, Json(GroupResponse { group, receipt })))
}

async fn upsert_group_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(group_id): Path<String>,
    Json(request): Json<UpsertGroupMemberRequest>,
) -> ApiResult<(StatusCode, Json<GroupMemberResponse>)> {
    let (actor, source_credential) = require_admin_with_credential(&state, &headers)?;
    let (member, receipt) = state.storage.upsert_group_member_authorized(
        &group_id,
        &request.email,
        &actor,
        &source_credential,
    )?;
    Ok((
        StatusCode::CREATED,
        Json(GroupMemberResponse { member, receipt }),
    ))
}

async fn remove_group_member(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(group_id): Path<String>,
    Json(request): Json<UpsertGroupMemberRequest>,
) -> ApiResult<Json<serde_json::Value>> {
    let (actor, source_credential) = require_admin_with_credential(&state, &headers)?;
    let receipt = state.storage.remove_group_member_authorized(
        &group_id,
        &request.email,
        &actor,
        &source_credential,
    )?;
    Ok(Json(json!({ "receipt": receipt })))
}

async fn upsert_workspace_group_grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
    Json(request): Json<UpsertWorkspaceGroupGrantRequest>,
) -> ApiResult<(StatusCode, Json<WorkspaceGroupGrantResponse>)> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    state.storage.ensure_workspace_permission(
        &workspace_id,
        &actor,
        WorkspacePermission::Manage,
    )?;
    let role = WorkspaceRole::parse(&request.role).ok_or_else(|| {
        ApiError::Validation("group grant role must be viewer or editor".to_string())
    })?;
    if role == WorkspaceRole::Owner {
        return Err(ApiError::Validation(
            "group grant role must be viewer or editor".to_string(),
        ));
    }
    let (grant, receipt) = state.storage.upsert_workspace_group_grant(
        &workspace_id,
        &request.group_id,
        role,
        &actor,
        &source_credential,
    )?;
    Ok((
        StatusCode::CREATED,
        Json(WorkspaceGroupGrantResponse { grant, receipt }),
    ))
}

async fn remove_workspace_group_grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((workspace_id, group_id)): Path<(String, String)>,
) -> ApiResult<Json<serde_json::Value>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    state.storage.ensure_workspace_permission(
        &workspace_id,
        &actor,
        WorkspacePermission::Manage,
    )?;
    let receipt = state.storage.remove_workspace_group_grant(
        &workspace_id,
        &group_id,
        &actor,
        &source_credential,
    )?;
    Ok(Json(json!({ "receipt": receipt })))
}
