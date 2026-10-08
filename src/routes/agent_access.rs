use axum::{
    body::to_bytes,
    extract::{DefaultBodyLimit, Path, Query, Request, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete, get, post},
    Json, Router,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    auth::{
        random_secret_token, require_agent_actor, require_user_actor_with_credential, token_hash,
        WorkspacePermission, AGENT_TOKEN_PREFIX,
    },
    blob,
    download_subjects::CurrentFileSubject,
    error::{ApiError, ApiResult},
    model::{
        AgentAccessListResponse, AgentAccessMutationResponse, AgentCreateFileRequest,
        AgentPrincipalGrantListResponse, AgentPrincipalListResponse, AgentSessionResponse,
        CreateAgentAccessRequest, CreateAgentAccessResponse, CreateDelegatedAgentRequest,
        CreateDelegatedAgentResponse, DelegatedAgentListResponse, DelegatedAgentMutationResponse,
        FileKind, FileMutationResponse, RemoveAgentPrincipalResponse, RotateAgentPrincipalRequest,
        RotateAgentPrincipalResponse,
    },
    server::AppState,
    storage::{validate_file_name, AgentFileUpdate, FileAccessKind},
};

use super::{
    blob_publication,
    blob_response::{
        is_initial_content_request, serve_blob_file_with_guard_after_open, Disposition,
    },
};

const DEFAULT_EXPIRY_SECONDS: i64 = 30 * 24 * 60 * 60;
const MIN_EXPIRY_SECONDS: i64 = 60 * 60;
const MAX_EXPIRY_SECONDS: i64 = 365 * 24 * 60 * 60;
const MAX_AGENT_CONTENT_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_AGENT_PRINCIPAL_PAGE_LIMIT: usize = 25;
const MAX_AGENT_PRINCIPAL_PAGE_LIMIT: usize = 50;
const AGENT_TREE_REQUESTS_PER_MINUTE: i64 = 30;

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/files/{file_id}/agent-access",
            get(list_agent_access).post(create_agent_access),
        )
        .route("/agent-principals", get(list_agent_principals))
        .route(
            "/agent-principals/{principal_id}",
            delete(remove_agent_principal),
        )
        .route(
            "/agent-principals/{principal_id}/grants",
            get(list_agent_principal_grants),
        )
        .route(
            "/agent-principals/{principal_id}/rotate",
            post(rotate_agent_principal),
        )
        .route("/agent-access/{grant_id}/rotate", post(rotate_agent_access))
        .route("/agent-access/{grant_id}/revoke", post(revoke_agent_access))
        .route(
            "/agent-delegations",
            get(list_delegated_agents).post(create_delegated_agent),
        )
        .route(
            "/agent-delegations/{principal_id}/rotate",
            post(rotate_delegated_agent),
        )
        .route(
            "/agent-delegations/{principal_id}/revoke",
            post(revoke_delegated_agent),
        )
        .route("/agent/v1/access", get(agent_session))
        .route("/agent/v1/grants/{grant_id}/tree", get(agent_tree))
        .route("/agent/v1/grants/{grant_id}/files", post(agent_create_file))
        .route(
            "/agent/v1/grants/{grant_id}/files/{file_id}",
            get(agent_file_metadata).patch(agent_update_file),
        )
        .route(
            "/agent/v1/grants/{grant_id}/files/{file_id}/content",
            get(agent_file_content)
                .put(agent_put_content)
                .layer(DefaultBodyLimit::max(MAX_AGENT_CONTENT_BYTES)),
        )
}

async fn list_delegated_agents(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AgentPrincipalPageQuery>,
) -> ApiResult<Json<DelegatedAgentListResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    let limit = validated_agent_principal_page_limit(query.limit.as_deref())?;
    let cursor = validated_agent_principal_cursor(query.cursor.as_deref())?;
    let (agents, next_cursor) = state.storage.list_delegated_agents_for_owner(
        &actor,
        &source_credential,
        cursor.as_deref(),
        limit,
    )?;
    state
        .storage
        .ensure_source_credential_publication_authorized(&actor, &source_credential)?;
    Ok(Json(DelegatedAgentListResponse {
        agents,
        next_cursor,
    }))
}

async fn create_delegated_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateDelegatedAgentRequest>,
) -> ApiResult<(StatusCode, Json<CreateDelegatedAgentResponse>)> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    let name = request.name.trim();
    if name.is_empty() || name.len() > 120 {
        return Err(ApiError::Validation(
            "agent name must contain 1 to 120 bytes".to_string(),
        ));
    }
    let expires_at = (Utc::now()
        + Duration::seconds(validated_expiry(request.expires_in_seconds)?))
    .to_rfc3339();
    let token = format!("{AGENT_TOKEN_PREFIX}{}", random_secret_token());
    let pending = state.storage.create_pending_delegated_agent(
        name,
        &token_hash(&token),
        &expires_at,
        &actor,
        &source_credential,
    )?;
    let completion =
        state
            .storage
            .publish_pending_delegated_agent(&pending, &actor, &source_credential)?;
    let agent = state.storage.get_current_delegated_agent_for_owner(
        &pending.principal_id,
        &actor,
        &source_credential,
    )?;
    state
        .storage
        .ensure_pending_delegated_agent_publication_authorized(
            &pending,
            &completion,
            &actor,
            &source_credential,
        )?;
    Ok((
        StatusCode::CREATED,
        Json(CreateDelegatedAgentResponse {
            agent,
            token,
            receipt: pending.receipt,
        }),
    ))
}

async fn rotate_delegated_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(principal_id): Path<String>,
    Json(request): Json<RotateAgentPrincipalRequest>,
) -> ApiResult<Json<CreateDelegatedAgentResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    let expires_at = (Utc::now()
        + Duration::seconds(validated_expiry(request.expires_in_seconds)?))
    .to_rfc3339();
    let token = format!("{AGENT_TOKEN_PREFIX}{}", random_secret_token());
    let pending = state.storage.stage_delegated_agent_rotation(
        &principal_id,
        &token_hash(&token),
        &expires_at,
        &actor,
        &source_credential,
    )?;
    let completion =
        state
            .storage
            .publish_pending_delegated_agent(&pending, &actor, &source_credential)?;
    let agent = state.storage.get_current_delegated_agent_for_owner(
        &principal_id,
        &actor,
        &source_credential,
    )?;
    state
        .storage
        .ensure_pending_delegated_agent_publication_authorized(
            &pending,
            &completion,
            &actor,
            &source_credential,
        )?;
    Ok(Json(CreateDelegatedAgentResponse {
        agent,
        token,
        receipt: pending.receipt,
    }))
}

async fn revoke_delegated_agent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(principal_id): Path<String>,
) -> ApiResult<Json<DelegatedAgentMutationResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    let (agent, receipt, completion) =
        state
            .storage
            .revoke_delegated_agent(&principal_id, &actor, &source_credential)?;
    state
        .storage
        .ensure_delegated_agent_revocation_publication_authorized(
            &principal_id,
            &completion,
            &actor,
            &source_credential,
        )?;
    Ok(Json(DelegatedAgentMutationResponse { agent, receipt }))
}

async fn create_agent_access(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
    Json(request): Json<CreateAgentAccessRequest>,
) -> ApiResult<(StatusCode, Json<CreateAgentAccessResponse>)> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    let folder = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    state
        .storage
        .ensure_item_response_permission(&folder.id, &actor, WorkspacePermission::Read)?;
    state.storage.ensure_workspace_permission(
        &folder.workspace_id,
        &actor,
        WorkspacePermission::Write,
    )?;
    if folder.trashed || !matches!(folder.kind, FileKind::Folder) {
        return Err(ApiError::Validation(
            "Share with AI requires an active folder".to_string(),
        ));
    }
    let expiry_seconds = validated_expiry(request.expires_in_seconds)?;
    let expires_at = (Utc::now() + Duration::seconds(expiry_seconds)).to_rfc3339();
    let (pending, token) = match (
        request.principal_id.as_deref().map(str::trim),
        request.name.as_deref().map(str::trim),
    ) {
        (Some(principal_id), None | Some("")) if !principal_id.is_empty() => {
            let pending = state.storage.grant_pending_agent_access_publication(
                principal_id,
                &folder.workspace_id,
                &folder.id,
                request.permission,
                &expires_at,
                &actor,
                &source_credential,
            )?;
            (pending, None)
        }
        (None, Some(name)) | (Some(""), Some(name)) => {
            if name.is_empty() || name.len() > 120 {
                return Err(ApiError::Validation(
                    "agent name must contain 1 to 120 bytes".to_string(),
                ));
            }
            let token = format!("{AGENT_TOKEN_PREFIX}{}", random_secret_token());
            let pending = state.storage.create_pending_agent_access_publication(
                name,
                &folder.workspace_id,
                &folder.id,
                request.permission,
                &token_hash(&token),
                &expires_at,
                &actor,
                &source_credential,
            )?;
            (pending, Some(token))
        }
        _ => {
            return Err(ApiError::Validation(
                "choose one existing AI agent or provide one new agent name".to_string(),
            ));
        }
    };
    state
        .storage
        .publish_pending_agent_access(&pending, &actor, &source_credential)?;
    Ok((
        StatusCode::CREATED,
        Json(CreateAgentAccessResponse {
            access: pending.access,
            token,
            receipt: pending.receipt,
        }),
    ))
}

async fn list_agent_principals(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AgentPrincipalPageQuery>,
) -> ApiResult<Json<AgentPrincipalListResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    let limit = validated_agent_principal_page_limit(query.limit.as_deref())?;
    let cursor = validated_agent_principal_cursor(query.cursor.as_deref())?;
    let (agents, next_cursor) = state.storage.list_agent_principals_for_creator(
        &actor,
        &source_credential,
        cursor.as_deref(),
        limit,
    )?;
    state
        .storage
        .ensure_source_credential_publication_authorized(&actor, &source_credential)?;
    Ok(Json(AgentPrincipalListResponse {
        agents,
        next_cursor,
    }))
}

async fn list_agent_principal_grants(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(principal_id): Path<String>,
    Query(query): Query<AgentPrincipalPageQuery>,
) -> ApiResult<Json<AgentPrincipalGrantListResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    let limit = validated_agent_principal_page_limit(query.limit.as_deref())?;
    let cursor = validated_agent_principal_cursor(query.cursor.as_deref())?;
    let (grants, next_cursor) = state.storage.list_agent_principal_grants_for_creator(
        &actor,
        &source_credential,
        &principal_id,
        cursor.as_deref(),
        limit,
    )?;
    state
        .storage
        .ensure_source_credential_publication_authorized(&actor, &source_credential)?;
    Ok(Json(AgentPrincipalGrantListResponse {
        grants,
        next_cursor,
    }))
}

#[derive(Debug, Deserialize)]
struct AgentPrincipalPageQuery {
    cursor: Option<String>,
    limit: Option<String>,
}

fn validated_agent_principal_page_limit(raw_limit: Option<&str>) -> ApiResult<usize> {
    let limit = match raw_limit {
        None => DEFAULT_AGENT_PRINCIPAL_PAGE_LIMIT,
        Some(raw_limit) => raw_limit.parse::<usize>().map_err(|_| {
            ApiError::Validation(format!(
                "agent principal limit must be a whole number from 1 to {MAX_AGENT_PRINCIPAL_PAGE_LIMIT}"
            ))
        })?,
    };
    if !(1..=MAX_AGENT_PRINCIPAL_PAGE_LIMIT).contains(&limit) {
        return Err(ApiError::Validation(format!(
            "agent principal limit must be a whole number from 1 to {MAX_AGENT_PRINCIPAL_PAGE_LIMIT}"
        )));
    }
    Ok(limit)
}

fn validated_agent_principal_cursor(raw_cursor: Option<&str>) -> ApiResult<Option<String>> {
    let Some(raw_cursor) = raw_cursor else {
        return Ok(None);
    };
    let cursor = Uuid::parse_str(raw_cursor).map_err(|_| {
        ApiError::Validation("agent principal cursor must be a canonical UUID".to_string())
    })?;
    let canonical = cursor.hyphenated().to_string();
    if canonical != raw_cursor {
        return Err(ApiError::Validation(
            "agent principal cursor must be a canonical UUID".to_string(),
        ));
    }
    Ok(Some(canonical))
}

async fn rotate_agent_principal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(principal_id): Path<String>,
    Json(request): Json<RotateAgentPrincipalRequest>,
) -> ApiResult<Json<RotateAgentPrincipalResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    authorize_human_principal_management(&state, &actor, &source_credential, &principal_id)?;
    let expiry_seconds = validated_expiry(request.expires_in_seconds)?;
    let expires_at = (Utc::now() + Duration::seconds(expiry_seconds)).to_rfc3339();
    let token = format!("{AGENT_TOKEN_PREFIX}{}", random_secret_token());
    let pending = state.storage.stage_pending_agent_principal_rotation(
        &principal_id,
        &token_hash(&token),
        &expires_at,
        &actor,
        &source_credential,
    )?;
    state
        .storage
        .publish_pending_agent_principal_rotation(&pending, &actor, &source_credential)?;
    let agent = state.storage.get_current_agent_principal_for_creator(
        &principal_id,
        &actor,
        &source_credential,
    )?;
    Ok(Json(RotateAgentPrincipalResponse {
        agent,
        token,
        receipt: pending.receipt,
    }))
}

async fn remove_agent_principal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(principal_id): Path<String>,
) -> ApiResult<Json<RemoveAgentPrincipalResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    authorize_human_principal_management(&state, &actor, &source_credential, &principal_id)?;
    let receipt =
        state
            .storage
            .remove_agent_principal(&principal_id, &actor, &source_credential)?;
    Ok(Json(RemoveAgentPrincipalResponse { receipt }))
}

async fn list_agent_access(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
    Query(query): Query<AgentPrincipalPageQuery>,
) -> ApiResult<Json<AgentAccessListResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    let folder = state
        .storage
        .get_file(&file_id)?
        .ok_or(ApiError::NotFound)?;
    state
        .storage
        .ensure_item_response_permission(&folder.id, &actor, WorkspacePermission::Read)?;
    state.storage.ensure_workspace_permission(
        &folder.workspace_id,
        &actor,
        WorkspacePermission::Write,
    )?;
    let limit = validated_agent_principal_page_limit(query.limit.as_deref())?;
    let cursor = validated_agent_principal_cursor(query.cursor.as_deref())?;
    let (access, next_cursor) =
        state
            .storage
            .list_agent_access_for_root(&file_id, cursor.as_deref(), limit)?;
    state.storage.ensure_workspace_publication_authorized(
        &folder.workspace_id,
        &actor,
        &source_credential,
        WorkspacePermission::Write,
    )?;
    Ok(Json(AgentAccessListResponse {
        access,
        next_cursor,
    }))
}

async fn rotate_agent_access(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(grant_id): Path<String>,
) -> ApiResult<Json<CreateAgentAccessResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    let access = state
        .storage
        .get_agent_access(&grant_id)?
        .ok_or(ApiError::NotFound)?;
    authorize_human_principal_management(&state, &actor, &source_credential, &access.principal_id)
        .map_err(|error| match error {
            ApiError::Forbidden => ApiError::NotFound,
            other => other,
        })?;
    let expires_at = (Utc::now() + Duration::seconds(DEFAULT_EXPIRY_SECONDS)).to_rfc3339();
    let token = format!("{AGENT_TOKEN_PREFIX}{}", random_secret_token());
    let pending = state.storage.stage_pending_agent_principal_rotation(
        &access.principal_id,
        &token_hash(&token),
        &expires_at,
        &actor,
        &source_credential,
    )?;
    state
        .storage
        .publish_pending_agent_principal_rotation(&pending, &actor, &source_credential)?;
    let access = state
        .storage
        .get_agent_access(&grant_id)?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(CreateAgentAccessResponse {
        access,
        token: Some(token),
        receipt: pending.receipt,
    }))
}

async fn revoke_agent_access(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(grant_id): Path<String>,
) -> ApiResult<Json<AgentAccessMutationResponse>> {
    let (actor, source_credential) = require_user_actor_with_credential(&state, &headers)?;
    authorize_human_access_management(&state, &actor, &grant_id)?;
    let (access, receipt) =
        state
            .storage
            .revoke_agent_access(&grant_id, &actor, &source_credential)?;
    Ok(Json(AgentAccessMutationResponse { access, receipt }))
}

fn authorize_human_access_management(
    state: &AppState,
    actor: &crate::auth::Actor,
    grant_id: &str,
) -> ApiResult<()> {
    let access = state
        .storage
        .get_agent_access(grant_id)?
        .ok_or(ApiError::NotFound)?;
    let root = state
        .storage
        .get_file(&access.root_file_id)?
        .ok_or(ApiError::NotFound)?;
    state
        .storage
        .ensure_item_response_permission(&root.id, actor, WorkspacePermission::Read)?;
    state
        .storage
        .ensure_workspace_permission(&root.workspace_id, actor, WorkspacePermission::Write)
        .map_err(|error| match error {
            ApiError::Forbidden => ApiError::NotFound,
            other => other,
        })
}

fn authorize_human_principal_management(
    state: &AppState,
    actor: &crate::auth::Actor,
    source_credential: &crate::auth::DriveCredential,
    principal_id: &str,
) -> ApiResult<()> {
    if state
        .storage
        .agent_principal_exists_for_creator(principal_id, actor, source_credential)?
    {
        Ok(())
    } else {
        Err(ApiError::Forbidden)
    }
}

async fn agent_session(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AgentPrincipalPageQuery>,
) -> ApiResult<Json<AgentSessionResponse>> {
    let agent = require_agent_actor(&state, &headers)?;
    let limit = validated_agent_principal_page_limit(query.limit.as_deref())?;
    let cursor = validated_agent_principal_cursor(query.cursor.as_deref())?;
    let (grants, next_cursor) = state.storage.list_active_agent_access_for_principal(
        &agent.principal_id,
        &agent.token_id,
        cursor.as_deref(),
        limit,
    )?;
    state.storage.ensure_agent_session_publication_authorized(
        &agent.principal_id,
        &agent.token_id,
        &grants,
    )?;
    Ok(Json(AgentSessionResponse {
        principal_id: agent.principal_id,
        name: agent.name,
        token_id: agent.token_id,
        grants,
        next_cursor,
    }))
}

async fn agent_tree(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(grant_id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    let agent = require_agent_actor(&state, &headers)?;
    state.storage.consume_partitioned_public_rate_limit(
        &agent.token_id,
        "agent_tree",
        "token",
        AGENT_TREE_REQUESTS_PER_MINUTE,
        60,
    )?;
    let _planning = state.try_metadata_planning(&format!("agent:{}", agent.token_id))?;
    let (grant, files) =
        state
            .storage
            .agent_tree(&agent.principal_id, &agent.token_id, &grant_id)?;
    let receipt_actor = agent_receipt_actor(&agent.principal_id, &agent.token_id);
    state
        .storage
        .insert_receipt("agent.tree.read", &receipt_actor, Some(&grant_id))?;
    state.storage.ensure_agent_tree_publication_authorized(
        &agent.principal_id,
        &agent.token_id,
        &grant_id,
        &files,
    )?;
    Ok(Json(serde_json::json!({ "grant": grant, "files": files })))
}

async fn agent_create_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(grant_id): Path<String>,
    Json(request): Json<AgentCreateFileRequest>,
) -> ApiResult<(StatusCode, Json<FileMutationResponse>)> {
    let agent = require_agent_actor(&state, &headers)?;
    let access = state.storage.authorize_agent_grant(
        &agent.principal_id,
        &agent.token_id,
        &grant_id,
        true,
    )?;
    let parent_id = request
        .parent_id
        .as_deref()
        .unwrap_or(access.root_file_id.as_str());
    let (_, parent) = state.storage.authorize_agent_file(
        &agent.principal_id,
        &agent.token_id,
        &grant_id,
        parent_id,
        true,
    )?;
    if !matches!(parent.kind, FileKind::Folder) {
        return Err(ApiError::Validation("parent must be a folder".to_string()));
    }
    if matches!(request.kind, FileKind::Folder)
        && request
            .content
            .as_deref()
            .is_some_and(|content| !content.is_empty())
    {
        return Err(ApiError::Validation(
            "folders cannot contain file content".to_string(),
        ));
    }
    let content_bytes = if matches!(request.kind, FileKind::File) {
        request
            .content
            .as_ref()
            .map_or(0, |content| content.len() as i64)
    } else {
        0
    };
    if content_bytes > 0 {
        state
            .storage
            .ensure_workspace_server_content_allowed(&access.workspace_id)?;
    }
    let name = validate_file_name(&request.name)?;
    let kind = request.kind.clone();
    let (file, receipt) = blob_publication::run(&state, |publications| {
        let content_hash = match (&request.kind, request.content.as_ref()) {
            (FileKind::File, Some(content)) => {
                Some(publications.put_bytes(content.as_bytes())?.hash)
            }
            _ => None,
        };
        let (file, receipt) = state.storage.create_agent_file(
            &agent.principal_id,
            &agent.token_id,
            &grant_id,
            request.parent_id.as_deref(),
            &name,
            kind,
            content_hash.as_deref(),
            content_bytes,
        )?;
        if let Some(content) = request.content {
            state.storage.index_file_text(&file, &content)?;
        }
        Ok((file, receipt))
    })
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(FileMutationResponse { file, receipt }),
    ))
}

#[derive(Debug, Deserialize)]
struct AgentUpdateFileRequest {
    base_revision: Option<i64>,
    name: Option<String>,
    parent_id: Option<String>,
    collision_policy: Option<String>,
    replace_target_id: Option<String>,
    replace_target_revision: Option<i64>,
}

async fn agent_update_file(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((grant_id, file_id)): Path<(String, String)>,
    Json(request): Json<AgentUpdateFileRequest>,
) -> ApiResult<Json<FileMutationResponse>> {
    if request.name.is_none() && request.parent_id.is_none() {
        return Err(ApiError::Validation(
            "provide a name or destination folder".to_string(),
        ));
    }
    let agent = require_agent_actor(&state, &headers)?;
    state.storage.authorize_agent_file(
        &agent.principal_id,
        &agent.token_id,
        &grant_id,
        &file_id,
        true,
    )?;
    if let Some(parent_id) = request.parent_id.as_deref() {
        state.storage.authorize_agent_file(
            &agent.principal_id,
            &agent.token_id,
            &grant_id,
            parent_id,
            true,
        )?;
    }
    let (file, receipt) = state.storage.update_agent_file(
        &agent.principal_id,
        &agent.token_id,
        &grant_id,
        &file_id,
        AgentFileUpdate {
            base_revision: request.base_revision,
            name: request.name,
            parent_id: request.parent_id,
            collision_policy: request.collision_policy,
            replace_target_id: request.replace_target_id,
            replace_target_revision: request.replace_target_revision,
        },
    )?;
    Ok(Json(FileMutationResponse { file, receipt }))
}

#[derive(Debug, Serialize)]
struct AgentFileMetadataResponse {
    file: crate::model::DriveFile,
    metadata: crate::model::FileMetadata,
}

async fn agent_file_metadata(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((grant_id, file_id)): Path<(String, String)>,
) -> ApiResult<Json<AgentFileMetadataResponse>> {
    let agent = require_agent_actor(&state, &headers)?;
    let (_, file) = state.storage.authorize_agent_file(
        &agent.principal_id,
        &agent.token_id,
        &grant_id,
        &file_id,
        false,
    )?;
    let metadata = state.storage.get_file_metadata(&file_id)?;
    let receipt_actor = agent_receipt_actor(&agent.principal_id, &agent.token_id);
    state
        .storage
        .insert_receipt("agent.file.metadata", &receipt_actor, Some(&file_id))?;
    state.storage.authorize_agent_file(
        &agent.principal_id,
        &agent.token_id,
        &grant_id,
        &file_id,
        false,
    )?;
    Ok(Json(AgentFileMetadataResponse { file, metadata }))
}

async fn agent_file_content(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((grant_id, file_id)): Path<(String, String)>,
) -> ApiResult<Response> {
    let agent = require_agent_actor(&state, &headers)?;
    let (_, file) = state.storage.authorize_agent_file(
        &agent.principal_id,
        &agent.token_id,
        &grant_id,
        &file_id,
        false,
    )?;
    if !matches!(file.kind, FileKind::File) {
        return Err(ApiError::NotFound);
    }
    let subject = CurrentFileSubject::from_file(&file)?;
    let path = blob::blob_file_path(&state.data_dir(), &subject.content_hash)?;
    let range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok());
    let stream_permit = state.try_authenticated_body_stream(&agent.principal_id)?;
    let terminal_storage = state.storage.clone();
    let terminal_principal_id = agent.principal_id.clone();
    let terminal_token_id = agent.token_id.clone();
    let terminal_grant_id = grant_id.clone();
    let terminal_file_id = file_id.clone();
    let response = serve_blob_file_with_guard_after_open(
        &file.name,
        &path,
        range,
        Disposition::Inline,
        stream_permit,
        move || {
            let (_, current_file) = terminal_storage.authorize_agent_file(
                &terminal_principal_id,
                &terminal_token_id,
                &terminal_grant_id,
                &terminal_file_id,
                false,
            )?;
            if CurrentFileSubject::from_file(&current_file)? != subject {
                return Err(ApiError::NotFound);
            }
            Ok(())
        },
    )
    .await?;
    if is_initial_content_request(range) {
        state.storage.record_file_access_best_effort(
            &file.id,
            &file.workspace_id,
            FileAccessKind::Access,
        );
    }
    let receipt_actor = agent_receipt_actor(&agent.principal_id, &agent.token_id);
    state
        .storage
        .insert_receipt("agent.file.read", &receipt_actor, Some(&file_id))?;
    Ok(response)
}

#[derive(Debug, Deserialize)]
struct AgentContentQuery {
    base_revision: i64,
}

async fn agent_put_content(
    State(state): State<AppState>,
    Path((grant_id, file_id)): Path<(String, String)>,
    Query(query): Query<AgentContentQuery>,
    request: Request,
) -> ApiResult<Response> {
    let headers = request.headers().clone();
    let agent = require_agent_actor(&state, &headers)?;
    let (_, file) = state.storage.authorize_agent_file(
        &agent.principal_id,
        &agent.token_id,
        &grant_id,
        &file_id,
        true,
    )?;
    if !matches!(file.kind, FileKind::File) {
        return Err(ApiError::Validation(
            "content can only be replaced on a file".to_string(),
        ));
    }
    if file.revision != query.base_revision {
        return Err(ApiError::PreconditionFailed);
    }
    let media_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("application/octet-stream")
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    state
        .storage
        .ensure_workspace_server_content_allowed(&file.workspace_id)?;
    // Bound all retained binary bytes, including while publication waits for
    // lifecycle ownership. Rotation or another grant must share this capacity.
    let _ingress = state
        .try_authenticated_upload_ingress(&format!("agent-principal:{}", agent.principal_id))?;
    let body = to_bytes(request.into_body(), MAX_AGENT_CONTENT_BYTES)
        .await
        .map_err(|_| {
            ApiError::PayloadTooLarge(format!(
                "agent content must not exceed {MAX_AGENT_CONTENT_BYTES} bytes"
            ))
        })?;
    blob_publication::run(&state, |publications| {
        let hash = publications.put_bytes(&body)?.hash;
        let (file, receipt) = state.storage.put_agent_content(
            &agent.principal_id,
            &agent.token_id,
            &grant_id,
            &file_id,
            query.base_revision,
            &hash,
            body.len() as i64,
        )?;
        if media_type.starts_with("text/") {
            if let Ok(text) = std::str::from_utf8(&body) {
                state.storage.index_file_text(&file, text)?;
            } else {
                state.storage.clear_file_text_index(&file)?;
            }
        } else {
            state.storage.clear_file_text_index(&file)?;
        }
        Ok(Json(FileMutationResponse { file, receipt }).into_response())
    })
    .await
}

fn validated_expiry(value: Option<i64>) -> ApiResult<i64> {
    let value = value.unwrap_or(DEFAULT_EXPIRY_SECONDS);
    if !(MIN_EXPIRY_SECONDS..=MAX_EXPIRY_SECONDS).contains(&value) {
        return Err(ApiError::Validation(format!(
            "expires_in_seconds must be between {MIN_EXPIRY_SECONDS} and {MAX_EXPIRY_SECONDS}"
        )));
    }
    Ok(value)
}

fn agent_receipt_actor(principal_id: &str, token_id: &str) -> String {
    format!("agent:{principal_id}:{token_id}")
}
