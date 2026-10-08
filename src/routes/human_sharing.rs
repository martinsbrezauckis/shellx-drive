use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    routing::{get, patch},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    auth::{
        require_admin, require_admin_with_credential, require_user_actor_with_credential,
        WorkspacePermission,
    },
    error::{ApiError, ApiResult},
    model::{
        CreateHumanItemGrantRequest, EveryoneGrantPolicyMutationResponse,
        EveryoneGrantPolicyResponse, HumanItemGrantListResponse, HumanItemGrantResponse,
        ItemActionCapabilitiesResponse, SharePrincipalListResponse, SharedByMeResponse,
        SharedItemRootsResponse, UpdateEveryoneGrantPolicyRequest, UpdateHumanItemGrantRequest,
    },
    server::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/admin/human-sharing-policy",
            get(get_everyone_grant_policy).patch(update_everyone_grant_policy),
        )
        .route("/share-principals", get(list_share_principals))
        .route(
            "/files/{file_id}/human-grants",
            get(list_human_item_grants).post(create_human_item_grant),
        )
        .route(
            "/files/{file_id}/action-capabilities",
            get(item_action_capabilities),
        )
        .route(
            "/human-grants/{grant_id}",
            patch(update_human_item_grant).delete(revoke_human_item_grant),
        )
        .route("/sharing/shared-with-me", get(shared_with_me))
        .route("/sharing/shared-by-me", get(shared_by_me))
}

#[derive(Debug, Deserialize)]
struct PrincipalQuery {
    file_id: String,
    kind: String,
    query: String,
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct RootListQuery {
    limit: Option<usize>,
    cursor: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct RootCursor {
    list: String,
    actor: String,
    name: String,
    id: String,
}

fn actor_cursor_key(email: &str) -> String {
    hex::encode(Sha256::digest(email.as_bytes()))
}

fn parse_root_cursor(
    raw: Option<&str>,
    list: &str,
    email: &str,
) -> ApiResult<Option<(String, String)>> {
    let Some(raw) = raw else { return Ok(None) };
    if raw.is_empty() || raw.len() > 2048 {
        return Err(ApiError::Validation("shared root cursor is invalid".into()));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(raw)
        .map_err(|_| ApiError::Validation("shared root cursor is invalid".into()))?;
    let cursor: RootCursor = serde_json::from_slice(&bytes)
        .map_err(|_| ApiError::Validation("shared root cursor is invalid".into()))?;
    if cursor.list != list
        || cursor.actor != actor_cursor_key(email)
        || cursor.name.len() > 512
        || Uuid::parse_str(&cursor.id).is_err()
    {
        return Err(ApiError::Validation("shared root cursor is invalid".into()));
    }
    Ok(Some((cursor.name, cursor.id)))
}

fn encode_root_cursor(
    list: &str,
    email: &str,
    position: Option<(String, String)>,
) -> Option<String> {
    position.map(|(name, id)| {
        URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&RootCursor {
                list: list.into(),
                actor: actor_cursor_key(email),
                name,
                id,
            })
            .expect("shared root cursor serializes"),
        )
    })
}

async fn list_share_principals(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PrincipalQuery>,
) -> ApiResult<Json<SharePrincipalListResponse>> {
    let (actor, credential) = require_user_actor_with_credential(&state, &headers)?;
    state.storage.ensure_item_response_permission(
        &query.file_id,
        &actor,
        WorkspacePermission::Manage,
    )?;
    let principals = state.storage.list_share_principals(
        &query.kind,
        &query.query,
        query.limit.unwrap_or(20),
    )?;
    state.storage.ensure_item_response_publication_authorized(
        &query.file_id,
        &actor,
        &credential,
        WorkspacePermission::Manage,
    )?;
    Ok(Json(SharePrincipalListResponse { principals }))
}

async fn list_human_item_grants(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> ApiResult<Json<HumanItemGrantListResponse>> {
    let (actor, credential) = require_user_actor_with_credential(&state, &headers)?;
    state
        .storage
        .ensure_item_response_permission(&file_id, &actor, WorkspacePermission::Manage)?;
    let grants = state.storage.list_human_item_grants(&file_id)?;
    // Read the non-secret policy before the terminal credential/item check so
    // no additional storage work can widen the publication race afterward.
    let everyone_policy_enabled = state
        .storage
        .everyone_grant_policy()?
        .everyone_grants_enabled;
    let (_, action_capabilities, _) = state
        .storage
        .item_action_capabilities_publication_authorized(
            &file_id,
            &actor,
            &credential,
            WorkspacePermission::Manage,
        )?;
    Ok(Json(HumanItemGrantListResponse {
        grants,
        action_capabilities,
        everyone_policy_enabled,
    }))
}

async fn get_everyone_grant_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<EveryoneGrantPolicyResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(EveryoneGrantPolicyResponse {
        policy: state.storage.everyone_grant_policy()?,
    }))
}

async fn update_everyone_grant_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<UpdateEveryoneGrantPolicyRequest>,
) -> ApiResult<Json<EveryoneGrantPolicyMutationResponse>> {
    let (actor, credential) = require_admin_with_credential(&state, &headers)?;
    let (policy, receipt) =
        state
            .storage
            .update_everyone_grant_policy_authorized(request, &actor, &credential)?;
    Ok(Json(EveryoneGrantPolicyMutationResponse {
        policy,
        receipt,
    }))
}

async fn item_action_capabilities(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> ApiResult<Json<ItemActionCapabilitiesResponse>> {
    let (actor, credential) = require_user_actor_with_credential(&state, &headers)?;
    state
        .storage
        .ensure_item_response_permission(&file_id, &actor, WorkspacePermission::Read)?;
    let (workspace_id, action_capabilities, access_generation) = state
        .storage
        .item_action_capabilities_publication_authorized(
            &file_id,
            &actor,
            &credential,
            WorkspacePermission::Read,
        )?;
    Ok(Json(ItemActionCapabilitiesResponse {
        file_id,
        workspace_id,
        action_capabilities,
        access_generation,
    }))
}

async fn create_human_item_grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
    Json(request): Json<CreateHumanItemGrantRequest>,
) -> ApiResult<(StatusCode, Json<HumanItemGrantResponse>)> {
    let (actor, credential) = require_user_actor_with_credential(&state, &headers)?;
    state
        .storage
        .ensure_item_response_permission(&file_id, &actor, WorkspacePermission::Read)?;
    let (grant, receipt) =
        state
            .storage
            .create_human_item_grant(&file_id, &request, &actor, &credential)?;
    Ok((
        StatusCode::CREATED,
        Json(HumanItemGrantResponse { grant, receipt }),
    ))
}

async fn update_human_item_grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(grant_id): Path<String>,
    Json(request): Json<UpdateHumanItemGrantRequest>,
) -> ApiResult<Json<HumanItemGrantResponse>> {
    let (actor, credential) = require_user_actor_with_credential(&state, &headers)?;
    let (grant, receipt) = state.storage.update_human_item_grant(
        &grant_id,
        request.role.as_deref(),
        request.expires_at.as_ref().map(|expiry| expiry.as_deref()),
        &actor,
        &credential,
    )?;
    Ok(Json(HumanItemGrantResponse { grant, receipt }))
}

async fn revoke_human_item_grant(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(grant_id): Path<String>,
) -> ApiResult<StatusCode> {
    let (actor, credential) = require_user_actor_with_credential(&state, &headers)?;
    state
        .storage
        .revoke_human_item_grant(&grant_id, &actor, &credential)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn shared_with_me(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<RootListQuery>,
) -> ApiResult<Json<SharedItemRootsResponse>> {
    let (actor, credential) = require_user_actor_with_credential(&state, &headers)?;
    let cursor = parse_root_cursor(query.cursor.as_deref(), "shared-with-me", &actor.email)?;
    let (roots, next_cursor) = state.storage.list_shared_item_roots_page_for_actor(
        &actor,
        query.limit.unwrap_or(100),
        cursor.as_ref(),
    )?;
    let roots = state
        .storage
        .revalidate_shared_item_roots_publication_authorized(&roots, &actor, &credential)?;
    Ok(Json(SharedItemRootsResponse {
        roots,
        next_cursor: encode_root_cursor("shared-with-me", &actor.email, next_cursor),
    }))
}

async fn shared_by_me(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<RootListQuery>,
) -> ApiResult<Json<SharedByMeResponse>> {
    let (actor, credential) = require_user_actor_with_credential(&state, &headers)?;
    let cursor = parse_root_cursor(query.cursor.as_deref(), "shared-by-me", &actor.email)?;
    let (roots, next_cursor) = state.storage.list_shared_by_me_page_for_actor(
        &actor,
        query.limit.unwrap_or(100),
        cursor.as_ref(),
    )?;
    let roots = state
        .storage
        .revalidate_shared_by_me_publication_authorized(&roots, &actor, &credential)?;
    Ok(Json(SharedByMeResponse {
        roots,
        next_cursor: encode_root_cursor("shared-by-me", &actor.email, next_cursor),
    }))
}

#[cfg(test)]
mod cursor_tests {
    use super::*;

    #[test]
    fn sharing_cursor_is_opaque_and_list_scoped() {
        let position = ("folder".to_string(), Uuid::now_v7().to_string());
        let encoded =
            encode_root_cursor("shared-with-me", "one@example.test", Some(position.clone()))
                .unwrap();
        assert_eq!(
            parse_root_cursor(Some(&encoded), "shared-with-me", "one@example.test").unwrap(),
            Some(position)
        );
        assert!(parse_root_cursor(Some(&encoded), "shared-by-me", "one@example.test").is_err());
        assert!(parse_root_cursor(Some(&encoded), "shared-with-me", "two@example.test").is_err());
        assert!(
            parse_root_cursor(Some("broken-token"), "shared-with-me", "one@example.test").is_err()
        );
    }
}
