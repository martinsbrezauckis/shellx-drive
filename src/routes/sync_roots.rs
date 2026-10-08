use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;

use crate::{
    auth::require_drive_actor_with_credential,
    error::{ApiError, ApiResult},
    model::{
        RevalidateSyncRootsRequest, RevalidateSyncRootsResponse, SyncRootManifestResponse,
        SyncRootPageResponse, SyncRootsResponse,
    },
    server::AppState,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/sync/roots", get(list_sync_roots))
        .route("/sync/roots/page", get(list_sync_root_page))
        .route(
            "/sync/roots/revalidate",
            post(revalidate_configured_sync_roots),
        )
        .route("/sync/roots/{root_id}/manifest", get(sync_root_manifest))
}

async fn revalidate_configured_sync_roots(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RevalidateSyncRootsRequest>,
) -> ApiResult<Json<RevalidateSyncRootsResponse>> {
    let (actor, credential) = require_drive_actor_with_credential(&state, &headers)?;
    let (roots, revoked_ids, replacements) =
        state
            .storage
            .revalidate_configured_sync_roots(&request.root_ids, &actor, &credential)?;
    Ok(Json(RevalidateSyncRootsResponse {
        roots,
        revoked_ids,
        replacements,
    }))
}

#[derive(Debug, Deserialize)]
struct SyncRootPageQuery {
    cursor: Option<String>,
    limit: Option<usize>,
}

async fn list_sync_root_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<SyncRootPageQuery>,
) -> ApiResult<Json<SyncRootPageResponse>> {
    let (actor, credential) = require_drive_actor_with_credential(&state, &headers)?;
    let page = state.storage.list_sync_root_page_limited(
        &actor,
        &credential,
        query.cursor.as_deref(),
        &state.config.token,
        query.limit.unwrap_or(50),
    )?;
    Ok(Json(page))
}

#[derive(Debug, Deserialize)]
struct SyncRootManifestQuery {
    access_generation: Option<String>,
}

fn required_access_generation(query: SyncRootManifestQuery) -> ApiResult<u64> {
    let value = query
        .access_generation
        .as_deref()
        .ok_or_else(|| ApiError::Validation("access_generation is required".to_string()))?;
    if value.is_empty()
        || value.len() > 20
        || value.bytes().any(|byte| !byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(ApiError::Validation(
            "access_generation must be a positive unsigned integer".to_string(),
        ));
    }
    let generation = value.parse::<u64>().map_err(|_| {
        ApiError::Validation("access_generation must be a positive unsigned integer".to_string())
    })?;
    if generation == 0 {
        return Err(ApiError::Validation(
            "access_generation must be a positive unsigned integer".to_string(),
        ));
    }
    Ok(generation)
}

async fn list_sync_roots(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<SyncRootsResponse>> {
    let (actor, credential) = require_drive_actor_with_credential(&state, &headers)?;
    let roots = state.storage.list_sync_roots_for_actor(&actor)?;
    let root_ids = roots.into_iter().map(|root| root.id).collect::<Vec<_>>();
    let revalidated = state.storage.revalidate_sync_roots_publication_authorized(
        &root_ids,
        &actor,
        &credential,
    )?;
    Ok(Json(SyncRootsResponse { roots: revalidated }))
}

async fn sync_root_manifest(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(root_id): Path<String>,
    Query(query): Query<SyncRootManifestQuery>,
) -> ApiResult<Json<SyncRootManifestResponse>> {
    let expected_access_generation = required_access_generation(query)?;
    let (actor, credential) = require_drive_actor_with_credential(&state, &headers)?;
    let (root, files, next_cursor) =
        state
            .storage
            .sync_root_manifest(&root_id, &actor, expected_access_generation)?;
    let root = state
        .storage
        .ensure_sync_root_manifest_publication_authorized(
            &root.id,
            &files,
            &actor,
            &credential,
            expected_access_generation,
        )?;
    let mode = if root.root_file_id.is_some() {
        "scoped_desktop_sync"
    } else {
        "full_desktop_sync"
    };
    Ok(Json(SyncRootManifestResponse {
        root,
        mode: mode.to_string(),
        next_cursor,
        files,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_generation_query_is_positive_and_canonical() {
        for value in [
            None,
            Some(""),
            Some("0"),
            Some("01"),
            Some("-1"),
            Some("nope"),
        ] {
            assert!(required_access_generation(SyncRootManifestQuery {
                access_generation: value.map(str::to_string),
            })
            .is_err());
        }
        assert_eq!(
            required_access_generation(SyncRootManifestQuery {
                access_generation: Some("18446744073709551615".to_string()),
            })
            .unwrap(),
            u64::MAX
        );
    }
}
