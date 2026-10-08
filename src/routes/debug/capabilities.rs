use axum::{
    extract::{Query, State},
    http::HeaderMap,
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    auth::{require_admin, token_hash},
    error::{ApiError, ApiResult},
    server::AppState,
    version,
};

#[derive(Deserialize)]
struct CapabilityQuery {
    workspace_id: Option<String>,
}

#[derive(Serialize)]
struct DebugCapabilitiesResponse {
    service: &'static str,
    build: String,
    actor: Value,
    server: Value,
    workspace: Option<Value>,
    client: Value,
}

pub(super) fn router() -> Router<AppState> {
    Router::new().route("/debug/capabilities", get(debug_capabilities))
}

async fn debug_capabilities(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<CapabilityQuery>,
) -> ApiResult<Json<DebugCapabilitiesResponse>> {
    let actor = require_admin(&state, &headers)?;
    let workspace = match query.workspace_id.as_deref() {
        Some(workspace_id) => {
            let workspace = state
                .storage
                .get_workspace(workspace_id)?
                .ok_or(ApiError::NotFound)?;
            let policy = state.storage.get_workspace_policy(workspace_id)?;
            let open = workspace.storage_mode == "open";
            Some(json!({
                "workspace_id": workspace.id,
                "storage_mode": workspace.storage_mode,
                "archived": workspace.archived_at.is_some(),
                "metadata_sync": true,
                "server_body_access": open,
                "previews": open,
                "streaming_downloads": open,
                "webdav": open,
                "public_sharing": open && policy.public_links_enabled,
                "never_expiring_links": open && policy.public_links_enabled && policy.allow_never_expire,
                "quota_bytes": policy.quota_bytes,
            }))
        }
        None => None,
    };
    Ok(Json(DebugCapabilitiesResponse {
        service: "shellx-drive",
        build: version::build_id(),
        actor: json!({
            "actor_ref": format!("actor-{}", &token_hash(&actor.email)[..12]),
            "admin": actor.is_admin,
            "auth_mode": actor.auth_mode.as_str(),
            "workspace_constraint": actor.allowed_workspace_ids.is_some(),
        }),
        server: json!({
            "resumable_uploads": true,
            "guest_shares": true,
            "previews": true,
            "range_downloads": true,
            "comments": true,
            "revisions": true,
            "webdav_class_2": true,
            "streaming_backup_v2": true,
            "debug_export_bounded": true,
        }),
        workspace,
        client: json!({
            "browser_snapshot": "local_operator_panel",
            "snapshot_schema": "shellx-drive-browser-debug-v1",
            "offline_metadata": true,
            "service_worker": true,
        }),
    }))
}
