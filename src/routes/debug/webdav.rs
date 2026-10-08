use axum::{extract::State, http::HeaderMap, routing::get, Json, Router};
use serde::Serialize;
use serde_json::{json, Value};

use crate::{
    auth::require_admin,
    error::ApiResult,
    server::AppState,
    storage::{DebugWebDavLock, MAX_WEBDAV_LOCK_TIMEOUT_SECONDS},
};

#[derive(Serialize)]
struct DebugWebDavResponse {
    service: &'static str,
    capabilities: Value,
    total_active_locks: i64,
    listed_active_locks: usize,
    locks_truncated: bool,
    locks: Vec<DebugWebDavLock>,
}

pub(super) fn router() -> Router<AppState> {
    Router::new().route("/debug/webdav", get(debug_webdav))
}

async fn debug_webdav(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<Json<Value>> {
    require_admin(&state, &headers)?;
    Ok(Json(debug_webdav_value(&state)?))
}

pub(crate) fn debug_webdav_value(state: &AppState) -> ApiResult<Value> {
    let (total_active_locks, locks) = state.storage.debug_webdav_locks()?;
    let response = DebugWebDavResponse {
        service: "shellx-drive",
        capabilities: json!({
            "dav_classes": ["1", "2"],
            "exclusive_write_locks": true,
            "shared_write_locks": false,
            "depth": ["0", "infinity"],
            "unmapped_url_locking": false,
            "max_timeout_seconds": MAX_WEBDAV_LOCK_TIMEOUT_SECONDS,
            "mutation_token_header": "If",
            "unlock_token_header": "Lock-Token"
        }),
        listed_active_locks: locks.len(),
        locks_truncated: total_active_locks > locks.len() as i64,
        total_active_locks,
        locks,
    };
    Ok(serde_json::to_value(response).expect("serializable WebDAV debug response"))
}
