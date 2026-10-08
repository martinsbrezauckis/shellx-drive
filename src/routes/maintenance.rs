//! Maintenance routes: operator-facing admin endpoints for platform upkeep.
//! Everything here is `require_admin`. Currently exposes the maintenance status
//! summary and the reference-counted orphan-blob garbage collector.

use std::time::Duration;

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    auth::{require_admin, require_admin_with_credential, Actor, DriveCredential},
    blob,
    config::Config,
    error::ApiResult,
    model::{MaintenanceStatus, MaintenanceStatusResponse},
    server::{admin_response_guard::ensure_admin_credential_current, AppState},
};

/// Default grace window for the blob GC: blobs modified within this many seconds
/// are left alone so an in-flight upload (blob written, DB row not yet
/// committed) is never reaped. Operators can override per-call.
const DEFAULT_BLOB_GC_GRACE_SECONDS: u64 = 3600;
const DEFAULT_BLOB_GC_BATCH_SIZE: usize = 256;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/admin/maintenance", get(maintenance_status))
        .route("/admin/maintenance/blobs/gc", post(gc_orphan_blobs))
}

pub fn current_maintenance_status(config: &Config) -> MaintenanceStatus {
    MaintenanceStatus {
        // Drive deliberately has no host-command or Ubuntu Pro probe. Reporting
        // `false` here used to imply a failed assessment and made /ready
        // permanently degraded even on otherwise healthy self-hosts.
        ubuntu_pro_attached: None,
        host_posture: "unassessed".to_string(),
        token_source: config.maintenance_token_source.clone(),
        sudo_source: config.maintenance_sudo_source.clone(),
        restart_policy: "no_restarts".to_string(),
        package_update_policy: "attach_before_update".to_string(),
        last_run_at: None,
        last_result: None,
    }
}

async fn maintenance_status(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<MaintenanceStatusResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(MaintenanceStatusResponse {
        maintenance: current_maintenance_status(&state.config),
    }))
}

#[derive(Debug, Default, Deserialize)]
struct BlobGcQuery {
    /// Grace window in seconds; blobs newer than this are skipped. Defaults to
    /// [`DEFAULT_BLOB_GC_GRACE_SECONDS`]. Pass `0` for a stop-the-world sweep
    /// when no upload is in flight.
    #[serde(default)]
    min_age_seconds: Option<u64>,
    /// Exclusive continuation cursor returned by a previous batch.
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

/// `POST /admin/maintenance/blobs/gc` — reference-counted orphan-blob sweep.
///
/// Processes one cursor-bounded blob-store page, and removes each old blob that
/// no DB row references (file content, revision, thumbnail, or folder cover).
/// This closes the gap
/// where a blob written by `put_blob` whose DB row insert then failed would be
/// orphaned forever. Also cleans stale `*.tmp` files from interrupted writes.
/// Admin-only.
async fn gc_orphan_blobs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<BlobGcQuery>,
) -> ApiResult<Json<Value>> {
    let (actor, source_credential) = require_admin_with_credential(&state, &headers)?;
    let min_age = Duration::from_secs(
        query
            .min_age_seconds
            .unwrap_or(DEFAULT_BLOB_GC_GRACE_SECONDS),
    );
    let limit = query.limit.unwrap_or(DEFAULT_BLOB_GC_BATCH_SIZE);
    if limit == 0 || limit > blob::MAX_GC_BATCH_SIZE {
        return Err(crate::error::ApiError::Validation(format!(
            "blob GC limit must be between 1 and {}",
            blob::MAX_GC_BATCH_SIZE
        )));
    }

    // The guard covers both stale temporary-file cleanup in the scan and the
    // content-object reference check/unlink below. It is acquired before any
    // storage query so a publisher cannot commit a new reference between the
    // check and physical deletion.
    let _blob_lifecycle_lock = blob::acquire_exclusive_lifecycle_lock(state.data_dir()).await?;
    revalidate_gc_administrator(&state, &actor, &source_credential)?;
    let scan = blob::scan_blobs_for_gc(&state.data_dir(), min_age, query.cursor.as_deref(), limit)
        .map_err(|error| {
            if blob::is_gc_object_budget_exceeded(&error) {
                crate::error::ApiError::PayloadTooLarge(error.to_string())
            } else if error.kind() == std::io::ErrorKind::InvalidInput {
                crate::error::ApiError::Validation(error.to_string())
            } else {
                crate::error::ApiError::Io(error)
            }
        })?;
    let scanned = scan.candidates.len() as u64;
    let hashes = scan
        .candidates
        .iter()
        .map(|(hash, _)| hash.clone())
        .collect::<Vec<_>>();
    let referenced = state.storage.referenced_content_hashes(&hashes)?;
    let mut removed = 0_u64;
    let mut reclaimed_bytes = 0_u64;
    for (hash, size) in scan.candidates {
        if !referenced.contains(&hash) && blob::remove_blob(&state.data_dir(), &hash)? {
            removed += 1;
            reclaimed_bytes += size;
        }
    }

    let receipt = state
        .storage
        .insert_receipt("maintenance.blob.gc", &actor.email, None)?;
    Ok(Json(json!({
        "service": "shellx-drive",
        "scanned": scanned,
        "removed": removed,
        "reclaimed_bytes": reclaimed_bytes,
        "skipped_recent": scan.skipped_recent,
        "tmp_removed": scan.tmp_removed,
        "inspected_entries": scan.inspected_entries,
        "limit": limit,
        "more_available": scan.more_available,
        "next_cursor": scan.next_cursor,
        "receipt": receipt,
    })))
}

/// The lifecycle lock serializes content publication with GC. Rechecking only
/// after it is held makes the authorization decision the final prerequisite to
/// scanning and unlinking, rather than a stale admission decision made while
/// waiting for another lifecycle operation.
fn revalidate_gc_administrator(
    state: &AppState,
    actor: &Actor,
    source_credential: &DriveCredential,
) -> ApiResult<()> {
    ensure_admin_credential_current(state, actor, source_credential)
}

#[cfg(test)]
mod tests {
    use chrono::{Duration as ChronoDuration, Utc};

    use super::*;
    use crate::{
        auth::{token_hash, Actor, AuthMode},
        config::Config,
    };

    fn test_state() -> (tempfile::TempDir, AppState, Actor, DriveCredential) {
        let data = tempfile::tempdir().unwrap();
        let state = AppState::open(Config {
            bind: "127.0.0.1:0".parse().unwrap(),
            data_dir: data.path().to_path_buf(),
            token: "gc-terminal-test-token".to_string(),
            bootstrap_token: None,
            e2e_enabled: true,
            email_transport: "capture".to_string(),
            email_from: "ShellX Drive <noreply@example.test>".to_string(),
            public_origin: crate::config::PublicOrigin::parse("http://127.0.0.1").unwrap(),
            email_smtp_host_source: "not_configured".to_string(),
            email_smtp_port: None,
            email_smtp_user_source: "not_configured".to_string(),
            maintenance_token_source: "not_configured".to_string(),
            maintenance_sudo_source: "not_configured".to_string(),
            local_session_ttl_seconds: 2_592_000,
            office_provider_name: "Office editor".to_string(),
            office_provider_url: None,
            office_session_ttl_seconds: 900,
            hosted_mode: false,
            hosted_billing_provider: "none".to_string(),
            hosted_public_rate_limit_per_minute: 60,
            backup_max_archive_bytes: 9 * 1024 * 1024 * 1024 * 1024,
            secure_cookies: false,
            trust_proxy_headers: false,
            update_repo: None,
        })
        .unwrap();
        let email = "gc-terminal-admin@example.test";
        let (account, _) = state
            .storage
            .bootstrap_auth_account(email, "stored-password-hash")
            .unwrap();
        let session_id = "gc-terminal-admin-session";
        state
            .storage
            .record_auth_session(
                session_id,
                email,
                "local-password",
                &account.user_id,
                &token_hash("gc-terminal-test-bearer"),
                &(Utc::now() + ChronoDuration::hours(1)).to_rfc3339(),
            )
            .unwrap();
        (
            data,
            state,
            Actor {
                email: email.to_string(),
                is_admin: true,
                auth_mode: AuthMode::LocalAccount,
                allowed_workspace_ids: None,
            },
            DriveCredential::UserSession(session_id.to_string()),
        )
    }

    #[tokio::test]
    async fn gc_terminal_recheck_rejects_a_session_revoked_while_waiting_for_the_lock() {
        let (_data, state, actor, credential) = test_state();
        let lifecycle_lock = blob::acquire_exclusive_lifecycle_lock(state.data_dir())
            .await
            .unwrap();

        state
            .storage
            .revoke_auth_session("gc-terminal-admin-session", &actor.email)
            .unwrap();
        assert!(matches!(
            revalidate_gc_administrator(&state, &actor, &credential),
            Err(crate::error::ApiError::Unauthenticated)
        ));
        drop(lifecycle_lock);
    }
}
