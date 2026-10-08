use axum::{
    extract::{Path, State},
    http::HeaderMap,
    routing::{delete, get},
    Json, Router,
};
use chrono::Utc;

use crate::{
    auth::{require_admin, require_admin_with_credential},
    error::ApiResult,
    model::{
        AdminSummary, AdminWorkspaceSummary, AdminWorkspacesResponse, ReadinessCheck,
        ReadinessResponse, RegistrationPolicyRequest, RegistrationPolicyResponse, SupportBundle,
        SupportBundleLog, SupportBundleResponse, WorkspaceDeleteResponse,
    },
    routes::{
        debug::{email_debug_response, redaction::DebugEmailResponse, support_debug_export},
        maintenance::current_maintenance_status,
    },
    server::AppState,
    storage::MAX_DEBUG_LIST_ROWS,
};

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/ready", get(readiness))
        .route("/admin/summary", get(admin_summary))
        .route("/admin/workspaces", get(admin_workspaces))
        .route(
            "/admin/workspaces/{workspace_id}",
            delete(delete_admin_workspace),
        )
        .route("/admin/email", get(admin_email).post(admin_email_run))
        .route(
            "/admin/registration-policy",
            get(admin_registration_policy).patch(update_admin_registration_policy),
        )
        .route("/admin/support-bundle", get(admin_support_bundle))
}

async fn admin_workspaces(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<AdminWorkspacesResponse>> {
    let actor = require_admin(&state, &headers)?;
    let mut workspaces = Vec::new();
    for workspace in state
        .storage
        .list_workspaces_bounded(MAX_DEBUG_LIST_ROWS.min(200))?
    {
        workspaces.push(AdminWorkspaceSummary {
            usage: state
                .run_workspace_usage(workspace.id.clone(), &actor.email)
                .await?,
            member_count: state.storage.workspace_member_count(&workspace.id)?,
            workspace,
        });
    }
    Ok(Json(AdminWorkspacesResponse { workspaces }))
}

async fn delete_admin_workspace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(workspace_id): Path<String>,
) -> ApiResult<Json<WorkspaceDeleteResponse>> {
    let (actor, source_credential) = require_admin_with_credential(&state, &headers)?;
    let receipt = state.storage.delete_empty_archived_workspace_authorized(
        &workspace_id,
        &actor,
        &source_credential,
    )?;
    Ok(Json(WorkspaceDeleteResponse {
        workspace_id,
        receipt,
    }))
}

async fn admin_summary(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<AdminSummary>> {
    require_admin(&state, &headers)?;
    let recent_receipts = state.storage.list_recent_receipts(10)?;
    let recent_activity = state
        .storage
        .list_activity()?
        .into_iter()
        .take(10)
        .collect();
    Ok(Json(AdminSummary {
        service: "shellx-drive".to_string(),
        totals: state.storage.admin_totals()?,
        job_totals: state.storage.background_job_totals()?,
        recent_receipts,
        recent_activity,
    }))
}

async fn readiness(State(state): State<AppState>) -> Json<ReadinessResponse> {
    Json(readiness_for_state(&state))
}

async fn admin_email(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<DebugEmailResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(email_debug_response(&state)?))
}

async fn admin_email_run(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<DebugEmailResponse>> {
    let (actor, source_credential) = require_admin_with_credential(&state, &headers)?;
    if state.config.email_transport == "capture" {
        state
            .storage
            .run_email_outbox_capture_authorized(&actor, &source_credential)?;
    }
    Ok(Json(email_debug_response(&state)?))
}

async fn admin_registration_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<RegistrationPolicyResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(RegistrationPolicyResponse {
        enabled: state.storage.registration_enabled()?,
        receipt: None,
    }))
}

async fn update_admin_registration_policy(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RegistrationPolicyRequest>,
) -> ApiResult<Json<RegistrationPolicyResponse>> {
    let (actor, source_credential) = require_admin_with_credential(&state, &headers)?;
    let (enabled, receipt) = state.storage.set_registration_enabled_authorized(
        request.enabled,
        &actor,
        &source_credential,
    )?;
    Ok(Json(RegistrationPolicyResponse {
        enabled,
        receipt: Some(receipt),
    }))
}

pub(crate) fn readiness_for_state(state: &AppState) -> ReadinessResponse {
    let mut checks = Vec::new();
    let mut ready = true;
    let mut degraded = false;

    match state.storage.ping() {
        Ok(()) => checks.push(ReadinessCheck {
            name: "storage".to_string(),
            status: "ready".to_string(),
            critical: true,
            message: "SQLite storage is reachable".to_string(),
        }),
        Err(_) => {
            ready = false;
            checks.push(ReadinessCheck {
                name: "storage".to_string(),
                status: "failed".to_string(),
                critical: true,
                message: "Storage is unavailable".to_string(),
            });
        }
    }

    match state.storage.get_backup_policy() {
        Ok(policy) => checks.push(ReadinessCheck {
            name: "backup_policy".to_string(),
            status: if policy.enabled { "ready" } else { "idle" }.to_string(),
            critical: false,
            message: if policy.enabled {
                "Scheduled backups are enabled".to_string()
            } else {
                "Scheduled backups are disabled".to_string()
            },
        }),
        Err(_) => {
            degraded = true;
            checks.push(ReadinessCheck {
                name: "backup_policy".to_string(),
                status: "degraded".to_string(),
                critical: false,
                message: "Backup policy is unavailable".to_string(),
            });
        }
    }

    if state.backup_maintenance().is_some() {
        ready = false;
        checks.push(ReadinessCheck {
            name: "backup_restore".to_string(),
            status: "maintenance".to_string(),
            critical: true,
            message: "A backup restore is in progress".to_string(),
        });
    } else {
        checks.push(ReadinessCheck {
            name: "backup_restore".to_string(),
            status: "ready".to_string(),
            critical: true,
            message: "No backup restore is in progress".to_string(),
        });
    }

    let maintenance = current_maintenance_status(&state.config);
    checks.push(ReadinessCheck {
        name: "maintenance".to_string(),
        // The binary does not run host commands, so it must not pretend that
        // an Ubuntu Pro posture was assessed. This informational row remains
        // visible without turning a healthy Drive service into a false
        // readiness degradation.
        status: maintenance.host_posture,
        critical: false,
        message: "Host maintenance posture is unassessed; Drive does not run an Ubuntu Pro probe"
            .to_string(),
    });

    let state_label = if !ready {
        "not_ready"
    } else if degraded {
        "degraded"
    } else {
        "ready"
    };

    ReadinessResponse {
        live: true,
        ready,
        state: state_label.to_string(),
        checks,
    }
}

async fn admin_support_bundle(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<SupportBundleResponse>> {
    let (actor, source_credential) = require_admin_with_credential(&state, &headers)?;
    let debug_export = support_debug_export(&state)?;
    let generated_at = Utc::now().to_rfc3339();
    let logs = vec![
        SupportBundleLog {
            kind: "metadata".to_string(),
            message: "strict operational allowlist included; user content, names, paths, and secrets omitted"
                .to_string(),
            created_at: generated_at.clone(),
        },
        SupportBundleLog {
            kind: "readiness".to_string(),
            message: readiness_for_state(&state).state,
            created_at: generated_at.clone(),
        },
    ];
    let debug_export_bytes = serde_json::to_vec(&debug_export)
        .map(|bytes| bytes.len() as i64)
        .unwrap_or_default();
    let (metadata, receipt) = state.storage.create_support_bundle_authorized(
        debug_export_bytes,
        logs.len() as i64,
        &actor,
        &source_credential,
    )?;
    Ok(Json(SupportBundleResponse {
        bundle: SupportBundle {
            id: metadata.id,
            service: "shellx-drive".to_string(),
            generated_at: metadata.generated_at,
            debug_export,
            logs,
        },
        receipt,
    }))
}
