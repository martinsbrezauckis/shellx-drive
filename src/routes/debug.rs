use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    routing::{get, post},
    Json, Router,
};
mod activity;
mod agent_access;
mod app_tokens;
mod browse;
mod capabilities;
mod e2e;
mod export;
mod file_access;
mod imports;
mod query;
pub(crate) mod redaction;
mod storage_integrity;
mod sync_conflicts;
mod webdav;
mod workspaces;

use serde::{Deserialize, Serialize};

use crate::{
    auth::{require_admin, require_admin_with_credential, token_hash},
    error::{ApiError, ApiResult},
    model::{
        BackgroundJob, BackgroundJobRunResponse, BackgroundJobTotals, CommentThread,
        DebugBackupsResponse, DebugDeltaSyncResponse, DebugDropUploadHealthResponse,
        DebugDropUploadSession, DebugFileTreeResponse, DebugGroupsResponse, DebugHostedResponse,
        DebugInvitationsResponse, DebugMaintenanceResponse, DebugMobileSyncResponse,
        DebugOfficeSessionsResponse, DebugPoliciesResponse, DebugRegistrationResponse,
        DebugSandboxesResponse, DebugSearchResponse, DebugState, DebugSupportBundleResponse,
        DebugSyncResponse, DebugUploadsResponse, DebugUsageResponse,
    },
    routes::{
        backups::list_backup_metadata, hosted::debug_hosted_response,
        maintenance::current_maintenance_status, sandboxes::preview_for_profile,
    },
    server::AppState,
};

const REDACTED_DATA_DIR: &str = "redacted";

#[derive(Serialize)]
struct ReceiptsResponse {
    receipts: Vec<redaction::DebugReceipt>,
}

#[derive(Serialize)]
struct CommentsResponse {
    comments: Vec<CommentThread>,
    total_threads: usize,
    total_replies: usize,
    truncated: bool,
}

#[derive(Serialize)]
struct FolderTemplatesResponse {
    templates: Vec<redaction::DebugFolderTemplate>,
}

#[derive(Serialize)]
struct DebugFilePreviewResponse {
    preview: redaction::DebugFilePreview,
}

#[derive(Serialize)]
struct DebugSharesResponse {
    service: String,
    shares: Vec<redaction::DebugShareLink>,
    attempts: Vec<crate::model::AuthAttemptDebug>,
}

#[derive(Serialize)]
struct DebugDropsResponse {
    service: String,
    drops: Vec<redaction::DebugDropLink>,
    attempts: Vec<crate::model::AuthAttemptDebug>,
}

#[derive(Serialize)]
struct DebugSyncChangesResponse {
    service: String,
    changes: Vec<redaction::DebugSyncChange>,
}

#[derive(Serialize)]
struct BackgroundJobsResponse {
    jobs: Vec<BackgroundJob>,
    totals: BackgroundJobTotals,
}

#[derive(Serialize)]
struct DebugDownloadsResponse {
    service: &'static str,
    single_files: crate::download_tickets::FileDownloadTicketHealth,
    archives: crate::streaming_zip::ArchiveTicketHealth,
}

#[derive(Deserialize)]
struct DebugSearchQuery {
    q: Option<String>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .merge(activity::router())
        .merge(agent_access::router())
        .merge(app_tokens::router())
        .merge(browse::router())
        .merge(capabilities::router())
        .merge(e2e::router())
        .merge(export::router())
        .merge(file_access::router())
        .merge(imports::router())
        .merge(storage_integrity::router())
        .merge(sync_conflicts::router())
        .merge(webdav::router())
        .merge(workspaces::router())
        .route("/debug/state", get(debug_state))
        .route("/debug/receipts", get(debug_receipts))
        .route("/debug/comments", get(debug_comments))
        .route("/debug/folder-templates", get(debug_folder_templates))
        .route("/debug/file-tree", get(debug_file_tree))
        .route("/debug/jobs", get(debug_jobs))
        .route("/debug/jobs/run", post(debug_run_jobs))
        .route("/debug/previews/{file_id}", get(debug_file_preview))
        .route("/debug/downloads", get(debug_downloads))
        .route("/debug/search", get(debug_search))
        .route("/debug/email", get(debug_email))
        .route("/debug/email/run", post(debug_email_run))
        .route("/debug/sync", get(debug_sync))
        .route("/debug/sync/changes", get(debug_sync_changes))
        .route("/debug/delta-sync", get(debug_delta_sync))
        .route("/debug/mobile-sync", get(debug_mobile_sync))
        .route("/debug/notifications", get(debug_notifications))
        .route("/debug/office-sessions", get(debug_office_sessions))
        .route("/debug/uploads", get(debug_uploads))
        .route("/debug/groups", get(debug_groups))
        .route("/debug/invitations", get(debug_invitations))
        .route("/debug/shares", get(debug_shares))
        .route("/debug/drops", get(debug_drops))
        .route("/debug/drops/{drop_id}", get(debug_drop_upload_health))
        .route("/debug/usage", get(debug_usage))
        .route("/debug/policies", get(debug_policies))
        .route("/debug/registration", get(debug_registration))
        .route("/debug/hosted", get(debug_hosted))
        .route("/debug/backups", get(debug_backups))
        .route("/debug/support-bundle", get(debug_support_bundle))
        .route("/debug/sandboxes", get(debug_sandboxes))
        .route("/debug/maintenance", get(debug_maintenance))
}

async fn debug_state(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<DebugState>> {
    require_admin(&state, &headers)?;
    Ok(Json(DebugState {
        service: "shellx-drive".to_string(),
        data_dir: REDACTED_DATA_DIR.to_string(),
        e2e_enabled: state.config.e2e_enabled,
    }))
}

async fn debug_receipts(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<ReceiptsResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(ReceiptsResponse {
        receipts: redaction::receipts(
            state.storage.list_recent_receipts(1_000)?,
            &state.config.token,
        ),
    }))
}

async fn debug_comments(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<CommentsResponse>> {
    require_admin(&state, &headers)?;
    let (total_threads, total_replies, comments) = state
        .storage
        .list_debug_comments_bounded(200, 1024 * 1024)?;
    let returned_replies: usize = comments.iter().map(|comment| comment.replies.len()).sum();
    Ok(Json(CommentsResponse {
        truncated: comments.len() < total_threads || returned_replies < total_replies,
        comments,
        total_threads,
        total_replies,
    }))
}

async fn debug_folder_templates(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<FolderTemplatesResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(FolderTemplatesResponse {
        templates: redaction::folder_templates(
            state.storage.list_all_folder_templates()?,
            &state.config.token,
        ),
    }))
}

async fn debug_file_tree(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<DebugFileTreeResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(DebugFileTreeResponse {
        service: "shellx-drive".to_string(),
        trees: state.storage.all_file_trees()?,
    }))
}

async fn debug_jobs(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<BackgroundJobsResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(BackgroundJobsResponse {
        jobs: state.storage.list_background_jobs()?,
        totals: state.storage.background_job_totals()?,
    }))
}

async fn debug_run_jobs(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<BackgroundJobRunResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(
        state
            .storage
            .run_queued_background_jobs(&state.data_dir())?,
    ))
}

async fn debug_file_preview(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(file_id): Path<String>,
) -> ApiResult<Json<DebugFilePreviewResponse>> {
    require_admin(&state, &headers)?;
    let preview = state
        .storage
        .get_file_preview(&file_id)?
        .ok_or(ApiError::NotFound)?;
    Ok(Json(DebugFilePreviewResponse {
        preview: redaction::preview(preview),
    }))
}

async fn debug_downloads(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<DebugDownloadsResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(DebugDownloadsResponse {
        service: "shellx-drive",
        single_files: state.file_download_tickets.health(),
        archives: state.archive_tickets.health(),
    }))
}

async fn debug_search(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<DebugSearchQuery>,
) -> ApiResult<Json<DebugSearchResponse>> {
    let actor = require_admin(&state, &headers)?;
    let query = query.q.unwrap_or_default();
    let _planning = state.try_metadata_planning(&format!("debug-search:{}", actor.email))?;
    Ok(Json(DebugSearchResponse {
        service: "shellx-drive".to_string(),
        query: query.clone(),
        using_fts: true,
        query_plan: state.storage.search_query_plan(&query)?,
        results: state.storage.search_file_results(&query)?,
    }))
}

async fn debug_email(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<redaction::DebugEmailResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(email_debug_response(&state)?))
}

async fn debug_email_run(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<redaction::DebugEmailResponse>> {
    let (actor, source_credential) = require_admin_with_credential(&state, &headers)?;
    if state.config.email_transport == "capture" {
        state
            .storage
            .run_email_outbox_capture_authorized(&actor, &source_credential)?;
    }
    Ok(Json(email_debug_response(&state)?))
}

async fn debug_sync(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<DebugSyncResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(DebugSyncResponse {
        service: "shellx-drive".to_string(),
        sync: state
            .storage
            .sync_health_for_workspaces(state.storage.list_workspaces()?, None)?,
        job_totals: state.storage.background_job_totals()?,
    }))
}

async fn debug_sync_changes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<DebugSyncChangesResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(DebugSyncChangesResponse {
        service: "shellx-drive".to_string(),
        changes: redaction::sync_changes(
            state.storage.list_all_sync_changes()?,
            &state.config.token,
        ),
    }))
}

async fn debug_uploads(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<DebugUploadsResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(DebugUploadsResponse {
        service: "shellx-drive".to_string(),
        sessions: state.storage.list_upload_sessions()?,
    }))
}

async fn debug_delta_sync(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<DebugDeltaSyncResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(DebugDeltaSyncResponse {
        service: "shellx-drive".to_string(),
        writes: state.storage.list_delta_sync_writes()?,
    }))
}

async fn debug_mobile_sync(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<DebugMobileSyncResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(DebugMobileSyncResponse {
        service: "shellx-drive".to_string(),
        mode: "mobile_metadata".to_string(),
        offline_files: state.storage.list_mobile_offline_files()?,
    }))
}

async fn debug_notifications(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<redaction::DebugNotificationsResponse>> {
    require_admin(&state, &headers)?;
    let notifications = state.storage.list_notifications()?;
    let unread_count = notifications
        .iter()
        .filter(|notification| notification.read_at.is_none())
        .count() as i64;
    Ok(Json(redaction::DebugNotificationsResponse {
        service: "shellx-drive".to_string(),
        unread_count,
        notifications: redaction::notifications(notifications, &state.config.token),
    }))
}

async fn debug_office_sessions(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<DebugOfficeSessionsResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(DebugOfficeSessionsResponse {
        service: "shellx-drive".to_string(),
        sessions: state.storage.list_debug_office_sessions_redacted()?,
    }))
}

async fn debug_groups(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<DebugGroupsResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(DebugGroupsResponse {
        service: "shellx-drive".to_string(),
        groups: state.storage.list_groups()?,
        members: state.storage.list_all_group_members()?,
        workspace_grants: state.storage.list_all_workspace_group_grants()?,
        effective_permissions: state.storage.list_effective_workspace_permissions()?,
    }))
}

async fn debug_invitations(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<DebugInvitationsResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(DebugInvitationsResponse {
        service: "shellx-drive".to_string(),
        invitations: state.storage.list_all_workspace_invitations()?,
    }))
}

fn redacted_shares(state: &AppState) -> ApiResult<Vec<redaction::DebugShareLink>> {
    Ok(redaction::shares(
        state.storage.list_all_shares()?,
        &state.config.token,
    ))
}

async fn debug_shares(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<DebugSharesResponse>> {
    require_admin(&state, &headers)?;
    let attempts = redaction::auth_attempts(
        state
            .storage
            .list_auth_attempts_bounded(1_000)?
            .into_iter()
            .filter(|attempt| attempt.scope.starts_with("share_password"))
            .collect(),
        &state.config.token,
    );
    Ok(Json(DebugSharesResponse {
        service: "shellx-drive".to_string(),
        shares: redacted_shares(&state)?,
        attempts,
    }))
}

async fn debug_drops(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<DebugDropsResponse>> {
    require_admin(&state, &headers)?;
    let attempts = redaction::auth_attempts(
        state
            .storage
            .list_auth_attempts_bounded(1_000)?
            .into_iter()
            .filter(|attempt| attempt.scope.starts_with("drop_password"))
            .collect(),
        &state.config.token,
    );
    Ok(Json(DebugDropsResponse {
        service: "shellx-drive".to_string(),
        drops: redaction::drops(
            state.storage.list_all_drops_bounded(1_000)?,
            &state.config.token,
        ),
        attempts,
    }))
}

async fn debug_drop_upload_health(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(drop_id): Path<String>,
) -> ApiResult<Json<DebugDropUploadHealthResponse>> {
    require_admin(&state, &headers)?;
    let totals = state.storage.drop_upload_totals(&drop_id)?;
    let sessions = state.storage.list_drop_upload_sessions(&drop_id)?;
    let listed_sessions = sessions.len() as i64;
    let sessions = sessions
        .into_iter()
        .map(|session| DebugDropUploadSession {
            session_ref: format!("drop-upload-{}", &token_hash(&session.id)[..12]),
            status: session.status,
            total_size: session.total_size,
            received_bytes: session.received_bytes,
            chunk_count: session.chunk_count,
            has_file: session.file_id.is_some(),
            last_error_code: session.last_error_code,
            created_at: session.created_at,
            updated_at: session.updated_at,
            completed_at: session.completed_at,
            canceled_at: session.canceled_at,
        })
        .collect();
    Ok(Json(DebugDropUploadHealthResponse {
        service: "shellx-drive".to_string(),
        drop_ref: redaction::drop_ref(&drop_id, &state.config.token),
        total_sessions: totals.total,
        listed_sessions,
        sessions_truncated: totals.total > listed_sessions,
        active_sessions: totals.active,
        completed_sessions: totals.completed,
        canceled_sessions: totals.canceled,
        failed_sessions: totals.failed,
        active_received_bytes: totals.active_received_bytes,
        sessions,
    }))
}

async fn debug_usage(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<DebugUsageResponse>> {
    let actor = require_admin(&state, &headers)?;
    Ok(Json(DebugUsageResponse {
        service: "shellx-drive".to_string(),
        usage: state.run_workspace_usage_list(&actor.email).await?,
    }))
}

async fn debug_policies(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<DebugPoliciesResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(DebugPoliciesResponse {
        service: "shellx-drive".to_string(),
        policies: state.storage.list_workspace_policies()?,
    }))
}

async fn debug_registration(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<DebugRegistrationResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(registration_debug_response(&state)?))
}

async fn debug_hosted(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<DebugHostedResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(debug_hosted_response(&state)?))
}

async fn debug_backups(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<DebugBackupsResponse>> {
    require_admin(&state, &headers)?;
    let catalog_state = state.clone();
    let backups = state
        .run_backup_work(move || list_backup_metadata(&catalog_state))
        .await??;
    Ok(Json(DebugBackupsResponse {
        service: "shellx-drive".to_string(),
        backups,
    }))
}

async fn debug_support_bundle(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<DebugSupportBundleResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(DebugSupportBundleResponse {
        service: "shellx-drive".to_string(),
        support_bundles: state.storage.list_support_bundles()?,
    }))
}

async fn debug_sandboxes(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<DebugSandboxesResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(DebugSandboxesResponse {
        service: "shellx-drive".to_string(),
        sandboxes: vec![preview_for_profile(
            state.storage.get_sandbox_profile()?,
            state.config.public_origin.as_str(),
        )?],
    }))
}

async fn debug_maintenance(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<DebugMaintenanceResponse>> {
    require_admin(&state, &headers)?;
    Ok(Json(DebugMaintenanceResponse {
        service: "shellx-drive".to_string(),
        maintenance: current_maintenance_status(&state.config),
    }))
}

pub(crate) use export::support_debug_export;

pub(crate) fn email_debug_response(state: &AppState) -> ApiResult<redaction::DebugEmailResponse> {
    Ok(redaction::DebugEmailResponse {
        service: "shellx-drive".to_string(),
        transport: state.config.email_transport.clone(),
        from: state.config.email_from.clone(),
        base_url: state.config.public_origin.as_str().to_string(),
        smtp_host_source: state.config.email_smtp_host_source.clone(),
        smtp_port: state.config.email_smtp_port,
        smtp_user_source: state.config.email_smtp_user_source.clone(),
        emails: redaction::emails(
            state.storage.list_email_outbox_redacted()?,
            &state.config.token,
        ),
    })
}

fn registration_debug_response(state: &AppState) -> ApiResult<DebugRegistrationResponse> {
    Ok(DebugRegistrationResponse {
        service: "shellx-drive".to_string(),
        enabled: state.storage.registration_enabled()?,
        accounts: state.storage.auth_account_count()?,
    })
}
