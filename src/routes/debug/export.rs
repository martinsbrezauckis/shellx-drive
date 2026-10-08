mod bounds;

use axum::{
    extract::{Query, State},
    http::HeaderMap,
    routing::get,
    Json, Router,
};
use serde_json::{json, Map, Value};

use bounds::{
    bound_value, build_envelope, checked_limits, enforce_byte_limit, recursive_item_count,
    ExportLimits, ExportQuery, SectionStats,
};

use super::{
    browse, email_debug_response, redacted_shares, redaction, registration_debug_response, webdav,
};
use crate::{
    auth::require_admin_with_credential,
    error::{ApiError, ApiResult},
    routes::{
        admin::readiness_for_state, backups::list_backup_metadata, hosted::debug_hosted_response,
        maintenance::current_maintenance_status, sandboxes::preview_for_profile,
    },
    server::AppState,
};

pub(super) fn router() -> Router<AppState> {
    Router::new().route("/debug/export", get(debug_export))
}

async fn debug_export(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ExportQuery>,
) -> ApiResult<Json<Value>> {
    let (actor, source_credential) = require_admin_with_credential(&state, &headers)?;
    let limits = checked_limits(query)?;
    let _backup_work = limits
        .section
        .as_deref()
        .is_none_or(|section| section == "backups")
        .then(|| state.try_backup_work())
        .transpose()?;
    let export_state = state.clone();
    let export = state
        .run_metadata_planning(&actor.email, move || {
            build_debug_export(&export_state, limits)
        })
        .await?;
    state
        .storage
        .ensure_admin_publication_authorized(&actor, &source_credential)?;
    Ok(Json(export))
}

/// Support artifacts use a strict operational allowlist. The full Debug API is
/// intentionally richer and may contain user-authored names, comments, and
/// paths, so it must never be relabeled as safe to send to an external helper.
pub(crate) fn support_debug_export(state: &AppState) -> ApiResult<Value> {
    let readiness = readiness_for_state(state);
    Ok(json!({
        "service": "shellx-drive",
        "schema_version": 1,
        "redaction": "strict-operational-allowlist",
        "e2e_enabled": state.config.e2e_enabled,
        "totals": state.storage.admin_totals()?,
        "background_job_totals": state.storage.background_job_totals()?,
        "backup_policy": state.storage.get_backup_policy()?,
        "readiness": {
            "live": readiness.live,
            "ready": readiness.ready,
            "state": readiness.state,
            "checks": readiness.checks.into_iter().map(|check| json!({
                "name": check.name,
                "status": check.status,
                "critical": check.critical,
            })).collect::<Vec<_>>(),
        },
        "downloads": {
            "single_files": state.file_download_tickets.health(),
            "archives": state.archive_tickets.health(),
        },
    }))
}

const DEBUG_EXPORT_SECTIONS: &[&str] = &[
    "receipts",
    "comments",
    "folder_templates",
    "file_trees",
    "file_metadata",
    "file_revisions",
    "upload_sessions",
    "sync_changes",
    "delta_sync",
    "background_jobs",
    "background_job_totals",
    "browse",
    "email",
    "file_previews",
    "mobile_offline_files",
    "notifications",
    "office_sessions",
    "groups",
    "group_members",
    "workspace_group_grants",
    "workspace_invitations",
    "shares",
    "drops",
    "effective_workspace_permissions",
    "workspace_usage",
    "workspace_policies",
    "registration",
    "hosted",
    "sessions",
    "backups",
    "backup_policy",
    "support_bundles",
    "readiness",
    "maintenance_history",
    "sandboxes",
    "maintenance",
    "activity",
    "workspaces",
    "app_tokens",
    "sync_conflicts",
    "imports",
    "webdav",
    "downloads",
    "storage_integrity",
    "capabilities",
    "auth",
];

fn build_debug_export(state: &AppState, limits: ExportLimits) -> ApiResult<Value> {
    if let Some(section) = limits.section.as_deref() {
        if !DEBUG_EXPORT_SECTIONS.contains(&section) {
            return Err(ApiError::Validation(format!(
                "unknown debug export section: {section}"
            )));
        }
    }
    let known = DEBUG_EXPORT_SECTIONS
        .iter()
        .map(|section| (*section).to_string())
        .collect::<Vec<_>>();
    let mut catalog = Map::new();
    let mut bounded_sections = Map::new();
    for name in DEBUG_EXPORT_SECTIONS.iter().copied().filter(|name| {
        limits
            .section
            .as_deref()
            .is_none_or(|selected| selected == *name)
    }) {
        let (value, explicit_total) = load_debug_export_section(state, &limits, name)?;
        let total_items = explicit_total.unwrap_or_else(|| recursive_item_count(&value));
        let bounded = bound_value(value, &limits);
        let returned_items = if name == "comments" {
            bounded
                .as_array()
                .map(|comments| {
                    comments.len()
                        + comments
                            .iter()
                            .map(|comment| comment["replies"].as_array().map_or(0, Vec::len))
                            .sum::<usize>()
                })
                .unwrap_or(0)
        } else {
            recursive_item_count(&bounded)
        };
        catalog.insert(
            name.to_string(),
            serde_json::to_value(SectionStats {
                total_items,
                returned_items,
                truncated: returned_items < total_items,
                omitted_for_byte_limit: false,
            })
            .expect("serializable export stats"),
        );
        bounded_sections.insert(name.to_string(), bounded);
    }

    let mut export = build_envelope(
        state.config.e2e_enabled,
        &limits,
        known,
        catalog,
        bounded_sections,
    );
    enforce_byte_limit(&mut export, limits.max_bytes);
    Ok(export)
}

fn load_debug_export_section(
    state: &AppState,
    limits: &ExportLimits,
    name: &str,
) -> ApiResult<(Value, Option<usize>)> {
    let value_and_total = match name {
        "receipts" => {
            let (total, rows) = state.storage.list_receipts_bounded(
                limits.limit,
                limits.before.as_deref(),
                limits.after.as_deref(),
                None,
            )?;
            (
                json!(redaction::receipts(rows, &state.config.token)),
                Some(total),
            )
        }
        "comments" => {
            let (total_threads, total_replies, comments) = state
                .storage
                .list_debug_comments_bounded(limits.limit, limits.max_bytes)?;
            (json!(comments), Some(total_threads + total_replies))
        }
        "folder_templates" => (
            json!(redaction::folder_templates(
                state.storage.list_all_folder_templates()?,
                &state.config.token,
            )),
            None,
        ),
        "file_trees" => (json!(state.storage.all_file_trees()?), None),
        "file_metadata" => (json!(state.storage.list_all_file_metadata()?), None),
        "file_revisions" => (json!(state.storage.list_all_file_revisions()?), None),
        "upload_sessions" => (json!(state.storage.list_upload_sessions()?), None),
        "sync_changes" => (
            json!(redaction::sync_changes(
                state.storage.list_all_sync_changes()?,
                &state.config.token,
            )),
            None,
        ),
        "delta_sync" => (json!(state.storage.list_delta_sync_writes()?), None),
        "background_jobs" => (json!(state.storage.list_background_jobs()?), None),
        "background_job_totals" => (json!(state.storage.background_job_totals()?), None),
        "browse" => (browse::debug_browse_value(state)?, None),
        "email" => (json!(email_debug_response(state)?), None),
        "file_previews" => (
            json!(redaction::previews(state.storage.list_file_previews()?)),
            None,
        ),
        "mobile_offline_files" => (json!(state.storage.list_mobile_offline_files()?), None),
        "notifications" => (
            json!(redaction::notifications(
                state.storage.list_notifications()?,
                &state.config.token,
            )),
            None,
        ),
        "office_sessions" => (
            json!(state.storage.list_debug_office_sessions_redacted()?),
            None,
        ),
        "groups" => (json!(state.storage.list_groups()?), None),
        "group_members" => (json!(state.storage.list_all_group_members()?), None),
        "workspace_group_grants" => (
            json!(state.storage.list_all_workspace_group_grants()?),
            None,
        ),
        "workspace_invitations" => (json!(state.storage.list_all_workspace_invitations()?), None),
        "shares" => (json!(redacted_shares(state)?), None),
        "drops" => (
            json!(redaction::drops(
                state.storage.list_all_drops_bounded(limits.limit)?,
                &state.config.token,
            )),
            None,
        ),
        "effective_workspace_permissions" => (
            json!(state.storage.list_effective_workspace_permissions()?),
            None,
        ),
        "workspace_usage" => (json!(state.storage.list_workspace_usage()?), None),
        "workspace_policies" => (json!(state.storage.list_workspace_policies()?), None),
        "registration" => (json!(registration_debug_response(state)?), None),
        "hosted" => (json!(debug_hosted_response(state)?), None),
        "sessions" => (
            json!(state.storage.list_auth_sessions_bounded(limits.limit)?),
            None,
        ),
        "backups" => (json!(list_backup_metadata(state)?), None),
        "backup_policy" => (json!(state.storage.get_backup_policy()?), None),
        "support_bundles" => (json!(state.storage.list_support_bundles()?), None),
        "readiness" => (json!(readiness_for_state(state)), None),
        "maintenance_history" => {
            let (total, rows) = state.storage.list_receipts_bounded(
                limits.limit,
                limits.before.as_deref(),
                limits.after.as_deref(),
                Some("maintenance."),
            )?;
            (
                json!(redaction::receipts(rows, &state.config.token)),
                Some(total),
            )
        }
        "sandboxes" => (
            json!([preview_for_profile(
                state.storage.get_sandbox_profile()?,
                state.config.public_origin.as_str(),
            )?]),
            None,
        ),
        "maintenance" => (json!(current_maintenance_status(&state.config)), None),
        "activity" => {
            let (total, rows) = state.storage.debug_activity_summaries(
                limits.limit as i64,
                limits.before.as_deref(),
                None,
            )?;
            (json!(rows), Some(total as usize))
        }
        "workspaces" => {
            let (total, rows) = state
                .storage
                .debug_workspace_summaries(limits.limit as i64)?;
            (json!(rows), Some(total as usize))
        }
        "app_tokens" => {
            let (total, rows) = state
                .storage
                .debug_app_token_summaries(limits.limit as i64)?;
            (json!(rows), Some(total as usize))
        }
        "sync_conflicts" => {
            let (total, rows) = state
                .storage
                .debug_sync_conflict_summaries(limits.limit as i64)?;
            (json!(rows), Some(total as usize))
        }
        "imports" => {
            let (total, rows) = state.storage.debug_import_summaries(limits.limit as i64)?;
            (json!(rows), Some(total as usize))
        }
        "webdav" => (webdav::debug_webdav_value(state)?, None),
        "downloads" => (
            json!({
                "single_files": state.file_download_tickets.health(),
                "archives": state.archive_tickets.health(),
            }),
            None,
        ),
        "storage_integrity" => (
            json!({"mode": "on_demand_read_only", "endpoint": "/debug/storage-integrity"}),
            None,
        ),
        "capabilities" => (
            json!({"endpoint": "/debug/capabilities", "workspace_context_supported": true}),
            None,
        ),
        "auth" => (
            json!({
                "accounts": state.storage.list_auth_accounts()?,
                "sessions": state.storage.list_auth_sessions_bounded(limits.limit)?,
                "attempts": redaction::auth_attempts(
                    state.storage.list_auth_attempts_bounded(limits.limit)?,
                    &state.config.token,
                ),
            }),
            None,
        ),
        _ => {
            return Err(ApiError::Validation(format!(
                "unknown debug export section: {name}"
            )))
        }
    };
    Ok(value_and_total)
}
