//! Linux polling and reconciliation command admission.

mod polling;
mod recovery;
mod restore;
mod review_execution;
pub(crate) mod reviews;

use polling::effective_poll_interval;
pub(crate) use polling::start_polling;
pub(super) use polling::stop_polling;
use recovery::*;
use review_execution::*;

use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};

use chrono::Utc;
use shellx_drive_desktop_core::{
    ensure_private_staging_directory, ensure_tree_has_no_links, inspect_local_tree,
    map_remote_paths, resolve_review_decision, restored_remote_response_matches,
    review_confirmation_fingerprint, reviewed_local_subtree_matches_baseline,
    reviewed_remote_subtree_matches_baseline, sync_pair_id, trashed_remote_response_matches,
    ActivityEntry, DesktopError, Result as CoreResult, ReviewDecision, ReviewItem, SyncPair,
};
use tauri::{AppHandle, Manager, State};

use crate::application::{
    connections::ConnectionManager,
    invalidate_pending_confirmation,
    sync_terminal::failure::{persist_terminal_failure, TerminalFailure},
    DesktopView, Runtime,
};

use super::{
    reconcile, roots,
    shell::{notify_actionable, update_tray},
};
use all_roots::reconcile_all_roots;

mod all_roots;

#[tauri::command]
pub(super) async fn sync_now(
    app: AppHandle,
    manager: State<'_, ConnectionManager>,
    connection_id: Option<String>,
) -> Result<DesktopView, String> {
    manager.ensure_mutation_allowed().map_err(present_error)?;
    let runtime = manager
        .resolve(connection_id.as_deref())
        .map_err(present_error)?;
    sync_or_recheck(&app, &runtime, false).await
}

#[tauri::command]
pub(super) async fn recheck_reviews(
    app: AppHandle,
    manager: State<'_, ConnectionManager>,
    connection_id: Option<String>,
) -> Result<DesktopView, String> {
    let runtime = manager
        .resolve(connection_id.as_deref())
        .map_err(present_error)?;
    sync_or_recheck(&app, &runtime, true).await
}

#[tauri::command]
pub(super) async fn set_paused(
    app: AppHandle,
    manager: State<'_, ConnectionManager>,
    connection_id: Option<String>,
    paused: bool,
) -> Result<DesktopView, String> {
    manager.ensure_mutation_allowed().map_err(present_error)?;
    let runtime = manager
        .resolve(connection_id.as_deref())
        .map_err(present_error)?;
    crate::application::lifecycle::persist_paused_state(&runtime, paused)
        .await
        .map_err(|error| error.to_string())?;
    super::shell::update_tray(&app, &runtime);
    Ok(runtime.view())
}

pub(crate) async fn sync_or_recheck(
    app: &AppHandle,
    runtime: &Runtime,
    recheck: bool,
) -> Result<DesktopView, String> {
    sync_with_schedule(app, runtime, recheck, false).await
}

async fn sync_with_schedule(
    app: &AppHandle,
    runtime: &Runtime,
    recheck: bool,
    scheduled: bool,
) -> Result<DesktopView, String> {
    let result = run_sync_or_recheck(app, runtime, recheck, scheduled).await;
    runtime.mark_sync_check_finished();
    result
}

async fn run_sync_or_recheck(
    app: &AppHandle,
    runtime: &Runtime,
    recheck: bool,
    scheduled: bool,
) -> Result<DesktopView, String> {
    runtime
        .require_candidate_recovery_complete()
        .map_err(present_error)?;
    runtime
        .ensure_disconnect_cleanup_complete()
        .map_err(present_error)?;
    let manager = app.state::<ConnectionManager>();
    let id = manager
        .id_for_runtime(runtime)
        .ok_or_else(|| "Drive connection is no longer registered.".to_string())?;
    {
        let _admission = manager.admission.lock().await;
        let state = runtime.coordinator.snapshot();
        if let Some(base) = state.sync_root_base.as_ref() {
            manager
                .validate_existing_connection_folder(&id, base)
                .map_err(present_error)?;
        }
        for pair in state.pairs() {
            manager
                .validate_existing_connection_folder(&id, &pair.local_root)
                .map_err(present_error)?;
        }
    }
    let _permit = manager
        .acquire_sync_permit_for(runtime)
        .await
        .map_err(present_error)?;
    if scheduled
        && !runtime
            .sync_check_delay(effective_poll_interval(&manager, runtime))
            .is_zero()
    {
        return Ok(runtime.view());
    }
    // A connection may have been removed or offboarded while queued fairly.
    runtime
        .require_candidate_recovery_complete()
        .and_then(|()| runtime.ensure_disconnect_cleanup_complete())
        .map_err(present_error)?;
    if !recheck {
        invalidate_pending_confirmation(runtime);
    }
    if let Err(error) = roots::refresh_authorized_roots(runtime).await {
        if matches!(error, DesktopError::SyncAlreadyRunning) {
            return Err(present_error(error));
        }
        return settle(app, runtime, Err(error));
    }
    let mut run = runtime.coordinator.begin_run().map_err(present_error)?;
    if recheck && !run.has_any_reviews() {
        return Err("There is no pending review to recheck.".to_string());
    }
    runtime.require_pair_credential().map_err(present_error)?;
    update_tray(app, runtime);
    let result = reconcile_all_roots(runtime, &mut run, recheck).await;
    settle(app, runtime, result)
}

fn settle(
    app: &AppHandle,
    runtime: &Runtime,
    result: CoreResult<()>,
) -> Result<DesktopView, String> {
    runtime.local_usage_cache.invalidate();
    if let Err(error) = result {
        match persist_terminal_failure(runtime, error).map_err(present_error)? {
            TerminalFailure::Admission(DesktopError::NeedsReconnect) => {
                update_tray(app, runtime);
                return Ok(runtime.view());
            }
            TerminalFailure::Admission(error) => return Err(present_error(error)),
            TerminalFailure::Offline => {
                update_tray(app, runtime);
                return Ok(runtime.view());
            }
            TerminalFailure::Persistent(error) => {
                update_tray(app, runtime);
                notify_actionable(app, runtime, true);
                return Err(present_error(error));
            }
        }
    }
    runtime.save().map_err(present_error)?;
    update_tray(app, runtime);
    notify_actionable(app, runtime, true);
    Ok(runtime.view())
}

pub(super) fn present_error(error: DesktopError) -> String {
    error.to_string()
}
