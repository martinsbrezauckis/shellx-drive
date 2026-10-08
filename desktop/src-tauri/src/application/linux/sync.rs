//! Linux polling and reconciliation command admission.

mod recovery;
mod restore;
mod review_execution;
pub(crate) mod reviews;

use recovery::*;
use review_execution::*;

use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::{sync::atomic::Ordering, time::Duration};

use chrono::Utc;
use shellx_drive_desktop_core::{
    ensure_private_staging_directory, ensure_tree_has_no_links, inspect_local_tree,
    map_remote_paths, resolve_review_decision, restored_remote_response_matches,
    review_confirmation_fingerprint, reviewed_local_subtree_matches_baseline,
    reviewed_remote_subtree_matches_baseline, sync_pair_id, trashed_remote_response_matches,
    ActivityEntry, DesktopError, Result as CoreResult, ReviewDecision, ReviewItem, SyncPair,
    SyncStatus,
};
use tauri::{AppHandle, Manager, State};

use crate::application::{
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

const POLL_INTERVAL: Duration = Duration::from_secs(20);
const OFFLINE_BACKOFF: Duration = Duration::from_secs(60);

#[tauri::command]
pub(super) async fn sync_now(
    app: AppHandle,
    runtime: State<'_, Runtime>,
) -> Result<DesktopView, String> {
    sync_or_recheck(&app, &runtime, false).await
}

#[tauri::command]
pub(super) async fn recheck_reviews(
    app: AppHandle,
    runtime: State<'_, Runtime>,
) -> Result<DesktopView, String> {
    sync_or_recheck(&app, &runtime, true).await
}

#[tauri::command]
pub(super) async fn set_paused(
    app: AppHandle,
    runtime: State<'_, Runtime>,
    paused: bool,
) -> Result<DesktopView, String> {
    crate::application::lifecycle::persist_paused_state(&runtime, paused)
        .await
        .map_err(|error| error.to_string())?;
    super::shell::update_tray(&app, &runtime);
    Ok(runtime.view())
}

pub(super) fn start_polling(app: &AppHandle, runtime: &Runtime) {
    if runtime
        .coordinator
        .snapshot()
        .has_pending_disconnect_cleanup()
        || runtime.polling_enabled.swap(true, Ordering::AcqRel)
    {
        return;
    }
    let generation = runtime.poll_generation.fetch_add(1, Ordering::AcqRel) + 1;
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            let runtime = app.state::<Runtime>();
            let delay = if runtime.status() == SyncStatus::Offline {
                OFFLINE_BACKOFF
            } else {
                POLL_INTERVAL
            };
            tokio::time::sleep(delay).await;
            if !runtime.polling_enabled.load(Ordering::Acquire)
                || runtime.poll_generation.load(Ordering::Acquire) != generation
            {
                break;
            }
            if matches!(
                runtime.status(),
                SyncStatus::NeedsSetup
                    | SyncStatus::NeedsReconnect
                    | SyncStatus::Syncing
                    | SyncStatus::Paused
            ) {
                continue;
            }
            if let Err(error) = sync_or_recheck(&app, &runtime, false).await {
                eprintln!("ShellX Drive Linux automatic poll did not complete: {error}");
            }
        }
    });
}

pub(super) fn stop_polling(runtime: &Runtime) {
    runtime.polling_enabled.store(false, Ordering::Release);
    runtime.poll_generation.fetch_add(1, Ordering::AcqRel);
}

pub(crate) async fn sync_or_recheck(
    app: &AppHandle,
    runtime: &Runtime,
    recheck: bool,
) -> Result<DesktopView, String> {
    runtime
        .require_candidate_recovery_complete()
        .map_err(present_error)?;
    runtime
        .ensure_disconnect_cleanup_complete()
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
