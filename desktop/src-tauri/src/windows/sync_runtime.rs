//! Serialized scoped-root reconciliation and polling.
//!
//! The legacy workspace manifest intentionally does not appear here: every
//! desktop pass obtains the server's current authority for the active opaque
//! root before inspecting or changing the corresponding local tree.

#[path = "sync_runtime/authority.rs"]
mod authority;

use super::*;
use authority::{
    finish_baseline, finish_stopped_root, root_access_was_removed, scoped_manifest_for_active_run,
};

use crate::application::sync_terminal::{
    failure::{persist_terminal_failure, TerminalFailure},
    session::{admit_persisted_all_roots, is_user_session_unauthorized},
    SyncCycleTerminal,
};
use crate::session_identity::SessionIdentity;
use root_sync::refresh_authorized_roots;
use shellx_drive_desktop_core::apply_sync_root_policy;

/// A conservative state poller replaces a fragile filesystem watcher. It
/// invokes exactly the same scoped-root paths as the manual commands.
pub(super) fn start_polling(app: &tauri::AppHandle, runtime: &Runtime) {
    let manager = app.state::<ConnectionManager>();
    let Some(runtime) = manager
        .all_runtimes()
        .into_iter()
        .find(|candidate| std::ptr::eq(candidate.as_ref(), runtime))
    else {
        return;
    };
    if !manager.may_sync(&runtime) {
        return;
    }
    if runtime
        .coordinator
        .snapshot()
        .has_pending_disconnect_cleanup()
    {
        return;
    }
    if runtime.polling_enabled.swap(true, Ordering::AcqRel) {
        return;
    }
    let generation = runtime.poll_generation.fetch_add(1, Ordering::AcqRel) + 1;
    runtime.mark_sync_check_finished();
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            let manager = handle.state::<ConnectionManager>();
            let interval = manager.effective_interval(&runtime);
            let delay = if runtime.status() == SyncStatus::Offline {
                interval.max(OFFLINE_BACKOFF)
            } else {
                interval
            };
            tokio::time::sleep(runtime.sync_check_delay(delay).max(Duration::from_secs(1))).await;
            if !runtime.polling_enabled.load(Ordering::Acquire)
                || runtime.poll_generation.load(Ordering::Acquire) != generation
            {
                break;
            }
            let interval = manager.effective_interval(&runtime);
            let interval = if runtime.status() == SyncStatus::Offline {
                interval.max(OFFLINE_BACKOFF)
            } else {
                interval
            };
            if !runtime.sync_check_delay(interval).is_zero() || !manager.may_sync(&runtime) {
                continue;
            }
            match runtime.status() {
                SyncStatus::NeedsSetup
                | SyncStatus::NeedsReconnect
                | SyncStatus::Syncing
                | SyncStatus::Paused => continue,
                SyncStatus::Synced
                | SyncStatus::Offline
                | SyncStatus::NeedsReview
                | SyncStatus::Error => {}
            }
            let result = sync_now_pass(&handle, &runtime, Some(generation)).await;
            if runtime.poll_generation.load(Ordering::Acquire) == generation {
                runtime.mark_sync_check_finished();
            }
            if let Err(error) = result {
                eprintln!("ShellX Drive automatic poll did not complete: {error}");
            }
        }
    });
}

pub(super) fn stop_polling(runtime: &Runtime) {
    runtime.polling_enabled.store(false, Ordering::Release);
    runtime.poll_generation.fetch_add(1, Ordering::AcqRel);
}

#[tauri::command]
pub(super) async fn sync_now(
    app: tauri::AppHandle,
    manager: State<'_, ConnectionManager>,
    connection_id: Option<String>,
) -> Result<DesktopView, String> {
    let runtime = manager
        .resolve(connection_id.as_deref())
        .map_err(user_error)?;
    sync_now_impl(&app, &runtime).await
}

#[tauri::command]
pub(super) async fn recheck_reviews(
    app: tauri::AppHandle,
    manager: State<'_, ConnectionManager>,
    connection_id: Option<String>,
) -> Result<DesktopView, String> {
    let runtime = manager
        .resolve(connection_id.as_deref())
        .map_err(user_error)?;
    recheck_reviews_impl(&app, &runtime, true).await
}

pub(crate) async fn sync_now_impl(
    app: &tauri::AppHandle,
    runtime: &Runtime,
) -> Result<DesktopView, String> {
    let result = sync_now_pass(app, runtime, None).await;
    runtime.mark_sync_check_finished();
    result
}

async fn sync_now_pass(
    app: &tauri::AppHandle,
    runtime: &Runtime,
    poll_generation: Option<u64>,
) -> Result<DesktopView, String> {
    recheck_connection_folders(app, runtime)
        .await
        .map_err(user_error)?;
    runtime
        .require_candidate_recovery_complete()
        .map_err(user_error)?;
    runtime
        .ensure_disconnect_cleanup_complete()
        .map_err(user_error)?;
    let manager = app.state::<ConnectionManager>();
    let _permit = manager
        .acquire_sync_permit_for(runtime)
        .await
        .map_err(user_error)?;
    if poll_generation.is_some_and(|generation| {
        !runtime.polling_enabled.load(Ordering::Acquire)
            || runtime.poll_generation.load(Ordering::Acquire) != generation
    }) {
        return Err(
            "This automatic sync check was canceled by a newer connection operation.".to_string(),
        );
    }
    if poll_generation.is_some() {
        let interval = manager.effective_interval(runtime);
        let interval = if runtime.status() == SyncStatus::Offline {
            interval.max(OFFLINE_BACKOFF)
        } else {
            interval
        };
        // A manual check may have completed while this poll waited fairly.
        // Keep its new deadline instead of starting queued catch-up work.
        if !runtime.sync_check_delay(interval).is_zero() {
            return Ok(runtime.view());
        }
    }
    runtime
        .require_candidate_recovery_complete()
        .and_then(|()| runtime.ensure_disconnect_cleanup_complete())
        .map_err(user_error)?;
    invalidate_pending_confirmation(runtime);
    // Refresh discovery before reserving a reconciliation run. This is the
    // authority revocation boundary for startup, manual, and periodic sync.
    if let Err(error) = refresh_authorized_roots(runtime).await {
        if matches!(error, DesktopError::SyncAlreadyRunning) {
            return Err(user_error(error));
        }
        return settle_reconciliation_result(app, runtime, Err(error));
    }
    let mut run = runtime.coordinator.begin_run().map_err(user_error)?;
    runtime.require_pair_credential().map_err(user_error)?;
    update_tray(app, runtime);
    let result = reconcile_all_roots(runtime, &mut run, false).await;
    settle_reconciliation_result(app, runtime, result)
}

/// Recheck after a confirmed recovery. It deliberately plans only and never
/// transfers ordinary work while a review remains pending.
pub(crate) async fn recheck_reviews_impl(
    app: &tauri::AppHandle,
    runtime: &Runtime,
    invalidate_confirmation: bool,
) -> Result<DesktopView, String> {
    let result = recheck_reviews_pass(app, runtime, invalidate_confirmation).await;
    runtime.mark_sync_check_finished();
    result
}

async fn recheck_reviews_pass(
    app: &tauri::AppHandle,
    runtime: &Runtime,
    invalidate_confirmation: bool,
) -> Result<DesktopView, String> {
    recheck_connection_folders(app, runtime)
        .await
        .map_err(user_error)?;
    runtime
        .require_candidate_recovery_complete()
        .map_err(user_error)?;
    runtime
        .ensure_disconnect_cleanup_complete()
        .map_err(user_error)?;
    let manager = app.state::<ConnectionManager>();
    let _permit = manager
        .acquire_sync_permit_for(runtime)
        .await
        .map_err(user_error)?;
    runtime
        .require_candidate_recovery_complete()
        .and_then(|()| runtime.ensure_disconnect_cleanup_complete())
        .map_err(user_error)?;
    if invalidate_confirmation {
        invalidate_pending_confirmation(runtime);
    }
    if let Err(error) = refresh_authorized_roots(runtime).await {
        if matches!(error, DesktopError::SyncAlreadyRunning) {
            return Err(user_error(error));
        }
        return settle_reconciliation_result(app, runtime, Err(error));
    }
    let run = runtime.coordinator.begin_run().map_err(user_error)?;
    recheck_reviews_with_run(app, runtime, run).await
}

pub(super) async fn recheck_connection_folders(
    app: &tauri::AppHandle,
    runtime: &Runtime,
) -> CoreResult<()> {
    let manager = app.state::<ConnectionManager>();
    let id = manager
        .id_for_runtime(runtime)
        .ok_or_else(|| DesktopError::InvalidState("unknown server connection".to_string()))?;
    let _admission = manager.admission.lock().await;
    let state = runtime.coordinator.snapshot();
    if let Some(base) = state.sync_root_base.as_ref() {
        manager.validate_existing_connection_folder(&id, base)?;
    }
    for pair in state.pairs() {
        manager.validate_existing_connection_folder(&id, &pair.local_root)?;
    }
    Ok(())
}

pub(super) async fn recheck_reviews_with_run(
    app: &tauri::AppHandle,
    runtime: &Runtime,
    run: SyncRun,
) -> Result<DesktopView, String> {
    let mut cycle_budget = SyncCycleBudget::new(SyncPassLimits::default());
    recheck_reviews_with_budget(app, runtime, run, &mut cycle_budget).await
}

pub(super) async fn recheck_reviews_with_budget(
    app: &tauri::AppHandle,
    runtime: &Runtime,
    mut run: SyncRun,
    cycle_budget: &mut SyncCycleBudget,
) -> Result<DesktopView, String> {
    if !run.has_any_reviews() {
        return Err("There is no pending review to recheck.".to_string());
    }
    runtime.require_pair_credential().map_err(user_error)?;
    update_tray(app, runtime);
    let result = reconcile_all_roots_with_budget(runtime, &mut run, true, cycle_budget).await;
    settle_reconciliation_result(app, runtime, result)
}

/// Reconcile every materialized root for the one signed-in server/account.
/// The UI's selected location is only a display choice: each temporary profile
/// activation happens inside this already-reserved run and is restored before
/// the complete state is published.
async fn reconcile_all_roots(
    runtime: &Runtime,
    run: &mut SyncRun,
    recheck_only: bool,
) -> CoreResult<()> {
    let mut cycle_budget = SyncCycleBudget::new(SyncPassLimits::default());
    reconcile_all_roots_with_budget(runtime, run, recheck_only, &mut cycle_budget).await
}

async fn reconcile_all_roots_with_budget(
    runtime: &Runtime,
    run: &mut SyncRun,
    recheck_only: bool,
    cycle_budget: &mut SyncCycleBudget,
) -> CoreResult<()> {
    let session = runtime.current_session()?;
    let captured_bearer = runtime.current_token(&session)?;
    shellx_drive_desktop_core::with_cycle_read_budget(
        shellx_drive_desktop_core::sync_cycle_local_read_limit(),
        reconcile_all_roots_with_captured_session(
            runtime,
            run,
            recheck_only,
            &session,
            &captured_bearer,
            cycle_budget,
        ),
    )
    .await
}

async fn reconcile_all_roots_with_captured_session(
    runtime: &Runtime,
    run: &mut SyncRun,
    recheck_only: bool,
    session: &SessionIdentity,
    captured_bearer: &str,
    cycle_budget: &mut SyncCycleBudget,
) -> CoreResult<()> {
    let selected_pair_id = run.selected_pair_id()?;
    let mut terminal = SyncCycleTerminal::default();
    let mut local_read_budget =
        ReadBudget::new_cycle(shellx_drive_desktop_core::sync_cycle_local_read_limit());
    run.ensure_not_cancelled()?;
    for pair_id in run.cycle_pair_ids()? {
        run.ensure_not_cancelled()?;
        run.activate_configured_pair(&pair_id)?;
        if (recheck_only && !run.has_active_reviews())
            || (!recheck_only && run.has_active_reviews())
        {
            continue;
        }
        let pair = run.state().pair.clone().ok_or(DesktopError::NeedsSetup)?;
        match reconcile_scoped_root(
            run,
            recheck_only,
            session,
            captured_bearer,
            cycle_budget,
            &mut local_read_budget,
        )
        .await
        {
            Ok(()) => (),
            Err(DesktopError::SyncCancelledForDisconnect) => {
                return Err(DesktopError::SyncCancelledForDisconnect);
            }
            Err(error) if is_user_session_unauthorized(&error) => {
                return admit_persisted_all_roots(
                    runtime,
                    run,
                    &selected_pair_id,
                    session,
                    captured_bearer,
                    error,
                )
                .await;
            }
            Err(error) if root_access_was_removed(&error) => {
                run.mark_active_root_removed(
                    shellx_drive_desktop_core::SyncRootAccessRemovalReason::RevokedOrRemoved,
                    Utc::now(),
                )?;
                finish_stopped_root(run, &pair);
                run.append_active_activity(ActivityEntry {
                    at: Utc::now(),
                    direction: "Drive".to_string(),
                    relative_path: PathBuf::new(),
                    result:
                        "Access was removed during this sync; local files were retained for review."
                            .to_string(),
                });
            }
            Err(error @ DesktopError::SyncCycleBudgetExceeded(_)) => {
                terminal.record_budget_exhaustion(run, error);
                run.defer_cycle_after(&pair_id)?;
                break;
            }
            Err(error) => {
                terminal.record_root_failure(run, error);
            }
        }
        run.ensure_not_cancelled()?;
    }
    run.ensure_not_cancelled()?;
    let final_state = run.finalize_all_roots_state(&selected_pair_id)?;
    let result = terminal.finish(&final_state);
    run.finish_persisted_state(final_state, |state| runtime.store.save(state))?;
    result
}

async fn reconcile_scoped_root(
    run: &mut SyncRun,
    recheck_only: bool,
    session: &SessionIdentity,
    captured_bearer: &str,
    cycle_budget: &mut SyncCycleBudget,
    local_read_budget: &mut ReadBudget,
) -> CoreResult<()> {
    run.ensure_not_cancelled()?;
    let state = run.state().clone();
    let pair = state.pair.clone().ok_or(DesktopError::NeedsSetup)?;
    let _pair_root_guard = guard_configured_pair_roots(&state, &pair.local_root)?;
    let Some((client, token, metadata, remote)) =
        scoped_manifest_for_active_run(run, session, captured_bearer, cycle_budget).await?
    else {
        finish_stopped_root(run, &pair);
        return Ok(());
    };
    run.ensure_not_cancelled()?;
    let local = inspect_local_tree_with_directory_identities_with_budget_and_cancellation(
        &pair.local_root,
        local_read_budget,
        run,
    )?;
    let mut plan = apply_sync_root_policy(
        &metadata,
        apply_local_path_compatibility_reviews(
            run.plan(&remote, &local.entries, Utc::now())?,
            &local.issues,
        ),
        Utc::now(),
    );
    let conflict_actions = (!recheck_only && !plan.reviews.is_empty()).then(|| {
        plan.actions
            .iter()
            .filter(|action| matches!(action, SyncAction::WriteRemoteConflictCopy { .. }))
            .cloned()
            .collect::<Vec<_>>()
    });
    cycle_budget.admit(
        &remote,
        conflict_actions.as_deref().unwrap_or(&plan.actions),
    )?;
    if recheck_only {
        return finish_recheck_plan(run, &pair, &state, &remote, plan, local_read_budget);
    }
    if !plan.reviews.is_empty() {
        // Viewer policy removes WriteRemoteConflictCopy before this call.
        execute_conflict_copies(
            run,
            &client,
            &token,
            &pair,
            &remote,
            conflict_actions.as_deref().unwrap_or(&[]),
            &mut plan.reviews,
            local_read_budget,
        )
        .await?;
        run.ensure_not_cancelled()?;
        run.record_reviews(plan.reviews);
        return Ok(());
    }
    match execute_non_delete_actions(
        run,
        &client,
        &token,
        &pair,
        &metadata.root,
        &remote,
        &plan,
        local_read_budget,
    )
    .await?
    {
        NonDeleteExecution::Complete => {
            run.ensure_not_cancelled()?;
            let refreshed = client.sync_root_manifest(&token, &metadata.root).await?;
            run.ensure_not_cancelled()?;
            run.refresh_active_sync_root(refreshed.root, Utc::now())?;
            let refreshed_remote = refreshed
                .files
                .into_iter()
                .map(remote_entry)
                .collect::<CoreResult<Vec<_>>>()?;
            finish_baseline(run, &pair, &state, &refreshed_remote, local_read_budget)?;
        }
        NonDeleteExecution::NeedsReview(reviews) => run.record_reviews(reviews),
    }
    Ok(())
}

fn finish_recheck_plan(
    run: &mut SyncRun,
    pair: &SyncPair,
    state: &DesktopState,
    remote: &[RemoteEntry],
    plan: ReconcilePlan,
    local_read_budget: &mut ReadBudget,
) -> CoreResult<()> {
    let path_compatibility_only = state.reviews.iter().all(is_path_compatibility_review);
    if !plan.reviews.is_empty() {
        run.append_active_activity(ActivityEntry {
            at: Utc::now(),
            direction: "Review".to_string(),
            relative_path: PathBuf::new(),
            result: "Rechecked current Drive and local state; a decision is still needed."
                .to_string(),
        });
        run.record_reviews(plan.reviews);
    } else if plan.requires_transfer() {
        if path_compatibility_only {
            run.append_active_activity(ActivityEntry {
                at: Utc::now(), direction: "Review".to_string(), relative_path: PathBuf::new(),
                result: "Drive paths are compatible again. Recheck changed no files; Sync now is ready to apply the planned work.".to_string(),
            });
            run.record_recheck_compatible();
        } else {
            run.append_active_activity(ActivityEntry {
                at: Utc::now(), direction: "Review".to_string(), relative_path: PathBuf::new(),
                result: "Recheck found additional changes; the recorded review remains pending without moving data.".to_string(),
            });
            run.record_recheck_pending();
        }
    } else {
        finish_baseline(run, pair, state, remote, local_read_budget)?;
    }
    Ok(())
}

pub(super) fn settle_reconciliation_result(
    app: &tauri::AppHandle,
    runtime: &Runtime,
    result: CoreResult<()>,
) -> Result<DesktopView, String> {
    runtime.local_usage_cache.invalidate();
    if let Err(error) = result {
        match persist_terminal_failure(runtime, error).map_err(user_error)? {
            TerminalFailure::Admission(DesktopError::NeedsReconnect) => {
                update_tray(app, runtime);
                return Ok(runtime.view());
            }
            TerminalFailure::Admission(error) => return Err(user_error(error)),
            TerminalFailure::Offline => {
                update_tray(app, runtime);
                return Ok(runtime.view());
            }
            TerminalFailure::Persistent(error) => {
                update_tray(app, runtime);
                notify_actionable(app, runtime, true);
                return Err(user_error(error));
            }
        }
    }
    runtime.save().map_err(user_error)?;
    update_tray(app, runtime);
    notify_actionable(app, runtime, false);
    Ok(runtime.view())
}
