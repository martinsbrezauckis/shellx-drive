//! Conservative macOS reconciliation with descriptor-rooted, fail-closed local mutations.

use std::{path::PathBuf, sync::atomic::Ordering, time::Duration};

use chrono::Utc;
use shellx_drive_desktop_core::{
    apply_local_path_compatibility_reviews, apply_sync_root_policy, inspect_local_tree,
    inspect_local_tree_with_cancellation, is_path_compatibility_review, ActivityEntry,
    DesktopError, DriveHttpClient, ReconcilePlan, RemoteEntry, SyncCycleBudget,
    SyncRootAccessRemovalReason, SyncRun,
};
use tauri::{Manager, State};

use super::*;

const POLL_INTERVAL: Duration = Duration::from_secs(20);
const OFFLINE_BACKOFF: Duration = Duration::from_secs(60);
mod all_roots;
mod baseline;
#[cfg(test)]
mod conflict_tests;
mod conflicts;
mod executor;
mod lifecycle;
mod result;
mod staging;
#[cfg(test)]
mod tests;

use all_roots::sync_all_roots;
use conflicts::materialize_conflict_copies as materialize_conflicts;
use result::{settle_result, settle_root_refresh_failure};
pub(super) use staging::remote_entry_for_review;

pub(super) fn start_polling(app: &tauri::AppHandle, runtime: &Runtime) {
    if runtime.polling_enabled.swap(true, Ordering::AcqRel) {
        return;
    }
    let generation = runtime.poll_generation.fetch_add(1, Ordering::AcqRel) + 1;
    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        loop {
            let runtime = handle.state::<Runtime>();
            let delay = if runtime.status() == shellx_drive_desktop_core::SyncStatus::Offline {
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
                shellx_drive_desktop_core::SyncStatus::NeedsSetup
                    | shellx_drive_desktop_core::SyncStatus::NeedsReconnect
                    | shellx_drive_desktop_core::SyncStatus::Syncing
                    | shellx_drive_desktop_core::SyncStatus::Paused
            ) {
                continue;
            }
            if let Err(error) = sync_now_impl(&handle, &runtime).await {
                eprintln!("ShellX Drive macOS automatic sync did not complete: {error}");
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
    runtime: State<'_, Runtime>,
) -> Result<DesktopView, String> {
    sync_now_impl(&app, &runtime).await
}

#[tauri::command]
pub(super) async fn recheck_reviews(
    app: tauri::AppHandle,
    runtime: State<'_, Runtime>,
) -> Result<DesktopView, String> {
    recheck_reviews_impl(&app, &runtime).await
}

pub(crate) async fn sync_now_impl(
    app: &tauri::AppHandle,
    runtime: &Runtime,
) -> Result<DesktopView, String> {
    sync_roots_impl(app, runtime, false).await
}

/// Recheck plans only; ordinary transfers stay blocked while a review is pending.
pub(crate) async fn recheck_reviews_impl(
    app: &tauri::AppHandle,
    runtime: &Runtime,
) -> Result<DesktopView, String> {
    sync_roots_impl(app, runtime, true).await
}

async fn sync_roots_impl(
    app: &tauri::AppHandle,
    runtime: &Runtime,
    recheck_only: bool,
) -> Result<DesktopView, String> {
    runtime
        .require_candidate_recovery_complete()
        .map_err(macos_error)?;
    runtime
        .ensure_disconnect_cleanup_complete()
        .map_err(macos_error)?;
    invalidate_pending_confirmation(runtime);
    if let Err(error) = pairing::refresh_authorized_roots(runtime).await {
        return settle_root_refresh_failure(app, runtime, error);
    }
    let mut run = runtime.coordinator.begin_run().map_err(macos_error)?;
    if recheck_only && !run.has_any_reviews() {
        return Err("There is no pending review to recheck.".to_string());
    }
    let result = sync_all_roots(runtime, &mut run, recheck_only).await;
    settle_result(app, runtime, result)
}

async fn sync_run(
    run: &mut shellx_drive_desktop_core::SyncRun,
    recheck_only: bool,
    session: &crate::session_identity::SessionIdentity,
    captured_bearer: &str,
    budget: &mut SyncCycleBudget,
) -> CoreResult<()> {
    run.ensure_not_cancelled()?;
    let state = run.state().clone();
    let pair = state.pair.clone().ok_or(DesktopError::NeedsSetup)?;
    let expected = pair.local_root_identity.as_ref().ok_or_else(|| {
        DesktopError::InvalidState(
            "the selected Drive folder has no macOS identity; pair it again".to_string(),
        )
    })?;
    let guard = crate::platform::unix::filesystem::UnixRootGuard::acquire(
        &pair.local_root,
        Some(expected),
    )?;
    guard.require_exact_pair_marker(&shellx_drive_desktop_core::PairMarker::from(&pair))?;
    let root = run.sync_root_for_active_pair()?.clone();
    if !root.is_available_at(Utc::now()) {
        return lifecycle::finish_stopped_root(run, &pair);
    }
    let client = DriveHttpClient::new(&session.server_url)?.with_cycle_budget(budget);
    let manifest = match client.sync_root_manifest(captured_bearer, &root.root).await {
        Ok(manifest) => manifest,
        Err(error) if root_access_was_removed(&error) => {
            run.mark_active_root_removed(
                SyncRootAccessRemovalReason::RevokedOrRemoved,
                Utc::now(),
            )?;
            return lifecycle::finish_stopped_root(run, &pair);
        }
        Err(error) => return Err(error),
    };
    run.ensure_not_cancelled()?;
    run.refresh_active_sync_root(manifest.root, Utc::now())?;
    let root = run.sync_root_for_active_pair()?.clone();
    if !root.is_available_at(Utc::now()) {
        return lifecycle::finish_stopped_root(run, &pair);
    }
    let remote = manifest
        .files
        .into_iter()
        .map(remote_entry_for_review)
        .collect::<CoreResult<Vec<_>>>()?;
    let mut local =
        inspect_local_tree_with_cancellation(&pair.local_root, || run.ensure_not_cancelled())?;
    guard.observe_directory_identities(&mut local, || run.ensure_not_cancelled())?;
    let plan = apply_sync_root_policy(
        &root,
        apply_local_path_compatibility_reviews(
            run.plan(&remote, &local.entries, Utc::now())?,
            &local.issues,
        ),
        Utc::now(),
    );
    // Only conflict copies execute while reviews are pending. Rechecks charge
    // their complete proposed plan even though they do not transfer bytes.
    let conflict_actions = if !recheck_only && !plan.reviews.is_empty() {
        Some(conflicts::content_conflict_copy_actions(&plan)?)
    } else {
        None
    };
    budget.admit(
        &remote,
        conflict_actions.as_deref().unwrap_or(&plan.actions),
    )?;
    if recheck_only {
        if plan.reviews.is_empty() && !plan.requires_transfer() {
            run.record_recheck_compatible();
        } else if plan.reviews.is_empty() {
            if !clear_resolved_path_review(run, &plan) {
                run.record_recheck_pending();
            }
        } else {
            lifecycle::persist_reviews(run, plan.reviews)?;
        }
        return Ok(());
    }
    if !plan.reviews.is_empty() {
        materialize_conflicts(
            run,
            &guard,
            &client,
            captured_bearer,
            &pair,
            &root.root,
            &remote,
            &plan,
        )
        .await?;
        run.ensure_not_cancelled()?;
        return lifecycle::persist_reviews(run, plan.reviews);
    }
    let reviews = executor::execute_actions(
        run,
        &guard,
        &client,
        captured_bearer,
        &pair,
        &root.root,
        &remote,
        &plan.actions,
    )
    .await?;
    run.ensure_not_cancelled()?;
    if !reviews.is_empty() {
        return lifecycle::persist_reviews(run, reviews);
    }
    let refreshed = client
        .sync_root_manifest(captured_bearer, &root.root)
        .await?;
    run.ensure_not_cancelled()?;
    run.refresh_active_sync_root(refreshed.root, Utc::now())?;
    let refreshed_remote = refreshed
        .files
        .into_iter()
        .map(remote_entry_for_review)
        .collect::<CoreResult<Vec<_>>>()?;
    let local =
        inspect_local_tree_with_cancellation(&pair.local_root, || run.ensure_not_cancelled())?;
    if !local.issues.is_empty() {
        let plan = apply_local_path_compatibility_reviews(
            shellx_drive_desktop_core::ReconcilePlan::default(),
            &local.issues,
        );
        return lifecycle::persist_reviews(run, plan.reviews);
    }
    baseline::finish(run, &pair, &guard, &refreshed_remote)?;
    run.append_active_activity(ActivityEntry {
        at: Utc::now(),
        direction: "Sync".to_string(),
        relative_path: PathBuf::new(),
        result: "macOS Drive reconciliation completed.".to_string(),
    });
    Ok(())
}

/// A compatibility-only review is cleared when a planning-only recheck sees
/// safe paths again. The transfer plan stays pending for a later explicit
/// Sync now action and no successful baseline is recorded here.
fn clear_resolved_path_review(run: &mut SyncRun, plan: &ReconcilePlan) -> bool {
    let resolved_path_only_review = plan.reviews.is_empty()
        && plan.requires_transfer()
        && !run.state().reviews.is_empty()
        && run.state().reviews.iter().all(is_path_compatibility_review);
    if !resolved_path_only_review {
        return false;
    }
    run.append_active_activity(ActivityEntry {
        at: Utc::now(),
        direction: "Review".to_string(),
        relative_path: PathBuf::new(),
        result: "Drive paths are compatible again. Recheck changed no files; Sync now is ready to apply the planned work.".to_string(),
    });
    run.record_recheck_compatible();
    true
}

fn root_access_was_removed(error: &DesktopError) -> bool {
    matches!(
        error,
        DesktopError::Server {
            status: 403 | 404 | 410,
            ..
        }
    )
}
