//! Descriptor-bound Linux reconciliation execution.
//!
//! This v0.1 adapter executes only operations whose local and remote terminal
//! boundaries can be revalidated. Linux renames use `renameat2` no-replace;
//! existing-file replacement first publishes a recovery link and then uses an
//! atomic exchange. Unsupported Unix targets stay fail-closed in the shared
//! filesystem adapter.

use std::{
    collections::{BTreeMap, HashMap},
    fs,
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

use chrono::Utc;
use shellx_drive_desktop_core::{
    apply_local_path_compatibility_reviews, apply_sync_root_policy, capture_folder_remote_witness,
    created_remote_response_matches, download_precondition_matches, download_staging_root,
    ensure_tree_has_no_links, folder_remote_witness_matches, folder_subtree_matches_precondition,
    initialize_owned_staging_root, inspect_local_tree,
    inspect_local_tree_with_budget_and_cancellation, is_path_compatibility_review,
    map_remote_paths, remote_move_response_matches, updated_remote_response_matches,
    validate_private_staging_file, windows_paths_equal_ignore_case, BaselineEntry, DesktopError,
    DownloadPrecondition, DriveHttpClient, ExistingFileTransfer, LocalEntry, ReadBudget,
    ReconcilePlan, RemoteEntry, RemoteEntryKind, RemoteFileKind, RemoteMoveTransfer,
    Result as CoreResult, ReviewAction, ReviewItem, ReviewKind, SyncAction, SyncCycleBudget,
    SyncPair, SyncPassLimits, SyncRoot, SyncRootAccessRemovalReason, SyncRun,
};

use crate::{
    platform::unix::filesystem::{ReplacingPublication, UnixRootGuard},
    session_identity::SessionIdentity,
};

mod baseline;
#[cfg(test)]
mod baseline_tests;
#[cfg(test)]
mod conflict_tests;
mod conflicts;
mod convergence;
mod local;
#[cfg(test)]
mod local_path_tests;
#[cfg(test)]
mod move_tests;
mod operations;
mod presentation;
#[cfg(test)]
mod tests;
mod transfers;

pub(super) use baseline::*;
pub(super) use conflicts::*;
use convergence::{Convergence, SyncAttemptDisposition};
pub(super) use local::*;
pub(super) use operations::*;
pub(super) use presentation::*;
pub(super) use transfers::*;

pub(super) async fn reconcile(
    run: &mut SyncRun,
    cycle_budget: &mut SyncCycleBudget,
    local_reads: &mut ReadBudget,
    recheck_only: bool,
    session: &SessionIdentity,
    captured_bearer: &str,
) -> CoreResult<()> {
    let mut convergence = Convergence::default();
    loop {
        convergence.begin_attempt(run)?;
        let disposition = reconcile_attempt(
            run,
            cycle_budget,
            local_reads,
            recheck_only,
            session,
            captured_bearer,
        )
        .await?;
        if convergence.complete_attempt(run, disposition)? {
            return Ok(());
        }
    }
}

async fn reconcile_attempt(
    run: &mut SyncRun,
    cycle_budget: &mut SyncCycleBudget,
    local_reads: &mut ReadBudget,
    recheck_only: bool,
    session: &SessionIdentity,
    captured_bearer: &str,
) -> CoreResult<SyncAttemptDisposition> {
    run.ensure_not_cancelled()?;
    let state = run.state().clone();
    let pair = state.pair.clone().ok_or(DesktopError::NeedsSetup)?;
    let guard = guard_pair(&pair)?;
    let Some((client, token, remote)) =
        scoped_manifest(run, session, captured_bearer, cycle_budget).await?
    else {
        finish_stopped(run, &pair);
        return Ok(SyncAttemptDisposition::Complete);
    };
    run.ensure_not_cancelled()?;
    let mut local =
        inspect_local_tree_with_budget_and_cancellation(&pair.local_root, local_reads, || {
            run.ensure_not_cancelled()
        })?;
    guard.observe_directory_identities(&mut local, || run.ensure_not_cancelled())?;
    let metadata = run.sync_root_for_active_pair()?.clone();
    let plan = apply_sync_root_policy(
        &metadata,
        plan_with_local_path_reviews(
            run.plan(&remote, &local.entries, Utc::now())?,
            &local.issues,
        ),
        Utc::now(),
    );
    if recheck_only {
        cycle_budget.admit(&remote, &plan.actions)?;
        if plan.reviews.is_empty() && !plan.requires_transfer() {
            return finish_baseline(run, local_reads, &pair, &guard, &remote);
        } else if plan.reviews.is_empty() {
            if !clear_resolved_path_review(run, &plan) {
                run.record_recheck_pending();
            }
        } else {
            run.record_reviews(plan.reviews);
        }
        return Ok(SyncAttemptDisposition::Complete);
    }
    if !plan.reviews.is_empty() {
        materialize_conflict_copies(
            run,
            cycle_budget,
            &client,
            &token,
            &pair,
            &guard,
            &metadata.root,
            &remote,
            &plan,
        )
        .await?;
        run.ensure_not_cancelled()?;
        run.record_reviews(plan.reviews);
        return Ok(SyncAttemptDisposition::Complete);
    }
    cycle_budget.admit(&remote, &plan.actions)?;
    let reviews = execute_actions(
        run,
        &client,
        &token,
        &pair,
        &guard,
        &metadata.root,
        &remote,
        &plan.actions,
    )
    .await?;
    run.ensure_not_cancelled()?;
    if !reviews.is_empty() {
        run.record_reviews(reviews);
        return Ok(SyncAttemptDisposition::Complete);
    }
    let refreshed = client.sync_root_manifest(&token, &metadata.root).await?;
    run.ensure_not_cancelled()?;
    run.refresh_active_sync_root(refreshed.root, Utc::now())?;
    let remote = refreshed
        .files
        .into_iter()
        .map(remote_entry)
        .collect::<CoreResult<Vec<_>>>()?;
    finish_baseline(run, local_reads, &pair, &guard, &remote)
}

fn plan_with_local_path_reviews(
    plan: ReconcilePlan,
    issues: &[shellx_drive_desktop_core::LocalPathIssue],
) -> ReconcilePlan {
    apply_local_path_compatibility_reviews(plan, issues)
}

/// A path-only review is resolved by a planning pass once the incompatible
/// entry is gone. The transfer plan remains pending for the next explicit
/// Sync now action; this branch neither executes it nor records a baseline.
fn clear_resolved_path_review(run: &mut SyncRun, plan: &ReconcilePlan) -> bool {
    let resolved_path_only_review = plan.reviews.is_empty()
        && plan.requires_transfer()
        && !run.state().reviews.is_empty()
        && run.state().reviews.iter().all(is_path_compatibility_review);
    if !resolved_path_only_review {
        return false;
    }
    run.append_active_activity(shellx_drive_desktop_core::ActivityEntry {
        at: Utc::now(),
        direction: "Review".to_string(),
        relative_path: PathBuf::new(),
        result: "Drive paths are compatible again. Recheck changed no files; Sync now is ready to apply the planned work.".to_string(),
    });
    run.record_recheck_compatible();
    true
}

async fn scoped_manifest(
    run: &mut SyncRun,
    session: &SessionIdentity,
    captured_bearer: &str,
    cycle_budget: &SyncCycleBudget,
) -> CoreResult<Option<(DriveHttpClient, String, Vec<RemoteEntry>)>> {
    let metadata = match run.sync_root_for_active_pair() {
        Ok(metadata) => metadata.clone(),
        Err(_) => return Ok(None),
    };
    if !metadata.is_available_at(Utc::now()) {
        return Ok(None);
    }
    let client = DriveHttpClient::new(&session.server_url)?.with_cycle_budget(cycle_budget);
    let manifest = match client
        .sync_root_manifest(captured_bearer, &metadata.root)
        .await
    {
        Ok(manifest) => manifest,
        Err(error) if root_access_was_removed(&error) => {
            run.mark_active_root_removed(
                SyncRootAccessRemovalReason::RevokedOrRemoved,
                Utc::now(),
            )?;
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    run.refresh_active_sync_root(manifest.root, Utc::now())?;
    let remote = manifest
        .files
        .into_iter()
        .map(remote_entry)
        .collect::<CoreResult<Vec<_>>>()?;
    Ok(Some((client, captured_bearer.to_string(), remote)))
}

pub(super) async fn current_manifest_for_review(
    run: &mut SyncRun,
    session: &SessionIdentity,
    captured_bearer: &str,
    cycle_budget: &SyncCycleBudget,
) -> CoreResult<Option<(DriveHttpClient, String, Vec<RemoteEntry>)>> {
    scoped_manifest(run, session, captured_bearer, cycle_budget).await
}

fn guard_pair(pair: &SyncPair) -> CoreResult<UnixRootGuard> {
    let guard = UnixRootGuard::acquire(&pair.local_root, pair.local_root_identity.as_ref())?;
    guard.require_exact_pair_marker(&shellx_drive_desktop_core::PairMarker::from(pair))?;
    Ok(guard)
}

pub(super) fn finish_stopped(run: &mut SyncRun, pair: &SyncPair) {
    let review = run
        .sync_root_for_active_pair()
        .ok()
        .map(|metadata| apply_sync_root_policy(metadata, Default::default(), Utc::now()).reviews)
        .unwrap_or_else(|| {
            vec![ReviewItem {
                id: format!("access-authority-missing:{}", shellx_drive_desktop_core::sync_pair_id(pair)),
                kind: ReviewKind::AccessRemoved,
                relative_path: PathBuf::new(),
                descendant_count: 0,
                is_directory: true,
                summary: "This Drive location no longer has current server authority. Sync stopped and local files were left untouched.".to_string(),
                actions: vec![ReviewAction::RemoveLocalCopy],
            }]
        });
    run.record_reviews(review);
}

pub(super) fn finish_revoked_during_cycle(run: &mut SyncRun, pair: &SyncPair) -> CoreResult<()> {
    run.mark_active_root_removed(SyncRootAccessRemovalReason::RevokedOrRemoved, Utc::now())?;
    finish_stopped(run, pair);
    run.append_active_activity(shellx_drive_desktop_core::ActivityEntry {
        at: Utc::now(),
        direction: "Drive".to_string(),
        relative_path: PathBuf::new(),
        result: "Access was removed during this sync; local files were retained for review."
            .to_string(),
    });
    Ok(())
}

pub(super) fn root_access_was_removed(error: &DesktopError) -> bool {
    matches!(
        error,
        DesktopError::Server {
            status: 403 | 404 | 410,
            ..
        }
    )
}
