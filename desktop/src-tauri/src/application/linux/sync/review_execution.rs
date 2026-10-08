use super::*;
use crate::application::sync_terminal::session::admit_user_session_response;
use crate::session_identity::SessionIdentity;
use shellx_drive_desktop_core::{SyncCycleBudget, SyncPassLimits};

pub(super) enum ReviewExecution {
    Recheck,
    RetainedRootMoved {
        pair: Box<SyncPair>,
        recovery: PathBuf,
    },
}

pub(super) async fn execute_review(
    runtime: &Runtime,
    run: &mut shellx_drive_desktop_core::SyncRun,
    item: &shellx_drive_desktop_core::ReviewItem,
    decision: ReviewDecision,
) -> CoreResult<ReviewExecution> {
    if decision == ReviewDecision::RemoveRetainedRoot {
        return execute_review_with_captured_bearer(run, item, decision, None).await;
    }
    let session = runtime.current_session()?;
    let captured_bearer = runtime.current_token(&session)?;
    admit_user_session_response(
        runtime,
        &session,
        &captured_bearer,
        shellx_drive_desktop_core::with_cycle_read_budget(
            shellx_drive_desktop_core::sync_cycle_local_read_limit(),
            execute_review_with_captured_bearer(
                run,
                item,
                decision,
                Some((&session, &captured_bearer)),
            ),
        )
        .await,
    )
    .await
}

async fn execute_review_with_captured_bearer(
    run: &mut shellx_drive_desktop_core::SyncRun,
    item: &shellx_drive_desktop_core::ReviewItem,
    decision: ReviewDecision,
    captured_session: Option<(&SessionIdentity, &str)>,
) -> CoreResult<ReviewExecution> {
    let pair = run.state().pair.clone().ok_or(DesktopError::NeedsSetup)?;
    if decision == ReviewDecision::RemoveRetainedRoot {
        let guard = reconcile::pair_guard(&pair)?;
        let root_leaf = pair.local_root.file_name().ok_or_else(|| {
            DesktopError::UnsafePath("the paired Drive root has no local leaf".to_string())
        })?;
        let recovery = recovery_destination(&pair, "retained-root", Some(Path::new(root_leaf)))?;
        guard.move_complete_root_to_recovery(
            &shellx_drive_desktop_core::PairMarker::from(&pair),
            &recovery,
            || {
                guard.require_exact_pair_marker(&shellx_drive_desktop_core::PairMarker::from(
                    &pair,
                ))?;
                ensure_tree_has_no_links(&pair.local_root)?;
                Ok(())
            },
        )?;
        return Ok(ReviewExecution::RetainedRootMoved {
            pair: Box::new(pair),
            recovery,
        });
    }
    let (session, bearer) = captured_session.ok_or(DesktopError::NeedsReconnect)?;
    let mut budget = SyncCycleBudget::new(SyncPassLimits::default());
    let Some((client, token, remote)) =
        reconcile::current_manifest_for_review(run, session, bearer, &budget).await?
    else {
        return Err(DesktopError::InvalidState(
            "Drive access was removed; this review was left pending.".to_string(),
        ));
    };
    budget.admit(&remote, &[])?;
    let current_root = run.sync_root_for_active_pair()?.root.clone();
    let baseline = run.state().baseline.clone();
    let saved = baseline
        .values()
        .find(|entry| entry.relative_path == item.relative_path)
        .ok_or_else(|| {
            DesktopError::InvalidState("This review has no exact saved Drive item.".to_string())
        })?;
    match decision {
        ReviewDecision::TrashRemote => {
            budget.admit_extra(1, 0, 0, 1)?;
            reconcile::require_write_grant_at_terminal(&current_root)?;
            let current = remote
                .iter()
                .find(|entry| entry.id == saved.remote_id && !entry.trashed)
                .ok_or_else(|| {
                    DesktopError::InvalidState(
                        "Drive item changed before trash could be confirmed.".to_string(),
                    )
                })?;
            if item.is_directory
                || current.revision != saved.revision
                || current.content_hash != saved.content_hash
            {
                return Err(DesktopError::InvalidState(
                    "Drive item changed before trash; nothing was removed.".to_string(),
                ));
            }
            reviewed_remote_subtree_matches_baseline(
                item,
                &baseline,
                pair.remote_root_id.as_deref(),
                &remote,
            )?;
            let trashed = client.trash_file(&token, &current.id).await?;
            if !trashed_remote_response_matches(
                &trashed,
                &saved.remote_id,
                &pair.workspace_id,
                current.revision,
                current,
            ) {
                return Err(DesktopError::InvalidState(
                    "Drive did not confirm the exact trashed file; the review remains pending"
                        .to_string(),
                ));
            }
        }
        ReviewDecision::RestoreLocal => {
            let guard = reconcile::pair_guard(&pair)?;
            super::restore::restore_local(
                &guard,
                &client,
                &token,
                &pair,
                &current_root,
                run.state(),
                item,
                &remote,
                &mut budget,
            )
            .await?;
        }
        ReviewDecision::RestoreRemote => {
            budget.admit_extra(1, 0, 0, 1)?;
            reconcile::require_write_grant_at_terminal(&current_root)?;
            if remote
                .iter()
                .any(|entry| entry.id == saved.remote_id && !entry.trashed)
            {
                return Err(DesktopError::InvalidState(
                    "Drive already restored this reviewed item; no overwrite was attempted"
                        .to_string(),
                ));
            }
            let paths = map_remote_paths(&remote, pair.remote_root_id.as_deref())?;
            if paths.values().any(|path| path == &saved.relative_path) {
                return Err(DesktopError::InvalidState(
                    "another live Drive item now occupies this restore path; no overwrite was attempted"
                        .to_string(),
                ));
            }
            let current = remote
                .iter()
                .find(|entry| entry.id == saved.remote_id && entry.trashed)
                .ok_or_else(|| {
                    DesktopError::InvalidState(
                        "Drive item is not in trash for this exact restore.".to_string(),
                    )
                })?;
            let restored = client.restore_file(&token, &current.id).await?;
            if !restored_remote_response_matches(
                &restored,
                &saved.remote_id,
                &pair.workspace_id,
                current.revision,
                current,
            ) {
                return Err(DesktopError::InvalidState(
                    "Drive did not confirm the exact restored file; the review remains pending"
                        .to_string(),
                ));
            }
        }
        ReviewDecision::RecoverLocal => {
            if remote
                .iter()
                .any(|entry| entry.id == saved.remote_id && !entry.trashed)
            {
                return Err(DesktopError::InvalidState(
                    "Drive restored this reviewed item after confirmation; local bytes were left in place"
                        .to_string(),
                ));
            }
            let guard = reconcile::pair_guard(&pair)?;
            checked_recovery_local_entries(&pair, run.state(), item, &guard)?;
            let recovery = recovery_destination(&pair, &item.id, Some(&item.relative_path))?;
            guard.move_entry_to_recovery(
                &item.relative_path,
                &recovery,
                item.is_directory,
                || {
                    guard.require_exact_pair_marker(
                        &shellx_drive_desktop_core::PairMarker::from(&pair),
                    )?;
                    checked_recovery_local_entries(&pair, run.state(), item, &guard)?;
                    Ok(())
                },
            )?;
        }
        ReviewDecision::RemoveRetainedRoot => unreachable!("handled before manifest access"),
    }
    let mut next = run.state().clone();
    next.reviews.retain(|review| review.id != item.id);
    run.finish_state(next);
    Ok(ReviewExecution::Recheck)
}
