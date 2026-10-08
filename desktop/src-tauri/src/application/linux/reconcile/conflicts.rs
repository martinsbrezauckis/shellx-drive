//! Safe materialization of planner-owned content-conflict copies.

use super::*;

// Keep cancellation and filesystem authority explicit at the conflict dispatch boundary.
#[allow(clippy::too_many_arguments)]
pub(super) async fn materialize_conflict_copies(
    run: &SyncRun,
    cycle_budget: &mut SyncCycleBudget,
    client: &DriveHttpClient,
    token: &str,
    pair: &SyncPair,
    guard: &UnixRootGuard,
    sync_root: &SyncRoot,
    remote: &[RemoteEntry],
    plan: &ReconcilePlan,
) -> CoreResult<()> {
    let actions = content_conflict_copy_actions(plan)?;
    cycle_budget.admit(remote, &actions)?;
    if actions.is_empty() {
        return Ok(());
    }
    let reviews =
        execute_actions(run, client, token, pair, guard, sync_root, remote, &actions).await?;
    if let Some(review) = reviews.first() {
        return Err(DesktopError::InvalidState(format!(
            "Drive could not safely create the planned conflict copy at {}; no local file was overwritten",
            review.relative_path.display()
        )));
    }
    Ok(())
}

pub(super) fn content_conflict_copy_actions(plan: &ReconcilePlan) -> CoreResult<Vec<SyncAction>> {
    let mut copies = Vec::new();
    for action in &plan.actions {
        let SyncAction::WriteRemoteConflictCopy {
            local_path,
            conflict_path,
            ..
        } = action
        else {
            continue;
        };
        let review_is_bound = plan.reviews.iter().any(|review| {
            review.kind == ReviewKind::ContentConflict
                && review.relative_path == *conflict_path
                && review.actions.contains(&ReviewAction::OpenConflictCopies)
                && review.id
                    == format!("{:?}:{}", ReviewKind::ContentConflict, local_path.display())
        });
        if !review_is_bound {
            return Err(DesktopError::InvalidState(
                "conflict-copy action was not bound to its visible content-conflict review"
                    .to_string(),
            ));
        }
        copies.push(action.clone());
    }
    Ok(copies)
}
