//! Safe materialization of planner-owned macOS content-conflict copies.

use shellx_drive_desktop_core::{
    DesktopError, DriveHttpClient, ReconcilePlan, RemoteEntry, Result as CoreResult, ReviewAction,
    ReviewKind, SyncAction, SyncPair, SyncPassLimits, SyncRoot, SyncRun,
};

use super::executor;

#[allow(clippy::too_many_arguments)]
pub(super) async fn materialize_conflict_copies(
    run: &SyncRun,
    guard: &crate::platform::unix::filesystem::UnixRootGuard,
    client: &DriveHttpClient,
    token: &str,
    pair: &SyncPair,
    root: &SyncRoot,
    remote: &[RemoteEntry],
    plan: &ReconcilePlan,
) -> CoreResult<()> {
    let actions = content_conflict_copy_actions(plan)?;
    if actions.is_empty() {
        return Ok(());
    }
    shellx_drive_desktop_core::validate_sync_pass(remote, &actions, SyncPassLimits::default())?;
    let reviews =
        executor::execute_actions(run, guard, client, token, pair, root, remote, &actions).await?;
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
