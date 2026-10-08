//! Scoped manifest acquisition and terminal root-state projections.

use super::super::*;
use crate::session_identity::SessionIdentity;
use shellx_drive_desktop_core::{
    apply_sync_root_policy, SyncRootAccessRemovalReason, SyncRootMetadata,
};

pub(super) async fn scoped_manifest_for_active_run(
    run: &mut SyncRun,
    session: &SessionIdentity,
    captured_bearer: &str,
    cycle_budget: &SyncCycleBudget,
) -> CoreResult<Option<(DriveHttpClient, String, SyncRootMetadata, Vec<RemoteEntry>)>> {
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
    let metadata = run.sync_root_for_active_pair()?.clone();
    if !metadata.is_available_at(Utc::now()) {
        return Ok(None);
    }
    let remote = manifest
        .files
        .into_iter()
        .map(remote_entry)
        .collect::<CoreResult<Vec<_>>>()?;
    Ok(Some((
        client,
        captured_bearer.to_string(),
        metadata,
        remote,
    )))
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

pub(super) fn finish_stopped_root(run: &mut SyncRun, pair: &SyncPair) {
    let review = match run.sync_root_for_active_pair() {
        Ok(metadata) => apply_sync_root_policy(metadata, ReconcilePlan::default(), Utc::now()).reviews,
        Err(_) => vec![ReviewItem {
            id: format!("access-authority-missing:{}", sync_pair_id(pair)),
            kind: ReviewKind::AccessRemoved, relative_path: PathBuf::new(), descendant_count: 0,
            is_directory: true,
            summary: "This retained Drive location predates role-aware root authority. Sync stopped and its local files were left untouched. Sign in to adopt the authorized root or re-pair this location before syncing.".to_string(),
            actions: vec![ReviewAction::RemoveLocalCopy],
        }],
    };
    run.record_reviews(review);
}

pub(super) fn finish_baseline(
    run: &mut SyncRun,
    pair: &SyncPair,
    state: &DesktopState,
    remote: &[RemoteEntry],
    local_read_budget: &mut ReadBudget,
) -> CoreResult<()> {
    match verify_and_build_baseline_with_budget(pair, remote, &state.baseline, local_read_budget)? {
        BaselineFinalization::Complete(baseline) => {
            run.append_active_activity(ActivityEntry {
                at: Utc::now(),
                direction: "Drive and local".to_string(),
                relative_path: PathBuf::new(),
                result: "Mirror completed safely.".to_string(),
            });
            run.record_success(baseline, Utc::now());
        }
        BaselineFinalization::NeedsReview(review) => {
            run.append_active_activity(ActivityEntry {
                at: Utc::now(), direction: "Review".to_string(), relative_path: PathBuf::new(),
                result: "A folder identity changed after the planned operation; the prior baseline was retained for review.".to_string(),
            });
            run.record_reviews(vec![review]);
        }
    }
    Ok(())
}
