//! Current root-role checks for native review execution.

use super::super::*;
use crate::session_identity::SessionIdentity;

pub(super) async fn current_scoped_review(
    state: &DesktopState,
    pair: &SyncPair,
    decision: ReviewDecision,
    session: &SessionIdentity,
    captured_bearer: &str,
    cycle_budget: &SyncCycleBudget,
) -> CoreResult<(DriveHttpClient, String, Vec<RemoteEntry>)> {
    review_decision_is_still_authorized(state, pair, decision)?;
    let client = DriveHttpClient::new(&session.server_url)?.with_cycle_budget(cycle_budget);
    let requested_root = state.sync_root_for_pair(pair).ok_or_else(|| {
        DesktopError::InvalidState(
            "this Drive location has no authenticated root authority; only the retained-local-copy review is available".to_string(),
        )
    })?;
    let manifest = client
        .sync_root_manifest(captured_bearer, &requested_root.root)
        .await?;
    if !manifest.root.is_available_at(Utc::now()) {
        return Err(DesktopError::InvalidState(
            "Drive root access expired before the review could run; local bytes were left untouched".to_string(),
        ));
    }
    if review_decision_requires_remote_write(decision) && !manifest.root.role.may_write() {
        return Err(DesktopError::InvalidState(
            "Drive root is now Viewer access; this review cannot change Drive".to_string(),
        ));
    }
    let remote = manifest
        .files
        .into_iter()
        .map(remote_entry)
        .collect::<CoreResult<Vec<_>>>()?;
    Ok((client, captured_bearer.to_string(), remote))
}

fn review_decision_is_still_authorized(
    state: &DesktopState,
    pair: &SyncPair,
    decision: ReviewDecision,
) -> CoreResult<()> {
    let metadata = state.sync_root_for_pair(pair).ok_or_else(|| {
        DesktopError::InvalidState(
            "this Drive location has no authenticated root authority; re-pair it before changing Drive".to_string(),
        )
    })?;
    if !metadata.is_available_at(Utc::now()) {
        return Err(DesktopError::InvalidState(
            "Drive root access was removed; local bytes were left untouched".to_string(),
        ));
    }
    if review_decision_requires_remote_write(decision) && !metadata.root.role.may_write() {
        return Err(DesktopError::InvalidState(
            "Viewer access cannot change Drive through a review action".to_string(),
        ));
    }
    Ok(())
}

fn review_decision_requires_remote_write(decision: ReviewDecision) -> bool {
    matches!(
        decision,
        ReviewDecision::TrashRemote | ReviewDecision::RestoreRemote
    )
}
