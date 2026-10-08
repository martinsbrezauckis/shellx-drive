//! Durable review state transitions for a stopped or non-converged sync run.

use std::path::PathBuf;

use chrono::Utc;
use shellx_drive_desktop_core::{
    apply_sync_root_policy, sync_pair_id, ReconcilePlan, Result as CoreResult, ReviewAction,
    ReviewItem, ReviewKind, SyncPair, SyncRun,
};

pub(super) fn finish_stopped_root(run: &mut SyncRun, pair: &SyncPair) -> CoreResult<()> {
    let reviews = match run.sync_root_for_active_pair() {
        Ok(metadata) => apply_sync_root_policy(metadata, ReconcilePlan::default(), Utc::now()).reviews,
        Err(_) => vec![ReviewItem {
            id: format!("access-authority-missing:{}", sync_pair_id(pair)),
            kind: ReviewKind::AccessRemoved,
            relative_path: PathBuf::new(),
            descendant_count: 0,
            is_directory: true,
            summary: "This retained Drive location no longer has current server authority. Sync stopped and local files were left untouched.".to_string(),
            actions: vec![ReviewAction::RemoveLocalCopy],
        }],
    };
    persist_reviews(run, reviews)
}

pub(super) fn persist_reviews(run: &mut SyncRun, reviews: Vec<ReviewItem>) -> CoreResult<()> {
    // The all-roots coordinator owns terminal persistence after every root has
    // been visited, so this root records its review without ending the
    // serialized cycle early. The macOS executor now has the same retained
    // recovery move contract as the other native adapters; do not strip a
    // confirmable core action from the UI ledger.
    run.record_reviews(admitted_reviews(reviews));
    Ok(())
}

fn admitted_reviews(reviews: Vec<ReviewItem>) -> Vec<ReviewItem> {
    reviews
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_preserves_a_confirmable_recovery_move() {
        let review = ReviewItem {
            id: "removed".to_string(),
            kind: ReviewKind::AccessRemoved,
            relative_path: PathBuf::new(),
            descendant_count: 0,
            is_directory: true,
            summary: "Access was removed.".to_string(),
            actions: vec![ReviewAction::RemoveLocalCopy],
        };
        let retained = admitted_reviews(vec![review]);
        assert_eq!(retained[0].actions, vec![ReviewAction::RemoveLocalCopy]);
    }
}
