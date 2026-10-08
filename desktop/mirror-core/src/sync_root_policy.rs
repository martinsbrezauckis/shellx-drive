//! Fail-closed reconciliation policy for root-scoped Drive authority.

use std::path::PathBuf;

use chrono::{DateTime, Utc};

use crate::{
    ReconcilePlan, ReviewAction, ReviewItem, ReviewKind, SyncAction, SyncRootAccessRemovalReason,
    SyncRootMetadata, SyncRootRole,
};

/// Keep only transfers authorized by the root's current role. Viewer changes
/// are intentionally retained as review items rather than sent to a guessed
/// endpoint; a removed or expired root performs no transfer at all.
pub fn apply_sync_root_policy(
    metadata: &SyncRootMetadata,
    mut plan: ReconcilePlan,
    now: DateTime<Utc>,
) -> ReconcilePlan {
    if !metadata.is_available_at(now) {
        plan.actions.clear();
        plan.reviews = vec![access_removed_review(metadata, now)];
        return plan;
    }
    if metadata.root.role != SyncRootRole::Viewer {
        return plan;
    }

    let mut blocked = Vec::new();
    plan.actions.retain(|action| {
        if !viewer_may_execute(action) {
            blocked.push(read_only_local_change_review(metadata, action));
            false
        } else {
            true
        }
    });
    for review in &mut plan.reviews {
        // Review decisions are part of the executor surface too. A Viewer
        // must never obtain a remote write through a pre-existing deletion
        // review such as `RemoteDeletion -> RestoreToDrive`.
        review.actions.retain(viewer_may_offer_review_action);
        if review.kind == ReviewKind::LocalDeletion {
            review.kind = ReviewKind::ReadOnlyLocalChange;
            review.summary = format!(
                "{} is shared as Viewer access. The local change remains on this PC and was not sent to Drive.",
                metadata.root.label
            );
        }
    }
    plan.reviews.extend(blocked);
    plan.reviews.sort_by(|left, right| {
        (&left.relative_path, &left.id).cmp(&(&right.relative_path, &right.id))
    });
    plan
}

/// Explicitly allow only actions whose execution is purely local or downloads
/// from Drive. New review actions therefore fail closed until their authority
/// semantics are considered here.
fn viewer_may_offer_review_action(action: &ReviewAction) -> bool {
    matches!(
        action,
        ReviewAction::RestoreLocalCopy
            | ReviewAction::RemoveLocalCopy
            | ReviewAction::OpenConflictCopies
            | ReviewAction::RenameLocalCopy
            | ReviewAction::ChooseAnotherLocation
            | ReviewAction::RetryWhenServerSupportsResumableReplacement
    )
}

/// Explicitly allow only known local/download operations. Any future planner
/// action enters a local-only review until its Viewer behavior is reviewed.
fn viewer_may_execute(action: &SyncAction) -> bool {
    matches!(
        action,
        SyncAction::EnsureLocalDirectory { .. }
            | SyncAction::Download { .. }
            | SyncAction::MoveLocal { .. }
            | SyncAction::WriteRemoteConflictCopy { .. }
    )
}

fn read_only_local_change_review(metadata: &SyncRootMetadata, action: &SyncAction) -> ReviewItem {
    let (relative_path, is_directory) = match action {
        SyncAction::UploadNew {
            relative_path,
            is_directory,
            ..
        } => (relative_path.clone(), *is_directory),
        SyncAction::UploadExisting { relative_path, .. }
        | SyncAction::MoveRemote {
            to: relative_path, ..
        } => (relative_path.clone(), false),
        _ => unreachable!("only Viewer-blocked actions create read-only reviews"),
    };
    ReviewItem {
        id: format!(
            "read-only-local:{}:{}",
            metadata.root.local_identity_key(),
            relative_path.display()
        ),
        kind: ReviewKind::ReadOnlyLocalChange,
        relative_path,
        descendant_count: 0,
        is_directory,
        summary: format!(
            "{} is shared as Viewer access. This local change is preserved on this PC and will not upload to Drive.",
            metadata.root.label
        ),
        actions: Vec::new(),
    }
}

fn access_removed_review(metadata: &SyncRootMetadata, _now: DateTime<Utc>) -> ReviewItem {
    let reason = metadata
        .access_removed
        .as_ref()
        .map(|removal| removal.reason)
        .unwrap_or(SyncRootAccessRemovalReason::Expired);
    let reason = match reason {
        SyncRootAccessRemovalReason::Expired => "expired",
        SyncRootAccessRemovalReason::RevokedOrRemoved => "was removed",
    };
    ReviewItem {
        id: format!("access-removed:{}", metadata.root.local_identity_key()),
        kind: ReviewKind::AccessRemoved,
        relative_path: PathBuf::new(),
        descendant_count: 0,
        is_directory: true,
        summary: format!(
            "Access to {} {}. Sync stopped; files already downloaded on this PC were left untouched. Review this local copy before removing it.",
            metadata.root.label, reason
        ),
        actions: vec![ReviewAction::RemoveLocalCopy],
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DownloadPrecondition, LocalEntry, ReconcilePlan, SyncRoot, SyncRootKind};

    fn metadata(role: SyncRootRole) -> SyncRootMetadata {
        SyncRootMetadata {
            root: SyncRoot {
                id: "item-grant:opaque".to_string(),
                kind: SyncRootKind::ItemGrant,
                workspace_id: "workspace".to_string(),
                root_file_id: Some("folder".to_string()),
                grant_id: Some("grant".to_string()),
                owner_label: "Avery".to_string(),
                role,
                access_generation: 1,
                expires_at: None,
                label: "Projects".to_string(),
            },
            access_removed: None,
        }
    }

    fn upload_plan() -> ReconcilePlan {
        ReconcilePlan {
            actions: vec![
                SyncAction::Download {
                    remote_id: "remote-file".to_string(),
                    relative_path: PathBuf::from("from-drive.txt"),
                    revision: 1,
                    precondition: DownloadPrecondition::Absent,
                },
                SyncAction::UploadNew {
                    relative_path: PathBuf::from("local-only.txt"),
                    is_directory: false,
                    local: LocalEntry {
                        relative_path: PathBuf::from("local-only.txt"),
                        content_hash: Some("a".repeat(64)),
                        size_bytes: 1,
                        is_directory: false,
                        directory_identity: None,
                    },
                },
                SyncAction::MoveRemote {
                    remote_id: "remote-file".to_string(),
                    from: PathBuf::from("old.txt"),
                    to: PathBuf::from("renamed.txt"),
                    base_revision: 1,
                    folder_precondition: None,
                },
                SyncAction::WriteRemoteConflictCopy {
                    remote_id: "remote-file".to_string(),
                    local_path: PathBuf::from("local-only.txt"),
                    conflict_path: PathBuf::from("local-only (Drive conflict).txt"),
                },
            ],
            reviews: Vec::new(),
            remote_paths: Default::default(),
        }
    }

    #[test]
    fn viewer_policy_keeps_downloads_but_never_emits_remote_writes() {
        let plan =
            apply_sync_root_policy(&metadata(SyncRootRole::Viewer), upload_plan(), Utc::now());
        assert!(plan.actions.iter().all(viewer_may_execute));
        assert!(plan
            .actions
            .iter()
            .any(|action| matches!(action, SyncAction::Download { .. })));
        assert_eq!(
            plan.reviews
                .iter()
                .filter(|review| review.kind == ReviewKind::ReadOnlyLocalChange)
                .count(),
            2
        );
        assert!(plan
            .actions
            .iter()
            .any(|action| matches!(action, SyncAction::WriteRemoteConflictCopy { .. })));
    }

    #[test]
    fn expired_or_removed_root_stops_every_transfer_and_preserves_a_review() {
        let mut metadata = metadata(SyncRootRole::Editor);
        metadata.mark_access_removed(SyncRootAccessRemovalReason::RevokedOrRemoved, Utc::now());
        let plan = apply_sync_root_policy(&metadata, upload_plan(), Utc::now());
        assert!(plan.actions.is_empty());
        assert_eq!(plan.reviews.len(), 1);
        assert_eq!(plan.reviews[0].kind, ReviewKind::AccessRemoved);
        assert!(plan.reviews[0].summary.contains("left untouched"));
    }

    #[test]
    fn viewer_policy_removes_remote_review_writes_too() {
        let plan = apply_sync_root_policy(
            &metadata(SyncRootRole::Viewer),
            ReconcilePlan {
                actions: Vec::new(),
                reviews: vec![ReviewItem {
                    id: "remote-delete".to_string(),
                    kind: ReviewKind::RemoteDeletion,
                    relative_path: PathBuf::from("local.txt"),
                    descendant_count: 0,
                    is_directory: false,
                    summary: "test".to_string(),
                    actions: vec![ReviewAction::RemoveLocalCopy, ReviewAction::RestoreToDrive],
                }],
                remote_paths: Default::default(),
            },
            Utc::now(),
        );
        assert_eq!(plan.reviews[0].actions, vec![ReviewAction::RemoveLocalCopy]);
        assert!(plan
            .reviews
            .iter()
            .flat_map(|review| &review.actions)
            .all(viewer_may_offer_review_action));
    }
}
