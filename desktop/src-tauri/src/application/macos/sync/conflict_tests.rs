use std::path::PathBuf;

use shellx_drive_desktop_core::{ReconcilePlan, ReviewAction, ReviewItem, ReviewKind, SyncAction};

use super::conflicts::content_conflict_copy_actions;

fn plan(with_review: bool) -> ReconcilePlan {
    let local = PathBuf::from("report.pdf");
    let conflict = PathBuf::from("report (Drive conflict 2026-09-03 120000).pdf");
    ReconcilePlan {
        actions: vec![
            SyncAction::EnsureLocalDirectory {
                remote_id: "unrelated".to_string(),
                relative_path: PathBuf::from("unrelated"),
            },
            SyncAction::WriteRemoteConflictCopy {
                remote_id: "file".to_string(),
                local_path: local.clone(),
                conflict_path: conflict.clone(),
            },
        ],
        reviews: with_review
            .then(|| ReviewItem {
                id: format!("{:?}:{}", ReviewKind::ContentConflict, local.display()),
                kind: ReviewKind::ContentConflict,
                relative_path: conflict,
                descendant_count: 0,
                is_directory: false,
                summary: "Both copies changed.".to_string(),
                actions: vec![ReviewAction::OpenConflictCopies],
            })
            .into_iter()
            .collect(),
        remote_paths: Default::default(),
    }
}

#[test]
fn reviewed_lane_executes_only_the_bound_conflict_copy() {
    let actions = content_conflict_copy_actions(&plan(true)).expect("bound plan");
    assert!(matches!(
        actions.as_slice(),
        [SyncAction::WriteRemoteConflictCopy { conflict_path, .. }]
            if conflict_path == &PathBuf::from("report (Drive conflict 2026-09-03 120000).pdf")
    ));
}

#[test]
fn reviewed_lane_rejects_an_unbound_copy() {
    let error = content_conflict_copy_actions(&plan(false)).expect_err("missing review");
    assert!(error
        .to_string()
        .contains("visible content-conflict review"));
}
