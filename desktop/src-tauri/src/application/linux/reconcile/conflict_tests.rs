use super::*;

fn conflict_plan(with_review: bool) -> ReconcilePlan {
    let local_path = PathBuf::from("report.pdf");
    let conflict_path = PathBuf::from("report (Drive conflict 2026-09-03 120000).pdf");
    ReconcilePlan {
        actions: vec![
            SyncAction::EnsureLocalDirectory {
                remote_id: "folder".to_string(),
                relative_path: PathBuf::from("unrelated"),
            },
            SyncAction::WriteRemoteConflictCopy {
                remote_id: "file".to_string(),
                local_path: local_path.clone(),
                conflict_path: conflict_path.clone(),
            },
        ],
        reviews: with_review
            .then(|| ReviewItem {
                id: format!("{:?}:{}", ReviewKind::ContentConflict, local_path.display()),
                kind: ReviewKind::ContentConflict,
                relative_path: conflict_path,
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
fn conflict_materialization_is_limited_to_the_bound_conflict_copy() {
    let actions = content_conflict_copy_actions(&conflict_plan(true)).expect("bound plan");

    assert!(matches!(
        actions.as_slice(),
        [SyncAction::WriteRemoteConflictCopy { conflict_path, .. }]
            if conflict_path == &PathBuf::from("report (Drive conflict 2026-09-03 120000).pdf")
    ));
}

#[test]
fn conflict_materialization_rejects_an_unreviewed_copy() {
    let error = content_conflict_copy_actions(&conflict_plan(false)).expect_err("missing review");

    assert!(error
        .to_string()
        .contains("visible content-conflict review"));
}
