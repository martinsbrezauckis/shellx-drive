//! macOS planning-only recheck terminal regressions.

use std::path::PathBuf;

use shellx_drive_desktop_core::{
    DesktopState, LocalEntry, MirrorCoordinator, ReconcilePlan, ReviewAction, ReviewItem,
    ReviewKind, SyncAction, SyncPair,
};

use super::*;

#[test]
fn resolved_path_review_releases_pending_transfer_without_clearing_other_reviews() {
    let coordinator = MirrorCoordinator::new(DesktopState {
        pair: Some(pair()),
        ..DesktopState::default()
    });
    let mut path_only = coordinator.begin_run().expect("path review reservation");
    path_only.finish_with_reviews(vec![path_review()]);

    let transfer = upload_plan();
    let mut recheck = coordinator.begin_run().expect("recheck reservation");
    assert!(clear_resolved_path_review(&mut recheck, &transfer));
    assert!(recheck.state().reviews.is_empty());
    assert!(recheck.state().baseline.is_empty());
    assert!(recheck.state().last_successful_sync.is_none());
    let rechecked_state = recheck.state().clone();
    recheck.finish_state(rechecked_state);

    let mut mixed = coordinator.begin_run().expect("mixed review reservation");
    mixed.finish_with_reviews(vec![path_review(), content_conflict_review()]);
    let mut blocked = coordinator.begin_run().expect("mixed recheck reservation");
    assert!(!clear_resolved_path_review(&mut blocked, &transfer));
    assert_eq!(blocked.state().reviews.len(), 2);
}

fn pair() -> SyncPair {
    SyncPair {
        server_url: "https://drive.example.test".to_string(),
        account_email: "owner@example.test".to_string(),
        workspace_id: "workspace".to_string(),
        workspace_name: "Workspace".to_string(),
        remote_root_id: None,
        remote_root_name: None,
        local_root: PathBuf::from("/tmp/Drive"),
        local_root_identity: None,
    }
}

fn upload_plan() -> ReconcilePlan {
    ReconcilePlan {
        actions: vec![SyncAction::UploadNew {
            relative_path: PathBuf::from("ordinary.txt"),
            is_directory: false,
            local: LocalEntry {
                relative_path: PathBuf::from("ordinary.txt"),
                content_hash: Some("a".repeat(64)),
                size_bytes: 1,
                is_directory: false,
                directory_identity: None,
            },
        }],
        reviews: Vec::new(),
        remote_paths: Default::default(),
    }
}

fn path_review() -> ReviewItem {
    ReviewItem {
        id: "local-path:AUX.txt".to_string(),
        kind: ReviewKind::UnsafePath,
        relative_path: PathBuf::from("AUX.txt"),
        descendant_count: 0,
        is_directory: false,
        summary: "A local path was incompatible.".to_string(),
        actions: Vec::new(),
    }
}

fn content_conflict_review() -> ReviewItem {
    ReviewItem {
        id: "ContentConflict:ordinary.txt".to_string(),
        kind: ReviewKind::ContentConflict,
        relative_path: PathBuf::from("ordinary.txt"),
        descendant_count: 0,
        is_directory: false,
        summary: "Both copies changed.".to_string(),
        actions: vec![ReviewAction::OpenConflictCopies],
    }
}
