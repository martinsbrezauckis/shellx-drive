//! Linux local-path planning and planning-only recheck regression.

use std::{collections::BTreeMap, fs, path::PathBuf};

use chrono::Utc;
use shellx_drive_desktop_core::{
    inspect_local_tree, plan_reconciliation, DesktopState, MirrorCoordinator, SyncPair, SyncStatus,
};

use super::*;

#[test]
fn incompatible_local_path_blocks_upload_until_a_later_sync() {
    let directory = tempfile::tempdir().expect("local root");
    fs::write(directory.path().join("AUX.txt"), b"reserved name").expect("unsafe file");
    fs::write(directory.path().join("ordinary.txt"), b"upload me").expect("ordinary file");

    let incompatible = inspect_local_tree(directory.path()).expect("bounded scan");
    let planned = plan_reconciliation(
        &BTreeMap::new(),
        None,
        &[],
        &incompatible.entries,
        Utc::now(),
    )
    .expect("ordinary upload plan");
    let blocked = plan_with_local_path_reviews(planned, &incompatible.issues);
    assert!(blocked.actions.is_empty());
    assert_eq!(blocked.reviews.len(), 1);
    assert_eq!(blocked.reviews[0].kind, ReviewKind::UnsafePath);
    assert_eq!(blocked.reviews[0].relative_path, PathBuf::from("AUX.txt"));

    let coordinator = MirrorCoordinator::new(DesktopState {
        pair: Some(pair(directory.path().to_path_buf())),
        ..DesktopState::default()
    });
    let mut initial = coordinator.begin_run().expect("review reservation");
    initial.finish_with_reviews(blocked.reviews);
    assert_eq!(coordinator.status(true), SyncStatus::NeedsReview);

    fs::remove_file(directory.path().join("AUX.txt")).expect("remove incompatible path");
    let corrected = inspect_local_tree(directory.path()).expect("bounded corrected scan");
    let pending_transfer =
        plan_reconciliation(&BTreeMap::new(), None, &[], &corrected.entries, Utc::now())
            .expect("upload remains planned");
    assert!(pending_transfer.requires_transfer());

    let mut recheck = coordinator.begin_run().expect("recheck reservation");
    assert!(clear_resolved_path_review(&mut recheck, &pending_transfer));
    assert!(recheck.state().reviews.is_empty());
    assert!(recheck.state().baseline.is_empty());
    assert!(recheck.state().last_successful_sync.is_none());
    let rechecked_state = recheck.state().clone();
    recheck.finish_state(rechecked_state);
}

fn pair(local_root: PathBuf) -> SyncPair {
    SyncPair {
        server_url: "https://drive.example.test".to_string(),
        account_email: "owner@example.test".to_string(),
        workspace_id: "workspace".to_string(),
        workspace_name: "Workspace".to_string(),
        remote_root_id: None,
        remote_root_name: None,
        local_root,
        local_root_identity: None,
    }
}
