use chrono::Utc;
use shellx_drive_desktop_core::{
    sync_pair_id, BaselineEntry, DesktopState, FakeCredentialStore, ReviewItem, ReviewKind,
    StateStore, SyncPair,
};

use super::*;
use crate::application::runtime::PendingReviewConfirmation;

use super::tests::TestPlatform;

#[test]
fn native_review_id_is_an_exact_pending_lookup_with_pair_action_witness_and_expiry_guards() {
    let directory = tempfile::tempdir().unwrap();
    let review_id = "LocalDeletion:nested/file name.txt";
    let path = std::path::PathBuf::from("nested").join("file name.txt");
    let pair = SyncPair {
        server_url: "https://drive.example.test".to_string(),
        account_email: "person@example.test".to_string(),
        workspace_id: "workspace".to_string(),
        workspace_name: "Shared work".to_string(),
        remote_root_id: Some("folder".to_string()),
        remote_root_name: Some("Reports".to_string()),
        local_root: directory.path().join("Drive"),
        local_root_identity: None,
    };
    let pair_id = sync_pair_id(&pair);
    let runtime = Runtime::from_loaded_state(
        Box::new(TestPlatform(FakeCredentialStore::default())),
        StateStore::new(directory.path().join("state.json")),
        DesktopState {
            pair: Some(pair),
            baseline: std::collections::BTreeMap::from([(
                "file".to_string(),
                BaselineEntry {
                    remote_id: "file".to_string(),
                    parent_id: Some("folder".to_string()),
                    relative_path: path.clone(),
                    kind: "file".to_string(),
                    content_hash: Some("unchanged".to_string()),
                    revision: 1,
                    directory_identity: None,
                },
            )]),
            reviews: vec![ReviewItem {
                id: review_id.to_string(),
                kind: ReviewKind::LocalDeletion,
                relative_path: path.clone(),
                descendant_count: 0,
                is_directory: false,
                summary: "Deleted locally".to_string(),
                actions: vec![
                    ReviewAction::RestoreLocalCopy,
                    ReviewAction::DeleteFromDrive,
                ],
            }],
            ..DesktopState::default()
        },
    );
    let prepared = prepare_review_confirmation_for_pair(
        &runtime,
        pair_id.clone(),
        review_id.to_string(),
        ReviewAction::RestoreLocalCopy,
    )
    .unwrap();
    assert_eq!(prepared.relative_path, path);
    ensure_review_confirmation_pair(
        &runtime,
        &pair_id,
        review_id,
        ReviewAction::RestoreLocalCopy,
        &prepared.confirmation_id,
        &prepared.fingerprint,
    )
    .unwrap();
    for invented in [
        "arbitrary",
        "../nested/file name.txt",
        "/outside/file name.txt",
        "LocalDeletion:nested/other.txt",
        "LocalDeletion:nested/file\nname.txt",
    ] {
        assert!(prepare_review_confirmation_for_pair(
            &runtime,
            pair_id.clone(),
            invented.to_string(),
            ReviewAction::RestoreLocalCopy
        )
        .is_err());
        assert!(ensure_review_confirmation_pair(
            &runtime,
            &pair_id,
            invented,
            ReviewAction::RestoreLocalCopy,
            &prepared.confirmation_id,
            &prepared.fingerprint
        )
        .is_err());
    }
    assert!(ensure_review_confirmation_pair(
        &runtime,
        "different-pair",
        review_id,
        ReviewAction::RestoreLocalCopy,
        &prepared.confirmation_id,
        &prepared.fingerprint
    )
    .is_err());
    assert!(ensure_review_confirmation_pair(
        &runtime,
        &pair_id,
        review_id,
        ReviewAction::DeleteFromDrive,
        &prepared.confirmation_id,
        &prepared.fingerprint
    )
    .is_err());
    assert!(ensure_review_confirmation_pair(
        &runtime,
        &pair_id,
        review_id,
        ReviewAction::RestoreLocalCopy,
        "stale-confirmation",
        &prepared.fingerprint
    )
    .is_err());
    assert!(ensure_review_confirmation_pair(
        &runtime,
        &pair_id,
        review_id,
        ReviewAction::RestoreLocalCopy,
        &prepared.confirmation_id,
        &"b".repeat(64)
    )
    .is_err());
    assert!(super::native::native_review_prompt(
        &runtime,
        review_id,
        ReviewAction::RestoreLocalCopy,
        &prepared.confirmation_id
    )
    .is_ok());
    let mut operation = runtime.coordinator.begin_lifecycle_operation().unwrap();
    let mut changed = runtime.coordinator.snapshot();
    changed.baseline.get_mut("file").unwrap().revision = 2;
    operation.finish_state(changed);
    assert!(super::native::native_review_prompt(
        &runtime,
        review_id,
        ReviewAction::RestoreLocalCopy,
        &prepared.confirmation_id
    )
    .is_err());
    runtime
        .pending_review_confirmation
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .expires_at = Utc::now() - chrono::Duration::seconds(1);
    assert!(ensure_review_confirmation_pair(
        &runtime,
        &pair_id,
        review_id,
        ReviewAction::RestoreLocalCopy,
        &prepared.confirmation_id,
        &prepared.fingerprint
    )
    .is_err());
}

#[test]
fn agent_confirmation_rejects_an_unbound_fingerprint_before_execution() {
    let directory = tempfile::tempdir().expect("temporary state directory");
    let pair = SyncPair {
        server_url: "https://drive.example.test".to_string(),
        account_email: "person@example.test".to_string(),
        workspace_id: "workspace".to_string(),
        workspace_name: "Shared work".to_string(),
        remote_root_id: Some("folder".to_string()),
        remote_root_name: Some("Reports".to_string()),
        local_root: directory.path().join("Drive"),
        local_root_identity: None,
    };
    let pair_id = sync_pair_id(&pair);
    let runtime = Runtime::from_loaded_state(
        Box::new(TestPlatform(FakeCredentialStore::default())),
        StateStore::new(directory.path().join("state.json")),
        DesktopState {
            pair: Some(pair),
            ..DesktopState::default()
        },
    );
    let expected_fingerprint = "a".repeat(64);
    *runtime
        .pending_review_confirmation
        .lock()
        .expect("review confirmation lock") = Some(PendingReviewConfirmation {
        id: "review-confirmation".to_string(),
        review_id: "review".to_string(),
        action: ReviewAction::RemoveLocalCopy,
        pair_id: pair_id.clone(),
        fingerprint: expected_fingerprint.clone(),
        expires_at: Utc::now() + chrono::Duration::seconds(30),
    });

    let error = ensure_review_confirmation_pair(
        &runtime,
        &pair_id,
        "review",
        ReviewAction::RemoveLocalCopy,
        "review-confirmation",
        &"b".repeat(64),
    )
    .expect_err("the terminal witness must match the prepared confirmation");
    assert!(error.to_string().contains("witness"));

    ensure_review_confirmation_pair(
        &runtime,
        &pair_id,
        "review",
        ReviewAction::RemoveLocalCopy,
        "review-confirmation",
        &expected_fingerprint,
    )
    .expect("the exact prepared witness remains executable");
}
