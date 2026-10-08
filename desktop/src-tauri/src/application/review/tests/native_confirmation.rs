use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use chrono::Utc;
use shellx_drive_desktop_core::{ReviewItem, ReviewKind, SyncPair};

use super::super::native::{execute_after_native_choice, native_review_prompt};
use super::*;

#[test]
fn native_prompt_binds_the_pending_action_and_escapes_the_reviewed_path() {
    let directory = tempfile::tempdir().expect("temporary state directory");
    let runtime = Runtime::from_loaded_state(
        Box::new(TestPlatform(FakeCredentialStore::default())),
        StateStore::new(directory.path().join("state.json")),
        DesktopState {
            pair: Some(SyncPair {
                server_url: "https://drive.example.test".to_string(),
                account_email: "person@example.test".to_string(),
                workspace_id: "workspace".to_string(),
                workspace_name: "Shared work".to_string(),
                remote_root_id: Some("folder".to_string()),
                remote_root_name: Some("Reports".to_string()),
                local_root: directory.path().join("Drive"),
                local_root_identity: None,
            }),
            reviews: vec![ReviewItem {
                id: "review".to_string(),
                kind: ReviewKind::RemoteDeletion,
                relative_path: "Reports/quarterly\nplan.txt".into(),
                descendant_count: 0,
                is_directory: false,
                summary: "Drive removed this file".to_string(),
                actions: vec![ReviewAction::RemoveLocalCopy, ReviewAction::RestoreToDrive],
            }],
            ..DesktopState::default()
        },
    );
    let prepared = prepare_review_confirmation(
        &runtime,
        "review".to_string(),
        ReviewAction::RemoveLocalCopy,
    )
    .expect("valid review can be prepared");
    let prompt = native_review_prompt(
        &runtime,
        "review",
        ReviewAction::RemoveLocalCopy,
        &prepared.confirmation_id,
    )
    .expect("matching pending action has a native prompt");
    assert!(prompt.contains("Move this local copy to recovery"));
    assert!(prompt.contains("Drive location: \"Reports\""));
    assert!(prompt.contains("quarterly\\nplan.txt"));
    assert!(!prompt.contains("quarterly\nplan.txt"));
    assert!(native_review_prompt(
        &runtime,
        "review",
        ReviewAction::RestoreToDrive,
        &prepared.confirmation_id,
    )
    .is_err());
    assert!(native_review_prompt(
        &runtime,
        "review",
        ReviewAction::RemoveLocalCopy,
        "renderer-chosen-id",
    )
    .is_err());
    runtime
        .pending_review_confirmation
        .lock()
        .expect("review confirmation lock")
        .as_mut()
        .expect("pending review")
        .expires_at = Utc::now() - chrono::Duration::seconds(1);
    assert!(native_review_prompt(
        &runtime,
        "review",
        ReviewAction::RemoveLocalCopy,
        &prepared.confirmation_id,
    )
    .is_err());
}

#[tokio::test]
async fn native_denial_never_calls_the_review_executor_and_approval_calls_it_once() {
    let calls = Arc::new(AtomicUsize::new(0));
    let denied_calls = Arc::clone(&calls);
    let error = execute_after_native_choice(false, move || async move {
        denied_calls.fetch_add(1, Ordering::SeqCst);
        Ok::<_, String>(())
    })
    .await
    .expect_err("cancel or dialog failure must stop before the executor");
    assert!(error.contains("cancelled"));
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let approved_calls = Arc::clone(&calls);
    execute_after_native_choice(true, move || async move {
        approved_calls.fetch_add(1, Ordering::SeqCst);
        Ok::<_, String>(())
    })
    .await
    .expect("native approval preserves the legitimate review route");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
