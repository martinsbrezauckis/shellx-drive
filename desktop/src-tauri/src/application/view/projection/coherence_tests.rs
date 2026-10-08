use chrono::Utc;
use shellx_drive_desktop_core::{
    DesktopState, DisconnectCleanupIntent, FakeCredentialStore, RemoteSessionRecord, StateStore,
    SyncPair,
};

use super::Runtime;
use crate::application::runtime::{tests::TestPlatform, PendingLogin};

fn pair() -> SyncPair {
    SyncPair {
        server_url: "https://drive.example.test".to_string(),
        account_email: "person@example.test".to_string(),
        workspace_id: "workspace".to_string(),
        workspace_name: "Shared work".to_string(),
        remote_root_id: Some("folder".to_string()),
        remote_root_name: Some("Reports".to_string()),
        local_root: std::path::PathBuf::from("Drive"),
        local_root_identity: None,
    }
}

#[test]
fn configured_root_overflow_is_visible_without_turning_success_into_an_error() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = Runtime::from_loaded_state(
        Box::new(TestPlatform(FakeCredentialStore::default())),
        StateStore::new(directory.path().join("state.json")),
        DesktopState {
            pair: Some(pair()),
            root_discovery_overflow: true,
            ..DesktopState::default()
        },
    );
    assert!(runtime.view().root_discovery_overflow);
    assert!(runtime.view().error.is_none());
}

#[test]
fn captured_pending_cleanup_view_does_not_mix_with_later_lifecycle_state() {
    let directory = tempfile::tempdir().expect("temporary state directory");
    let mut state = DesktopState {
        pair: Some(pair()),
        ..DesktopState::default()
    };
    let intent = DisconnectCleanupIntent::for_disconnect(state.pair.as_ref(), Vec::new()).unwrap();
    state.begin_disconnect_cleanup(intent).unwrap();
    let runtime = Runtime::from_loaded_state(
        Box::new(TestPlatform(FakeCredentialStore::default())),
        StateStore::new(directory.path().join("state.json")),
        state,
    );
    let captured = runtime.coordinator.view_snapshot();

    let mut completed = captured.state.clone().into_disconnected(Utc::now());
    let cleanup = completed.pending_disconnect_cleanup_mut().unwrap();
    cleanup.confirm_remote_retirement();
    cleanup.acknowledge_marker();
    completed.finish_disconnect_cleanup().unwrap();
    let mut operation = runtime.coordinator.begin_lifecycle_operation().unwrap();
    operation.finish_state(completed);

    let captured_view = runtime.view_from_coordinator_snapshot(captured);
    assert_eq!(captured_view.status, "error");
    assert!(captured_view.disconnect_cleanup_pending);
    assert!(captured_view.disconnect_available);
    assert!(captured_view.active_pair_id.is_some());
    assert_eq!(runtime.view().status, "needs_setup");
    assert!(!runtime.view().disconnect_available);
}

#[test]
fn saved_sign_in_before_first_pair_keeps_disconnect_available_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let store = StateStore::new(directory.path().join("state.json"));
    let mut state = DesktopState::default();
    state.publish_active_remote_session(RemoteSessionRecord {
        server_url: "https://drive.example.test".to_string(),
        account_email: "person@example.test".to_string(),
        session_id: "saved-sign-in".to_string(),
        expires_at: Utc::now() + chrono::Duration::hours(1),
    });
    store.save(&state).unwrap();
    let restored = store.load().unwrap();
    let runtime = Runtime::from_loaded_state(
        Box::new(TestPlatform(FakeCredentialStore::default())),
        store,
        restored,
    );

    assert!(runtime.session.lock().unwrap().is_none());
    let view = runtime.view();
    assert_eq!(view.status, "needs_setup");
    assert!(view.active_pair_id.is_none());
    assert!(view.local_root.is_empty());
    assert!(view.drive_location.is_empty());
    assert!(view.disconnect_available);
    let serialized = serde_json::to_value(&view).unwrap();
    assert_eq!(serialized["disconnectAvailable"], true);
    assert!(!runtime.coordinator.snapshot().uninstall_cleanup_ready());
}

#[test]
fn unfinished_sign_in_can_be_canceled_without_creating_a_pair() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = Runtime::from_loaded_state(
        Box::new(TestPlatform(FakeCredentialStore::default())),
        StateStore::new(directory.path().join("state.json")),
        DesktopState::default(),
    );
    *runtime.pending_login.lock().unwrap() = Some(PendingLogin {
        server_url: "https://drive.example.test".to_string(),
        email: "person@example.test".to_string(),
        password: "fixture-password".to_string(),
        generation: 1,
    });
    assert!(runtime.view().disconnect_available);
    assert!(runtime.view().local_root.is_empty());

    *runtime.pending_login.lock().unwrap() = None;
    assert!(!runtime.view().disconnect_available);
    assert!(runtime.coordinator.snapshot().uninstall_cleanup_ready());
}

#[test]
fn retained_candidate_and_revocation_without_a_pair_offer_normal_disconnect() {
    let directory = tempfile::tempdir().unwrap();
    let record = RemoteSessionRecord {
        server_url: "https://drive.example.test".to_string(),
        account_email: "person@example.test".to_string(),
        session_id: "retained-session".to_string(),
        expires_at: Utc::now() + chrono::Duration::hours(1),
    };
    for state in [
        DesktopState {
            pending_candidate_session: Some(record.clone()),
            ..DesktopState::default()
        },
        DesktopState {
            pending_remote_revocations: vec![record.clone()],
            ..DesktopState::default()
        },
    ] {
        let runtime = Runtime::from_loaded_state(
            Box::new(TestPlatform(FakeCredentialStore::default())),
            StateStore::new(directory.path().join("state.json")),
            state,
        );
        assert!(runtime.view().active_pair_id.is_none());
        assert!(runtime.view().disconnect_available);
        assert!(!runtime.coordinator.snapshot().uninstall_cleanup_ready());
    }
}
