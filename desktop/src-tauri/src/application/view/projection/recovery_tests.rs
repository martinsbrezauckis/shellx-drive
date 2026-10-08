use chrono::{Duration, Utc};
use shellx_drive_desktop_core::{
    DesktopState, DisconnectCleanupIntent, FakeCredentialStore, RemoteSessionRecord, StateStore,
    SyncPair, CANDIDATE_RECOVERY_PAUSED_ERROR,
};

use super::Runtime;
use crate::{application::runtime::tests::TestPlatform, session_identity::SessionIdentity};

fn candidate() -> RemoteSessionRecord {
    RemoteSessionRecord::new(
        "https://drive.example.test",
        "person@example.test",
        "retained-candidate",
        Utc::now() + Duration::hours(1),
    )
    .unwrap()
}

fn restored_runtime(state: DesktopState) -> (tempfile::TempDir, Runtime) {
    let directory = tempfile::tempdir().unwrap();
    let store = StateStore::new(directory.path().join("state.json"));
    store.save(&state).unwrap();
    let restored = store.load().unwrap();
    let runtime = Runtime::from_loaded_state(
        Box::new(TestPlatform(FakeCredentialStore::default())),
        store,
        restored,
    );
    runtime.set_candidate_recovery_pending(true);
    (directory, runtime)
}

#[test]
fn restarted_no_slot_candidate_projects_retained_identity_without_authentication() {
    let record = candidate();
    let (_directory, runtime) = restored_runtime(DesktopState {
        pending_candidate_session: Some(record.clone()),
        last_error: Some(CANDIDATE_RECOVERY_PAUSED_ERROR.to_string()),
        ..DesktopState::default()
    });
    assert!(runtime.session.lock().unwrap().is_none());
    let view = runtime.view();
    assert_eq!(view.status, "error");
    assert!(view.credential_recovery_pending);
    assert_eq!(view.account, record.account_email);
    assert_eq!(view.server_url, record.server_url);
    assert!(view.active_pair_id.is_none());
    assert!(view.local_root.is_empty());
    assert!(view.drive_location.is_empty());
    assert!(runtime.current_session().is_err());
    assert!(runtime.require_candidate_recovery_complete().is_err());
    let serialized = serde_json::to_value(view).unwrap();
    assert_eq!(serialized["credentialRecoveryPending"], true);
    assert!(serialized.get("password").is_none());
    assert!(serialized.get("bearerToken").is_none());
}

#[test]
fn candidate_identity_wins_over_a_stale_ephemeral_setup_session() {
    let record = candidate();
    let (_directory, runtime) = restored_runtime(DesktopState {
        active_remote_session: Some(record.clone()),
        ..DesktopState::default()
    });
    *runtime.session.lock().unwrap() = Some(SessionIdentity::new(
        "https://other.example.test",
        "other@example.test",
    ));
    let view = runtime.view();
    assert_eq!(view.account, record.account_email);
    assert_eq!(view.server_url, record.server_url);
}

#[test]
fn cached_recovery_identity_must_be_unique_and_does_not_fall_back_to_setup_session() {
    let (_directory, runtime) = restored_runtime(DesktopState::default());
    let first = SessionIdentity::new("https://drive.example.test", "person@example.test");
    let second = SessionIdentity::new("https://other.example.test", "other@example.test");
    *runtime.session.lock().unwrap() = Some(second.clone());
    assert!(runtime.view().account.is_empty());
    runtime.remember_candidate_recovery_identity(&first);
    assert_eq!(runtime.view().account, first.email);
    assert_eq!(runtime.view().server_url, first.server_url);
    runtime.remember_candidate_recovery_identity(&second);
    assert!(runtime.view().account.is_empty());
    assert!(runtime.view().server_url.is_empty());
    runtime.set_candidate_recovery_pending(false);
    let view = runtime.view();
    assert!(!view.credential_recovery_pending);
    assert_eq!(view.account, second.email);
}

#[test]
fn retained_pair_identity_and_disconnect_admission_survive_recovery_projection() {
    let record = candidate();
    let mut state = DesktopState {
        pair: Some(SyncPair {
            server_url: "https://paired.example.test".to_string(),
            account_email: "paired@example.test".to_string(),
            workspace_id: "workspace".to_string(),
            workspace_name: "Retained workspace".to_string(),
            remote_root_id: None,
            remote_root_name: None,
            local_root: std::path::PathBuf::from("retained-drive"),
            local_root_identity: None,
        }),
        pending_candidate_session: Some(record),
        ..DesktopState::default()
    };
    state
        .begin_disconnect_cleanup(
            DisconnectCleanupIntent::for_disconnect(state.pair.as_ref(), Vec::new()).unwrap(),
        )
        .unwrap();
    let (_directory, runtime) = restored_runtime(state);
    let view = runtime.view();
    assert_eq!(view.status, "error");
    assert_eq!(view.account, "paired@example.test");
    assert_eq!(view.server_url, "https://paired.example.test");
    assert!(view.credential_recovery_pending);
    assert!(view.disconnect_cleanup_pending);
    assert!(!view.disconnect_remote_retirement_confirmed);
    assert!(runtime.ensure_disconnect_cleanup_complete().is_err());
    assert!(runtime.require_candidate_recovery_complete().is_err());
}
