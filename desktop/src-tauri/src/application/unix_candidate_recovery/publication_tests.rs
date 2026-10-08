use chrono::{Duration, Utc};
use shellx_drive_desktop_core::{
    DisconnectCleanupIntent, FakeCredentialStore, StateStore, CANDIDATE_RECOVERY_PAUSED_ERROR,
};

use super::*;
use crate::application::{runtime::tests::TestPlatform, Runtime};

fn published_state(error: &str) -> DesktopState {
    DesktopState {
        active_remote_session: Some(
            RemoteSessionRecord::new(
                "https://drive.example.test",
                "person@example.test",
                "published-session",
                Utc::now() + Duration::hours(1),
            )
            .unwrap(),
        ),
        last_error: Some(error.to_string()),
        ..DesktopState::default()
    }
}

#[test]
fn converged_publication_persists_only_the_known_recovery_error_clearance() {
    let directory = tempfile::tempdir().unwrap();
    let store = StateStore::new(directory.path().join("state.json"));
    for error in [CANDIDATE_RECOVERY_PAUSED_ERROR, "unrelated root failure"] {
        let mut state = published_state(error);
        let active = state.active_remote_session.clone();
        store.save(&state).unwrap();
        persist_converged_candidate_state(&mut state, Vec::new(), |image| store.save(image))
            .unwrap();
        let restored = store.load().unwrap();
        let expected_error = (error != CANDIDATE_RECOVERY_PAUSED_ERROR).then(|| error.to_string());
        assert_eq!(state.last_error, expected_error);
        assert_eq!(restored.last_error, expected_error);
        assert_eq!(restored.active_remote_session, active);
    }
}

#[test]
fn failed_clearance_save_retains_persisted_error_and_runtime_admission_latch() {
    let directory = tempfile::tempdir().unwrap();
    let store = StateStore::new(directory.path().join("state.json"));
    let initial = published_state(CANDIDATE_RECOVERY_PAUSED_ERROR);
    store.save(&initial).unwrap();
    let runtime = Runtime::from_loaded_state(
        Box::new(TestPlatform(FakeCredentialStore::default())),
        store,
        initial,
    );
    runtime.set_candidate_recovery_pending(true);
    let mut operation = runtime.coordinator.begin_lifecycle_operation().unwrap();
    let mut state = runtime.coordinator.snapshot();
    assert!(
        persist_converged_candidate_state(&mut state, Vec::new(), |_| { Err(recovery_error()) })
            .is_err()
    );
    operation.finish_state(state);
    assert_eq!(
        runtime.store.load().unwrap().last_error.as_deref(),
        Some(CANDIDATE_RECOVERY_PAUSED_ERROR)
    );
    assert_eq!(runtime.view().status, "error");
    assert!(runtime.view().credential_recovery_pending);
    assert!(runtime.require_candidate_recovery_complete().is_err());
    assert_eq!(
        runtime.coordinator.snapshot().last_error.as_deref(),
        Some(CANDIDATE_RECOVERY_PAUSED_ERROR)
    );
}

#[test]
fn incomplete_candidate_or_disconnect_state_never_clears_or_saves_the_error() {
    for condition in ["locator", "slot", "disconnect"] {
        let mut state = published_state(CANDIDATE_RECOVERY_PAUSED_ERROR);
        let pending_keys = if condition == "slot" {
            vec!["remaining-staged-slot".to_string()]
        } else {
            Vec::new()
        };
        if condition == "locator" {
            state.pending_candidate_session = state.active_remote_session.clone();
        }
        if condition == "disconnect" {
            state
                .begin_disconnect_cleanup(
                    DisconnectCleanupIntent::for_disconnect(None, Vec::new()).unwrap(),
                )
                .unwrap();
        }
        assert!(
            persist_converged_candidate_state(&mut state, pending_keys, |_| {
                panic!("incomplete recovery must not persist error clearance")
            })
            .is_err()
        );
        assert_eq!(
            state.last_error.as_deref(),
            Some(CANDIDATE_RECOVERY_PAUSED_ERROR)
        );
    }
}
