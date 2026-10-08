//! Durable Desktop-agent Disconnect state-transition coverage.

use chrono::Utc;
use tempfile::tempdir;

use crate::{
    DesktopAgentDisconnectContinuation, DesktopAgentDisconnectPhase, DesktopError, DesktopState,
    DisconnectCleanupIntent, StateStore,
};

fn local_cleanup_state() -> DesktopState {
    let mut state = DesktopState::default();
    state
        .begin_disconnect_cleanup(
            DisconnectCleanupIntent::for_disconnect(None, Vec::new()).unwrap(),
        )
        .unwrap();
    state
        .begin_desktop_agent_disconnect(DesktopAgentDisconnectContinuation {
            canonical_server_origin: "https://drive.example.test".to_string(),
            command_id: "command_1".to_string(),
            lease_id: "lease_1".to_string(),
            retirement_expires_at: None,
            completion_expires_at: Utc::now() + chrono::Duration::hours(1),
            completion_event_sequence: 3,
            phase: DesktopAgentDisconnectPhase::LocalCleanup,
            retire_assertion: None,
            bound_owner_session: None,
            terminal_receipt: None,
            blocked_reason: None,
        })
        .unwrap();
    state
        .pending_disconnect_cleanup_mut()
        .unwrap()
        .confirm_remote_retirement();
    state.into_disconnected(Utc::now())
}

#[test]
fn local_cleanup_intermediate_cannot_cross_the_state_store_boundary() {
    let directory = tempdir().unwrap();
    let store = StateStore::new(directory.path().join("state.json"));
    let mut state = local_cleanup_state();
    store.save(&state).unwrap();

    state.finish_disconnect_cleanup().unwrap();
    assert!(matches!(
        store.save(&state),
        Err(DesktopError::InvalidState(message))
            if message == "desktop-agent Disconnect continuation does not match local cleanup state"
    ));
}

#[test]
fn agent_cleanup_reporting_transition_saves_and_reloads_atomically() {
    let directory = tempdir().unwrap();
    let store = StateStore::new(directory.path().join("state.json"));
    let mut state = local_cleanup_state();
    store.save(&state).unwrap();

    state.finish_agent_disconnect_cleanup().unwrap();
    store.save(&state).unwrap();

    let restored = store.load().unwrap();
    assert!(!restored.has_pending_disconnect_cleanup());
    assert_eq!(
        restored.pending_desktop_agent_disconnect().unwrap().phase,
        DesktopAgentDisconnectPhase::Reporting
    );
}

#[test]
fn ordinary_cleanup_finish_still_saves_without_an_agent_continuation() {
    let directory = tempdir().unwrap();
    let store = StateStore::new(directory.path().join("state.json"));
    let mut state = DesktopState::default();
    state
        .begin_disconnect_cleanup(
            DisconnectCleanupIntent::for_disconnect(None, Vec::new()).unwrap(),
        )
        .unwrap();
    state
        .pending_disconnect_cleanup_mut()
        .unwrap()
        .confirm_remote_retirement();
    store.save(&state).unwrap();

    state.finish_disconnect_cleanup().unwrap();
    store.save(&state).unwrap();
    assert!(!store.load().unwrap().has_pending_disconnect_cleanup());
}
