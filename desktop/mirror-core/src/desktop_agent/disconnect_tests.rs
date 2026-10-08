use chrono::Utc;

#[path = "disconnect_tests/archival.rs"]
mod archival;
#[path = "disconnect_tests/transitions.rs"]
mod transitions;

use crate::{
    DesktopAgentDisconnectContinuation, DesktopAgentDisconnectPhase, DesktopState,
    DisconnectCleanupIntent,
};

#[test]
fn disconnected_projection_retains_only_the_reporting_locator() {
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

    let disconnected = state.into_disconnected(Utc::now());
    assert!(disconnected.pair.is_none());
    assert!(!disconnected.desktop_agent_control.enabled);
    assert_eq!(
        disconnected
            .pending_desktop_agent_disconnect()
            .unwrap()
            .completion_event_sequence,
        3
    );
}

#[test]
fn completion_needs_reporting_phase_after_local_cleanup() {
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

    assert!(state.finish_desktop_agent_disconnect().is_err());
}

#[test]
fn legacy_disconnect_continuation_without_a_lease_deadline_remains_loadable() {
    let mut continuation = transitions::retiring_continuation();
    continuation.completion_expires_at = Utc::now() - chrono::Duration::days(367);
    continuation.retirement_expires_at = None;
    let serialized = serde_json::to_value(continuation).unwrap();
    assert!(serialized.get("retirement_expires_at").is_none());
    let restored: DesktopAgentDisconnectContinuation = serde_json::from_value(serialized).unwrap();
    assert!(restored.retirement_expires_at.is_none());
    restored.validate().unwrap();
}
