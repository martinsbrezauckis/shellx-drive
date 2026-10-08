use chrono::Utc;

use crate::{
    DesktopAgentCommandJournalState, DesktopAgentCommandKind, DesktopAgentDisconnectBlockedReason,
    DesktopAgentDisconnectPhase, DesktopAgentProgressPhase, DesktopAgentTerminalCode,
    DesktopAgentTerminalStatus,
};

use super::{retiring_continuation, state_with_cleanup};

#[test]
fn retirement_cancellation_retains_the_exact_terminal_across_a_crash_boundary() {
    let mut state = state_with_cleanup();
    let now = Utc::now();
    state
        .desktop_agent_control
        .record_lease(
            "command_1".to_string(),
            "lease_1".to_string(),
            DesktopAgentCommandKind::Disconnect,
            now,
        )
        .unwrap();
    state
        .desktop_agent_control
        .mark_acknowledged("command_1", now)
        .unwrap();
    let accepted_sequence = state
        .desktop_agent_control
        .begin_progress("command_1", DesktopAgentProgressPhase::Accepted, now)
        .unwrap();
    state
        .desktop_agent_control
        .mark_progress_reported(
            "command_1",
            accepted_sequence,
            DesktopAgentProgressPhase::Accepted,
            now,
        )
        .unwrap();
    state
        .begin_desktop_agent_disconnect(retiring_continuation())
        .unwrap();
    state
        .reserve_desktop_agent_disconnect_retirement_cancellation(now)
        .unwrap();

    let continuation = state.pending_desktop_agent_disconnect().unwrap();
    assert_eq!(
        continuation.phase,
        DesktopAgentDisconnectPhase::RetirementCancelled
    );
    assert_eq!(
        continuation.blocked_reason,
        Some(DesktopAgentDisconnectBlockedReason::CancellationRequested)
    );
    assert!(continuation.requires_capability_retry());
    assert!(continuation.blocks_new_pairing());
    assert!(state.desktop_agent_control.enabled);
    assert!(state.has_pending_disconnect_cleanup());
    assert_eq!(
        continuation
            .retire_assertion
            .as_ref()
            .and_then(|assertion| assertion.last_terminal_command_id.as_deref()),
        Some("command_1")
    );
    let persisted = serde_json::to_value(&state).unwrap();
    let mut state: crate::DesktopState = serde_json::from_value(persisted).unwrap();
    state
        .pending_desktop_agent_disconnect()
        .unwrap()
        .validate()
        .unwrap();
    state.desktop_agent_control.validate().unwrap();
    let retry = state
        .desktop_agent_control
        .terminal_reports()
        .unwrap()
        .pop()
        .unwrap();
    assert_eq!(retry.event_sequence, 3);
    assert_eq!(
        retry.terminal_status,
        DesktopAgentTerminalStatus::Interrupted
    );
    assert_eq!(
        retry.terminal_code,
        DesktopAgentTerminalCode::CancellationRequested
    );
    assert!(retry.result_code.is_none());
    assert!(retry.result.is_none());

    // A crash after reservation but before the broker's 204 must retain both
    // cleanup and the exact retry witness.
    assert!(state
        .finish_desktop_agent_disconnect_retirement_cancellation()
        .is_err());
    assert!(state.has_pending_disconnect_cleanup());
    assert!(state.pending_desktop_agent_disconnect().is_some());

    state
        .desktop_agent_control
        .mark_terminal_reported("command_1", now)
        .unwrap();
    state
        .finish_desktop_agent_disconnect_retirement_cancellation()
        .unwrap();
    assert!(state.pending_desktop_agent_disconnect().is_none());
    assert!(!state.has_pending_disconnect_cleanup());
    assert!(state.desktop_agent_control.enabled);
    assert_eq!(
        state.desktop_agent_control.command_journal[0].state,
        DesktopAgentCommandJournalState::Interrupted
    );
}
