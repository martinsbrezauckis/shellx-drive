use chrono::{Duration, Utc};

use crate::{
    DesktopAgentDeviceAssertion, DesktopAgentDisconnectBlockedReason,
    DesktopAgentDisconnectContinuation, DesktopAgentDisconnectPhase,
    DesktopAgentDisconnectTerminalReceipt, DesktopAgentObservedStatus, DesktopState,
    DisconnectCleanupIntent, RemoteSessionRecord,
};

#[path = "transitions/cancellation.rs"]
mod cancellation;

pub(super) fn retiring_continuation() -> DesktopAgentDisconnectContinuation {
    DesktopAgentDisconnectContinuation {
        canonical_server_origin: "https://drive.example.test".to_string(),
        command_id: "command_1".to_string(),
        lease_id: "lease_1".to_string(),
        retirement_expires_at: Some(Utc::now() + Duration::seconds(45)),
        completion_expires_at: Utc::now() + Duration::minutes(10),
        completion_event_sequence: 3,
        phase: DesktopAgentDisconnectPhase::RetiringRemote,
        retire_assertion: Some(DesktopAgentDeviceAssertion {
            app_version: "1.0.0".to_string(),
            pair_fingerprint: "a".repeat(64),
            status: DesktopAgentObservedStatus::Ready,
            pending_disconnect_cleanup: true,
            candidate_recovery: false,
            last_terminal_command_id: None,
        }),
        bound_owner_session: Some(
            RemoteSessionRecord::new(
                "https://drive.example.test",
                "owner@example.test",
                "session_1",
                Utc::now() + Duration::hours(1),
            )
            .unwrap(),
        ),
        terminal_receipt: None,
        blocked_reason: None,
    }
}

pub(super) fn state_with_cleanup() -> DesktopState {
    let mut state = DesktopState::default();
    state
        .begin_disconnect_cleanup(
            DisconnectCleanupIntent::for_disconnect(None, Vec::new()).unwrap(),
        )
        .unwrap();
    state
        .desktop_agent_control
        .enroll("device_1".to_string(), None, "a".repeat(64))
        .unwrap();
    state
}

#[test]
fn retiring_remote_persists_the_exact_retry_witness_before_rpc() {
    let mut state = state_with_cleanup();
    let continuation = retiring_continuation();
    state
        .begin_desktop_agent_disconnect(continuation.clone())
        .unwrap();

    assert_eq!(
        state.pending_desktop_agent_disconnect(),
        Some(&continuation)
    );
    assert_eq!(
        continuation.canonical_server_origin,
        "https://drive.example.test"
    );
    assert_eq!(continuation.command_id, "command_1");
    assert_eq!(continuation.lease_id, "lease_1");
    assert!(continuation.completion_expires_at > Utc::now());
    assert_eq!(continuation.completion_event_sequence, 3);
    assert!(continuation.retire_assertion.is_some());
    assert!(continuation.bound_owner_session.is_some());
    assert!(continuation.blocks_new_pairing());
    continuation.validate().unwrap();
}

#[test]
fn retirement_acceptance_discards_witness_only_after_remote_commit() {
    let mut state = state_with_cleanup();
    state
        .begin_desktop_agent_disconnect(retiring_continuation())
        .unwrap();
    state.mark_desktop_agent_disconnect_retired().unwrap();

    let continuation = state.pending_desktop_agent_disconnect().unwrap();
    assert_eq!(
        continuation.phase,
        DesktopAgentDisconnectPhase::LocalCleanup
    );
    assert!(continuation.retire_assertion.is_none());
    assert!(continuation.bound_owner_session.is_none());
    assert!(state.has_pending_disconnect_cleanup());
}

#[test]
fn terminal_receipt_is_durable_before_continuation_is_cleared() {
    let mut state = state_with_cleanup();
    state
        .begin_desktop_agent_disconnect(retiring_continuation())
        .unwrap();
    state.mark_desktop_agent_disconnect_retired().unwrap();
    state = state.into_disconnected(Utc::now());
    state
        .pending_disconnect_cleanup_mut()
        .unwrap()
        .confirm_remote_retirement();
    state.finish_disconnect_cleanup().unwrap();
    state.mark_desktop_agent_disconnect_reporting().unwrap();

    state
        .record_desktop_agent_disconnect_terminal(DesktopAgentDisconnectTerminalReceipt::Completed)
        .unwrap();
    assert_eq!(
        state.pending_desktop_agent_disconnect().unwrap().phase,
        DesktopAgentDisconnectPhase::TerminalAccepted
    );
    assert_eq!(
        state
            .pending_desktop_agent_disconnect()
            .unwrap()
            .terminal_receipt,
        Some(DesktopAgentDisconnectTerminalReceipt::Completed)
    );
    assert!(state
        .pending_desktop_agent_disconnect()
        .unwrap()
        .requires_capability_retry());
    assert!(!state.desktop_agent_control.enabled);
    state.finish_desktop_agent_disconnect().unwrap();
    assert!(state.pending_desktop_agent_disconnect().is_none());
}

#[test]
fn retirement_block_preserves_unconfirmed_cleanup_and_control() {
    let mut state = state_with_cleanup();
    state
        .begin_desktop_agent_disconnect(retiring_continuation())
        .unwrap();
    state
        .block_desktop_agent_disconnect_retirement(
            DesktopAgentDisconnectBlockedReason::AuthorizationLost,
        )
        .unwrap();

    let continuation = state.pending_desktop_agent_disconnect().unwrap();
    assert_eq!(
        continuation.phase,
        DesktopAgentDisconnectPhase::RetirementBlocked
    );
    assert_eq!(
        continuation.blocked_reason,
        Some(DesktopAgentDisconnectBlockedReason::AuthorizationLost)
    );
    assert!(continuation.requires_capability_retry());
    assert!(continuation.blocks_new_pairing());
    assert!(state.desktop_agent_control.enabled);
    assert!(state.has_pending_disconnect_cleanup());
}

#[test]
fn blocked_completion_preserves_truth_without_blocking_new_pairing() {
    let mut state = state_with_cleanup();
    state
        .begin_desktop_agent_disconnect(retiring_continuation())
        .unwrap();
    state.mark_desktop_agent_disconnect_retired().unwrap();
    state = state.into_disconnected(Utc::now());
    state
        .pending_disconnect_cleanup_mut()
        .unwrap()
        .confirm_remote_retirement();
    state.finish_disconnect_cleanup().unwrap();
    state.mark_desktop_agent_disconnect_reporting().unwrap();
    state
        .block_desktop_agent_disconnect_completion(
            DesktopAgentDisconnectBlockedReason::CapabilityExpired,
        )
        .unwrap();

    let continuation = state.pending_desktop_agent_disconnect().unwrap();
    assert_eq!(
        continuation.phase,
        DesktopAgentDisconnectPhase::CompletionBlocked
    );
    assert!(!continuation.blocks_new_pairing());
    assert!(continuation.requires_capability_retry());
    assert!(!state.desktop_agent_control.enabled);
    assert!(!state.has_pending_disconnect_cleanup());
}
