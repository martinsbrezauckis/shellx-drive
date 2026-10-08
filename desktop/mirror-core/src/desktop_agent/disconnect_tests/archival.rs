use crate::{
    DesktopAgentDisconnectBlockedReason, DesktopAgentDisconnectPhase,
    DesktopAgentDisconnectUnconfirmedDisposition, DisconnectCleanupIntent,
};
use chrono::Utc;

use super::transitions::{retiring_continuation, state_with_cleanup};

#[test]
fn blocked_completion_archives_truth_and_allows_a_later_disconnect_continuation() {
    let mut state = state_with_cleanup();
    state
        .begin_desktop_agent_disconnect(retiring_continuation())
        .unwrap();
    state.mark_desktop_agent_disconnect_retired().unwrap();
    state
        .pending_disconnect_cleanup_mut()
        .unwrap()
        .confirm_remote_retirement();
    state = state.into_disconnected(Utc::now());
    state.finish_disconnect_cleanup().unwrap();
    state.mark_desktop_agent_disconnect_reporting().unwrap();
    state
        .block_desktop_agent_disconnect_completion(
            DesktopAgentDisconnectBlockedReason::CapabilityExpired,
        )
        .unwrap();
    state.archive_desktop_agent_disconnect_block().unwrap();

    assert!(state.pending_desktop_agent_disconnect().is_none());
    let archived = state.unconfirmed_desktop_agent_disconnect.as_ref().unwrap();
    assert_eq!(
        archived.disposition,
        DesktopAgentDisconnectUnconfirmedDisposition::CompletionBlocked
    );
    assert_eq!(
        archived.reason,
        DesktopAgentDisconnectBlockedReason::CapabilityExpired
    );

    state
        .desktop_agent_control
        .enroll("device_2".to_string(), None, "a".repeat(64))
        .unwrap();
    state
        .begin_disconnect_cleanup(
            DisconnectCleanupIntent::for_disconnect(None, Vec::new()).unwrap(),
        )
        .unwrap();
    state
        .begin_desktop_agent_disconnect(retiring_continuation())
        .unwrap();
    assert_eq!(
        state.pending_desktop_agent_disconnect().unwrap().phase,
        DesktopAgentDisconnectPhase::RetiringRemote
    );
}
