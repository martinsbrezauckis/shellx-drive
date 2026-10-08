use chrono::Utc;
use shellx_drive_desktop_core::{
    DesktopAgentCommandJournalState, DesktopAgentCommandKind, DesktopAgentControlState,
    DesktopAgentProgressPhase, DesktopAgentTerminalCode, DesktopAgentTerminalStatus, DesktopState,
};

use super::matching_agent_restart_candidate;

#[test]
fn accepted_crash_unproven_terminal_clears_only_its_matching_restart_intent() {
    let now = Utc::now();
    let mut state = DesktopState::default();
    state
        .record_desktop_update_restart_for_agent(
            "1.2.3".to_string(),
            "candidate_1".to_string(),
            "command_1".to_string(),
        )
        .unwrap();

    assert_eq!(matching_agent_restart_candidate(&state, "command_2"), None,);
    let candidate_id = matching_agent_restart_candidate(&state, "command_1").unwrap();
    assert!(state.pending_desktop_update_restart.is_some());

    let mut control = DesktopAgentControlState::default();
    control
        .record_lease(
            "command_1".to_string(),
            "lease_1".to_string(),
            DesktopAgentCommandKind::InstallDesktopUpdate,
            now,
        )
        .unwrap();
    control.mark_acknowledged("command_1", now).unwrap();
    let sequence = control
        .begin_progress("command_1", DesktopAgentProgressPhase::Accepted, now)
        .unwrap();
    control
        .mark_progress_reported(
            "command_1",
            sequence,
            DesktopAgentProgressPhase::Accepted,
            now,
        )
        .unwrap();
    let retry = control.interrupt_after_restart(now).pop().unwrap();
    assert_eq!(
        retry.terminal_status,
        DesktopAgentTerminalStatus::Interrupted
    );
    assert_eq!(retry.terminal_code, DesktopAgentTerminalCode::CrashUnproven);
    assert_eq!(retry.event_sequence, 3);
    assert!(retry.result.is_none());
    assert!(state.pending_desktop_update_restart.is_some());

    // This occurs only after the matching terminal POST returned 204.
    control.mark_terminal_reported("command_1", now).unwrap();
    assert_eq!(
        control.command_journal[0].state,
        DesktopAgentCommandJournalState::Interrupted
    );
    assert!(control.terminal_reports().unwrap().is_empty());
    state
        .complete_desktop_update_restart_for_agent(&candidate_id, "command_1")
        .unwrap();
    assert!(state.pending_desktop_update_restart.is_none());
}
