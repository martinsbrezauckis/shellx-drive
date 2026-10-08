use chrono::Utc;

use super::*;

#[test]
fn cancellation_replaces_a_pending_success_without_changing_its_sequence() {
    let now = Utc::now();
    let mut control = enrolled_control(DesktopAgentCommandKind::SetPaused);
    control
        .mark_terminal(
            "command_1",
            DesktopAgentTerminalStatus::Succeeded,
            DesktopAgentTerminalCode::Completed,
            Some(DesktopAgentResultCode::PausePersisted),
            Some(DesktopAgentResultPayload::Pause { paused: true }),
            now,
        )
        .unwrap();

    let replacement = control
        .replace_pending_terminal_with_cancellation("command_1", now)
        .unwrap();
    assert_eq!(replacement.event_sequence, 3);
    assert_eq!(
        replacement.terminal_code,
        DesktopAgentTerminalCode::CancellationRequested
    );
    assert!(replacement.result_code.is_none());
    assert!(replacement.result.is_none());
    assert_eq!(control.next_event_sequence("command_1").unwrap(), 4);
    assert_eq!(control.terminal_reports().unwrap(), vec![replacement]);
}

#[test]
fn cancellation_replaces_an_unreported_progress_in_its_reserved_event_slot() {
    let now = Utc::now();
    let mut control = enrolled_control(DesktopAgentCommandKind::SyncNow);
    let event_sequence = control
        .begin_progress("command_1", DesktopAgentProgressPhase::Syncing, now)
        .unwrap();

    let replacement = control
        .replace_pending_progress_with_cancellation("command_1", event_sequence, now)
        .unwrap();
    assert_eq!(replacement.event_sequence, event_sequence);
    assert_eq!(
        replacement.terminal_code,
        DesktopAgentTerminalCode::CancellationRequested
    );
    assert!(replacement.result.is_none());
    assert!(control.pending_progress_reports().unwrap().is_empty());
    assert_eq!(control.next_event_sequence("command_1").unwrap(), 4);
    assert_eq!(
        control.last_terminal_command_id.as_deref(),
        Some("command_1")
    );
    assert_eq!(control.terminal_reports().unwrap(), vec![replacement]);
}
