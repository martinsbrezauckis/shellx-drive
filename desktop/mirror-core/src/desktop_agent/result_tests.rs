use chrono::Utc;

use crate::{DesktopAgentResultPayload, DesktopAgentTerminalCode, DesktopAgentTerminalStatus};

use super::*;

#[path = "result_tests/cancellation.rs"]
mod cancellation;
#[path = "result_tests/page.rs"]
mod page;
#[path = "result_tests/root_page.rs"]
mod root_page;

fn enrolled_control(kind: DesktopAgentCommandKind) -> DesktopAgentControlState {
    let now = Utc::now();
    let mut control = DesktopAgentControlState::default();
    control
        .enroll(
            "device_1".to_string(),
            None,
            desktop_agent_pair_fingerprint(&crate::SyncPair {
                server_url: "https://drive.example.test".to_string(),
                account_email: "person@example.test".to_string(),
                workspace_id: "workspace_1".to_string(),
                workspace_name: "Workspace".to_string(),
                remote_root_id: Some("root_1".to_string()),
                remote_root_name: Some("Root".to_string()),
                local_root: std::path::PathBuf::from("/not-reported"),
                local_root_identity: None,
            }),
        )
        .unwrap();
    control
        .record_lease("command_1".to_string(), "lease_1".to_string(), kind, now)
        .unwrap();
    control.mark_acknowledged("command_1", now).unwrap();
    let accepted = control
        .begin_progress("command_1", DesktopAgentProgressPhase::Accepted, now)
        .unwrap();
    control
        .mark_progress_reported(
            "command_1",
            accepted,
            DesktopAgentProgressPhase::Accepted,
            now,
        )
        .unwrap();
    control
}

#[test]
fn successful_terminal_response_loss_retries_the_identical_bounded_result() {
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

    let retry = control.terminal_reports().unwrap().pop().unwrap();
    assert_eq!(retry.event_sequence, 3);
    assert_eq!(
        retry.result_code,
        Some(DesktopAgentResultCode::PausePersisted)
    );
    assert_eq!(
        retry.result,
        Some(DesktopAgentResultPayload::Pause { paused: true })
    );
}

#[test]
fn restarted_update_is_terminal_only_after_its_matching_proof() {
    let now = Utc::now();
    let mut control = enrolled_control(DesktopAgentCommandKind::InstallDesktopUpdate);
    assert_eq!(control.begin_relaunch_pending("command_1", now).unwrap(), 3);
    control
        .mark_progress_reported(
            "command_1",
            3,
            DesktopAgentProgressPhase::RelaunchPending,
            now,
        )
        .unwrap();
    control
        .complete_relaunched_update(
            "command_1",
            "candidate_1".to_string(),
            "1.2.3".to_string(),
            now,
        )
        .unwrap();

    let retry = control.terminal_reports().unwrap().pop().unwrap();
    assert_eq!(retry.event_sequence, 4);
    assert_eq!(
        retry.result_code,
        Some(DesktopAgentResultCode::UpdateInstalled)
    );
    assert_eq!(
        retry.result,
        Some(DesktopAgentResultPayload::UpdateInstall {
            candidate_id: "candidate_1".to_string(),
            installed_version: "1.2.3".to_string(),
        })
    );
}

#[test]
fn permanent_broker_refusal_stops_only_that_command_without_terminal_success() {
    let now = Utc::now();
    let mut control = enrolled_control(DesktopAgentCommandKind::SetPaused);
    control
        .abandon(
            "command_1",
            DesktopAgentAbandonmentReason::BrokerConflict,
            now,
        )
        .unwrap();

    let abandoned = &control.command_journal[0];
    assert_eq!(abandoned.state, DesktopAgentCommandJournalState::Abandoned);
    assert_eq!(
        abandoned.abandonment_reason,
        Some(DesktopAgentAbandonmentReason::BrokerConflict)
    );
    assert!(abandoned.terminal_event_sequence.is_none());
    assert!(abandoned.result.is_none());
    assert!(control.pending_progress_reports().unwrap().is_empty());
    assert!(control.terminal_reports().unwrap().is_empty());

    control
        .record_lease(
            "command_2".to_string(),
            "lease_2".to_string(),
            DesktopAgentCommandKind::DesktopView,
            now,
        )
        .unwrap();
    assert_eq!(control.command_journal.len(), 1);
    assert_eq!(control.command_journal[0].command_id, "command_2");
}
