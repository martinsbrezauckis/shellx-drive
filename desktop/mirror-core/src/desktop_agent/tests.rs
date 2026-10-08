use std::path::PathBuf;

use crate::{DesktopState, ReviewAction, SyncPair};
use chrono::Utc;

use super::*;

fn pair(local_root: &str) -> SyncPair {
    SyncPair {
        server_url: "https://drive.example.test/".to_string(),
        account_email: "OWNER@example.test".to_string(),
        workspace_id: "workspace_1".to_string(),
        workspace_name: "Workspace".to_string(),
        remote_root_id: Some("root_1".to_string()),
        remote_root_name: Some("Root".to_string()),
        local_root: PathBuf::from(local_root),
        local_root_identity: None,
    }
}

#[test]
fn pair_fingerprint_does_not_disclose_or_depend_on_local_root() {
    assert_eq!(
        desktop_agent_pair_fingerprint(&pair("/fixture/Private Drive")),
        desktop_agent_pair_fingerprint(&pair("/different/private/root")),
    );
}

#[test]
fn enrollment_fingerprint_is_domain_separated_and_root_independent() {
    let first = pair("/fixture/one");
    let mut second = pair("/fixture/two");
    second.workspace_id = "workspace_2".to_string();
    second.remote_root_id = Some("root_2".to_string());

    let first_fingerprint =
        desktop_agent_enrollment_fingerprint(&first.server_url, &first.account_email);
    assert_eq!(
        first_fingerprint,
        desktop_agent_enrollment_fingerprint(&second.server_url, &second.account_email)
    );
    assert_ne!(first_fingerprint, desktop_agent_pair_fingerprint(&first));
    assert_ne!(
        first_fingerprint,
        desktop_agent_enrollment_fingerprint("https://other.example.test", &first.account_email)
    );
    assert_ne!(
        first_fingerprint,
        desktop_agent_enrollment_fingerprint(&first.server_url, "other@example.test")
    );
}

#[test]
fn command_payload_cannot_cross_kind_boundaries_or_accept_control_review_ids() {
    assert!(DesktopAgentClaimPayload::SetPaused { paused: true }
        .parse(DesktopAgentCommandKind::SetLaunchAtLogin)
        .is_err());
    assert!(DesktopAgentClaimPayload::PrepareReviewAction {
        pair_id: "pair_1".to_string(),
        review_id: "LocalDeletion:control\npath".to_string(),
        action: ReviewAction::RemoveLocalCopy,
    }
    .parse(DesktopAgentCommandKind::PrepareReviewAction)
    .is_err());
    assert_eq!(
        DesktopAgentClaimPayload::StartPair {
            workspace_id: "workspace_1".to_string(),
        }
        .parse(DesktopAgentCommandKind::StartPair)
        .unwrap(),
        DesktopAgentCommand::StartPair {
            workspace_id: "workspace_1".to_string(),
        },
    );
}

#[test]
fn start_pair_is_direct_only_for_a_root_refresh_with_a_bounded_result() {
    assert_eq!(
        DesktopAgentClaimPayload::StartPair {
            workspace_id: "workspace_1".to_string(),
        }
        .parse(DesktopAgentCommandKind::StartPair)
        .unwrap(),
        DesktopAgentCommand::StartPair {
            workspace_id: "workspace_1".to_string(),
        }
    );

    let result = DesktopAgentResultPayload::RootsRefreshed {
        workspace_id: "workspace_1".to_string(),
        added_root_count: 1,
        existing_root_count: 2,
    };
    assert!(result
        .validate_for(
            DesktopAgentCommandKind::StartPair,
            DesktopAgentResultCode::RootsRefreshed,
        )
        .is_ok());
    assert!(DesktopAgentResultPayload::RootsRefreshed {
        workspace_id: "workspace_1".to_string(),
        added_root_count: 0,
        existing_root_count: 0,
    }
    .validate_for(
        DesktopAgentCommandKind::StartPair,
        DesktopAgentResultCode::RootsRefreshed,
    )
    .is_err());
}

#[test]
fn broker_payload_contract_parses_and_preserves_local_gesture_boundaries() {
    let confirmation = DesktopAgentClaimPayload::decode(
        DesktopAgentCommandKind::ConfirmReviewAction,
        serde_json::json!({
            "pair_id": "pair_1",
            "review_id": "review_1",
            "action": "remove_local_copy",
            "prepared_confirmation_id": "confirm_1",
            "fingerprint": "a".repeat(64),
        }),
    )
    .unwrap();
    assert_eq!(
        confirmation
            .parse(DesktopAgentCommandKind::ConfirmReviewAction)
            .unwrap(),
        DesktopAgentCommand::ConfirmReviewAction {
            pair_id: "pair_1".to_string(),
            review_id: "review_1".to_string(),
            action: ReviewAction::RemoveLocalCopy,
            prepared_confirmation_id: "confirm_1".to_string(),
            fingerprint: "a".repeat(64),
        }
    );
    assert!(DesktopAgentClaimPayload::decode(
        DesktopAgentCommandKind::PrepareReviewAction,
        serde_json::json!({"review_id": "review_1", "action": "remove_local_copy"}),
    )
    .is_err());

    let selected_pair = DesktopAgentClaimPayload::decode(
        DesktopAgentCommandKind::OpenDrive,
        serde_json::json!({ "pair_id": "pair_1" }),
    )
    .unwrap();
    assert_eq!(
        selected_pair
            .parse(DesktopAgentCommandKind::OpenDrive)
            .unwrap(),
        DesktopAgentCommand::OpenDrive {
            pair_id: Some("pair_1".to_string())
        }
    );

    assert_eq!(
        DesktopAgentClaimPayload::Empty {}
            .parse(DesktopAgentCommandKind::ContinueMfa)
            .unwrap(),
        DesktopAgentCommand::RequiresLocalGesture(DesktopAgentLocalGesture::ContinueMfa)
    );
}

#[test]
fn restart_interrupts_only_post_ack_work_without_replay() {
    let now = Utc::now();
    let mut control = DesktopAgentControlState::default();
    control
        .enroll(
            "device_1".to_string(),
            None,
            desktop_agent_pair_fingerprint(&pair("/one")),
        )
        .unwrap();
    control
        .record_lease(
            "command_1".to_string(),
            "lease_1".to_string(),
            DesktopAgentCommandKind::SyncNow,
            now,
        )
        .unwrap();
    control
        .record_lease(
            "command_2".to_string(),
            "lease_2".to_string(),
            DesktopAgentCommandKind::DesktopView,
            now,
        )
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

    let interruptions = control.interrupt_after_restart(now);

    assert_eq!(
        interruptions,
        vec![DesktopAgentJournalRecovery {
            command_id: "command_1".to_string(),
            lease_id: "lease_1".to_string(),
            event_sequence: 3,
            terminal_status: DesktopAgentTerminalStatus::Interrupted,
            terminal_code: DesktopAgentTerminalCode::CrashUnproven,
            result_code: None,
            result: None,
        }]
    );
    assert_eq!(
        control.command_journal[0].state,
        DesktopAgentCommandJournalState::TerminalReporting
    );
    assert_eq!(
        control.command_journal[1].state,
        DesktopAgentCommandJournalState::Leased
    );
}

#[test]
fn restart_retries_a_persisted_terminal_with_its_original_outcome() {
    let now = Utc::now();
    let mut control = DesktopAgentControlState::default();
    control
        .enroll(
            "device_1".to_string(),
            None,
            desktop_agent_pair_fingerprint(&pair("/one")),
        )
        .unwrap();
    control
        .record_lease(
            "command_1".to_string(),
            "lease_1".to_string(),
            DesktopAgentCommandKind::SetPaused,
            now,
        )
        .unwrap();
    assert_eq!(control.next_event_sequence("command_1").unwrap(), 1);
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
        .mark_terminal(
            "command_1",
            DesktopAgentTerminalStatus::Failed,
            DesktopAgentTerminalCode::NativeDispatchFailed,
            None,
            None,
            now,
        )
        .unwrap();

    let retry = control.interrupt_after_restart(now);

    assert_eq!(
        retry,
        vec![DesktopAgentJournalRecovery {
            command_id: "command_1".to_string(),
            lease_id: "lease_1".to_string(),
            event_sequence: 3,
            terminal_status: DesktopAgentTerminalStatus::Failed,
            terminal_code: DesktopAgentTerminalCode::NativeDispatchFailed,
            result_code: None,
            result: None,
        }]
    );
    assert_eq!(
        control.last_terminal_command_id.as_deref(),
        Some("command_1")
    );
    assert_eq!(
        control.command_journal[0].state,
        DesktopAgentCommandJournalState::TerminalReporting
    );
    control.mark_terminal_reported("command_1", now).unwrap();
    assert_eq!(
        control.command_journal[0].state,
        DesktopAgentCommandJournalState::Failed
    );
}

#[test]
fn running_command_renewals_use_strictly_later_durable_sequences() {
    let now = Utc::now();
    let mut control = DesktopAgentControlState::default();
    control
        .enroll(
            "device_1".to_string(),
            None,
            desktop_agent_pair_fingerprint(&pair("/one")),
        )
        .unwrap();
    control
        .record_lease(
            "command_1".to_string(),
            "lease_1".to_string(),
            DesktopAgentCommandKind::SyncNow,
            now,
        )
        .unwrap();
    assert_eq!(control.mark_acknowledged("command_1", now).unwrap(), 1);
    let accepted = control
        .begin_progress("command_1", DesktopAgentProgressPhase::Accepted, now)
        .unwrap();
    assert_eq!(accepted, 2);
    control
        .mark_progress_reported(
            "command_1",
            accepted,
            DesktopAgentProgressPhase::Accepted,
            now,
        )
        .unwrap();
    assert_eq!(
        control
            .begin_progress("command_1", DesktopAgentProgressPhase::Syncing, now)
            .unwrap(),
        3
    );
    assert_eq!(control.next_event_sequence("command_1").unwrap(), 4);
    assert!(control.validate().is_ok());
}

#[test]
fn progress_response_loss_retries_its_exact_durable_event_before_terminalizing() {
    let now = Utc::now();
    let mut control = DesktopAgentControlState::default();
    control
        .enroll(
            "device_1".to_string(),
            None,
            desktop_agent_pair_fingerprint(&pair("/one")),
        )
        .unwrap();
    control
        .record_lease(
            "command_1".to_string(),
            "lease_1".to_string(),
            DesktopAgentCommandKind::SyncNow,
            now,
        )
        .unwrap();
    control.mark_acknowledged("command_1", now).unwrap();
    let event_sequence = control
        .begin_progress("command_1", DesktopAgentProgressPhase::Accepted, now)
        .unwrap();

    assert_eq!(
        control.pending_progress_reports().unwrap(),
        vec![DesktopAgentPendingProgress {
            command_id: "command_1".to_string(),
            lease_id: "lease_1".to_string(),
            event_sequence,
            phase: DesktopAgentProgressPhase::Accepted,
        }]
    );
    assert!(control
        .mark_terminal(
            "command_1",
            DesktopAgentTerminalStatus::Failed,
            DesktopAgentTerminalCode::NativeDispatchFailed,
            None,
            None,
            now,
        )
        .is_err());

    control
        .mark_progress_reported(
            "command_1",
            event_sequence,
            DesktopAgentProgressPhase::Accepted,
            now,
        )
        .unwrap();
    assert_eq!(
        control
            .mark_terminal(
                "command_1",
                DesktopAgentTerminalStatus::Interrupted,
                DesktopAgentTerminalCode::CrashUnproven,
                None,
                None,
                now,
            )
            .unwrap(),
        event_sequence + 1
    );
}

#[test]
fn disabled_control_cannot_retain_an_enrollment_or_journal() {
    let state = DesktopAgentControlState {
        enabled: false,
        device_id: Some("device_1".to_string()),
        ..Default::default()
    };
    assert!(state.validate().is_err());
}

#[test]
fn retirement_clears_only_agent_update_recovery() {
    let mut state = DesktopState::default();
    state
        .desktop_agent_control
        .enroll("device_1".to_string(), None, "a".repeat(64))
        .unwrap();
    state
        .record_desktop_update_restart_for_agent(
            "1.2.3".to_string(),
            "candidate_1".to_string(),
            "command_1".to_string(),
        )
        .unwrap();
    state.retire_desktop_agent_control();
    assert!(state.pending_desktop_update_restart.is_none());
    assert!(!state.desktop_agent_control.enabled);
    assert!(state.desktop_agent_control.device_id.is_none());
    state
        .record_desktop_update_restart("1.2.3".to_string(), "candidate_2".to_string())
        .unwrap();
    let human_intent = state.pending_desktop_update_restart.clone();
    state.retire_desktop_agent_control();
    assert_eq!(state.pending_desktop_update_restart, human_intent);
}
