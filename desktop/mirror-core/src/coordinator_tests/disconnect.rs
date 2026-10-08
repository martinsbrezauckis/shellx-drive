use chrono::Utc;
use std::cell::RefCell;

use super::*;

fn paired_state() -> DesktopState {
    DesktopState {
        pair: Some(crate::SyncPair {
            server_url: "https://drive.example".into(),
            account_email: "owner@example.test".into(),
            workspace_id: "workspace".into(),
            workspace_name: "Workspace".into(),
            remote_root_id: None,
            remote_root_name: None,
            local_root: "C:/Drive".into(),
            local_root_identity: None,
        }),
        ..DesktopState::default()
    }
}

#[test]
fn disconnect_cancels_one_run_and_cannot_clean_up_before_its_guard_drops() {
    let coordinator = MirrorCoordinator::new(paired_state());
    let run = coordinator.begin_run().unwrap();
    let mut request = coordinator.request_disconnect().unwrap();

    assert!(matches!(
        run.ensure_not_cancelled(),
        Err(DesktopError::SyncCancelledForDisconnect)
    ));
    assert!(coordinator.view_snapshot().disconnect_requested);
    assert!(matches!(
        coordinator.begin_run(),
        Err(DesktopError::SyncAlreadyRunning)
    ));
    assert!(!request.is_ready().unwrap());
    assert!(request.try_begin().unwrap().is_none());

    drop(run);
    assert!(request.is_ready().unwrap());
    let operation = request
        .try_begin()
        .unwrap()
        .expect("released sync promotes exact Disconnect request");
    assert!(!coordinator.view_snapshot().disconnect_requested);
    assert!(matches!(
        coordinator.begin_run(),
        Err(DesktopError::SyncAlreadyRunning)
    ));
    drop(operation);
    assert!(coordinator.begin_run().is_ok());
}

#[test]
fn abandoned_and_duplicate_requests_cannot_clear_another_generation() {
    let coordinator = MirrorCoordinator::new(paired_state());
    let run = coordinator.begin_run().unwrap();
    let request = coordinator.request_disconnect().unwrap();
    assert!(coordinator.request_disconnect().is_err());
    assert!(run.ensure_not_cancelled().is_err());

    drop(request);
    assert!(run.ensure_not_cancelled().is_ok());
    let mut replacement = coordinator.request_disconnect().unwrap();
    assert!(run.ensure_not_cancelled().is_err());
    drop(run);
    assert!(replacement.try_begin().unwrap().is_some());
}

#[test]
fn concurrent_agent_journal_survives_sync_terminal_publication() {
    let coordinator = MirrorCoordinator::new(paired_state());
    let mut run = coordinator.begin_run().unwrap();
    let now = Utc::now();
    coordinator
        .update_desktop_agent_control(
            |control| {
                control.enroll("device_1".to_string(), None, "11".repeat(32))?;
                control.record_lease(
                    "command_1".to_string(),
                    "lease_1".to_string(),
                    crate::DesktopAgentCommandKind::Disconnect,
                    now,
                )?;
                control.mark_acknowledged("command_1", now)
            },
            |_| Ok(()),
        )
        .unwrap();

    let stale_terminal = run.state().clone();
    let persisted = RefCell::new(None);
    run.finish_persisted_state(stale_terminal, |state| {
        persisted.replace(Some(state.clone()));
        Ok(())
    })
    .unwrap();
    let control = coordinator.snapshot().desktop_agent_control;
    assert_eq!(
        persisted.into_inner().unwrap().desktop_agent_control,
        control
    );
    assert!(control.enabled);
    assert_eq!(control.command_journal.len(), 1);
    assert_eq!(
        control.command_journal[0].state,
        crate::DesktopAgentCommandJournalState::Acknowledged
    );
}

#[test]
fn failed_agent_journal_persistence_does_not_publish_memory_state() {
    let coordinator = MirrorCoordinator::new(paired_state());
    let result = coordinator.update_desktop_agent_control(
        |control| {
            control.enabled = true;
            Ok(())
        },
        |_| {
            Err(DesktopError::InvalidState(
                "simulated persistence failure".to_string(),
            ))
        },
    );
    assert!(result.is_err());
    assert!(!coordinator.snapshot().desktop_agent_control.enabled);
}

#[test]
fn agent_journal_cannot_bypass_an_active_lifecycle_operation() {
    let coordinator = MirrorCoordinator::new(paired_state());
    let operation = coordinator.begin_lifecycle_operation().unwrap();
    let result = coordinator.update_desktop_agent_control(
        |control| {
            control.enabled = true;
            Ok(())
        },
        |_| Ok(()),
    );
    assert!(matches!(result, Err(DesktopError::SyncAlreadyRunning)));
    assert!(!coordinator.snapshot().desktop_agent_control.enabled);
    drop(operation);
}
