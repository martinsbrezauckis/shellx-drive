use std::collections::BTreeSet;

use shellx_drive_desktop_core::{
    DesktopAgentCommandKind, DesktopState, FakeCredentialStore, StateStore,
};

use super::workspace_refresh_counts;
use crate::application::{
    desktop_agent::update_desktop_state,
    runtime::{tests::TestPlatform, Runtime},
};

fn root_ids(ids: &[&str]) -> BTreeSet<String> {
    ids.iter().map(|id| (*id).to_string()).collect()
}

#[test]
fn refreshed_workspace_counts_only_retained_requested_root_ids() {
    assert_eq!(
        workspace_refresh_counts(
            root_ids(&["pair_preexisting", "pair_removed"]),
            root_ids(&["pair_preexisting", "pair_new"]),
        )
        .unwrap(),
        (1, 1)
    );
}

#[test]
fn refreshed_workspace_requires_an_authoritative_usable_root() {
    assert!(workspace_refresh_counts(root_ids(&["pair_stale"]), BTreeSet::new()).is_err());
}

#[test]
fn failed_retirement_save_retains_agent_journal_and_restart_intent() {
    let directory = tempfile::tempdir().unwrap();
    let parent = directory.path().join("state-parent");
    std::fs::write(&parent, b"not a directory").unwrap();
    let mut state = DesktopState::default();
    state
        .desktop_agent_control
        .enroll("device_1".to_string(), None, "a".repeat(64))
        .unwrap();
    state
        .desktop_agent_control
        .record_lease(
            "command_1".to_string(),
            "lease_1".to_string(),
            DesktopAgentCommandKind::InstallDesktopUpdate,
            chrono::Utc::now(),
        )
        .unwrap();
    state
        .record_desktop_update_restart_for_agent(
            "1.2.3".to_string(),
            "candidate_1".to_string(),
            "command_1".to_string(),
        )
        .unwrap();
    let runtime = Runtime::from_loaded_state(
        Box::new(TestPlatform(FakeCredentialStore::default())),
        StateStore::new(parent.join("state.json")),
        state,
    );
    assert!(update_desktop_state(&runtime, |state| {
        state.retire_desktop_agent_control();
        Ok(())
    })
    .is_err());
    let retained = runtime.coordinator.snapshot();
    assert!(retained.desktop_agent_control.enabled);
    assert_eq!(retained.desktop_agent_control.command_journal.len(), 1);
    assert!(retained.pending_desktop_update_restart.is_some());
}
