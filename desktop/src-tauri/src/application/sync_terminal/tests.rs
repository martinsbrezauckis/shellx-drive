use std::{collections::BTreeMap, path::PathBuf};

use chrono::Utc;
use shellx_drive_desktop_core::{
    sync_pair_id, DesktopError, DesktopState, MirrorCoordinator, ReviewAction, ReviewItem,
    ReviewKind, SyncPair, SyncStatus,
};

use super::SyncCycleTerminal;

fn pair(workspace_id: &str) -> SyncPair {
    SyncPair {
        server_url: "https://drive.example.test".to_string(),
        account_email: "owner@example.test".to_string(),
        workspace_id: workspace_id.to_string(),
        workspace_name: workspace_id.to_string(),
        remote_root_id: None,
        remote_root_name: None,
        local_root: PathBuf::from(format!("/tmp/{workspace_id}")),
        local_root_identity: None,
    }
}

fn access_removed_review() -> ReviewItem {
    ReviewItem {
        id: "access-removed".to_string(),
        kind: ReviewKind::AccessRemoved,
        relative_path: PathBuf::new(),
        descendant_count: 0,
        is_directory: true,
        summary: "This retained Drive location lost access.".to_string(),
        actions: vec![ReviewAction::RemoveLocalCopy],
    }
}

fn server_unavailable() -> DesktopError {
    DesktopError::Server {
        status: 503,
        message: "temporary upstream failure".to_string(),
    }
}

fn configured_three_root_state() -> DesktopState {
    let mut state = DesktopState::default();
    state.configure_pair(pair("reviewed")).unwrap();
    state.configure_pair(pair("unavailable")).unwrap();
    state.configure_pair(pair("selected")).unwrap();
    state
}

#[test]
fn skipped_inactive_access_review_prevents_a_later_503_from_projecting_offline() {
    let mut state = configured_three_root_state();
    state
        .inactive_pairs
        .iter_mut()
        .find(|profile| profile.pair.workspace_id == "reviewed")
        .unwrap()
        .reviews = vec![access_removed_review()];
    let coordinator = MirrorCoordinator::new(state);
    let mut run = coordinator.begin_run().unwrap();
    let selected = run.selected_pair_id().unwrap();
    let reviewed = sync_pair_id(&pair("reviewed"));
    let unavailable = sync_pair_id(&pair("unavailable"));

    // The selected root completes, while a prior review is intentionally
    // skipped in a normal pass and another root sees a transient response.
    run.record_success(BTreeMap::new(), Utc::now());
    run.activate_configured_pair(&reviewed).unwrap();
    assert!(run.has_active_reviews());
    run.activate_configured_pair(&unavailable).unwrap();
    let mut terminal = SyncCycleTerminal::default();
    terminal.record_root_failure(&mut run, server_unavailable());

    let final_state = run.finalize_all_roots_state(&selected).unwrap();
    assert!(terminal.finish(&final_state).is_ok());
    run.finish_state(final_state);
    coordinator.set_offline(true);

    let state = coordinator.snapshot();
    assert!(
        state.reviews.is_empty(),
        "selected review items stay selected"
    );
    assert_eq!(state.pending_review_count(), 1);
    assert_eq!(coordinator.status(true), SyncStatus::NeedsReview);
    assert!(coordinator.should_notify(false));
}

#[test]
fn permanent_root_failure_wins_over_a_later_503() {
    let mut state = DesktopState::default();
    state.configure_pair(pair("failed")).unwrap();
    state.configure_pair(pair("selected")).unwrap();
    let coordinator = MirrorCoordinator::new(state);
    let mut run = coordinator.begin_run().unwrap();
    let selected = run.selected_pair_id().unwrap();
    let failed = run
        .configured_pair_ids()
        .unwrap()
        .into_iter()
        .find(|pair_id| pair_id != &selected)
        .unwrap();
    let mut terminal = SyncCycleTerminal::default();

    run.activate_configured_pair(&failed).unwrap();
    terminal.record_root_failure(&mut run, DesktopError::UnsafePath("AUX.txt".to_string()));
    run.activate_configured_pair(&selected).unwrap();
    terminal.record_root_failure(&mut run, server_unavailable());

    let final_state = run.finalize_all_roots_state(&selected).unwrap();
    assert!(terminal.finish(&final_state).is_ok());
    run.finish_state(final_state);
    coordinator.set_offline(true);

    assert_eq!(coordinator.status(true), SyncStatus::Error);
}

#[test]
fn isolated_503_remains_the_offline_terminal() {
    let mut state = DesktopState::default();
    state.configure_pair(pair("selected")).unwrap();
    let coordinator = MirrorCoordinator::new(state);
    let mut run = coordinator.begin_run().unwrap();
    let selected = run.selected_pair_id().unwrap();
    let mut terminal = SyncCycleTerminal::default();
    terminal.record_root_failure(&mut run, server_unavailable());

    let final_state = run.finalize_all_roots_state(&selected).unwrap();
    assert!(matches!(
        terminal.finish(&final_state),
        Err(DesktopError::Server { status: 503, .. })
    ));
    run.finish_state(final_state);
    coordinator.set_offline(true);

    assert_eq!(coordinator.status(true), SyncStatus::Offline);
}
