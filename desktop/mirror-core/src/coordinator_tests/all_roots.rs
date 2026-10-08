use std::{collections::BTreeMap, path::PathBuf};

use chrono::Utc;

use crate::{
    sync_pair_id, ActivityEntry, BaselineEntry, DesktopError, DesktopState, MirrorCoordinator,
    ReviewAction, ReviewItem, ReviewKind, SyncPair, SyncRoot, SyncRootAccessRemovalReason,
    SyncRootKind, SyncRootRole, SyncStatus,
};

fn pair(workspace: &str, remote_root_id: Option<&str>, local_root: &str) -> SyncPair {
    SyncPair {
        server_url: "https://drive.example.test".to_string(),
        account_email: "owner@example.test".to_string(),
        workspace_id: workspace.to_string(),
        workspace_name: workspace.to_string(),
        remote_root_id: remote_root_id.map(str::to_string),
        remote_root_name: remote_root_id.map(str::to_string),
        local_root: PathBuf::from(local_root),
        local_root_identity: None,
    }
}

fn root(pair: &SyncPair, id: &str, role: SyncRootRole) -> SyncRoot {
    let item_grant = pair.remote_root_id.is_some();
    SyncRoot {
        id: id.to_string(),
        kind: if item_grant {
            SyncRootKind::ItemGrant
        } else {
            SyncRootKind::Workspace
        },
        workspace_id: pair.workspace_id.clone(),
        root_file_id: pair.remote_root_id.clone(),
        grant_id: item_grant.then(|| format!("grant-{id}")),
        owner_label: "Owner".to_string(),
        role,
        access_generation: 1,
        expires_at: None,
        label: pair.workspace_name.clone(),
    }
}

fn baseline(id: &str) -> BTreeMap<String, BaselineEntry> {
    BTreeMap::from([(
        id.to_string(),
        BaselineEntry {
            remote_id: id.to_string(),
            parent_id: None,
            relative_path: PathBuf::from(format!("{id}.txt")),
            kind: "file".to_string(),
            content_hash: Some(id.to_string()),
            revision: 1,
            directory_identity: None,
        },
    )])
}

fn activity(result: &str) -> ActivityEntry {
    ActivityEntry {
        at: Utc::now(),
        direction: "Drive".to_string(),
        relative_path: PathBuf::new(),
        result: result.to_string(),
    }
}

fn two_root_state() -> (DesktopState, String, String) {
    let owned = pair("workspace-owned", None, "C:/Drive/My files");
    let shared = pair(
        "workspace-shared",
        Some("shared-folder"),
        "C:/Drive/Shared with me/Owner/Folder",
    );
    let mut state = DesktopState::default();
    state.configure_pair(owned.clone()).unwrap();
    state
        .record_sync_root(&owned, root(&owned, "workspace:owned", SyncRootRole::Owner))
        .unwrap();
    state.configure_pair(shared.clone()).unwrap();
    state
        .record_sync_root(&shared, root(&shared, "grant:shared", SyncRootRole::Viewer))
        .unwrap();
    (state, sync_pair_id(&owned), sync_pair_id(&shared))
}

fn finish_cycle(coordinator: &MirrorCoordinator, run: &mut crate::SyncRun, selected_pair_id: &str) {
    let state = run.finalize_all_roots_state(selected_pair_id).unwrap();
    run.finish_state(state);
    assert_eq!(
        sync_pair_id(coordinator.snapshot().pair.as_ref().unwrap()),
        selected_pair_id
    );
}

#[test]
fn one_serialized_cycle_visits_every_root_and_restores_display_selection() {
    let (state, owned_id, shared_id) = two_root_state();
    let coordinator = MirrorCoordinator::new(state);
    let mut run = coordinator.begin_run().unwrap();
    let selected = run.selected_pair_id().unwrap();
    let ids = run.configured_pair_ids().unwrap();
    assert_eq!(ids, vec![selected.clone(), owned_id.clone()]);
    assert_eq!(selected, shared_id);

    for pair_id in ids {
        run.activate_configured_pair(&pair_id).unwrap();
        let root_id = run.sync_root_for_active_pair().unwrap().root.id.clone();
        run.record_success(baseline(&root_id), Utc::now());
        run.append_active_activity(activity(&format!("completed {root_id}")));
    }
    finish_cycle(&coordinator, &mut run, &selected);

    assert_eq!(coordinator.snapshot().baseline, baseline("grant:shared"));
    coordinator.activate_pair(&owned_id).unwrap();
    let owned = coordinator.snapshot();
    assert_eq!(owned.baseline, baseline("workspace:owned"));
    assert_eq!(owned.activity.len(), 1);
    assert!(owned.last_error.is_none());
}

#[test]
fn budget_deferral_survives_restart_without_changing_display_selection() {
    let (state, _, selected_id) = two_root_state();
    let coordinator = MirrorCoordinator::new(state);
    let mut first = coordinator.begin_run().unwrap();
    let first_order = first.cycle_pair_ids().unwrap();
    assert_eq!(first_order.len(), 2);
    assert!(first_order.contains(&selected_id));
    first.defer_cycle_after(&first_order[0]).unwrap();
    finish_cycle(&coordinator, &mut first, &selected_id);
    let durable: DesktopState =
        serde_json::from_slice(&serde_json::to_vec(&coordinator.snapshot()).unwrap()).unwrap();
    let restarted = MirrorCoordinator::new(durable);
    let mut second = restarted.begin_run().unwrap();
    let second_order = second.cycle_pair_ids().unwrap();
    assert_eq!(second_order.len(), first_order.len());
    assert_eq!(second_order[0], first_order[1]);
    assert_eq!(second.selected_pair_id().unwrap(), selected_id);
    second.defer_cycle_after(&second_order[0]).unwrap();
    finish_cycle(&restarted, &mut second, &selected_id);
    let mut third = restarted.begin_run().unwrap();
    assert_eq!(third.cycle_pair_ids().unwrap()[0], first_order[0]);
    finish_cycle(&restarted, &mut third, &selected_id);
}

#[test]
fn three_root_budget_deferral_advances_every_root_across_restarts() {
    let (mut state, _, selected_id) = two_root_state();
    let third = pair("workspace-third", None, "C:/Drive/Third");
    state.configure_pair(third.clone()).unwrap();
    state
        .record_sync_root(&third, root(&third, "workspace:third", SyncRootRole::Owner))
        .unwrap();
    state.activate_pair(&selected_id).unwrap();

    let coordinator = MirrorCoordinator::new(state);
    let mut first = coordinator.begin_run().unwrap();
    let initial_order = first.cycle_pair_ids().unwrap();
    assert_eq!(initial_order.len(), 3);
    assert!(initial_order.contains(&selected_id));
    first.activate_configured_pair(&initial_order[1]).unwrap();
    first.defer_cycle_after(&initial_order[1]).unwrap();
    finish_cycle(&coordinator, &mut first, &selected_id);

    let mut durable: DesktopState =
        serde_json::from_slice(&serde_json::to_vec(&coordinator.snapshot()).unwrap()).unwrap();
    let mut first_roots = Vec::new();
    for _ in 0..3 {
        let restarted = MirrorCoordinator::new(durable);
        let mut run = restarted.begin_run().unwrap();
        let current = run.cycle_pair_ids().unwrap()[0].clone();
        first_roots.push(current.clone());
        assert_eq!(run.selected_pair_id().unwrap(), selected_id);
        run.activate_configured_pair(&current).unwrap();
        run.defer_cycle_after(&current).unwrap();
        finish_cycle(&restarted, &mut run, &selected_id);
        durable =
            serde_json::from_slice(&serde_json::to_vec(&restarted.snapshot()).unwrap()).unwrap();
    }
    assert_eq!(
        first_roots,
        vec![
            initial_order[2].clone(),
            initial_order[0].clone(),
            initial_order[1].clone()
        ]
    );

    durable.sync_cycle_resume_pair_id = Some("removed-root".to_string());
    let stale = MirrorCoordinator::new(durable);
    assert_eq!(
        stale.begin_run().unwrap().cycle_pair_ids().unwrap(),
        initial_order
    );
}

#[test]
fn alternating_display_selection_cannot_starve_a_third_root() {
    let (mut state, _, _) = two_root_state();
    let third = pair("workspace-third", None, "C:/Drive/Third");
    state.configure_pair(third.clone()).unwrap();
    state
        .record_sync_root(&third, root(&third, "workspace:third", SyncRootRole::Owner))
        .unwrap();
    let mut ids: Vec<String> = state.pairs().map(sync_pair_id).collect();
    ids.sort_unstable();
    let mut durable = state;
    let mut first_roots = Vec::new();

    for cycle in 0..6 {
        let coordinator = MirrorCoordinator::new(durable);
        let selected = &ids[cycle % 2];
        coordinator.activate_pair(selected).unwrap();
        let mut run = coordinator.begin_run().unwrap();
        let current = run.cycle_pair_ids().unwrap()[0].clone();
        first_roots.push(current.clone());
        run.activate_configured_pair(&current).unwrap();
        run.defer_cycle_after(&current).unwrap();
        finish_cycle(&coordinator, &mut run, selected);
        durable =
            serde_json::from_slice(&serde_json::to_vec(&coordinator.snapshot()).unwrap()).unwrap();
    }
    assert_eq!(first_roots, [ids.clone(), ids].concat());
}

#[test]
fn one_root_failure_retains_its_own_state_and_does_not_corrupt_another() {
    let (state, owned_id, shared_id) = two_root_state();
    let coordinator = MirrorCoordinator::new(state);
    let mut run = coordinator.begin_run().unwrap();
    let selected = run.selected_pair_id().unwrap();
    for pair_id in run.configured_pair_ids().unwrap() {
        run.activate_configured_pair(&pair_id).unwrap();
        if pair_id == owned_id {
            run.record_success(baseline("owned-after"), Utc::now());
            run.append_active_activity(activity("owned completed"));
        } else {
            let original_baseline = run.state().baseline.clone();
            run.record_active_error("shared fixture failed");
            run.append_active_activity(activity("shared failed"));
            assert_eq!(run.state().baseline, original_baseline);
        }
    }
    finish_cycle(&coordinator, &mut run, &selected);

    coordinator.activate_pair(&owned_id).unwrap();
    let owned = coordinator.snapshot();
    assert_eq!(owned.baseline, baseline("owned-after"));
    assert!(owned.last_error.is_none());
    coordinator.activate_pair(&shared_id).unwrap();
    let shared = coordinator.snapshot();
    assert_eq!(shared.last_error.as_deref(), Some("shared fixture failed"));
    assert!(shared.baseline.is_empty());
    assert_eq!(shared.activity.len(), 1);
}

#[test]
fn inactive_root_error_remains_on_its_profile_and_is_notified_aggregately() {
    let (state, owned_id, shared_id) = two_root_state();
    let coordinator = MirrorCoordinator::new(state);
    let mut run = coordinator.begin_run().unwrap();
    run.activate_configured_pair(&owned_id).unwrap();
    run.record_active_error("owned fixture failed");
    run.activate_configured_pair(&shared_id).unwrap();
    run.record_success(baseline("shared-after"), Utc::now());
    assert!(run.state().last_error.is_none());

    let selected_pair_id = run.selected_pair_id().unwrap();
    let final_state = run.finalize_all_roots_state(&selected_pair_id).unwrap();
    assert!(final_state.last_error.is_none());
    assert!(final_state
        .aggregate_error()
        .as_deref()
        .is_some_and(|error| error.contains("other Drive locations")));
    run.finish_state(final_state);
    let state = coordinator.snapshot();
    assert!(state.last_error.is_none());
    assert!(state
        .inactive_pairs
        .iter()
        .any(|profile| profile.last_error.as_deref() == Some("owned fixture failed")));
    assert_eq!(
        sync_pair_id(coordinator.snapshot().pair.as_ref().unwrap()),
        selected_pair_id
    );
    assert_eq!(coordinator.status(true), SyncStatus::Error);
    assert!(!coordinator.should_notify(false));
    assert!(coordinator.should_notify(true));
}

#[test]
fn revocation_during_a_cycle_stops_only_that_root_and_retains_local_pair() {
    let (state, owned_id, shared_id) = two_root_state();
    let coordinator = MirrorCoordinator::new(state);
    let shared_local_root = coordinator
        .snapshot()
        .pairs()
        .find(|pair| sync_pair_id(pair) == shared_id)
        .unwrap()
        .local_root
        .clone();
    let mut run = coordinator.begin_run().unwrap();
    let selected = run.selected_pair_id().unwrap();
    run.activate_configured_pair(&owned_id).unwrap();
    run.record_success(baseline("owned-after"), Utc::now());
    run.activate_configured_pair(&shared_id).unwrap();
    run.mark_active_root_removed(SyncRootAccessRemovalReason::RevokedOrRemoved, Utc::now())
        .unwrap();
    run.record_reviews(vec![ReviewItem {
        id: "access-removed".to_string(),
        kind: ReviewKind::AccessRemoved,
        relative_path: PathBuf::new(),
        descendant_count: 0,
        is_directory: true,
        summary: "Local files retained.".to_string(),
        actions: vec![ReviewAction::RemoveLocalCopy],
    }]);
    run.append_active_activity(activity("shared root revoked"));
    finish_cycle(&coordinator, &mut run, &selected);

    coordinator.activate_pair(&owned_id).unwrap();
    assert_eq!(coordinator.snapshot().baseline, baseline("owned-after"));
    coordinator.activate_pair(&shared_id).unwrap();
    let shared = coordinator.snapshot();
    assert_eq!(shared.pair.as_ref().unwrap().local_root, shared_local_root);
    assert_eq!(shared.reviews.len(), 1);
    assert_eq!(
        shared
            .sync_root_for_pair(shared.pair.as_ref().unwrap())
            .unwrap()
            .access_removed
            .as_ref()
            .unwrap()
            .reason,
        SyncRootAccessRemovalReason::RevokedOrRemoved
    );
}

#[test]
fn coordinator_keeps_the_whole_multi_root_cycle_exclusive() {
    let (state, owned_id, _) = two_root_state();
    let coordinator = MirrorCoordinator::new(state);
    let mut run = coordinator.begin_run().unwrap();
    run.activate_configured_pair(&owned_id).unwrap();
    assert!(matches!(
        coordinator.begin_run(),
        Err(DesktopError::SyncAlreadyRunning)
    ));
    assert!(matches!(
        coordinator.activate_pair(&owned_id),
        Err(DesktopError::SyncAlreadyRunning)
    ));
    let selected = run.selected_pair_id().unwrap();
    finish_cycle(&coordinator, &mut run, &selected);
}

#[test]
fn startup_reconnect_pause_and_root_add_remove_state_cover_every_configured_root() {
    let (mut state, owned_id, shared_id) = two_root_state();
    let cold_start = MirrorCoordinator::new(state.clone());
    assert_eq!(cold_start.status(false), SyncStatus::NeedsReconnect);
    assert_eq!(cold_start.status(true), SyncStatus::Synced);
    let startup_run = cold_start.begin_run().unwrap();
    assert_eq!(startup_run.configured_pair_ids().unwrap().len(), 2);
    drop(startup_run);

    state.set_all_pairs_paused(true);
    assert!(state.paused);
    assert!(state.inactive_pairs.iter().all(|profile| profile.paused));
    let now = Utc::now();
    let owned_pair = state
        .pairs()
        .find(|pair| sync_pair_id(pair) == owned_id)
        .unwrap()
        .clone();
    let reconciliation = state
        .reconcile_sync_roots(
            &[root(&owned_pair, "workspace:owned", SyncRootRole::Owner)],
            now,
        )
        .unwrap();
    assert_eq!(reconciliation.access_removed_pair_ids, vec![shared_id]);
    assert_eq!(state.pair_count(), 2);
    let coordinator = MirrorCoordinator::new(state);
    assert!(matches!(
        coordinator.begin_run(),
        Err(DesktopError::SyncPaused)
    ));
}
