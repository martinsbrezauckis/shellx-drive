use std::{collections::BTreeMap, path::PathBuf};

use super::*;

fn pair(workspace: &str, local: &str) -> SyncPair {
    SyncPair {
        server_url: "https://drive.example".to_string(),
        account_email: "owner@example.test".to_string(),
        workspace_id: workspace.to_string(),
        workspace_name: workspace.to_string(),
        remote_root_id: None,
        remote_root_name: None,
        local_root: PathBuf::from(local),
        local_root_identity: None,
    }
}

#[test]
fn switching_locations_restores_each_independent_sync_state() {
    let mut state = DesktopState::default();
    state.configure_pair(pair("one", "C:/Drive One")).unwrap();
    state.change_cursor = 41;
    state.baseline.insert(
        "remote-one".to_string(),
        crate::BaselineEntry {
            remote_id: "remote-one".to_string(),
            parent_id: None,
            relative_path: PathBuf::from("one.txt"),
            kind: "file".to_string(),
            content_hash: None,
            revision: 1,
            directory_identity: None,
        },
    );
    let first_id = sync_pair_id(state.pair.as_ref().unwrap());
    state.configure_pair(pair("two", "C:/Drive Two")).unwrap();
    assert_eq!(state.pair_count(), 2);
    assert!(state.activate_pair(&first_id).unwrap());
    assert_eq!(state.change_cursor, 41);
    assert_eq!(
        state.baseline.keys().cloned().collect::<Vec<_>>(),
        vec!["remote-one"]
    );
}

#[test]
fn selecting_a_review_owning_location_preserves_all_profiles_and_actions() {
    let mut state = DesktopState::default();
    let clean = pair("clean", "C:/Drive Clean");
    let reviewed = pair("reviewed", "C:/Drive Reviewed");
    state.configure_pair(clean.clone()).unwrap();
    state.configure_pair(reviewed.clone()).unwrap();
    state.reviews = vec![crate::ReviewItem {
        id: "access-removed".to_string(),
        kind: crate::ReviewKind::AccessRemoved,
        relative_path: PathBuf::new(),
        descendant_count: 0,
        is_directory: true,
        summary: "The local files were retained for review.".to_string(),
        actions: vec![crate::ReviewAction::RemoveLocalCopy],
    }];
    let clean_id = sync_pair_id(&clean);
    let reviewed_id = sync_pair_id(&reviewed);

    assert!(state.activate_pair(&clean_id).unwrap());
    assert!(state.reviews.is_empty());
    assert_eq!(state.pending_review_count(), 1);
    let mut ids_before = state.pairs().map(sync_pair_id).collect::<Vec<_>>();
    ids_before.sort();

    assert!(state.activate_pair(&reviewed_id).unwrap());
    assert_eq!(state.reviews.len(), 1);
    assert_eq!(state.reviews[0].id, "access-removed");
    assert_eq!(
        state.reviews[0].actions,
        vec![crate::ReviewAction::RemoveLocalCopy]
    );
    let mut ids_after = state.pairs().map(sync_pair_id).collect::<Vec<_>>();
    ids_after.sort();
    assert_eq!(ids_after, ids_before);
}

#[test]
fn root_materialized_while_drive_is_paused_stays_paused() {
    let mut state = DesktopState::default();
    state.configure_pair(pair("one", "C:/Drive One")).unwrap();
    state.set_all_pairs_paused(true);
    state.configure_pair(pair("two", "D:/Drive Two")).unwrap();

    assert!(state.paused);
    assert!(state.inactive_pairs.iter().all(|profile| profile.paused));
}

#[test]
fn one_hundred_locations_are_navigable_and_the_next_is_rejected_without_state_loss() {
    let mut state = DesktopState::default();
    for index in 1..=MAX_SYNC_PAIRS {
        state
            .configure_pair(pair(
                &format!("workspace-{index:03}"),
                &format!("C:/Drive/Root-{index:03}"),
            ))
            .expect("the supported location limit is accepted");
    }

    let first = state
        .pairs()
        .find(|pair| pair.workspace_id == "workspace-001")
        .map(sync_pair_id)
        .expect("first configured location");
    let last = state
        .pairs()
        .find(|pair| pair.workspace_id == "workspace-100")
        .map(sync_pair_id)
        .expect("last configured location");
    assert!(state
        .activate_pair(&first)
        .expect("activate first location"));
    assert_eq!(
        state.pair.as_ref().map(|pair| pair.workspace_id.as_str()),
        Some("workspace-001")
    );
    assert!(state.activate_pair(&last).expect("activate last location"));
    assert_eq!(
        state.pair.as_ref().map(|pair| pair.workspace_id.as_str()),
        Some("workspace-100")
    );

    let before_ids = state.pairs().map(sync_pair_id).collect::<Vec<_>>();
    let error = state
        .configure_pair(pair("workspace-101", "C:/Drive/Root-101"))
        .expect_err("the 101st location must not be admitted");
    assert!(error.to_string().contains("maximum of 100 Drive locations"));
    assert_eq!(state.pair_count(), MAX_SYNC_PAIRS);
    assert_eq!(
        state.pairs().map(sync_pair_id).collect::<Vec<_>>(),
        before_ids
    );
    assert_eq!(
        state.pair.as_ref().map(|pair| pair.workspace_id.as_str()),
        Some("workspace-100")
    );
}

#[test]
fn duplicate_remote_or_overlapping_local_locations_are_rejected() {
    let mut state = DesktopState::default();
    state.configure_pair(pair("one", "C:/Drive")).unwrap();
    assert!(state.configure_pair(pair("one", "C:/Other")).is_err());
    assert!(state
        .configure_pair(pair("two", "C:/Drive/Nested"))
        .is_err());
    let mut other = pair("two", "D:/Drive");
    other.account_email = "other@example.test".to_string();
    assert!(state.configure_pair(other).is_err());
    assert_eq!(state.pair_count(), 1);
    assert_eq!(state.baseline, BTreeMap::new());
}

#[test]
fn remove_pair_keeps_other_profile_and_drops_only_removed_root_metadata() {
    let mut state = DesktopState::default();
    let one = pair("one", "C:/Drive One");
    let two = pair("two", "C:/Drive Two");
    state.configure_pair(one.clone()).unwrap();
    let one_id = sync_pair_id(&one);
    state.sync_roots.insert(
        one_id.clone(),
        crate::SyncRootMetadata {
            root: crate::SyncRoot {
                id: "workspace:one".to_string(),
                kind: crate::SyncRootKind::Workspace,
                workspace_id: "one".to_string(),
                root_file_id: None,
                grant_id: None,
                owner_label: "Owner".to_string(),
                role: crate::SyncRootRole::Owner,
                access_generation: 1,
                expires_at: None,
                label: "My files".to_string(),
            },
            access_removed: None,
        },
    );
    state.configure_pair(two.clone()).unwrap();
    assert_eq!(state.remove_pair(&sync_pair_id(&two)).unwrap(), two);
    assert_eq!(state.pair, Some(one));
    assert!(state.sync_roots.contains_key(&one_id));
}

#[test]
fn v2_single_location_state_migrates_without_inventing_profiles() {
    let directory = tempfile::tempdir().unwrap();
    let store = crate::StateStore::new(directory.path().join("state.json"));
    let mut raw = serde_json::to_value(DesktopState {
        schema_version: 2,
        pair: Some(pair("one", "C:/Drive")),
        ..DesktopState::default()
    })
    .unwrap();
    raw.as_object_mut().unwrap().remove("inactive_pairs");
    std::fs::write(store.path(), serde_json::to_vec(&raw).unwrap()).unwrap();
    let migrated = store.load().unwrap();
    assert_eq!(migrated.schema_version, 7);
    assert_eq!(migrated.pair_count(), 1);
    assert!(migrated.inactive_pairs.is_empty());
}
