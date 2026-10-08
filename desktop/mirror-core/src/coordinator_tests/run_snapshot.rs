use std::{collections::BTreeMap, path::PathBuf};

use crate::{sync_pair_id, BaselineEntry, DesktopError, DesktopState, MirrorCoordinator, SyncPair};

fn pair(workspace_id: &str, local_root: &str) -> SyncPair {
    SyncPair {
        server_url: "https://drive.example".into(),
        account_email: "owner@example.test".into(),
        workspace_id: workspace_id.into(),
        workspace_name: workspace_id.into(),
        remote_root_id: None,
        remote_root_name: None,
        local_root: PathBuf::from(local_root),
        local_root_identity: None,
    }
}

fn baseline(remote_id: &str, path: &str) -> BaselineEntry {
    BaselineEntry {
        remote_id: remote_id.to_string(),
        parent_id: None,
        relative_path: PathBuf::from(path),
        kind: "file".to_string(),
        content_hash: Some(remote_id.to_string()),
        revision: 1,
        directory_identity: None,
    }
}

#[test]
fn run_snapshot_binds_the_profile_selected_at_reservation_time() {
    let mut state = DesktopState::default();
    state.configure_pair(pair("second", "D:/Second")).unwrap();
    let second_baseline = BTreeMap::from([(
        "second-file".to_string(),
        baseline("second-file", "second.txt"),
    )]);
    state.baseline = second_baseline.clone();
    state.configure_pair(pair("first", "C:/First")).unwrap();
    state.baseline = BTreeMap::from([(
        "first-file".to_string(),
        baseline("first-file", "first.txt"),
    )]);

    let coordinator = MirrorCoordinator::new(state);
    let stale_before_switch = coordinator.snapshot();
    assert_eq!(
        stale_before_switch.pair.as_ref().unwrap().workspace_id,
        "first"
    );
    let second_id = sync_pair_id(
        stale_before_switch
            .pairs()
            .find(|pair| pair.workspace_id == "second")
            .unwrap(),
    );
    let first_id = sync_pair_id(stale_before_switch.pair.as_ref().unwrap());

    // Model selection completing after a caller snapshots but before it
    // reserves the run. The run must bind the newly active profile.
    assert!(coordinator.activate_pair(&second_id).unwrap());
    let run = coordinator.begin_run().unwrap();
    assert_eq!(run.state().pair.as_ref().unwrap().workspace_id, "second");
    assert_eq!(run.state().baseline, second_baseline);
    assert!(matches!(
        coordinator.activate_pair(&first_id),
        Err(DesktopError::SyncAlreadyRunning)
    ));
}

#[path = "run_snapshot/scoped_root.rs"]
mod scoped_root;
