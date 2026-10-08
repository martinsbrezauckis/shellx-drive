use std::{cell::Cell, path::PathBuf};

use tempfile::tempdir;

use crate::{
    persist_pairing_state, DesktopError, DesktopState, PairMarkerDisposition, StateStore, SyncPair,
};

fn pair(local_root: PathBuf) -> SyncPair {
    SyncPair {
        server_url: "https://drive.example".to_string(),
        account_email: "owner@example.test".to_string(),
        workspace_id: "workspace".to_string(),
        workspace_name: "Workspace".to_string(),
        remote_root_id: None,
        remote_root_name: None,
        local_root,
        local_root_identity: None,
    }
}

#[test]
fn rejected_pair_does_not_publish_a_marker() {
    let directory = tempdir().unwrap();
    let store = StateStore::new(directory.path().join("state.json"));
    let expected = pair(directory.path().join("Drive"));
    let mut current = DesktopState::default();
    current.configure_pair(expected.clone()).unwrap();
    let marker_prepared = Cell::new(false);

    let result = persist_pairing_state(
        &store,
        &current,
        expected,
        |_| {
            marker_prepared.set(true);
            Ok(PairMarkerDisposition::Created)
        },
        |_| panic!("a rejected pair cannot own a marker to roll back"),
    );

    assert!(matches!(
        result,
        Err(DesktopError::InvalidState(message)) if message.contains("already configured")
    ));
    assert!(!marker_prepared.get());
    assert!(!store.path().exists());
}
