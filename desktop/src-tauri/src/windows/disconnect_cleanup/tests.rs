//! Native retry coverage using disposable roots and no credential entries.

use std::fs;

use shellx_drive_desktop_core::{PairMarker, SyncPair};

use super::*;

fn cleanup_fixture(root: &std::path::Path) -> (DesktopState, PairMarker) {
    fs::create_dir(root).unwrap();
    let identity = pair_root_identity::guard_configured_pair_roots(&DesktopState::default(), root)
        .unwrap()
        .required_identity
        .clone();
    let pair = SyncPair {
        server_url: "https://drive.example.test".to_string(),
        account_email: "owner@example.test".to_string(),
        workspace_id: "workspace".to_string(),
        workspace_name: "Workspace".to_string(),
        remote_root_id: None,
        remote_root_name: None,
        local_root: root.to_path_buf(),
        local_root_identity: Some(identity),
    };
    let marker = PairMarker::from(&pair);
    pair_marker::write_or_recognize(root, &marker).unwrap();
    let mut state = DesktopState::default();
    state.configure_pair(pair.clone()).unwrap();
    state
        .begin_disconnect_cleanup(
            DisconnectCleanupIntent::for_disconnect_pairs(vec![pair], Vec::new()).unwrap(),
        )
        .unwrap();
    (state, marker)
}

#[test]
fn marker_removal_resumes_after_acknowledgement_save_failure() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("Drive");
    let (mut state, _) = cleanup_fixture(&root);
    fs::write(root.join("kept.txt"), b"local user file").unwrap();
    state
        .pending_disconnect_cleanup_mut()
        .unwrap()
        .confirm_remote_retirement();
    let mut state = state.into_disconnected(Utc::now());
    let store = StateStore::new(fixture.path().join("state.json"));
    store.save(&state).unwrap();
    let original_journal = fs::read(store.path()).unwrap();

    let blocked_parent = fixture.path().join("blocked-parent");
    fs::write(&blocked_parent, b"not a directory").unwrap();
    let failing_store = StateStore::new(blocked_parent.join("state.json"));
    assert!(complete_pending_local_cleanup(&failing_store, &mut state).is_err());
    assert!(!root.join(pair_marker::MARKER_FILE).exists());
    assert!(state.pending_disconnect_cleanup().unwrap().marker.is_some());
    assert_eq!(fs::read(store.path()).unwrap(), original_journal);

    // Startup sees the old journal but the exact marker deletion already ran.
    let mut restored = store.load().unwrap();
    resume_disconnected_local_cleanup(&store, &mut restored).unwrap();
    assert!(!restored.has_pending_disconnect_cleanup());
    assert!(!store.load().unwrap().has_pending_disconnect_cleanup());
    assert_eq!(fs::read(root.join("kept.txt")).unwrap(), b"local user file");
}

#[test]
fn local_cleanup_does_not_remove_a_marker_before_remote_retirement() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("Drive");
    let (mut state, marker) = cleanup_fixture(&root);
    let store = StateStore::new(fixture.path().join("state.json"));
    store.save(&state).unwrap();

    assert!(complete_pending_local_cleanup(&store, &mut state).is_err());
    pair_marker::require_exact(&root, &marker).unwrap();
    assert!(state.pair.is_some());
    assert!(!state
        .pending_disconnect_cleanup()
        .unwrap()
        .remote_retirement_confirmed());
}
