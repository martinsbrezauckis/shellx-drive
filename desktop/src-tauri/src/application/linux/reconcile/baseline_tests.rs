//! Linux successful-baseline activity regressions.

use std::{
    fs,
    path::{Path, PathBuf},
};

use shellx_drive_desktop_core::{
    sync_pair_id, DesktopState, FakeCredentialStore, PairMarker, StateStore, SyncPair,
};

use crate::application::{runtime::tests::TestPlatform, Runtime};

use super::*;

#[test]
fn initial_inbound_baseline_persists_and_projects_history_after_another_root() {
    let directory = tempfile::tempdir().expect("temporary roots");
    let (first, first_guard) = paired_root(directory.path(), "Earlier", "earlier-workspace");
    fs::write(first.local_root.join("inbound.md"), b"inbound from Drive")
        .expect("materialized inbound file");
    let (selected, _) = paired_root(directory.path(), "Selected", "selected-workspace");
    let mut state = DesktopState::default();
    state.configure_pair(first.clone()).expect("first root");
    state.configure_pair(selected).expect("selected root");
    let runtime = Runtime::from_loaded_state(
        Box::new(TestPlatform(FakeCredentialStore::default())),
        StateStore::new(directory.path().join("state.json")),
        state,
    );
    let first_id = sync_pair_id(&first);
    let mut run = runtime.coordinator.begin_run().expect("sync reservation");
    let mut reads = ReadBudget::new_cycle(shellx_drive_desktop_core::sync_cycle_local_read_limit());
    let selected_id = run.selected_pair_id().expect("selected root id");

    run.activate_configured_pair(&first_id)
        .expect("first root activation");
    finish_baseline(
        &mut run,
        &mut reads,
        &first,
        &first_guard,
        &[inbound_entry(&first)],
    )
    .expect("baseline");
    let completed = run
        .finalize_all_roots_state(&selected_id)
        .expect("restore selected root");
    run.finish_state(completed);
    runtime.save().expect("persist cycle");

    let persisted = runtime.store.load().expect("load persisted cycle");
    let retained = persisted
        .inactive_pairs
        .iter()
        .find(|profile| sync_pair_id(&profile.pair) == first_id)
        .expect("retained earlier root");
    assert_eq!(retained.baseline.len(), 1);
    assert_eq!(
        retained.baseline["inbound"].relative_path,
        PathBuf::from("inbound.md")
    );
    assert_eq!(retained.activity.len(), 1);
    assert_eq!(retained.activity[0].direction, "Sync");
    assert_eq!(
        retained.activity[0].result,
        "Linux Drive reconciliation completed."
    );

    runtime
        .coordinator
        .activate_pair(&first_id)
        .expect("select retained root");
    assert_eq!(runtime.view().activity, retained.activity);
}

#[path = "baseline_tests/final_manifest.rs"]
mod final_manifest;

#[path = "baseline_tests/selected_root.rs"]
mod selected_root;

pub(super) fn paired_root(
    root: &Path,
    name: &str,
    workspace_id: &str,
) -> (SyncPair, UnixRootGuard) {
    let local_root = root.join(name);
    fs::create_dir(&local_root).expect("create local root");
    let guard = UnixRootGuard::acquire(&local_root, None).expect("root guard");
    let pair = SyncPair {
        server_url: "https://drive.example.test".to_string(),
        account_email: "owner@example.test".to_string(),
        workspace_id: workspace_id.to_string(),
        workspace_name: name.to_string(),
        remote_root_id: None,
        remote_root_name: None,
        local_root,
        local_root_identity: Some(guard.identity().clone()),
    };
    guard
        .write_or_recognize_pair_marker(&PairMarker::from(&pair))
        .expect("pair marker");
    (pair, guard)
}

pub(super) fn inbound_entry(pair: &SyncPair) -> RemoteEntry {
    let local = inspect_local_tree(&pair.local_root).expect("inspect inbound root");
    let inbound = local
        .entries
        .iter()
        .find(|entry| entry.relative_path == Path::new("inbound.md"))
        .expect("inbound entry");
    RemoteEntry {
        id: "inbound".to_string(),
        parent_id: None,
        name: "inbound.md".to_string(),
        kind: RemoteEntryKind::File,
        revision: 1,
        content_hash: inbound.content_hash.clone(),
        size_bytes: Some(inbound.size_bytes),
        trashed: false,
    }
}
