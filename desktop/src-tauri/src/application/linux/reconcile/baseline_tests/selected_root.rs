//! A selected remote folder is the local root, not a materialized child.

use super::*;

#[test]
fn empty_selected_folder_can_finish_without_recording_the_root_as_a_child() {
    let directory = tempfile::tempdir().expect("temporary root");
    let (pair, guard, root) = selected_pair(directory.path());
    let runtime = selected_runtime(directory.path(), &pair);
    let mut run = runtime.coordinator.begin_run().expect("sync reservation");
    let mut reads = ReadBudget::new_cycle(shellx_drive_desktop_core::sync_cycle_local_read_limit());

    finish_baseline(&mut run, &mut reads, &pair, &guard, &[root]).expect("empty selected baseline");

    assert!(run.state().baseline.is_empty());
    assert!(run.state().last_successful_sync.is_some());
    assert_eq!(run.state().activity.len(), 1);
    guard
        .require_exact_pair_marker(&PairMarker::from(&pair))
        .expect("selected-root marker remains intact");
}

#[test]
fn selected_folder_records_exact_matching_descendants_and_directory_identity() {
    let directory = tempfile::tempdir().expect("temporary root");
    let (pair, guard, root) = selected_pair(directory.path());
    fs::create_dir(pair.local_root.join("folder")).expect("materialized child directory");
    fs::write(
        pair.local_root.join("folder/inbound.md"),
        b"selected-root body",
    )
    .expect("materialized child file");
    let local = inspect_local_tree(&pair.local_root).expect("local selected tree");
    let file = local
        .entries
        .iter()
        .find(|entry| !entry.is_directory)
        .unwrap();
    let folder = RemoteEntry {
        id: "child-folder".to_string(),
        parent_id: Some(root.id.clone()),
        name: "folder".to_string(),
        ..root.clone()
    };
    let file = RemoteEntry {
        id: "child-file".to_string(),
        parent_id: Some(folder.id.clone()),
        name: "inbound.md".to_string(),
        kind: RemoteEntryKind::File,
        revision: 7,
        content_hash: file.content_hash.clone(),
        size_bytes: Some(file.size_bytes),
        trashed: false,
    };
    let runtime = selected_runtime(directory.path(), &pair);
    let mut run = runtime.coordinator.begin_run().expect("sync reservation");
    let mut reads = ReadBudget::new_cycle(shellx_drive_desktop_core::sync_cycle_local_read_limit());

    finish_baseline(
        &mut run,
        &mut reads,
        &pair,
        &guard,
        &[root, folder, file.clone()],
    )
    .expect("matching selected descendants");

    let baseline = &run.state().baseline;
    assert_eq!(baseline.len(), 2);
    assert!(!baseline.contains_key("selected-root"));
    assert_eq!(baseline["child-folder"].relative_path, Path::new("folder"));
    assert!(baseline["child-folder"].directory_identity.is_some());
    assert_eq!(
        baseline["child-file"].relative_path,
        Path::new("folder/inbound.md")
    );
    assert_eq!(baseline["child-file"].content_hash, file.content_hash);
    assert_eq!(baseline["child-file"].revision, 7);
    assert!(run.state().last_successful_sync.is_some());
}

fn selected_runtime(root: &Path, pair: &SyncPair) -> Runtime {
    let mut state = DesktopState::default();
    state
        .configure_pair(pair.clone())
        .expect("selected folder pair");
    Runtime::from_loaded_state(
        Box::new(TestPlatform(FakeCredentialStore::default())),
        StateStore::new(root.join("state.json")),
        state,
    )
}

fn selected_pair(root: &Path) -> (SyncPair, UnixRootGuard, RemoteEntry) {
    let local_root = root.join("Selected");
    fs::create_dir(&local_root).expect("create selected root");
    let guard = UnixRootGuard::acquire(&local_root, None).expect("root guard");
    let pair = SyncPair {
        server_url: "https://drive.example.test".to_string(),
        account_email: "owner@example.test".to_string(),
        workspace_id: "workspace".to_string(),
        workspace_name: "Workspace".to_string(),
        remote_root_id: Some("selected-root".to_string()),
        remote_root_name: Some("Selected".to_string()),
        local_root,
        local_root_identity: Some(guard.identity().clone()),
    };
    guard
        .write_or_recognize_pair_marker(&PairMarker::from(&pair))
        .expect("pair marker");
    let root = RemoteEntry {
        id: "selected-root".to_string(),
        parent_id: None,
        name: "Selected".to_string(),
        kind: RemoteEntryKind::Folder,
        revision: 3,
        content_hash: None,
        size_bytes: None,
        trashed: false,
    };
    (pair, guard, root)
}
