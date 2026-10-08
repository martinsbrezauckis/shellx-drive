//! Final-manifest admission must retain unresolved local or remote changes.

use super::*;

#[test]
fn final_manifest_deletion_keeps_baseline_and_requires_remote_deletion_review() {
    let directory = tempfile::tempdir().expect("temporary roots");
    let (pair, guard) = paired_root(directory.path(), "Drive", "workspace");
    fs::write(
        pair.local_root.join("inbound.md"),
        b"materialized before final manifest",
    )
    .expect("retained local body");
    let entry = inbound_entry(&pair);
    let mut state = DesktopState::default();
    state.configure_pair(pair.clone()).expect("configured root");
    state.baseline.insert(
        entry.id.clone(),
        BaselineEntry {
            remote_id: entry.id.clone(),
            parent_id: None,
            relative_path: PathBuf::from("inbound.md"),
            kind: "file".to_string(),
            content_hash: entry.content_hash,
            revision: entry.revision,
            directory_identity: None,
        },
    );
    let prior_baseline = state.baseline.clone();
    let runtime = Runtime::from_loaded_state(
        Box::new(TestPlatform(FakeCredentialStore::default())),
        StateStore::new(directory.path().join("state.json")),
        state,
    );
    let mut run = runtime.coordinator.begin_run().expect("sync reservation");
    let mut reads = ReadBudget::new_cycle(shellx_drive_desktop_core::sync_cycle_local_read_limit());

    // Drive deleted the tracked file during the final manifest request. The
    // local body still exists, so accepting an empty baseline would make the
    // next pass upload it as a new file and silently reverse that deletion.
    assert_eq!(
        finish_baseline(&mut run, &mut reads, &pair, &guard, &[]).unwrap(),
        SyncAttemptDisposition::TreeChanged
    );
    assert_eq!(run.state().baseline, prior_baseline);
    assert!(run.state().last_successful_sync.is_none());
    let local = inspect_local_tree(&pair.local_root).expect("retained local tree");
    let next = run
        .plan(&[], &local.entries, Utc::now())
        .expect("next plan");
    assert!(next.actions.is_empty());
    assert_eq!(next.reviews.len(), 1);
    assert_eq!(next.reviews[0].kind, ReviewKind::RemoteDeletion);
    assert_eq!(next.reviews[0].relative_path, PathBuf::from("inbound.md"));
    assert_eq!(
        fs::read(pair.local_root.join("inbound.md")).expect("preserved body"),
        b"materialized before final manifest"
    );
}

#[test]
fn new_local_file_before_final_manifest_cannot_be_reported_as_synced() {
    let directory = tempfile::tempdir().expect("temporary roots");
    let (pair, guard) = paired_root(directory.path(), "Drive", "workspace");
    fs::write(pair.local_root.join("inbound.md"), b"already in Drive").expect("matched local body");
    let entry = inbound_entry(&pair);
    fs::write(pair.local_root.join("late.md"), b"not uploaded yet")
        .expect("new local body after planning");
    let mut state = DesktopState::default();
    state.configure_pair(pair.clone()).expect("configured root");
    let runtime = Runtime::from_loaded_state(
        Box::new(TestPlatform(FakeCredentialStore::default())),
        StateStore::new(directory.path().join("state.json")),
        state,
    );
    let mut run = runtime.coordinator.begin_run().expect("sync reservation");
    let mut reads = ReadBudget::new_cycle(shellx_drive_desktop_core::sync_cycle_local_read_limit());

    assert_eq!(
        finish_baseline(&mut run, &mut reads, &pair, &guard, &[entry]).unwrap(),
        SyncAttemptDisposition::TreeChanged
    );
    assert!(run.state().baseline.is_empty());
    assert!(run.state().last_successful_sync.is_none());
    assert!(run.state().activity.is_empty());
}

#[test]
fn final_manifest_file_size_must_match_its_local_body() {
    let directory = tempfile::tempdir().expect("temporary roots");
    let (pair, guard) = paired_root(directory.path(), "Drive", "workspace");
    fs::write(pair.local_root.join("inbound.md"), b"exact local body")
        .expect("materialized local body");
    let mut entry = inbound_entry(&pair);
    entry.size_bytes = entry.size_bytes.map(|size| size + 1);
    let mut state = DesktopState::default();
    state.configure_pair(pair.clone()).expect("configured root");
    let runtime = Runtime::from_loaded_state(
        Box::new(TestPlatform(FakeCredentialStore::default())),
        StateStore::new(directory.path().join("state.json")),
        state,
    );
    let mut run = runtime.coordinator.begin_run().expect("sync reservation");
    let mut reads = ReadBudget::new_cycle(shellx_drive_desktop_core::sync_cycle_local_read_limit());

    assert_eq!(
        finish_baseline(&mut run, &mut reads, &pair, &guard, &[entry]).unwrap(),
        SyncAttemptDisposition::TreeChanged
    );
    assert!(run.state().baseline.is_empty());
    assert!(run.state().last_successful_sync.is_none());
}
