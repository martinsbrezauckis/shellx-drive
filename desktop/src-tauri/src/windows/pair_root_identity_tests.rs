use std::{fs, path::PathBuf, process::Command};

use shellx_drive_desktop_core::{DesktopState, SyncPair};

use super::super::root_materialization::ensure_local_directory_pinned;
use super::*;

struct SubstDrive(String);

impl Drop for SubstDrive {
    fn drop(&mut self) {
        let _ = Command::new("subst.exe").args([&self.0, "/D"]).status();
    }
}

fn pair(workspace: &str, root: PathBuf) -> SyncPair {
    SyncPair {
        server_url: "https://drive.example".to_string(),
        account_email: "owner@example.test".to_string(),
        workspace_id: workspace.to_string(),
        workspace_name: workspace.to_string(),
        remote_root_id: None,
        remote_root_name: None,
        local_root: root,
        local_root_identity: None,
    }
}

fn physically_bound_pair(workspace: &str, root: PathBuf) -> SyncPair {
    let identity = guard_configured_pair_roots(&DesktopState::default(), &root)
        .unwrap()
        .required_identity
        .clone();
    let mut pair = pair(workspace, root);
    pair.local_root_identity = Some(identity);
    pair
}

#[test]
fn configured_root_replacement_is_rejected_even_with_copied_exact_marker() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("Drive");
    let displaced = fixture.path().join("Drive-displaced");
    fs::create_dir(&root).unwrap();
    let pair = physically_bound_pair("workspace", root.clone());
    let marker = PairMarker::from(&pair);
    pair_marker::write_or_recognize(&root, &marker).unwrap();
    let mut state = DesktopState::default();
    state.configure_pair(pair).unwrap();

    assert!(guard_configured_pair_roots(&state, &root).is_ok());
    fs::rename(&root, &displaced).unwrap();
    fs::create_dir(&root).unwrap();
    pair_marker::write_or_recognize(&root, &marker).unwrap();

    assert!(matches!(
        guard_configured_pair_roots(&state, &root),
        Err(DesktopError::UnsafePath(message))
            if message.contains("configured Drive folder was replaced")
    ));
}

#[test]
fn base_and_child_replacement_at_marker_publication_are_blocked_without_publication() {
    let fixture = tempfile::tempdir().unwrap();
    let base = fixture.path().join("Drive");
    let displaced = fixture.path().join("Drive-displaced");
    let displaced_child = fixture.path().join("My-files-displaced");
    let relative = Path::new("My files");
    fs::create_dir(&base).unwrap();
    let directory_pins = ensure_local_directory_pinned(&base, relative).unwrap();
    let root = base.join(relative);
    let state = DesktopState::default();
    let guard = guard_configured_pair_roots(&state, &root).unwrap();
    let mut pair = pair("workspace", root.clone());
    pair.local_root_identity = Some(guard.required_identity.clone());
    let marker = PairMarker::from(&pair);
    let mut rename_was_blocked = false;
    let mut child_rename_was_blocked = false;

    let result = guard.write_or_recognize_marker_with_test_hook(&root, &marker, || {
        let rename = fs::rename(&base, &displaced);
        rename_was_blocked = rename.is_err();
        if rename.is_ok() {
            fs::create_dir(&base).unwrap();
        }
        child_rename_was_blocked = fs::rename(&root, &displaced_child).is_err();
        Err(DesktopError::InvalidState(
            "stop after the deterministic replacement probe".to_string(),
        ))
    });

    assert!(result.is_err());
    assert!(rename_was_blocked);
    assert!(child_rename_was_blocked);
    assert!(base.exists());
    assert!(!displaced.exists());
    assert!(!displaced_child.exists());
    assert!(!root.join(pair_marker::MARKER_FILE).exists());
    assert_eq!(state.pair_count(), 0);
    drop(guard);
    drop(directory_pins);
}

#[test]
fn legacy_pair_without_a_physical_identity_requires_repair() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("Drive");
    fs::create_dir(&root).unwrap();
    let pair = pair("workspace", root.clone());
    let marker = PairMarker::from(&pair);
    pair_marker::write_or_recognize(&root, &marker).unwrap();
    let mut state = DesktopState::default();
    state.configure_pair(pair).unwrap();

    assert!(matches!(
        guard_configured_pair_roots(&state, &root),
        Err(DesktopError::InvalidState(message))
            if message.contains("predates physical root binding")
    ));
}

#[test]
fn disconnected_root_accepts_an_absent_marker_but_active_root_rejects_it() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("Drive");
    fs::create_dir(&root).unwrap();
    let pair = physically_bound_pair("workspace", root.clone());
    let marker = PairMarker::from(&pair);
    pair_marker::write_or_recognize(&root, &marker).unwrap();
    let mut state = DesktopState::default();
    state.configure_pair(pair).unwrap();
    assert!(pair_marker::remove(&root, &marker).unwrap());

    assert!(guard_disconnected_pair_root(&root, &marker).is_ok());
    assert!(guard_configured_pair_roots(&state, &root).is_err());
}

#[test]
fn disconnected_root_rejects_a_present_foreign_marker_without_changing_it() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("Drive");
    fs::create_dir(&root).unwrap();
    let pair = physically_bound_pair("workspace", root.clone());
    let marker = PairMarker::from(&pair);
    let mut foreign = marker.clone();
    foreign.workspace_id = "another-workspace".to_string();
    let bytes = serde_json::to_vec(&foreign).unwrap();
    fs::write(root.join(pair_marker::MARKER_FILE), &bytes).unwrap();

    assert!(guard_disconnected_pair_root(&root, &marker).is_err());
    assert_eq!(
        fs::read(root.join(pair_marker::MARKER_FILE)).unwrap(),
        bytes
    );
}

#[test]
fn disconnected_root_replacement_is_rejected_even_with_an_absent_marker() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("Drive");
    fs::create_dir(&root).unwrap();
    let pair = physically_bound_pair("workspace", root.clone());
    let marker = PairMarker::from(&pair);
    fs::rename(&root, fixture.path().join("Drive-displaced")).unwrap();
    fs::create_dir(&root).unwrap();

    assert!(matches!(
        guard_disconnected_pair_root(&root, &marker),
        Err(DesktopError::UnsafePath(message))
            if message.contains("configured Drive folder was replaced")
    ));
}

#[tokio::test]
async fn pinned_root_blocks_remote_mutation_callback_after_marker_removal() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("Drive");
    fs::create_dir(&root).unwrap();
    let pair = physically_bound_pair("workspace", root.clone());
    pair_marker::write_or_recognize(&root, &PairMarker::from(&pair)).unwrap();
    let mut state = DesktopState::default();
    state.configure_pair(pair.clone()).unwrap();

    let _initial_guard = guard_configured_pair_roots(&state, &root).unwrap();
    fs::remove_file(root.join(pair_marker::MARKER_FILE)).unwrap();
    let mut called = false;
    let result = super::super::with_current_pair_remote_mutation(&state, &pair, || {
        called = true;
        async { Ok(()) }
    })
    .await;
    assert!(result.is_err());
    assert!(!called);
}

#[tokio::test]
async fn current_pair_runs_remote_mutation_callback_with_root_pinned() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path().join("Drive");
    fs::create_dir(&root).unwrap();
    let pair = physically_bound_pair("workspace", root.clone());
    pair_marker::write_or_recognize(&root, &PairMarker::from(&pair)).unwrap();
    let mut state = DesktopState::default();
    state.configure_pair(pair.clone()).unwrap();

    let mut called = false;
    super::super::with_current_pair_remote_mutation(&state, &pair, || {
        called = true;
        async { Ok(()) }
    })
    .await
    .unwrap();
    assert!(called);
}

#[test]
fn subst_alias_nested_root_is_rejected() {
    let fixture = tempfile::tempdir().unwrap();
    let outer = fixture.path().join("outer");
    let child = outer.join("child");
    fs::create_dir_all(&child).unwrap();
    let drive = (b'D'..=b'Z')
        .rev()
        .map(|letter| format!("{}:", char::from(letter)))
        .find(|drive| !Path::new(&format!("{drive}\\")).exists())
        .expect("a temporary SUBST drive letter is required");
    let status = Command::new("subst.exe")
        .args([&drive, outer.to_str().unwrap()])
        .status()
        .unwrap();
    assert!(status.success());
    let _mapping = SubstDrive(drive.clone());

    let mut state = DesktopState::default();
    state.configure_pair(pair("outer", outer.clone())).unwrap();
    let alias_child = PathBuf::from(format!("{drive}\\child"));
    assert!(guard_configured_pair_roots(&state, &alias_child).is_err());
}
