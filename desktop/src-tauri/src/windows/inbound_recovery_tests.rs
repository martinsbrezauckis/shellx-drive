//! Recovery publication regressions kept separate from inbound move coverage.

use super::*;

fn recovery_fixture(root: &Path, include_file: bool) -> (SyncPair, DesktopState, ReviewItem) {
    fs::create_dir(root.join("Projects")).unwrap();
    let folder_identity = capture_directory_identity(root, Path::new("Projects")).unwrap();
    let mut baseline = BTreeMap::from([(
        "folder".to_string(),
        BaselineEntry {
            remote_id: "folder".to_string(),
            parent_id: None,
            relative_path: PathBuf::from("Projects"),
            kind: "folder".to_string(),
            content_hash: None,
            revision: 1,
            directory_identity: Some(folder_identity),
        },
    )]);
    if include_file {
        fs::write(root.join("Projects/note.txt"), b"baseline").unwrap();
        let note = entry(root, Path::new("Projects/note.txt"));
        baseline.insert(
            "note".to_string(),
            BaselineEntry {
                remote_id: "note".to_string(),
                parent_id: Some("folder".to_string()),
                relative_path: PathBuf::from("Projects/note.txt"),
                kind: "file".to_string(),
                content_hash: note.content_hash,
                revision: 1,
                directory_identity: None,
            },
        );
    }
    let pair = SyncPair {
        server_url: "https://drive.test.invalid".to_string(),
        account_email: "acceptance@example.invalid".to_string(),
        workspace_id: "workspace".to_string(),
        workspace_name: "Acceptance".to_string(),
        remote_root_id: None,
        remote_root_name: None,
        local_root: root.to_path_buf(),
        local_root_identity: None,
    };
    let descendant_count = baseline.len().saturating_sub(1);
    (
        pair,
        DesktopState {
            baseline,
            ..DesktopState::default()
        },
        ReviewItem {
            id: "remote-delete:Projects".to_string(),
            kind: ReviewKind::RemoteDeletion,
            relative_path: PathBuf::from("Projects"),
            descendant_count,
            is_directory: true,
            summary: "fixture".to_string(),
            actions: vec![ReviewAction::RemoveLocalCopy],
        },
    )
}

fn assert_no_recovered_projects(parent: &TestDirectory) {
    let recovery_root = parent.path().join(".shellx-drive-recovery");
    if recovery_root.exists() {
        assert!(fs::read_dir(recovery_root)
            .unwrap()
            .all(|entry| { !entry.unwrap().path().join("Projects").exists() }));
    }
}

#[test]
fn recovery_rejects_a_recreated_folder_identity_before_moving_anything() {
    let parent = TestDirectory::new("recovery-directory-identity");
    let root = parent.path().join("pair");
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("Projects")).unwrap();
    let recreated_identity = capture_directory_identity(&root, Path::new("Projects")).unwrap();
    let saved_identity =
        WindowsDirectoryIdentity::windows(recreated_identity.volume_serial, [0x5a; 16]);
    assert_ne!(saved_identity, recreated_identity);
    let pair = SyncPair {
        server_url: "https://drive.test.invalid".to_string(),
        account_email: "acceptance@example.invalid".to_string(),
        workspace_id: "workspace".to_string(),
        workspace_name: "Acceptance".to_string(),
        remote_root_id: None,
        remote_root_name: None,
        local_root: root.clone(),
        local_root_identity: None,
    };
    let state = DesktopState {
        baseline: BTreeMap::from([(
            "folder".to_string(),
            BaselineEntry {
                remote_id: "folder".to_string(),
                parent_id: None,
                relative_path: PathBuf::from("Projects"),
                kind: "folder".to_string(),
                content_hash: None,
                revision: 1,
                directory_identity: Some(saved_identity),
            },
        )]),
        ..DesktopState::default()
    };
    let item = ReviewItem {
        id: "remote-delete:Projects".to_string(),
        kind: ReviewKind::RemoteDeletion,
        relative_path: PathBuf::from("Projects"),
        descendant_count: 0,
        is_directory: true,
        summary: "fixture".to_string(),
        actions: vec![ReviewAction::RemoveLocalCopy],
    };

    assert!(move_local_to_recovery(&pair, &state, &item).is_err());
    assert!(root.join("Projects").is_dir());
    assert!(!parent.path().join(".shellx-drive-recovery").exists());
}

#[test]
fn recovery_refuses_an_inherited_acl_sibling_before_moving_anything() {
    let parent = TestDirectory::new("recovery-foreign-acl");
    let root = parent.path().join("pair");
    fs::create_dir(&root).unwrap();
    let (pair, state, item) = recovery_fixture(&root, true);
    let foreign_recovery = parent.path().join(".shellx-drive-recovery");
    fs::create_dir(&foreign_recovery).unwrap();

    assert!(move_local_to_recovery(&pair, &state, &item).is_err());
    assert!(root.join("Projects/note.txt").is_file());
    assert!(foreign_recovery.is_dir());
}

#[test]
fn recovery_rechecks_a_late_file_edit_after_handles_are_pinned() {
    let parent = TestDirectory::new("recovery-late-file-edit");
    let root = parent.path().join("pair");
    fs::create_dir(&root).unwrap();
    let (pair, state, item) = recovery_fixture(&root, true);

    assert!(
        move_local_to_recovery_before_native(&pair, &state, &item, || {
            fs::write(root.join("Projects/note.txt"), b"late edit").unwrap();
            Ok(())
        })
        .is_err()
    );
    assert_eq!(
        fs::read(root.join("Projects/note.txt")).unwrap(),
        b"late edit"
    );
    assert!(root.join("Projects").is_dir());
    assert_no_recovered_projects(&parent);
}

#[test]
fn recovery_rechecks_a_late_new_descendant_after_handles_are_pinned() {
    let parent = TestDirectory::new("recovery-late-new-descendant");
    let root = parent.path().join("pair");
    fs::create_dir(&root).unwrap();
    let (pair, state, item) = recovery_fixture(&root, false);

    assert!(
        move_local_to_recovery_before_native(&pair, &state, &item, || {
            fs::write(root.join("Projects/late.txt"), b"new after review").unwrap();
            Ok(())
        })
        .is_err()
    );
    assert_eq!(
        fs::read(root.join("Projects/late.txt")).unwrap(),
        b"new after review"
    );
    assert!(root.join("Projects").is_dir());
    assert_no_recovered_projects(&parent);
}
