//! Windows inbound publication and recovery regression coverage.

use std::{
    cell::Cell,
    collections::BTreeMap,
    fs,
    io::Write,
    os::windows::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    process,
    sync::atomic::{AtomicU64, Ordering},
};

use super::verified_staging::{move_verified_staged_file, VerifiedStagedFile};

use super::*;

#[path = "inbound_recovery_tests.rs"]
mod recovery;

static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "shellx-drive-desktop-{label}-{}-{}",
            process::id(),
            NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::AcqRel),
        ));
        fs::create_dir_all(&root).unwrap();
        Self(root)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn entry(root: &Path, relative: &Path) -> LocalEntry {
    scan_local_tree(root)
        .unwrap()
        .into_iter()
        .find(|entry| entry.relative_path == relative)
        .unwrap()
}

fn staged(root: &Path, name: &str, body: &[u8]) -> PathBuf {
    let path = root.parent().unwrap().join(name);
    fs::write(&path, body).unwrap();
    path
}

#[test]
fn stable_upload_snapshot_matches_source_and_retires_on_ntfs() {
    let parent = TestDirectory::new("upload-snapshot");
    let root = parent.path().join("pair");
    fs::create_dir(&root).unwrap();
    let relative = Path::new("from-local.txt");
    fs::write(root.join(relative), b"stable local upload body").unwrap();
    let mut budget = local_read_budget_for_sync_pass();

    let snapshot = snapshot_upload_source(&root, relative, &mut budget).unwrap();

    assert!(upload_source_still_matches(&root, &snapshot, &mut budget).unwrap());
    assert!(verify_upload_snapshot(&snapshot).unwrap());
    retire_upload_snapshot(&snapshot).unwrap();
}

#[test]
fn root_level_staged_payload_reuses_its_verified_batch_directory() {
    let batch = TestDirectory::new("root-level-staged-payload");

    ensure_local_directory(batch.path(), Path::new("")).unwrap();

    assert!(batch.path().is_dir());
}

fn witness_precondition() -> FolderMovePrecondition {
    let identity = WindowsDirectoryIdentity::windows(42, [7; 16]);
    FolderMovePrecondition {
        identity: identity.clone(),
        entries: BTreeMap::from([(
            PathBuf::new(),
            shellx_drive_desktop_core::FolderMoveEntry {
                content_hash: None,
                is_directory: true,
                directory_identity: Some(identity),
            },
        )]),
        remote_witness: None,
    }
}

#[test]
fn executor_preflight_witness_mismatch_runs_no_native_folder_move() {
    let moved = Cell::new(false);
    let precondition = witness_precondition();
    let outcome = execute_inbound_folder_move_preflight(
        Path::new("P"),
        Path::new("Q"),
        &precondition,
        false,
        || {
            moved.set(true);
            Ok(())
        },
    )
    .unwrap();
    assert!(!moved.get());
    assert!(matches!(
        outcome,
        NonDeleteExecution::NeedsReview(reviews)
            if reviews.len() == 1
                && reviews[0].id.contains("drive-preflight")
                && reviews[0].descendant_count == 0
    ));
}

#[test]
fn executor_postflight_witness_mismatch_stops_descendant_and_baseline_work() {
    let root_moved = Cell::new(false);
    let descendant_or_baseline_advanced = Cell::new(false);
    let precondition = witness_precondition();
    let root_outcome = execute_inbound_folder_move_preflight(
        Path::new("P"),
        Path::new("Q"),
        &precondition,
        true,
        || {
            root_moved.set(true);
            Ok(())
        },
    )
    .unwrap();
    assert!(matches!(root_outcome, NonDeleteExecution::Complete));
    assert!(root_moved.get());

    match finish_inbound_folder_move_postflight(
        Path::new("P"),
        Path::new("Q"),
        &precondition,
        false,
    ) {
        NonDeleteExecution::NeedsReview(reviews) => {
            assert_eq!(reviews.len(), 1);
            assert!(reviews[0].id.contains("drive-postmove"));
            assert!(reviews[0].summary.contains("P to Q completed"));
        }
        NonDeleteExecution::Complete => {
            // The real executor only reaches descendant actions and
            // final baseline construction on Complete.
            descendant_or_baseline_advanced.set(true);
        }
    }
    assert!(!descendant_or_baseline_advanced.get());
}

#[test]
fn outbound_folder_postpatch_edit_stops_child_actions_and_baseline_adoption() {
    let parent = TestDirectory::new("outbound-folder-postpatch-edit");
    let root = parent.path().join("pair");
    fs::create_dir(&root).unwrap();
    fs::create_dir_all(root.join("Renamed/Child")).unwrap();
    fs::write(root.join("Renamed/Child/note.txt"), b"baseline").unwrap();
    let inspection = inspect_local_tree_with_directory_identities(&root).unwrap();
    let identity = capture_directory_identity(&root, Path::new("Renamed")).unwrap();
    let entries = inspection
        .entries
        .iter()
        .filter(|entry| entry.relative_path.starts_with("Renamed"))
        .map(|entry| {
            (
                entry
                    .relative_path
                    .strip_prefix("Renamed")
                    .unwrap()
                    .to_path_buf(),
                shellx_drive_desktop_core::FolderMoveEntry {
                    content_hash: entry.content_hash.clone(),
                    is_directory: entry.is_directory,
                    directory_identity: entry.directory_identity.clone(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let precondition = FolderMovePrecondition {
        identity,
        entries,
        remote_witness: None,
    };
    assert!(folder_move_source_still_matches(&root, Path::new("Renamed"), &precondition,).unwrap());

    // Model a child edit after Drive has accepted the root PATCH and
    // before the executor can start any next action/final baseline.
    fs::write(root.join("Renamed/Child/note.txt"), b"late local edit").unwrap();
    let outcome = finish_outbound_folder_move_postpatch(
        Path::new("Renamed"),
        &precondition,
        folder_move_source_still_matches(&root, Path::new("Renamed"), &precondition).unwrap(),
    );
    let descendant_or_baseline_advanced = Cell::new(false);
    match outcome {
        NonDeleteExecution::NeedsReview(reviews) => {
            assert_eq!(reviews.len(), 1);
            assert!(reviews[0].id.contains("postpatch"));
            assert_eq!(reviews[0].descendant_count, 2);
            assert!(reviews[0]
                .summary
                .contains("Drive accepted the folder rename"));
        }
        NonDeleteExecution::Complete => descendant_or_baseline_advanced.set(true),
    }
    assert!(!descendant_or_baseline_advanced.get());
    assert_eq!(
        fs::read(root.join("Renamed/Child/note.txt")).unwrap(),
        b"late local edit"
    );
}

#[test]
fn handle_relative_replace_publishes_exact_bodies_without_backups() {
    let parent = TestDirectory::new("replace");
    let root = parent.path().join("pair");
    fs::create_dir(&root).unwrap();
    let destination = root.join("report.bin");
    fs::write(&destination, b"baseline").unwrap();
    for round in 0..3 {
        let precondition =
            DownloadPrecondition::observed(Some(&entry(&root, Path::new("report.bin"))));
        let boundary = capture_local_operation_boundary(&root, &destination).unwrap();
        let body = format!("remote-body-{round}");
        let replacement = staged(
            &root,
            &format!("verified-remote-{round}.bin"),
            body.as_bytes(),
        );
        let outcome = publish_staged_download(
            &root,
            Path::new("report.bin"),
            &destination,
            &replacement,
            &precondition,
            &boundary,
        )
        .unwrap();

        assert!(matches!(outcome, DownloadPublication::Published));
        assert_eq!(fs::read(&destination).unwrap(), body.as_bytes());
        assert!(!replacement.exists());
    }
    assert_eq!(
        fs::read_dir(parent.path()).unwrap().count(),
        1,
        "handle-relative replacement must not accumulate backup paths"
    );
}

#[test]
fn verified_staged_handle_rejects_writers_through_native_publication() {
    let parent = TestDirectory::new("verified-staged-handle");
    let root = parent.path().join("pair");
    let batch = parent.path().join("batch");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&batch).unwrap();
    let staged = batch.join("payload");
    let destination = root.join("report.bin");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .access_mode(
            windows_sys::Win32::Foundation::GENERIC_WRITE
                | windows_sys::Win32::Storage::FileSystem::DELETE
                | windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES,
        )
        .create_new(true)
        .share_mode(windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ)
        .custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT)
        .open(&staged)
        .unwrap();
    file.write_all(b"hash-verified-body").unwrap();
    file.sync_all().unwrap();
    let verified = VerifiedStagedFile(file);
    assert!(fs::OpenOptions::new().write(true).open(&staged).is_err());

    move_verified_staged_file(
        &batch,
        &staged,
        &verified,
        &destination,
        &root,
        false,
        || {
            assert!(fs::OpenOptions::new().write(true).open(&staged).is_err());
            Ok(())
        },
    )
    .unwrap();

    assert_eq!(fs::read(&destination).unwrap(), b"hash-verified-body");
    drop(verified);
}

#[test]
fn replacement_race_keeps_local_bytes_and_returns_needs_review() {
    let parent = TestDirectory::new("replacement-race");
    let root = parent.path().join("pair");
    fs::create_dir(&root).unwrap();
    let destination = root.join("report.bin");
    fs::write(&destination, b"baseline").unwrap();
    let precondition = DownloadPrecondition::observed(Some(&entry(&root, Path::new("report.bin"))));
    let boundary = capture_local_operation_boundary(&root, &destination).unwrap();
    let replacement = staged(&root, "verified-remote.bin", b"remote-body");
    fs::write(&destination, b"local-edit-after-download").unwrap();

    let outcome = publish_staged_download(
        &root,
        Path::new("report.bin"),
        &destination,
        &replacement,
        &precondition,
        &boundary,
    )
    .unwrap();

    assert!(matches!(outcome, DownloadPublication::NeedsReview { .. }));
    assert_eq!(
        fs::read(&destination).unwrap(),
        b"local-edit-after-download"
    );
    assert_eq!(fs::read(&replacement).unwrap(), b"remote-body");
}

#[test]
fn conflict_copy_publication_race_replaces_the_optimistic_review_claim() {
    let conflict_path = Path::new("report (Drive conflict 2026-09-03 120000).bin");
    let mut reviews = vec![ReviewItem {
        id: "ContentConflict:report.bin".to_string(),
        kind: ReviewKind::ContentConflict,
        relative_path: conflict_path.to_path_buf(),
        descendant_count: 0,
        is_directory: false,
        summary: "Both copies changed. The Drive copy is written beside the local copy."
            .to_string(),
        actions: vec![ReviewAction::OpenConflictCopies],
    }];

    merge_conflict_copy_publication_review(
        &mut reviews,
        conflict_path,
        DownloadPublication::NeedsReview {
            review: download_race_review(conflict_path),
        },
    )
    .unwrap();

    assert_eq!(reviews.len(), 1);
    assert_eq!(reviews[0].id, "ContentConflict:report.bin");
    assert_eq!(reviews[0].relative_path, conflict_path);
    assert!(reviews[0].summary.contains("Local state changed"));
    assert!(!reviews[0].summary.contains("Drive copy is written"));
    assert_eq!(reviews[0].actions, vec![ReviewAction::OpenConflictCopies]);
}

#[test]
fn conflict_copy_without_a_visible_bound_review_is_rejected_before_transfer() {
    let error = validate_planned_conflict_copy_review(
        &[],
        Path::new("report (Drive conflict 2026-09-03 120000).bin"),
    )
    .expect_err("unbound copy");

    assert!(error
        .to_string()
        .contains("matching visible content-conflict review"));
}

#[test]
fn movefileex_moves_only_an_unchanged_source_without_a_duplicate() {
    let parent = TestDirectory::new("move");
    let root = parent.path().join("pair");
    fs::create_dir(&root).unwrap();
    let from = Path::new("before.bin");
    let to = Path::new("after.bin");
    fs::write(root.join(from), b"baseline").unwrap();
    let precondition = DownloadPrecondition::observed(Some(&entry(&root, from)));

    move_unchanged_local_path(&root, from, to, &precondition).unwrap();

    assert!(!root.join(from).exists());
    assert_eq!(fs::read(root.join(to)).unwrap(), b"baseline");
    assert_eq!(scan_local_tree(&root).unwrap().len(), 1);
}

#[test]
fn occupied_move_destination_preserves_the_source() {
    let parent = TestDirectory::new("move-race");
    let root = parent.path().join("pair");
    fs::create_dir(&root).unwrap();
    let from = Path::new("before.bin");
    let to = Path::new("after.bin");
    fs::write(root.join(from), b"baseline").unwrap();
    let precondition = DownloadPrecondition::observed(Some(&entry(&root, from)));
    fs::write(root.join(to), b"local-destination").unwrap();

    assert!(move_unchanged_local_path(&root, from, to, &precondition).is_err());
    assert_eq!(fs::read(root.join(from)).unwrap(), b"baseline");
    assert_eq!(fs::read(root.join(to)).unwrap(), b"local-destination");
}

#[test]
fn replacement_refuses_a_reparse_target_without_touching_its_target() {
    use std::os::windows::fs::symlink_file;

    let parent = TestDirectory::new("reparse");
    let root = parent.path().join("pair");
    fs::create_dir(&root).unwrap();
    let destination = root.join("report.bin");
    let outside = parent.path().join("outside.bin");
    fs::write(&destination, b"baseline").unwrap();
    fs::write(&outside, b"outside-bytes").unwrap();
    let precondition = DownloadPrecondition::observed(Some(&entry(&root, Path::new("report.bin"))));
    let boundary = capture_local_operation_boundary(&root, &destination).unwrap();
    let replacement = staged(&root, "verified-remote.bin", b"remote-body");
    fs::remove_file(&destination).unwrap();
    if let Err(error) = symlink_file(&outside, &destination) {
        // Some Windows test hosts prohibit unprivileged symlink
        // creation. The installed NTFS acceptance case remains the
        // required proof there; compilation still covers the same
        // no-follow executor path.
        if error.raw_os_error() == Some(1314) {
            return;
        }
        panic!("could not create reparse-point test fixture: {error}");
    }

    let outcome = publish_staged_download(
        &root,
        Path::new("report.bin"),
        &destination,
        &replacement,
        &precondition,
        &boundary,
    )
    .unwrap();

    assert!(matches!(outcome, DownloadPublication::NeedsReview { .. }));
    assert_eq!(fs::read(&outside).unwrap(), b"outside-bytes");
    assert_eq!(fs::read(&replacement).unwrap(), b"remote-body");
}

#[test]
fn checked_ntfs_directory_identity_survives_move_but_not_copy_or_recreate() {
    let parent = TestDirectory::new("directory-identity");
    let root = parent.path().join("pair");
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("Projects")).unwrap();
    let original = capture_directory_identity(&root, Path::new("Projects")).unwrap();

    fs::rename(root.join("Projects"), root.join("Renamed")).unwrap();
    assert_eq!(
        capture_directory_identity(&root, Path::new("Renamed")).unwrap(),
        original
    );

    fs::create_dir(root.join("Copy")).unwrap();
    assert_ne!(
        capture_directory_identity(&root, Path::new("Copy")).unwrap(),
        original
    );
    fs::remove_dir(root.join("Renamed")).unwrap();
    fs::create_dir(root.join("Renamed")).unwrap();
    assert_ne!(
        capture_directory_identity(&root, Path::new("Renamed")).unwrap(),
        original
    );
}

#[test]
fn verified_baseline_persists_checked_directory_identity_for_future_moves() {
    let parent = TestDirectory::new("baseline-directory-identity");
    let root = parent.path().join("pair");
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("Projects")).unwrap();
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
    let baseline = verify_and_build_baseline(
        &pair,
        &[RemoteEntry {
            id: "folder".to_string(),
            parent_id: None,
            name: "Projects".to_string(),
            kind: RemoteEntryKind::Folder,
            revision: 1,
            content_hash: None,
            size_bytes: None,
            trashed: false,
        }],
        &BTreeMap::new(),
    )
    .unwrap();
    let BaselineFinalization::Complete(baseline) = baseline else {
        panic!("a new folder must establish its first checked identity");
    };
    assert_eq!(
        baseline["folder"].directory_identity,
        Some(capture_directory_identity(&root, Path::new("Projects")).unwrap())
    );
}

#[test]
fn finalization_refuses_a_recreated_folder_and_keeps_the_prior_baseline() {
    let parent = TestDirectory::new("finalization-identity-swap");
    let root = parent.path().join("pair");
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("Projects")).unwrap();
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
    let remote = vec![RemoteEntry {
        id: "folder".to_string(),
        parent_id: None,
        name: "Projects".to_string(),
        kind: RemoteEntryKind::Folder,
        revision: 1,
        content_hash: None,
        size_bytes: None,
        trashed: false,
    }];
    let BaselineFinalization::Complete(prior) =
        verify_and_build_baseline(&pair, &remote, &BTreeMap::new()).unwrap()
    else {
        panic!("initial checked baseline must complete");
    };
    let original_identity = prior["folder"]
        .directory_identity
        .clone()
        .expect("initial baseline captured the folder identity");

    // This models a replacement between a completed root move/PATCH
    // and the final fresh manifest/baseline pass.
    fs::remove_dir(root.join("Projects")).unwrap();
    fs::create_dir(root.join("Projects")).unwrap();
    assert_ne!(
        capture_directory_identity(&root, Path::new("Projects")).unwrap(),
        original_identity
    );

    let result = verify_and_build_baseline(&pair, &remote, &prior).unwrap();
    assert!(matches!(
        result,
        BaselineFinalization::NeedsReview(ReviewItem {
            relative_path,
            is_directory: true,
            descendant_count: 0,
            ..
        }) if relative_path == Path::new("Projects")
    ));
    // `verify_and_build_baseline` only received an immutable prior
    // map, and the local replacement remains untouched for review.
    assert_eq!(prior["folder"].directory_identity, Some(original_identity));
    assert!(root.join("Projects").is_dir());
}

#[test]
fn finalization_reports_an_intermediate_folder_move_when_drive_moves_again() {
    let parent = TestDirectory::new("finalization-folder-moved-again");
    let root = parent.path().join("pair");
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("Q")).unwrap();
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
    let identity = capture_directory_identity(&root, Path::new("Q")).unwrap();
    let prior = BTreeMap::from([(
        "folder".to_string(),
        BaselineEntry {
            remote_id: "folder".to_string(),
            parent_id: None,
            relative_path: PathBuf::from("P"),
            kind: "folder".to_string(),
            content_hash: None,
            revision: 1,
            directory_identity: Some(identity.clone()),
        },
    )]);
    let remote = vec![RemoteEntry {
        id: "folder".to_string(),
        parent_id: None,
        name: "R".to_string(),
        kind: RemoteEntryKind::Folder,
        revision: 3,
        content_hash: None,
        size_bytes: None,
        trashed: false,
    }];

    let result = verify_and_build_baseline(&pair, &remote, &prior).unwrap();
    assert!(matches!(
        result,
        BaselineFinalization::NeedsReview(ReviewItem {
            relative_path,
            descendant_count: 0,
            is_directory: true,
            summary,
            ..
        }) if relative_path == Path::new("Q")
            && summary.contains("from P to Q completed")
            && summary.contains("again to R")
    ));
    assert_eq!(prior["folder"].directory_identity, Some(identity));
    assert!(root.join("Q").is_dir());
    assert!(!root.join("R").exists());
}

#[test]
fn finalization_reports_moved_again_when_new_drive_path_has_a_local_collision() {
    let parent = TestDirectory::new("finalization-folder-moved-again-collision");
    let root = parent.path().join("pair");
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("Q")).unwrap();
    fs::write(root.join("R"), b"different local item").unwrap();
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
    let identity = capture_directory_identity(&root, Path::new("Q")).unwrap();
    let prior = BTreeMap::from([(
        "folder".to_string(),
        BaselineEntry {
            remote_id: "folder".to_string(),
            parent_id: None,
            relative_path: PathBuf::from("P"),
            kind: "folder".to_string(),
            content_hash: None,
            revision: 1,
            directory_identity: Some(identity.clone()),
        },
    )]);
    let remote = vec![RemoteEntry {
        id: "folder".to_string(),
        parent_id: None,
        name: "R".to_string(),
        kind: RemoteEntryKind::Folder,
        revision: 3,
        content_hash: None,
        size_bytes: None,
        trashed: false,
    }];

    let result = verify_and_build_baseline(&pair, &remote, &prior).unwrap();
    assert!(matches!(
        result,
        BaselineFinalization::NeedsReview(ReviewItem {
            relative_path,
            descendant_count: 0,
            is_directory: true,
            summary,
            ..
        }) if relative_path == Path::new("Q")
            && summary.contains("from P to Q completed")
            && summary.contains("again to R")
            && summary.contains("already occupied by a different local item")
    ));
    assert_eq!(prior["folder"].directory_identity, Some(identity));
    assert!(root.join("Q").is_dir());
    assert_eq!(fs::read(root.join("R")).unwrap(), b"different local item");
}

#[test]
fn finalization_allows_a_remote_child_body_update_when_folder_identity_is_stable() {
    let parent = TestDirectory::new("finalization-child-body");
    let root = parent.path().join("pair");
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("Projects")).unwrap();
    fs::write(root.join("Projects/report.txt"), b"new remote body").unwrap();
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
    let folder_identity = capture_directory_identity(&root, Path::new("Projects")).unwrap();
    let body = entry(&root, Path::new("Projects/report.txt"));
    let prior = BTreeMap::from([
        (
            "folder".to_string(),
            BaselineEntry {
                remote_id: "folder".to_string(),
                parent_id: None,
                relative_path: PathBuf::from("Projects"),
                kind: "folder".to_string(),
                content_hash: None,
                revision: 1,
                directory_identity: Some(folder_identity.clone()),
            },
        ),
        (
            "child".to_string(),
            BaselineEntry {
                remote_id: "child".to_string(),
                parent_id: Some("folder".to_string()),
                relative_path: PathBuf::from("Projects/report.txt"),
                kind: "file".to_string(),
                content_hash: Some("old body".to_string()),
                revision: 1,
                directory_identity: None,
            },
        ),
    ]);
    let remote = vec![
        RemoteEntry {
            id: "folder".to_string(),
            parent_id: None,
            name: "Projects".to_string(),
            kind: RemoteEntryKind::Folder,
            revision: 1,
            content_hash: None,
            size_bytes: None,
            trashed: false,
        },
        RemoteEntry {
            id: "child".to_string(),
            parent_id: Some("folder".to_string()),
            name: "report.txt".to_string(),
            kind: RemoteEntryKind::File,
            revision: 2,
            content_hash: body.content_hash.clone(),
            size_bytes: Some(body.size_bytes),
            trashed: false,
        },
    ];

    let BaselineFinalization::Complete(baseline) =
        verify_and_build_baseline(&pair, &remote, &prior).unwrap()
    else {
        panic!("a remote child body update must not look like a folder identity swap");
    };
    assert_eq!(baseline["folder"].directory_identity, Some(folder_identity));
    assert_eq!(baseline["child"].content_hash, body.content_hash);
}

#[test]
fn native_folder_move_keeps_root_identity_and_moves_no_duplicate_children() {
    let parent = TestDirectory::new("folder-move-success");
    let root = parent.path().join("pair");
    fs::create_dir(&root).unwrap();
    fs::create_dir_all(root.join("Projects/Child")).unwrap();
    fs::write(root.join("Projects/Child/note.txt"), b"baseline").unwrap();
    fs::create_dir(root.join("Archive")).unwrap();
    let inspection = inspect_local_tree_with_directory_identities(&root).unwrap();
    let identity = capture_directory_identity(&root, Path::new("Projects")).unwrap();
    let entries = inspection
        .entries
        .iter()
        .filter(|entry| entry.relative_path.starts_with("Projects"))
        .map(|entry| {
            (
                entry
                    .relative_path
                    .strip_prefix("Projects")
                    .unwrap()
                    .to_path_buf(),
                shellx_drive_desktop_core::FolderMoveEntry {
                    content_hash: entry.content_hash.clone(),
                    is_directory: entry.is_directory,
                    directory_identity: entry.directory_identity.clone(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let precondition = FolderMovePrecondition {
        identity: identity.clone(),
        entries,
        remote_witness: None,
    };
    move_unchanged_local_folder(
        &root,
        Path::new("Projects"),
        Path::new("Archive/Projects"),
        &DownloadPrecondition::ExactLocal {
            content_hash: None,
            size_bytes: 0,
            is_directory: true,
        },
        &precondition,
    )
    .unwrap();
    assert!(!root.join("Projects").exists());
    assert_eq!(
        capture_directory_identity(&root, Path::new("Archive/Projects")).unwrap(),
        identity
    );
    assert_eq!(
        fs::read(root.join("Archive/Projects/Child/note.txt")).unwrap(),
        b"baseline"
    );
}

#[test]
fn handle_bound_move_pins_destination_parent_and_ancestors_through_the_native_call() {
    let parent = TestDirectory::new("handle-bound-move");
    let root = parent.path().join("pair");
    let outside = parent.path().join("outside");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::create_dir_all(root.join("Archive/Nested")).unwrap();
    fs::write(root.join("before.txt"), b"baseline").unwrap();
    let precondition = DownloadPrecondition::observed(Some(&entry(&root, Path::new("before.txt"))));

    move_unchanged_local_path_before_native(
        &root,
        Path::new("before.txt"),
        Path::new("Archive/Nested/after.txt"),
        &precondition,
        || {
            // Both pins are already held without FILE_SHARE_DELETE.
            // An attacker cannot replace either visible ancestor with
            // a junction in the only remaining pre-native window.
            assert!(fs::rename(root.join("Archive"), root.join("Archive-swapped")).is_err());
            assert!(fs::rename(
                root.join("Archive/Nested"),
                root.join("Archive/Nested-swapped"),
            )
            .is_err());
            assert!(!outside.join("after.txt").exists());
            Ok(())
        },
    )
    .unwrap();

    assert!(!root.join("before.txt").exists());
    assert_eq!(
        fs::read(root.join("Archive/Nested/after.txt")).unwrap(),
        b"baseline"
    );
    assert!(!outside.join("after.txt").exists());
}

#[test]
fn handle_bound_recovery_move_pins_its_recovery_ancestry() {
    let parent = TestDirectory::new("handle-bound-recovery");
    let root = parent.path().join("pair");
    let recovery_root = parent.path().join(".shellx-drive-recovery");
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("Projects")).unwrap();
    fs::create_dir_all(recovery_root.join("batch")).unwrap();

    move_existing_entry_by_verified_parent(
        &root,
        &root.join("Projects"),
        &recovery_root.join("batch/Projects"),
        &recovery_root,
        || {
            assert!(fs::rename(
                recovery_root.join("batch"),
                recovery_root.join("batch-swapped"),
            )
            .is_err());
            assert!(fs::rename(&recovery_root, parent.path().join("recovery-swapped"),).is_err());
            Ok(())
        },
    )
    .unwrap();

    assert!(!root.join("Projects").exists());
    assert!(recovery_root.join("batch/Projects").is_dir());
}

#[test]
fn handle_bound_download_replacement_pins_destination_ancestry() {
    let parent = TestDirectory::new("handle-bound-download-replace");
    let root = parent.path().join("pair");
    let staging_root = parent.path().join("staging");
    fs::create_dir_all(root.join("Nested")).unwrap();
    fs::create_dir(&staging_root).unwrap();
    let destination = root.join("Nested/report.bin");
    let staged = staging_root.join("payload");
    fs::write(&destination, b"baseline").unwrap();
    fs::write(&staged, b"verified remote").unwrap();

    replace_existing_entry_by_verified_parent(&staging_root, &staged, &destination, &root, || {
        assert!(fs::rename(root.join("Nested"), root.join("Nested-swapped")).is_err());
        Ok(())
    })
    .unwrap();

    assert_eq!(fs::read(destination).unwrap(), b"verified remote");
    assert!(!staged.exists());
}

#[test]
fn native_folder_move_refuses_a_changed_descendant_and_preserves_the_source() {
    let parent = TestDirectory::new("folder-move-identity");
    let root = parent.path().join("pair");
    fs::create_dir(&root).unwrap();
    fs::create_dir_all(root.join("Projects/Child")).unwrap();
    fs::write(root.join("Projects/Child/note.txt"), b"baseline").unwrap();
    fs::create_dir(root.join("Archive")).unwrap();
    let inspection = inspect_local_tree_with_directory_identities(&root).unwrap();
    let identity = capture_directory_identity(&root, Path::new("Projects")).unwrap();
    let entries = inspection
        .entries
        .iter()
        .filter(|entry| entry.relative_path.starts_with("Projects"))
        .map(|entry| {
            let tail = entry
                .relative_path
                .strip_prefix("Projects")
                .unwrap()
                .to_path_buf();
            (
                tail,
                shellx_drive_desktop_core::FolderMoveEntry {
                    content_hash: entry.content_hash.clone(),
                    is_directory: entry.is_directory,
                    directory_identity: entry.directory_identity.clone(),
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let precondition = FolderMovePrecondition {
        identity,
        entries,
        remote_witness: None,
    };
    fs::write(root.join("Projects/Child/late.txt"), b"late edit").unwrap();

    assert!(move_unchanged_local_folder(
        &root,
        Path::new("Projects"),
        Path::new("Archive/Projects"),
        &DownloadPrecondition::ExactLocal {
            content_hash: None,
            size_bytes: 0,
            is_directory: true,
        },
        &precondition,
    )
    .is_err());
    assert!(root.join("Projects/Child/note.txt").exists());
    assert!(!root.join("Archive/Projects").exists());
}

#[test]
fn native_folder_move_never_creates_an_unplanned_destination_parent() {
    let parent = TestDirectory::new("folder-move-parent");
    let root = parent.path().join("pair");
    fs::create_dir(&root).unwrap();
    fs::create_dir(root.join("Projects")).unwrap();
    let identity = capture_directory_identity(&root, Path::new("Projects")).unwrap();
    let precondition = FolderMovePrecondition {
        identity: identity.clone(),
        entries: BTreeMap::from([(
            PathBuf::new(),
            shellx_drive_desktop_core::FolderMoveEntry {
                content_hash: None,
                is_directory: true,
                directory_identity: Some(identity),
            },
        )]),
        remote_witness: None,
    };

    assert!(move_unchanged_local_folder(
        &root,
        Path::new("Projects"),
        Path::new("Missing/Projects"),
        &DownloadPrecondition::ExactLocal {
            content_hash: None,
            size_bytes: 0,
            is_directory: true,
        },
        &precondition,
    )
    .is_err());
    assert!(root.join("Projects").is_dir());
    assert!(!root.join("Missing").exists());
}

#[test]
fn native_moves_refuse_a_reparse_parent_without_creating_outside_children() {
    use std::os::windows::fs::symlink_dir;

    let parent = TestDirectory::new("move-reparse-parent");
    let root = parent.path().join("pair");
    let outside = parent.path().join("outside");
    fs::create_dir(&root).unwrap();
    fs::create_dir(&outside).unwrap();
    fs::create_dir(root.join("Projects")).unwrap();
    fs::write(root.join("before.txt"), b"baseline").unwrap();
    // Capture the legitimate source witness before introducing the hostile
    // parent. A fresh whole-tree scan must reject that reparse point.
    let file_precondition =
        DownloadPrecondition::observed(Some(&entry(&root, Path::new("before.txt"))));
    if let Err(error) = symlink_dir(&outside, root.join("Linked")) {
        // Unprivileged Windows hosts can decline symlink creation.
        // The installed NTFS matrix retains the junction/reparse proof.
        if error.raw_os_error() == Some(1314) {
            return;
        }
        panic!("could not create reparse-point test fixture: {error}");
    }
    assert!(matches!(
        scan_local_tree(&root),
        Err(DesktopError::UnsafePath(_))
    ));
    let folder_identity = capture_directory_identity(&root, Path::new("Projects")).unwrap();
    let folder_precondition = FolderMovePrecondition {
        identity: folder_identity.clone(),
        entries: BTreeMap::from([(
            PathBuf::new(),
            shellx_drive_desktop_core::FolderMoveEntry {
                content_hash: None,
                is_directory: true,
                directory_identity: Some(folder_identity),
            },
        )]),
        remote_witness: None,
    };

    assert!(move_unchanged_local_folder(
        &root,
        Path::new("Projects"),
        Path::new("Linked/Projects"),
        &DownloadPrecondition::ExactLocal {
            content_hash: None,
            size_bytes: 0,
            is_directory: true,
        },
        &folder_precondition,
    )
    .is_err());
    assert!(move_unchanged_local_path(
        &root,
        Path::new("before.txt"),
        Path::new("Linked/after.txt"),
        &file_precondition,
    )
    .is_err());
    assert!(root.join("Projects").is_dir());
    assert_eq!(fs::read(root.join("before.txt")).unwrap(), b"baseline");
    assert!(!outside.join("Projects").exists());
    assert!(!outside.join("after.txt").exists());
}
