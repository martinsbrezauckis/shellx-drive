//! Reconciliation planner and coordinator regression coverage.

use std::fs;

use super::*;
use crate::{DesktopState, DirectoryIdentity, MirrorCoordinator, SyncPair, SyncStatus};

#[path = "mirror_tests/upload_plan_witness.rs"]
mod upload_plan_witness;

const WHEN: &str = "2026-08-12T17:30:45Z";

fn timestamp() -> DateTime<Utc> {
    WHEN.parse().unwrap()
}

fn remote(id: &str, hash: &str, revision: i64) -> RemoteEntry {
    RemoteEntry {
        id: id.into(),
        parent_id: None,
        name: "report.pdf".into(),
        kind: RemoteEntryKind::File,
        revision,
        content_hash: Some(hash.into()),
        size_bytes: Some(2),
        trashed: false,
    }
}

fn local(hash: &str, size_bytes: u64) -> LocalEntry {
    local_at("report.pdf", hash, size_bytes)
}

fn local_at(path: &str, hash: &str, size_bytes: u64) -> LocalEntry {
    LocalEntry {
        relative_path: PathBuf::from(path),
        content_hash: Some(hash.into()),
        size_bytes,
        is_directory: false,
        directory_identity: None,
    }
}

fn local_directory(path: &str) -> LocalEntry {
    LocalEntry {
        relative_path: PathBuf::from(path),
        content_hash: None,
        size_bytes: 0,
        is_directory: true,
        directory_identity: None,
    }
}

fn directory_identity(byte: u8) -> DirectoryIdentity {
    DirectoryIdentity::windows(42, [byte; 16])
}

fn local_directory_with_identity(path: &str, byte: u8) -> LocalEntry {
    LocalEntry {
        directory_identity: Some(directory_identity(byte)),
        ..local_directory(path)
    }
}

fn folder_baseline(id: &str, path: &str, revision: i64, identity: Option<u8>) -> BaselineEntry {
    BaselineEntry {
        remote_id: id.to_string(),
        parent_id: None,
        relative_path: PathBuf::from(path),
        kind: "folder".to_string(),
        content_hash: None,
        revision,
        directory_identity: identity.map(directory_identity),
    }
}

fn file_baseline(
    id: &str,
    parent_id: &str,
    path: &str,
    hash: &str,
    revision: i64,
) -> BaselineEntry {
    BaselineEntry {
        remote_id: id.to_string(),
        parent_id: Some(parent_id.to_string()),
        relative_path: PathBuf::from(path),
        kind: "file".to_string(),
        content_hash: Some(hash.to_string()),
        revision,
        directory_identity: None,
    }
}

fn folder_remote(id: &str, name: &str, revision: i64) -> RemoteEntry {
    RemoteEntry {
        id: id.to_string(),
        parent_id: None,
        name: name.to_string(),
        kind: RemoteEntryKind::Folder,
        revision,
        content_hash: None,
        size_bytes: None,
        trashed: false,
    }
}

fn baseline() -> BTreeMap<String, BaselineEntry> {
    BTreeMap::from([(
        "f1".into(),
        BaselineEntry {
            remote_id: "f1".into(),
            parent_id: None,
            relative_path: PathBuf::from("report.pdf"),
            kind: "file".into(),
            content_hash: Some("base".into()),
            revision: 1,
            directory_identity: None,
        },
    )])
}

#[test]
fn both_changed_preserves_a_named_conflict_copy() {
    let plan = plan_reconciliation(
        &baseline(),
        None,
        &[remote("f1", "remote", 2)],
        &[local("local", 2)],
        timestamp(),
    )
    .unwrap();
    assert!(matches!(
        plan.actions.as_slice(),
        [SyncAction::WriteRemoteConflictCopy { conflict_path, .. }]
            if conflict_path == &PathBuf::from("report (Drive conflict 2026-08-12 173045).pdf")
    ));
    assert_eq!(plan.reviews[0].kind, ReviewKind::ContentConflict);
    assert_eq!(plan.reviews[0].id, "ContentConflict:report.pdf");
}

#[test]
fn pending_content_conflict_keeps_its_written_copy_path_on_recheck() {
    let first = plan_reconciliation(
        &baseline(),
        None,
        &[remote("f1", "remote", 2)],
        &[local("local", 2)],
        timestamp(),
    )
    .unwrap();
    let mut recheck = plan_reconciliation(
        &baseline(),
        None,
        &[remote("f1", "remote", 2)],
        &[local("local", 2)],
        "2026-08-12T17:31:45Z".parse().unwrap(),
    )
    .unwrap();

    crate::conflicts::stabilize_pending_content_conflicts(&mut recheck, &first.reviews);

    assert_eq!(recheck.reviews, first.reviews);
    assert!(matches!(
        (&first.actions[0], &recheck.actions[0]),
        (
            SyncAction::WriteRemoteConflictCopy {
                conflict_path: first_path,
                ..
            },
            SyncAction::WriteRemoteConflictCopy {
                conflict_path: recheck_path,
                ..
            }
        ) if first_path == recheck_path
    ));
}

#[test]
fn pending_content_conflict_never_reuses_an_unrelated_or_escaping_path() {
    let mut pending = plan_reconciliation(
        &baseline(),
        None,
        &[remote("f1", "remote", 2)],
        &[local("local", 2)],
        timestamp(),
    )
    .unwrap()
    .reviews;
    pending[0].relative_path = PathBuf::from("../outside.txt");
    let mut recheck = plan_reconciliation(
        &baseline(),
        None,
        &[remote("f1", "remote", 2)],
        &[local("local", 2)],
        "2026-08-12T17:31:45Z".parse().unwrap(),
    )
    .unwrap();
    let generated = recheck.reviews[0].relative_path.clone();

    crate::conflicts::stabilize_pending_content_conflicts(&mut recheck, &pending);

    assert_eq!(recheck.reviews[0].relative_path, generated);
    assert_ne!(recheck.reviews[0].relative_path, pending[0].relative_path);
}

#[test]
fn deletes_are_reviews_never_actions() {
    let plan = plan_reconciliation(
        &baseline(),
        None,
        &[remote("f1", "base", 1)],
        &[],
        timestamp(),
    )
    .unwrap();
    assert!(plan.actions.is_empty());
    assert_eq!(plan.reviews[0].kind, ReviewKind::LocalDeletion);
    assert_eq!(
        plan.reviews[0].actions,
        vec![
            ReviewAction::DeleteFromDrive,
            ReviewAction::RestoreLocalCopy
        ]
    );
}

#[test]
fn deleted_local_folder_confirmation_keeps_the_saved_descendant_impact() {
    let baseline = BTreeMap::from([
        (
            "folder".to_string(),
            BaselineEntry {
                remote_id: "folder".to_string(),
                parent_id: None,
                relative_path: PathBuf::from("Projects"),
                kind: "folder".to_string(),
                content_hash: None,
                revision: 1,
                directory_identity: None,
            },
        ),
        (
            "child".to_string(),
            BaselineEntry {
                remote_id: "child".to_string(),
                parent_id: Some("folder".to_string()),
                relative_path: PathBuf::from("Projects/brief.md"),
                kind: "file".to_string(),
                content_hash: Some("base".to_string()),
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
            name: "brief.md".to_string(),
            kind: RemoteEntryKind::File,
            revision: 1,
            content_hash: Some("base".to_string()),
            size_bytes: Some(1),
            trashed: false,
        },
    ];
    let plan = plan_reconciliation(&baseline, None, &remote, &[], timestamp()).unwrap();
    let folder_review = plan
        .reviews
        .iter()
        .find(|item| item.relative_path == Path::new("Projects"))
        .unwrap();
    assert_eq!(folder_review.kind, ReviewKind::LocalDeletion);
    assert_eq!(folder_review.descendant_count, 1);
    assert!(folder_review.is_directory);
    assert_eq!(folder_review.actions, vec![ReviewAction::RestoreLocalCopy]);
}

#[test]
fn remote_delete_never_resurrects_the_local_file_as_upload_new() {
    let plan =
        plan_reconciliation(&baseline(), None, &[], &[local("base", 2)], timestamp()).unwrap();
    assert_eq!(plan.reviews[0].kind, ReviewKind::RemoteDeletion);
    assert!(!plan
        .actions
        .iter()
        .any(|action| matches!(action, SyncAction::UploadNew { .. })));
}

#[test]
fn unbaselined_remote_never_downloads_over_existing_local_bytes() {
    let plan = plan_reconciliation(
        &BTreeMap::new(),
        None,
        &[remote("new", "remote", 1)],
        &[local("local", 2)],
        timestamp(),
    )
    .unwrap();
    assert!(plan.actions.is_empty());
    assert_eq!(plan.reviews[0].kind, ReviewKind::PathConflict);
}

#[test]
fn unique_local_file_rename_moves_the_same_remote_id_with_its_baseline_revision() {
    let plan = plan_reconciliation(
        &baseline(),
        None,
        &[remote("f1", "base", 1)],
        &[local_at("renamed.pdf", "base", 2)],
        timestamp(),
    )
    .unwrap();
    assert!(plan.reviews.is_empty());
    assert!(matches!(
        plan.actions.as_slice(),
        [SyncAction::MoveRemote {
            remote_id,
            from,
            to,
            base_revision: 1,
            ..
        }] if remote_id == "f1" && from == Path::new("report.pdf") && to == Path::new("renamed.pdf")
    ));
    assert!(!plan
        .actions
        .iter()
        .any(|action| matches!(action, SyncAction::UploadNew { .. })));
}

#[test]
fn unchanged_exact_baseline_path_is_not_mistaken_for_another_missing_file() {
    let baseline = BTreeMap::from([
        (
            "a".to_string(),
            BaselineEntry {
                remote_id: "a".to_string(),
                parent_id: None,
                relative_path: PathBuf::from("a.txt"),
                kind: "file".to_string(),
                content_hash: Some("same".to_string()),
                revision: 1,
                directory_identity: None,
            },
        ),
        (
            "b".to_string(),
            BaselineEntry {
                remote_id: "b".to_string(),
                parent_id: None,
                relative_path: PathBuf::from("b.txt"),
                kind: "file".to_string(),
                content_hash: Some("same".to_string()),
                revision: 1,
                directory_identity: None,
            },
        ),
    ]);
    let remote = vec![
        RemoteEntry {
            id: "a".to_string(),
            parent_id: None,
            name: "a.txt".to_string(),
            kind: RemoteEntryKind::File,
            revision: 1,
            content_hash: Some("same".to_string()),
            size_bytes: Some(4),
            trashed: false,
        },
        RemoteEntry {
            id: "b".to_string(),
            parent_id: None,
            name: "b.txt".to_string(),
            kind: RemoteEntryKind::File,
            revision: 1,
            content_hash: Some("same".to_string()),
            size_bytes: Some(4),
            trashed: false,
        },
    ];
    let plan = plan_reconciliation(
        &baseline,
        None,
        &remote,
        &[local_at("b.txt", "same", 4)],
        timestamp(),
    )
    .unwrap();
    assert!(plan.actions.is_empty());
    assert!(plan.reviews.iter().any(|review| {
        review.kind == ReviewKind::LocalDeletion && review.relative_path == Path::new("a.txt")
    }));
    assert!(!plan
        .reviews
        .iter()
        .any(|review| review.kind == ReviewKind::UnsupportedTransfer));
}

#[test]
fn ambiguous_same_hash_file_rename_is_reviewed_without_uploading_candidates() {
    let plan = plan_reconciliation(
        &baseline(),
        None,
        &[remote("f1", "base", 1)],
        &[
            local_at("first-name.pdf", "base", 2),
            local_at("second-name.pdf", "base", 2),
        ],
        timestamp(),
    )
    .unwrap();
    assert!(plan.actions.is_empty());
    assert!(plan.reviews.iter().any(|review| {
        review.kind == ReviewKind::PathConflict && review.relative_path == Path::new("report.pdf")
    }));
}

#[test]
fn folders_do_not_infer_a_rename_from_a_shared_none_hash() {
    let baseline = BTreeMap::from([
        (
            "a".to_string(),
            BaselineEntry {
                remote_id: "a".to_string(),
                parent_id: None,
                relative_path: PathBuf::from("A"),
                kind: "folder".to_string(),
                content_hash: None,
                revision: 1,
                directory_identity: None,
            },
        ),
        (
            "b".to_string(),
            BaselineEntry {
                remote_id: "b".to_string(),
                parent_id: None,
                relative_path: PathBuf::from("B"),
                kind: "folder".to_string(),
                content_hash: None,
                revision: 1,
                directory_identity: None,
            },
        ),
    ]);
    let remote = vec![
        RemoteEntry {
            id: "a".to_string(),
            parent_id: None,
            name: "A".to_string(),
            kind: RemoteEntryKind::Folder,
            revision: 1,
            content_hash: None,
            size_bytes: None,
            trashed: false,
        },
        RemoteEntry {
            id: "b".to_string(),
            parent_id: None,
            name: "B".to_string(),
            kind: RemoteEntryKind::Folder,
            revision: 1,
            content_hash: None,
            size_bytes: None,
            trashed: false,
        },
    ];
    let local = [LocalEntry {
        relative_path: PathBuf::from("B"),
        content_hash: None,
        size_bytes: 0,
        is_directory: true,
        directory_identity: None,
    }];
    let plan = plan_reconciliation(&baseline, None, &remote, &local, timestamp()).unwrap();
    assert!(plan.actions.is_empty());
    assert!(plan.reviews.iter().any(|review| {
        review.kind == ReviewKind::LocalDeletion && review.relative_path == Path::new("A")
    }));
    assert!(!plan
        .reviews
        .iter()
        .any(|review| review.kind == ReviewKind::UnsupportedTransfer));
}

#[test]
fn download_precondition_detects_post_scan_create_and_edit() {
    let absent = DownloadPrecondition::Absent;
    assert!(download_precondition_matches(&absent, None));
    assert!(!download_precondition_matches(
        &absent,
        Some(&local_at("report.pdf", "created-after-scan", 18))
    ));

    let observed = local_at("report.pdf", "base", 2);
    let exact = DownloadPrecondition::observed(Some(&observed));
    assert!(download_precondition_matches(&exact, Some(&observed)));
    assert!(!download_precondition_matches(
        &exact,
        Some(&local_at("report.pdf", "edited-after-scan", 22))
    ));
    assert!(!download_precondition_matches(&exact, None));
}

#[test]
fn exact_tracked_remote_updates_publish_without_a_private_backup() {
    let local = local_at("report.pdf", "base", 2);
    let expected = DownloadPrecondition::observed(Some(&local));
    for _ in 0..3 {
        assert_eq!(
            download_publication_disposition(&expected, Some(&local)),
            DownloadPublicationDisposition::PublishReplacing
        );
    }
}

#[test]
fn changed_local_body_or_publish_failure_leaves_the_tracked_bytes_in_place() {
    let original = local_at("report.pdf", "base", 2);
    let expected = DownloadPrecondition::observed(Some(&original));
    let late_edit = local_at("report.pdf", "late-edit", 9);
    assert_eq!(
        download_publication_disposition(&expected, Some(&late_edit)),
        DownloadPublicationDisposition::NeedsReviewWithoutMutation
    );
    // The unchanged case is eligible for a single native replacement with
    // no app-owned backup path. A native failure remains a review in the
    // Windows executor and the original path is never renamed away first.
    assert_eq!(
        download_publication_disposition(&expected, Some(&original)),
        DownloadPublicationDisposition::PublishReplacing
    );
}

#[test]
fn only_an_absent_destination_allows_a_nonreplacing_drive_publish() {
    assert_eq!(
        download_publication_disposition(&DownloadPrecondition::Absent, None),
        DownloadPublicationDisposition::PublishNonReplacing
    );
    assert_eq!(
        download_publication_disposition(
            &DownloadPrecondition::Absent,
            Some(&local_at("report.pdf", "user-created", 12))
        ),
        DownloadPublicationDisposition::NeedsReviewWithoutMutation
    );
}

#[test]
fn unchanged_file_follows_an_inbound_remote_move_without_a_duplicate() {
    let mut moved = remote("f1", "base", 2);
    moved.name = "renamed.pdf".to_string();
    let plan = plan_reconciliation(
        &baseline(),
        None,
        &[moved],
        &[local("base", 2)],
        timestamp(),
    )
    .unwrap();
    assert!(matches!(
        plan.actions.as_slice(),
        [SyncAction::MoveLocal { from, to, precondition, .. }]
            if from == Path::new("report.pdf")
                && to == Path::new("renamed.pdf")
                && *precondition == DownloadPrecondition::ExactLocal {
                    content_hash: Some("base".to_string()),
                    size_bytes: 2,
                    is_directory: false,
                }
    ));
    assert!(plan.reviews.is_empty());
}

#[test]
fn inbound_remote_move_with_a_changed_body_moves_then_replaces_the_baseline_file() {
    let mut moved = remote("f1", "remote", 2);
    moved.name = "renamed.pdf".to_string();
    let plan = plan_reconciliation(
        &baseline(),
        None,
        &[moved],
        &[local("base", 2)],
        timestamp(),
    )
    .unwrap();
    assert!(matches!(
        plan.actions.as_slice(),
        [
            SyncAction::MoveLocal { from, to, .. },
            SyncAction::Download { relative_path, precondition, .. }
        ] if from == Path::new("report.pdf")
            && to == Path::new("renamed.pdf")
            && relative_path == Path::new("renamed.pdf")
            && *precondition == DownloadPrecondition::ExactLocal {
                content_hash: Some("base".to_string()),
                size_bytes: 2,
                is_directory: false,
            }
    ));
    assert!(plan.reviews.is_empty());
}

#[test]
fn interrupted_inbound_file_move_resumes_the_download_at_the_new_path() {
    let mut moved = remote("f1", "remote", 2);
    moved.name = "renamed.pdf".to_string();

    // First pass pairs an atomic local move with a verified replacement.
    let first = plan_reconciliation(
        &baseline(),
        None,
        &[moved.clone()],
        &[local("base", 2)],
        timestamp(),
    )
    .unwrap();
    assert!(matches!(
        first.actions.as_slice(),
        [SyncAction::MoveLocal { .. }, SyncAction::Download { .. }]
    ));

    // Simulate a connection stop after the move: the old baseline body is
    // now exactly at Drive's current path. This is one unambiguous file
    // identity, so resume the download rather than reporting PathConflict.
    let second = plan_reconciliation(
        &baseline(),
        None,
        &[moved],
        &[local_at("renamed.pdf", "base", 2)],
        timestamp(),
    )
    .unwrap();
    assert!(matches!(
        second.actions.as_slice(),
        [SyncAction::Download {
            relative_path,
            precondition: DownloadPrecondition::ExactLocal {
                content_hash: Some(hash),
                size_bytes: 2,
                is_directory: false,
            },
            ..
        }] if relative_path == Path::new("renamed.pdf") && hash == "base"
    ));
    assert!(second.reviews.is_empty());

    let mut move_only = remote("f1", "base", 2);
    move_only.name = "renamed.pdf".to_string();
    let converged = plan_reconciliation(
        &baseline(),
        None,
        &[move_only],
        &[local_at("renamed.pdf", "base", 2)],
        timestamp(),
    )
    .unwrap();
    assert!(converged.actions.is_empty());
    assert!(converged.reviews.is_empty());
}

#[test]
fn inbound_folder_rename_freezes_unchanged_and_changed_descendants() {
    let baseline = BTreeMap::from([
        (
            "folder".to_string(),
            BaselineEntry {
                remote_id: "folder".to_string(),
                parent_id: None,
                relative_path: PathBuf::from("Projects"),
                kind: "folder".to_string(),
                content_hash: None,
                revision: 1,
                directory_identity: None,
            },
        ),
        (
            "steady".to_string(),
            BaselineEntry {
                remote_id: "steady".to_string(),
                parent_id: Some("folder".to_string()),
                relative_path: PathBuf::from("Projects/steady.md"),
                kind: "file".to_string(),
                content_hash: Some("steady".to_string()),
                revision: 1,
                directory_identity: None,
            },
        ),
        (
            "changed".to_string(),
            BaselineEntry {
                remote_id: "changed".to_string(),
                parent_id: Some("folder".to_string()),
                relative_path: PathBuf::from("Projects/changed.md"),
                kind: "file".to_string(),
                content_hash: Some("base".to_string()),
                revision: 1,
                directory_identity: None,
            },
        ),
    ]);
    let remote = vec![
        RemoteEntry {
            id: "folder".to_string(),
            parent_id: None,
            name: "Renamed Projects".to_string(),
            kind: RemoteEntryKind::Folder,
            revision: 2,
            content_hash: None,
            size_bytes: None,
            trashed: false,
        },
        RemoteEntry {
            id: "steady".to_string(),
            parent_id: Some("folder".to_string()),
            name: "steady.md".to_string(),
            kind: RemoteEntryKind::File,
            revision: 1,
            content_hash: Some("steady".to_string()),
            size_bytes: Some(6),
            trashed: false,
        },
        RemoteEntry {
            id: "changed".to_string(),
            parent_id: Some("folder".to_string()),
            name: "changed.md".to_string(),
            kind: RemoteEntryKind::File,
            revision: 2,
            content_hash: Some("remote-change".to_string()),
            size_bytes: Some(13),
            trashed: false,
        },
    ];
    let local = [
        local_directory("Projects"),
        local_at("Projects/steady.md", "steady", 6),
        local_at("Projects/changed.md", "base", 4),
        local_at("Projects/local-only.md", "local-only", 10),
    ];

    let plan = plan_reconciliation(&baseline, None, &remote, &local, timestamp()).unwrap();
    assert!(plan.actions.is_empty());
    assert!(matches!(
        plan.reviews.as_slice(),
        [ReviewItem {
            kind: ReviewKind::PathConflict,
            relative_path,
            is_directory: true,
            ..
        }] if relative_path == Path::new("Projects")
    ));
}

#[test]
fn outbound_folder_rename_claims_the_whole_local_candidate_subtree() {
    let baseline = BTreeMap::from([
        (
            "folder".to_string(),
            BaselineEntry {
                remote_id: "folder".to_string(),
                parent_id: None,
                relative_path: PathBuf::from("Projects"),
                kind: "folder".to_string(),
                content_hash: None,
                revision: 1,
                directory_identity: None,
            },
        ),
        (
            "steady".to_string(),
            BaselineEntry {
                remote_id: "steady".to_string(),
                parent_id: Some("folder".to_string()),
                relative_path: PathBuf::from("Projects/steady.md"),
                kind: "file".to_string(),
                content_hash: Some("steady".to_string()),
                revision: 1,
                directory_identity: None,
            },
        ),
        (
            "changed".to_string(),
            BaselineEntry {
                remote_id: "changed".to_string(),
                parent_id: Some("folder".to_string()),
                relative_path: PathBuf::from("Projects/changed.md"),
                kind: "file".to_string(),
                content_hash: Some("base".to_string()),
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
            id: "steady".to_string(),
            parent_id: Some("folder".to_string()),
            name: "steady.md".to_string(),
            kind: RemoteEntryKind::File,
            revision: 1,
            content_hash: Some("steady".to_string()),
            size_bytes: Some(6),
            trashed: false,
        },
        RemoteEntry {
            id: "changed".to_string(),
            parent_id: Some("folder".to_string()),
            name: "changed.md".to_string(),
            kind: RemoteEntryKind::File,
            revision: 1,
            content_hash: Some("base".to_string()),
            size_bytes: Some(4),
            trashed: false,
        },
    ];
    let local = [
        local_directory("Renamed Projects"),
        local_at("Renamed Projects/steady.md", "steady", 6),
        local_at("Renamed Projects/changed.md", "local-change", 12),
        local_at("Renamed Projects/local-only.md", "local-only", 10),
    ];

    let plan = plan_reconciliation(&baseline, None, &remote, &local, timestamp()).unwrap();
    assert!(plan.actions.is_empty());
    assert!(matches!(
        plan.reviews.as_slice(),
        [ReviewItem {
            kind: ReviewKind::PathConflict,
            relative_path,
            is_directory: true,
            ..
        }] if relative_path == Path::new("Projects")
    ));
}

#[test]
fn empty_folder_rename_uses_only_its_persisted_ntfs_identity() {
    let baseline = BTreeMap::from([(
        "folder".to_string(),
        folder_baseline("folder", "Projects", 1, Some(1)),
    )]);
    let plan = plan_reconciliation(
        &baseline,
        None,
        &[folder_remote("folder", "Projects", 1)],
        &[local_directory_with_identity("Renamed", 1)],
        timestamp(),
    )
    .unwrap();
    assert!(plan.reviews.is_empty());
    assert!(matches!(
        plan.actions.as_slice(),
        [SyncAction::MoveRemote {
            remote_id,
            from,
            to,
            base_revision: 1,
            folder_precondition: Some(_),
        }] if remote_id == "folder" && from == Path::new("Projects") && to == Path::new("Renamed")
    ));
}

#[test]
fn nonempty_inbound_folder_rename_moves_only_the_root_then_downloads_child_body() {
    let baseline = BTreeMap::from([
        (
            "folder".to_string(),
            folder_baseline("folder", "Projects", 1, Some(1)),
        ),
        (
            "child".to_string(),
            file_baseline("child", "folder", "Projects/report.txt", "base", 1),
        ),
    ]);
    let remote = vec![
        folder_remote("folder", "Renamed", 2),
        RemoteEntry {
            id: "child".to_string(),
            parent_id: Some("folder".to_string()),
            name: "report.txt".to_string(),
            kind: RemoteEntryKind::File,
            revision: 2,
            content_hash: Some("remote".to_string()),
            size_bytes: Some(6),
            trashed: false,
        },
    ];
    let plan = plan_reconciliation(
        &baseline,
        None,
        &remote,
        &[
            local_directory_with_identity("Projects", 1),
            local_at("Projects/report.txt", "base", 4),
        ],
        timestamp(),
    )
    .unwrap();
    assert!(plan.reviews.is_empty());
    assert!(matches!(
        plan.actions.as_slice(),
        [
            SyncAction::MoveLocal { folder_precondition: Some(_), .. },
            SyncAction::Download { remote_id, relative_path, .. },
        ] if remote_id == "child" && relative_path == Path::new("Renamed/report.txt")
    ));
    assert_eq!(
        plan.actions
            .iter()
            .filter(|action| matches!(action, SyncAction::MoveLocal { .. }))
            .count(),
        1
    );
}

#[test]
fn inbound_folder_remote_witness_rejects_preflight_and_postmove_manifest_divergence() {
    let baseline = BTreeMap::from([
        (
            "folder".to_string(),
            folder_baseline("folder", "Projects", 1, Some(1)),
        ),
        (
            "child".to_string(),
            file_baseline("child", "folder", "Projects/report.txt", "base", 1),
        ),
    ]);
    let remote = vec![
        folder_remote("folder", "Renamed", 2),
        RemoteEntry {
            id: "child".to_string(),
            parent_id: Some("folder".to_string()),
            name: "report.txt".to_string(),
            kind: RemoteEntryKind::File,
            revision: 2,
            content_hash: Some("remote".to_string()),
            size_bytes: Some(6),
            trashed: false,
        },
    ];
    let plan = plan_reconciliation(
        &baseline,
        None,
        &remote,
        &[
            local_directory_with_identity("Projects", 1),
            local_at("Projects/report.txt", "base", 4),
        ],
        timestamp(),
    )
    .unwrap();
    let witness = plan
        .actions
        .iter()
        .find_map(|action| match action {
            SyncAction::MoveLocal {
                folder_precondition: Some(precondition),
                ..
            } => Some(precondition),
            _ => None,
        })
        .expect("inbound folder move carries a remote witness");
    assert!(folder_remote_witness_matches(witness, None, &remote));

    // This is both the executor's preflight seam and its post-native-rename
    // seam: a changed child body/revision blocks the native root move
    // before it starts, or stops all descendants/baseline afterward.
    let mut changed_child = remote.clone();
    let child = changed_child
        .iter_mut()
        .find(|entry| entry.id == "child")
        .unwrap();
    child.revision = 3;
    child.content_hash = Some("changed-again".to_string());
    assert!(!folder_remote_witness_matches(
        witness,
        None,
        &changed_child
    ));

    let mut extra_descendant = remote.clone();
    extra_descendant.push(RemoteEntry {
        id: "extra".to_string(),
        parent_id: Some("folder".to_string()),
        name: "extra.txt".to_string(),
        kind: RemoteEntryKind::File,
        revision: 1,
        content_hash: Some("extra".to_string()),
        size_bytes: Some(5),
        trashed: false,
    });
    assert!(!folder_remote_witness_matches(
        witness,
        None,
        &extra_descendant
    ));
}

#[test]
fn inbound_folder_remote_witness_binds_the_selected_root_effective_location() {
    let baseline = BTreeMap::from([(
        "folder".to_string(),
        folder_baseline("folder", "Projects", 1, Some(1)),
    )]);
    let remote = vec![
        RemoteEntry {
            id: "workspace".to_string(),
            parent_id: Some("account".to_string()),
            name: "Selected workspace".to_string(),
            kind: RemoteEntryKind::Folder,
            revision: 7,
            content_hash: None,
            size_bytes: None,
            trashed: false,
        },
        RemoteEntry {
            id: "account".to_string(),
            parent_id: None,
            name: "Account root".to_string(),
            kind: RemoteEntryKind::Folder,
            revision: 4,
            content_hash: None,
            size_bytes: None,
            trashed: false,
        },
        RemoteEntry {
            id: "folder".to_string(),
            parent_id: Some("workspace".to_string()),
            name: "Renamed".to_string(),
            kind: RemoteEntryKind::Folder,
            revision: 2,
            content_hash: None,
            size_bytes: None,
            trashed: false,
        },
    ];
    let plan = plan_reconciliation(
        &baseline,
        Some("workspace"),
        &remote,
        &[local_directory_with_identity("Projects", 1)],
        timestamp(),
    )
    .unwrap();
    let witness = plan
        .actions
        .iter()
        .find_map(|action| match action {
            SyncAction::MoveLocal {
                folder_precondition: Some(precondition),
                ..
            } => Some(precondition),
            _ => None,
        })
        .expect("selected-root inbound move carries a witness");
    assert!(folder_remote_witness_matches(
        witness,
        Some("workspace"),
        &remote
    ));

    let mut moved_selected_root = remote.clone();
    let selected_root = moved_selected_root
        .iter_mut()
        .find(|entry| entry.id == "workspace")
        .unwrap();
    selected_root.parent_id = None;
    selected_root.revision = 8;
    assert!(!folder_remote_witness_matches(
        witness,
        Some("workspace"),
        &moved_selected_root
    ));
}

#[test]
fn delete_recreate_or_copy_never_reuses_a_folder_remote_id() {
    let baseline = BTreeMap::from([(
        "folder".to_string(),
        folder_baseline("folder", "Projects", 1, Some(1)),
    )]);
    for local in [
        vec![local_directory_with_identity("Renamed", 2)],
        vec![
            local_directory_with_identity("First", 1),
            local_directory_with_identity("Second", 1),
        ],
    ] {
        let plan = plan_reconciliation(
            &baseline,
            None,
            &[folder_remote("folder", "Projects", 1)],
            &local,
            timestamp(),
        )
        .unwrap();
        assert!(plan.actions.is_empty());
        assert!(matches!(
            plan.reviews.as_slice(),
            [ReviewItem {
                kind: ReviewKind::PathConflict,
                is_directory: true,
                ..
            }]
        ));
    }
}

#[test]
fn legacy_identity_missing_never_auto_moves_then_future_identity_enables_empty_rename() {
    let legacy = BTreeMap::from([(
        "folder".to_string(),
        folder_baseline("folder", "Projects", 1, None),
    )]);
    let legacy_plan = plan_reconciliation(
        &legacy,
        None,
        &[folder_remote("folder", "Projects", 1)],
        &[local_directory_with_identity("Renamed", 1)],
        timestamp(),
    )
    .unwrap();
    assert!(legacy_plan.actions.is_empty());
    assert_eq!(legacy_plan.reviews.len(), 1);

    // This represents the baseline persisted after an unchanged v1 pair
    // was scanned by the checked Windows handle path.
    let observed = BTreeMap::from([(
        "folder".to_string(),
        folder_baseline("folder", "Projects", 1, Some(1)),
    )]);
    let moved_plan = plan_reconciliation(
        &observed,
        None,
        &[folder_remote("folder", "Projects", 1)],
        &[local_directory_with_identity("Renamed", 1)],
        timestamp(),
    )
    .unwrap();
    assert!(matches!(
        moved_plan.actions.as_slice(),
        [SyncAction::MoveRemote {
            folder_precondition: Some(_),
            ..
        }]
    ));
}

#[test]
fn stale_remote_root_revision_or_inbound_collision_freezes_the_root_only() {
    let baseline = BTreeMap::from([(
        "folder".to_string(),
        folder_baseline("folder", "Projects", 1, Some(1)),
    )]);
    let cases = [
        (
            vec![folder_remote("folder", "Projects", 2)],
            vec![local_directory_with_identity("Renamed", 1)],
        ),
        (
            vec![folder_remote("folder", "Renamed", 2)],
            vec![
                local_directory_with_identity("Projects", 1),
                local_directory_with_identity("Renamed", 2),
            ],
        ),
    ];
    for (remote, local) in cases {
        let plan = plan_reconciliation(&baseline, None, &remote, &local, timestamp()).unwrap();
        assert!(plan.actions.is_empty());
        assert!(matches!(
            plan.reviews.as_slice(),
            [ReviewItem {
                kind: ReviewKind::PathConflict,
                is_directory: true,
                ..
            }]
        ));
    }
}

#[test]
fn interrupted_inbound_folder_move_resumes_at_the_identity_bound_destination() {
    let baseline = BTreeMap::from([
        (
            "folder".to_string(),
            folder_baseline("folder", "Projects", 1, Some(1)),
        ),
        (
            "child".to_string(),
            file_baseline("child", "folder", "Projects/report.txt", "base", 1),
        ),
    ]);
    let remote = vec![
        folder_remote("folder", "Renamed", 2),
        RemoteEntry {
            id: "child".to_string(),
            parent_id: Some("folder".to_string()),
            name: "report.txt".to_string(),
            kind: RemoteEntryKind::File,
            revision: 2,
            content_hash: Some("remote".to_string()),
            size_bytes: Some(6),
            trashed: false,
        },
    ];
    let plan = plan_reconciliation(
        &baseline,
        None,
        &remote,
        &[
            local_directory_with_identity("Renamed", 1),
            local_at("Renamed/report.txt", "base", 4),
        ],
        timestamp(),
    )
    .unwrap();
    assert!(plan.reviews.is_empty());
    assert!(matches!(
        plan.actions.as_slice(),
        [SyncAction::Download { relative_path, .. }]
            if relative_path == Path::new("Renamed/report.txt")
    ));
}

#[test]
fn interrupted_folder_move_with_recreated_extra_or_missing_child_stays_one_root_review() {
    let baseline = BTreeMap::from([
        (
            "folder".to_string(),
            folder_baseline("folder", "Projects", 1, Some(1)),
        ),
        (
            "child".to_string(),
            BaselineEntry {
                remote_id: "child".to_string(),
                parent_id: Some("folder".to_string()),
                relative_path: PathBuf::from("Projects/Child"),
                kind: "folder".to_string(),
                content_hash: None,
                revision: 1,
                directory_identity: Some(directory_identity(2)),
            },
        ),
    ]);
    let remote = vec![
        folder_remote("folder", "Renamed", 2),
        RemoteEntry {
            id: "child".to_string(),
            parent_id: Some("folder".to_string()),
            name: "Child".to_string(),
            kind: RemoteEntryKind::Folder,
            revision: 1,
            content_hash: None,
            size_bytes: None,
            trashed: false,
        },
    ];
    let cases = [
        vec![
            local_directory_with_identity("Renamed", 1),
            local_directory_with_identity("Renamed/Child", 3),
        ],
        vec![
            local_directory_with_identity("Renamed", 1),
            local_directory_with_identity("Renamed/Child", 2),
            local_at("Renamed/extra.txt", "extra", 5),
        ],
        vec![local_directory_with_identity("Renamed", 1)],
    ];
    for local in cases {
        let plan = plan_reconciliation(&baseline, None, &remote, &local, timestamp()).unwrap();
        assert!(plan.actions.is_empty());
        assert!(matches!(
            plan.reviews.as_slice(),
            [ReviewItem {
                relative_path,
                is_directory: true,
                descendant_count: 1,
                ..
            }] if relative_path == Path::new("Projects")
        ));
    }
}

#[test]
fn moved_root_with_recreated_child_directory_is_one_review_with_no_child_actions() {
    let baseline = BTreeMap::from([
        (
            "folder".to_string(),
            folder_baseline("folder", "Projects", 1, Some(1)),
        ),
        (
            "child-folder".to_string(),
            BaselineEntry {
                remote_id: "child-folder".to_string(),
                parent_id: Some("folder".to_string()),
                relative_path: PathBuf::from("Projects/Child"),
                kind: "folder".to_string(),
                content_hash: None,
                revision: 1,
                directory_identity: Some(directory_identity(2)),
            },
        ),
    ]);
    let plan = plan_reconciliation(
        &baseline,
        None,
        &[
            folder_remote("folder", "Projects", 1),
            RemoteEntry {
                id: "child-folder".to_string(),
                parent_id: Some("folder".to_string()),
                name: "Child".to_string(),
                kind: RemoteEntryKind::Folder,
                revision: 1,
                content_hash: None,
                size_bytes: None,
                trashed: false,
            },
        ],
        &[
            local_directory_with_identity("Renamed", 1),
            local_directory_with_identity("Renamed/Child", 3),
        ],
        timestamp(),
    )
    .unwrap();
    assert!(plan.actions.is_empty());
    assert!(matches!(
        plan.reviews.as_slice(),
        [ReviewItem {
            relative_path,
            is_directory: true,
            descendant_count: 1,
            ..
        }] if relative_path == Path::new("Projects")
    ));
}

#[test]
fn unsafe_child_reparse_replaces_a_planned_folder_move_with_one_root_review() {
    let plan = ReconcilePlan {
        actions: vec![
            SyncAction::MoveLocal {
                remote_id: "folder".to_string(),
                from: PathBuf::from("Projects"),
                to: PathBuf::from("Renamed"),
                precondition: DownloadPrecondition::ExactLocal {
                    content_hash: None,
                    size_bytes: 0,
                    is_directory: true,
                },
                folder_precondition: Some(FolderMovePrecondition {
                    identity: directory_identity(1),
                    entries: BTreeMap::from([(
                        PathBuf::new(),
                        FolderMoveEntry {
                            content_hash: None,
                            is_directory: true,
                            directory_identity: Some(directory_identity(1)),
                        },
                    )]),
                    remote_witness: None,
                }),
            },
            SyncAction::Download {
                remote_id: "child".to_string(),
                relative_path: PathBuf::from("Renamed/child.txt"),
                revision: 2,
                precondition: DownloadPrecondition::Absent,
            },
        ],
        reviews: Vec::new(),
        remote_paths: BTreeMap::new(),
    };
    let reviewed = apply_local_path_compatibility_reviews(
        plan,
        &[LocalPathIssue {
            path: PathBuf::from("Projects/unsafe-link"),
            reason: "it is a symbolic link or Windows reparse point".to_string(),
        }],
    );
    assert!(reviewed.actions.is_empty());
    assert!(matches!(
        reviewed.reviews.as_slice(),
        [ReviewItem {
            kind: ReviewKind::UnsafeLink,
            relative_path,
            is_directory: true,
            ..
        }] if relative_path == Path::new("Projects")
    ));
}

#[test]
fn missing_local_folder_subtree_is_one_root_deletion_review_without_child_leaks() {
    let baseline = BTreeMap::from([
        (
            "folder".to_string(),
            folder_baseline("folder", "Projects", 1, Some(1)),
        ),
        (
            "child".to_string(),
            file_baseline("child", "folder", "Projects/note.txt", "base", 1),
        ),
    ]);
    let remote = vec![
        folder_remote("folder", "Projects", 1),
        RemoteEntry {
            id: "child".to_string(),
            parent_id: Some("folder".to_string()),
            name: "note.txt".to_string(),
            kind: RemoteEntryKind::File,
            revision: 1,
            content_hash: Some("base".to_string()),
            size_bytes: Some(4),
            trashed: false,
        },
    ];
    let plan = plan_reconciliation(&baseline, None, &remote, &[], timestamp()).unwrap();
    assert!(plan.actions.is_empty());
    assert!(matches!(
        plan.reviews.as_slice(),
        [ReviewItem {
            kind: ReviewKind::LocalDeletion,
            relative_path,
            descendant_count: 1,
            is_directory: true,
            ..
        }] if relative_path == Path::new("Projects")
    ));
}

#[test]
fn missing_remote_folder_subtree_is_one_root_review_without_upload_resurrection() {
    let baseline = BTreeMap::from([
        (
            "folder".to_string(),
            folder_baseline("folder", "Projects", 1, Some(1)),
        ),
        (
            "child".to_string(),
            file_baseline("child", "folder", "Projects/note.txt", "base", 1),
        ),
    ]);
    let plan = plan_reconciliation(
        &baseline,
        None,
        &[],
        &[
            local_directory_with_identity("Projects", 1),
            local_at("Projects/note.txt", "base", 4),
        ],
        timestamp(),
    )
    .unwrap();
    assert!(plan.actions.is_empty());
    assert!(matches!(
        plan.reviews.as_slice(),
        [ReviewItem {
            kind: ReviewKind::RemoteDeletion,
            relative_path,
            descendant_count: 1,
            ..
        }] if relative_path == Path::new("Projects")
    ));
}

#[test]
fn inbound_remote_move_with_a_local_edit_stays_reviewed() {
    let mut moved = remote("f1", "base", 2);
    moved.name = "renamed.pdf".to_string();
    let plan = plan_reconciliation(
        &baseline(),
        None,
        &[moved],
        &[local("local-edit", 10)],
        timestamp(),
    )
    .unwrap();
    assert!(plan.actions.is_empty());
    assert_eq!(plan.reviews[0].kind, ReviewKind::PathConflict);
}

#[test]
fn ordinary_dot_suffix_file_is_an_upload_never_client_scratch() {
    let plan = plan_reconciliation(
        &BTreeMap::new(),
        None,
        &[remote("server", "remote", 1)],
        &[local_at(".report.pdf.shellx-download", "user-bytes", 10)],
        timestamp(),
    )
    .unwrap();
    assert!(plan.actions.iter().any(|action| {
        matches!(
            action,
            SyncAction::UploadNew { relative_path, is_directory: false, .. }
                if relative_path == Path::new(".report.pdf.shellx-download")
        )
    }));
}

#[test]
fn remote_trash_refuses_a_new_descendant_after_confirmation() {
    let baseline = BTreeMap::from([
        (
            "folder".to_string(),
            BaselineEntry {
                remote_id: "folder".to_string(),
                parent_id: None,
                relative_path: PathBuf::from("Projects"),
                kind: "folder".to_string(),
                content_hash: None,
                revision: 1,
                directory_identity: None,
            },
        ),
        (
            "saved".to_string(),
            BaselineEntry {
                remote_id: "saved".to_string(),
                parent_id: Some("folder".to_string()),
                relative_path: PathBuf::from("Projects/saved.txt"),
                kind: "file".to_string(),
                content_hash: Some("saved".to_string()),
                revision: 1,
                directory_identity: None,
            },
        ),
    ]);
    let review = remote_deletion_review(Path::new("Projects"), 1);
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
            id: "saved".to_string(),
            parent_id: Some("folder".to_string()),
            name: "saved.txt".to_string(),
            kind: RemoteEntryKind::File,
            revision: 1,
            content_hash: Some("saved".to_string()),
            size_bytes: Some(5),
            trashed: false,
        },
        RemoteEntry {
            id: "added".to_string(),
            parent_id: Some("folder".to_string()),
            name: "added.txt".to_string(),
            kind: RemoteEntryKind::File,
            revision: 1,
            content_hash: Some("added".to_string()),
            size_bytes: Some(5),
            trashed: false,
        },
    ];
    let wrong_impact = remote_deletion_review(Path::new("Projects"), 0);
    let error =
        reviewed_remote_subtree_matches_baseline(&wrong_impact, &baseline, None, &remote[..2])
            .expect_err("review impact must bind the exact saved descendant count");
    assert!(error.to_string().contains("reviewed descendant impact"));
    assert!(reviewed_remote_subtree_matches_baseline(&review, &baseline, None, &remote).is_err());
}

#[test]
fn large_replacements_use_the_optimistic_resumable_executor() {
    let plan = plan_reconciliation(
        &baseline(),
        None,
        &[remote("f1", "base", 1)],
        &[local("changed", SIMPLE_EXISTING_REPLACEMENT_LIMIT + 1)],
        timestamp(),
    )
    .unwrap();
    assert!(plan.reviews.is_empty());
    assert!(matches!(
        plan.actions.as_slice(),
        [SyncAction::UploadExisting { relative_path, base_revision: 1, .. }]
            if relative_path == Path::new("report.pdf")
    ));
}

#[test]
fn run_guard_serializes_watcher_and_poller() {
    let state = DesktopState {
        pair: Some(SyncPair {
            server_url: "https://drive.example".into(),
            account_email: "owner@example.test".into(),
            workspace_id: "workspace".into(),
            workspace_name: "Workspace".into(),
            remote_root_id: None,
            remote_root_name: None,
            local_root: PathBuf::from("C:/Drive"),
            local_root_identity: None,
        }),
        ..DesktopState::default()
    };
    let coordinator = MirrorCoordinator::new(state);
    let run = coordinator.begin_run().unwrap();
    assert_eq!(coordinator.status(true), SyncStatus::Syncing);
    assert!(matches!(
        coordinator.begin_run(),
        Err(DesktopError::SyncAlreadyRunning)
    ));
    drop(run);
    assert_eq!(coordinator.status(true), SyncStatus::Synced);
}

#[test]
fn disconnect_and_repair_refuse_to_clear_a_pair_while_a_run_is_active() {
    let state = DesktopState {
        pair: Some(SyncPair {
            server_url: "https://drive.example".into(),
            account_email: "owner@example.test".into(),
            workspace_id: "workspace".into(),
            workspace_name: "Workspace".into(),
            remote_root_id: None,
            remote_root_name: None,
            local_root: PathBuf::from("C:/Drive"),
            local_root_identity: None,
        }),
        ..DesktopState::default()
    };
    let coordinator = MirrorCoordinator::new(state);
    let run = coordinator.begin_run().unwrap();
    assert!(matches!(
        coordinator.disconnect(),
        Err(DesktopError::SyncAlreadyRunning)
    ));
    assert!(matches!(
        coordinator.configure_pair(SyncPair {
            server_url: "https://other.example".into(),
            account_email: "other@example.test".into(),
            workspace_id: "other".into(),
            workspace_name: "Other".into(),
            remote_root_id: None,
            remote_root_name: None,
            local_root: PathBuf::from("C:/Other"),
            local_root_identity: None,
        }),
        Err(DesktopError::SyncAlreadyRunning)
    ));
    assert_eq!(
        coordinator.snapshot().pair.unwrap().workspace_id,
        "workspace"
    );
    drop(run);

    let lifecycle = coordinator.begin_lifecycle_operation().unwrap();
    assert!(matches!(
        coordinator.configure_pair(SyncPair {
            server_url: "https://other.example".into(),
            account_email: "other@example.test".into(),
            workspace_id: "other".into(),
            workspace_name: "Other".into(),
            remote_root_id: None,
            remote_root_name: None,
            local_root: PathBuf::from("C:/Other"),
            local_root_identity: None,
        }),
        Err(DesktopError::SyncAlreadyRunning)
    ));
    drop(lifecycle);
}

#[test]
fn paused_coordinator_rejects_a_direct_sync_run_without_marking_it_active() {
    let state = DesktopState {
        pair: Some(SyncPair {
            server_url: "https://drive.example".into(),
            account_email: "owner@example.test".into(),
            workspace_id: "workspace".into(),
            workspace_name: "Workspace".into(),
            remote_root_id: None,
            remote_root_name: None,
            local_root: PathBuf::from("C:/Drive"),
            local_root_identity: None,
        }),
        paused: true,
        ..DesktopState::default()
    };
    let coordinator = MirrorCoordinator::new(state);
    assert!(matches!(
        coordinator.begin_run(),
        Err(DesktopError::SyncPaused)
    ));
    assert_eq!(coordinator.status(true), SyncStatus::Paused);

    let mut pause = coordinator.begin_lifecycle_operation().unwrap();
    let mut resumed = coordinator.snapshot();
    resumed.paused = false;
    pause.publish_persisted_state(resumed.clone()).unwrap();
    assert!(matches!(
        coordinator.begin_lifecycle_operation(),
        Err(DesktopError::SyncAlreadyRunning)
    ));
    pause.finish_state(resumed);
    let run = coordinator.begin_run().unwrap();
    assert_eq!(coordinator.status(true), SyncStatus::Syncing);
    drop(run);
}

#[test]
fn review_state_keeps_the_last_verified_baseline_until_a_fresh_pass_succeeds() {
    let state = DesktopState {
        pair: Some(SyncPair {
            server_url: "https://drive.example".into(),
            account_email: "owner@example.test".into(),
            workspace_id: "workspace".into(),
            workspace_name: "Workspace".into(),
            remote_root_id: None,
            remote_root_name: None,
            local_root: PathBuf::from("C:/Drive"),
            local_root_identity: None,
        }),
        baseline: baseline(),
        ..DesktopState::default()
    };
    let coordinator = MirrorCoordinator::new(state);
    let mut run = coordinator.begin_run().unwrap();
    run.finish_with_reviews(vec![local_deletion_review(
        Path::new("report.pdf"),
        0,
        false,
    )]);
    let snapshot = coordinator.snapshot();
    assert_eq!(snapshot.baseline, baseline());
    assert_eq!(snapshot.reviews.len(), 1);
    assert!(snapshot.last_successful_sync.is_none());
}

#[test]
fn recheck_keeps_a_review_until_a_planning_only_pass_can_converge() {
    let state = DesktopState {
        pair: Some(SyncPair {
            server_url: "https://drive.example".into(),
            account_email: "owner@example.test".into(),
            workspace_id: "workspace".into(),
            workspace_name: "Workspace".into(),
            remote_root_id: None,
            remote_root_name: None,
            local_root: PathBuf::from("C:/Drive"),
            local_root_identity: None,
        }),
        baseline: baseline(),
        reviews: vec![remote_deletion_review(Path::new("report.pdf"), 0)],
        ..DesktopState::default()
    };
    let coordinator = MirrorCoordinator::new(state);

    let mut recheck = coordinator.begin_run().unwrap();
    recheck.finish_recheck_pending();
    let retained = coordinator.snapshot();
    assert_eq!(retained.baseline, baseline());
    assert_eq!(retained.reviews.len(), 1);
    assert_eq!(coordinator.status(true), SyncStatus::NeedsReview);

    // This represents a later recheck after the approved recovery has
    // converged: no mutations occur until that fresh verified baseline is
    // available, and only then is the old review cleared.
    let mut converged = coordinator.begin_run().unwrap();
    converged.finish_success(BTreeMap::new(), timestamp());
    assert!(coordinator.snapshot().reviews.is_empty());
    assert_eq!(coordinator.status(true), SyncStatus::Synced);
}

#[test]
fn incompatible_remote_paths_project_stable_reviews_without_planned_mutation() {
    let local_root = tempfile::tempdir().unwrap();
    let before = fs::read_dir(local_root.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    let state = DesktopState {
        pair: Some(SyncPair {
            server_url: "https://drive.example".into(),
            account_email: "owner@example.test".into(),
            workspace_id: "workspace".into(),
            workspace_name: "Workspace".into(),
            remote_root_id: None,
            remote_root_name: None,
            local_root: local_root.path().to_path_buf(),
            local_root_identity: None,
        }),
        ..DesktopState::default()
    };
    let coordinator = MirrorCoordinator::new(state);
    let incompatible = vec![RemoteEntry {
        id: "reserved".into(),
        parent_id: None,
        name: "AUX.txt".into(),
        kind: RemoteEntryKind::File,
        revision: 1,
        content_hash: Some("remote".into()),
        size_bytes: Some(1),
        trashed: false,
    }];

    let mut first = coordinator.begin_run().unwrap();
    let first_plan = first.plan(&incompatible, &[], timestamp()).unwrap();
    assert!(first_plan.actions.is_empty());
    assert_eq!(first_plan.reviews.len(), 1);
    assert_eq!(first_plan.reviews[0].kind, ReviewKind::UnsafePath);
    assert_eq!(
        first_plan.reviews[0].relative_path,
        PathBuf::from("AUX.txt")
    );
    assert_eq!(first_plan.reviews[0].actions, Vec::<ReviewAction>::new());
    assert!(first_plan.reviews[0]
        .summary
        .contains("reserved by Windows"));
    assert!(first_plan.reviews[0]
        .summary
        .contains("No local files were changed"));
    assert!(is_path_compatibility_review(&first_plan.reviews[0]));
    let after_plan = fs::read_dir(local_root.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    assert_eq!(after_plan, before);
    first.finish_with_reviews(first_plan.reviews.clone());
    let persisted = coordinator.snapshot();
    assert_eq!(coordinator.status(true), SyncStatus::NeedsReview);

    // Replanning the same manifest reproduces the exact UI-facing review
    // and remains pure: there are still no transfer actions to execute.
    let mut same_manifest_recheck = coordinator.begin_run().unwrap();
    let same_plan = same_manifest_recheck
        .plan(&incompatible, &[], timestamp())
        .unwrap();
    assert_eq!(same_plan.reviews, persisted.reviews);
    assert!(same_plan.actions.is_empty());
    same_manifest_recheck.finish_with_reviews(same_plan.reviews);
    assert_eq!(coordinator.snapshot().reviews, persisted.reviews);

    // A compatible ordinary Latvian name removes the path-only review by
    // planning alone.  The resulting download is intentionally not run
    // here; it remains the next explicit normal-sync action.
    let compatible = vec![RemoteEntry {
        id: "latvian".into(),
        parent_id: None,
        name: "Ābols Žurnāls.txt".into(),
        kind: RemoteEntryKind::File,
        revision: 1,
        content_hash: Some("remote".into()),
        size_bytes: Some(1),
        trashed: false,
    }];
    let mut compatible_recheck = coordinator.begin_run().unwrap();
    let compatible_plan = compatible_recheck
        .plan(&compatible, &[], timestamp())
        .unwrap();
    assert!(compatible_plan.reviews.is_empty());
    assert!(compatible_plan.requires_transfer());
    compatible_recheck.finish_recheck_compatible();
    let cleared = coordinator.snapshot();
    assert!(cleared.reviews.is_empty());
    assert!(cleared.baseline.is_empty());
    assert!(cleared.last_successful_sync.is_none());
}

#[test]
fn ordinary_precomposed_latvian_paths_plan_download_and_upload() {
    let remote_path = "Ābols Žurnāls.txt";
    let remote = RemoteEntry {
        id: "remote-latvian".into(),
        parent_id: None,
        name: remote_path.into(),
        kind: RemoteEntryKind::File,
        revision: 1,
        content_hash: Some("remote".into()),
        size_bytes: Some(1),
        trashed: false,
    };
    let download =
        plan_reconciliation(&BTreeMap::new(), None, &[remote], &[], timestamp()).unwrap();
    assert!(download.reviews.is_empty());
    assert!(matches!(
        download.actions.as_slice(),
        [SyncAction::Download { relative_path, .. }] if relative_path == Path::new(remote_path)
    ));

    let local_root = tempfile::tempdir().unwrap();
    fs::write(local_root.path().join(remote_path), b"x").unwrap();
    let local = inspect_local_tree(local_root.path()).unwrap();
    assert!(local.issues.is_empty());
    let upload =
        plan_reconciliation(&BTreeMap::new(), None, &[], &local.entries, timestamp()).unwrap();
    assert!(upload.reviews.is_empty());
    assert!(matches!(
        upload.actions.as_slice(),
        [SyncAction::UploadNew { relative_path, is_directory: false, .. }]
            if relative_path == Path::new(remote_path)
    ));
}

#[cfg(not(target_os = "windows"))]
#[test]
fn local_incompatible_paths_project_stable_reviews_without_uploading() {
    let local_root = tempfile::tempdir().unwrap();
    fs::write(local_root.path().join("AUX.txt"), b"local").unwrap();
    let state = DesktopState {
        pair: Some(SyncPair {
            server_url: "https://drive.example".into(),
            account_email: "owner@example.test".into(),
            workspace_id: "workspace".into(),
            workspace_name: "Workspace".into(),
            remote_root_id: None,
            remote_root_name: None,
            local_root: local_root.path().to_path_buf(),
            local_root_identity: None,
        }),
        ..DesktopState::default()
    };
    let coordinator = MirrorCoordinator::new(state);
    let remote = vec![RemoteEntry {
        id: "remote".into(),
        parent_id: None,
        name: "Drive file.txt".into(),
        kind: RemoteEntryKind::File,
        revision: 1,
        content_hash: Some("remote".into()),
        size_bytes: Some(1),
        trashed: false,
    }];

    let local = inspect_local_tree(local_root.path()).unwrap();
    assert!(local.entries.is_empty());
    assert_eq!(
        local.issues,
        vec![LocalPathIssue {
            path: PathBuf::from("AUX.txt"),
            reason: "name is reserved by Windows".to_string(),
        }]
    );
    assert!(matches!(
        scan_local_tree(local_root.path()),
        Err(DesktopError::UnsafePath(_))
    ));

    let mut first = coordinator.begin_run().unwrap();
    let first_plan = apply_local_path_compatibility_reviews(
        first.plan(&remote, &local.entries, timestamp()).unwrap(),
        &local.issues,
    );
    assert!(first_plan.actions.is_empty());
    assert_eq!(first_plan.reviews.len(), 1);
    assert_eq!(first_plan.reviews[0].relative_path, Path::new("AUX.txt"));
    assert!(first_plan.reviews[0]
        .summary
        .contains("No local files were uploaded"));
    assert!(is_path_compatibility_review(&first_plan.reviews[0]));
    first.finish_with_reviews(first_plan.reviews.clone());
    let persisted = coordinator.snapshot();
    assert_eq!(coordinator.status(true), SyncStatus::NeedsReview);

    let local_recheck = inspect_local_tree(local_root.path()).unwrap();
    let mut same_recheck = coordinator.begin_run().unwrap();
    let same_plan = apply_local_path_compatibility_reviews(
        same_recheck
            .plan(&remote, &local_recheck.entries, timestamp())
            .unwrap(),
        &local_recheck.issues,
    );
    assert_eq!(same_plan.reviews, persisted.reviews);
    assert!(same_plan.actions.is_empty());
    same_recheck.finish_with_reviews(same_plan.reviews);

    fs::remove_file(local_root.path().join("AUX.txt")).unwrap();
    let compatible_local = inspect_local_tree(local_root.path()).unwrap();
    let mut compatible_recheck = coordinator.begin_run().unwrap();
    let compatible_plan = apply_local_path_compatibility_reviews(
        compatible_recheck
            .plan(&remote, &compatible_local.entries, timestamp())
            .unwrap(),
        &compatible_local.issues,
    );
    assert!(compatible_plan.reviews.is_empty());
    assert!(compatible_plan.requires_transfer());
    compatible_recheck.finish_recheck_compatible();
    assert!(coordinator.snapshot().reviews.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn local_case_collisions_are_inspected_as_needs_review_data() {
    let local_root = tempfile::tempdir().unwrap();
    fs::write(local_root.path().join("Report.txt"), b"upper").unwrap();
    fs::write(local_root.path().join("report.txt"), b"lower").unwrap();

    let inspection = inspect_local_tree(local_root.path()).unwrap();
    assert!(inspection.entries.is_empty());
    assert_eq!(inspection.issues.len(), 2);
    assert!(inspection.issues.iter().all(|issue| {
        issue.reason
            == "Windows treats this local path as the same path when matching case-insensitively"
    }));
    let plan = apply_local_path_compatibility_reviews(ReconcilePlan::default(), &inspection.issues);
    assert!(plan.actions.is_empty());
    assert_eq!(plan.reviews.len(), 2);
    assert!(plan.reviews.iter().all(is_path_compatibility_review));
}

#[test]
fn local_ambiguous_unicode_is_reviewed_without_an_upload_action() {
    let local_root = tempfile::tempdir().unwrap();
    let path = "Cafe\u{301}.txt";
    fs::write(local_root.path().join(path), b"local").unwrap();

    let inspection = inspect_local_tree(local_root.path()).unwrap();
    assert!(inspection.entries.is_empty());
    assert_eq!(inspection.issues.len(), 1);
    assert_eq!(inspection.issues[0].path, Path::new(path));
    assert!(inspection.issues[0]
        .reason
        .contains("normalization or case mapping"));
    let plan = apply_local_path_compatibility_reviews(
        plan_reconciliation(
            &BTreeMap::new(),
            None,
            &[],
            &inspection.entries,
            timestamp(),
        )
        .unwrap(),
        &inspection.issues,
    );
    assert!(plan.actions.is_empty());
    assert_eq!(plan.reviews.len(), 1);
    assert!(is_path_compatibility_review(&plan.reviews[0]));
}

#[test]
fn recovery_refuses_a_local_subtree_edited_after_the_review() {
    let baseline = BTreeMap::from([
        (
            "folder".to_string(),
            BaselineEntry {
                remote_id: "folder".to_string(),
                parent_id: None,
                relative_path: PathBuf::from("Projects"),
                kind: "folder".to_string(),
                content_hash: None,
                revision: 1,
                directory_identity: None,
            },
        ),
        (
            "file".to_string(),
            BaselineEntry {
                remote_id: "file".to_string(),
                parent_id: Some("folder".to_string()),
                relative_path: PathBuf::from("Projects/notes.txt"),
                kind: "file".to_string(),
                content_hash: Some("saved".to_string()),
                revision: 1,
                directory_identity: None,
            },
        ),
    ]);
    let review = remote_deletion_review(Path::new("Projects"), 1);
    let local = vec![
        LocalEntry {
            relative_path: PathBuf::from("Projects"),
            content_hash: None,
            size_bytes: 0,
            is_directory: true,
            directory_identity: None,
        },
        local_at("Projects/notes.txt", "edited-after-review", 22),
    ];
    assert!(reviewed_local_subtree_matches_baseline(&review, &baseline, &local).is_err());
}

#[test]
fn recovery_refuses_a_recreated_directory_identity_after_review() {
    let baseline = BTreeMap::from([(
        "folder".to_string(),
        folder_baseline("folder", "Projects", 1, Some(1)),
    )]);
    let review = remote_deletion_review(Path::new("Projects"), 0);
    let recreated = [local_directory_with_identity("Projects", 2)];
    assert!(reviewed_local_subtree_matches_baseline(&review, &baseline, &recreated).is_err());
}

#[test]
fn notification_policy_stays_quiet_until_action_is_needed() {
    let coordinator = MirrorCoordinator::new(DesktopState::default());
    coordinator.set_offline(true);
    assert!(!coordinator.should_notify(false));
    coordinator.record_error("Bearer secret should never be shown");
    assert!(coordinator.should_notify(true));
    assert!(coordinator
        .snapshot()
        .last_error
        .unwrap()
        .contains("protected request"));
}
