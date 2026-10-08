//! Linux move review, collision, and postflight regressions.

use super::*;
use shellx_drive_desktop_core::{
    DirectoryIdentity, FolderMoveEntry, FolderMovePrecondition, RemoteFile, ReviewKind,
};

#[test]
fn move_collisions_remain_path_reviews_with_folder_impact() {
    let review = move_review(Path::new("Renamed"), "collision", true, 3);
    assert_eq!(review.kind, ReviewKind::PathConflict);
    assert!(review.is_directory);
    assert_eq!(review.descendant_count, 3);
    assert!(review.actions.contains(&ReviewAction::RenameLocalCopy));
}

#[test]
fn outbound_move_preflight_rejects_exact_and_case_alias_destinations() {
    let paths = BTreeMap::from([
        ("source".to_string(), PathBuf::from("old.txt")),
        ("sibling".to_string(), PathBuf::from("REPORT.txt")),
    ]);
    assert!(!destination_is_available(
        &paths,
        "source",
        Path::new("report.txt")
    ));
    assert!(destination_is_available(
        &paths,
        "source",
        Path::new("free.txt")
    ));
}

#[test]
fn outbound_folder_postflight_shifts_every_witness_path_and_root_revision() {
    let identity = DirectoryIdentity::unix(7, 9);
    let mut folder = FolderMovePrecondition {
        identity: identity.clone(),
        entries: BTreeMap::from([(
            PathBuf::new(),
            FolderMoveEntry {
                content_hash: None,
                is_directory: true,
                directory_identity: Some(identity),
            },
        )]),
        remote_witness: None,
    };
    let current = vec![
        RemoteEntry {
            id: "folder".to_string(),
            parent_id: None,
            name: "Old".to_string(),
            kind: RemoteEntryKind::Folder,
            revision: 4,
            content_hash: None,
            size_bytes: None,
            trashed: false,
        },
        RemoteEntry {
            id: "child".to_string(),
            parent_id: Some("folder".to_string()),
            name: "child.txt".to_string(),
            kind: RemoteEntryKind::File,
            revision: 2,
            content_hash: Some("hash".to_string()),
            size_bytes: Some(4),
            trashed: false,
        },
    ];
    folder.remote_witness = capture_folder_remote_witness("folder", None, &current);
    assert!(folder_remote_witness_matches(&folder, None, &current));
    let moved = RemoteFile {
        id: "folder".to_string(),
        workspace_id: "workspace".to_string(),
        parent_id: Some("parent".to_string()),
        name: "New".to_string(),
        kind: RemoteFileKind::Folder,
        revision: 5,
        trashed: false,
        content_hash: None,
        size_bytes: None,
    };
    let shifted = moved_folder_precondition(&folder, &moved, Path::new("Parent/New")).unwrap();
    let witness = shifted.remote_witness.unwrap();
    assert_eq!(witness.root_path, Path::new("Parent/New"));
    assert_eq!(
        witness.entries["folder"].relative_path,
        Path::new("Parent/New")
    );
    assert_eq!(witness.entries["folder"].revision, 5);
    assert_eq!(
        witness.entries["folder"].parent_id.as_deref(),
        Some("parent")
    );
    assert_eq!(
        witness.entries["child"].relative_path,
        Path::new("Parent/New/child.txt")
    );
    assert_eq!(witness.entries["child"].revision, 2);
}
