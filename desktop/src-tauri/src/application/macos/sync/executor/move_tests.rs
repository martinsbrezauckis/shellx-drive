use std::{collections::BTreeMap, path::Path};

use shellx_drive_desktop_core::{
    DirectoryIdentity, FolderMoveEntry, FolderMovePrecondition, ReviewAction, ReviewKind,
};

use super::{outbound_move::destination_is_available, presentation::move_review};

#[test]
fn outbound_move_rejects_exact_and_case_alias_destinations() {
    let paths = BTreeMap::from([
        ("source".to_string(), Path::new("old.txt").to_path_buf()),
        ("sibling".to_string(), Path::new("REPORT.txt").to_path_buf()),
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
    assert!(destination_is_available(
        &paths,
        "source",
        Path::new("OLD.txt")
    ));
}

#[test]
fn folder_move_review_retains_kind_actions_and_descendant_impact() {
    let identity = DirectoryIdentity::unix(7, 9);
    let witness = FolderMovePrecondition {
        identity: identity.clone(),
        entries: BTreeMap::from([
            (
                Path::new("").to_path_buf(),
                FolderMoveEntry {
                    content_hash: None,
                    is_directory: true,
                    directory_identity: Some(identity),
                },
            ),
            (
                Path::new("child.txt").to_path_buf(),
                FolderMoveEntry {
                    content_hash: Some("hash".to_string()),
                    is_directory: false,
                    directory_identity: None,
                },
            ),
        ]),
        remote_witness: None,
    };
    let review = move_review(
        Path::new("renamed"),
        "Move needs review.",
        true,
        witness.entries.len().saturating_sub(1),
    );
    assert_eq!(review.kind, ReviewKind::PathConflict);
    assert_eq!(
        review.actions,
        vec![
            ReviewAction::RenameLocalCopy,
            ReviewAction::OpenConflictCopies
        ]
    );
    assert!(review.is_directory);
    assert_eq!(review.descendant_count, 1);
}
