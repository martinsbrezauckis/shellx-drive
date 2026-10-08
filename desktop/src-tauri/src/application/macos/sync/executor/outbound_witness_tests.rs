use std::{collections::BTreeMap, path::Path};

use shellx_drive_desktop_core::{
    DirectoryIdentity, FolderMoveEntry, FolderMovePrecondition, RemoteEntry, RemoteEntryKind,
    RemoteFile, RemoteFileKind, SyncPair,
};

use super::outbound_witness::{capture, moved_folder_precondition};

#[test]
fn folder_postflight_shifts_every_path_and_only_the_root_revision() {
    let identity = DirectoryIdentity::unix(7, 9);
    let planned = FolderMovePrecondition {
        identity: identity.clone(),
        entries: BTreeMap::from([(
            Path::new("").to_path_buf(),
            FolderMoveEntry {
                content_hash: None,
                is_directory: true,
                directory_identity: Some(identity),
            },
        )]),
        remote_witness: None,
    };
    let current = vec![
        entry("folder", None, "Old", RemoteEntryKind::Folder, 4),
        entry(
            "child",
            Some("folder"),
            "child.txt",
            RemoteEntryKind::File,
            2,
        ),
    ];
    let pair = SyncPair {
        workspace_id: "workspace".to_string(),
        workspace_name: "Workspace".to_string(),
        local_root: Path::new("/Drive").to_path_buf(),
        local_root_identity: None,
        remote_root_id: None,
        remote_root_name: None,
        server_url: "https://drive.example".to_string(),
        account_email: "owner@example.com".to_string(),
    };
    let exact = capture(&planned, "folder", &pair, &current).unwrap();
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
    let shifted = moved_folder_precondition(&exact, &moved, Path::new("Parent/New")).unwrap();
    let witness = shifted.remote_witness.unwrap();
    assert_eq!(witness.root_path, Path::new("Parent/New"));
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

fn entry(
    id: &str,
    parent: Option<&str>,
    name: &str,
    kind: RemoteEntryKind,
    revision: i64,
) -> RemoteEntry {
    RemoteEntry {
        id: id.to_string(),
        parent_id: parent.map(str::to_string),
        name: name.to_string(),
        kind,
        revision,
        content_hash: None,
        size_bytes: None,
        trashed: false,
    }
}
