use super::*;
use std::{collections::BTreeMap, path::PathBuf};

use shellx_drive_desktop_core::{ReviewAction, ReviewKind};

fn pair() -> SyncPair {
    SyncPair {
        server_url: "https://drive.example.test".to_string(),
        account_email: "person@example.test".to_string(),
        workspace_id: "workspace".to_string(),
        workspace_name: "Workspace".to_string(),
        remote_root_id: None,
        remote_root_name: None,
        local_root: PathBuf::from("/tmp/Drive"),
        local_root_identity: None,
    }
}

fn baseline(id: &str, parent: Option<&str>, path: &str, kind: &str) -> BaselineEntry {
    BaselineEntry {
        remote_id: id.to_string(),
        parent_id: parent.map(str::to_string),
        relative_path: PathBuf::from(path),
        kind: kind.to_string(),
        content_hash: (kind == "file").then(|| "hash".to_string()),
        revision: 1,
        directory_identity: None,
    }
}

fn remote(id: &str, parent: Option<&str>, name: &str, kind: RemoteEntryKind) -> RemoteEntry {
    RemoteEntry {
        id: id.to_string(),
        parent_id: parent.map(str::to_string),
        name: name.to_string(),
        kind: kind.clone(),
        revision: 1,
        content_hash: (kind == RemoteEntryKind::File).then(|| "hash".to_string()),
        size_bytes: (kind == RemoteEntryKind::File).then_some(4),
        trashed: false,
    }
}

fn fixture(descendant_count: usize) -> (DesktopState, ReviewItem, Vec<RemoteEntry>) {
    let state = DesktopState {
        baseline: BTreeMap::from([
            (
                "folder".to_string(),
                baseline("folder", None, "Projects", "folder"),
            ),
            (
                "saved".to_string(),
                baseline("saved", Some("folder"), "Projects/saved.txt", "file"),
            ),
        ]),
        ..DesktopState::default()
    };
    let item = ReviewItem {
        id: "restore-folder".to_string(),
        kind: ReviewKind::LocalDeletion,
        relative_path: PathBuf::from("Projects"),
        descendant_count,
        is_directory: true,
        summary: "restore".to_string(),
        actions: vec![ReviewAction::RestoreLocalCopy],
    };
    let remote = vec![
        remote("folder", None, "Projects", RemoteEntryKind::Folder),
        remote("saved", Some("folder"), "saved.txt", RemoteEntryKind::File),
    ];
    (state, item, remote)
}

#[test]
fn folder_restore_binds_reviewed_count_and_rejects_a_new_remote_descendant() {
    let (state, item, mut entries) = fixture(1);
    let expected = entries.clone();
    assert!(reviewed_saved_tree(&state, &item, &pair(), &entries).is_ok());
    entries.push(remote(
        "added",
        Some("folder"),
        "added.txt",
        RemoteEntryKind::File,
    ));
    assert!(reviewed_saved_tree(&state, &item, &pair(), &entries).is_err());
    assert!(terminal_tree_matches(&pair(), &state, &item, &expected, &entries).is_err());
    let (state, item, entries) = fixture(0);
    assert!(reviewed_saved_tree(&state, &item, &pair(), &entries).is_err());
}
