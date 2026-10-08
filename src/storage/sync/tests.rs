use std::{sync::mpsc, thread, time::Duration};

use super::*;
use crate::model::CreateFileRequest;

#[test]
fn manifest_cursor_replays_a_create_committed_after_file_selection() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let workspace = storage
        .create_workspace("Cursor race", "owner@example.test")
        .unwrap()
        .0;
    let workspace_id = workspace.id;
    let writer_storage = storage.clone();
    let writer_workspace_id = workspace_id.clone();
    let (selected_tx, selected_rx) = mpsc::channel();
    let (created_tx, created_rx) = mpsc::channel();
    let writer = thread::spawn(move || {
        selected_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        let file = writer_storage
            .create_file_with_content_bytes(
                CreateFileRequest {
                    workspace_id: writer_workspace_id,
                    parent_id: None,
                    name: "concurrent.txt".to_string(),
                    kind: crate::model::FileKind::File,
                    content: None,
                    path: None,
                },
                Some("a".repeat(64)),
                1,
            )
            .unwrap()
            .0;
        created_tx.send(file.id).unwrap();
    });

    let (files, cursor) = manifest_with_cursor(&storage, &workspace_id, || {
        let files = storage.list_sync_manifest_files(&workspace_id, 10).unwrap();
        selected_tx.send(()).unwrap();
        created_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        Ok(files)
    })
    .unwrap();
    writer.join().unwrap();

    assert!(
        files.is_empty(),
        "the create committed after file selection"
    );
    let current = storage.list_sync_manifest_files(&workspace_id, 10).unwrap();
    assert_eq!(current.len(), 1);
    let changes = storage
        .list_sync_changes(cursor, Some(&workspace_id))
        .unwrap();
    assert!(
        changes
            .iter()
            .any(|change| { change.kind == "file.create" && change.entity_id == current[0].id }),
        "the replay cursor must retain the create missing from the manifest"
    );
}
