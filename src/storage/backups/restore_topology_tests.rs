use chrono::Utc;
use rusqlite::params;

use super::*;
use crate::{
    model::{CreateFileRequest, FileKind},
    storage::MAX_FILE_TREE_DEPTH,
};

fn node(storage: &Storage, workspace_id: &str, parent_id: Option<String>, name: &str) -> String {
    storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace_id.to_string(),
                parent_id,
                name: name.to_string(),
                kind: FileKind::Folder,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap()
        .0
        .id
}

#[test]
fn rejects_cross_workspace_edges_and_cycles() {
    let root = tempfile::tempdir().unwrap();
    let storage = Storage::open(root.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (first, _, _) = storage
        .create_workspace("First", "owner@example.test")
        .unwrap();
    let (second, _, _) = storage
        .create_workspace("Second", "owner@example.test")
        .unwrap();
    let first_root = node(&storage, &first.id, None, "root");
    let foreign_child = node(&storage, &second.id, None, "foreign");
    {
        let mut conn = storage.conn.lock().unwrap();
        let tx = conn.transaction().unwrap();
        tx.execute(
            "UPDATE files SET parent_id = ?1 WHERE id = ?2",
            params![first_root, foreign_child],
        )
        .unwrap();
        assert!(restore_topology::validate_in_tx(&tx)
            .unwrap_err()
            .to_string()
            .contains("workspace parent boundary"));
    }

    let root = tempfile::tempdir().unwrap();
    let storage = Storage::open(root.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Cycle", "owner@example.test")
        .unwrap();
    let first = node(&storage, &workspace.id, None, "first");
    let second = node(&storage, &workspace.id, Some(first.clone()), "second");
    let mut conn = storage.conn.lock().unwrap();
    let tx = conn.transaction().unwrap();
    tx.execute(
        "UPDATE files SET parent_id = ?1 WHERE id = ?2",
        params![second, first],
    )
    .unwrap();
    assert!(restore_topology::validate_in_tx(&tx)
        .unwrap_err()
        .to_string()
        .contains("parent cycle"));
}

#[test]
fn rejects_overdeep_forests() {
    let root = tempfile::tempdir().unwrap();
    let storage = Storage::open(root.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Depth", "owner@example.test")
        .unwrap();
    let now = Utc::now().to_rfc3339();
    let mut conn = storage.conn.lock().unwrap();
    let tx = conn.transaction().unwrap();
    let mut parent_id: Option<String> = None;
    for depth in 0..=MAX_FILE_TREE_DEPTH + 1 {
        let id = format!("depth-{depth:04}");
        tx.execute(
            "INSERT INTO files (id, workspace_id, parent_id, name, kind, revision, trashed,
             starred, content_hash, content_bytes, created_at, updated_at, cover_hash, cover_bytes)
             VALUES (?1, ?2, ?3, ?4, 'folder', 1, 0, 0, NULL, 0, ?5, ?5, NULL, 0)",
            params![id, workspace.id, parent_id, format!("node-{depth}"), now],
        )
        .unwrap();
        parent_id = Some(id);
    }
    assert!(restore_topology::validate_in_tx(&tx)
        .unwrap_err()
        .to_string()
        .contains("depth limit"));
}
