use rusqlite::params;

use crate::{
    model::{CreateFileRequest, DriveFile, FileKind},
    storage::{Storage, MAX_FILE_TREE_DEPTH},
};

fn create_node(
    storage: &Storage,
    workspace_id: &str,
    parent_id: Option<String>,
    name: &str,
    kind: FileKind,
) -> DriveFile {
    storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace_id.to_string(),
                parent_id,
                name: name.to_string(),
                kind,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap()
        .0
}

#[test]
fn file_tree_validates_topology_before_hiding_legacy_descendants() {
    let root = tempfile::tempdir().unwrap();
    let storage = Storage::open(root.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Paths", "owner@example.test")
        .unwrap();
    let first = create_node(&storage, &workspace.id, None, "first", FileKind::Folder);
    let second = create_node(
        &storage,
        &workspace.id,
        Some(first.id.clone()),
        "second",
        FileKind::Folder,
    );
    let legacy_child = create_node(
        &storage,
        &workspace.id,
        Some(first.id.clone()),
        "legacy-child",
        FileKind::File,
    );
    let ordinary = storage.file_tree(&workspace.id).unwrap();
    assert!(ordinary
        .nodes
        .iter()
        .any(|node| node.path == "first/second"));

    let conn = storage.conn.lock().unwrap();
    conn.execute(
        "UPDATE files SET trashed = 1 WHERE id = ?1",
        params![&first.id],
    )
    .unwrap();
    drop(conn);
    let tree = storage.file_tree(&workspace.id).unwrap();
    assert!(tree
        .nodes
        .iter()
        .any(|node| node.id == first.id && node.trashed));
    assert!(!tree.nodes.iter().any(|node| node.id == legacy_child.id));

    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE files SET parent_id = ?1 WHERE id = ?2",
            params![&second.id, &first.id],
        )
        .unwrap();
    let error = storage.file_tree(&workspace.id).unwrap_err();
    assert!(error.to_string().contains("parent cycle"));
}

#[test]
fn file_tree_rejects_missing_and_overdeep_parent_topology() {
    let root = tempfile::tempdir().unwrap();
    let storage = Storage::open(root.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (missing_workspace, _, _) = storage
        .create_workspace("Missing parent", "owner@example.test")
        .unwrap();
    let missing = create_node(
        &storage,
        &missing_workspace.id,
        None,
        "missing-parent",
        FileKind::File,
    );
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "UPDATE files SET parent_id = 'absent-parent' WHERE id = ?1",
            params![&missing.id],
        )
        .unwrap();
    let error = storage.file_tree(&missing_workspace.id).unwrap_err();
    assert!(error
        .to_string()
        .contains("missing or cross-workspace parent"));

    let (deep_workspace, _, _) = storage
        .create_workspace("Overdeep parent", "owner@example.test")
        .unwrap();
    let conn = storage.conn.lock().unwrap();
    let mut insert = conn
        .prepare(
            "INSERT INTO files (
                id, workspace_id, parent_id, name, kind, revision, trashed, starred,
                content_hash, content_bytes, cover_hash, created_at, updated_at
             ) VALUES (?1, ?2, ?3, ?1, 'folder', 1, 0, 0, NULL, 0, NULL,
                       '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
        )
        .unwrap();
    let mut parent_id = None;
    for depth in 0..=MAX_FILE_TREE_DEPTH + 1 {
        let id = format!("overdeep-{depth}");
        insert
            .execute(params![&id, &deep_workspace.id, parent_id])
            .unwrap();
        parent_id = Some(id);
    }
    drop(insert);
    drop(conn);
    let error = storage.file_tree(&deep_workspace.id).unwrap_err();
    assert!(error.to_string().contains("depth limit"));
}
