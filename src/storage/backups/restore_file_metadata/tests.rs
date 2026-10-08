use chrono::Utc;
use rusqlite::params;

use super::super::restore_topology;
use super::*;
use crate::storage::{Storage, MAX_FILE_TREE_DEPTH};

#[path = "derived_name_tests.rs"]
mod derived_name_tests;

fn insert_folder(
    tx: &Transaction<'_>,
    id: &str,
    workspace_id: &str,
    parent_id: Option<&str>,
    name: &str,
    updated_at: &str,
) {
    tx.execute(
        "INSERT INTO files (id, workspace_id, parent_id, name, kind, revision, trashed,
         starred, content_hash, content_bytes, created_at, updated_at, cover_hash, cover_bytes)
         VALUES (?1, ?2, ?3, ?4, 'folder', 1, 0, 0, NULL, 0, ?5, ?5, NULL, 0)",
        params![id, workspace_id, parent_id, name, updated_at],
    )
    .unwrap();
}

#[test]
fn rejects_aggregate_metadata_and_projected_path_budgets() {
    let root = tempfile::tempdir().unwrap();
    let storage = Storage::open(root.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Metadata", "owner@example.test")
        .unwrap();
    let mut conn = storage.conn.lock().unwrap();
    let tx = conn.transaction().unwrap();
    let large_metadata = "t".repeat(2_100_000);
    insert_folder(&tx, "large-a", &workspace.id, None, "a", &large_metadata);
    insert_folder(&tx, "large-b", &workspace.id, None, "b", &large_metadata);
    let error = validate_in_tx(&tx).unwrap_err();
    assert!(matches!(error, ApiError::PayloadTooLarge(_)));
    assert!(error.to_string().contains("file metadata"));
    tx.rollback().unwrap();
    drop(conn);

    let mut conn = storage.conn.lock().unwrap();
    let tx = conn.transaction().unwrap();
    let now = Utc::now().to_rfc3339();
    let name = "x".repeat(255);
    let mut parent_id: Option<String> = None;
    for depth in 0..MAX_FILE_TREE_DEPTH {
        let id = format!("path-{depth:04}");
        insert_folder(&tx, &id, &workspace.id, parent_id.as_deref(), &name, &now);
        parent_id = Some(id);
    }
    restore_topology::validate_in_tx(&tx).unwrap();
    let error = validate_in_tx(&tx).unwrap_err();
    assert!(matches!(error, ApiError::PayloadTooLarge(_)));
    assert!(error.to_string().contains("path metadata"));
}

#[test]
fn rejects_noncanonical_file_rows() {
    let root = tempfile::tempdir().unwrap();
    let storage = Storage::open(root.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Rows", "owner@example.test")
        .unwrap();
    let now = Utc::now().to_rfc3339();
    let mut conn = storage.conn.lock().unwrap();
    let tx = conn.transaction().unwrap();
    insert_folder(&tx, "bad-kind", &workspace.id, None, "valid", &now);
    // The production trigger rejects this row at write time. Drop only the
    // ephemeral fixture trigger so the independent restore validator still
    // proves that an imported legacy catalog cannot bypass the same invariant.
    tx.execute_batch("DROP TRIGGER files_kind_content_update_guard")
        .unwrap();
    tx.execute("UPDATE files SET kind = 'device' WHERE id = 'bad-kind'", [])
        .unwrap();
    let error = validate_in_tx(&tx).unwrap_err();
    assert!(error.to_string().contains("file-row invariants"));
}
