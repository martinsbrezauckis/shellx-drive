use rusqlite::params;
use serde_json::json;

use crate::{
    error::ApiError,
    model::{CreateFileRequest, FileKind, UpdateFileRequest},
};

use super::super::Storage;
use super::*;

fn storage() -> (tempfile::TempDir, Storage, String, String) {
    let data = tempfile::tempdir().unwrap();
    let storage = Storage::open(data.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Auxiliary", "owner@example.test")
        .unwrap();
    let (file, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "notes.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    (data, storage, workspace.id, file.id)
}

fn metadata_request(labels: Vec<String>) -> UpdateFileRequest {
    UpdateFileRequest {
        base_revision: None,
        name: None,
        parent_id: None,
        move_to_root: None,
        collision_policy: None,
        replace_target_id: None,
        replace_target_revision: None,
        labels: Some(labels),
        custom_metadata: Some(json!({"phase": "draft"})),
    }
}

fn force_auxiliary_total(storage: &Storage, workspace_id: &str, notification_bytes: i64) {
    let conn = storage.conn.lock().unwrap();
    conn.execute_batch("DROP TRIGGER workspace_auxiliary_budget_growth_guard")
        .unwrap();
    conn.execute(
        "UPDATE workspace_auxiliary_usage
         SET notification_bytes = ?1 WHERE workspace_id = ?2",
        params![notification_bytes, workspace_id],
    )
    .unwrap();
}

#[test]
fn metadata_update_enforces_utf8_byte_boundaries_without_mutating_prior_metadata() {
    let (_data, storage, _workspace_id, file_id) = storage();
    let at_limit = "🙂".repeat(16);
    storage
        .update_file(&file_id, metadata_request(vec![at_limit.clone()]))
        .unwrap();
    assert_eq!(
        storage.get_file_metadata(&file_id).unwrap().labels,
        [at_limit]
    );

    let error = storage
        .update_file(&file_id, metadata_request(vec!["🙂".repeat(17)]))
        .unwrap_err();
    assert!(matches!(error, ApiError::PayloadTooLarge(_)));
    assert_eq!(storage.get_file_metadata(&file_id).unwrap().labels.len(), 1);
}

#[test]
fn metadata_labels_keep_legacy_empty_label_compatibility_and_bound_normalized_bytes() {
    let projection =
        project_file_metadata_storage(vec!["  ".to_string(), "Alpha".to_string()], &json!({}))
            .unwrap();
    assert_eq!(projection.labels, ["alpha"]);
    let error = project_file_metadata_storage(vec!["İ".repeat(32)], &json!({})).unwrap_err();
    assert!(matches!(error, ApiError::PayloadTooLarge(_)));
}

#[test]
fn metadata_patch_budget_rejection_is_atomic() {
    let (_data, storage, workspace_id, file_id) = storage();
    force_auxiliary_total(
        &storage,
        &workspace_id,
        DEFAULT_WORKSPACE_AUXILIARY_STORAGE_LIMIT_BYTES - 4,
    );
    let error = storage
        .update_file(&file_id, metadata_request(vec!["blocked".to_string()]))
        .unwrap_err();
    assert!(matches!(error, ApiError::PayloadTooLarge(_)));
    assert_eq!(storage.get_file(&file_id).unwrap().unwrap().revision, 1);
    assert_eq!(
        storage.get_file_metadata(&file_id).unwrap().labels,
        Vec::<String>::new()
    );
}

#[test]
fn recursive_copy_budget_rejection_does_not_create_a_partial_tree() {
    let (_data, storage, workspace_id, _file_id) = storage();
    let (root, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace_id.clone(),
                parent_id: None,
                name: "folder".to_string(),
                kind: FileKind::Folder,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    let root_id = root.id;
    let (child, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace_id.clone(),
                parent_id: Some(root_id.clone()),
                name: "child.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    force_auxiliary_total(
        &storage,
        &workspace_id,
        DEFAULT_WORKSPACE_AUXILIARY_STORAGE_LIMIT_BYTES - 8,
    );
    let error = storage.copy_file(&root_id, None, None).unwrap_err();
    assert!(matches!(error, ApiError::PayloadTooLarge(_)));
    assert!(storage.get_file(&root_id).unwrap().is_some());
    assert!(storage.get_file(&child.id).unwrap().is_some());
    let conn = storage.conn.lock().unwrap();
    assert_eq!(
        conn.query_row(
            "SELECT COUNT(*) FROM files WHERE workspace_id = ?1",
            params![workspace_id],
            |row| row.get::<_, i64>(0),
        )
        .unwrap(),
        3
    );
}

#[test]
fn file_cascade_reconciles_metadata_ledger_before_and_after_rebuild() {
    let (_data, storage, workspace_id, file_id) = storage();
    storage
        .update_file(&file_id, metadata_request(vec!["tracked".to_string()]))
        .unwrap();
    assert!(
        storage
            .workspace_auxiliary_storage_usage(&workspace_id)
            .unwrap()
            .file_metadata_bytes
            > 0
    );
    storage
        .conn
        .lock()
        .unwrap()
        .execute("DELETE FROM files WHERE id = ?1", params![file_id])
        .unwrap();
    let before_rebuild = storage
        .workspace_auxiliary_storage_usage(&workspace_id)
        .unwrap();
    storage.rebuild_workspace_auxiliary_storage_usage().unwrap();
    let after_rebuild = storage
        .workspace_auxiliary_storage_usage(&workspace_id)
        .unwrap();
    assert_eq!(before_rebuild.total_bytes, 0);
    assert_eq!(before_rebuild.total_bytes, after_rebuild.total_bytes);
    assert_eq!(
        before_rebuild.file_metadata_bytes,
        after_rebuild.file_metadata_bytes
    );
    assert_eq!(
        before_rebuild.metadata_fts_projection_bytes,
        after_rebuild.metadata_fts_projection_bytes
    );
}
