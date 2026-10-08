use rusqlite::params;
use serde_json::json;

use crate::{
    error::ApiError,
    model::{CreateFileRequest, FileKind, UpdateFileRequest},
    storage::Storage,
};

#[test]
fn legacy_restore_rebuilds_bounded_metadata_fts_and_auxiliary_ledger() {
    let source_data = tempfile::tempdir().unwrap();
    let source = Storage::open(source_data.path().join("drive.db")).unwrap();
    source.migrate().unwrap();
    let (workspace, _, _) = source
        .create_workspace("Source", "owner@example.test")
        .unwrap();
    let (file, _) = source
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
    source
        .update_file(
            &file.id,
            UpdateFileRequest {
                base_revision: None,
                name: None,
                parent_id: None,
                move_to_root: None,
                collision_policy: None,
                replace_target_id: None,
                replace_target_revision: None,
                labels: Some(vec!["žurnāls".to_string()]),
                custom_metadata: Some(json!({"phase": "draft"})),
            },
        )
        .unwrap();
    let expected_usage = source
        .workspace_auxiliary_storage_usage(&workspace.id)
        .unwrap();
    let tables = source.export_backup_tables().unwrap();
    assert!(!tables.iter().any(|table| {
        matches!(
            table.name.as_str(),
            "workspace_auxiliary_usage" | "workspace_auxiliary_metadata_fts_projection"
        )
    }));

    let target_data = tempfile::tempdir().unwrap();
    let target = Storage::open(target_data.path().join("drive.db")).unwrap();
    target.migrate().unwrap();
    target.restore_backup_tables(&tables).unwrap();
    let restored_usage = target
        .workspace_auxiliary_storage_usage(&workspace.id)
        .unwrap();
    assert_eq!(restored_usage.total_bytes, expected_usage.total_bytes);
    assert_eq!(
        restored_usage.file_metadata_bytes,
        expected_usage.file_metadata_bytes
    );
    assert_eq!(
        restored_usage.metadata_fts_projection_bytes,
        expected_usage.metadata_fts_projection_bytes
    );
    let conn = target.conn.lock().unwrap();
    let fts_labels: String = conn
        .query_row(
            "SELECT labels FROM file_search_fts WHERE file_id = ?1",
            [&file.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(fts_labels, "[\"žurnāls\"]");
}

#[test]
fn restore_validator_rejects_oversized_metadata_before_derived_rebuild() {
    let data = tempfile::tempdir().unwrap();
    let storage = Storage::open(data.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Restore", "owner@example.test")
        .unwrap();
    let (file, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id,
                parent_id: None,
                name: "notes.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    let oversized = format!("{{\"payload\":\"{}\"}}", "x".repeat(64 * 1024));
    let mut conn = storage.conn.lock().unwrap();
    let tx = conn.transaction().unwrap();
    tx.execute(
        "INSERT INTO file_metadata (file_id, labels_json, custom_json, updated_at)
         VALUES (?1, '[]', ?2, 'now')",
        params![file.id, oversized],
    )
    .unwrap();
    assert!(matches!(
        super::auxiliary_metadata::validate_bounded_metadata_in_tx(&tx),
        Err(ApiError::PayloadTooLarge(_))
    ));
}
