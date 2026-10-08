use rusqlite::params;
use serde_json::json;

use crate::{
    model::{CreateFileRequest, FileKind, UpdateFileRequest},
    storage::Storage,
};

#[test]
fn legacy_oversized_metadata_can_be_replaced_with_a_bounded_value() {
    let data = tempfile::tempdir().unwrap();
    let storage = Storage::open(data.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Legacy", "owner@example.test")
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
    let oversized = format!("{{\"legacy\":\"{}\"}}", "x".repeat(64 * 1024));
    storage
        .conn
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO file_metadata (file_id, labels_json, custom_json, updated_at)
             VALUES (?1, '[]', ?2, 'now')",
            params![&file.id, oversized],
        )
        .unwrap();

    storage
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
                labels: Some(vec!["bounded".to_string()]),
                custom_metadata: Some(json!({})),
            },
        )
        .unwrap();
    let usage = storage
        .workspace_auxiliary_storage_usage(&workspace.id)
        .unwrap();
    assert!(usage.total_bytes < 128);
    assert_eq!(
        storage.get_file_metadata(&file.id).unwrap().labels,
        ["bounded"]
    );
}
