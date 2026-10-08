use rusqlite::params;

use super::*;

fn create_content_file(storage: &Storage, workspace_id: &str, name: &str, hash: &str) -> DriveFile {
    storage
        .create_file_with_content_bytes(
            CreateFileRequest {
                workspace_id: workspace_id.to_string(),
                parent_id: None,
                name: name.to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            Some(hash.to_string()),
            1,
        )
        .unwrap()
        .0
}

#[test]
fn capacity_drop_after_replacement_leaves_superseded_search_text_absent() {
    let temp = tempfile::tempdir().unwrap();
    let storage = Storage::open(temp.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let (workspace, _, _) = storage
        .create_workspace("Search capacity", "owner@example.test")
        .unwrap();
    let file = create_content_file(&storage, &workspace.id, "memo.txt", &"a".repeat(64));
    storage.index_file_text(&file, "capacityoldneedle").unwrap();
    clear_jobs(&storage);

    storage
        .put_content(&file.id, file.revision, &"b".repeat(64), 1)
        .unwrap();
    let current = storage.get_file(&file.id).unwrap().unwrap();
    let limits = PendingJobLimits {
        global_count: 1,
        workspace_count: 1,
        global_bytes: 1,
        workspace_bytes: 1,
    };

    assert_eq!(
        enqueue_with_limits(&storage, &current, limits),
        BackgroundJobAdmission::DroppedAtCapacity
    );
    let conn = storage.conn.lock().unwrap();
    let index_rows: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM file_text_index WHERE file_id = ?1",
            params![&file.id],
            |row| row.get(0),
        )
        .unwrap();
    let fts_content: String = conn
        .query_row(
            "SELECT content FROM file_search_fts WHERE file_id = ?1",
            params![&file.id],
            |row| row.get(0),
        )
        .unwrap();
    drop(conn);
    assert_eq!(index_rows, 0);
    assert_eq!(fts_content, "");
    assert!(storage
        .search_file_results("capacityoldneedle")
        .unwrap()
        .is_empty());
}
