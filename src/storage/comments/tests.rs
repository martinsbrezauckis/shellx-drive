mod admission;
mod delete_fanout;
mod pruning;

use crate::{
    model::{CreateFileRequest, FileKind},
    storage::Storage,
};

fn storage() -> (tempfile::TempDir, Storage) {
    let data = tempfile::tempdir().unwrap();
    let storage = Storage::open(data.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    (data, storage)
}

fn workspace_with_comment_and_reply(storage: &Storage) -> (String, String, String) {
    let (workspace, _, _) = storage
        .create_workspace("Comment accounting", "owner@example.test")
        .unwrap();
    let (file, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "comment.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    let (comment, _) = storage
        .create_comment(&file.id, "owner@example.test", "comment body")
        .unwrap();
    let (reply, _) = storage
        .create_comment_reply(&comment.id, "owner@example.test", "reply body")
        .unwrap();
    (workspace.id, file.id, reply.id)
}

fn usage_tuple(storage: &Storage, workspace_id: &str) -> (i64, i64, i64, i64, i64, i64) {
    let usage = storage
        .workspace_auxiliary_storage_usage(workspace_id)
        .unwrap();
    (
        usage.total_bytes,
        usage.file_metadata_bytes,
        usage.metadata_fts_projection_bytes,
        usage.comment_reply_body_bytes,
        usage.notification_bytes,
        usage.email_outbox_bytes,
    )
}

fn assert_ledger_matches_rebuild(storage: &Storage, workspace_id: &str) {
    let before = usage_tuple(storage, workspace_id);
    storage.rebuild_workspace_auxiliary_storage_usage().unwrap();
    assert_eq!(before, usage_tuple(storage, workspace_id));
}

#[test]
fn direct_comment_reply_and_file_deletes_keep_auxiliary_ledger_exact() {
    let (_data, storage) = storage();
    let (workspace_id, _file_id, reply_id) = workspace_with_comment_and_reply(&storage);
    {
        let conn = storage.conn.lock().unwrap();
        conn.execute("DELETE FROM comment_replies WHERE id = ?1", [&reply_id])
            .unwrap();
    }
    assert_ledger_matches_rebuild(&storage, &workspace_id);

    let (workspace_id, _file_id, reply_id) = workspace_with_comment_and_reply(&storage);
    {
        let conn = storage.conn.lock().unwrap();
        let comment_id: String = conn
            .query_row(
                "SELECT comment_id FROM comment_replies WHERE id = ?1",
                [&reply_id],
                |row| row.get(0),
            )
            .unwrap();
        conn.execute("DELETE FROM comments WHERE id = ?1", [&comment_id])
            .unwrap();
    }
    assert_ledger_matches_rebuild(&storage, &workspace_id);

    let (workspace_id, file_id, _reply_id) = workspace_with_comment_and_reply(&storage);
    {
        let conn = storage.conn.lock().unwrap();
        conn.execute("DELETE FROM files WHERE id = ?1", [&file_id])
            .unwrap();
    }
    assert_ledger_matches_rebuild(&storage, &workspace_id);
}

#[test]
fn empty_archived_workspace_delete_removes_attributed_delivery_rows() {
    let (_data, storage) = storage();
    let (workspace, _, _) = storage
        .create_workspace("Archived", "owner@example.test")
        .unwrap();
    storage
        .create_notification(
            "owner@example.test",
            "comment_created",
            "Comment on archived workspace",
            "A bounded message",
            Some(&workspace.id),
            None,
            Some("comment"),
            Some("comment-id"),
        )
        .unwrap();
    storage
        .queue_workspace_email(
            &workspace.id,
            "comment_created",
            "owner@example.test",
            "ShellX Drive comment",
            "A bounded message",
            Some("comment"),
            Some("comment-id"),
        )
        .unwrap();
    {
        let conn = storage.conn.lock().unwrap();
        conn.execute(
            "UPDATE workspaces SET archived_at = '2026-08-27T00:00:00Z' WHERE id = ?1",
            [&workspace.id],
        )
        .unwrap();
    }
    storage
        .delete_empty_archived_workspace(&workspace.id, "owner@example.test")
        .unwrap();
    let conn = storage.conn.lock().unwrap();
    let notification_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM notifications WHERE workspace_id = ?1",
            [&workspace.id],
            |row| row.get(0),
        )
        .unwrap();
    let email_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM email_outbox WHERE workspace_id = ?1",
            [&workspace.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!((notification_count, email_count), (0, 0));
}
