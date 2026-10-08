use crate::{
    auth::{Actor, AuthMode, DriveCredential, WorkspaceRole},
    error::ApiError,
    model::{CreateFileRequest, FileKind},
    storage::DEFAULT_WORKSPACE_AUXILIARY_STORAGE_LIMIT_BYTES,
};

use super::{assert_ledger_matches_rebuild, storage, workspace_with_comment_and_reply};

#[test]
fn authorized_comment_fanout_quota_rejection_leaves_no_partial_rows_or_receipt() {
    let (_data, storage) = storage();
    let (workspace, _, _) = storage
        .create_workspace("Fanout atomicity", "owner@example.test")
        .unwrap();
    let (file, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "fanout.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    let operator = Actor {
        email: "operator@example.test".to_string(),
        is_admin: true,
        auth_mode: AuthMode::Operator,
        allowed_workspace_ids: None,
    };
    storage
        .upsert_workspace_member(
            &workspace.id,
            "recipient@example.test",
            WorkspaceRole::Viewer,
            &operator,
            &DriveCredential::Operator,
        )
        .unwrap();
    {
        let conn = storage.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM workspace_auxiliary_usage WHERE workspace_id = ?1",
            [&workspace.id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO workspace_auxiliary_usage (
                workspace_id, file_metadata_bytes, metadata_fts_projection_bytes,
                comment_reply_body_bytes, notification_bytes, email_outbox_bytes, updated_at
             ) VALUES (?1, 0, 0, 0, ?2, 0, 'now')",
            rusqlite::params![
                &workspace.id,
                DEFAULT_WORKSPACE_AUXILIARY_STORAGE_LIMIT_BYTES
            ],
        )
        .unwrap();
    }
    let receipts_before = storage.list_receipts().unwrap().len();
    assert!(matches!(
        storage.create_comment_authorized(
            &file.id,
            &operator,
            &DriveCredential::Operator,
            "must remain atomic",
        ),
        Err(ApiError::PayloadTooLarge(_))
    ));
    assert!(storage.list_comments_for_file(&file.id).unwrap().is_empty());
    assert!(storage.list_notifications().unwrap().is_empty());
    assert!(storage.list_email_outbox_redacted().unwrap().is_empty());
    assert_eq!(storage.list_receipts().unwrap().len(), receipts_before);
}

#[test]
fn comment_body_rejects_more_than_32_kibibytes_of_utf8() {
    let (_data, storage) = storage();
    let (workspace_id, file_id, _reply_id) = workspace_with_comment_and_reply(&storage);
    let oversized = "x".repeat(32 * 1024 + 1);
    assert!(matches!(
        storage.create_comment(&file_id, "owner@example.test", &oversized),
        Err(ApiError::PayloadTooLarge(_))
    ));
    assert_ledger_matches_rebuild(&storage, &workspace_id);
}

#[test]
fn authorized_tombstone_is_allowed_when_a_legacy_ledger_is_over_limit() {
    let (_data, storage) = storage();
    let (workspace_id, file_id, _reply_id) = workspace_with_comment_and_reply(&storage);
    let (comment, _) = storage
        .create_comment(&file_id, "owner@example.test", "remove me")
        .unwrap();
    let operator = Actor {
        email: "operator@example.test".to_string(),
        is_admin: true,
        auth_mode: AuthMode::Operator,
        allowed_workspace_ids: None,
    };
    {
        let conn = storage.conn.lock().unwrap();
        conn.execute(
            "DELETE FROM workspace_auxiliary_usage WHERE workspace_id = ?1",
            [&workspace_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO workspace_auxiliary_usage (
                workspace_id, file_metadata_bytes, metadata_fts_projection_bytes,
                comment_reply_body_bytes, notification_bytes, email_outbox_bytes, updated_at
             ) VALUES (?1, 0, 0, ?2, 0, 0, 'now')",
            rusqlite::params![
                &workspace_id,
                DEFAULT_WORKSPACE_AUXILIARY_STORAGE_LIMIT_BYTES + 32
            ],
        )
        .unwrap();
    }
    let (deleted, _) = storage
        .delete_comment_authorized(&comment.id, &operator, &DriveCredential::Operator)
        .unwrap();
    assert_eq!(deleted.body, "");
    assert!(storage.list_notifications().unwrap().is_empty());
    assert!(storage.list_email_outbox_redacted().unwrap().is_empty());
}
