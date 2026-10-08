use crate::{
    auth::{Actor, AuthMode, DriveCredential},
    storage::DEFAULT_WORKSPACE_AUXILIARY_STORAGE_LIMIT_BYTES,
};

use super::{storage, workspace_with_comment_and_reply};

fn operator() -> Actor {
    Actor {
        email: "operator@example.test".to_string(),
        is_admin: true,
        auth_mode: AuthMode::Operator,
        allowed_workspace_ids: None,
    }
}

fn notification_ids(storage: &crate::storage::Storage, workspace_id: &str) -> Vec<String> {
    let conn = storage.conn.lock().unwrap();
    let mut stmt = conn
        .prepare(
            "SELECT id FROM notifications
             WHERE workspace_id = ?1 AND recipient_email = 'owner@example.test'
             ORDER BY id",
        )
        .unwrap();
    stmt.query_map([workspace_id], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap()
}

#[test]
fn suppressed_delete_fanout_keeps_existing_notifications_unchanged() {
    let (_data, storage) = storage();
    let (workspace_id, _file_id, reply_id) = workspace_with_comment_and_reply(&storage);
    {
        let conn = storage.conn.lock().unwrap();
        conn.execute(
            "WITH RECURSIVE sequence(value) AS (
                 VALUES(1) UNION ALL SELECT value + 1 FROM sequence WHERE value < 1000
             )
             INSERT INTO notifications (
                 id, recipient_email, workspace_id, file_id, kind, title, body,
                 related_type, related_id, read_at, created_at
             )
             SELECT 'old-notice-' || value, 'owner@example.test', ?1, NULL,
                    'legacy', 'Legacy notice', 'old notice ' || value,
                    NULL, NULL, NULL, '2026-08-27T00:00:00Z'
             FROM sequence",
            [&workspace_id],
        )
        .unwrap();
    }
    let usage = storage
        .workspace_auxiliary_storage_usage(&workspace_id)
        .unwrap();
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
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'now')",
            rusqlite::params![
                &workspace_id,
                usage.file_metadata_bytes,
                usage.metadata_fts_projection_bytes,
                DEFAULT_WORKSPACE_AUXILIARY_STORAGE_LIMIT_BYTES + 1024,
                usage.notification_bytes,
                usage.email_outbox_bytes,
            ],
        )
        .unwrap();
    }
    let before = notification_ids(&storage, &workspace_id);

    let (deleted, _) = storage
        .delete_comment_reply_authorized(&reply_id, &operator(), &DriveCredential::Operator)
        .unwrap();

    assert_eq!(deleted.body, "");
    assert_eq!(notification_ids(&storage, &workspace_id), before);
    let conn = storage.conn.lock().unwrap();
    let delete_emails: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM email_outbox WHERE kind = 'comment_reply_deleted'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(delete_emails, 0);
}

#[test]
fn full_email_queue_does_not_suppress_in_app_delete_fanout() {
    let (_data, storage) = storage();
    let (workspace_id, _file_id, reply_id) = workspace_with_comment_and_reply(&storage);
    {
        let conn = storage.conn.lock().unwrap();
        conn.execute(
            "WITH RECURSIVE sequence(value) AS (
                 VALUES(1) UNION ALL SELECT value + 1 FROM sequence WHERE value < 10000
             )
             INSERT INTO email_outbox (
                 id, kind, status, recipient_email, subject, body_text, workspace_id,
                 related_type, related_id, attempts, last_error, created_at, updated_at, sent_at
             )
             SELECT 'queued-mail-' || value, 'legacy', 'queued', 'owner@example.test',
                    'Legacy', 'queued', NULL, NULL, NULL, 0, NULL,
                    '2026-08-27T00:00:00Z', '2026-08-27T00:00:00Z', NULL
             FROM sequence",
            [],
        )
        .unwrap();
    }

    let (deleted, _) = storage
        .delete_comment_reply_authorized(&reply_id, &operator(), &DriveCredential::Operator)
        .unwrap();

    assert_eq!(deleted.body, "");
    let conn = storage.conn.lock().unwrap();
    let notifications: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM notifications
             WHERE workspace_id = ?1 AND kind = 'comment_reply_deleted'",
            [&workspace_id],
            |row| row.get(0),
        )
        .unwrap();
    let delete_emails: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM email_outbox WHERE kind = 'comment_reply_deleted'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!((notifications, delete_emails), (1, 0));
}
