use chrono::{Duration, Utc};
use rusqlite::params;

use crate::model::{CreateFileRequest, FileKind};

use super::storage;

#[test]
fn terminal_share_and_invitation_delivery_rows_are_scrubbed() {
    let (_data, storage) = storage();
    let (workspace, _, _) = storage
        .create_workspace("Delivery cleanup", "owner@example.test")
        .unwrap();
    let (file, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "delivery.txt".to_string(),
                kind: FileKind::File,
                content: None,
                path: None,
            },
            None,
        )
        .unwrap();
    let now = Utc::now().to_rfc3339();
    let future = (Utc::now() + Duration::hours(1)).to_rfc3339();
    let conn = storage.conn.lock().unwrap();
    conn.execute(
        "INSERT INTO shares (
            id, file_id, password_hash, password_required, expires_at, expires_in_seconds,
            revoked, created_at, target_kind, allow_download, recipient_note, max_uses,
            publication_pending
         ) VALUES ('revoked-share', ?1, 'hash', 0, NULL, NULL, 1, ?2, 'file', 1, NULL, NULL, 0),
                  ('pending-share', ?1, 'hash', 0, NULL, NULL, 0, ?2, 'file', 1, NULL, NULL, 1)",
        params![&file.id, &now],
    )
    .unwrap();
    for (id, status, expires_at, publication_pending) in [
        ("canceled-invitation", "canceled", now.as_str(), 0),
        (
            "expired-invitation",
            "pending",
            "2000-01-01T00:00:00+00:00",
            0,
        ),
        ("staged-invitation", "pending", future.as_str(), 1),
    ] {
        conn.execute(
            "INSERT INTO workspace_invitations (
                id, workspace_id, email, role, token_hash, status, invited_by, expires_at,
                member_expires_in_seconds, accepted_at, canceled_at, created_at, updated_at,
                publication_pending
             ) VALUES (?1, ?2, ?3, 'viewer', ?4, ?5, 'owner@example.test', ?6,
                       NULL, NULL, NULL, ?7, ?7, ?8)",
            params![
                id,
                &workspace.id,
                format!("{id}@example.test"),
                format!("{id}-token"),
                status,
                expires_at,
                &now,
                publication_pending,
            ],
        )
        .unwrap();
    }
    for (id, related_type, related_id) in [
        ("queued-share", "share", "revoked-share"),
        (
            "queued-canceled",
            "workspace_invitation",
            "canceled-invitation",
        ),
        (
            "queued-expired",
            "workspace_invitation",
            "expired-invitation",
        ),
        ("queued-pending-share", "share", "pending-share"),
        (
            "queued-staged-invitation",
            "workspace_invitation",
            "staged-invitation",
        ),
    ] {
        conn.execute(
            "INSERT INTO email_outbox (
                id, kind, status, recipient_email, subject, body_text, related_type,
                related_id, attempts, created_at, updated_at
             ) VALUES (?1, 'delivery', 'queued', 'recipient@example.test', 'subject', 'body',
                       ?2, ?3, 0, ?4, ?4)",
            params![id, related_type, related_id, &now],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO notifications (
                id, recipient_email, workspace_id, kind, title, body, related_type,
                related_id, created_at
             ) VALUES (?1, 'recipient@example.test', ?2, 'delivery', 'title', 'body',
                       ?3, ?4, ?5)",
            params![
                format!("notice-{id}"),
                &workspace.id,
                related_type,
                related_id,
                &now
            ],
        )
        .unwrap();
    }
    conn.execute(
        "INSERT INTO email_outbox (
            id, kind, status, recipient_email, subject, body_text, related_type,
            related_id, attempts, created_at, updated_at, sent_at
         ) VALUES ('sent-share', 'delivery', 'sent', 'recipient@example.test', 'subject', 'body',
                   'share', 'revoked-share', 1, ?1, ?1, ?1)",
        [&now],
    )
    .unwrap();
    drop(conn);

    storage.run_email_outbox_capture().unwrap();

    let conn = storage.conn.lock().unwrap();
    let queued: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM email_outbox WHERE status = 'queued'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let notices: i64 = conn
        .query_row("SELECT COUNT(*) FROM notifications", [], |row| row.get(0))
        .unwrap();
    let sent_audit: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM email_outbox WHERE id = 'sent-share'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(queued, 0);
    assert_eq!(notices, 0);
    assert_eq!(sent_audit, 1);
}
