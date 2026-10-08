use chrono::{Duration, Utc};
use rusqlite::params;

use crate::{
    error::ApiError,
    model::{CreateFileRequest, FileKind},
    storage::Storage,
};

use super::admission::{
    MAX_QUEUED_WORKSPACE_EMAIL_ROWS, MAX_QUEUED_WORKSPACE_RECIPIENT_EMAIL_ROWS,
};

mod authorization;
mod lifecycle;
mod migration;

pub(super) fn storage() -> (tempfile::TempDir, Storage) {
    let data = tempfile::tempdir().unwrap();
    let storage = Storage::open(data.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    (data, storage)
}

#[test]
fn workspace_mail_cannot_consume_the_security_reserve() {
    let (_data, storage) = storage();
    let (workspace, _, _) = storage
        .create_workspace("Queue admission", "owner@example.test")
        .unwrap();
    let now = Utc::now().to_rfc3339();
    let conn = storage.conn.lock().unwrap();
    let tx = conn.unchecked_transaction().unwrap();
    for index in 0..9_000 {
        tx.execute(
            "INSERT INTO email_outbox (
                id, kind, status, recipient_email, subject, body_text, workspace_id,
                attempts, created_at, updated_at
             ) VALUES (?1, 'share_created', 'queued', ?2, 'subject', 'body', ?3, 0, ?4, ?4)",
            params![
                format!("queued-{index}"),
                format!("{index}@example.test"),
                &workspace.id,
                &now
            ],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    drop(conn);

    assert!(storage
        .create_password_reset_token_and_email_if_none_active(
            "security@example.test",
            "security-token",
            &(Utc::now() + Duration::hours(1)).to_rfc3339(),
            "Reset password",
            "reset body",
        )
        .unwrap());
}

#[test]
fn workspace_mail_is_bounded_by_workspace_and_recipient() {
    let (_data, storage) = storage();
    let (workspace, _, _) = storage
        .create_workspace("Queue bounds", "owner@example.test")
        .unwrap();
    for index in 0..MAX_QUEUED_WORKSPACE_RECIPIENT_EMAIL_ROWS {
        storage
            .queue_workspace_email(
                &workspace.id,
                "share_created",
                "same@example.test",
                "subject",
                &format!("body-{index}"),
                None,
                None,
            )
            .unwrap();
    }
    assert!(matches!(
        storage.queue_workspace_email(
            &workspace.id,
            "share_created",
            "same@example.test",
            "subject",
            "overflow",
            None,
            None,
        ),
        Err(ApiError::TooManyRequests)
    ));

    for index in MAX_QUEUED_WORKSPACE_RECIPIENT_EMAIL_ROWS..MAX_QUEUED_WORKSPACE_EMAIL_ROWS {
        storage
            .queue_workspace_email(
                &workspace.id,
                "share_created",
                &format!("{index}@example.test"),
                "subject",
                "body",
                None,
                None,
            )
            .unwrap();
    }
    assert!(matches!(
        storage.queue_workspace_email(
            &workspace.id,
            "share_created",
            "overflow@example.test",
            "subject",
            "overflow",
            None,
            None,
        ),
        Err(ApiError::TooManyRequests)
    ));
}

#[test]
fn migration_attributes_live_share_and_invitation_mail() {
    let (_data, storage) = storage();
    let (workspace, _, _) = storage
        .create_workspace("Legacy delivery", "owner@example.test")
        .unwrap();
    let (file, _) = storage
        .create_file(
            CreateFileRequest {
                workspace_id: workspace.id.clone(),
                parent_id: None,
                name: "legacy.txt".to_string(),
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
            revoked, created_at, target_kind, allow_download, recipient_note, max_uses
         ) VALUES ('share-live', ?1, 'hash', 0, ?2, 3600, 0, ?3, 'file', 1, NULL, NULL)",
        params![&file.id, &future, &now],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO workspace_invitations (
            id, workspace_id, email, role, token_hash, status, invited_by, expires_at,
            accepted_at, canceled_at, created_at, updated_at, member_expires_in_seconds
         ) VALUES ('invitation-live', ?1, 'invitee@example.test', 'viewer', 'hash',
                   'pending', 'owner@example.test', ?2, NULL, NULL, ?3, ?3, NULL)",
        params![&workspace.id, &future, &now],
    )
    .unwrap();
    for (id, related_type, related_id) in [
        ("legacy-share", "share", "share-live"),
        (
            "legacy-invitation",
            "workspace_invitation",
            "invitation-live",
        ),
    ] {
        conn.execute(
            "INSERT INTO email_outbox (
                id, kind, status, recipient_email, subject, body_text, workspace_id,
                related_type, related_id, attempts, created_at, updated_at
             ) VALUES (?1, 'legacy', 'queued', 'recipient@example.test', 'subject', 'body',
                       NULL, ?2, ?3, 0, ?4, ?4)",
            params![id, related_type, related_id, &now],
        )
        .unwrap();
    }
    drop(conn);

    storage.migrate().unwrap();
    let conn = storage.conn.lock().unwrap();
    let attributed: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM email_outbox
             WHERE id IN ('legacy-share', 'legacy-invitation') AND workspace_id = ?1",
            [&workspace.id],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(attributed, 2);
}
