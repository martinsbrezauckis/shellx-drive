use chrono::Utc;
use rusqlite::params;

use super::storage;

#[test]
fn migration_keeps_the_newest_workspace_queue_rows() {
    let (_data, storage) = storage();
    let (workspace, _, _) = storage
        .create_workspace("Queue migration", "owner@example.test")
        .unwrap();
    let now = Utc::now().to_rfc3339();
    let conn = storage.conn.lock().unwrap();
    for index in 0..251 {
        conn.execute(
            "INSERT INTO email_outbox (
                id, kind, status, recipient_email, subject, body_text, workspace_id,
                attempts, created_at, updated_at
             ) VALUES (?1, 'legacy', 'queued', ?2, 'subject', 'body', ?3, 0, ?4, ?5)",
            params![
                format!("legacy-{index:03}"),
                format!("{index}@example.test"),
                &workspace.id,
                &now,
                format!("2026-01-01T00:00:{index:03}Z"),
            ],
        )
        .unwrap();
    }
    drop(conn);

    storage.migrate().unwrap();

    let conn = storage.conn.lock().unwrap();
    let retained: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM email_outbox WHERE workspace_id = ?1",
            [&workspace.id],
            |row| row.get(0),
        )
        .unwrap();
    let oldest_retained: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM email_outbox WHERE id = 'legacy-000'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let newest_retained: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM email_outbox WHERE id = 'legacy-250'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(retained, 250);
    assert_eq!(oldest_retained, 0);
    assert_eq!(newest_retained, 1);
}
