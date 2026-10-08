use rusqlite::params;

use super::super::{row_to_notification, Storage};

fn create_workspace(storage: &Storage, name: &str) -> String {
    storage
        .create_workspace(name, "owner@example.test")
        .unwrap()
        .0
        .id
}

fn create_notice(storage: &Storage, workspace_id: &str, body: &str) {
    storage
        .create_notification(
            "recipient@example.test",
            "share_created",
            "Share notice",
            body,
            Some(workspace_id),
            None,
            Some("share"),
            Some(body),
        )
        .unwrap();
}

#[test]
fn one_workspace_cannot_evict_another_recipients_partition() {
    let data = tempfile::tempdir().unwrap();
    let storage = Storage::open(data.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let workspace_a = create_workspace(&storage, "A");
    let workspace_b = create_workspace(&storage, "B");
    create_notice(&storage, &workspace_b, "workspace-b-retained");
    for index in 0..100 {
        create_notice(&storage, &workspace_a, &format!("a-{index}"));
    }
    for index in 0..7 {
        let workspace = create_workspace(&storage, &format!("Other {index}"));
        for notice in 0..100 {
            create_notice(&storage, &workspace, &format!("{index}-{notice}"));
        }
    }
    let final_workspace = create_workspace(&storage, "Final");
    for notice in 0..99 {
        create_notice(&storage, &final_workspace, &format!("final-{notice}"));
    }
    let before = {
        let conn = storage.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, recipient_email, workspace_id, file_id, kind, title, body,
                    related_type, related_id, read_at, created_at
             FROM notifications WHERE recipient_email = ?1 AND workspace_id = ?2",
            params!["recipient@example.test", &workspace_b],
            row_to_notification,
        )
        .unwrap()
    };

    create_notice(&storage, &workspace_a, "a-replacement");

    let after = {
        let conn = storage.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, recipient_email, workspace_id, file_id, kind, title, body,
                    related_type, related_id, read_at, created_at
             FROM notifications WHERE recipient_email = ?1 AND workspace_id = ?2",
            params!["recipient@example.test", &workspace_b],
            row_to_notification,
        )
        .unwrap()
    };
    assert_eq!(
        serde_json::to_vec(&after).unwrap(),
        serde_json::to_vec(&before).unwrap()
    );
}

#[test]
fn migration_keeps_the_newest_workspace_partition_rows() {
    let data = tempfile::tempdir().unwrap();
    let storage = Storage::open(data.path().join("drive.db")).unwrap();
    storage.migrate().unwrap();
    let workspace = create_workspace(&storage, "Migration retention");
    let conn = storage.conn.lock().unwrap();
    for index in 0..101 {
        conn.execute(
            "INSERT INTO notifications (
                id, recipient_email, workspace_id, kind, title, body, created_at
             ) VALUES (?1, 'recipient@example.test', ?2, 'legacy', 'title', 'body', ?3)",
            params![
                format!("legacy-{index:03}"),
                &workspace,
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
            "SELECT COUNT(*) FROM notifications WHERE workspace_id = ?1",
            [&workspace],
            |row| row.get(0),
        )
        .unwrap();
    let oldest_retained: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM notifications WHERE id = 'legacy-000'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let newest_retained: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM notifications WHERE id = 'legacy-100'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(retained, 100);
    assert_eq!(oldest_retained, 0);
    assert_eq!(newest_retained, 1);
}
