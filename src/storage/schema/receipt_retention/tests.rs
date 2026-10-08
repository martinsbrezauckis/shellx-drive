use super::*;

mod query_plan;

fn connection() -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE receipts (
           id TEXT PRIMARY KEY, kind TEXT NOT NULL, actor TEXT NOT NULL,
           target_id TEXT, created_at TEXT NOT NULL
         );
         CREATE INDEX idx_receipts_created ON receipts(created_at DESC, id DESC);
         CREATE TABLE retention_counters (
           name TEXT PRIMARY KEY, row_count INTEGER NOT NULL CHECK (row_count >= 0)
         );",
    )
    .unwrap();
    conn
}

fn insert(conn: &Connection, id: usize, kind: &str) {
    conn.execute(
        "INSERT INTO receipts (id, kind, actor, created_at) VALUES (?1, ?2, 'actor', ?3)",
        (
            format!("id-{id:03}"),
            kind,
            format!("2026-01-01T00:00:{id:02}Z"),
        ),
    )
    .unwrap();
}

#[test]
fn trigger_keeps_forensic_receipts_ahead_of_routine_mutations() {
    let conn = connection();
    install_with_limit(&conn, 5).unwrap();
    for (id, kind) in [
        (1, "auth.2fa.enable"),
        (2, "backup.restore"),
        (3, "maintenance.blob.gc"),
        (4, "workspace.policy.update"),
    ] {
        insert(&conn, id, kind);
    }
    for id in 5..=12 {
        insert(&conn, id, "file.update");
    }
    let kinds: Vec<String> = conn
        .prepare("SELECT kind FROM receipts ORDER BY created_at")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(kinds.len(), 5);
    assert!(kinds.contains(&"auth.2fa.enable".to_string()));
    assert!(kinds.contains(&"backup.restore".to_string()));
    assert!(kinds.contains(&"maintenance.blob.gc".to_string()));
    assert!(kinds.contains(&"workspace.policy.update".to_string()));
    assert_eq!(kinds.last().unwrap(), "file.update");
}

#[test]
fn migration_prune_is_priority_aware_and_still_hard_bounded() {
    let conn = connection();
    for (id, kind) in [
        (1, "auth.password.change"),
        (2, "group.member.upsert"),
        (3, "file.update"),
        (4, "comment.create"),
        (5, "upload.complete"),
        (6, "share.create"),
    ] {
        insert(&conn, id, kind);
    }
    install_with_limit(&conn, 3).unwrap();
    let kinds: Vec<String> = conn
        .prepare("SELECT kind FROM receipts ORDER BY created_at")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(
        kinds,
        [
            "auth.password.change",
            "group.member.upsert",
            "share.create"
        ]
    );
    for id in 7..=12 {
        insert(&conn, id, "backup.restore");
    }
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM receipts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 3);
}
