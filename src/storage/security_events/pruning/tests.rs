use super::*;
use chrono::Utc;
use rusqlite::params;

mod batching;
mod low_authority;
mod priority;
mod priority_low_authority;

fn test_connection() -> rusqlite::Connection {
    let conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE security_events (
            actor_email TEXT, credential_kind TEXT, category TEXT, outcome TEXT, created_at TEXT,
            low_authority INTEGER NOT NULL DEFAULT 0,
            route TEXT GENERATED ALWAYS AS (CASE category
              WHEN 'login' THEN '/auth/login' WHEN 'admin_test' THEN '/admin/test'
              WHEN 'policy_test' THEN '/workspaces/{workspace_id}/policy'
              ELSE '/files/{file_id}' END) VIRTUAL
         );
         CREATE TABLE auth_sessions (
            client_ip TEXT, user_agent TEXT, revoked_at TEXT,
            expires_at TEXT, last_seen_at TEXT, created_at TEXT
         );",
    )
    .unwrap();
    conn
}

#[test]
fn actorless_failures_cannot_consume_identity_or_capability_reserve() {
    let conn = test_connection();
    let now = Utc::now().to_rfc3339();
    for credential_kind in [
        "anonymous",
        "app_token",
        "agent_token",
        "guest",
        "anonymous",
    ] {
        conn.execute(
            "INSERT INTO security_events VALUES (NULL, ?1, 'access', 'denied', ?2, 0)",
            params![credential_kind, &now],
        )
        .unwrap();
    }
    conn.execute(
        "INSERT INTO security_events VALUES (?1, 'local_session', 'command', 'denied', ?2, 0)",
        params!["admin@example.test", &now],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO security_events VALUES (NULL, 'guest', 'guest_access', 'success', ?1, 1)",
        [&now],
    )
    .unwrap();

    prune_with_limits(&conn, 90, 100, 3, 100).unwrap();
    assert_eq!(count_low_value(&conn), 3);
    assert_eq!(count_protected(&conn), 2);
}

#[test]
fn sparse_rowids_delete_only_actual_overflow_and_preserve_protected_rows() {
    let conn = test_connection();
    let now = Utc::now().to_rfc3339();
    for (rowid, actor, kind, outcome) in [
        (10, Some("admin@example.test"), "local_session", "denied"),
        (20, None, "guest", "success"),
        (100, None, "anonymous", "denied"),
        (200, None, "app_token", "denied"),
        (300, None, "agent_token", "denied"),
        (400, None, "guest", "rejected"),
    ] {
        conn.execute(
            "INSERT INTO security_events (
                rowid, actor_email, credential_kind, category, outcome, created_at
             ) VALUES (?1, ?2, ?3, 'command', ?4, ?5)",
            params![rowid, actor, kind, outcome, &now],
        )
        .unwrap();
    }

    prune_with_limits(&conn, 90, 4, 2, 100).unwrap();
    assert_eq!(count_low_value(&conn), 2);
    assert_eq!(count_protected(&conn), 2);
    let rowids: Vec<i64> = conn
        .prepare("SELECT rowid FROM security_events ORDER BY rowid")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(rowids, vec![10, 20, 300, 400]);
}

#[test]
fn prune_countdown_sweeps_once_per_bounded_batch() {
    let countdown = AtomicUsize::new(0);
    assert!(prune_is_due(&countdown));
    countdown.store(SECURITY_EVENT_PRUNE_INTERVAL, Ordering::Relaxed);
    for _ in 1..SECURITY_EVENT_PRUNE_INTERVAL {
        assert!(!prune_is_due(&countdown));
    }
    assert!(prune_is_due(&countdown));
}

fn count_low_value(conn: &rusqlite::Connection) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM security_events
         WHERE actor_email IS NULL AND outcome != 'success'",
        [],
        |row| row.get(0),
    )
    .unwrap()
}

fn count_protected(conn: &rusqlite::Connection) -> i64 {
    conn.query_row(
        "SELECT COUNT(*) FROM security_events
         WHERE NOT (actor_email IS NULL AND outcome != 'success')",
        [],
        |row| row.get(0),
    )
    .unwrap()
}
