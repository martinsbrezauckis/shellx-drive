use super::*;

#[test]
fn routine_success_flood_preserves_forensic_priorities_at_the_hard_cap() {
    let conn = test_connection();
    let now = Utc::now().to_rfc3339();
    for (category, outcome) in [
        ("login", "success"),
        ("admin_test", "success"),
        ("policy_test", "success"),
        ("access", "denied"),
    ] {
        conn.execute(
            "INSERT INTO security_events VALUES (
                'admin@example.test', 'local_session', ?1, ?2, ?3, 0
             )",
            params![category, outcome, &now],
        )
        .unwrap();
    }
    for _ in 0..20 {
        conn.execute(
            "INSERT INTO security_events VALUES (
                'member@example.test', 'local_session', 'command', 'success', ?1, 0
             )",
            [&now],
        )
        .unwrap();
    }

    prune_with_limits(&conn, 90, 6, 100, 100).unwrap();
    let protected: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM security_events
             WHERE category IN ('login', 'admin_test', 'policy_test')
                OR outcome != 'success'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(protected, 4);
    assert_eq!(total(&conn), 6);

    for _ in 0..10 {
        conn.execute(
            "INSERT INTO security_events VALUES (
                'admin@example.test', 'local_session', 'admin_test', 'success', ?1, 0
             )",
            [&now],
        )
        .unwrap();
    }
    prune_with_limits(&conn, 90, 6, 100, 100).unwrap();
    assert_eq!(total(&conn), 6);
}

fn total(conn: &rusqlite::Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM security_events", [], |row| row.get(0))
        .unwrap()
}
