use super::*;

#[test]
fn low_authority_protected_denials_leave_before_real_protected_history() {
    let conn = test_connection();
    let now = Utc::now().to_rfc3339();
    for _ in 0..8 {
        conn.execute(
            "INSERT INTO security_events VALUES (
                'member@example.test', 'local_session', 'admin_test', 'denied', ?1, 1
             )",
            [&now],
        )
        .unwrap();
    }
    for (category, outcome) in [
        ("login", "success"),
        ("admin_test", "success"),
        ("policy_test", "denied"),
    ] {
        conn.execute(
            "INSERT INTO security_events VALUES (
                'admin@example.test', 'local_session', ?1, ?2, ?3, 0
             )",
            params![category, outcome, &now],
        )
        .unwrap();
    }

    prune_with_limits(&conn, 90, 4, 100, 100).unwrap();
    let low_authority: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM security_events WHERE low_authority = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(low_authority, 1);
    let protected: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM security_events WHERE low_authority = 0",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(protected, 3);
}
