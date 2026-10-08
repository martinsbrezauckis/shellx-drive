use super::*;

#[test]
fn low_authority_events_cannot_consume_the_high_value_reserve() {
    let conn = test_connection();
    let now = Utc::now().to_rfc3339();
    for index in 0..8 {
        conn.execute(
            "INSERT INTO security_events VALUES (
                ?1, 'local_password', 'login', 'denied', ?2, 1
             )",
            params![format!("user-{index}@example.test"), &now],
        )
        .unwrap();
    }
    conn.execute(
        "INSERT INTO security_events VALUES (
            'admin@example.test', 'local_session', 'command', 'success', ?1, 0
         )",
        [&now],
    )
    .unwrap();

    prune_with_limits(&conn, 90, 100, 100, 3).unwrap();
    let low_authority: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM security_events WHERE category = 'login'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(low_authority, 3);
    let high_value: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM security_events WHERE category = 'command'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(high_value, 1);
}
