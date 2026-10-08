use super::*;

#[test]
fn batched_pruning_never_exposes_total_or_actorless_rows_above_hard_caps() {
    let conn = test_connection();
    let countdown = AtomicUsize::new(0);
    let now = Utc::now().to_rfc3339();
    let hard_total = 6;
    let hard_actorless = 4;
    let hard_low_authority = 4;
    let interval = 2;

    for rowid in 1..=10 {
        conn.execute(
            "INSERT INTO security_events
             VALUES (NULL, 'anonymous', 'access', 'denied', ?1, 0)",
            [&now],
        )
        .unwrap();
        maybe_prune_with_limits(
            &conn,
            &countdown,
            90,
            hard_total,
            hard_actorless,
            hard_low_authority,
            interval,
        )
        .unwrap();
        assert!(count_low_value(&conn) <= hard_actorless);
        assert!(total(&conn) <= hard_total, "actorless insert {rowid}");
    }
    for rowid in 11..=20 {
        conn.execute(
            "INSERT INTO security_events
             VALUES ('admin@example.test', 'local_session', 'command', 'success', ?1, 0)",
            [&now],
        )
        .unwrap();
        maybe_prune_with_limits(
            &conn,
            &countdown,
            90,
            hard_total,
            hard_actorless,
            hard_low_authority,
            interval,
        )
        .unwrap();
        assert!(count_low_value(&conn) <= hard_actorless);
        assert!(total(&conn) <= hard_total, "protected insert {rowid}");
    }
}

fn total(conn: &rusqlite::Connection) -> i64 {
    conn.query_row("SELECT COUNT(*) FROM security_events", [], |row| row.get(0))
        .unwrap()
}
