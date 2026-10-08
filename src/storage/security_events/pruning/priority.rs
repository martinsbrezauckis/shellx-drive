pub(super) fn prune(conn: &rusqlite::Connection, maximum_events: i64) -> rusqlite::Result<()> {
    let total: i64 =
        conn.query_row("SELECT COUNT(*) FROM security_events", [], |row| row.get(0))?;
    let mut overflow = total.saturating_sub(maximum_events.max(0));
    if overflow <= 0 {
        return Ok(());
    }
    // Routine successful mutations are reproducible operational history. Keep
    // denied/failed evidence ahead of them, and auth/admin/policy evidence last,
    // while the outer hard cap still bounds even the protected classes. Each
    // class walks rowid order and stops at the overflow instead of sorting the
    // whole capped table during the periodic sweep.
    for predicate in [
        "outcome = 'success' AND category != 'login'
          AND route NOT LIKE '/auth/%' AND route NOT LIKE '/admin/%'
          AND route NOT LIKE '%/policy'",
        "outcome != 'success' AND category != 'login'
          AND route NOT LIKE '/auth/%' AND route NOT LIKE '/admin/%'
          AND route NOT LIKE '%/policy'",
        "low_authority = 1
          OR category = 'guest_access'
          OR (category = 'login' AND outcome != 'success')",
        "1 = 1",
    ] {
        let deleted = delete_oldest(conn, predicate, overflow)?;
        overflow = overflow.saturating_sub(i64::try_from(deleted).unwrap_or(i64::MAX));
        if overflow <= 0 {
            break;
        }
    }
    Ok(())
}

fn delete_oldest(
    conn: &rusqlite::Connection,
    predicate: &str,
    maximum: i64,
) -> rusqlite::Result<usize> {
    conn.execute(
        &format!(
            "DELETE FROM security_events WHERE rowid IN (
               SELECT rowid FROM security_events WHERE {predicate}
               ORDER BY rowid ASC LIMIT ?1
             )"
        ),
        [maximum],
    )
}
