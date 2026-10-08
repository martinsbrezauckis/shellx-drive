pub(super) fn prune(conn: &rusqlite::Connection, maximum_events: i64) -> rusqlite::Result<()> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM security_events
         WHERE low_authority = 1
            OR category = 'guest_access'
            OR (category = 'login' AND outcome != 'success')",
        [],
        |row| row.get(0),
    )?;
    let overflow = count.saturating_sub(maximum_events.max(0));
    if overflow > 0 {
        conn.execute(
            "DELETE FROM security_events WHERE rowid IN (
                SELECT rowid FROM security_events
                WHERE low_authority = 1
                   OR category = 'guest_access'
                   OR (category = 'login' AND outcome != 'success')
                ORDER BY rowid ASC LIMIT ?1
             )",
            [overflow],
        )?;
    }
    Ok(())
}
