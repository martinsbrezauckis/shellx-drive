use rusqlite::{params, Connection};

/// Account/global delivery rows remain NULL. Collaboration fanout rows carry
/// a workspace ID for quota accounting but intentionally have no FK, so an
/// empty archived workspace must remove them before its final deletion.
pub(super) fn delete_workspace_attributed_delivery_rows(
    conn: &Connection,
    workspace_id: &str,
) -> rusqlite::Result<()> {
    conn.execute(
        "DELETE FROM notifications WHERE workspace_id = ?1",
        params![workspace_id],
    )?;
    conn.execute(
        "DELETE FROM email_outbox WHERE workspace_id = ?1",
        params![workspace_id],
    )?;
    Ok(())
}
