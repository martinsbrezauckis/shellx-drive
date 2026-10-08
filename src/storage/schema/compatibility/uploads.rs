use rusqlite::Connection;

use super::super::super::ensure_column;

pub(super) fn migrate(conn: &Connection) -> rusqlite::Result<()> {
    ensure_column(
        conn,
        "upload_sessions",
        "duplicate_policy",
        "duplicate_policy TEXT NOT NULL DEFAULT 'keep_both'",
    )
}
