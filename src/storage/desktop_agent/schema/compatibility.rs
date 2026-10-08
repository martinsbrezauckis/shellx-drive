//! Additive schema compatibility for already-installed desktop-agent tables.

use rusqlite::Connection;

pub(super) fn install_compatibility_columns(conn: &Connection) -> rusqlite::Result<()> {
    for (table, column, definition) in [
        (
            "desktop_agent_devices",
            "candidate_recovery",
            "INTEGER NOT NULL DEFAULT 0",
        ),
        ("desktop_agent_commands", "lease_phase", "TEXT"),
        (
            "desktop_agent_commands",
            "lease_progress_basis_points",
            "INTEGER",
        ),
        ("desktop_agent_commands", "result_json", "TEXT"),
        (
            "desktop_agent_commands",
            "terminal_event_sequence",
            "INTEGER",
        ),
        ("desktop_agent_command_events", "result_json", "TEXT"),
        (
            "desktop_agent_disconnect_completions",
            "retirement_assertion_hash",
            "TEXT",
        ),
    ] {
        add_column_if_needed(conn, table, column, definition)?;
    }
    Ok(())
}

fn add_column_if_needed(
    conn: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> rusqlite::Result<()> {
    let mut statement = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let names = statement
        .query_map([], |row| row.get::<_, String>(1))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if !names.iter().any(|name| name == column) {
        conn.execute(
            &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
            [],
        )?;
    }
    Ok(())
}
