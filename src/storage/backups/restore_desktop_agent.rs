use rusqlite::{params, Connection};

use crate::error::{ApiError, ApiResult};

/// Desktop-agent controls bind a live device credential and pending local
/// action to this server instance. They are deliberately never archive data.
pub(super) const LOCAL_DESKTOP_AGENT_TABLES: [&str; 4] = [
    "desktop_agent_devices",
    "desktop_agent_commands",
    "desktop_agent_command_events",
    "desktop_agent_disconnect_completions",
];

pub(super) fn reject_backup_table_names<'a>(
    names: impl IntoIterator<Item = &'a str>,
) -> ApiResult<()> {
    for name in names {
        if LOCAL_DESKTOP_AGENT_TABLES.contains(&name) {
            return Err(ApiError::Validation(format!(
                "backup must not contain local desktop-agent table {name}"
            )));
        }
    }
    Ok(())
}

/// Clear target-local broker controls as part of a successful restore. This
/// prevents an archived product state from retaining a live device credential
/// or pending command that was authorized before restoration began.
pub(super) fn purge_local_state_in_tx(tx: &Connection) -> ApiResult<()> {
    let mut present = 0;
    for table in LOCAL_DESKTOP_AGENT_TABLES {
        if table_exists(tx, table)? {
            present += 1;
        }
    }
    if present == 0 {
        return Ok(());
    }
    if present != LOCAL_DESKTOP_AGENT_TABLES.len() {
        return Err(ApiError::Validation(
            "desktop-agent local control schema is incomplete".to_string(),
        ));
    }
    for table in LOCAL_DESKTOP_AGENT_TABLES.iter().rev() {
        tx.execute(&format!("DELETE FROM {table}"), [])?;
    }
    Ok(())
}

fn table_exists(conn: &Connection, table: &str) -> ApiResult<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
        params![table],
        |row| row.get::<_, i64>(0),
    )? != 0)
}
