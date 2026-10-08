use rusqlite::Connection;

const MAX_RECEIPTS: i64 = 100_000;
const PROTECTED: &str = r#"
    kind GLOB 'auth.*' OR kind GLOB 'session.*'
    OR kind GLOB 'app_token.*' OR kind GLOB 'agent_access.*'
    OR kind GLOB 'agent_principal.*' OR kind GLOB 'backup.*'
    OR kind GLOB 'maintenance.*' OR kind GLOB 'sandbox.*'
    OR kind GLOB 'retention.*' OR kind GLOB 'support_bundle.*'
    OR kind GLOB 'group.*' OR kind GLOB 'hosted.tenant.*'
    OR kind GLOB 'workspace.member.*' OR kind GLOB 'workspace.owner.*'
    OR kind GLOB 'workspace.group.*' OR kind GLOB 'workspace.invitation.*'
    OR kind GLOB 'workspace.delete.*' OR kind GLOB '*.policy.*'
"#;

pub(super) fn install(conn: &Connection) -> rusqlite::Result<()> {
    install_with_limit(conn, MAX_RECEIPTS)
}

fn install_with_limit(conn: &Connection, maximum: i64) -> rusqlite::Result<()> {
    let sql = format!(
        "DROP TRIGGER IF EXISTS receipts_count_delete;
         DROP TRIGGER IF EXISTS receipts_bound_history;
         CREATE INDEX IF NOT EXISTS idx_receipts_routine_retention
           ON receipts(created_at ASC, id ASC) WHERE NOT ({PROTECTED});
         CREATE TRIGGER receipts_count_delete BEFORE DELETE ON receipts BEGIN
           UPDATE retention_counters SET row_count = MAX(0, row_count - 1)
           WHERE name = 'receipts';
         END;
         CREATE TRIGGER receipts_bound_history AFTER INSERT ON receipts BEGIN
           INSERT INTO retention_counters (name, row_count) VALUES ('receipts', 1)
           ON CONFLICT(name) DO UPDATE SET row_count = row_count + 1;
           DELETE FROM receipts WHERE id = COALESCE(
             (SELECT id FROM receipts WHERE NOT ({PROTECTED})
              ORDER BY created_at ASC, id ASC LIMIT 1),
             (SELECT id FROM receipts ORDER BY created_at ASC, id ASC LIMIT 1)
           ) AND (SELECT row_count FROM retention_counters WHERE name = 'receipts') > {maximum};
         END;"
    );
    conn.execute_batch(&sql)?;
    let count: i64 = conn.query_row("SELECT COUNT(*) FROM receipts", [], |row| row.get(0))?;
    conn.execute(
        "INSERT INTO retention_counters (name, row_count) VALUES ('receipts', ?1)
         ON CONFLICT(name) DO UPDATE SET row_count = excluded.row_count",
        [count],
    )?;
    prune_existing(conn, maximum)
}

fn prune_existing(conn: &Connection, maximum: i64) -> rusqlite::Result<()> {
    let total: i64 = conn.query_row("SELECT COUNT(*) FROM receipts", [], |row| row.get(0))?;
    let overflow = total.saturating_sub(maximum.max(0));
    if overflow > 0 {
        let sql = format!(
            "DELETE FROM receipts WHERE id IN (
               SELECT id FROM receipts ORDER BY CASE WHEN {PROTECTED} THEN 1 ELSE 0 END,
                 created_at ASC, id ASC LIMIT ?1
             )"
        );
        conn.execute(&sql, [overflow])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
