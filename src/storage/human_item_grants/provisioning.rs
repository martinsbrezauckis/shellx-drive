use rusqlite::{params, OptionalExtension, Transaction};

use crate::error::ApiResult;

/// Bind an account to exactly one canonical private workspace in the same
/// transaction that publishes the account.  The deterministic id also makes a
/// retry after a process crash harmless.
pub(in crate::storage) fn ensure_private_workspace_for_account_in_tx(
    tx: &Transaction<'_>,
    user_id: &str,
    now: &str,
) -> ApiResult<()> {
    let existing = tx
        .query_row(
            "SELECT workspace_id FROM account_private_workspaces WHERE user_id = ?1",
            [user_id],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if existing.is_some() {
        return Ok(());
    }
    let workspace_id = format!("private-v1:{user_id}");
    tx.execute(
        "INSERT OR IGNORE INTO workspaces
            (id, tenant_id, name, storage_mode, created_at, updated_at)
         VALUES (?1, NULL, 'My files', 'open', ?2, ?2)",
        params![&workspace_id, now],
    )?;
    tx.execute(
        "INSERT OR IGNORE INTO workspace_members (workspace_id, user_id, role)
         VALUES (?1, ?2, 'owner')",
        params![&workspace_id, user_id],
    )?;
    tx.execute(
        "INSERT OR IGNORE INTO account_private_workspaces (user_id, workspace_id, created_at)
         VALUES (?1, ?2, ?3)",
        params![user_id, &workspace_id, now],
    )?;
    Ok(())
}

pub(in crate::storage) fn register_private_workspace_in_tx(
    tx: &Transaction<'_>,
    user_id: &str,
    workspace_id: &str,
    now: &str,
) -> ApiResult<()> {
    tx.execute(
        "INSERT INTO account_private_workspaces (user_id, workspace_id, created_at)
         VALUES (?1, ?2, ?3)",
        params![user_id, workspace_id, now],
    )?;
    Ok(())
}
