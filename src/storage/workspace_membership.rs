//! Transactional invariants shared by every workspace-membership write path.

use chrono::Utc;
use rusqlite::{params, OptionalExtension, Transaction};

use crate::{
    auth::WorkspaceRole,
    error::{ApiError, ApiResult},
};

pub(super) fn ensure_role_transition_preserves_owner(
    tx: &Transaction<'_>,
    workspace_id: &str,
    user_id: &str,
    next_role: WorkspaceRole,
) -> ApiResult<()> {
    let now = Utc::now().to_rfc3339();
    let existing_role = tx
        .query_row(
            "SELECT role FROM workspace_members
             WHERE workspace_id = ?1 AND user_id = ?2
               AND (expires_at IS NULL OR expires_at > ?3)",
            params![workspace_id, user_id, &now],
            |row| row.get::<_, String>(0),
        )
        .optional()?;
    if existing_role.as_deref() != Some(WorkspaceRole::Owner.as_db_str())
        || next_role == WorkspaceRole::Owner
    {
        return Ok(());
    }
    if active_owner_count(tx, workspace_id, &now)? <= 1 {
        return Err(ApiError::Validation(
            "cannot change the role of the last workspace owner".to_string(),
        ));
    }
    Ok(())
}

pub(super) fn ensure_removal_preserves_owner(
    tx: &Transaction<'_>,
    workspace_id: &str,
    user_id: &str,
    error_message: &str,
) -> ApiResult<()> {
    let now = Utc::now().to_rfc3339();
    let is_active_owner: bool = tx.query_row(
        "SELECT EXISTS(
             SELECT 1 FROM workspace_members
             WHERE workspace_id = ?1 AND user_id = ?2 AND role = 'owner'
               AND (expires_at IS NULL OR expires_at > ?3)
         )",
        params![workspace_id, user_id, &now],
        |row| row.get(0),
    )?;
    if is_active_owner && active_owner_count(tx, workspace_id, &now)? <= 1 {
        return Err(ApiError::Validation(error_message.to_string()));
    }
    Ok(())
}

fn active_owner_count(tx: &Transaction<'_>, workspace_id: &str, now: &str) -> ApiResult<i64> {
    Ok(tx.query_row(
        "SELECT COUNT(*) FROM workspace_members
         WHERE workspace_id = ?1 AND role = 'owner'
           AND (expires_at IS NULL OR expires_at > ?2)",
        params![workspace_id, now],
        |row| row.get(0),
    )?)
}
