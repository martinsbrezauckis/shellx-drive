use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};

use crate::error::{ApiError, ApiResult};

pub(super) const MAX_WORKSPACE_MEMBERS: i64 = 100;
pub(super) const MAX_PENDING_WORKSPACE_INVITATIONS: i64 = 256;
pub(super) const MAX_TERMINAL_WORKSPACE_INVITATIONS: i64 = 512;
pub(super) const MAX_WORKSPACE_INVITATION_ROWS: i64 =
    MAX_PENDING_WORKSPACE_INVITATIONS + MAX_TERMINAL_WORKSPACE_INVITATIONS;

pub(super) fn ensure_workspace_member_capacity(
    conn: &Connection,
    workspace_id: &str,
    user_id: &str,
) -> ApiResult<()> {
    let existing = conn
        .query_row(
            "SELECT 1 FROM workspace_members WHERE workspace_id = ?1 AND user_id = ?2",
            params![workspace_id, user_id],
            |_| Ok(()),
        )
        .optional()?
        .is_some();
    if existing {
        return Ok(());
    }
    let members: i64 = conn.query_row(
        "SELECT COUNT(*) FROM workspace_members WHERE workspace_id = ?1",
        params![workspace_id],
        |row| row.get(0),
    )?;
    if members >= MAX_WORKSPACE_MEMBERS {
        return Err(ApiError::PayloadTooLarge(format!(
            "workspace membership is limited to {MAX_WORKSPACE_MEMBERS} direct members"
        )));
    }
    Ok(())
}

pub(super) fn prune_workspace_invitation_history(
    conn: &Connection,
    workspace_id: &str,
) -> ApiResult<()> {
    let now = Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE workspace_invitations
         SET status = 'expired', updated_at = ?2
         WHERE workspace_id = ?1 AND status = 'pending' AND expires_at <= ?2",
        params![workspace_id, now],
    )?;
    conn.execute(
        "DELETE FROM workspace_invitations
         WHERE workspace_id = ?1 AND status <> 'pending' AND id NOT IN (
             SELECT id FROM workspace_invitations
             WHERE workspace_id = ?1 AND status <> 'pending'
             ORDER BY updated_at DESC, id DESC LIMIT ?2
         )",
        params![workspace_id, MAX_TERMINAL_WORKSPACE_INVITATIONS],
    )?;
    super::email_outbox::purge_inactive_delivery_rows_locked(conn, &now)?;
    Ok(())
}

pub(super) fn ensure_pending_invitation_capacity(
    conn: &Connection,
    workspace_id: &str,
) -> ApiResult<()> {
    let pending: i64 = conn.query_row(
        "SELECT COUNT(*) FROM workspace_invitations
         WHERE workspace_id = ?1 AND status = 'pending'",
        params![workspace_id],
        |row| row.get(0),
    )?;
    if pending >= MAX_PENDING_WORKSPACE_INVITATIONS {
        return Err(ApiError::PayloadTooLarge(format!(
            "workspace invitations are limited to {MAX_PENDING_WORKSPACE_INVITATIONS} pending entries"
        )));
    }
    Ok(())
}
