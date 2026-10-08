use rusqlite::{params, Connection};

use crate::{
    error::{ApiError, ApiResult},
    model::Notification,
};

const MAX_ACCOUNT_NOTIFICATIONS_PER_RECIPIENT: i64 = 100;
const MAX_WORKSPACE_NOTIFICATIONS_PER_RECIPIENT: i64 = 900;
const MAX_NOTIFICATIONS_PER_WORKSPACE_RECIPIENT: i64 = 100;

/// Reserve one notification slot without ever deleting a different
/// workspace's retained rows. A full shared recipient budget rejects a new
/// origin partition rather than evicting another workspace or account notice.
pub(in super::super) fn reserve_notification_slot_locked(
    conn: &Connection,
    notification: &Notification,
) -> ApiResult<()> {
    if let Some(workspace_id) = notification.workspace_id.as_deref() {
        prune_workspace_partition_locked(conn, &notification.recipient_email, workspace_id)?;
        let workspace_total: i64 = conn.query_row(
            "SELECT COUNT(*) FROM notifications
             WHERE recipient_email = ?1 AND workspace_id IS NOT NULL",
            params![&notification.recipient_email],
            |row| row.get(0),
        )?;
        if workspace_total >= MAX_WORKSPACE_NOTIFICATIONS_PER_RECIPIENT {
            return Err(ApiError::TooManyRequests);
        }
    } else {
        prune_account_partition_locked(conn, &notification.recipient_email)?;
        let account_total: i64 = conn.query_row(
            "SELECT COUNT(*) FROM notifications
             WHERE recipient_email = ?1 AND workspace_id IS NULL",
            params![&notification.recipient_email],
            |row| row.get(0),
        )?;
        if account_total >= MAX_ACCOUNT_NOTIFICATIONS_PER_RECIPIENT {
            return Err(ApiError::TooManyRequests);
        }
    }
    Ok(())
}

fn prune_workspace_partition_locked(
    conn: &Connection,
    recipient_email: &str,
    workspace_id: &str,
) -> ApiResult<()> {
    conn.execute(
        "DELETE FROM notifications
         WHERE recipient_email = ?1 AND workspace_id = ?2
           AND id NOT IN (
             SELECT id FROM notifications
             WHERE recipient_email = ?1 AND workspace_id = ?2
             ORDER BY created_at DESC, id DESC LIMIT ?3
           )",
        params![
            recipient_email,
            workspace_id,
            MAX_NOTIFICATIONS_PER_WORKSPACE_RECIPIENT - 1
        ],
    )?;
    Ok(())
}

fn prune_account_partition_locked(conn: &Connection, recipient_email: &str) -> ApiResult<()> {
    conn.execute(
        "DELETE FROM notifications
         WHERE recipient_email = ?1 AND workspace_id IS NULL
           AND id NOT IN (
             SELECT id FROM notifications
             WHERE recipient_email = ?1 AND workspace_id IS NULL
             ORDER BY created_at DESC, id DESC LIMIT ?2
           )",
        params![recipient_email, MAX_ACCOUNT_NOTIFICATIONS_PER_RECIPIENT - 1],
    )?;
    Ok(())
}

pub(in super::super) fn migrate_notification_retention(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_notifications_recipient_workspace_created
             ON notifications(recipient_email, workspace_id, created_at, id);
         DELETE FROM notifications
         WHERE id IN (
             SELECT id FROM (
                 SELECT id, ROW_NUMBER() OVER (
                     PARTITION BY recipient_email, workspace_id
                     ORDER BY created_at DESC, id DESC
                 ) AS partition_rank
                 FROM notifications
                 WHERE workspace_id IS NOT NULL
             ) WHERE partition_rank > 100
         );
         DELETE FROM notifications
         WHERE id IN (
             SELECT id FROM (
                 SELECT id, ROW_NUMBER() OVER (
                     PARTITION BY recipient_email
                     ORDER BY created_at DESC, id DESC
             ) AS account_rank
                 FROM notifications
                 WHERE workspace_id IS NULL
             ) WHERE account_rank > 100
         );",
    )?;
    Ok(())
}
