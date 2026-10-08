use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::{
    error::{ApiError, ApiResult},
    model::WorkspaceAuxiliaryStorageUsage,
};

use super::super::Storage;
use super::accounting::checked_usage_total;
use super::{WorkspaceAuxiliaryStorageDelta, DEFAULT_WORKSPACE_AUXILIARY_STORAGE_LIMIT_BYTES};

impl Storage {
    /// Recompute the derived ledger from authoritative application tables. It
    /// is intentionally public for migration and restore orchestration.
    pub fn rebuild_workspace_auxiliary_storage_usage(&self) -> ApiResult<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        super::reconciliation::rebuild_workspace_auxiliary_storage_usage_in_tx(&tx)?;
        tx.commit()?;
        Ok(())
    }

    pub fn workspace_auxiliary_storage_usage(
        &self,
        workspace_id: &str,
    ) -> ApiResult<WorkspaceAuxiliaryStorageUsage> {
        let conn = self.conn.lock().unwrap();
        workspace_auxiliary_storage_usage_in_tx(&conn, workspace_id)
    }

    /// Test-only admission probe. Production mutation paths must check their
    /// delta inside the same transaction that writes the source row.
    #[cfg(test)]
    pub(crate) fn ensure_workspace_auxiliary_storage_delta_fits(
        &self,
        workspace_id: &str,
        delta: WorkspaceAuxiliaryStorageDelta,
    ) -> ApiResult<WorkspaceAuxiliaryStorageUsage> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let usage = ensure_workspace_auxiliary_storage_delta_fits_in_tx(&tx, workspace_id, delta)?;
        tx.commit()?;
        Ok(usage)
    }
}

/// Check one exact category delta inside the caller's `BEGIN IMMEDIATE`
/// transaction. Source-table triggers apply the delta only if the caller then
/// writes the matching row. Reductions are always allowed, including when a
/// restored or legacy workspace is already over the current default limit.
pub(crate) fn ensure_workspace_auxiliary_storage_delta_fits_in_tx(
    conn: &Connection,
    workspace_id: &str,
    delta: WorkspaceAuxiliaryStorageDelta,
) -> ApiResult<WorkspaceAuxiliaryStorageUsage> {
    ensure_ledger_row_in_tx(conn, workspace_id)?;
    let current = workspace_auxiliary_storage_usage_in_tx(conn, workspace_id)?;
    let next_file_metadata = checked_apply(
        current.file_metadata_bytes,
        delta.file_metadata_bytes,
        "file metadata",
    )?;
    let next_metadata_fts = checked_apply(
        current.metadata_fts_projection_bytes,
        delta.metadata_fts_projection_bytes,
        "metadata FTS projection",
    )?;
    let next_comment_reply = checked_apply(
        current.comment_reply_body_bytes,
        delta.comment_reply_body_bytes,
        "comment/reply bodies",
    )?;
    let next_notifications = checked_apply(
        current.notification_bytes,
        delta.notification_bytes,
        "notifications",
    )?;
    let next_email_outbox = checked_apply(
        current.email_outbox_bytes,
        delta.email_outbox_bytes,
        "workspace email outbox",
    )?;
    let next_total = checked_usage_total(
        next_file_metadata,
        next_metadata_fts,
        next_comment_reply,
        next_notifications,
        next_email_outbox,
    )?;
    if delta.checked_total()? > 0 && next_total > DEFAULT_WORKSPACE_AUXILIARY_STORAGE_LIMIT_BYTES {
        return Err(ApiError::PayloadTooLarge(format!(
            "workspace auxiliary storage budget exceeded: {next_total} bytes would exceed {} bytes",
            DEFAULT_WORKSPACE_AUXILIARY_STORAGE_LIMIT_BYTES
        )));
    }
    Ok(WorkspaceAuxiliaryStorageUsage {
        workspace_id: workspace_id.to_string(),
        total_bytes: next_total,
        file_metadata_bytes: next_file_metadata,
        metadata_fts_projection_bytes: next_metadata_fts,
        comment_reply_body_bytes: next_comment_reply,
        notification_bytes: next_notifications,
        email_outbox_bytes: next_email_outbox,
        limit_bytes: DEFAULT_WORKSPACE_AUXILIARY_STORAGE_LIMIT_BYTES,
        remaining_bytes: DEFAULT_WORKSPACE_AUXILIARY_STORAGE_LIMIT_BYTES
            .saturating_sub(next_total)
            .max(0),
        over_limit: next_total > DEFAULT_WORKSPACE_AUXILIARY_STORAGE_LIMIT_BYTES,
    })
}

fn ensure_ledger_row_in_tx(conn: &Connection, workspace_id: &str) -> ApiResult<()> {
    let exists = conn
        .query_row(
            "SELECT 1 FROM workspaces WHERE id = ?1",
            params![workspace_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()?
        .is_some();
    if !exists {
        return Err(ApiError::NotFound);
    }
    conn.execute(
        "INSERT INTO workspace_auxiliary_usage (
            workspace_id, file_metadata_bytes, metadata_fts_projection_bytes,
            comment_reply_body_bytes, notification_bytes, email_outbox_bytes, updated_at
         ) VALUES (?1, 0, 0, 0, 0, 0, ?2)
         ON CONFLICT(workspace_id) DO NOTHING",
        params![workspace_id, Utc::now().to_rfc3339()],
    )?;
    Ok(())
}

fn workspace_auxiliary_storage_usage_in_tx(
    conn: &Connection,
    workspace_id: &str,
) -> ApiResult<WorkspaceAuxiliaryStorageUsage> {
    let row = conn
        .query_row(
            "SELECT file_metadata_bytes, metadata_fts_projection_bytes,
                    comment_reply_body_bytes, notification_bytes, email_outbox_bytes
             FROM workspace_auxiliary_usage WHERE workspace_id = ?1",
            params![workspace_id],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?;
    let Some((
        file_metadata_bytes,
        metadata_fts_projection_bytes,
        comment_reply_body_bytes,
        notification_bytes,
        email_outbox_bytes,
    )) = row
    else {
        let exists = conn
            .query_row(
                "SELECT 1 FROM workspaces WHERE id = ?1",
                params![workspace_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()?
            .is_some();
        if !exists {
            return Err(ApiError::NotFound);
        }
        return usage_from_values(workspace_id, 0, 0, 0, 0, 0);
    };
    usage_from_values(
        workspace_id,
        file_metadata_bytes,
        metadata_fts_projection_bytes,
        comment_reply_body_bytes,
        notification_bytes,
        email_outbox_bytes,
    )
}

fn usage_from_values(
    workspace_id: &str,
    file_metadata_bytes: i64,
    metadata_fts_projection_bytes: i64,
    comment_reply_body_bytes: i64,
    notification_bytes: i64,
    email_outbox_bytes: i64,
) -> ApiResult<WorkspaceAuxiliaryStorageUsage> {
    let total_bytes = checked_usage_total(
        file_metadata_bytes,
        metadata_fts_projection_bytes,
        comment_reply_body_bytes,
        notification_bytes,
        email_outbox_bytes,
    )?;
    Ok(WorkspaceAuxiliaryStorageUsage {
        workspace_id: workspace_id.to_string(),
        total_bytes,
        file_metadata_bytes,
        metadata_fts_projection_bytes,
        comment_reply_body_bytes,
        notification_bytes,
        email_outbox_bytes,
        limit_bytes: DEFAULT_WORKSPACE_AUXILIARY_STORAGE_LIMIT_BYTES,
        remaining_bytes: DEFAULT_WORKSPACE_AUXILIARY_STORAGE_LIMIT_BYTES
            .saturating_sub(total_bytes)
            .max(0),
        over_limit: total_bytes > DEFAULT_WORKSPACE_AUXILIARY_STORAGE_LIMIT_BYTES,
    })
}

fn checked_apply(current: i64, delta: i64, label: &str) -> ApiResult<i64> {
    let value = current
        .checked_add(delta)
        .ok_or_else(|| ApiError::Validation(format!("{label} ledger overflow")))?;
    if value < 0 {
        return Err(ApiError::Validation(format!(
            "{label} ledger cannot become negative"
        )));
    }
    Ok(value)
}
