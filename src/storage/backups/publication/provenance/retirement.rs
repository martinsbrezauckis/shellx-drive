use chrono::Utc;
use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::{
    error::{ApiError, ApiResult},
    storage::Storage,
};

use super::catalog;

impl Storage {
    /// Atomically retire a locally managed (or authenticated local-v2)
    /// generation. The tombstone is intentionally written before any caller
    /// mutates archive files, so a failed or raced deletion stays fail-closed
    /// instead of permitting a replay at restart.
    pub(crate) fn retire_managed_backup_publication(&self, backup_id: &str) -> ApiResult<()> {
        let now = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let already_tombstoned = tx
            .query_row(
                "SELECT 1 FROM managed_backup_tombstones WHERE backup_id = ?1",
                params![backup_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !already_tombstoned {
            let tombstone_count: i64 = tx.query_row(
                "SELECT COUNT(*) FROM managed_backup_tombstones",
                [],
                |row| row.get(0),
            )?;
            if tombstone_count >= catalog::MAX_MANAGED_BACKUP_TOMBSTONES {
                return Err(ApiError::PayloadTooLarge(format!(
                    "managed backup tombstone registry reaches its {}-entry limit",
                    catalog::MAX_MANAGED_BACKUP_TOMBSTONES
                )));
            }
            tx.execute(
                "INSERT INTO managed_backup_tombstones (backup_id, retired_at)
                 VALUES (?1, ?2)",
                params![backup_id, &now],
            )?;
        }
        tx.execute(
            "DELETE FROM managed_backup_publications WHERE backup_id = ?1",
            params![backup_id],
        )?;
        tx.commit()?;
        Ok(())
    }
}
