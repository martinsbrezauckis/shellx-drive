use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::{
    error::{ApiError, ApiResult},
    storage::Storage,
};

impl Storage {
    pub(crate) fn record_managed_backup_publication(
        &self,
        backup_id: &str,
        archive_sha256: &str,
        published_at: &str,
    ) -> ApiResult<()> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if tx
            .query_row(
                "SELECT 1 FROM managed_backup_tombstones WHERE backup_id = ?1",
                params![backup_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some()
        {
            return Err(ApiError::NotFound);
        }
        tx.execute(
            "INSERT OR IGNORE INTO managed_backup_publications
                (backup_id, archive_sha256, published_at)
             VALUES (?1, ?2, ?3)",
            params![backup_id, archive_sha256, published_at],
        )?;
        let recorded: String = tx.query_row(
            "SELECT archive_sha256 FROM managed_backup_publications WHERE backup_id = ?1",
            params![backup_id],
            |row| row.get(0),
        )?;
        if recorded != archive_sha256 {
            return Err(ApiError::Validation(
                "managed backup publication digest conflicts with existing provenance".to_string(),
            ));
        }
        tx.commit()?;
        Ok(())
    }
}
