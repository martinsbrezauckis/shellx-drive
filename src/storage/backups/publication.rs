use chrono::Utc;
use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::{
    error::{ApiError, ApiResult},
    model::{BackupJob, Receipt},
};

use super::{insert_receipt_rows, job_authorization, new_receipt, query_backup_job, Storage};

mod provenance;

/// The locally durable classification for an ID that has ever named a
/// managed generation. A tombstone is deliberately distinct from an unknown
/// ID: a backup directory is attacker-controlled for this decision, so a
/// retired ID must not re-enter a portable or legacy compatibility lane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ManagedBackupGeneration {
    Active { archive_sha256: String },
    Tombstoned,
    Unmanaged,
}

impl Storage {
    /// Commit the final authorization decision after the potentially long
    /// archive hash and before authenticated catalog publication.
    pub(crate) fn create_backup_v2_publication_intent(&self, job_id: &str) -> ApiResult<Receipt> {
        let now = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        job_authorization::ensure_job_authorized(
            &tx,
            job_id,
            self.operator_credential_generation.as_ref(),
        )?;
        let (backup_id, actor): (String, String) = tx
            .query_row(
                "SELECT backup_id, actor FROM backup_jobs WHERE id = ?1 AND status = 'running'",
                params![job_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(ApiError::Conflict)?;
        let changed = tx.execute(
            "UPDATE backup_jobs
             SET phase = 'publishing', updated_at = ?1
             WHERE id = ?2 AND status = 'running'",
            params![&now, job_id],
        )?;
        if changed != 1 {
            return Err(ApiError::Conflict);
        }
        let receipt = new_receipt("backup.create.intent", &actor, Some(&backup_id));
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok(receipt)
    }

    /// Atomically publish the durable create success row and its final receipt.
    /// A failure writing either record leaves the job running so the worker's
    /// incomplete-publication guard can remove the unpublished generation.
    pub(crate) fn finalize_v2_backup_create_publication(
        &self,
        job_id: &str,
        archive_sha256: &str,
    ) -> ApiResult<BackupJob> {
        let now = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        job_authorization::ensure_job_authorized(
            &tx,
            job_id,
            self.operator_credential_generation.as_ref(),
        )?;
        let (backup_id, actor): (String, String) = tx
            .query_row(
                "SELECT backup_id, actor FROM backup_jobs
                 WHERE id = ?1 AND kind = 'create' AND status = 'running'",
                params![job_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?
            .ok_or(ApiError::Conflict)?;
        let changed = tx.execute(
            "UPDATE backup_jobs
             SET status = 'succeeded', phase = 'complete', archive_sha256 = ?1,
                 last_error = NULL, updated_at = ?2, finished_at = ?2
             WHERE id = ?3 AND kind = 'create' AND status = 'running'",
            params![archive_sha256, &now, job_id],
        )?;
        if changed != 1 {
            return Err(ApiError::Conflict);
        }
        // A newly generated UUID should never normally reuse an ID, but a
        // successful managed publication is the only operation allowed to
        // replace a retired generation. Startup reconciliation must not clear
        // this state from archive-controlled data.
        tx.execute(
            "DELETE FROM managed_backup_tombstones WHERE backup_id = ?1",
            params![&backup_id],
        )?;
        tx.execute(
            "INSERT INTO managed_backup_publications
                (backup_id, archive_sha256, published_at)
             VALUES (?1, ?2, ?3)",
            params![&backup_id, archive_sha256, &now],
        )?;
        let receipt = new_receipt("backup.create", &actor, Some(&backup_id));
        insert_receipt_rows(&tx, &receipt)?;
        let job = query_backup_job(&tx, job_id)?.ok_or(ApiError::NotFound)?;
        tx.commit()?;
        Ok(job)
    }
}
