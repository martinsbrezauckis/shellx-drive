use chrono::Utc;
use rusqlite::{params, TransactionBehavior};

use crate::{error::ApiResult, storage::Storage};

use super::{bound_existing_queued_jobs, prune_terminal_background_jobs};

pub(crate) const MAX_BACKGROUND_JOB_ATTEMPTS: i64 = 3;

impl Storage {
    /// Recover claims left by the prior process. AppState already owns the
    /// data-root instance lock, so no live worker can still own these rows.
    pub(crate) fn recover_running_background_jobs(&self) -> ApiResult<(usize, usize)> {
        let now = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let failed = tx.execute(
            "UPDATE background_jobs
             SET status = 'failed',
                 last_error = 'service restarted repeatedly while this job was running',
                 updated_at = ?1, finished_at = ?1
             WHERE status = 'running' AND attempts >= ?2",
            params![&now, MAX_BACKGROUND_JOB_ATTEMPTS],
        )?;
        let requeued = tx.execute(
            "UPDATE background_jobs
             SET status = 'queued',
                 last_error = 'service restarted before this job completed',
                 updated_at = ?1, started_at = NULL, finished_at = NULL
             WHERE status = 'running'",
            params![&now],
        )?;
        bound_existing_queued_jobs(&tx)?;
        prune_terminal_background_jobs(&tx)?;
        tx.commit()?;
        Ok((requeued, failed))
    }
}
