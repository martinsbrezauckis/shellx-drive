use chrono::Utc;
use rusqlite::TransactionBehavior;

use crate::{
    auth::{Actor, DriveCredential},
    error::ApiResult,
};

use super::super::authorization;
use super::{purge_inactive_delivery_rows_locked, Storage};

impl Storage {
    /// Capture transport is an administrator mutation: recheck the exact
    /// source credential in the transaction that changes queued delivery rows.
    pub(crate) fn run_email_outbox_capture_authorized(
        &self,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<()> {
        self.run_email_outbox_capture_with(Some((actor, source_credential)))
    }

    #[cfg(test)]
    pub(crate) fn run_email_outbox_capture(&self) -> ApiResult<()> {
        self.run_email_outbox_capture_with(None)
    }

    fn run_email_outbox_capture_with(
        &self,
        authorization_context: Option<(&Actor, &DriveCredential)>,
    ) -> ApiResult<()> {
        let now = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        if let Some((actor, source_credential)) = authorization_context {
            authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
        }
        purge_inactive_delivery_rows_locked(&tx, &now)?;
        tx.execute(
            "UPDATE email_outbox
             SET status = 'sent', attempts = attempts + 1, updated_at = ?1, sent_at = ?1
             WHERE status = 'queued'",
            [&now],
        )?;
        tx.commit()?;
        Ok(())
    }
}
