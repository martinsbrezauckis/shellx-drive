use chrono::Utc;
use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::{
    auth::{Actor, DriveCredential},
    error::{ApiError, ApiResult},
    model::{Notification, Receipt},
};

use super::super::{
    authorization::ensure_source_credential_active, normalize_storage_email, row_to_notification,
    Storage,
};

use super::visibility::notification_is_live_in_tx;

impl Storage {
    pub fn mark_notification_read(
        &self,
        notification_id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(Notification, Receipt)> {
        let recipient_email = normalize_storage_email(&actor.email)?;
        let now = Utc::now().to_rfc3339();
        let notification = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            ensure_source_credential_active(&tx, actor, source_credential)?;
            let notification = tx
                .query_row(
                    "SELECT id, recipient_email, workspace_id, file_id, kind, title, body,
                            related_type, related_id, read_at, created_at
                     FROM notifications WHERE id = ?1 AND recipient_email = ?2",
                    params![notification_id, &recipient_email],
                    row_to_notification,
                )
                .optional()?
                .ok_or(ApiError::NotFound)?;
            if !notification_is_live_in_tx(
                &tx,
                &notification,
                actor,
                Some(source_credential),
                &now,
            )? {
                return Err(ApiError::NotFound);
            }
            let updated = tx.execute(
                "UPDATE notifications SET read_at = COALESCE(read_at, ?1)
                 WHERE id = ?2 AND recipient_email = ?3",
                params![&now, notification_id, &recipient_email],
            )?;
            if updated == 0 {
                return Err(ApiError::NotFound);
            }
            let notification = tx.query_row(
                "SELECT id, recipient_email, workspace_id, file_id, kind, title, body,
                        related_type, related_id, read_at, created_at
                 FROM notifications WHERE id = ?1 AND recipient_email = ?2",
                params![notification_id, &recipient_email],
                row_to_notification,
            )?;
            tx.commit()?;
            notification
        };
        let receipt =
            self.insert_receipt("notification.read", &recipient_email, Some(notification_id))?;
        Ok((notification, receipt))
    }

    pub fn mark_all_notifications_read(
        &self,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<Receipt> {
        let recipient_email = normalize_storage_email(&actor.email)?;
        let now = Utc::now().to_rfc3339();
        {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            ensure_source_credential_active(&tx, actor, source_credential)?;
            tx.execute(
                "UPDATE notifications SET read_at = COALESCE(read_at, ?1)
                 WHERE recipient_email = ?2",
                params![&now, &recipient_email],
            )?;
            tx.commit()?;
        }
        Ok(self.insert_receipt(
            "notification.read_all",
            &recipient_email,
            Some(&recipient_email),
        )?)
    }
}
