use chrono::Utc;
use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::{
    auth::{Actor, DriveCredential},
    error::{ApiError, ApiResult},
    model::Receipt,
};

use super::{
    authorization::ensure_admin_authorized, insert_receipt_rows, new_receipt,
    normalize_storage_email, Storage,
};

impl Storage {
    /// Create a recovery capability that an authorized server administrator
    /// may copy exactly once from the immediate HTTP response. Only a hash is
    /// durable; issuing another link for the same account rotates the prior
    /// capability, including any unconsumed capture-outbox reset.
    pub(crate) fn create_admin_password_reset_link(
        &self,
        email: &str,
        reset_token_hash: &str,
        expires_at: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<Receipt> {
        let email = normalize_storage_email(email)?;
        let now = Utc::now().to_rfc3339();
        let receipt = new_receipt(
            "auth.password_reset.link.create",
            &actor.email,
            Some(&email),
        );
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_admin_authorized(&tx, actor, source_credential)?;
        let active_account = tx
            .query_row(
                "SELECT 1 FROM auth_accounts WHERE email = ?1 AND disabled_at IS NULL",
                params![&email],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !active_account {
            return Err(ApiError::NotFound);
        }
        tx.execute(
            "DELETE FROM password_reset_tokens WHERE email = ?1 AND used_at IS NULL",
            params![&email],
        )?;
        tx.execute(
            "INSERT INTO password_reset_tokens (
                id, email, token_hash, expires_at, used_at, created_at
             ) VALUES (?1, ?2, ?3, ?4, NULL, ?5)",
            params![
                uuid::Uuid::now_v7().to_string(),
                &email,
                reset_token_hash,
                expires_at,
                &now,
            ],
        )?;
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok(receipt)
    }

    /// Revoke the active recovery capability without exposing or retaining its
    /// plaintext form. A missing/expired link is reported to the administrator
    /// rather than being treated as a successful state change.
    pub(crate) fn revoke_admin_password_reset_link(
        &self,
        email: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<Receipt> {
        let email = normalize_storage_email(email)?;
        let now = Utc::now().to_rfc3339();
        let receipt = new_receipt(
            "auth.password_reset.link.revoke",
            &actor.email,
            Some(&email),
        );
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_admin_authorized(&tx, actor, source_credential)?;
        let revoked = tx.execute(
            "UPDATE password_reset_tokens
             SET used_at = ?2
             WHERE email = ?1 AND used_at IS NULL AND expires_at > ?2",
            params![&email, &now],
        )?;
        if revoked != 1 {
            return Err(ApiError::NotFound);
        }
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok(receipt)
    }

    /// Commit the authorization decision immediately before an E2E response
    /// publishes the plaintext reset capability. Ordinary reset requests never
    /// call this boundary and retain their non-enumerating response contract.
    pub(crate) fn create_password_reset_debug_publication_intent(
        &self,
        email: &str,
        reset_token_hash: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<Receipt> {
        let email = normalize_storage_email(email)?;
        let now = Utc::now().to_rfc3339();
        let receipt = new_receipt(
            "auth.password_reset.debug.publish.intent",
            &actor.email,
            Some(&email),
        );
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        ensure_admin_authorized(&tx, actor, source_credential)?;
        let active = tx
            .query_row(
                "SELECT 1 FROM password_reset_tokens
                 WHERE email = ?1 AND token_hash = ?2 AND used_at IS NULL
                   AND expires_at > ?3",
                params![&email, reset_token_hash, &now],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        if !active {
            return Err(ApiError::NotFound);
        }
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok(receipt)
    }
}
