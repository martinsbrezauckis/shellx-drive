use chrono::Utc;
use rusqlite::{params, TransactionBehavior};

use crate::{
    auth::{Actor, DriveCredential},
    error::{ApiError, ApiResult},
    model::Receipt,
};

use super::super::{authorization, insert_receipt_rows, new_receipt, Storage};

impl Storage {
    /// Linearize a token's bearer publication. The pending token becomes
    /// usable only in the same write transaction that proves the issuing
    /// administrator is still current. A competing revoke therefore orders
    /// entirely before (cancel) or after (published) this operation.
    pub(crate) fn publish_pending_app_token(
        &self,
        app_token_id: &str,
        creation_receipt: &Receipt,
        admin_actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<()> {
        self.publish_pending_app_token_with(
            app_token_id,
            creation_receipt,
            admin_actor,
            source_credential,
            || {},
        )
    }

    fn publish_pending_app_token_with<F>(
        &self,
        app_token_id: &str,
        creation_receipt: &Receipt,
        admin_actor: &Actor,
        source_credential: &DriveCredential,
        before_publication: F,
    ) -> ApiResult<()>
    where
        F: FnOnce(),
    {
        before_publication();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        match authorization::ensure_admin_authorized(&tx, admin_actor, source_credential) {
            Ok(()) => {
                let published = tx.execute(
                    "UPDATE app_tokens
                     SET publication_pending = 0
                     WHERE id = ?1 AND publication_pending = 1 AND revoked_at IS NULL",
                    params![app_token_id],
                )?;
                if published != 1 {
                    return Err(ApiError::Conflict);
                }
                insert_receipt_rows(&tx, creation_receipt)?;
                tx.commit()?;
                Ok(())
            }
            Err(error) => {
                cancel_pending_app_token_in_tx(&tx, app_token_id, &admin_actor.email)?;
                tx.commit()?;
                Err(error)
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn publish_pending_app_token_with_test_barrier<F>(
        &self,
        app_token_id: &str,
        creation_receipt: &Receipt,
        admin_actor: &Actor,
        source_credential: &DriveCredential,
        before_publication: F,
    ) -> ApiResult<()>
    where
        F: FnOnce(),
    {
        self.publish_pending_app_token_with(
            app_token_id,
            creation_receipt,
            admin_actor,
            source_credential,
            before_publication,
        )
    }
}

fn cancel_pending_app_token_in_tx(
    tx: &rusqlite::Transaction<'_>,
    app_token_id: &str,
    actor: &str,
) -> ApiResult<()> {
    let revoked_at = Utc::now().to_rfc3339();
    let canceled = tx.execute(
        "UPDATE app_tokens
         SET revoked_at = COALESCE(revoked_at, ?2)
         WHERE id = ?1 AND publication_pending = 1",
        params![app_token_id, &revoked_at],
    )?;
    if canceled != 1 {
        return Err(ApiError::Conflict);
    }
    tx.execute(
        "UPDATE office_edit_sessions
         SET used_at = COALESCE(used_at, ?2)
         WHERE source_credential_kind = 'app_token'
           AND source_credential_id = ?1 AND used_at IS NULL",
        params![app_token_id, &revoked_at],
    )?;
    let receipt = new_receipt(
        "app_token.revoke.stale_publication",
        actor,
        Some(app_token_id),
    );
    insert_receipt_rows(tx, &receipt)?;
    Ok(())
}
