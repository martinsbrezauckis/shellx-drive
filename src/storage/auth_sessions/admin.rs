use chrono::Utc;
use rusqlite::{params, OptionalExtension, TransactionBehavior};

use crate::{
    auth::{Actor, DriveCredential},
    error::{ApiError, ApiResult},
    model::{AuthSession, Receipt},
};

use super::{row_to_auth_session, Storage};
use crate::storage::{authorization, insert_receipt_rows};

impl Storage {
    pub(crate) fn revoke_auth_session_authorized(
        &self,
        id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(AuthSession, Receipt)> {
        let revoked_at = Utc::now().to_rfc3339();
        let receipt = Receipt {
            id: uuid::Uuid::now_v7().to_string(),
            kind: "session.revoke".to_string(),
            actor: actor.email.clone(),
            target_id: Some(id.to_string()),
            created_at: revoked_at.clone(),
        };
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_admin_authorized(&tx, actor, source_credential)?;
        tx.execute(
            "UPDATE auth_sessions SET revoked_at = COALESCE(revoked_at, ?2) WHERE id = ?1",
            params![id, &revoked_at],
        )?;
        tx.execute(
            "UPDATE office_edit_sessions
             SET used_at = COALESCE(used_at, ?2)
             WHERE source_credential_kind = 'user_session'
               AND source_credential_id = ?1 AND used_at IS NULL",
            params![id, &revoked_at],
        )?;
        let session = tx
            .query_row(
                "SELECT id, actor_email, issuer, subject, expires_at, revoked_at, created_at
                 FROM auth_sessions WHERE id = ?1",
                params![id],
                row_to_auth_session,
            )
            .optional()?
            .ok_or(ApiError::NotFound)?;
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok((session, receipt))
    }
}
