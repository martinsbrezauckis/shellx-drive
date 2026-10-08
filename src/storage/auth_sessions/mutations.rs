use chrono::Utc;
use rusqlite::{params, OptionalExtension};

use crate::{
    auth::{Actor, DriveCredential},
    error::{ApiError, ApiResult},
    model::{AuthSession, Receipt},
};

use super::row_to_auth_session;
use crate::storage::{authorization, insert_receipt_rows, new_receipt, Storage};

impl Storage {
    pub fn revoke_auth_session_for_actor_authorized(
        &self,
        id: &str,
        actor: &Actor,
        source_credential: &DriveCredential,
        receipt_kind: &str,
    ) -> ApiResult<(AuthSession, Receipt)> {
        let revoked_at = Utc::now().to_rfc3339();
        let receipt = new_receipt(receipt_kind, &actor.email, Some(id));
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        authorization::ensure_source_credential_active(&tx, actor, source_credential)?;
        tx.execute(
            "UPDATE auth_sessions
             SET revoked_at = COALESCE(revoked_at, ?3)
             WHERE id = ?1 AND actor_email = ?2",
            params![id, &actor.email, &revoked_at],
        )?;
        tx.execute(
            "UPDATE office_edit_sessions
             SET used_at = COALESCE(used_at, ?3)
             WHERE source_credential_kind = 'user_session'
               AND source_credential_id = ?1 AND actor_email = ?2
               AND used_at IS NULL",
            params![id, &actor.email, &revoked_at],
        )?;
        let session = tx
            .query_row(
                "SELECT id, actor_email, issuer, subject, expires_at, revoked_at, created_at
                 FROM auth_sessions WHERE id = ?1 AND actor_email = ?2",
                params![id, &actor.email],
                row_to_auth_session,
            )
            .optional()?
            .ok_or(ApiError::NotFound)?;
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok((session, receipt))
    }

    pub fn revoke_other_auth_sessions_for_actor_authorized(
        &self,
        current_session_id: Option<&str>,
        actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<(usize, Receipt)> {
        let revoked_at = Utc::now().to_rfc3339();
        let receipt = new_receipt("auth.session.revoke_others", &actor.email, None);
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        authorization::ensure_source_credential_active(&tx, actor, source_credential)?;
        let mut statement = tx.prepare(
            "SELECT id FROM auth_sessions
             WHERE actor_email = ?1 AND (?2 IS NULL OR id <> ?2)
               AND revoked_at IS NULL
               AND julianday(expires_at) > julianday(?3)",
        )?;
        let session_ids = statement
            .query_map(
                params![&actor.email, current_session_id, &revoked_at],
                |row| row.get::<_, String>(0),
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(statement);
        for session_id in &session_ids {
            tx.execute(
                "UPDATE auth_sessions
                 SET revoked_at = COALESCE(revoked_at, ?3)
                 WHERE id = ?1 AND actor_email = ?2",
                params![session_id, &actor.email, &revoked_at],
            )?;
            tx.execute(
                "UPDATE office_edit_sessions
                 SET used_at = COALESCE(used_at, ?3)
                 WHERE source_credential_kind = 'user_session'
                   AND source_credential_id = ?1 AND actor_email = ?2
                   AND used_at IS NULL",
                params![session_id, &actor.email, &revoked_at],
            )?;
        }
        insert_receipt_rows(&tx, &receipt)?;
        tx.commit()?;
        Ok((session_ids.len(), receipt))
    }
}
