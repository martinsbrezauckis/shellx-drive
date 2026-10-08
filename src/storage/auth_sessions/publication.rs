use chrono::Utc;
use rusqlite::{params, TransactionBehavior};

use crate::{
    auth::{Actor, DriveCredential},
    error::{ApiError, ApiResult},
    model::AuthSession,
};

use super::{insert_auth_session_in_tx, retention, Storage};
use crate::storage::{authorization, insert_receipt_rows, new_receipt};

impl Storage {
    /// Record an inactive SSO issuance intent. The signed bearer can be
    /// constructed before this call, but it remains unusable until the final
    /// source-admin publication transaction succeeds.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn record_pending_auth_session_publication(
        &self,
        id: &str,
        actor_email: &str,
        issuer: &str,
        subject: &str,
        token_hash: &str,
        expires_at: &str,
        admin_actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<AuthSession> {
        let session = AuthSession {
            id: id.to_string(),
            actor_email: actor_email.to_string(),
            issuer: issuer.to_string(),
            subject: subject.to_string(),
            expires_at: expires_at.to_string(),
            revoked_at: None,
            created_at: Utc::now().to_rfc3339(),
            revoked: false,
        };
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        authorization::ensure_admin_authorized(&tx, admin_actor, source_credential)?;
        insert_auth_session_in_tx(&tx, &session, token_hash, true)?;
        tx.commit()?;
        Ok(session)
    }

    /// Linearize SSO bearer publication. The session becomes active only in
    /// the transaction that proves the source administrator remains current;
    /// a concurrent revoke therefore deterministically cancels or follows the
    /// issuance rather than leaving an in-between active session.
    pub(crate) fn publish_pending_auth_session(
        &self,
        session_id: &str,
        admin_actor: &Actor,
        source_credential: &DriveCredential,
    ) -> ApiResult<()> {
        self.publish_pending_auth_session_with(session_id, admin_actor, source_credential, || {})
    }

    fn publish_pending_auth_session_with<F>(
        &self,
        session_id: &str,
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
                    "UPDATE auth_sessions
                     SET publication_pending = 0
                     WHERE id = ?1 AND publication_pending = 1 AND revoked_at IS NULL",
                    params![session_id],
                )?;
                if published != 1 {
                    return Err(ApiError::Conflict);
                }
                let actor_email: String = tx.query_row(
                    "SELECT actor_email FROM auth_sessions WHERE id = ?1",
                    params![session_id],
                    |row| row.get(0),
                )?;
                // Pending sessions deliberately do not participate in the
                // active-session cap. Enforce it at the publication
                // linearization point, after this session becomes active and
                // before either the session or its creation receipt commits.
                retention::enforce_active_session_limit_in_tx(&tx, &actor_email, session_id)?;
                let receipt = new_receipt(
                    "auth.session.sso.create",
                    &admin_actor.email,
                    Some(session_id),
                );
                insert_receipt_rows(&tx, &receipt)?;
                tx.commit()?;
                Ok(())
            }
            Err(error) => {
                cancel_pending_auth_session_in_tx(&tx, session_id, &admin_actor.email)?;
                tx.commit()?;
                Err(error)
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn publish_pending_auth_session_with_test_barrier<F>(
        &self,
        session_id: &str,
        admin_actor: &Actor,
        source_credential: &DriveCredential,
        before_publication: F,
    ) -> ApiResult<()>
    where
        F: FnOnce(),
    {
        self.publish_pending_auth_session_with(
            session_id,
            admin_actor,
            source_credential,
            before_publication,
        )
    }
}

fn cancel_pending_auth_session_in_tx(
    tx: &rusqlite::Transaction<'_>,
    session_id: &str,
    actor: &str,
) -> ApiResult<()> {
    let revoked_at = Utc::now().to_rfc3339();
    let canceled = tx.execute(
        "UPDATE auth_sessions
         SET revoked_at = COALESCE(revoked_at, ?2)
         WHERE id = ?1 AND publication_pending = 1",
        params![session_id, &revoked_at],
    )?;
    if canceled != 1 {
        return Err(ApiError::Conflict);
    }
    tx.execute(
        "UPDATE office_edit_sessions
         SET used_at = COALESCE(used_at, ?2)
         WHERE source_credential_kind = 'user_session'
           AND source_credential_id = ?1 AND used_at IS NULL",
        params![session_id, &revoked_at],
    )?;
    let receipt = new_receipt(
        "auth.session.revoke.stale_publication",
        actor,
        Some(session_id),
    );
    insert_receipt_rows(tx, &receipt)?;
    Ok(())
}
