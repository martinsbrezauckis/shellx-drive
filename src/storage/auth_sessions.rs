mod admin;
mod client;
mod listing;
mod mutations;
mod publication;
mod retention;
mod validation;
mod verified;

use chrono::Utc;
use listing::row_to_auth_session;
use rusqlite::{params, OptionalExtension};

use crate::{
    error::{ApiError, ApiResult},
    model::{AuthSession, Receipt},
};

use super::Storage;

impl Storage {
    pub fn record_auth_session(
        &self,
        id: &str,
        actor_email: &str,
        issuer: &str,
        subject: &str,
        token_hash: &str,
        expires_at: &str,
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
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        insert_auth_session_in_tx(&tx, &session, token_hash, false)?;
        tx.commit()?;
        Ok(session)
    }

    /// Complete session history for agent/debug and audit export surfaces.
    pub fn revoke_auth_session(
        &self,
        id: &str,
        actor_email: &str,
    ) -> ApiResult<(AuthSession, Receipt)> {
        let revoked_at = Utc::now().to_rfc3339();
        let session = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute(
                "UPDATE auth_sessions
                 SET revoked_at = COALESCE(revoked_at, ?2)
                 WHERE id = ?1",
                params![id, revoked_at],
            )?;
            tx.execute(
                "UPDATE office_edit_sessions
                 SET used_at = COALESCE(used_at, ?2)
                 WHERE source_credential_kind = 'user_session'
                   AND source_credential_id = ?1 AND used_at IS NULL",
                params![id, revoked_at],
            )?;
            let session = tx
                .query_row(
                    "SELECT id, actor_email, issuer, subject, expires_at, revoked_at, created_at
                 FROM auth_sessions WHERE id = ?1",
                    params![id],
                    row_to_auth_session,
                )
                .optional()?;
            tx.commit()?;
            session
        }
        .ok_or(ApiError::NotFound)?;
        let receipt = self.insert_receipt("session.revoke", actor_email, Some(id))?;
        Ok((session, receipt))
    }

    pub fn revoke_auth_session_for_actor(
        &self,
        id: &str,
        actor_email: &str,
        receipt_kind: &str,
    ) -> ApiResult<(AuthSession, Receipt)> {
        let revoked_at = Utc::now().to_rfc3339();
        let session = {
            let mut conn = self.conn.lock().unwrap();
            let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
            tx.execute(
                "UPDATE auth_sessions
                 SET revoked_at = COALESCE(revoked_at, ?3)
                 WHERE id = ?1 AND actor_email = ?2",
                params![id, actor_email, revoked_at],
            )?;
            tx.execute(
                "UPDATE office_edit_sessions
                 SET used_at = COALESCE(used_at, ?3)
                 WHERE source_credential_kind = 'user_session'
                   AND source_credential_id = ?1 AND actor_email = ?2
                   AND used_at IS NULL",
                params![id, actor_email, revoked_at],
            )?;
            let session = tx
                .query_row(
                    "SELECT id, actor_email, issuer, subject, expires_at, revoked_at, created_at
                 FROM auth_sessions WHERE id = ?1 AND actor_email = ?2",
                    params![id, actor_email],
                    row_to_auth_session,
                )
                .optional()?;
            tx.commit()?;
            session
        }
        .ok_or(ApiError::NotFound)?;
        let receipt = self.insert_receipt(receipt_kind, actor_email, Some(id))?;
        Ok((session, receipt))
    }

    pub fn revoke_auth_sessions_for_actor(&self, actor_email: &str) -> ApiResult<usize> {
        let revoked_at = Utc::now().to_rfc3339();
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let revoked = tx.execute(
            "UPDATE auth_sessions
             SET revoked_at = COALESCE(revoked_at, ?2)
             WHERE actor_email = ?1",
            params![actor_email, revoked_at],
        )?;
        tx.execute(
            "UPDATE office_edit_sessions
             SET used_at = COALESCE(used_at, ?2)
             WHERE source_credential_kind = 'user_session'
               AND source_credential_id IN (
                   SELECT id FROM auth_sessions WHERE actor_email = ?1
               )
               AND used_at IS NULL",
            params![actor_email, revoked_at],
        )?;
        tx.commit()?;
        Ok(revoked)
    }
}

pub(super) fn insert_auth_session_with_client_in_tx(
    conn: &rusqlite::Connection,
    session: &AuthSession,
    token_hash: &str,
    client_ip: Option<&str>,
    user_agent: Option<&str>,
) -> ApiResult<()> {
    insert_auth_session_in_tx(conn, session, token_hash, false)?;
    client::set_auth_session_client_in_tx(conn, &session.id, client_ip, user_agent)
}

pub(super) fn insert_auth_session_in_tx(
    conn: &rusqlite::Connection,
    session: &AuthSession,
    token_hash: &str,
    publication_pending: bool,
) -> ApiResult<()> {
    retention::prepare_auth_session_issuance_in_tx(conn)?;
    conn.execute(
        "INSERT INTO auth_sessions (
            id, actor_email, issuer, subject, token_hash,
            expires_at, revoked_at, created_at, publication_pending
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            &session.id,
            &session.actor_email,
            &session.issuer,
            &session.subject,
            token_hash,
            &session.expires_at,
            &session.revoked_at,
            &session.created_at,
            publication_pending as i64,
        ],
    )?;
    retention::enforce_active_session_limit_in_tx(conn, &session.actor_email, &session.id)?;
    Ok(())
}
